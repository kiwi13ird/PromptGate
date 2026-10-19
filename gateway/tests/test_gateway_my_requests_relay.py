"""2026-10-11 - 내 요청 기록 중계(gateway_my_requests_relay + gateway.py 연결 4줄).

확장 프로그램 페이지가 http://llm-gateway.local/__llmsgw/my/requests[/<id>/evidence]를 부르면(PAC가 Gateway로 보냄)
Gateway가 목적지만 대시보드 내부 주소(/api/my/requests...)로 바꾸고 실제 전달은 mitmproxy가 비동기로 한다.
  1) 모듈 단위 시험(네트워크 없음)
  2) gateway.request()·response()·error() 훅을 지나는 시험(실제 mitmproxy flow 객체)
  3) 이 폴더의 gateway.py를 실제 mitmdump로 띄운 종단 시험(가짜 대시보드, 127.0.0.1 임시 포트만 연다)
가짜 값만 쓴다. 열람 키는 매번 무작위로 만들고 출력하지 않는다.
실행: python -m unittest tests.test_gateway_my_requests_relay -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import hashlib
import http.client as http_client
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

_TMP = tempfile.mkdtemp(prefix="gw-my-requests-")
os.environ.setdefault("DASHBOARD_OUTBOX_PATH", str(Path(_TMP) / "outbox.sqlite3"))   # gateway를 불러도 작업 폴더에 쓰지 않게
os.environ.setdefault("SIGNATURE_REVIEW_DIR", str(Path(_TMP) / "review"))
os.environ.pop("DASHBOARD_EVENT_URL", None)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mitmproxy import flow as mflow  # noqa: E402
from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
import gateway_my_requests_relay as relay  # noqa: E402
from tests.gw_support import run_hook  # noqa: E402

EXT = relay.DEFAULT_ALLOWED_ORIGINS[0]
DASHBOARD_ENV = {"DASHBOARD_EVENT_URL": "http://10.0.4.203/api/events/ingest"}
KNOWN_EVENT = "evt-11111111-2222-3333-4444-555555555555"
G = "http://llm-gateway.local"


def viewer_key(mode: str = "") -> str:
    """가짜 열람 키(43자 base64url). 종단 시험에서는 앞 4글자로 가짜 대시보드 동작을 고른다."""
    return (mode + secrets.token_urlsafe(32))[:43]


def make_flow(path, method="GET", headers=None, body=b"", host="llm-gateway.local"):
    req = tutils.treq(host=host, port=80, scheme=b"http", method=method.encode(), path=path.encode(),
                      headers=http.Headers([(b"Host", host.encode())]), content=body)
    for name, value in (headers or {}).items():
        req.headers[name] = value
    return tflow.tflow(req=req)


def upstream_response(status, body, ctype="application/json; charset=utf-8"):
    return tutils.tresp(status_code=status, content=body, headers=http.Headers(
        [(b"Content-Type", ctype.encode()), (b"Set-Cookie", b"llmsgw_admin_session=fake"), (b"Server", b"nginx/1.24.0"),
         (b"Access-Control-Allow-Origin", b"*")]))


class EnvMixin:
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ, DASHBOARD_ENV, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("DASHBOARD_MY_REQUESTS_URL", "MY_REQUESTS_ALLOWED_ORIGINS"):
            os.environ.pop(name, None)
        self.key = viewer_key()


# ------------------------------------------------------------------ 1) 모듈 단위

class RelayRequestTests(EnvMixin, unittest.TestCase):
    def test_gateway_own_routes_left_to_gateway(self):
        # gateway.py가 직접 답하는 llm-gateway.local 경로: health(이 모듈보다 앞, 방식 무관)·review(GET, 이 모듈보다 뒤)
        for method, path in (("GET", "/__llmsgw/health"), ("GET", "/__llmsgw/health?t=1"), ("POST", "/__llmsgw/health"),
                             ("GET", "/__llmsgw/review/x"), ("GET", "/__llmsgw/review/" + "0" * 32 + "?t=1")):
            f = make_flow(path, method, headers={"X-Viewer-Key": self.key})
            self.assertFalse(relay.handle_request(f), (method, path))
            self.assertIsNone(f.response)
            self.assertNotIn(relay.META, f.metadata)
            self.assertEqual(f.request.host, "llm-gateway.local")

    def test_other_llm_gateway_local_paths_answered_404_locally(self):
        # 중계·health·review 밖의 llm-gateway.local 경로는 Gateway가 직접 404 - upstream(llm-gateway.local:80)으로 열람 키를 넘기지 않는다
        for method, path in (("GET", "/__llmsgw/my/evidence"), ("GET", "/__llmsgw/my/requestsX"), ("GET", "/__llmsgw/my"),
                             ("GET", "/__llmsgw/my/"), ("GET", "/__llmsgw/stats"), ("GET", "/"), ("GET", "/favicon.ico"),
                             ("GET", "/api/my/requests"), ("GET", "/__llmsgw/not-a-route"), ("POST", "/__llmsgw/review/x"),
                             ("OPTIONS", "/__llmsgw/stats"), ("GET", "/__llmsgw/reviewx"), ("GET", "/__llmsgw/review")):
            f = make_flow(path, method, headers={"X-Viewer-Key": self.key, "Origin": "http://evil.example"})
            self.assertTrue(relay.handle_request(f), (method, path))
            self.assertEqual((f.response.status_code, json.loads(f.response.content)), (404, {"error": {"code": "NOT_FOUND"}}),
                             (method, path))
            self.assertEqual(f.metadata[relay.META], "local")
            self.assertEqual((f.request.host, f.request.port), ("llm-gateway.local", 80))
            self.assertEqual(f.response.headers["Cache-Control"], "no-store")
            self.assertNotIn("Access-Control-Allow-Origin", f.response.headers)

    def test_list_rewritten_with_only_viewer_key(self):
        f = make_flow("/__llmsgw/my/requests?t=1", headers={
            "X-Viewer-Key": self.key, "Cookie": "s=1", "Authorization": "Bearer x", "Origin": EXT,
            "Referer": "chrome-extension://x/p.html", "X-LLMSGW-Client-ID": "c", "X-Forwarded-For": "1.1.1.1"})
        self.assertTrue(relay.handle_request(f))
        self.assertIsNone(f.response)
        self.assertEqual(f.metadata[relay.META], "upstream")
        self.assertEqual((f.request.scheme, f.request.host, f.request.port, f.request.path),
                         ("http", "10.0.4.203", 80, "/api/my/requests"))
        self.assertEqual(sorted(k.lower() for k in f.request.headers.keys()), ["accept", "host", "user-agent", "x-viewer-key"])
        self.assertEqual(f.request.headers["Host"], "10.0.4.203")
        self.assertEqual(f.request.headers["X-Viewer-Key"], self.key)

    def test_evidence_rewritten(self):
        f = make_flow(f"/__llmsgw/my/requests/{KNOWN_EVENT}/evidence?x=1", headers={"X-Viewer-Key": self.key})
        self.assertTrue(relay.handle_request(f))
        self.assertEqual(f.request.path, f"/api/my/requests/{KNOWN_EVENT}/evidence")
        f = make_flow("/__llmsgw/my/requests/" + "a" * 128 + "/evidence", headers={"X-Viewer-Key": self.key})
        self.assertTrue(relay.handle_request(f))
        self.assertIsNone(f.response)

    def test_target_from_event_url_or_override(self):
        cases = [({"DASHBOARD_MY_REQUESTS_URL": "http://10.0.4.203:9100"}, ("http", "10.0.4.203", 9100), "10.0.4.203:9100"),
                 ({"DASHBOARD_EVENT_URL": "https://dash.internal.test/api/events/ingest"}, ("https", "dash.internal.test", 443),
                  "dash.internal.test"),
                 ({"DASHBOARD_EVENT_URL": "http://127.0.0.1:8080/x?y=1"}, ("http", "127.0.0.1", 8080), "127.0.0.1:8080")]
        for env, target, host_header in cases:
            with mock.patch.dict(os.environ, env):
                self.assertEqual(relay.dashboard_target(), target, env)
                f = make_flow("/__llmsgw/my/requests", headers={"X-Viewer-Key": self.key})
                relay.handle_request(f)
            self.assertEqual((f.request.scheme, f.request.host, f.request.port), target)
            self.assertEqual(f.request.headers["Host"], host_header)
            self.assertEqual(f.request.path, "/api/my/requests")

    def test_not_configured_or_unsafe_target(self):
        for env in ({"DASHBOARD_EVENT_URL": ""}, {"DASHBOARD_EVENT_URL": "ftp://10.0.4.203/x"},
                    {"DASHBOARD_EVENT_URL": "http://user:pw@10.0.4.203/x"}, {"DASHBOARD_EVENT_URL": "http://10.0.4.203:99999/x"},
                    {"DASHBOARD_EVENT_URL": "not a url"}):
            with mock.patch.dict(os.environ, env):
                f = make_flow("/__llmsgw/my/requests", headers={"X-Viewer-Key": self.key})
                self.assertTrue(relay.handle_request(f))
            self.assertEqual(f.response.status_code, 503, env)
            self.assertEqual(json.loads(f.response.content), {"error": {"code": "RELAY_NOT_CONFIGURED"}})
            self.assertEqual(f.request.host, "llm-gateway.local")

    def test_local_answers(self):
        k = {"X-Viewer-Key": self.key}
        cases = [("/__llmsgw/my/requests", "GET", {}, b"", 401),
                 ("/__llmsgw/my/requests", "GET", {"X-Viewer-Key": "a" * 64}, b"", 401),
                 ("/__llmsgw/my/requests", "GET", {"X-Viewer-Key": self.key[:42]}, b"", 401),
                 ("/__llmsgw/my/requests", "GET", {"X-Viewer-Key": self.key[:42] + "+"}, b"", 401),
                 ("/__llmsgw/my/requests", "POST", k, b"{}", 405),
                 ("/__llmsgw/my/requests", "HEAD", k, b"", 405),
                 ("/__llmsgw/my/requests", "GET", k, b"x", 400),
                 ("/__llmsgw/my/requests/", "GET", k, b"", 404),
                 (f"/__llmsgw/my/requests/{KNOWN_EVENT}", "GET", k, b"", 404),
                 (f"/__llmsgw/my/requests/{KNOWN_EVENT}/evidence/x", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests/a%2Fb/evidence", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests/%2e%2e/evidence", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests/../evidence", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests/.x/evidence", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests//evidence", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests/" + "a" * 129 + "/evidence", "GET", k, b"", 404),
                 ("/__llmsgw/my/requests", "OPTIONS", {"Origin": "http://evil.example"}, b"", 403)]
        for path, method, headers, body, want in cases:
            f = make_flow(path, method, headers, body)
            self.assertTrue(relay.handle_request(f))
            self.assertEqual(f.response.status_code, want, (path, method))
            self.assertEqual(f.metadata[relay.META], "local")
            self.assertEqual(f.request.host, "llm-gateway.local")
            self.assertEqual(f.response.headers["Cache-Control"], "no-store")
            self.assertNotIn("Access-Control-Allow-Origin", f.response.headers)

    def test_two_viewer_key_headers_rejected(self):
        f = make_flow("/__llmsgw/my/requests")
        f.request.headers.add("X-Viewer-Key", self.key)
        f.request.headers.add("X-Viewer-Key", viewer_key())
        relay.handle_request(f)
        self.assertEqual(f.response.status_code, 401)

    def test_preflight_only_for_allowed_origin(self):
        f = make_flow("/__llmsgw/my/requests", "OPTIONS", {"Origin": EXT})
        relay.handle_request(f)
        self.assertEqual(f.response.status_code, 204)
        self.assertEqual(f.response.headers["Access-Control-Allow-Origin"], EXT)
        self.assertEqual(f.response.headers["Access-Control-Allow-Headers"], "X-Viewer-Key")
        with mock.patch.dict(os.environ, {"MY_REQUESTS_ALLOWED_ORIGINS": ""}):
            f = make_flow("/__llmsgw/my/requests", "OPTIONS", {"Origin": EXT})
            relay.handle_request(f)
        self.assertEqual(f.response.status_code, 403)
        with mock.patch.dict(os.environ, {"MY_REQUESTS_ALLOWED_ORIGINS": " chrome-extension://other , " + EXT}):
            f = make_flow("/__llmsgw/my/requests", "OPTIONS", {"Origin": "chrome-extension://other"})
            relay.handle_request(f)
        self.assertEqual(f.response.status_code, 204)


class RelayResponseTests(unittest.TestCase):
    def relayed(self, status, body, ctype="application/json; charset=utf-8", origin=""):
        f = make_flow("/x")
        f.metadata[relay.META] = "upstream"
        f.metadata["gw_my_requests_origin"] = origin
        f.response = upstream_response(status, body, ctype)
        relay.handle_response(f)
        return f.response

    def test_json_passes_and_headers_cleaned(self):
        for status in (200, 401, 404, 405):
            resp = self.relayed(status, b'{"items":[],"window_days":7}', origin=EXT)
            self.assertEqual(resp.status_code, status)
            self.assertEqual(json.loads(resp.content), {"items": [], "window_days": 7})
            self.assertNotIn("Set-Cookie", resp.headers)
            self.assertNotIn("Server", resp.headers)
            self.assertEqual(resp.headers["Cache-Control"], "no-store")
            self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(resp.headers["Access-Control-Allow-Origin"], EXT)
        self.assertNotIn("Access-Control-Allow-Origin", self.relayed(200, b"{}", origin="http://evil.example").headers)
        self.assertNotIn("Access-Control-Allow-Origin", self.relayed(200, b"{}").headers)

    def test_non_json_or_unexpected_status_becomes_fixed_error(self):
        resp = self.relayed(502, b"<html>nginx 10.0.4.203</html>", "text/html")
        self.assertEqual((resp.status_code, json.loads(resp.content)), (502, {"error": {"code": "DASHBOARD_UNAVAILABLE"}}))
        self.assertNotIn(b"10.0.4.203", resp.content)
        self.assertEqual(self.relayed(504, b"<html></html>", "text/html").status_code, 504)
        self.assertEqual(self.relayed(500, b'{"error":{"code":"INTERNAL"}}').status_code, 502)
        self.assertEqual(self.relayed(302, b"", "text/html").status_code, 502)
        self.assertEqual(json.loads(self.relayed(200, b"<html/>", "text/html").content), {"error": {"code": "DASHBOARD_UNAVAILABLE"}})

    def test_too_large(self):
        with mock.patch.object(relay, "MAX_RESPONSE_BYTES", 10):
            resp = self.relayed(200, b'{"items":[1,2,3,4,5]}')
        self.assertEqual((resp.status_code, json.loads(resp.content)), (502, {"error": {"code": "RESPONSE_TOO_LARGE"}}))

    def test_unknown_encoding_becomes_fixed_error(self):
        f = make_flow("/x")
        f.metadata[relay.META] = "upstream"
        f.response = upstream_response(200, b"\x00garbage")
        f.response.headers["Content-Encoding"] = "fake-encoding"
        relay.handle_response(f)
        self.assertEqual(f.response.status_code, 502)

    def test_non_relay_flow_untouched(self):
        for meta in (None, "local"):
            f = make_flow("/x")
            if meta:
                f.metadata[relay.META] = meta
            f.response = tutils.tresp(status_code=200, content=b"<html/>")
            f.live = True
            before = f.response
            relay.handle_response(f)
            relay.handle_error(f)
            self.assertIs(f.response, before)
            self.assertTrue(f.killable)

    def test_error_kills_relay_flow(self):
        f = make_flow("/x")
        f.metadata[relay.META] = "upstream"
        f.live = True
        f.error = mflow.Error("[Errno 111] Connect call failed ('10.0.4.203', 80)")
        relay.handle_error(f)
        self.assertEqual(f.error.msg, mflow.Error.KILLED_MESSAGE)


# ------------------------------------------------------------------ 2) gateway.py 훅

class GatewayHookTests(EnvMixin, unittest.TestCase):
    def test_gateway_wires_relay_module(self):
        self.assertIs(getattr(gateway, "my_requests_relay", None), relay)

    def test_request_hook_rewrites_before_metrics_and_inspection(self):
        before = gateway._gateway_metrics["total_requests"]
        f = make_flow("/__llmsgw/my/requests?t=1", headers={"X-Viewer-Key": self.key, "X-LLMSGW-Client-ID": "c1"})
        run_hook(gateway.request(f))
        self.assertIsNone(f.response)
        self.assertEqual((f.request.host, f.request.port, f.request.path), ("10.0.4.203", 80, "/api/my/requests"))
        self.assertEqual(sorted(k.lower() for k in f.request.headers.keys()), ["accept", "host", "user-agent", "x-viewer-key"])
        for name in ("gw_metrics_started_at", "gw_settings", "gw_processing_ms", "gw_action", "gw_dashboard_events"):
            self.assertNotIn(name, f.metadata)
        self.assertEqual(gateway._gateway_metrics["total_requests"], before)

    def test_request_hook_local_answer(self):
        f = make_flow("/__llmsgw/my/requests")
        run_hook(gateway.request(f))
        self.assertEqual(f.response.status_code, 401)
        self.assertEqual(json.loads(f.response.content), {"error": {"code": "VIEWER_KEY_REQUIRED"}})
        self.assertNotIn("gw_metrics_started_at", f.metadata)

    def test_health_and_review_still_answered_by_gateway(self):
        f = make_flow("/__llmsgw/health")
        run_hook(gateway.request(f))
        self.assertEqual(f.response.status_code, 200)
        self.assertEqual(json.loads(f.response.content)["service"], "llm-security-gateway")
        self.assertNotIn(relay.META, f.metadata)
        f = make_flow("/__llmsgw/review/" + "0" * 32)
        run_hook(gateway.request(f))
        self.assertEqual((f.response.status_code, f.response.content), (404, b'{"error":"review_not_found"}'))
        self.assertNotIn(relay.META, f.metadata)

    def test_non_relay_llm_gateway_local_paths_not_forwarded(self):
        before = gateway._gateway_metrics["total_requests"]
        for method, path in (("GET", "/__llmsgw/my/evidence"), ("GET", "/__llmsgw/stats"), ("POST", "/__llmsgw/review/x")):
            f = make_flow(path, method, headers={"X-Viewer-Key": self.key})
            run_hook(gateway.request(f))
            self.assertEqual((f.response.status_code, json.loads(f.response.content)), (404, {"error": {"code": "NOT_FOUND"}}),
                             (method, path))
            self.assertEqual(f.request.host, "llm-gateway.local")
            for name in ("gw_metrics_started_at", "gw_settings", "gw_processing_ms"):
                self.assertNotIn(name, f.metadata)
            before_response = f.response
            gateway.response(f)
            self.assertIs(f.response, before_response)
        self.assertEqual(gateway._gateway_metrics["total_requests"], before)

    def test_only_llm_gateway_local_is_relayed(self):
        f = make_flow("/__llmsgw/my/requests", headers={"X-Viewer-Key": self.key}, host="example.test")
        run_hook(gateway.request(f))
        self.assertIsNone(f.response)
        self.assertNotIn(relay.META, f.metadata)
        self.assertEqual((f.request.host, f.request.path), ("example.test", "/__llmsgw/my/requests"))
        self.assertEqual(f.request.headers["X-Viewer-Key"], self.key)

    def test_response_hook_sanitises_relay_response(self):
        f = make_flow("/__llmsgw/my/requests", headers={"X-Viewer-Key": self.key, "Origin": EXT})
        run_hook(gateway.request(f))
        f.response = upstream_response(200, b'{"items":[],"window_days":7}')
        gateway.response(f)
        self.assertEqual(json.loads(f.response.content), {"items": [], "window_days": 7})
        self.assertNotIn("Set-Cookie", f.response.headers)
        self.assertNotIn("Server", f.response.headers)
        self.assertEqual(f.response.headers["Access-Control-Allow-Origin"], EXT)
        f = make_flow("/__llmsgw/my/requests", headers={"X-Viewer-Key": self.key})
        run_hook(gateway.request(f))
        f.response = upstream_response(502, b"<html>10.0.4.203</html>", "text/html")
        gateway.response(f)
        self.assertEqual((f.response.status_code, json.loads(f.response.content)),
                         (502, {"error": {"code": "DASHBOARD_UNAVAILABLE"}}))

    def test_response_hook_leaves_local_answers(self):
        f = make_flow("/__llmsgw/my/requests")
        run_hook(gateway.request(f))
        before = f.response
        gateway.response(f)
        self.assertIs(f.response, before)
        self.assertEqual(f.response.status_code, 401)

    def test_error_hook_kills_relay_flow_only(self):
        f = make_flow("/__llmsgw/my/requests", headers={"X-Viewer-Key": self.key})
        run_hook(gateway.request(f))
        f.live = True
        f.error = mflow.Error("[Errno 111] Connect call failed ('10.0.4.203', 80)")
        gateway.error(f)
        self.assertEqual(f.error.msg, mflow.Error.KILLED_MESSAGE)
        other = make_flow("/v1/x", host="example.test")
        other.live = True
        other.error = mflow.Error("connect failed")
        gateway.error(other)
        self.assertEqual(other.error.msg, "connect failed")


# ------------------------------------------------------------------ 3) 실제 mitmdump 종단

MITMDUMP_MAIN = "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())"
SLOW_SECONDS = 2.0
# 시험용 mitmdump에 gateway.py 다음으로 싣는 보호 장치: 127.0.0.1 밖으로는 연결하지 않는다.
# 중계가 없거나 깨진 사본으로 돌려도 llm-gateway.local(PC에 따라 외부 주소로 풀림)로 요청이 나가지 않고 599로 바로 끝난다.
GUARD_ADDON = '''\
from mitmproxy import http

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def request(flow):
    if flow.response is None and (flow.request.host or "").lower() not in LOOPBACK:
        flow.response = http.Response.make(599, b'{"test_guard":"not relayed"}', {"Content-Type": "application/json"})


def server_connect(data):
    address = data.server.address
    if not address or address[0] not in LOOPBACK:
        data.server.error = "blocked by test guard (loopback only)"
'''


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeDashboard:
    """대시보드(nginx → app.mjs) 흉내. /api/my/requests 규칙은 app.mjs와 같게(GET만, 열람 키 43자 아니면 401, 근거는 아는 번호만).
    열람 키 앞 4글자로 동작을 고른다: slow=지연, bigg=17MiB, html=nginx식 502 HTML, cook=Set-Cookie·Server·ACAO:* 추가.
    받은 요청은 경로·머리 이름·열람 키 지문만 남긴다(키 원문은 남기지 않음)."""

    def __init__(self):
        self.hits = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, status, payload, ctype="application/json; charset=utf-8", extra=None):
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for name, value in (extra or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                key = self.headers.get("X-Viewer-Key", "")
                owner.hits.append({"path": self.path, "headers": sorted(h.lower() for h in self.headers.keys()),
                                   "host": self.headers.get("Host"),
                                   "key_sha": hashlib.sha256(key.encode()).hexdigest() if key else None})
                if not self.path.startswith("/api/my/requests"):
                    return self._send(404, {"error": {"code": "NOT_FOUND"}})
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", key):
                    return self._send(401, {"error": {"code": "VIEWER_KEY_REQUIRED"}})
                mode = key[:4]
                if mode == "slow":
                    time.sleep(SLOW_SECONDS)
                if mode == "html":
                    return self._send(502, b"<html><body>502 Bad Gateway nginx/1.24.0 10.0.4.203</body></html>", "text/html")
                if mode == "bigg":
                    return self._send(200, {"items": [], "window_days": 7, "pad": "x" * (17 * 1024 * 1024)})
                extra = {"Set-Cookie": "llmsgw_admin_session=fake; HttpOnly", "Server": "nginx/1.24.0 (Ubuntu)",
                         "Access-Control-Allow-Origin": "*"} if mode == "cook" else None
                if self.path == "/api/my/requests":
                    return self._send(200, {"items": [], "window_days": 7}, extra=extra)
                match = re.fullmatch(r"/api/my/requests/([^/]{1,200})/evidence", self.path)
                if match and match.group(1) == KNOWN_EVENT:
                    return self._send(200, {"event_id": KNOWN_EVENT, "status": "NOT_RECORDED"}, extra=extra)
                return self._send(404, {"error": {"code": "NOT_FOUND"}})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                owner.hits.append({"path": self.path, "method": "POST"})
                self._send(404, {"error": {"code": "NOT_FOUND"}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def relay_hits(self):
        return [hit for hit in self.hits if hit["path"].startswith("/api/my/")]


def proxy_call(port, method, url, headers=None, body=None, timeout=30):
    """확장 프로그램 페이지가 PAC 프록시로 보내는 것과 같은 절대 주소 요청."""
    parts = urlsplit(url)
    conn = http_client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    sent = {"Host": parts.netloc, **(headers or {})}
    started = time.perf_counter()
    try:
        conn.request(method, url, body=body, headers=sent)
        resp = conn.getresponse()
        data = resp.read()
        return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.getheaders()}, "body": data,
                "ms": (time.perf_counter() - started) * 1000, "end": time.perf_counter()}
    except (OSError, http_client.HTTPException) as exc:
        return {"status": None, "error": type(exc).__name__, "headers": {}, "body": b"",
                "ms": (time.perf_counter() - started) * 1000, "end": time.perf_counter()}
    finally:
        conn.close()


def body_json(result):
    try:
        return json.loads(result["body"] or b"null")
    except ValueError:
        return None


class MitmdumpGateway:
    """이 폴더의 gateway.py를 같은 Python의 mitmdump로 127.0.0.1 임시 포트에 띄운다.
    대시보드·Detection 토큰은 주지 않는다(검사·이벤트 전송 없음). 설정·인증서·기록 파일은 모두 임시 폴더."""

    def __init__(self, env_extra: dict):
        self.dir = Path(tempfile.mkdtemp(prefix="gw-my-requests-mitm-"))
        self.port = free_port()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("DASHBOARD_", "DETECTION_", "SIGNATURE_", "GATEWAY_", "MY_REQUESTS_"))}
        env.update(DASHBOARD_OUTBOX_PATH=str(self.dir / "outbox.sqlite3"), SIGNATURE_REVIEW_DIR=str(self.dir / "review"),
                   GATEWAY_SETTINGS_CACHE_PATH=str(self.dir / "gateway-settings.json"),
                   PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", **env_extra)
        guard = self.dir / "loopback_guard.py"
        guard.write_text(GUARD_ADDON, encoding="utf-8")
        self.log_path = self.dir / "mitmdump.log"
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-c", MITMDUMP_MAIN, "--listen-host", "127.0.0.1", "--listen-port", str(self.port),
             "--set", "block_global=false", "--set", f"confdir={self.dir / 'confdir'}",
             "-s", str(ROOT / "gateway.py"), "-s", str(guard)],
            stdout=self.log, stderr=subprocess.STDOUT, env=env, cwd=str(ROOT))
        try:
            self._wait_ready()
        except BaseException:
            self.stop()          # 시작 도중 무슨 일이 나도 mitmdump를 남기지 않는다
            raise

    def _wait_ready(self):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("mitmdump exited during start: " + self.log_text()[-2000:])
            probe = proxy_call(self.port, "GET", f"{G}/__llmsgw/health", timeout=3)
            if probe["status"] == 200 and (body_json(probe) or {}).get("service") == "llm-security-gateway":
                return
            time.sleep(0.2)
        raise RuntimeError("mitmdump did not start: " + self.log_text()[-2000:])

    def log_text(self) -> str:
        if not self.log.closed:
            self.log.flush()
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(10)
        if not self.log.closed:
            self.log.close()

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class RelayE2ETests(unittest.TestCase):
    """대시보드 주소는 DASHBOARD_EVENT_URL(경로 /api/events/ingest)의 스킴·호스트·포트에서 얻는다(덮어쓰기 없음)."""

    @classmethod
    def setUpClass(cls):
        cls.keys = []
        cls.dashboard = FakeDashboard()
        try:
            cls.gw = MitmdumpGateway({"DASHBOARD_EVENT_URL": f"http://127.0.0.1:{cls.dashboard.port}/api/events/ingest"})
        except Exception:
            cls.dashboard.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.gw.stop()
        cls.dashboard.stop()
        cls.gw.cleanup()

    @classmethod
    def key(cls, mode=""):
        value = viewer_key(mode)
        cls.keys.append(value)
        return value

    def call(self, method, path, headers=None, body=None, timeout=30):
        return proxy_call(self.gw.port, method, G + path, headers, body, timeout)

    def test_guard_keeps_test_traffic_on_loopback(self):
        # 보호 장치 확인: Gateway가 밖으로 넘기려는 요청(다른 호스트)은 시험에서는 599로 끝난다
        n = len(self.dashboard.hits)
        r = proxy_call(self.gw.port, "GET", "http://guard-check.invalid/x", {"X-Viewer-Key": self.key()})
        self.assertEqual((r["status"], body_json(r)), (599, {"test_guard": "not relayed"}))
        self.assertEqual(self.dashboard.hits[n:], [])

    def test_non_relay_llm_gateway_local_paths_answered_by_gateway(self):
        # 중계·health·review 밖의 llm-gateway.local 경로는 Gateway가 직접 404(보호 장치 599까지 가지 않음 = upstream으로 넘기지 않음)
        n = len(self.dashboard.hits)
        for method, path in (("GET", "/__llmsgw/my/evidence"), ("GET", "/__llmsgw/not-a-route"), ("GET", "/__llmsgw/stats"),
                             ("GET", "/"), ("POST", "/__llmsgw/review/" + "0" * 32)):
            r = self.call(method, path, {"X-Viewer-Key": self.key()}, b"{}" if method == "POST" else None)
            self.assertEqual((r["status"], body_json(r)), (404, {"error": {"code": "NOT_FOUND"}}), (method, path))
        self.assertEqual(self.dashboard.hits[n:], [])

    def test_health_and_review_unchanged(self):
        r = self.call("GET", "/__llmsgw/health")
        self.assertEqual(r["status"], 200)
        self.assertEqual(body_json(r)["status"], "ok")
        r = self.call("GET", "/__llmsgw/review/" + "0" * 32)
        self.assertEqual(r["status"], 404)
        self.assertIn(b"review_not_found", r["body"])

    def test_list_relayed_with_only_viewer_key(self):
        key = self.key()
        junk = {"Cookie": "llmsgw_admin_session=fake", "Authorization": "Bearer fake", "X-LLMSGW-Client-ID": "c1",
                "X-LLMSGW-Viewer-Key": key, "Origin": EXT, "Referer": "chrome-extension://x/p.html",
                "X-Forwarded-For": "192.0.2.1", "Accept-Encoding": "gzip", "User-Agent": "Mozilla/5.0"}
        n = len(self.dashboard.hits)
        r = self.call("GET", "/__llmsgw/my/requests?t=123", {"X-Viewer-Key": key, **junk})
        self.assertEqual(r["status"], 200)
        self.assertEqual(body_json(r), {"items": [], "window_days": 7})
        self.assertEqual(r["headers"].get("cache-control"), "no-store")
        self.assertEqual(r["headers"].get("x-content-type-options"), "nosniff")
        self.assertEqual(r["headers"].get("access-control-allow-origin"), EXT)
        hits = self.dashboard.hits[n:]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["path"], "/api/my/requests")
        self.assertEqual(hits[0]["headers"], ["accept", "host", "user-agent", "x-viewer-key"])
        self.assertEqual(hits[0]["host"], f"127.0.0.1:{self.dashboard.port}")
        self.assertEqual(hits[0]["key_sha"], hashlib.sha256(key.encode()).hexdigest())

    def test_evidence_relayed_and_unknown_404_passes(self):
        key = self.key()
        r = self.call("GET", f"/__llmsgw/my/requests/{KNOWN_EVENT}/evidence", {"X-Viewer-Key": key})
        self.assertEqual((r["status"], body_json(r)), (200, {"event_id": KNOWN_EVENT, "status": "NOT_RECORDED"}))
        self.assertEqual(self.dashboard.hits[-1]["path"], f"/api/my/requests/{KNOWN_EVENT}/evidence")
        r = self.call("GET", "/__llmsgw/my/requests/evt-00000000-0000-0000-0000-000000000000/evidence", {"X-Viewer-Key": key})
        self.assertEqual((r["status"], body_json(r)), (404, {"error": {"code": "NOT_FOUND"}}))

    def test_local_answers_never_reach_dashboard(self):
        key = self.key()
        vk = {"X-Viewer-Key": key}
        n = len(self.dashboard.hits)
        cases = [("GET", "/__llmsgw/my/requests", {}, None, 401),
                 ("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": secrets.token_hex(32)}, None, 401),
                 ("POST", "/__llmsgw/my/requests", {**vk, "Content-Type": "application/json"}, b"{}", 405),
                 ("HEAD", "/__llmsgw/my/requests", vk, None, 405),
                 ("DELETE", f"/__llmsgw/my/requests/{KNOWN_EVENT}/evidence", vk, None, 405),
                 ("GET", "/__llmsgw/my/requests", vk, b"x=1", 400),
                 ("GET", "/__llmsgw/my/requests/", vk, None, 404),
                 ("GET", f"/__llmsgw/my/requests/{KNOWN_EVENT}", vk, None, 404),
                 ("GET", f"/__llmsgw/my/requests/{KNOWN_EVENT}/evidence/x", vk, None, 404),
                 ("GET", "/__llmsgw/my/requests/..%2F..%2Fevents/evidence", vk, None, 404),
                 ("GET", "/__llmsgw/my/requests/%2e%2e/evidence", vk, None, 404),
                 ("GET", "/__llmsgw/my/requests/../evidence", vk, None, 404),
                 ("GET", "/__llmsgw/my/requests/.x/evidence", vk, None, 404),
                 ("GET", "/__llmsgw/my/requests//evidence", vk, None, 404),
                 ("GET", "/__llmsgw/my/requests/" + "a" * 129 + "/evidence", vk, None, 404),
                 ("OPTIONS", "/__llmsgw/my/requests", {"Origin": "http://evil.example", "Access-Control-Request-Method": "GET",
                                                       "Access-Control-Request-Headers": "x-viewer-key"}, None, 403)]
        for method, path, headers, body, want in cases:
            r = self.call(method, path, headers, body)
            self.assertEqual(r["status"], want, (method, path))
            self.assertNotIn("access-control-allow-origin", r["headers"], (method, path))
        conn = http_client.HTTPConnection("127.0.0.1", self.gw.port, timeout=10)
        try:
            conn.putrequest("GET", f"{G}/__llmsgw/my/requests", skip_host=True)
            conn.putheader("Host", "llm-gateway.local")
            conn.putheader("X-Viewer-Key", key)
            conn.putheader("X-Viewer-Key", self.key())
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, 401)
        finally:
            conn.close()
        self.assertEqual(self.dashboard.hits[n:], [])

    def test_preflight_for_extension_origin(self):
        r = self.call("OPTIONS", f"/__llmsgw/my/requests/{KNOWN_EVENT}/evidence",
                      {"Origin": EXT, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-viewer-key"})
        self.assertEqual(r["status"], 204)
        self.assertEqual(r["headers"].get("access-control-allow-origin"), EXT)
        self.assertEqual(r["headers"].get("access-control-allow-headers"), "X-Viewer-Key")

    def test_dashboard_response_sanitised(self):
        r = self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": self.key("cook"), "Origin": "http://evil.example"})
        self.assertEqual(r["status"], 200)
        self.assertFalse({"set-cookie", "server"} & set(r["headers"]), sorted(r["headers"]))
        self.assertNotIn("access-control-allow-origin", r["headers"])
        r = self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": self.key("html")})
        self.assertEqual((r["status"], body_json(r)), (502, {"error": {"code": "DASHBOARD_UNAVAILABLE"}}))
        self.assertNotIn(b"10.0.4.203", r["body"])
        r = self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": self.key("bigg")})
        self.assertEqual((r["status"], body_json(r)), (502, {"error": {"code": "RESPONSE_TOO_LARGE"}}))

    def test_slow_dashboard_does_not_block_gateway(self):
        holder = {}
        slow_key = self.key("slow")
        worker = threading.Thread(target=lambda: holder.setdefault(
            "slow", self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": slow_key})))
        worker.start()
        time.sleep(0.3)
        health = self.call("GET", "/__llmsgw/health")
        other = self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": self.key()})
        worker.join()
        slow = holder["slow"]
        self.assertEqual([slow["status"], health["status"], other["status"]], [200, 200, 200])
        self.assertGreaterEqual(slow["ms"], SLOW_SECONDS * 1000 - 100)
        self.assertLess(health["end"], slow["end"])
        self.assertLess(other["end"], slow["end"])
        self.assertLess(health["ms"], 1000)
        results = []
        keys = [self.key("slow") for _ in range(3)]
        threads = [threading.Thread(target=lambda k=k: results.append(
            self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": k}))) for k in keys]
        started = time.perf_counter()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        wall_ms = (time.perf_counter() - started) * 1000
        self.assertEqual(sorted(r["status"] for r in results), [200, 200, 200])
        self.assertLess(wall_ms, SLOW_SECONDS * 1000 * 1.75)     # 직렬이면 3배

    def test_z_log_has_no_viewer_key_or_traceback(self):
        # 같은 클래스의 다른 시험 뒤에 돈다(이름순). 그때까지 쓴 열람 키가 mitmdump 로그에 하나도 없어야 한다
        self.call("GET", "/__llmsgw/my/requests", {"X-Viewer-Key": self.key()})
        time.sleep(0.3)
        text = self.gw.log_text()
        self.assertGreater(len(self.keys), 5)
        self.assertEqual([k for k in self.keys if k in text], [])
        self.assertNotIn("Traceback", text)
        self.assertNotIn("error in script", text.lower())


class RelayConnectFailureE2ETests(unittest.TestCase):
    """대시보드에 연결할 수 없으면 연결을 끊는다(mitmproxy 기본 502 화면에는 내부 주소가 적힘). DASHBOARD_MY_REQUESTS_URL 덮어쓰기."""

    @classmethod
    def setUpClass(cls):
        cls.closed_port = free_port()
        cls.key = viewer_key()
        cls.gw = MitmdumpGateway({"DASHBOARD_EVENT_URL": "http://127.0.0.1:9/api/events/ingest",
                                  "DASHBOARD_MY_REQUESTS_URL": f"http://127.0.0.1:{cls.closed_port}"})

    @classmethod
    def tearDownClass(cls):
        cls.gw.stop()
        cls.gw.cleanup()

    def test_connect_failure_closes_connection_and_gateway_stays_up(self):
        r = proxy_call(self.gw.port, "GET", f"{G}/__llmsgw/my/requests", {"X-Viewer-Key": self.key}, timeout=30)
        self.assertIsNone(r["status"], (r.get("status"), r["body"][:200]))
        r = proxy_call(self.gw.port, "GET", f"{G}/__llmsgw/health")
        self.assertEqual(r["status"], 200)
        time.sleep(0.3)
        text = self.gw.log_text()
        self.assertIn("[MY-REQUESTS] dashboard relay failed", text)
        self.assertNotIn(self.key, text)
        self.assertNotIn("Traceback", text)


if __name__ == "__main__":
    unittest.main()
