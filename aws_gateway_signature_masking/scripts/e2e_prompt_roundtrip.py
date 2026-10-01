#!/usr/bin/env python3
"""Run client -> :8081 Gateway -> Detection -> masked mock GPT round trip.

This uses the candidate's real ``gateway.request`` hook and Detection pipeline.
Only mitmproxy's transport shell, Redis, dashboard delivery, and the external GPT
endpoint are replaced with local test doubles. No sensitive value leaves localhost.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import threading
import types
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = Path(os.getenv("E2E_GATEWAY_DIR", ROOT / "worktrees" / "candidate_8081_signature_masking"))
DETECTION = Path(os.getenv("E2E_DETECTION_DIR", ROOT.parent / "detection"))


class Headers(dict):
    def __init__(self, values=()):
        super().__init__((str(k).lower(), str(v)) for k, v in dict(values).items())

    def __setitem__(self, key, value):
        super().__setitem__(str(key).lower(), str(value))

    def __delitem__(self, key):
        super().__delitem__(str(key).lower())

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)


class FakeResponse:
    def __init__(self, status_code, content=b"", headers=None):
        self.status_code = status_code
        self.raw_content = content
        self.headers = Headers(headers or {})

    @classmethod
    def make(cls, status_code, content=b"", headers=None):
        return cls(status_code, content, headers)


class FakeRequest:
    def __init__(self, body: bytes, headers):
        self.method = "POST"
        self.host = "api.openai.com"
        self.pretty_host = self.host
        self.path = "/v1/responses"
        self.headers = Headers(headers)
        self.raw_content = body

    def get_text(self):
        return self.raw_content.decode("utf-8")

    def set_text(self, value):
        self.raw_content = value.encode("utf-8")


class FakeFlow:
    def __init__(self, request):
        self.request = request
        self.response = None
        self.metadata = {}
        self.client_conn = types.SimpleNamespace(peername=("127.0.0.1", 50000))


class NoRedis:
    """Makes WindowHash report error and fall through to Signature, as designed."""


def install_mitmproxy_stub():
    http_module = types.ModuleType("mitmproxy.http")
    http_module.Response = FakeResponse
    http_module.HTTPFlow = FakeFlow
    package = types.ModuleType("mitmproxy")
    package.http = http_module
    sys.modules["mitmproxy"] = package
    sys.modules["mitmproxy.http"] = http_module


def install_requests_stub():
    """Satisfy the unused dashboard sender import without installing packages."""
    module = types.ModuleType("requests")
    module.RequestException = OSError

    class UnusedSession:
        def __init__(self):
            self.trust_env = False

        def post(self, *_args, **_kwargs):
            raise OSError("dashboard transport disabled in E2E harness")

    module.Session = UnusedSession
    sys.modules["requests"] = module


def read_json(handler):
    size = int(handler.headers.get("content-length", "0"))
    return json.loads(handler.rfile.read(size).decode("utf-8"))


def send_json(handler, status, body):
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def configure_v2_policy_if_present(pipeline, directory):
    """Give the AWS DB-policy build an isolated MASK_FULL policy for E2E."""
    if not hasattr(pipeline, "policy_store"):
        return None
    path = directory / "e2e-policy.db"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE detection_policies (
            policy_id TEXT PRIMARY KEY, target_type TEXT, target_value TEXT,
            action TEXT CHECK (action IN ('ALLOW','MASK','BLOCK')),
            priority INTEGER, version INTEGER, enabled INTEGER
        );
        INSERT INTO detection_policies VALUES ('POLICY-PII', 'CATEGORY', 'PII', 'MASK', 100, 1, 1);
        INSERT INTO detection_policies VALUES ('POLICY-CREDENTIAL', 'CATEGORY', 'CREDENTIAL', 'MASK', 100, 1, 1);
    """)
    connection.commit()
    connection.close()
    pipeline.policy_store.configure_database(str(path))
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway-port", type=int, default=8081)
    parser.add_argument("--detection-port", type=int, default=18000)
    parser.add_argument("--upstream-port", type=int, default=18080)
    args = parser.parse_args()

    os.environ["DETECTION_BASE_URL"] = f"http://127.0.0.1:{args.detection_port}"
    os.environ.setdefault("SIGNATURE_POLICY_JSON", json.dumps({"default_action": "mask_full"}))
    os.environ.setdefault("DETECTION_LOG_PATH", "/tmp/signature-e2e-decisions.jsonl")

    install_mitmproxy_stub()
    install_requests_stub()
    sys.path.insert(0, str(DETECTION))
    sys.path.insert(0, str(CANDIDATE))
    from detection_service import pipeline
    import gateway
    policy_tmp = tempfile.TemporaryDirectory(prefix="signature-policy-")
    configure_v2_policy_if_present(pipeline, Path(policy_tmp.name))

    # Dashboard/event delivery is orthogonal to masking and would wait three seconds.
    gateway.send_to_next_module = lambda event: None
    upstream_received = {}

    class DetectionHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/detect":
                send_json(self, 404, {"error": "not_found"})
                return
            request = read_json(self)
            response = pipeline.run(
                NoRedis(),
                request["normalized_text"],
                request_id=request["request_id"],
                source=request.get("source"),
                decision_log=None,
            )
            send_json(self, 200, response.model_dump())

        def log_message(self, *_):
            pass

    class UpstreamHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = read_json(self)
            upstream_received["body"] = body
            send_json(self, 200, {"id": "mock-response", "received_input": body.get("input")})

        def log_message(self, *_):
            pass

    upstream_url = f"http://127.0.0.1:{args.upstream_port}/v1/responses"

    class GatewayHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("content-length", "0"))
            original = self.rfile.read(size)
            flow = FakeFlow(FakeRequest(original, self.headers))
            gateway.request(flow)
            if flow.response is not None:
                self.send_response(flow.response.status_code)
                for key, value in flow.response.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(flow.response.raw_content)
                return
            upstream_request = urllib.request.Request(
                upstream_url,
                data=flow.request.raw_content,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(upstream_request, timeout=3) as response:
                payload = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type"))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        def log_message(self, *_):
            pass

    servers = [
        ThreadingHTTPServer(("127.0.0.1", args.detection_port), DetectionHandler),
        ThreadingHTTPServer(("127.0.0.1", args.upstream_port), UpstreamHandler),
        ThreadingHTTPServer(("127.0.0.1", args.gateway_port), GatewayHandler),
    ]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    original_value = "010-1234-5678"
    request_body = {"model": "gpt-test", "input": f"연락처는 {original_value} 입니다"}
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{args.gateway_port}/v1/responses",
            data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            client_response = json.loads(response.read().decode("utf-8"))
    finally:
        for server in reversed(servers):
            server.shutdown()
            server.server_close()
        policy_tmp.cleanup()

    forwarded = upstream_received.get("body")
    forwarded_input = forwarded.get("input") if forwarded else None
    ok = (
        client_response.get("received_input") == forwarded_input
        and original_value not in (forwarded_input or "")
        and "[KR_PHONE_NUMBER]" in (forwarded_input or "")
    )
    print("\n=== E2E PROMPT ROUND TRIP ===")
    print("client input:       연락처는 <PHONE> 입니다")
    print("upstream received: ", forwarded_input)
    print("client received:   ", client_response)
    print("result:             ", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
