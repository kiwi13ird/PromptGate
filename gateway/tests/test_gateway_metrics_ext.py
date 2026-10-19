"""Gateway 실시간 지표 확장 칸(2026-10-15) - 표본 수·검사 요청 분모·브라우저 취소·IP 안 확장 ID 묶음.

감사(docs/audit-2026-10-15/traffic-system-gateway.md 1·2·3·4·12번)에서 나온 Gateway 쪽 산정 오류를 고친 것을 본다.
  - 실시간 P95·평균의 실제 표본 수(latency_samples)를 보낸다. 표본 0건이면 평균·P95는 0.0이 아니라 null
  - '검사 응답 없음'·'시간 초과' 비율의 검사 요청 분모(inspected_requests)와 분자 건수(반올림 없이)를 보낸다
  - 브라우저가 답변 스트림을 취소한 것(HTTP/2 CANCEL·HTTP/1 클라이언트 끊김)을 연결 오류와 따로 센다
  - 같은 IP 뒤 확장 프로그램이 여럿이면 IP 항목 안에 확장 ID별 묶음(by_client)을 보낸다
  - 옛 대시보드(10/14 운영 app.mjs)는 모르는 칸이 오면 지표 전체를 거부하므로, 응답에 metrics_ext가 온 뒤에만 싣는다
실제 mitmproxy flow로 request()·response()·error() 훅을 지나고 지표 전송기 값(_publisher_snapshot)을 본다.
가짜 값만 쓴다(문서용 IP 203.0.113.x, 가짜 확장 프로그램 id). Detection·대시보드는 가짜다(127.0.0.1 임시 포트).
실행: python -m unittest tests.test_gateway_metrics_ext -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import contextlib
import io
import json
import math
import threading
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from mitmproxy import flow as mflow  # noqa: E402
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
from dashboard_event_sender import DeliveryResult, send_dashboard_metrics  # noqa: E402
from gateway_client_tracker import ClientTracker  # noqa: E402

try:
    from gateway_metrics_ext import MetricsExtNegotiator  # noqa: E402
except ImportError:   # 고치기 전 코드(이 모듈 없음)로 같은 시험을 돌려 실패를 확인할 때: 아무것도 켜지 않는 대역
    class MetricsExtNegotiator:
        def __init__(self, **_):
            pass

        def include(self):
            return False

        def enabled(self):
            return False

        def offer(self, _):
            pass

        def on_metrics_status(self, _):
            pass

IP_A = "203.0.113.51"
CLIENT_A = "chrome-00000000-0000-4000-8000-0000000000a1"
CLIENT_B = "chrome-00000000-0000-4000-8000-0000000000b2"
T0 = 1_760_000_000.0

# ---- 운영 대시보드 서버(52.79.153.42 /opt/llm-security-dashboard/server/app.mjs md5 905db51e, 10/14 11:03 UTC)의
#      gatewayMetricsPayload·parseGatewayClients 규칙을 그대로 옮긴 것(옛 서버가 받는지 보는 데만 쓴다)
OLD_FIELDS = ["active_clients", "concurrent_requests", "requests_per_sec", "avg_latency_ms", "p95_latency_ms",
              "timeout_rate", "degraded_rate", "total_requests", "completed_requests", "error_requests",
              "action_distribution", "llm_distribution", "detector_distribution", "window_seconds", "event_delivery",
              "settings_applied", "clients", "relay", "access_applied"]
OLD_OPTIONAL = {"event_delivery", "settings_applied", "clients", "relay", "access_applied"}
OLD_CLIENT_FIELDS = ["ip", "client_id", "connections", "inflight", "requests_5m", "targets", "first_seen_at", "last_seen_at"]
EXT_FIELDS = {"metrics_ext", "latency_samples", "inspected_requests", "degraded_requests", "timeout_requests",
              "inspected_timeout_requests", "client_cancelled_requests", "connection_error_requests"}


def _finite(value, *, integer=False, maximum=None):
    return (type(value) in (int, float) and math.isfinite(value) and value >= 0
            and (not integer or float(value).is_integer()) and (maximum is None or value <= maximum))


def old_dashboard_accepts(body):
    """(HTTP 상태, clients를 받았는지). 400 = 모르는 칸·빠진 칸, 422 = 값 형식, 202 = 받음."""
    keys = set(body)
    if keys - set(OLD_FIELDS) or (set(OLD_FIELDS) - OLD_OPTIONAL) - keys:
        return 400, False
    for name in ("active_clients", "concurrent_requests", "total_requests", "completed_requests", "error_requests",
                 "window_seconds"):
        if not _finite(body[name], integer=True):
            return 422, False
    for name in ("requests_per_sec", "avg_latency_ms", "p95_latency_ms"):
        if not _finite(body[name]):
            return 422, False
    for name in ("timeout_rate", "degraded_rate"):
        if not _finite(body[name], maximum=1):
            return 422, False
    for name in ("action_distribution", "llm_distribution", "detector_distribution"):
        if not isinstance(body[name], dict) or not all(_finite(v, integer=True) for v in body[name].values()):
            return 422, False
    clients_ok = False
    if "clients" in body:
        try:
            for item in body["clients"]:
                expected = OLD_CLIENT_FIELDS + (["waiting"] if "waiting" in item else [])
                assert len(item) == len(expected) and set(item) == set(expected)
                assert ip_address(item["ip"])
            clients_ok = True
        except Exception:
            clients_ok = False    # 서버는 지표는 받고 clients만 버린다
    return 202, clients_ok


def new_dashboard_accepts(body):
    """CONTRACT.md대로 확장 칸을 아는 대시보드(시험용): 확장 칸·null 평균을 받고 나머지는 옛 규칙."""
    legacy = {key: value for key, value in body.items() if key not in EXT_FIELDS}
    if body.get("metrics_ext") == 1:
        for name in EXT_FIELDS - {"metrics_ext"}:
            if not _finite(body.get(name), integer=True):
                return 422, False
        if body["latency_samples"] == 0:
            if body["avg_latency_ms"] is not None or body["p95_latency_ms"] is not None:
                return 422, False
            legacy["avg_latency_ms"] = legacy["p95_latency_ms"] = 0.0
        legacy["clients"] = [{k: v for k, v in item.items() if k != "by_client"} for item in body.get("clients", [])]
    return old_dashboard_accepts(legacy)


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


def fresh_metrics():
    return {key: (Counter() if isinstance(value, Counter) else 0) for key, value in gateway._gateway_metrics.items()}


class MetricsExtFlowBase(bundle.Base):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.output = io.StringIO()
        for name, value in (("_client_tracker", ClientTracker(clock=self.clock)),
                            ("_gateway_metrics", fresh_metrics()),
                            ("_gateway_latencies_ms", gateway.deque(maxlen=gateway.METRICS_LATENCY_MAX)),
                            ("_gateway_client_inflight", Counter()),
                            ("_metrics_ext", MetricsExtNegotiator(logger=self.output.write))):
            patcher = mock.patch.object(gateway, name, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        # 지표 전송기 응답 처리는 실제 연결(_each(설정, 접속 차단, 확장 칸))을 쓰되 협상기만 이 시험 것으로
        publisher = gateway.MetricsPublisher(
            gateway._publisher_snapshot,
            on_payload=gateway._each(gateway.GATEWAY_SETTINGS.offer, gateway.GATEWAY_ACCESS.offer, gateway._metrics_ext.offer),
            on_status=gateway._each(gateway.GATEWAY_SETTINGS.on_metrics_status, gateway.GATEWAY_ACCESS.on_metrics_status,
                                    gateway._metrics_ext.on_metrics_status))
        self.publisher = publisher
        self.conns = {}

    def client(self, name, ip=IP_A, port=50000):
        """확장 프로그램 하나의 TCP 연결(같은 연결로 여러 요청)."""
        if name not in self.conns:
            conn = tflow.tclient_conn()
            conn.peername = (ip, port + len(self.conns))
            with contextlib.redirect_stdout(self.output):
                gateway.client_connected(conn)
            self.conns[name] = conn
        return self.conns[name]

    def run_flow(self, req, *, conn="a", client_id=CLIENT_A):
        if client_id:
            req.headers["x-llmsgw-client-id"] = client_id
        flow = tflow.tflow(req=req)
        flow.client_conn = self.client(conn)
        self.sent = req.raw_content
        with contextlib.redirect_stdout(self.output):
            bundle.run_hook(gateway.request(flow))
        return flow

    def get(self, host, path, **kwargs):
        req = tutils.treq(host=host, port=443, scheme=b"https", method=b"GET", path=path.encode(), content=b"",
                          headers=((b"accept", b"*/*"),))
        return self.run_flow(req, **kwargs)

    def prompt(self, text, **kwargs):
        req = tutils.treq(host="chatgpt.com", port=443, scheme=b"https", method=b"POST", path=b"/backend-api/f/conversation",
                          content=json.dumps({"action": "next", "messages": [{"author": {"role": "user"},
                                              "content": {"content_type": "text", "parts": [text]}}]},
                                             ensure_ascii=False).encode(),
                          headers=((b"content-type", b"application/json"),))
        return self.run_flow(req, **kwargs)

    def finish(self, flow, *, upstream_seconds=0.0):
        with contextlib.redirect_stdout(self.output):
            return super().finish(flow, upstream_seconds=upstream_seconds)

    def end_with_error(self, flow, message):
        """응답 대신 mitmproxy 오류로 끝남(error 훅)."""
        flow.error = mflow.Error(message)
        with contextlib.redirect_stdout(self.output), mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
            gateway.error(flow)
        return flow

    def payload(self):
        with contextlib.redirect_stdout(self.output):
            body = gateway._publisher_snapshot()
        json.dumps(body, allow_nan=False)
        return body

    def answer(self, body):
        """대시보드 응답을 실제 응답 처리 연결로 넘긴다(전송기 _deliver: on_payload → on_status)."""
        with contextlib.redirect_stdout(self.output):
            self.publisher._deliver(body)

    def advertise(self):
        self.answer(DeliveryResult(status="sent", http_status=202, payload={"accepted": True, "metrics_ext": 1}))


class NegotiationTests(MetricsExtFlowBase):
    def test_old_dashboard_keeps_receiving_the_10_14_fields_only(self):
        """옛 대시보드는 metrics_ext를 알리지 않는다 → 확장 칸 없이 10/14 칸 그대로(옛 서버 규칙으로 202·clients 받음)."""
        flows = [self.prompt("회의 일정 정리해 줘"), self.get("assets-proxy.anthropic.com", "/a.js")]
        for flow in flows:
            self.finish(flow)
        for _ in range(3):
            body = self.payload()
            self.assertFalse(EXT_FIELDS & set(body), sorted(EXT_FIELDS & set(body)))
            self.assertEqual(old_dashboard_accepts(body), (202, True))
            self.assertTrue(all("by_client" not in row for row in body["clients"]))
            self.answer(DeliveryResult(status="sent", http_status=202, payload={"accepted": True}))
        empty = self.fresh_payload_without_samples()
        self.assertEqual((empty["avg_latency_ms"], empty["p95_latency_ms"]), (0.0, 0.0))   # 옛 서버에는 0.0 그대로
        self.assertEqual(old_dashboard_accepts(empty), (202, True))

    def fresh_payload_without_samples(self):
        with mock.patch.object(gateway, "_gateway_latencies_ms", gateway.deque(maxlen=10)):
            return self.payload()

    def test_extension_fields_start_after_the_dashboard_advertises_them(self):
        self.assertNotIn("metrics_ext", self.payload())
        self.advertise()
        body = self.payload()
        self.assertEqual(body["metrics_ext"], 1)
        self.assertTrue(EXT_FIELDS <= set(body))
        self.assertEqual(old_dashboard_accepts(body)[0], 400)          # 그래서 옛 서버에는 보내면 안 된다
        self.assertEqual(new_dashboard_accepts(body), (202, True))
        self.assertIn("[METRICS] ext fields on version=1", self.output.getvalue())

    def test_rolled_back_dashboard_stops_the_extension_at_once(self):
        self.advertise()
        self.assertIn("metrics_ext", self.payload())
        self.answer(DeliveryResult(status="sent", http_status=202, payload={"accepted": True}))
        body = self.payload()
        self.assertFalse(EXT_FIELDS & set(body))
        self.assertEqual(old_dashboard_accepts(body), (202, True))

    def test_http_400_with_extension_fields_falls_back_and_waits(self):
        neg = MetricsExtNegotiator(clock=self.clock, logger=self.output.write)
        neg.offer({"metrics_ext": 1})
        self.assertTrue(neg.include())
        neg.on_metrics_status(400)                                     # 확장 칸을 실은 전송이 거부됨
        self.assertFalse(neg.include())
        neg.offer({"metrics_ext": 1})                                  # 곧바로 다시 알려도 300초 동안은 싣지 않는다
        self.assertFalse(neg.include())
        self.clock.now = T0 + 299
        neg.offer({"metrics_ext": 1})
        self.assertFalse(neg.enabled())
        self.clock.now = T0 + 300
        neg.offer({"metrics_ext": 1})
        self.assertTrue(neg.include())
        neg.on_metrics_status(422)                                     # 400만 본다
        self.assertTrue(neg.enabled())
        self.assertIn("[METRICS] ext fields off reason=http_400", self.output.getvalue())

    def test_400_without_extension_fields_changes_nothing(self):
        neg = MetricsExtNegotiator(clock=self.clock, logger=self.output.write)
        self.assertFalse(neg.include())                                # 이번 전송은 옛 칸만
        neg.offer({"metrics_ext": 1})                                  # (응답 순서상 같은 전송의 2xx는 오지 않지만) 켜짐
        neg.on_metrics_status(400)                                     # 앞 전송(확장 칸 없음)의 400은 무시
        self.assertTrue(neg.enabled())

    def test_only_a_positive_integer_turns_the_extension_on(self):
        neg = MetricsExtNegotiator(clock=self.clock, logger=self.output.write)
        for payload in (None, {}, {"metrics_ext": True}, {"metrics_ext": "1"}, {"metrics_ext": 0}, {"metrics_ext": 1.0},
                        [1], {"gateway_settings": None}):
            neg.offer(payload)
            self.assertFalse(neg.enabled(), payload)
        neg.offer({"metrics_ext": 2})                                  # 더 높은 판도 1판 칸을 받는다고 본다
        self.assertTrue(neg.enabled())
        neg.offer(None)                                                # 실패한 전송(응답 없음)은 상태를 바꾸지 않는다
        self.assertTrue(neg.enabled())

    def test_round_trips_against_old_new_and_broken_dashboards_over_http(self):
        """실제 전송 함수(send_dashboard_metrics)로 127.0.0.1 가짜 대시보드 세 종류에 10번씩 보낸다."""
        results = {}
        for kind in ("old", "new", "broken"):
            with FakeDashboard(kind) as server, mock.patch.dict(gateway.os.environ, {
                    "DASHBOARD_METRICS_URL": server.url, "DASHBOARD_INGEST_TOKEN": "test-token-not-used"}):
                neg = MetricsExtNegotiator(clock=self.clock, logger=self.output.write)
                with mock.patch.object(gateway, "_metrics_ext", neg, create=True):
                    publisher = gateway.MetricsPublisher(
                        gateway._publisher_snapshot, on_payload=gateway._each(neg.offer), on_status=gateway._each(neg.on_metrics_status))
                    for _ in range(10):
                        with contextlib.redirect_stdout(self.output):
                            result = send_dashboard_metrics(gateway._publisher_snapshot(), logger=self.output.write)
                        publisher._deliver(result)
                results[kind] = server.statuses
        self.assertEqual(results["old"], [202] * 10)                       # 옛 서버: 한 번도 거부되지 않음
        self.assertEqual(results["new"], [202] * 10)
        self.assertEqual(results["broken"], [202, 400] + [202] * 8)        # 알리고도 거부하는 서버: 한 번 거부 뒤 옛 칸으로
        self.assertEqual(FakeDashboard.ext_seen["old"], 0)
        self.assertEqual(FakeDashboard.ext_seen["new"], 9)                 # 첫 전송(알림 전) 뒤로는 확장 칸
        self.assertEqual(FakeDashboard.ext_seen["broken"], 1)


class FakeDashboard:
    """old = 10/14 운영 규칙(모르는 칸 400, metrics_ext 알리지 않음) / new = CONTRACT.md / broken = 알리지만 확장 칸은 400."""
    ext_seen: dict = {}

    def __init__(self, kind):
        self.kind = kind
        self.statuses = []
        FakeDashboard.ext_seen[kind] = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):   # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "metrics_ext" in body:
                    FakeDashboard.ext_seen[owner.kind] += 1
                judge = new_dashboard_accepts if owner.kind == "new" else old_dashboard_accepts
                status, _ = judge(body)
                owner.statuses.append(status)
                reply = {"accepted": True} if status == 202 else {"error": "invalid"}
                if status == 202 and owner.kind in ("new", "broken"):
                    reply["metrics_ext"] = 1
                data = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api/traffic/metrics"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class LatencySampleTests(MetricsExtFlowBase):
    def test_no_samples_means_null_average_and_p95_with_the_sample_count(self):
        """판정 요청 0건·자산만 있으면 옛 값은 '0초'였다(감사 2번). 확장 칸에서는 null + 표본 0."""
        self.advertise()
        for flow in [self.get("assets-proxy.anthropic.com", f"/a{i}.js") for i in range(5)]:
            self.finish(flow)
        body = self.payload()
        self.assertEqual((body["completed_requests"], body["latency_samples"]), (5, 0))
        self.assertIsNone(body["avg_latency_ms"])
        self.assertIsNone(body["p95_latency_ms"])
        self.assertEqual(new_dashboard_accepts(body), (202, True))

    def test_sample_count_is_the_processing_time_sample_not_completed_requests(self):
        """완료 193·표본 1처럼 완료 수를 표본 수로 쓰면 '20건 미만'이 안 뜬다(감사 1번). 표본 = 평균·P95를 낸 값 수."""
        self.advertise()
        flows = [self.get("claude.ai", f"/api/poll{i}") for i in range(6)] + [self.prompt("회의 일정 정리해 줘"),
                                                                              self.prompt(f"로드맵 {bundle.SECRET} 요약")]
        for flow in flows:
            self.finish(flow)
        body = self.payload()
        self.assertEqual(body["completed_requests"], 8)
        self.assertEqual(body["latency_samples"], 2)
        self.assertEqual(body["latency_samples"], len(gateway._gateway_latencies_ms))
        self.assertIsInstance(body["avg_latency_ms"], float)
        self.assertIsInstance(body["p95_latency_ms"], float)

    def test_sample_count_follows_the_5000_sample_window(self):
        self.advertise()
        with mock.patch.object(gateway, "_gateway_latencies_ms", gateway.deque([1.0] * 5000, maxlen=5000)):
            self.assertEqual(self.payload()["latency_samples"], 5000)


class InspectedDenominatorTests(MetricsExtFlowBase):
    def test_rates_get_an_inspected_request_denominator_and_raw_counts(self):
        """응답 없음 비율 분모가 전체 HTTP 요청(자산 포함)이라 수십~수백 배 작게 보였다(감사 3번)."""
        self.advertise()
        flows = [self.get("assets-proxy.anthropic.com", f"/a{i}.js") for i in range(8)]
        flows.append(self.prompt("회의 일정 정리해 줘"))
        flows.append(self.prompt(f"로드맵 {bundle.SECRET} 요약"))                     # 차단
        gateway.check_detection = lambda *args, **kwargs: bundle.failure_result(
            "UNREACHABLE", kwargs.get("failure_policy") or "FAIL_OPEN", kwargs["request_id"])
        degraded = self.prompt("응답 없음 시험")
        self.assertTrue(degraded.metadata.get("gw_degraded"))
        flows.append(degraded)
        for flow in flows:
            self.finish(flow)
        body = self.payload()
        self.assertEqual((body["total_requests"], body["completed_requests"]), (11, 11))
        self.assertEqual((body["inspected_requests"], body["degraded_requests"]), (3, 1))
        self.assertEqual(body["degraded_rate"], round(1 / 11, 4))                     # 옛 칸은 그대로(전체 요청 분모)
        self.assertEqual(body["timeout_requests"], 0)
        self.assertLessEqual(body["degraded_requests"], body["inspected_requests"])

    def test_timeouts_keep_the_old_numerator_and_add_the_inspected_part(self):
        self.advertise()
        asset = self.get("cdn.oaistatic.com", "/assets/main.css")
        self.end_with_error(asset, "Error connecting to cdn.oaistatic.com: timed out")
        question = self.prompt("회의 일정 정리해 줘")
        self.assertIsNone(question.response)                                          # 검사 뒤 전달 → upstream 시간 초과
        self.end_with_error(question, "Server connection to chatgpt.com timed out")
        body = self.payload()
        self.assertEqual((body["timeout_requests"], body["inspected_timeout_requests"], body["inspected_requests"]), (2, 1, 1))
        self.assertEqual(body["timeout_rate"], round(2 / 2, 4))                       # 옛 칸 그대로
        self.assertEqual((body["error_requests"], body["connection_error_requests"]), (2, 2))

    def test_counts_survive_without_the_extension(self):
        """확장 칸을 아직 안 보내도 셈은 한다 → 대시보드가 알리면 시작 이후 누적이 바로 나온다(요청마다 남기는 지표 줄에도)."""
        self.finish(self.prompt("회의 일정 정리해 줘"))
        self.assertNotIn("inspected_requests", self.payload())
        line = [json.loads(text) for text in self.output.getvalue().splitlines() if text.startswith('{"active_clients"')][-1]
        self.assertEqual((line["inspected_requests"], line["latency_samples"]), (1, 1))
        self.assertNotIn("metrics_ext", line)
        self.advertise()
        self.assertEqual(self.payload()["inspected_requests"], 1)


class ClientCancelTests(MetricsExtFlowBase):
    def test_browser_cancel_is_counted_apart_from_connection_errors(self):
        """연결 오류 132건 중 다수가 브라우저 스트림 취소였다(감사 4번). error_requests(옛 칸)는 그대로 둔다."""
        self.advertise()
        cases = [("stream reset by client (CANCEL)", True), ("Client disconnected.", True),
                 ("stream reset by client (INTERNAL_ERROR)", False), ("peer closed connection", False),
                 ("Connection killed.", False), ("[Errno -3] Temporary failure in name resolution", False)]
        for index, (message, cancelled) in enumerate(cases):
            flow = self.get("chatgpt.com", f"/backend-api/stream{index}")
            self.end_with_error(flow, message)
            self.assertEqual(gateway._gateway_error_is_client_cancel(flow), cancelled, message)
        body = self.payload()
        self.assertEqual(body["error_requests"], 6)
        self.assertEqual((body["client_cancelled_requests"], body["connection_error_requests"]), (2, 4))

    def test_a_cancelled_streaming_answer_after_inspection(self):
        self.advertise()
        question = self.prompt("회의 일정 정리해 줘")
        question.response = tutils.tresp(status_code=200)                             # 답변 스트리밍 중 브라우저가 멈춤
        self.end_with_error(question, "stream reset by client (CANCEL)")
        body = self.payload()
        self.assertEqual((body["error_requests"], body["client_cancelled_requests"], body["connection_error_requests"]),
                         (1, 1, 0))
        self.assertEqual((body["inspected_requests"], body["latency_samples"]), (1, 1))


class ByClientTests(MetricsExtFlowBase):
    def rows(self):
        return {row["ip"]: row for row in self.payload()["clients"]}

    def test_two_extensions_behind_one_ip_are_split(self):
        """IP당 1줄·client_id는 마지막 값이라 '이 IP 확장 n개'가 나올 수 없었다(감사 12번)."""
        self.advertise()
        a1 = self.prompt("회의 일정 정리해 줘", conn="a", client_id=CLIENT_A)
        a2 = self.get("assets-proxy.anthropic.com", "/a.js", conn="a", client_id=None)  # 헤더 없는 자산: 연결의 확장 ID로
        b1 = self.prompt("주간 보고 요약", conn="b", client_id=CLIENT_B)
        b2 = self.prompt(f"주민번호 {bundle.RRN} 확인", conn="b", client_id=CLIENT_B)
        self.client("idle")                                                         # 아직 요청 없는 연결
        for flow in (a1, b1, b2):
            self.finish(flow)
        row = self.rows()[IP_A]
        self.assertEqual((row["client_id"], row["connections"], row["inflight"], row["requests_5m"]), (CLIENT_B, 3, 1, 3))
        groups = {group["client_id"]: group for group in row["by_client"]}
        self.assertEqual(set(groups), {CLIENT_A, CLIENT_B, None})
        self.assertEqual(set(groups[CLIENT_A]), {"client_id", "connections", "inflight", "waiting", "requests_5m",
                                                 "targets", "first_seen_at", "last_seen_at"})
        self.assertEqual([(groups[k]["connections"], groups[k]["inflight"], groups[k]["requests_5m"], groups[k]["targets"])
                          for k in (CLIENT_A, CLIENT_B, None)],
                         [(1, 1, 1, {"ChatGPT": 1}), (1, 0, 2, {"ChatGPT": 2}), (1, 0, 0, {})])
        for name in ("connections", "inflight", "waiting", "requests_5m"):            # 묶음 합 = IP 값
            self.assertEqual(sum(group[name] for group in row["by_client"]), row[name], name)
        self.finish(a2)
        with contextlib.redirect_stdout(self.output):
            gateway.client_disconnected(self.conns["idle"])
        groups = {group["client_id"]: group for group in self.rows()[IP_A]["by_client"]}
        self.assertEqual(set(groups), {CLIENT_A, CLIENT_B})                            # 빈 null 묶음은 싣지 않는다
        self.assertEqual(new_dashboard_accepts(self.payload()), (202, True))

    def test_without_the_extension_rows_keep_the_9_field_contract(self):
        self.finish(self.prompt("회의 일정 정리해 줘", conn="a", client_id=CLIENT_A))
        self.finish(self.prompt("주간 보고 요약", conn="b", client_id=CLIENT_B))
        rows = self.payload()["clients"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), set(OLD_CLIENT_FIELDS) | {"waiting"})

    def test_quiet_extension_stays_listed_for_ten_minutes(self):
        self.advertise()
        self.finish(self.prompt("회의 일정 정리해 줘", conn="a", client_id=CLIENT_A))
        with contextlib.redirect_stdout(self.output):
            gateway.client_disconnected(self.conns["a"])
        self.clock.now = T0 + 400                                                    # 5분 창은 지났고 10분은 안 됨
        self.finish(self.prompt("주간 보고 요약", conn="b", client_id=CLIENT_B))
        groups = {g["client_id"]: g for g in self.rows()[IP_A]["by_client"]}
        self.assertEqual((groups[CLIENT_A]["requests_5m"], groups[CLIENT_A]["connections"]), (0, 0))
        self.assertEqual(groups[CLIENT_B]["requests_5m"], 1)
        self.assertEqual([g["client_id"] for g in self.rows()[IP_A]["by_client"]], [CLIENT_B, CLIENT_A])   # 최근 활동 순
        self.clock.now = T0 + 601
        self.assertEqual([g["client_id"] for g in self.rows()[IP_A]["by_client"]], [CLIENT_B])

    def test_many_extension_ids_are_bounded(self):
        tracker = ClientTracker(clock=self.clock)
        for index in range(80):
            tracker.request_inspected(IP_A, "ChatGPT", f"chrome-{index:04d}")
        row, = tracker.snapshot(by_client=True)
        self.assertEqual(row["requests_5m"], 80)
        self.assertEqual(len(row["by_client"]), 20)                                  # 목록 상한
        self.assertLessEqual(len(tracker._entries[IP_A].seen), 50)                   # 시각 기록 상한


if __name__ == "__main__":
    unittest.main()
