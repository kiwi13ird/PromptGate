"""연결 중인 IP 표 '최근 5분 검사 요청'(2026-10-15) - requests_5m·targets는 보안 검사를 거친 요청만 센다.

운영에서 IP 한 줄이 '최근 5분 요청 186'으로 보였다(질문 몇 개를 보냈을 뿐). 10/14까지는 LLM 사이트로 간 HTTP 요청 전체
(페이지 로딩·이미지·스크립트 자산·폴링)를 요청 시작 때 셌기 때문이다. 이 시험은 실제 mitmproxy flow로 request()·response()
훅을 지나고 지표 전송기 값(_publisher_snapshot의 clients)을 본다.
  - 자산·페이지·폴링·상태 확인은 세지 않는다(처리 중·연결 수에는 그대로 잡힌다)
  - 질문·파일 업로드는 차단·마스킹·허용·검사 응답 없음·검사 못 한 파일 모두 1건씩
  - 한 요청 안에서 Detection을 여러 번 불러도 1건, 같은 flow를 두 번 마쳐도 1건
  - 5분(300초)이 지나면 빠진다
가짜 값만 쓴다(문서용 IP 203.0.113.x·198.51.100.x, 가짜 확장 프로그램 id). Detection·대시보드는 가짜다.
실행: python -m unittest tests.test_gateway_request_count -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
from gateway_client_tracker import ClientTracker  # noqa: E402
from tests.gw_support import png_bytes, run_hook  # noqa: E402

IP_A = "203.0.113.41"
IP_B = "198.51.100.42"
CLIENT_A = "chrome-00000000-0000-4000-8000-0000000000c1"
T0 = 1_760_000_000.0


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class RequestCountTests(bundle.Base):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        patcher = mock.patch.object(gateway, "_client_tracker", ClientTracker(clock=self.clock))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.peer = (IP_A, 50200)
        self.output = io.StringIO()

    # -- flow 만들기: 확장 프로그램 식별 머리 + 접속 IP를 붙여 request() 훅까지
    def run_flow(self, req):
        req.headers["x-llmsgw-client-id"] = CLIENT_A
        flow = tflow.tflow(req=req)
        flow.client_conn.peername = self.peer
        self.sent = req.raw_content
        with contextlib.redirect_stdout(self.output):
            gateway.client_connected(flow.client_conn)
            run_hook(gateway.request(flow))
        return flow

    def finish(self, flow, *, upstream_seconds=0.0):
        with contextlib.redirect_stdout(self.output):
            return super().finish(flow, upstream_seconds=upstream_seconds)

    def get(self, host, path, *, scheme=b"https", port=443):
        req = tutils.treq(host=host, port=port, scheme=scheme, method=b"GET", path=path.encode(), content=b"",
                          headers=((b"accept", b"*/*"),))
        return self.run_flow(req)

    def row(self, ip=IP_A):
        snapshot = gateway._publisher_snapshot()
        json.dumps(snapshot)
        return {r["ip"]: r for r in snapshot["clients"]}.get(ip)

    def counted(self, ip=IP_A):
        row = self.row(ip)
        return (row["requests_5m"], row["targets"]) if row else None

    # -- 자산·페이지·폴링은 세지 않는다
    def test_page_loads_assets_and_polling_are_not_counted(self):
        total_before = gateway._gateway_metrics_snapshot()["total_requests"]
        flows = [
            self.get("assets-proxy.anthropic.com", "/claude-ai/v2/assets/v1/app.js"),     # 운영 10분 136건이던 자산
            self.get("claude.ai", "/new"),                                              # 페이지
            self.get("claude.ai", f"/api/organizations/{bundle.ORG}/chat_conversations?limit=30"),   # 목록 폴링
            self.get("api.anthropic.com", "/api/oauth/profile"),
            self.get("chatgpt.com", "/backend-api/conversations?offset=0&limit=28"),
            self.get("ab.chatgpt.com", "/v1/rgstr"),
            self.get("gemini.google.com", "/app"),
            self.get("cdn.oaistatic.com", "/assets/main.css"),
        ]
        for flow in flows:
            self.assertIsNone(flow.response, flow.request.host)                      # 그대로 통과
            self.assertFalse(flow.metadata.get("gw_inspected_counted"), flow.request.host)
        self.assertEqual(self.counted(), (0, {}))
        row = self.row()
        self.assertEqual((row["inflight"], row["connections"]), (8, 8))              # 처리 중·연결 수에는 그대로 잡힌다
        self.assertEqual(gateway._gateway_metrics_snapshot()["total_requests"] - total_before, 8)   # Gateway 실시간 지표는 그대로
        for flow in flows:
            self.finish(flow)
        self.assertEqual(self.counted(), (0, {}))
        self.assertEqual(self.row()["inflight"], 0)
        self.assertEqual(self.calls, [])                                             # Detection 호출 없음

    def test_health_check_and_relay_host_are_not_counted(self):
        flow = self.get("llm-gateway.local", "/__llmsgw/health", scheme=b"http", port=80)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(self.counted(), (0, {}))

    # -- 질문·파일 업로드는 결과와 무관하게 1건씩
    def test_prompts_and_file_uploads_are_counted_whatever_the_outcome(self):
        allowed = self.chatgpt_prompt("회의 일정 정리해 줘")
        self.assertIsNone(allowed.response)
        self.assertEqual(self.counted(), (1, {"ChatGPT": 1}))
        blocked = self.chatgpt_prompt(f"로드맵 {bundle.SECRET} 요약")
        self.assert_blocked(blocked)
        masked = self.claude_completion({"prompt": f"주민번호 {bundle.RRN} 확인"})
        self.assertEqual(masked.metadata.get("gw_action"), "mask")
        upload = self.claude_upload(("memo.txt", "text/plain", "회의 메모".encode()))
        put = self.chatgpt_put("파일 본문".encode(), "memo.txt")
        image = self.chatgpt_put(png_bytes(), "p.png")                               # 검사 못 한 파일(기본: 허용)
        self.assertEqual(image.metadata.get("gw_action"), "allow")
        self.assertFalse(image.metadata.get("gw_inspected"))
        for flow in (allowed, blocked, masked, upload, put, image):
            self.assertTrue(flow.metadata.get("gw_inspected_counted"))
            self.finish(flow)                                                      # 응답 훅은 세지 않는다
        self.assertEqual(self.counted(), (6, {"ChatGPT": 4, "Claude": 2}))

    def test_detection_unreachable_is_still_an_inspected_request(self):
        gateway.check_detection = lambda *args, **kwargs: bundle.failure_result(
            "UNREACHABLE", kwargs.get("failure_policy") or "FAIL_OPEN", kwargs["request_id"])
        flow = self.chatgpt_prompt("응답 없음 시험")
        self.assertTrue(flow.metadata.get("gw_degraded"))
        self.finish(flow)
        self.assertEqual(self.counted(), (1, {"ChatGPT": 1}))

    def test_one_request_with_several_detection_calls_counts_once(self):
        flow = self.claude_completion({"prompt": "요약", "attachments": [
            {"file_name": "a.txt", "extracted_content": "첫 메모"},
            {"file_name": "b.txt", "extracted_content": "둘째 메모"}]})
        self.assertGreaterEqual(len(self.calls), 3)                                  # 질문 + 첨부 2개
        multi = self.claude_upload(("a.txt", "text/plain", "하나".encode()), ("b.txt", "text/plain", "둘".encode()))
        self.assertGreaterEqual(len(self.calls), 5)
        self.assertEqual(self.counted(), (2, {"Claude": 2}))
        with contextlib.redirect_stdout(self.output):
            gateway._count_inspected_request(flow)                                 # 같은 요청을 또 마쳐도
            gateway._request_sync(multi)                                           # 처리 본체를 다시 지나도
        self.finish(flow)
        self.finish(multi)
        self.assertEqual(self.counted(), (2, {"Claude": 2}))

    def test_blocked_and_retried_uploads_count_each_attempt(self):
        """ChatGPT는 막힌 업로드를 같은 파일로 다시 보낸다: 시도마다 검사하므로 시도마다 1건(대시보드 이벤트는 처음 한 번)."""
        for _ in range(3):
            self.finish(self.chatgpt_put(f"기밀 {bundle.SECRET}".encode(), "plan.txt"))
        self.assertEqual(self.counted(), (3, {"ChatGPT": 3}))

    def test_gemini_upload_host_is_named_gemini(self):
        """Gemini 파일 업로드는 push.clients6.google.com(Gateway 지표 대상 호스트가 아님)으로 가지만 검사하면 센다."""
        req = tutils.treq(host="push.clients6.google.com", port=443, scheme=b"https", method=b"POST",
                          path=b"/upload/?upload_id=x&upload_protocol=resumable", content=b"x")
        flow = tflow.tflow(req=req)
        flow.client_conn.peername = (IP_B, 40000)
        flow.metadata["gw_action"] = "allow"
        gateway._count_inspected_request(flow)
        gateway._count_inspected_request(flow)
        self.assertEqual(self.counted(IP_B), (1, {"Gemini": 1}))
        api = tflow.tflow(req=tutils.treq(host="api.openai.com", port=443, scheme=b"https", method=b"POST",
                                          path=b"/v1/responses", content=b"{}"))
        api.client_conn.peername = (IP_B, 40001)
        api.metadata["gw_inspected"] = True
        gateway._count_inspected_request(api)
        self.assertEqual(self.counted(IP_B), (2, {"Gemini": 1, "ChatGPT": 1}))     # 보안 이벤트 targetLlm과 같은 이름

    def test_a_tracker_failure_never_breaks_the_request(self):
        broken = mock.Mock()
        broken.request_inspected.side_effect = RuntimeError(IP_A)
        broken.request_started.return_value = None
        with mock.patch.object(gateway, "_client_tracker", broken):
            flow = self.chatgpt_prompt("평소처럼 전달")
        self.assertIsNone(flow.response)
        self.assertIn("inspected request count omitted error_type=RuntimeError", self.output.getvalue())
        self.assertNotIn(IP_A, self.output.getvalue())

    # -- 5분 창
    def test_counts_leave_the_window_after_300_seconds(self):
        self.finish(self.chatgpt_prompt("하나"))
        self.clock.now = T0 + 120
        for flow in (self.claude_completion({"prompt": "둘"}), self.get("assets-proxy.anthropic.com", "/a.js")):
            self.finish(flow)
        self.assertEqual(self.counted(), (2, {"ChatGPT": 1, "Claude": 1}))
        self.clock.now = T0 + 299.999
        self.assertEqual(self.counted(), (2, {"ChatGPT": 1, "Claude": 1}))
        self.clock.now = T0 + 300                                                   # 첫 질문은 300초가 되면 빠진다
        self.assertEqual(self.counted(), (1, {"Claude": 1}))
        self.clock.now = T0 + 420
        self.assertEqual(self.counted(), (0, {}))
        self.assertIsNotNone(self.row())                                            # 행은 10분 활동 기준으로 남는다


class TrackerInspectedTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.tracker = ClientTracker(clock=self.clock)

    def row(self, ip=IP_A):
        return {r["ip"]: r for r in self.tracker.snapshot()}.get(ip)

    def test_started_requests_are_not_counted_until_inspected(self):
        tickets = [self.tracker.request_started(IP_A) for _ in range(186)]          # 화면 로딩 186건
        row = self.row()
        self.assertEqual((row["requests_5m"], row["targets"], row["inflight"]), (0, {}, 186))
        self.tracker.request_inspected(IP_A, "Claude")
        for ticket in tickets:
            self.tracker.request_finished(ticket)
        row = self.row()
        self.assertEqual((row["requests_5m"], row["targets"], row["inflight"]), (1, {"Claude": 1}, 0))

    def test_inspected_without_a_started_request_creates_the_row(self):
        self.tracker.request_inspected("::ffff:203.0.113.41", "Gemini")
        self.tracker.request_inspected("not-an-ip", "Gemini")
        self.tracker.request_inspected(None, "Gemini")
        self.assertEqual([(r["ip"], r["requests_5m"], r["targets"], r["inflight"], r["connections"])
                          for r in self.tracker.snapshot()], [(IP_A, 1, {"Gemini": 1}, 0, 0)])

    def test_inspection_is_activity_for_the_row(self):
        self.tracker.request_started(IP_A)
        self.clock.now = T0 + 500
        self.tracker.request_inspected(IP_A, "ChatGPT")
        self.assertEqual(self.row()["last_seen_at"], "2025-10-09T09:01:40.000Z")


if __name__ == "__main__":
    unittest.main()
