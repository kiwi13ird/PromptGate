"""연결 중인 IP 표(2026-10-12) - gateway_client_tracker 단위 시험 + 실제 mitmproxy flow·훅으로 지표 전송기까지.

가짜 값만 쓴다(문서용 IP 203.0.113.x·198.51.100.x·2001:db8::, 가짜 확장 프로그램 id). Detection·대시보드는 가짜다.
실행: python -m unittest tests.test_gateway_client_tracker -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import threading
import time
import unittest
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
import gateway_client_tracker as T  # noqa: E402
from gateway_client_tracker import ClientTracker  # noqa: E402
from tests.gw_support import run_hook  # noqa: E402

IP_A = "203.0.113.10"
IP_B = "198.51.100.20"
IP_V6 = "2001:db8::7"
CLIENT_A = "chrome-00000000-0000-4000-8000-00000000000a"
CLIENT_B = "chrome-00000000-0000-4000-8000-00000000000b"
T0 = 1_760_000_000.0
ISO_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
KEYS = {"ip", "client_id", "connections", "inflight", "waiting", "requests_5m", "targets", "first_seen_at",
        "last_seen_at"}


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


def rows_by_ip(rows):
    return {row["ip"]: row for row in rows}


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.tracker = ClientTracker(clock=self.clock)

    def row(self, ip):
        return rows_by_ip(self.tracker.snapshot()).get(ip)

    def test_row_shape_matches_the_dashboard_contract(self):
        self.tracker.connected(IP_A, "c1")
        ticket = self.tracker.request_started(IP_A)
        self.tracker.request_inspected(IP_A, "ChatGPT")              # 10/15: 요청 수·LLM별 수는 검사한 요청만
        self.tracker.note_client_id(IP_A, CLIENT_A)
        self.clock.now += 2.5
        self.tracker.request_finished(ticket)
        rows = self.tracker.snapshot()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(set(row), KEYS)
        self.assertEqual(row, {**row, "ip": IP_A, "client_id": CLIENT_A, "connections": 1, "inflight": 0,
                               "waiting": 0, "requests_5m": 1, "targets": {"ChatGPT": 1}})
        self.assertRegex(row["first_seen_at"], ISO_RE)
        self.assertRegex(row["last_seen_at"], ISO_RE)
        self.assertEqual(row["first_seen_at"], "2025-10-09T08:53:20.000Z")
        self.assertEqual(row["last_seen_at"], "2025-10-09T08:53:22.500Z")
        json.dumps(rows)   # 그대로 JSON으로 보낼 수 있다

    def test_connections_count_open_connection_ids_and_never_go_negative(self):
        self.tracker.disconnected(IP_A, "never-connected")          # 모르는 IP: 아무것도 안 생김
        self.assertEqual(self.tracker.snapshot(), [])
        self.tracker.connected(IP_A, "c1")
        self.tracker.connected(IP_A, "c2")
        self.tracker.connected(IP_A, "c2")                          # 같은 연결 두 번 = 하나
        self.assertEqual(self.row(IP_A)["connections"], 2)
        self.tracker.disconnected(IP_A, "c1")
        self.tracker.disconnected(IP_A, "c1")                       # 두 번 끊김
        self.tracker.disconnected(IP_A, "unknown")                  # 모르는 연결(스크립트 다시 읽기 전 연결 등)
        self.assertEqual(self.row(IP_A)["connections"], 1)
        self.tracker.disconnected(IP_A, "c2")
        self.tracker.disconnected(IP_A, "c2")
        self.assertEqual(self.row(IP_A)["connections"], 0)
        self.tracker.connected(IP_A, None)                          # id 없는 연결은 세지 않는다
        self.assertEqual(self.row(IP_A)["connections"], 0)

    def test_inflight_never_goes_negative(self):
        ticket = self.tracker.request_started(IP_A)
        self.tracker.request_finished(ticket)
        self.tracker.request_finished(ticket)
        for junk in (None, "x", (IP_A,), [IP_A, 999], 5):
            self.tracker.request_finished(junk)
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 0))
        self.assertIsNone(self.tracker.request_started(None))
        self.assertIsNone(self.tracker.request_started("not-an-ip"))

    def test_a_ticket_that_does_not_match_a_running_request_changes_nothing(self):
        ticket = self.tracker.request_started(IP_A)
        ip, gen, request_id = ticket
        for stray in ((ip, gen), (ip, gen + 1, request_id), (ip, gen, request_id + 1), ("198.51.100.99", gen, request_id),
                      (ip, gen, request_id, "extra")):
            self.tracker.request_finished(stray)
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 0))
        self.tracker.request_finished(ticket)
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 0))

    def test_long_running_requests_are_reported_as_waiting_after_30_seconds(self):
        self.assertEqual(T.LONG_INFLIGHT_SECONDS, 30)
        stream = self.tracker.request_started(IP_A)          # 스트리밍 응답: 끝나지 않는다
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 0))
        self.clock.now = T0 + 29.999
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 0))
        self.clock.now = T0 + 30                                        # 30초부터 대기 연결
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 1))
        self.clock.now = T0 + 120
        quick = self.tracker.request_started(IP_A)           # 새 요청은 다시 처리 중
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 1))
        self.clock.now += 5
        self.tracker.request_finished(quick)                            # 짧은 요청이 끝나도 대기 연결은 그대로
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 1))
        self.tracker.request_finished(stream)                           # 대기 연결이 끝나면 0
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 0))
        self.tracker.request_finished(stream)                           # 두 번 끝나도 음수 없음
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 0))

    def test_waiting_is_the_old_stuck_inflight_symptom_with_no_requests_in_5_minutes(self):
        self.tracker.connected(IP_A, "c1")
        self.tracker.request_started(IP_A)                    # 끝나지 않는 StreamTimeline류 요청
        self.clock.now = T0 + 400
        row = self.row(IP_A)
        self.assertEqual((row["inflight"], row["waiting"], row["requests_5m"], row["connections"]), (0, 1, 0, 1))

    def test_each_request_is_aged_on_its_own_and_finishing_one_never_ends_another(self):
        old = self.tracker.request_started(IP_A)
        other_ip = self.tracker.request_started(IP_B)
        self.clock.now = T0 + 10
        middle = self.tracker.request_started(IP_A)
        self.clock.now = T0 + 25
        newest = self.tracker.request_started(IP_A)
        self.clock.now = T0 + 35                                       # old 35초 → 대기, middle 25초·newest 10초 → 처리 중
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (2, 1))
        self.clock.now = T0 + 40                                        # middle 30초 → 대기
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 2))
        self.tracker.request_finished(middle)                           # 중간 것만 끝남
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 1))
        self.tracker.request_finished(old)
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 0))
        self.assertEqual((self.row(IP_B)["inflight"], self.row(IP_B)["waiting"]), (0, 1))   # 다른 IP는 따로 센다
        self.tracker.request_finished(newest)
        self.tracker.request_finished(other_ip)
        self.assertEqual([(r["inflight"], r["waiting"]) for r in self.tracker.snapshot()], [(0, 0), (0, 0)])

    def test_the_30_second_limit_can_be_changed_per_tracker(self):
        tracker = ClientTracker(clock=self.clock, long_inflight_seconds=5)
        tracker.request_started(IP_A)
        self.clock.now = T0 + 4.9
        self.assertEqual((tracker.snapshot()[0]["inflight"], tracker.snapshot()[0]["waiting"]), (1, 0))
        self.clock.now = T0 + 5
        self.assertEqual((tracker.snapshot()[0]["inflight"], tracker.snapshot()[0]["waiting"]), (0, 1))

    def test_a_waiting_request_keeps_the_entry_busy_but_expires_with_it_after_600_seconds(self):
        tracker = ClientTracker(clock=self.clock, max_tracked=2)
        tracker.request_started(IP_A)                         # 가장 오래됐고 연결은 없지만 요청이 열려 있음
        self.clock.now += 100
        tracker.request_finished(tracker.request_started(IP_B))
        self.clock.now += 100
        tracker.request_finished(tracker.request_started(IP_V6))   # 가득 참 → 끝난 IP_B가 빠지고 IP_A가 남는다
        self.assertEqual(set(rows_by_ip(tracker.snapshot())), {IP_A, IP_V6})
        self.assertEqual(rows_by_ip(tracker.snapshot())[IP_A]["waiting"], 1)
        self.clock.now = T0 + 600.001                                    # 연결 없이 600초 조용하면 대기 요청째로 빠진다(계약)
        self.assertNotIn(IP_A, rows_by_ip(tracker.snapshot()))
        self.assertEqual(tracker.tracked_count(), 1)

    def test_idle_entries_expire_after_600_seconds_and_open_connections_keep_them(self):
        self.tracker.request_started(IP_A)   # 끝나지 않은 요청도 연결이 없으면 600초 뒤 빠진다(계약)
        self.tracker.connected(IP_B, "b1")
        self.clock.now = T0 + 600
        self.assertEqual(set(rows_by_ip(self.tracker.snapshot())), {IP_A, IP_B})
        self.clock.now = T0 + 600.001
        self.assertEqual(set(rows_by_ip(self.tracker.snapshot())), {IP_B})
        self.assertEqual(self.tracker.tracked_count(), 1)            # 메모리에서도 빠진다
        self.clock.now = T0 + 86_400                                 # 연결이 열려 있으면 하루 지나도 남는다
        self.assertEqual(self.row(IP_B)["connections"], 1)
        self.tracker.disconnected(IP_B, "b1")                         # 끊김도 활동: 그때부터 600초
        self.clock.now += 600
        self.assertIsNotNone(self.row(IP_B))
        self.clock.now += 1
        self.assertEqual(self.tracker.snapshot(), [])
        self.assertEqual(self.tracker.tracked_count(), 0)

    def test_requests_and_targets_cover_the_last_300_seconds(self):
        # 10/15: 검사한 요청(request_inspected)만 센다. 처리 중 수는 시작(request_started) 기준 그대로
        self.tracker.request_started(IP_A)
        self.tracker.request_inspected(IP_A, "ChatGPT")
        self.clock.now = T0 + 100
        for _ in range(2):
            self.tracker.request_started(IP_A)
            self.tracker.request_inspected(IP_A, "Claude")
        self.assertEqual((self.row(IP_A)["requests_5m"], self.row(IP_A)["targets"]), (3, {"Claude": 2, "ChatGPT": 1}))
        self.clock.now = T0 + 300                                    # 300초 전 요청은 빠진다
        self.assertEqual((self.row(IP_A)["requests_5m"], self.row(IP_A)["targets"]), (2, {"Claude": 2}))
        self.clock.now = T0 + 400
        self.assertEqual((self.row(IP_A)["requests_5m"], self.row(IP_A)["targets"]), (0, {}))
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (0, 3))   # 처리 중 수는 구간과 무관, 30초 넘어 대기로 셈

    def test_targets_keep_the_ten_busiest_names(self):
        for index in range(12):
            for _ in range(index + 1):
                self.tracker.request_inspected(IP_A, f"LLM{index:02d}")
        self.tracker.request_inspected(IP_A, "")                     # 이름이 비면 Unknown
        self.tracker.request_inspected(IP_A, "x" * 41)                # 너무 긴 이름도 Unknown
        row = self.row(IP_A)
        self.assertEqual(row["requests_5m"], sum(range(1, 13)) + 2)
        self.assertEqual(len(row["targets"]), 10)
        self.assertEqual(list(row["targets"]), [f"LLM{index:02d}" for index in range(11, 1, -1)])
        self.assertEqual(row["targets"]["LLM11"], 12)

    def test_list_is_newest_first_and_capped_at_200(self):
        for index in range(250):
            self.clock.now = T0 + index
            self.tracker.request_started(f"203.0.113.{index}")
        rows = self.tracker.snapshot()
        self.assertEqual(len(rows), T.MAX_LISTED)
        self.assertEqual(rows[0]["ip"], "203.0.113.249")
        stamps = [row["last_seen_at"] for row in rows]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_memory_is_bounded_and_busy_entries_are_kept(self):
        tracker = ClientTracker(clock=self.clock, max_tracked=5, max_recent=7)
        tracker.connected(IP_B, "b1")                                # 가장 오래됐지만 연결이 열려 있음
        for index in range(20):
            self.clock.now += 1
            tracker.request_finished(tracker.request_started(f"2001:db8::{index:x}"))
            tracker.request_inspected(f"2001:db8::{index:x}", "ChatGPT")
        self.assertEqual(tracker.tracked_count(), 5)
        rows = rows_by_ip(tracker.snapshot())
        self.assertIn(IP_B, rows)
        self.assertEqual(set(rows) - {IP_B}, {f"2001:db8::{index:x}" for index in range(16, 20)})
        self.assertEqual(sum(row["requests_5m"] for row in rows.values()), 4)   # 기록 7건 중 남은 IP 것만
        tracker.request_inspected(IP_B, "Claude")
        self.assertEqual(len(tracker._recent), 7)                     # 최근 검사 요청 기록 상한

    def test_ipv6_and_ip_normalization(self):
        self.tracker.connected("2001:0db8:0000:0000:0000:0000:0000:0007", "v1")
        self.tracker.request_inspected(IP_V6, "Claude")
        self.tracker.request_inspected("::ffff:203.0.113.10", "ChatGPT")   # IPv4가 IPv6 형식으로 와도 같은 IP
        self.tracker.request_inspected(IP_A, "ChatGPT")
        self.tracker.request_started("fe80::1%eth0")                     # 영역 표시는 뗀다
        long_v6 = "2001:db8:1111:2222:3333:4444:198.51.100.1"            # 섞인 표기 → 짧은 형태
        self.tracker.request_started(long_v6)
        for bad in (None, "", "203.0.113", "example.test", "203.0.113.300", 12345, ("203.0.113.1",), "1" * 70):
            self.assertIsNone(self.tracker.request_started(bad))
            self.tracker.request_inspected(bad, "Gemini")
            self.tracker.connected(bad, "bad")
        rows = rows_by_ip(self.tracker.snapshot())
        self.assertEqual(set(rows), {IP_V6, IP_A, "fe80::1", "2001:db8:1111:2222:3333:4444:c633:6401"})
        self.assertEqual((rows[IP_V6]["connections"], rows[IP_V6]["requests_5m"]), (1, 1))
        self.assertEqual(rows[IP_A]["targets"], {"ChatGPT": 2})
        self.assertTrue(all(len(ip) <= T.IP_MAX_CHARS for ip in rows))

    def test_client_id_pick_up(self):
        self.tracker.note_client_id(IP_A, CLIENT_A)                 # 항목이 없으면 만들지 않는다
        self.assertEqual(self.tracker.snapshot(), [])
        self.tracker.request_started(IP_A)
        self.assertIsNone(self.row(IP_A)["client_id"])
        self.tracker.note_client_id(IP_A, f"  {CLIENT_A}  ")
        self.assertEqual(self.row(IP_A)["client_id"], CLIENT_A)
        for bad in (None, "", "a b", "chrome-\n1", "x" * 81, "-leading", 7, "클라이언트"):
            self.tracker.note_client_id(IP_A, bad)                   # 헤더 없음·형식 틀림: 이전 값 그대로
        self.assertEqual(self.row(IP_A)["client_id"], CLIENT_A)
        self.tracker.note_client_id(IP_A, CLIENT_B)                  # 같은 IP의 다른 확장 프로그램: 마지막 값
        self.assertEqual(self.row(IP_A)["client_id"], CLIENT_B)
        self.tracker.note_client_id(IP_A, "c" * 80)
        self.assertEqual(self.row(IP_A)["client_id"], "c" * 80)

    def test_a_finish_from_an_expired_entry_does_not_touch_the_new_one(self):
        old = self.tracker.request_started(IP_A)
        self.clock.now = T0 + 700
        self.assertEqual(self.tracker.snapshot(), [])                # 빠짐
        self.tracker.connected(IP_A, "c9")
        self.tracker.request_started(IP_A)
        self.tracker.request_finished(old)
        self.assertEqual((self.row(IP_A)["inflight"], self.row(IP_A)["waiting"]), (1, 0))
        self.assertEqual(self.row(IP_A)["first_seen_at"], "2025-10-09T09:05:00.000Z")

    def test_concurrent_hooks_from_many_threads(self):
        tracker = ClientTracker()
        errors = []

        def work(worker):
            try:
                ip = IP_V6 if worker % 2 else IP_A
                for index in range(500):
                    conn = f"w{worker}-{index}"
                    tracker.connected(ip, conn)
                    ticket = tracker.request_started(ip)
                    tracker.request_inspected(ip, "Claude")
                    tracker.note_client_id(ip, CLIENT_A)
                    if index % 50 == 0:
                        tracker.snapshot()
                    tracker.request_finished(ticket)
                    tracker.disconnected(ip, conn)
            except Exception as exc:   # pragma: no cover - 실패 때만
                errors.append(exc)
        threads = [threading.Thread(target=work, args=(worker,)) for worker in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        rows = rows_by_ip(tracker.snapshot())
        for ip in (IP_A, IP_V6):
            self.assertEqual((rows[ip]["connections"], rows[ip]["inflight"], rows[ip]["waiting"],
                              rows[ip]["requests_5m"]), (0, 0, 0, 2000))


class GatewayFlowTests(bundle.Base):
    """실제 mitmproxy flow로 client_connected → request → response → client_disconnected 훅을 지나고
    지표 전송기 값(_publisher_snapshot)에만 clients가 실리는지, 요청마다 찍는 지표 로그에는 없는지 본다."""

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        patcher = mock.patch.object(gateway, "_client_tracker", ClientTracker(clock=self.clock))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.peer = (IP_A, 50123)
        self.client_header = CLIENT_A
        self.output = io.StringIO()

    def run_flow(self, req):
        if self.client_header:
            req.headers["x-llmsgw-client-id"] = self.client_header
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

    def clients(self):
        snapshot = gateway._publisher_snapshot()
        json.dumps(snapshot)
        return rows_by_ip(snapshot["clients"])

    def test_publisher_snapshot_carries_clients_through_real_flows(self):
        flow = self.chatgpt_prompt("안녕하세요")
        self.assertNotIn("x-llmsgw-client-id", flow.request.headers)      # 지금처럼 LLM 서비스로는 보내지 않는다
        row = self.clients()[IP_A]
        self.assertEqual(set(row), KEYS)
        self.assertEqual({k: row[k] for k in ("client_id", "connections", "inflight", "requests_5m", "targets")},
                         {"client_id": CLIENT_A, "connections": 1, "inflight": 1, "requests_5m": 1,
                          "targets": {"ChatGPT": 1}})
        self.clock.now += 3
        self.finish(flow)
        row = self.clients()[IP_A]
        self.assertEqual((row["inflight"], row["connections"]), (0, 1))
        self.assertEqual(row["last_seen_at"], "2025-10-09T08:53:23.000Z")
        gateway.client_disconnected(flow.client_conn)
        self.assertEqual(self.clients()[IP_A]["connections"], 0)
        self.clock.now += 601
        self.assertEqual(self.clients(), {})

    def test_a_long_running_flow_moves_from_inflight_to_waiting_in_the_publisher_payload(self):
        flow = self.chatgpt_prompt("스트리밍")                          # response 훅이 오지 않는 요청 = 열린 스트림
        row = self.clients()[IP_A]
        self.assertEqual((row["inflight"], row["waiting"], row["requests_5m"]), (1, 0, 1))
        self.clock.now += 29
        self.assertEqual((self.clients()[IP_A]["inflight"], self.clients()[IP_A]["waiting"]), (1, 0))
        self.clock.now += 1                                              # 30초
        row = self.clients()[IP_A]
        self.assertEqual((row["inflight"], row["waiting"], row["connections"]), (0, 1, 1))
        self.clock.now += 400                                            # 5분 넘게: 요청 0건이어도 대기 1건
        row = self.clients()[IP_A]
        self.assertEqual((row["inflight"], row["waiting"], row["requests_5m"], row["connections"]), (0, 1, 0, 1))
        self.finish(flow)                                                # 스트림이 끝나면 둘 다 0
        row = self.clients()[IP_A]
        self.assertEqual((row["inflight"], row["waiting"]), (0, 0))

    def test_two_clients_ipv6_and_a_request_without_the_extension_header(self):
        self.peer = (IP_V6, 443, 0, 0)
        self.client_header = None
        self.finish(self.claude_completion({"prompt": "요약해 줘"}))
        self.peer = (IP_B, 40000)
        self.client_header = CLIENT_B
        self.chatgpt_prompt("하나")
        clients = self.clients()
        self.assertEqual(set(clients), {IP_V6, IP_B})
        self.assertEqual((clients[IP_V6]["client_id"], clients[IP_V6]["targets"], clients[IP_V6]["inflight"]),
                         (None, {"Claude": 1}, 0))
        self.assertEqual((clients[IP_B]["client_id"], clients[IP_B]["inflight"]), (CLIENT_B, 1))
        self.assertEqual(list(clients), [IP_B, IP_V6])                     # 최근 순(같은 시각이면 나중에 생긴 것 먼저)

    def test_file_upload_on_the_worker_thread_is_counted(self):
        flow = self.claude_upload(("memo.txt", "text/plain", "회의 메모".encode()))
        self.assertTrue(gateway.is_file_upload_request(flow))
        self.assertEqual(self.clients()[IP_A]["inflight"], 1)
        self.finish(flow)
        row = self.clients()[IP_A]
        self.assertEqual((row["inflight"], row["requests_5m"], row["targets"]), (0, 1, {"Claude": 1}))

    def test_clients_are_only_in_the_publisher_payload_and_never_logged(self):
        flow = self.chatgpt_prompt("둘")
        self.finish(flow)
        gateway.client_disconnected(flow.client_conn)
        log = self.output.getvalue()
        self.assertIn("===== GATEWAY TRAFFIC METRICS =====", log)
        metrics_line = log.split("===== GATEWAY TRAFFIC METRICS =====", 1)[1].splitlines()[2]
        self.assertNotIn("clients", json.loads(metrics_line))             # 요청마다 찍는 지표 줄
        self.assertNotIn("clients", flow.metadata["gw_metrics_snapshot"])  # 이벤트 메타데이터에 쓰는 값
        self.assertNotIn("clients", gateway._gateway_metrics_snapshot())
        self.assertNotIn(IP_A, log)
        self.assertNotIn(CLIENT_A, log)
        published = gateway._publisher_snapshot()
        self.assertEqual(set(published) - set(gateway._gateway_metrics_snapshot()) - {"settings_applied"},
                         {"clients", "relay"})
        sent = []
        publisher = gateway.MetricsPublisher(gateway._publisher_snapshot, sender=lambda s: sent.append(s),
                                             heartbeat=30, min_interval=0.05, logger=lambda m: None)
        publisher.start()
        deadline = time.monotonic() + 5
        while not sent and time.monotonic() < deadline:
            time.sleep(0.02)
        publisher.stop()
        self.assertEqual(sent[0]["clients"][0]["ip"], IP_A)

    def test_a_broken_tracker_drops_only_the_clients_field(self):
        broken = mock.Mock()
        broken.snapshot.side_effect = RuntimeError(IP_A)
        with mock.patch.object(gateway, "_client_tracker", broken), contextlib.redirect_stdout(io.StringIO()) as out:
            snapshot = gateway._publisher_snapshot()
        self.assertNotIn("clients", snapshot)
        self.assertIn("total_requests", snapshot)
        self.assertIn("error_type=RuntimeError", out.getvalue())
        self.assertNotIn(IP_A, out.getvalue())

    def test_health_check_is_not_a_request_but_the_connection_counts(self):
        req = tutils.treq(host="llm-gateway.local", port=80, scheme=b"http", method=b"GET",
                          path=b"/__llmsgw/health", content=b"")
        flow = self.run_flow(req)
        self.assertEqual(flow.response.status_code, 200)
        row = self.clients()[IP_A]
        self.assertEqual((row["connections"], row["requests_5m"], row["inflight"]), (1, 0, 0))


if __name__ == "__main__":
    unittest.main()
