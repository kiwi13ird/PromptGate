"""중계 접속 현황(2026-10-12 시스템 상태 화면) - 중계 GET /status, Gateway 조회(gateway_relay_status), 지표 전송기 "relay" 칸.

중계는 실제 websocket_server.py(웹소켓 서버 + HTTP 핸들러)를 127.0.0.1의 임시 포트에서 돌린다. 운영 중계·대시보드에는 연결하지 않는다.
가짜 값만 쓴다(가짜 확장 프로그램 id).
실행: python -m unittest tests.test_gateway_relay_status -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from websockets.asyncio.server import serve  # noqa: E402
from websockets.sync.client import connect  # noqa: E402

import gateway  # noqa: E402
import gateway_relay_status as R  # noqa: E402
import websocket_server as relay  # noqa: E402

CLIENT_A = "chrome-00000000-0000-4000-8000-00000000000a"
CLIENT_B = "chrome-00000000-0000-4000-8000-00000000000b"
FAILED = {"ok": False, "connected": 0, "registered": 0}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def closed_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}/status"


class FakeRelay:
    """GET만 받는 가짜 중계 HTTP. 받은 요청을 calls에 남긴다."""

    def __init__(self, status=200, body=b'{"connected": 3, "registered": 2}', delay=0.0):
        self.status, self.body, self.delay = status, body, delay
        self.calls = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.calls.append(self.path)
                if outer.delay:
                    time.sleep(outer.delay)
                try:
                    self.send_response(outer.status)
                    self.send_header("Content-Length", str(len(outer.body)))
                    self.end_headers()
                    self.wfile.write(outer.body)
                except OSError:        # 조회 쪽이 먼저 시간 초과로 끊은 경우
                    pass

            def log_message(self, format, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/status"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class FetchTests(unittest.TestCase):
    def setUp(self):
        R._last_ok = None
        self.logs = []

    def fake(self, **kwargs):
        server = FakeRelay(**kwargs)
        self.addCleanup(server.close)
        return server

    def fetch(self, server, **kwargs):
        return R.fetch_relay_status(url=server.url, logger=self.logs.append, **kwargs)

    def test_ok_returns_the_counts(self):
        server = self.fake()
        self.assertEqual(self.fetch(server), {"ok": True, "connected": 3, "registered": 2})
        self.assertEqual(server.calls, ["/status"])

    def test_only_the_three_fields_pass_through(self):
        server = self.fake(body=b'{"connected": 1, "registered": 1, "ids": ["secret-id"], "ok": false}')
        self.assertEqual(self.fetch(server), {"ok": True, "connected": 1, "registered": 1})

    def test_zero_counts_are_ok(self):
        server = self.fake(body=b'{"connected": 0, "registered": 0}')
        self.assertEqual(self.fetch(server), {"ok": True, "connected": 0, "registered": 0})

    def test_wrong_shapes_are_ok_false_with_zeros(self):
        bodies = [b"not json", b"[]", b"null", b"{}", b'{"connected": 1}', b'{"registered": 1}',
                  b'{"connected": -1, "registered": 0}', b'{"connected": 0, "registered": -2}',
                  b'{"connected": true, "registered": 0}', b'{"connected": 1.5, "registered": 0}',
                  b'{"connected": "1", "registered": 0}', b'{"connected": null, "registered": 0}',
                  b"\xff\xfe\x00", b'{"connected": 1, "registered": 1, "pad": "' + b"x" * 5000 + b'"}']
        for body in bodies:
            with self.subTest(body=body[:40]):
                R._last_ok = None
                self.assertEqual(self.fetch(self.fake(body=body)), FAILED)

    def test_non_200_is_ok_false(self):
        for status in (204, 301, 404, 500, 503):
            with self.subTest(status=status):
                self.assertEqual(self.fetch(self.fake(status=status)), FAILED)

    def test_nothing_listening_is_ok_false_within_the_timeout(self):
        started = time.monotonic()
        result = R.fetch_relay_status(url=closed_port_url(), timeout=0.3, logger=self.logs.append)
        self.assertEqual(result, FAILED)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_a_slow_relay_is_cut_at_the_timeout(self):
        server = self.fake(delay=2.0)
        started = time.monotonic()
        self.assertEqual(self.fetch(server, timeout=0.3), FAILED)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_defaults_are_half_a_second_and_the_local_relay(self):
        self.assertEqual(R.TIMEOUT_SECONDS, 0.5)
        self.assertEqual(R.RELAY_STATUS_URL, "http://127.0.0.1:8766/status")
        seen = {}

        class Opener:
            def open(self, url, timeout=None):
                seen.update(url=url, timeout=timeout)
                raise OSError("nothing")

        self.assertEqual(R.fetch_relay_status(opener=Opener(), logger=self.logs.append), FAILED)
        self.assertEqual(seen, {"url": "http://127.0.0.1:8766/status", "timeout": 0.5})

    def test_it_never_raises(self):
        for error in (RuntimeError("x"), ValueError("x"), OSError("x"), TimeoutError("x"), urllib.error.URLError("x"),
                      ConnectionResetError("x"), UnicodeDecodeError("utf-8", b"", 0, 1, "x")):
            class Opener:
                def open(self, url, timeout=None):
                    raise error

            with self.subTest(error=type(error).__name__):
                self.assertEqual(R.fetch_relay_status(opener=Opener(), logger=self.logs.append), FAILED)

    def test_a_broken_logger_does_not_matter(self):
        def broken(message):
            raise RuntimeError("logger down")

        R._last_ok = None
        self.assertEqual(R.fetch_relay_status(url=closed_port_url(), timeout=0.2, logger=broken), FAILED)

    def test_logs_only_when_the_state_changes_and_never_the_address_or_body(self):
        up = self.fake(body=b'{"connected": 1, "registered": 1}')
        down_url = closed_port_url()
        for url in (up.url, up.url, down_url, down_url, up.url):
            R.fetch_relay_status(url=url, timeout=0.2, logger=self.logs.append)
        self.assertEqual(len(self.logs), 3)
        self.assertEqual(self.logs[0], "[RELAY] status ok")
        self.assertTrue(self.logs[1].startswith("[RELAY] status unavailable error_type="))
        self.assertEqual(self.logs[2], "[RELAY] status ok")
        self.assertNotIn("127.0.0.1", " ".join(self.logs))


class RelayServerTests(unittest.TestCase):
    """실제 websocket_server: 웹소켓 서버(임시 포트)와 EventHandler HTTP(임시 포트)를 띄워 GET /status를 본다."""

    def setUp(self):
        patcher = mock.patch.object(relay, "print", create=True, new=lambda *args, **kwargs: None)
        patcher.start()
        self.addCleanup(patcher.stop)
        ws_log = logging.getLogger("websockets.server")        # 갑자기 끊긴 연결의 traceback이 시험 출력을 어지럽히지 않게
        self.addCleanup(ws_log.setLevel, ws_log.level)
        ws_log.setLevel(logging.CRITICAL)
        relay.clients.clear()
        relay.connected_count = 0
        self.addCleanup(relay.clients.clear)
        self.addCleanup(setattr, relay, "connected_count", 0)
        self.addCleanup(setattr, relay, "event_loop", None)
        self.ready = threading.Event()
        self.ws_stop = None
        self.ws_loop = None
        self.ws_port = None
        self.ws_thread = threading.Thread(target=self._run_websocket, daemon=True)
        self.ws_thread.start()
        self.assertTrue(self.ready.wait(5))
        self.httpd = HTTPServer(("127.0.0.1", 0), relay.EventHandler)
        self.http_port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.sockets = []
        self.addCleanup(self._stop_servers)

    def _run_websocket(self):
        async def main():
            self.ws_loop = relay.event_loop = asyncio.get_running_loop()
            self.ws_stop = asyncio.Event()
            async with serve(relay.websocket_handler, "127.0.0.1", 0) as server:
                self.ws_port = server.sockets[0].getsockname()[1]
                self.ready.set()
                await self.ws_stop.wait()

        asyncio.run(main())

    def _stop_servers(self):
        for client in self.sockets:
            with contextlib.suppress(Exception):
                client.close()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.ws_loop.call_soon_threadsafe(self.ws_stop.set)
        self.ws_thread.join(5)

    # -- 도구
    def client(self, register=None):
        ws = connect(f"ws://127.0.0.1:{self.ws_port}")
        self.sockets.append(ws)
        if register:
            ws.send(json.dumps({"type": "REGISTER", "clientId": register}))
        return ws

    def get(self, path="/status"):
        try:
            with OPENER.open(f"http://127.0.0.1:{self.http_port}{path}", timeout=5) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def post(self, path, data):
        request = urllib.request.Request(f"http://127.0.0.1:{self.http_port}{path}", data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with OPENER.open(request, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def status(self):
        code, _, body = self.get()
        self.assertEqual(code, 200)
        return json.loads(body)

    def wait_status(self, connected, registered):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = self.status()
            if value == {"connected": connected, "registered": registered}:
                return value
            time.sleep(0.02)
        self.fail(f"status did not reach connected={connected} registered={registered}: {self.status()}")

    # -- 시험
    def test_status_with_nobody_connected(self):
        code, headers, body = self.get()
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertEqual(json.loads(body), {"connected": 0, "registered": 0})

    def test_counts_follow_connections_and_registrations(self):
        first = self.client()
        second = self.client()
        self.wait_status(2, 0)                       # 연결만 한 것은 등록 수에 들어가지 않는다
        first.send(json.dumps({"type": "REGISTER", "clientId": CLIENT_A}))
        self.wait_status(2, 1)
        second.send(json.dumps({"type": "REGISTER", "clientId": CLIENT_B}))
        self.wait_status(2, 2)
        first.close()
        self.wait_status(1, 1)
        second.close()
        self.wait_status(0, 0)

    def test_reconnect_with_the_same_id_keeps_one_registration(self):
        old = self.client(register=CLIENT_A)
        self.wait_status(1, 1)
        new = self.client(register=CLIENT_A)
        self.wait_status(2, 1)
        old.close()
        self.wait_status(1, 1)                       # 옛 연결이 닫혀도 새 연결의 등록은 그대로
        new.close()
        self.wait_status(0, 0)

    def test_garbage_and_registration_without_an_id_only_count_as_connected(self):
        ws = self.client()
        ws.send("this is not json")
        ws.send(json.dumps({"type": "REGISTER"}))
        ws.send(json.dumps({"type": "REGISTER", "clientId": ""}))
        ws.send(json.dumps({"type": "SOMETHING_ELSE", "clientId": CLIENT_A}))
        self.wait_status(1, 0)
        ws.close()
        self.wait_status(0, 0)

    def test_connections_that_drop_without_a_closing_handshake_are_not_counted_forever(self):
        for _ in range(5):
            ws = self.client(register=CLIENT_B)
            # 리눅스에서는 다른 스레드가 recv 중인 소켓을 close()만 하면 FIN이 안 나간다 - shutdown으로 실제로 끊는다
            ws.socket.shutdown(socket.SHUT_RDWR)
            ws.socket.close()
        for _ in range(5):
            self.client().close()
        self.wait_status(0, 0)

    def test_many_connect_disconnect_cycles_end_at_zero(self):
        for index in range(25):
            self.client(register=f"chrome-{index:04d}").close()
        self.wait_status(0, 0)

    def test_the_body_has_only_counts_never_ids(self):
        self.client(register=CLIENT_A)
        self.wait_status(1, 1)
        _, _, body = self.get()
        self.assertEqual(set(json.loads(body)), {"connected", "registered"})
        self.assertNotIn(CLIENT_A.encode(), body)

    def test_other_get_paths_are_404_and_a_query_string_is_ignored(self):
        for path in ("/", "/event", "/statuses", "/status/", "/status/x", "/STATUS"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 404)
        self.assertEqual(self.get("/status?probe=1")[0], 200)

    def test_post_event_still_delivers_and_the_other_posts_are_unchanged(self):
        ws = self.client(register=CLIENT_A)
        self.wait_status(1, 1)
        event = {"eventId": "evt-1", "timestamp": "2026-10-12T00:00:00.000Z", "clientId": CLIENT_A,
                 "targetLlm": "ChatGPT", "finalAction": "BLOCK"}
        self.assertEqual(self.post("/event", json.dumps(event).encode()), (200, b"OK"))
        message = json.loads(ws.recv(timeout=5))
        self.assertEqual((message["type"], message["clientId"], message["action"]),
                         ("SECURITY_EVENT", CLIENT_A, "BLOCK"))
        self.assertEqual(self.post("/status", b"{}")[0], 404)
        self.assertEqual(self.post("/other", b"{}")[0], 404)
        self.assertEqual(self.post("/event", b"not json")[0], 400)

    def test_status_calls_do_not_hold_up_event_delivery(self):
        ws = self.client(register=CLIENT_A)
        self.wait_status(1, 1)
        for _ in range(30):
            self.status()
        event = {"eventId": "evt-2", "timestamp": "2026-10-12T00:00:00.000Z", "clientId": CLIENT_A,
                 "targetLlm": "Claude", "finalAction": "ALLOW"}
        self.assertEqual(self.post("/event", json.dumps(event).encode())[0], 200)
        self.assertEqual(json.loads(ws.recv(timeout=5))["action"], "ALLOW")

    def test_the_gateway_fetch_reads_the_real_relay(self):
        self.client(register=CLIENT_A)
        self.client()
        self.wait_status(2, 1)
        R._last_ok = None
        result = R.fetch_relay_status(url=f"http://127.0.0.1:{self.http_port}/status", logger=lambda m: None)
        self.assertEqual(result, {"ok": True, "connected": 2, "registered": 1})


class GatewayRelayFieldTests(bundle.Base):
    """지표 전송기 값(_publisher_snapshot)에만 relay가 실리고, 요청 처리 경로는 중계를 부르지 않는다."""

    def setUp(self):
        super().setUp()
        R._last_ok = None
        self.logs = io.StringIO()

    def use_relay(self, **kwargs):
        server = FakeRelay(**kwargs)
        self.addCleanup(server.close)
        for patcher in (mock.patch.object(gateway, "fetch_relay_status", R.fetch_relay_status),   # Base의 가짜 대신 진짜
                        mock.patch.object(R, "RELAY_STATUS_URL", server.url)):
            patcher.start()
            self.addCleanup(patcher.stop)
        return server

    def test_publisher_snapshot_carries_relay(self):
        server = self.use_relay()
        with contextlib.redirect_stdout(self.logs):
            snapshot = gateway._publisher_snapshot()
        self.assertEqual(snapshot["relay"], {"ok": True, "connected": 3, "registered": 2})
        self.assertEqual(set(snapshot["relay"]), {"ok", "connected", "registered"})
        self.assertIn("clients", snapshot)
        self.assertIn("total_requests", snapshot)
        json.dumps(snapshot)
        self.assertEqual(server.calls, ["/status"])

    def test_per_request_metrics_never_carry_relay_and_never_call_it(self):
        server = self.use_relay()
        with contextlib.redirect_stdout(self.logs):
            flow = self.chatgpt_prompt("안녕하세요")
            self.finish(flow)
            claude = self.claude_completion({"prompt": "요약해 줘"})
            self.finish(claude)
        log = self.logs.getvalue()
        self.assertIn("===== GATEWAY TRAFFIC METRICS =====", log)
        for block in log.split("===== GATEWAY TRAFFIC METRICS =====")[1:]:
            self.assertNotIn("relay", json.loads(block.splitlines()[2]))         # 요청마다 찍는 지표 줄
        self.assertNotIn("relay", flow.metadata["gw_metrics_snapshot"])         # 이벤트 메타데이터에 쓰는 값
        self.assertNotIn("relay", gateway._gateway_metrics_snapshot())
        self.assertEqual(server.calls, [])                                       # 요청 처리 중 중계 호출 없음
        with contextlib.redirect_stdout(self.logs):
            gateway._publisher_snapshot()
        self.assertEqual(server.calls, ["/status"])                              # 전송기 값을 만들 때만 한 번

    def test_the_publisher_thread_makes_the_call_and_sends_it(self):
        names = []

        def recording(**kwargs):
            names.append(threading.current_thread().name)
            return {"ok": True, "connected": 4, "registered": 3}

        sent = []
        with mock.patch.object(gateway, "fetch_relay_status", recording):
            publisher = gateway.MetricsPublisher(gateway._publisher_snapshot, sender=lambda s: sent.append(s),
                                                 heartbeat=30, min_interval=0.05, logger=lambda m: None)
            publisher.start()
            deadline = time.monotonic() + 5
            while not sent and time.monotonic() < deadline:
                time.sleep(0.02)
            publisher.stop()
            with contextlib.redirect_stdout(self.logs):
                self.finish(self.chatgpt_prompt("하나"))                         # 요청 처리 경로
        self.assertEqual(sent[0]["relay"], {"ok": True, "connected": 4, "registered": 3})
        self.assertEqual(set(names), {"dashboard-metrics-publisher"})            # 요청 스레드·메인 스레드에서는 부르지 않음

    def test_relay_down_sends_ok_false_and_zeros_and_keeps_the_other_fields(self):
        with mock.patch.object(gateway, "fetch_relay_status", R.fetch_relay_status), \
                mock.patch.object(R, "RELAY_STATUS_URL", closed_port_url()), contextlib.redirect_stdout(self.logs):
            started = time.monotonic()
            snapshot = gateway._publisher_snapshot()
            elapsed = time.monotonic() - started
        self.assertEqual(snapshot["relay"], FAILED)
        self.assertIn("[RELAY] status unavailable error_type=", self.logs.getvalue())     # 기본 로그: 한 줄, 주소·본문 없음
        self.assertNotIn("127.0.0.1", self.logs.getvalue())
        self.assertIn("total_requests", snapshot)
        self.assertIn("clients", snapshot)
        self.assertLess(elapsed, 2.0)

    def test_an_invalid_relay_answer_is_ok_false(self):
        self.use_relay(body=b'{"connected": "many", "registered": 1}')
        with contextlib.redirect_stdout(self.logs):
            self.assertEqual(gateway._publisher_snapshot()["relay"], FAILED)
        self.assertIn("error_type=InvalidResponse", self.logs.getvalue())

    def test_a_hung_relay_costs_at_most_the_timeout(self):
        self.use_relay(delay=3.0)
        started = time.monotonic()
        with contextlib.redirect_stdout(self.logs):
            snapshot = gateway._publisher_snapshot()
        self.assertEqual(snapshot["relay"], FAILED)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_a_broken_fetch_gives_ok_false_and_logs_only_the_error_type(self):
        broken = mock.Mock(side_effect=RuntimeError("secret-detail-xyz"))
        with mock.patch.object(gateway, "fetch_relay_status", broken), contextlib.redirect_stdout(self.logs):
            snapshot = gateway._publisher_snapshot()
        self.assertEqual(snapshot["relay"], FAILED)
        self.assertIn("total_requests", snapshot)
        self.assertIn("error_type=RuntimeError", self.logs.getvalue())
        self.assertNotIn("secret-detail-xyz", self.logs.getvalue())


if __name__ == "__main__":
    unittest.main()
