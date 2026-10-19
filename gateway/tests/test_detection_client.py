"""2026-10-11 - detection_client.check(): Detection 응답이 깨져도 예외 대신 실패 판정을 돌려준다(Claude 새 화면 질문 검사 검토 2).

깨진 응답(본문 끊김 IncompleteRead·상태 줄 오류 BadStatusLine·긴 머리 LineTooLong·깨진 chunked)은 OSError도 ValueError도
아니라서, 잡지 않으면 request 훅 밖으로 나가고 mitmproxy가 'Addon error'만 남긴 채 원래 요청을 보낸다(질문 처리 설정이 '차단'이어도).
가짜 Detection은 127.0.0.1 임시 포트 소켓이다(요청을 다 읽은 뒤 정한 바이트를 보내고 끊음). 가짜 값만 쓴다.
실행: python -m unittest tests.test_detection_client -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import http.client
import socket
import threading
import unittest
from unittest import mock

import detection_client

REPLIES = {
    "truncated_body": (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n"
                       b"{\"blocked\": fa"),
    "bad_status_line": b"GARBAGE\r\n\r\n",
    "line_too_long": b"HTTP/1.1 200 OK\r\nX-Fake: " + b"a" * 70000 + b"\r\n\r\n",
    "broken_chunked": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
    "no_response": b"",
    "invalid_json": b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{nope",
}
BROKEN = ("truncated_body", "bad_status_line", "line_too_long", "broken_chunked")


class RawDetection:
    """요청마다 머리·본문을 다 읽고 REPLIES[mode]를 보낸 뒤 연결을 닫는 가짜 Detection."""

    def __init__(self, mode: str):
        self.reply = REPLIES[mode]
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.stopped = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stopped:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            try:
                conn.settimeout(2)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                while len(rest) < length:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                if self.reply:
                    conn.sendall(self.reply)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self.stopped = True
        self.sock.close()
        self.thread.join(2)


def call(url: str, policy: str):
    return detection_client.check(url, "rid-fake-0001", "가짜 질문 글자", source={"service": "Claude"}, timeout=2.0,
                                  failure_policy=policy)


def verdict(result):
    return (result.action, result.blocked, result.degraded, result.degraded_reason, result.reason_code,
            result.http_status, result.failure_policy, result.request_id)


class BrokenResponseTests(unittest.TestCase):
    def detection(self, mode):
        server = RawDetection(mode)
        self.addCleanup(server.close)
        return server.url

    def test_broken_responses_become_failure_results(self):
        expected = {
            "FAIL_CLOSED": ("block", True, True, "OTHER", "detection_error", 503, "FAIL_CLOSED", "rid-fake-0001"),
            "FAIL_OPEN": ("allow_degraded", False, True, "OTHER", "detection_error", None, "FAIL_OPEN", "rid-fake-0001"),
        }
        for mode in BROKEN:
            url = self.detection(mode)
            for policy, want in expected.items():
                with self.subTest(mode=mode, policy=policy):
                    self.assertEqual(verdict(call(url, policy)), want)

    def test_failure_closed_message_is_the_usual_one(self):
        result = call(self.detection("truncated_body"), "FAIL_CLOSED")
        self.assertEqual(result.user_message, "보안 검사를 완료하지 못해 장애 처리 정책에 따라 전송을 차단했습니다.")

    def test_existing_failure_reasons_are_unchanged(self):
        # 지켜야 할 동작: 응답 없이 끊김 → UNREACHABLE(RemoteDisconnected는 OSError), 연결 거부 → UNREACHABLE, 깨진 JSON → PARSE_ERROR
        self.assertEqual(call(self.detection("no_response"), "FAIL_CLOSED").degraded_reason, "UNREACHABLE")
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        refused = f"http://127.0.0.1:{probe.getsockname()[1]}"
        probe.close()
        # 연결 거부: Linux는 바로 UNREACHABLE, Windows는 거부된 연결을 대기 시간 동안 다시 시도해 TIMEOUT
        self.assertIn(call(refused, "FAIL_CLOSED").degraded_reason, ("UNREACHABLE", "TIMEOUT"))
        self.assertEqual(call(self.detection("invalid_json"), "FAIL_CLOSED").degraded_reason, "PARSE_ERROR")

    def test_unexpected_exceptions_become_failure_results(self):
        for error in (http.client.IncompleteRead(b"{"), http.client.BadStatusLine("x"), RuntimeError("boom")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(detection_client.urllib.request, "urlopen", side_effect=error):
                    result = call("http://127.0.0.1:9", "FAIL_CLOSED")
                self.assertEqual((result.action, result.degraded_reason, result.http_status), ("block", "OTHER", 503))

    def test_invalid_arguments_still_raise(self):
        # 호출 쪽 설정 오류는 조용히 허용하지 않는다(기존 동작)
        with self.assertRaises(ValueError):
            detection_client.check("http://127.0.0.1:9", "rid", "x", failure_policy="MAYBE")


if __name__ == "__main__":
    unittest.main()
