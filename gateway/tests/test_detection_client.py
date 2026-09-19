"""detection_client 테스트 - mock 대신 실제 로컬 HTTP 서버로 왕복시킨다(팀 방침:
스모크 테스트/mock만으로는 부족하다, 실제 네트워크 경로까지 확인).
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from detection_client import check

_RESPONSE_BODY = {
    "blocked": True,
    "reason": "테스트 문서와 복붙 수준 일치",
    "request_id": "srv-echo",
    "decided_by": "windowhash", "doc_id": "test-doc", "doc_span": "0-100", "input_span": "0-120", "score": 0.97,
    "pii_hits": None, "hash_status": "ok", "signature_status": "skipped", "total_ms": 4.2,
    "decision": {"action": "block", "reason_code": "doc_excerpt", "user_message": "차단 안내", "http_status": 403},
}


def _make_server(handler_cls: type[BaseHTTPRequestHandler]) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class _EchoDetectHandler(BaseHTTPRequestHandler):
    received: dict | None = None

    def do_POST(self) -> None:  # noqa: N802 - http.server 관례
        length = int(self.headers["Content-Length"])
        _EchoDetectHandler.received = json.loads(self.rfile.read(length))
        body = json.dumps(_RESPONSE_BODY).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # 테스트 출력 조용히
        pass


class _SlowHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        time.sleep(1.0)  # detection_client의 timeout(0.5s 기본, 테스트는 더 짧게 지정)보다 길게
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


@pytest.fixture()
def echo_server():
    server = _make_server(_EchoDetectHandler)
    try:
        yield server
    finally:
        server.shutdown()


@pytest.fixture()
def slow_server():
    server = _make_server(_SlowHandler)
    try:
        yield server
    finally:
        server.shutdown()


def test_successful_roundtrip_returns_decision(echo_server: HTTPServer) -> None:
    base_url = f"http://127.0.0.1:{echo_server.server_port}"
    result = check(base_url, request_id="r1", normalized_text="내용", source={"service": "OpenAI"})

    assert result.blocked is True
    assert result.degraded is False
    assert result.doc_id == "test-doc" and result.doc_span == "0-100" and result.decided_by == "windowhash" and result.evidence is None


def test_request_payload_matches_contract(echo_server: HTTPServer) -> None:
    base_url = f"http://127.0.0.1:{echo_server.server_port}"
    check(base_url, request_id="r2", normalized_text="본문 텍스트", source={"service": "Gemini"})

    assert _EchoDetectHandler.received == {
        "request_id": "r2",
        "normalized_text": "본문 텍스트",
        "source": {"service": "Gemini"},
    }


def test_timeout_fails_open_and_marks_degraded(slow_server: HTTPServer) -> None:
    base_url = f"http://127.0.0.1:{slow_server.server_port}"
    result = check(base_url, request_id="r3", normalized_text="내용", timeout=0.1)

    assert result.blocked is False
    assert result.degraded is True
    assert "잠정" in result.reason


def test_unreachable_host_fails_open_and_marks_degraded() -> None:
    # 포트 1(예약 포트, 아무도 안 듣는다)로 즉시 연결 거부를 유도한다.
    result = check("http://127.0.0.1:1", request_id="r4", normalized_text="내용", timeout=0.2)

    assert result.blocked is False
    assert result.degraded is True


def test_decision_block_is_exposed_for_gateway(echo_server: HTTPServer) -> None:
    result = check(f"http://127.0.0.1:{echo_server.server_port}", request_id="r-dec", normalized_text="본문")
    assert result.action == "block" and result.reason_code == "doc_excerpt" and result.http_status == 403
    assert result.user_message == "차단 안내" and result.request_id == "srv-echo" and result.degraded is False


def test_old_server_without_decision_block_still_works() -> None:
    class _OldHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"]); self.rfile.read(length)
            body = json.dumps({"blocked": False, "reason": "매치 없음", "evidence": None}).encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def log_message(self, *_a) -> None:
            pass

    server = _make_server(_OldHandler)
    try:
        result = check(f"http://127.0.0.1:{server.server_port}", request_id="r-old", normalized_text="본문")
        assert result.action == "allow" and result.reason_code == "none" and result.request_id == "r-old"
    finally:
        server.shutdown()


def test_unreachable_marks_allow_degraded() -> None:
    result = check("http://127.0.0.1:9", request_id="r-down", normalized_text="본문", timeout=0.3)
    assert result.degraded and result.action == "allow_degraded" and result.reason_code == "detection_unreachable"
