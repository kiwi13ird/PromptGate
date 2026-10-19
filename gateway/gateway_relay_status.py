"""확장 프로그램 중계(websocket_server.py)의 접속 현황 조회(2026-10-12 시스템 상태 화면).

지표 전송기 스레드(gateway._publisher_snapshot)에서만 부른다. 요청 처리 경로에서는 부르지 않는다.
중계 HTTP(127.0.0.1:8766)의 GET /status → {"connected": 열린 웹소켓 연결 수, "registered": 등록된 클라이언트 id 수}.
실패하면 예외 없이 {"ok": False, "connected": 0, "registered": 0}. 값(주소·응답 본문)은 로그에 남기지 않는다.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

RELAY_STATUS_URL = "http://127.0.0.1:8766/status"
TIMEOUT_SECONDS = 0.5
MAX_BODY_BYTES = 4096

# 이 컴퓨터 안의 중계만 부르므로 환경 변수의 프록시 설정은 쓰지 않는다
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_last_ok = None


def _log(message: str) -> None:
    print(message, flush=True)


def _failed() -> dict:
    return {"ok": False, "connected": 0, "registered": 0}


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _parse(body: bytes) -> dict | None:
    if len(body) > MAX_BODY_BYTES:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    connected, registered = _count(data.get("connected")), _count(data.get("registered"))
    if connected is None or registered is None:
        return None
    return {"ok": True, "connected": connected, "registered": registered}


def fetch_relay_status(*, url: str | None = None, timeout: float = TIMEOUT_SECONDS,
                       opener=None, logger=_log) -> dict:
    """중계 접속 현황 한 번 조회. 절대 예외를 내지 않는다. 로그는 정상↔실패가 바뀔 때만 한 줄."""
    global _last_ok
    error_type = None
    result = None
    try:
        with (opener or _OPENER).open(url or RELAY_STATUS_URL, timeout=timeout) as response:
            status = int(response.getcode())
            if status == 200:
                result = _parse(response.read(MAX_BODY_BYTES + 1))
                if result is None:
                    error_type = "InvalidResponse"
            else:
                error_type = f"HTTP_{status}"
    except urllib.error.HTTPError as exc:
        error_type = f"HTTP_{exc.code}"
    except Exception as exc:
        error_type = type(exc).__name__
    ok = result is not None
    if ok != _last_ok:
        _last_ok = ok
        try:
            logger("[RELAY] status ok" if ok else f"[RELAY] status unavailable error_type={error_type}")
        except Exception:
            pass
    return result if ok else _failed()
