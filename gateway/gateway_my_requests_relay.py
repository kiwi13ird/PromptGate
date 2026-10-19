"""내 요청 기록 중계 (2026-10-11).

확장 프로그램 페이지 → http://llm-gateway.local/__llmsgw/my/requests[/<id>/evidence]
(PAC가 llm-gateway.local을 이미 Gateway로 보낸다) → Gateway가 이 flow의 목적지를
대시보드 내부 주소(/api/my/requests...)로 바꾸고, 실제 전달·대기는 mitmproxy가 비동기로 한다.

request 훅 안에서 대시보드를 직접 부르지 않는다: 훅은 mitmproxy 이벤트 루프에서 동기로 돌기 때문에
그 안의 네트워크 대기는 Gateway의 다른 모든 요청을 함께 멈춘다.

대시보드 주소: DASHBOARD_MY_REQUESTS_URL(있으면) 또는 DASHBOARD_EVENT_URL의 스킴·호스트·포트만 쓴다(경로는 버림).
열람 키는 로그에 남기지 않는다. 중계 요청은 Gateway 지표(평균·p95)에 들어가지 않는다(_start_gateway_metric 전에 끝남).

llm-gateway.local의 나머지 경로(보강): gateway.py가 직접 답하는 health(이 모듈보다 앞)·review GET(이 모듈보다 뒤)만 넘기고,
그 밖은 Gateway가 직접 404로 답한다. upstream(llm-gateway.local:80)으로 넘기면 열람 키 머리가 그대로 실려 나가기 때문이다.
gateway.py에 llm-gateway.local 경로를 새로 더하면 _gateway_own_route에도 더해야 한다.

gateway.py 연결 지점(3곳):
  _handle_request  llm-gateway.local 분기 안, health 다음:  if my_requests_relay.handle_request(flow): return
  response()       맨 앞:                                   my_requests_relay.handle_response(flow)
  error()          맨 앞:                                   my_requests_relay.handle_error(flow)
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

from mitmproxy import http

PREFIX = "/__llmsgw/my/requests"
UPSTREAM_LIST_PATH = "/api/my/requests"
# gateway.py _handle_request가 직접 답하는 llm-gateway.local 경로(같은 조건)
GATEWAY_HEALTH_PREFIX = "/__llmsgw/health"      # 방식 무관, 이 모듈보다 앞에서 처리
GATEWAY_REVIEW_PREFIX = "/__llmsgw/review/"     # GET만, 이 모듈보다 뒤에서 처리
_LIST_ROUTE = re.compile(r"^/__llmsgw/my/requests$")
# Gateway가 만드는 기록 번호는 evt-<uuid4>. 여유는 두되 '/'·'%'·'.'으로 시작하는 값은 받지 않는다(경로 바꿔치기 방지)
_EVIDENCE_ROUTE = re.compile(r"^/__llmsgw/my/requests/([A-Za-z0-9_-][A-Za-z0-9._-]{0,127})/evidence$")
# 확장 프로그램 열람 키(32바이트 base64url, utils/validation.js isValidViewerKey와 같음)
_VIEWER_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
# manifest.json의 key로 고정되는 확장 프로그램 ID. 다른 빌드를 쓰면 MY_REQUESTS_ALLOWED_ORIGINS로 바꾼다
DEFAULT_ALLOWED_ORIGINS = ("chrome-extension://mdeejegfkckeeolcgbkkblnccealmgan",)
# 근거 응답은 프롬프트·문서 구간을 실어 수 MB가 될 수 있다(대시보드 TEXT_LIMIT 200만 자)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_PASS_STATUSES = {200, 401, 404, 405}
META = "gw_my_requests_relay"            # "local"(Gateway가 직접 답함) 또는 "upstream"(대시보드로 보냄)


def _allowed_origins() -> tuple[str, ...]:
    raw = os.getenv("MY_REQUESTS_ALLOWED_ORIGINS")
    if raw is None:
        return DEFAULT_ALLOWED_ORIGINS
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def dashboard_target() -> tuple[str, str, int] | None:
    """대시보드 주소(스킴·호스트·포트)만. 이벤트 전송 주소(DASHBOARD_EVENT_URL)와 같은 내부 경로를 쓴다."""
    raw = (os.getenv("DASHBOARD_MY_REQUESTS_URL") or os.getenv("DASHBOARD_EVENT_URL") or "").strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    return parts.scheme, parts.hostname, port or (443 if parts.scheme == "https" else 80)


def _cors_headers(origin: str) -> dict[str, str]:
    if origin and origin in _allowed_origins():
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    return {}


def _json_response(status: int, payload: dict | bytes, origin: str = "", extra: dict | None = None) -> http.Response:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        **_cors_headers(origin),
        **(extra or {}),
    }
    return http.Response.make(status, body, headers)


def _error(code: str) -> dict:
    return {"error": {"code": code}}


def _local(flow: http.HTTPFlow, status: int, code: str, origin: str) -> bool:
    flow.metadata[META] = "local"
    flow.response = _json_response(status, _error(code), origin)
    return True


def _gateway_own_route(method: str, path: str, route: str) -> bool:
    return path.startswith(GATEWAY_HEALTH_PREFIX) or (method == "GET" and route.startswith(GATEWAY_REVIEW_PREFIX))


def handle_request(flow: http.HTTPFlow) -> bool:
    """llm-gateway.local 요청 처리(gateway.py가 이 호스트일 때만 부른다).
    내 요청 기록 경로면 중계·직접 응답하고 True. gateway.py가 직접 답하는 health·review GET은 건드리지 않고 False.
    그 밖의 경로는 Gateway가 직접 404로 답하고 True(upstream으로 넘기지 않는다)."""
    req = flow.request
    route = req.path.split("?", 1)[0]
    origin = req.headers.get("Origin", "")
    if route != PREFIX and not route.startswith(PREFIX + "/"):
        if _gateway_own_route(req.method, req.path, route):
            return False
        return _local(flow, 404, "NOT_FOUND", origin)

    if req.method == "OPTIONS":
        # 확장 프로그램 페이지는 host_permissions가 있으면 CORS를 건너뛴다. 혹시 사전 확인이 와도 허용 출처에만 답한다
        flow.metadata[META] = "local"
        if not _cors_headers(origin):
            flow.response = _json_response(403, _error("ORIGIN_NOT_ALLOWED"))
            return True
        flow.response = http.Response.make(204, b"", {
            **_cors_headers(origin),
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "X-Viewer-Key",
            "Access-Control-Max-Age": "600",
            "Cache-Control": "no-store",
        })
        return True
    if req.method != "GET":
        return _local(flow, 405, "METHOD_NOT_ALLOWED", origin)
    if req.raw_content:
        return _local(flow, 400, "BODY_NOT_ALLOWED", origin)

    if _LIST_ROUTE.match(route):
        upstream_path = UPSTREAM_LIST_PATH
    else:
        match = _EVIDENCE_ROUTE.match(route)
        if not match:
            return _local(flow, 404, "NOT_FOUND", origin)
        upstream_path = f"{UPSTREAM_LIST_PATH}/{match.group(1)}/evidence"

    keys = req.headers.get_all("X-Viewer-Key")
    if len(keys) != 1 or not _VIEWER_KEY.match(keys[0]):
        return _local(flow, 401, "VIEWER_KEY_REQUIRED", origin)
    target = dashboard_target()
    if target is None:
        return _local(flow, 503, "RELAY_NOT_CONFIGURED", origin)

    scheme, host, port = target
    default_port = 443 if scheme == "https" else 80
    flow.metadata[META] = "upstream"
    flow.metadata["gw_my_requests_origin"] = origin
    req.scheme, req.host, req.port = scheme, host, port
    req.path = upstream_path                     # 쿼리(?t=...)는 버린다 - 대시보드는 쓰지 않는다
    # 머리는 새로 만든다: 열람 키만 넘기고 쿠키·인증·식별·Origin·Referer·X-Forwarded-* 는 모두 버린다
    req.headers = http.Headers(
        Host=host if port == default_port else f"{host}:{port}",
        Accept="application/json",
        User_Agent="llmsgw-my-requests-relay",
        X_Viewer_Key=keys[0],
    )
    return True


def handle_response(flow: http.HTTPFlow) -> None:
    """대시보드 응답을 정리한다: JSON·정해진 상태만 그대로, 나머지는 고정된 오류. 쿠키·서버 머리는 넘기지 않는다."""
    if flow.metadata.get(META) != "upstream" or flow.response is None:
        return
    origin = flow.metadata.get("gw_my_requests_origin", "")
    resp = flow.response
    try:
        body = resp.content or b""
    except ValueError:                           # 알 수 없는 압축
        body = None
    content_type = resp.headers.get("Content-Type", "")
    if body is not None and len(body) > MAX_RESPONSE_BYTES:
        flow.response = _json_response(502, _error("RESPONSE_TOO_LARGE"), origin)
    elif body is not None and resp.status_code in _PASS_STATUSES and content_type.startswith("application/json"):
        flow.response = _json_response(resp.status_code, body, origin)
    else:
        print("[MY-REQUESTS] dashboard answered status=", resp.status_code, "json=",
              content_type.startswith("application/json"))
        flow.response = _json_response(504 if resp.status_code == 504 else 502,
                                       _error("DASHBOARD_UNAVAILABLE"), origin)


def handle_error(flow: http.HTTPFlow) -> None:
    """대시보드 연결 실패. mitmproxy 기본 502 화면에는 내부 주소가 적히므로 연결을 끊는다(확장 프로그램은 '연결 실패'로 보여 준다)."""
    if flow.metadata.get(META) != "upstream":
        return
    print("[MY-REQUESTS] dashboard relay failed:", (flow.error.msg if flow.error else "")[:200])
    if flow.killable:
        flow.kill()
