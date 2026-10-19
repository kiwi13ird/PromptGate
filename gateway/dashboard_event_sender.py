"""Best-effort, metadata-only Dashboard Event delivery."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import urllib.error
import urllib.request


DEFAULT_TIMEOUT_SECONDS = 0.3
# 지표 응답 본문 상한(2026-10-10 Gateway 처리 설정). 넘으면 본문을 쓰지 않는다
METRICS_RESPONSE_MAX_BYTES = 65536


@dataclass(frozen=True)
class DeliveryResult:
    status: str
    http_status: int | None = None
    error_type: str | None = None
    # 지표 전송 2xx 응답의 JSON 객체(gateway_settings 칸을 담아 온다). 그 밖에는 None
    payload: dict | None = None


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def report_allow_events_enabled() -> bool:
    return _truthy(os.getenv("DASHBOARD_REPORT_ALLOW_EVENTS"))


def dashboard_integration_enabled() -> bool:
    return bool(os.getenv("DASHBOARD_EVENT_URL") and os.getenv("DASHBOARD_INGEST_TOKEN"))


def _metrics_url() -> str | None:
    configured = os.getenv("DASHBOARD_METRICS_URL")
    if configured:
        return configured
    event_url = os.getenv("DASHBOARD_EVENT_URL")
    if not event_url:
        return None
    suffix = "/events/ingest"
    return (
        event_url[: -len(suffix)] + "/traffic/metrics"
        if event_url.endswith(suffix)
        else None
    )


def metrics_url() -> str | None:
    """지표를 보내는 대시보드 주소. 연동이 꺼져 있으면(토큰 없음) None - 그때는 설정도 받지 않는다."""
    if not os.getenv("DASHBOARD_INGEST_TOKEN"):
        return None
    return _metrics_url()


def _response_payload(body: bytes | None) -> dict | None:
    """2xx 응답 본문 → JSON 객체. 상한 초과·JSON 아님·객체 아님 → None. 본문은 로그에 남기지 않는다."""
    if not body or len(body) > METRICS_RESPONSE_MAX_BYTES:
        return None
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _timeout_from_env() -> float:
    raw = os.getenv("DASHBOARD_EVENT_TIMEOUT")
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_TIMEOUT_SECONDS


def _safe_log_fields(event: dict) -> str:
    return (
        f"eventId={event.get('eventId', 'unknown')} "
        f"requestId={event.get('requestId', 'unknown')} "
        f"action={event.get('finalAction', 'unknown')}"
    )


def send_dashboard_event(
    event: dict,
    *,
    url: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
    opener=None,
    logger=print,
) -> DeliveryResult:
    """One delivery attempt, called by the durable outbox worker in production."""

    resolved_url = url if url is not None else os.getenv("DASHBOARD_EVENT_URL")
    resolved_token = token if token is not None else os.getenv("DASHBOARD_INGEST_TOKEN")
    if not resolved_url or not resolved_token:
        return DeliveryResult(status="disabled")

    resolved_timeout = timeout if timeout is not None else _timeout_from_env()
    open_request = opener or urllib.request.urlopen

    try:
        payload = json.dumps(event, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode("utf-8")
        request = urllib.request.Request(
            resolved_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {resolved_token}",
            },
            method="POST",
        )
        with open_request(request, timeout=resolved_timeout) as response:
            status = int(response.getcode())
        if 200 <= status < 300:
            logger(f"[DASHBOARD] event sent {_safe_log_fields(event)}")
            return DeliveryResult(status="sent", http_status=status)

        logger(
            f"[DASHBOARD] event delivery failed {_safe_log_fields(event)} "
            f"error_type=HTTP_{status}"
        )
        return DeliveryResult(status="failed", http_status=status, error_type=f"HTTP_{status}")
    except urllib.error.HTTPError as exc:
        logger(f"[DASHBOARD] event delivery failed {_safe_log_fields(event)} error_type=HTTP_{exc.code}")
        return DeliveryResult(status="failed",http_status=exc.code,error_type=f"HTTP_{exc.code}")
    except Exception as exc:  # Delivery must never alter BLOCK/PASS enforcement.
        error_type = type(exc).__name__
        logger(
            f"[DASHBOARD] event delivery failed {_safe_log_fields(event)} "
            f"error_type={error_type}"
        )
        return DeliveryResult(status="failed", error_type=error_type)


def send_dashboard_metrics(
    snapshot: dict,
    *,
    url: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
    opener=None,
    logger=print,
) -> DeliveryResult:
    """Deliver aggregate counters only; no prompt or response content."""
    resolved_url = url if url is not None else _metrics_url()
    resolved_token = token if token is not None else os.getenv("DASHBOARD_INGEST_TOKEN")
    if not resolved_url or not resolved_token:
        return DeliveryResult(status="disabled")
    resolved_timeout = timeout if timeout is not None else _timeout_from_env()
    open_request = opener or urllib.request.urlopen
    try:
        payload = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            resolved_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {resolved_token}",
            },
            method="POST",
        )
        body = None
        with open_request(request, timeout=resolved_timeout) as response:
            status = int(response.getcode())
            if 200 <= status < 300:
                # 2026-10-10: 응답의 gateway_settings(처리 설정)를 읽는다. 읽기 실패는 전송 상태를 바꾸지 않는다
                try:
                    body = response.read(METRICS_RESPONSE_MAX_BYTES + 1)
                except Exception:
                    body = None
        ok = 200 <= status < 300
        return DeliveryResult(
            status="sent" if ok else "failed",
            http_status=status,
            error_type=None if ok else f"HTTP_{status}",
            payload=_response_payload(body) if ok else None,
        )
    except urllib.error.HTTPError as exc:
        # 400 등도 상태 코드를 남긴다(설정 적용 보고를 실은 전송이 400이면 다음부터 빼기 위해)
        logger(f"[DASHBOARD] metrics delivery failed error_type=HTTP_{exc.code}")
        return DeliveryResult(status="failed", http_status=exc.code, error_type=f"HTTP_{exc.code}")
    except Exception as exc:
        logger(f"[DASHBOARD] metrics delivery failed error_type={type(exc).__name__}")
        return DeliveryResult(status="failed", error_type=type(exc).__name__)
