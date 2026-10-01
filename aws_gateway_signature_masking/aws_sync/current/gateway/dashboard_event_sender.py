"""Best-effort, metadata-only Dashboard Event delivery."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import urllib.error
import urllib.request


DEFAULT_TIMEOUT_SECONDS = 0.3


@dataclass(frozen=True)
class DeliveryResult:
    status: str
    http_status: int | None = None
    error_type: str | None = None


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
    """Send once and never raise into the Gateway enforcement path.

    TODO: Dashboard delivery retry policy pending team agreement.
    """

    resolved_url = url if url is not None else os.getenv("DASHBOARD_EVENT_URL")
    resolved_token = token if token is not None else os.getenv("DASHBOARD_INGEST_TOKEN")
    if not resolved_url or not resolved_token:
        return DeliveryResult(status="disabled")

    resolved_timeout = timeout if timeout is not None else _timeout_from_env()
    open_request = opener or urllib.request.urlopen

    try:
        payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
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
        with open_request(request, timeout=resolved_timeout) as response:
            status = int(response.getcode())
        return DeliveryResult(
            status="sent" if 200 <= status < 300 else "failed",
            http_status=status,
            error_type=None if 200 <= status < 300 else f"HTTP_{status}",
        )
    except Exception as exc:
        logger(f"[DASHBOARD] metrics delivery failed error_type={type(exc).__name__}")
        return DeliveryResult(status="failed", error_type=type(exc).__name__)
