"""Gateway 지표 확장 칸 협상(2026-10-15) - 새 칸은 대시보드가 받겠다고 알린 뒤에만 싣는다.

운영 대시보드 서버(10/14판 app.mjs gatewayMetricsPayload)는 지표 칸 목록을 정확히 비교한다: 모르는 칸이 하나라도 오면
지표 전체를 400으로 거부하고, avg_latency_ms·p95_latency_ms가 숫자가 아니면 422, clients 항목에 모르는 칸이 있으면
clients 목록 전체를 버린다. 그래서 새 칸(표본 수·검사 요청 수·브라우저 취소 수·IP별 확장 ID 묶음)은
  - 지표 전송 2xx 응답 본문에 "metrics_ext": 1 이상(정수)이 있을 때부터 싣고(설정 칸 gateway_settings와 같은 방식),
  - 그 칸이 없는 2xx 응답이 오면 바로 뺀다(대시보드를 옛 판으로 되돌린 경우),
  - 새 칸을 실은 전송이 400이면 빼고 RETRY_AFTER_SECONDS 동안은 알림이 와도 다시 싣지 않는다(오가며 반씩 거부되는 것 방지).
칸 정의는 docs/handoff/gateway-metrics-fix-2026-10-15/CONTRACT.md. 값·URL·토큰은 로그에 남기지 않는다.
"""
from __future__ import annotations

import threading
import time

METRICS_EXT_VERSION = 1
RETRY_AFTER_SECONDS = 300.0


class MetricsExtNegotiator:
    def __init__(self, *, clock=time.monotonic, logger=print, retry_after=RETRY_AFTER_SECONDS):
        self._clock = clock
        self._logger = logger
        self._retry_after = retry_after
        self._lock = threading.Lock()
        self._enabled = False
        self._last_sent_ext = False
        self._blocked_until = None

    def include(self) -> bool:
        """지표 전송기가 값을 만들 때 한 번 부른다. 이번 전송에 새 칸을 싣는지(그리고 그 사실을 기억한다)."""
        with self._lock:
            self._last_sent_ext = self._enabled
            return self._enabled

    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def offer(self, payload) -> None:
        """지표 전송 2xx 응답 본문(실패한 전송은 None → 아무것도 안 함)."""
        if not isinstance(payload, dict):
            return
        version = payload.get("metrics_ext")
        supported = type(version) is int and version >= METRICS_EXT_VERSION
        with self._lock:
            if supported:
                if self._enabled:
                    return
                if self._blocked_until is not None and self._clock() < self._blocked_until:
                    return
                self._blocked_until = None
                self._enabled = True
                message = f"[METRICS] ext fields on version={METRICS_EXT_VERSION}"
            else:
                if not self._enabled:
                    return
                self._enabled = False
                message = "[METRICS] ext fields off reason=not_advertised"
        self._log(message)

    def on_metrics_status(self, http_status) -> None:
        """새 칸을 실은 전송이 400이면(대시보드가 모르는 칸) 빼고 한동안 다시 싣지 않는다."""
        if http_status != 400:
            return
        with self._lock:
            if not (self._last_sent_ext and self._enabled):
                return
            self._enabled = False
            self._blocked_until = self._clock() + self._retry_after
        self._log("[METRICS] ext fields off reason=http_400")

    def _log(self, message: str) -> None:
        try:
            self._logger(message)
        except Exception:
            pass
