"""Bounded metadata-only telemetry delivery, separate from enforcement.

One worker coalesces request notifications and sends real process counters during
idle periods too. It never records prompts or produces synthetic traffic.
"""
from __future__ import annotations

import math
import threading
import time

from dashboard_event_sender import send_dashboard_metrics


class MetricsPublisher:
    def __init__(self, snapshot_factory, *, sender=send_dashboard_metrics,
                 heartbeat=10.0, min_interval=1.0, logger=print, on_payload=None, on_status=None):
        if not math.isfinite(heartbeat) or heartbeat <= 0:
            raise ValueError('heartbeat must be positive and finite')
        if not math.isfinite(min_interval) or min_interval <= 0:
            raise ValueError('min_interval must be positive and finite')
        self._snapshot_factory = snapshot_factory
        self._sender = sender
        # 2026-10-10 Gateway 처리 설정: 응답 본문(gateway_settings)과 상태 코드(400이면 적용 보고를 뺌)
        self._on_payload = on_payload
        self._on_status = on_status
        self._heartbeat = heartbeat
        self._min_interval = min_interval
        self._logger = logger
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lifecycle = threading.Lock()
        self._thread = None
        self._last_status = None

    def start(self):
        with self._lifecycle:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._wake.set()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name='dashboard-metrics-publisher')
            self._thread.start()

    def notify(self):
        # Event is a one-bit signal: no backlog and no network work on this path.
        self._wake.set()

    def stop(self):
        with self._lifecycle:
            self._stop.set()
            self._wake.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def _log_status(self, status):
        if status not in {'sent', 'failed', 'disabled'}:
            status = 'failed'
        if status != self._last_status:
            self._last_status = status
            try:
                self._logger(f'[DASHBOARD] metrics status={status}')
            except Exception:
                pass

    def _run(self):
        last_sent = None
        while not self._stop.is_set():
            self._wake.wait(timeout=self._heartbeat)
            self._wake.clear()
            if self._stop.is_set():
                break
            if last_sent is not None:
                deadline = last_sent + self._min_interval
                # Some platforms can return a timed wait just before its deadline.
                while (remaining := deadline - time.monotonic()) > 0:
                    if self._stop.wait(remaining):
                        return
            result = None
            try:
                snapshot = self._snapshot_factory()
                result = self._sender(snapshot)
                self._log_status(getattr(result, 'status', 'failed'))
            except Exception:
                # No payload, credential, URL or exception message enters logs.
                self._log_status('failed')
            last_sent = time.monotonic()
            if result is not None:
                self._deliver(result)

    def _deliver(self, result):
        """설정 처리는 전송과 따로: 여기서 예외가 나도 전송 상태·다음 전송에 영향이 없다."""
        for callback, value in ((self._on_payload, getattr(result, 'payload', None)),
                                (self._on_status, getattr(result, 'http_status', None))):
            if callback is None:
                continue
            try:
                callback(value)
            except Exception as exc:
                try:
                    self._logger(f'[DASHBOARD] metrics response handling failed error_type={type(exc).__name__}')
                except Exception:
                    pass
