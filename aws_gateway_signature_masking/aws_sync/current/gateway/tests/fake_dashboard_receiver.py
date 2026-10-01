"""Minimal metadata-only receiver for Gateway sender tests.

This is not a Dashboard backend.  It validates the test Bearer token and
canonical event shape, refuses known sensitive body fields, and logs only a
small metadata summary.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import time


INGEST_PATH = "/api/events/ingest"
HEALTH_PATH = "/healthz"
FORBIDDEN_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "detection_response",
    "full_detection_response",
    "full_llm_request_body",
    "llm_request_body",
    "normalized_text",
    "prompt",
    "raw_prompt",
    "request_body",
}


@dataclass(frozen=True)
class ReceiverConfig:
    token: str
    mode: str = "success"
    delay_seconds: float = 1.0
    logger: object = print


def _normalized_key(value: object) -> str:
    return str(value).strip().lower().replace("-", "_")


def find_forbidden_keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = _normalized_key(key)
            if normalized in FORBIDDEN_KEYS:
                found.add(normalized)
            found.update(find_forbidden_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(find_forbidden_keys(nested))
    return found


class FakeDashboardHandler(BaseHTTPRequestHandler):
    server_version = "FakeDashboardReceiver/1.0"

    @property
    def config(self) -> ReceiverConfig:
        return self.server.receiver_config  # type: ignore[attr-defined]

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # Expected when the timeout test closes the client connection.
            return

    def do_GET(self) -> None:
        if self.path == HEALTH_PATH:
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != INGEST_PATH:
            self._send_json(404, {"error": "not_found"})
            return

        expected = f"Bearer {self.config.token}"
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, expected):
            self._send_json(401, {"error": "unauthorized"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            event = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "invalid_json"})
            return

        if not isinstance(event, dict):
            self._send_json(400, {"error": "event_must_be_object"})
            return

        forbidden = find_forbidden_keys(event)
        if forbidden:
            self.config.logger(
                "[FAKE-DASHBOARD] rejected event "
                f"forbidden_fields={','.join(sorted(forbidden))}"
            )
            self._send_json(422, {"error": "sensitive_field_rejected"})
            return

        missing = [key for key in ("eventId", "requestId", "finalAction") if not event.get(key)]
        if missing:
            self._send_json(400, {"error": "missing_metadata", "fields": missing})
            return

        self.config.logger(
            "[FAKE-DASHBOARD] received "
            f"eventId={event['eventId']} requestId={event['requestId']} "
            f"action={event['finalAction']} targetLlm={event.get('targetLlm', 'unknown')}"
        )

        if self.config.mode == "error":
            self._send_json(500, {"error": "simulated_failure"})
            return
        if self.config.mode == "delay":
            time.sleep(self.config.delay_seconds)
        self._send_json(201, {"accepted": True})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def build_server(
    host: str,
    port: int,
    *,
    token: str,
    mode: str = "success",
    delay_seconds: float = 1.0,
    logger=print,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), FakeDashboardHandler)
    server.receiver_config = ReceiverConfig(  # type: ignore[attr-defined]
        token=token,
        mode=mode,
        delay_seconds=delay_seconds,
        logger=logger,
    )
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19100)
    parser.add_argument("--mode", choices=("success", "error", "delay"), default="success")
    parser.add_argument("--delay-seconds", type=float, default=1.0)
    args = parser.parse_args()

    token = os.getenv("FAKE_DASHBOARD_TOKEN")
    if not token:
        parser.error("FAKE_DASHBOARD_TOKEN must be set to a test-only value")

    server = build_server(
        args.host,
        args.port,
        token=token,
        mode=args.mode,
        delay_seconds=args.delay_seconds,
    )
    print(
        "[FAKE-DASHBOARD] test receiver started "
        f"host={args.host} port={server.server_port} mode={args.mode}"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("[FAKE-DASHBOARD] stopped")


if __name__ == "__main__":
    main()
