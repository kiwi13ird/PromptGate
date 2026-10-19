from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
import urllib.request


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dashboard_event_sender import send_dashboard_event
from fake_dashboard_receiver import build_server


TOKEN = "receiver-test-token"


def safe_event() -> dict:
    return {
        "type": "SECURITY_EVENT",
        "eventId": "evt-fixture-001",
        "requestId": "req-fixture-001",
        "timestamp": "2026-09-20T05:00:00Z",
        "clientId": "client-fixture",
        "targetLlm": "ChatGPT",
        "contentType": "prompt",
        "finalAction": "BLOCK",
        "degraded": False,
        "detections": [],
        "enforcement": {"applied": True, "httpStatus": 403},
    }


class RunningReceiver:
    def __init__(self, *, mode="success", delay_seconds=0.2):
        self.logs = []
        self.server = build_server(
            "127.0.0.1",
            0,
            token=TOKEN,
            mode=mode,
            delay_seconds=delay_seconds,
            logger=self.logs.append,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/api/events/ingest"


class FakeReceiverTests(unittest.TestCase):
    def test_success_returns_201_and_logs_safe_metadata_only(self):
        with RunningReceiver() as receiver:
            result = send_dashboard_event(
                safe_event(), url=receiver.url, token=TOKEN, timeout=1,
                logger=lambda _message: None,
            )

        self.assertEqual(result.status, "sent")
        self.assertEqual(result.http_status, 201)
        output = " ".join(receiver.logs)
        self.assertIn("evt-fixture-001", output)
        self.assertNotIn(TOKEN, output)

    def test_wrong_bearer_is_rejected(self):
        with RunningReceiver() as receiver:
            result = send_dashboard_event(
                safe_event(), url=receiver.url, token="wrong", timeout=1,
                logger=lambda _message: None,
            )
        self.assertEqual(result.status, "failed")

    def test_sensitive_body_field_is_rejected_without_value_logging(self):
        marker = "SENSITIVE-FIXTURE-MUST-NOT-BE-LOGGED"
        event = safe_event()
        event["normalized_text"] = marker
        body = json.dumps(event).encode("utf-8")

        with RunningReceiver() as receiver:
            request = urllib.request.Request(
                receiver.url,
                data=body,
                headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=1)

        self.assertEqual(raised.exception.code, 422)
        self.assertNotIn(marker, " ".join(receiver.logs))

    def test_http_500_isolated_as_failed_delivery(self):
        with RunningReceiver(mode="error") as receiver:
            result = send_dashboard_event(
                safe_event(), url=receiver.url, token=TOKEN, timeout=1,
                logger=lambda _message: None,
            )
        self.assertEqual(result.status, "failed")

    def test_delayed_response_isolated_as_timeout(self):
        with RunningReceiver(mode="delay", delay_seconds=0.2) as receiver:
            result = send_dashboard_event(
                safe_event(), url=receiver.url, token=TOKEN, timeout=0.02,
                logger=lambda _message: None,
            )
        self.assertEqual(result.status, "failed")
        self.assertIn(result.error_type, {"TimeoutError", "URLError"})


if __name__ == "__main__":
    unittest.main()
