from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
from types import SimpleNamespace


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client_identity import read_and_strip_identity
from dashboard_event_mapper import build_dashboard_event
from dashboard_event_sender import send_dashboard_event


def result(**overrides):
    values = {
        "blocked": True,
        "action": "block",
        "degraded": False,
        "decided_by": "signature",
        "request_id": "req-test-001",
        "http_status": 403,
        "reason": "SECRET-RAW-REASON",
        "reason_code": "pii",
        "policy_version": None,
        "pii_hits": "KR_PHONE:2,KR_RRN:1",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def map_event(detection_result, **overrides):
    values = {
        "result": detection_result,
        "request_id": detection_result.request_id,
        "identity": {
            "client_id": "client-test",
            "tenant_id": "tenant-test",
            "extension_version": "1.0.0",
        },
        "target_llm": "ChatGPT",
        "host": "chatgpt.com",
        "endpoint": "/backend-api/f/conversation",
        "content_type": "prompt",
        "enforcement_applied": detection_result.action == "block",
        "http_status": detection_result.http_status,
        "event_id_factory": lambda: "evt-test-001",
        "timestamp_factory": lambda: "2026-09-20T05:00:00Z",
    }
    values.update(overrides)
    return build_dashboard_event(**values)


class IdentityTests(unittest.TestCase):
    def test_reads_and_strips_internal_headers(self):
        headers = {
            "x-llmsgw-client-id": "client-123",
            "x-llmsgw-tenant-id": "tenant-456",
            "x-llmsgw-extension-version": "1.2.3",
            "authorization": "must-remain-for-upstream",
        }
        flow = SimpleNamespace(request=SimpleNamespace(headers=headers))

        identity = read_and_strip_identity(flow)

        self.assertEqual(identity["client_id"], "client-123")
        self.assertNotIn("x-llmsgw-client-id", headers)
        self.assertNotIn("x-llmsgw-tenant-id", headers)
        self.assertNotIn("x-llmsgw-extension-version", headers)
        self.assertEqual(headers["authorization"], "must-remain-for-upstream")


class MapperTests(unittest.TestCase):
    def test_block_maps_confirmed_enforcement_metadata(self):
        event, reason = map_event(result())

        self.assertIsNone(reason)
        self.assertEqual(event["eventId"], "evt-test-001")
        self.assertNotEqual(event["eventId"], event["requestId"])
        self.assertEqual(event["finalAction"], "BLOCK")
        self.assertEqual(event["enforcement"], {"applied": True, "httpStatus": 403})
        self.assertEqual(event["clientId"], "client-test")
        self.assertEqual(event["tenantId"], "tenant-test")
        self.assertEqual(event["detectionOutcome"], "MATCH")
        self.assertEqual(
            event["detections"],
            [{
                "detector": "SIGNATURE",
                "matchType": "SIGNATURE_RULE",
                "entityCounts": [
                    {"entityType": "KR_PHONE", "count": 2},
                    {"entityType": "KR_RRN", "count": 1},
                ],
                "action": "BLOCK",
            }],
        )
        self.assertNotIn("recommendedAction", event)
        self.assertEqual(event["reasonCode"], "pii")

    def test_forwards_policy_version_only_when_detection_provides_it(self):
        event, reason = map_event(result(policy_version="policy-2026-09"))

        self.assertIsNone(reason)
        self.assertEqual(event["policyVersion"], "policy-2026-09")

    def test_event_ids_are_distinct_uuid_values(self):
        first, _ = build_dashboard_event(
            result=result(), request_id="req-same", identity={}, target_llm="ChatGPT",
            host="chatgpt.com", endpoint="/backend-api/f/conversation",
            content_type="prompt", enforcement_applied=True, http_status=403,
        )
        second, _ = build_dashboard_event(
            result=result(), request_id="req-same", identity={}, target_llm="ChatGPT",
            host="chatgpt.com", endpoint="/backend-api/f/conversation",
            content_type="prompt", enforcement_applied=True, http_status=403,
        )

        self.assertNotEqual(first["eventId"], second["eventId"])
        self.assertNotEqual(first["eventId"], "req-same")
        self.assertEqual(first["clientId"], "unknown-client")

    def test_allow_degraded_maps_to_unavailable_fail_open(self):
        degraded = result(
            blocked=False,
            action="allow_degraded",
            degraded=True,
            decided_by="none",
            reason_code="detection_unreachable",
            http_status=None,
        )
        event, reason = map_event(
            degraded,
            enforcement_applied=False,
            http_status=None,
        )

        self.assertIsNone(reason)
        self.assertEqual(event["finalAction"], "ALLOW")
        self.assertEqual(event["detectionOutcome"], "UNAVAILABLE")
        self.assertTrue(event["degraded"])
        self.assertEqual(event["degradedReason"], "UNREACHABLE")
        self.assertEqual(event["failurePolicy"], "FAIL_OPEN")
        self.assertEqual(event["reasonCode"], "detection_unreachable")
        self.assertNotIn("enforcement", event)

    def test_regular_allow_is_disabled_by_default(self):
        allowed = result(
            blocked=False,
            action="allow",
            degraded=False,
            decided_by="none",
            http_status=None,
        )
        event, reason = map_event(
            allowed,
            enforcement_applied=False,
            http_status=None,
        )

        self.assertIsNone(event)
        self.assertEqual(reason, "ALLOW event reporting disabled")

    def test_windowhash_uses_confirmed_match_rate_and_normalized_spans(self):
        windowhash = result(
            decided_by="windowhash",
            score=0.1,
            match_rate=0.75,
            doc_id="doc-001",
            input_span="4-34",
            doc_span="24100-24130",
            pii_hits=None,
            reason_code="doc_excerpt",
        )
        event, reason = map_event(windowhash)

        self.assertIsNone(reason)
        self.assertEqual(event["detectionOutcome"], "MATCH")
        self.assertEqual(event["detections"], [{
            "detector": "WINDOW_HASH",
            "matchType": "TEXT_FRAGMENT",
            "score": 0.75,
            "scoreKind": "COVERAGE",
            "matchedDocumentId": "doc-001",
            "inputSpan": {"charStart": 4, "charEnd": 34, "endExclusive": True},
            "documentSpan": {"charStart": 24100, "charEnd": 24130, "endExclusive": True},
            "action": "BLOCK",
        }])

    def test_incomplete_evidence_is_skipped_instead_of_invented(self):
        event, reason = map_event(result(decided_by="signature", pii_hits="SECRET-PII"))

        self.assertIsNone(event)
        self.assertEqual(reason, "incomplete Signature evidence")

    def test_sensitive_detection_values_are_not_copied(self):
        event, _ = map_event(result())
        serialized = json.dumps(event)

        for forbidden in (
            "SECRET-RAW-REASON",
            "990314-1234567",
            "normalized_text",
            "authorization",
            "cookie",
            "extension_version",
        ):
            self.assertNotIn(forbidden, serialized)


class SenderTests(unittest.TestCase):
    def test_successful_sender_posts_once_with_bearer_token(self):
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received["body"] = json.loads(self.rfile.read(length))
                received["authorization"] = self.headers.get("Authorization")
                self.send_response(201)
                self.end_headers()

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logs = []
        try:
            event, _ = map_event(result())
            delivery = send_dashboard_event(
                event,
                url=f"http://127.0.0.1:{server.server_port}/api/events/ingest",
                token="test-token",
                timeout=1,
                logger=logs.append,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(delivery.status, "sent")
        self.assertEqual(delivery.http_status, 201)
        self.assertEqual(received["body"]["eventId"], "evt-test-001")
        self.assertEqual(received["authorization"], "Bearer test-token")
        self.assertNotIn("test-token", " ".join(logs))

    def test_sender_timeout_never_raises(self):
        def timeout_opener(*_args, **_kwargs):
            raise TimeoutError("simulated timeout")

        event, _ = map_event(result())
        delivery = send_dashboard_event(
            event,
            url="http://127.0.0.1:1/api/events/ingest",
            token="test-token",
            timeout=0.01,
            opener=timeout_opener,
            logger=lambda _message: None,
        )

        self.assertEqual(delivery.status, "failed")
        self.assertEqual(delivery.error_type, "TimeoutError")


if __name__ == "__main__":
    unittest.main()
