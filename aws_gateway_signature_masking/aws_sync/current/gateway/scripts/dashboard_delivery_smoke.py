"""Send one synthetic metadata-only event to the fake receiver."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard_event_sender import send_dashboard_event


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", choices=("sent", "failed", "disabled"), required=True)
    args = parser.parse_args()

    event = {
        "type": "SECURITY_EVENT",
        "eventId": "evt-smoke-001",
        "requestId": "req-smoke-001",
        "timestamp": "2026-09-20T05:00:00Z",
        "clientId": "client-smoke",
        "targetLlm": "ChatGPT",
        "contentType": "prompt",
        "finalAction": "BLOCK",
        "degraded": False,
        "detections": [],
        "enforcement": {"applied": True, "httpStatus": 403},
    }
    result = send_dashboard_event(event)
    print(
        "[SMOKE] delivery "
        f"status={result.status} httpStatus={result.http_status or 'none'} "
        f"errorType={result.error_type or 'none'}"
    )
    if result.status != args.expect:
        print(f"[FAIL] expected={args.expect} actual={result.status}")
        return 1
    print(f"[PASS] expected={args.expect}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
