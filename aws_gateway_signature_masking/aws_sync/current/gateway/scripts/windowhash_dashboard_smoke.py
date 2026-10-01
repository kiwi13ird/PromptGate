"""Send one metadata-only WindowHash event through the deployed Gateway mapper.

The values are copied from an existing Detection decision row. No prompt,
document text, hash, credential, or matched value is read or transmitted.
"""

from __future__ import annotations

from types import SimpleNamespace

from dashboard_event_mapper import build_dashboard_event
from dashboard_event_sender import send_dashboard_event


result = SimpleNamespace(
    blocked=True,
    action="block",
    degraded=False,
    decided_by="windowhash",
    request_id="codex-windowhash-metadata-check-20260929",
    http_status=403,
    reason_code="doc_excerpt",
    policy_version=None,
    doc_id="07_채용평가서",
    doc_span="200-500",
    input_span="0-300",
    score=None,
    match_rate=1.0,
    pii_hits=None,
)

event, skip_reason = build_dashboard_event(
    result=result,
    request_id=result.request_id,
    identity={"client_id": "codex-windowhash-metadata-check"},
    target_llm="ChatGPT",
    host="api.openai.com",
    endpoint="/integration/windowhash-metadata-check",
    content_type="prompt",
    enforcement_applied=True,
    http_status=403,
)
if event is None:
    raise SystemExit(f"mapping skipped: {skip_reason}")

delivery = send_dashboard_event(event)
print(f"event_id={event['eventId']}")
print(f"delivery_status={delivery.status}")
print(f"http_status={delivery.http_status}")
print(f"detector={event['detections'][0]['detector']}")
print(f"coverage={event['detections'][0]['score']}")
