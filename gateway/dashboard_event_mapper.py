"""Map confirmed Gateway runtime metadata to Dashboard canonical Security Event v1.

The mapper deliberately omits fields whose meaning is not proven by the current
Detection contract.

WindowHash events were skipped entirely until 2026-09-29, when Detection confirmed
both open points: `match_rate` (matched chars / input chars, union of all clusters -
stable regardless of where the match sits) and the span coordinate system (character
offsets in the normalized text, same space as `documents.normalized_text`). The raw
`score` field remains unconverted on purpose - its denominator is the number of windows
actually looked up, which shrinks once evidence is found, so the same input yields
different values depending on match position.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
import uuid


CANONICAL_TARGETS = {"ChatGPT", "Gemini", "Claude"}
SPAN_PATTERN = re.compile(r"^(\d+)-(\d+)$")
ENTITY_PATTERN = re.compile(r"^([A-Z][A-Z0-9_]{0,99}):(\d+)$")

# Detection action -> Dashboard finalAction. 정책 v2(2026-10-01)의 action 값과 이전 값을 모두 받는다.
# 부분/전체 마스킹 구분은 싣지 않는다 - Security Event v1은 모르는 필드가 있으면 이벤트 전체를 422로 거부한다.
_FINAL_ACTION = {
    "block": "BLOCK", "block_notify": "BLOCK",
    "mask": "MASK", "mask_partial": "MASK", "mask_full": "MASK",
    "allow": "ALLOW", "allow_notify": "ALLOW", "allow_degraded": "ALLOW",
}

# Gateway가 검사하지 않은 파일(2026-10-10): 검사할 수 없는 형식·상한 초과. 허용이어도 늘 보내고(관리자 기록),
# 검사 결과가 없으므로 detectionOutcome은 UNAVAILABLE(NO_MATCH는 "검사했다"는 뜻)
UNINSPECTED_REASONS = frozenset({
    "file_uninspectable_image", "file_uninspectable_scanned_pdf", "file_uninspectable_other", "file_too_large",
})
# 접속 차단(2026-10-12): Detection을 부르지 않고 Gateway가 막은 요청(차단한 확장 ID·확장 ID 없음). 검사 결과가 없으므로
# UNAVAILABLE(장애 아님: degraded false). client_blocked만 규칙 번호(accessRuleId, 소문자 UUID)를 싣는다
ACCESS_REASONS = frozenset({"client_blocked", "client_id_missing"})
_ACCESS_RULE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _value(result, name: str, default=None):
    return getattr(result, name, default)


def _event_id() -> str:
    return f"evt-{uuid.uuid4()}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _span(value) -> dict[str, int | bool] | None:
    match = SPAN_PATTERN.fullmatch(str(value or "").strip())
    if not match:
        return None
    start, end = (int(part) for part in match.groups())
    if end <= start:
        return None
    return {"charStart": start, "charEnd": end, "endExclusive": True}


def _entity_counts(value) -> list[dict[str, int | str]]:
    counts: dict[str, int] = {}
    for part in str(value or "").split(","):
        match = ENTITY_PATTERN.fullmatch(part.strip())
        if not match:
            continue
        entity_type, raw_count = match.groups()
        count = int(raw_count)
        if count > 0:
            counts[entity_type] = counts.get(entity_type, 0) + count
    return [
        {"entityType": entity_type, "count": count}
        for entity_type, count in sorted(counts.items())
    ]


def build_dashboard_event(
    *,
    result,
    request_id: str,
    identity: dict[str, str] | None,
    target_llm: str,
    host: str | None,
    endpoint: str | None,
    content_type: str,
    enforcement_applied: bool,
    http_status: int | None,
    report_allow_events: bool = False,
    event_id_factory=_event_id,
    timestamp_factory=_timestamp,
) -> tuple[dict | None, str | None]:
    """Return ``(event, None)`` or ``(None, safe_skip_reason)``.

    A skipped event is preferable to inventing canonical detector semantics.
    """

    if target_llm not in CANONICAL_TARGETS:
        return None, "unsupported target LLM"

    action = _value(result, "action")
    if not action:
        action = "block" if bool(_value(result, "blocked", False)) else "allow"

    degraded = bool(_value(result, "degraded", False)) or action == "allow_degraded"
    final_action = _FINAL_ACTION.get(action)
    if final_action is None:
        return None, "unsupported Detection action"

    uninspected = str(_value(result, "reason_code") or "") in UNINSPECTED_REASONS | ACCESS_REASONS
    if final_action == "ALLOW" and not degraded and not report_allow_events and not uninspected:
        return None, "ALLOW event reporting disabled"

    event: dict = {
        "type": "SECURITY_EVENT",
        "eventId": event_id_factory(),
        "requestId": request_id,
        "timestamp": timestamp_factory(),
        "clientId": (identity or {}).get("client_id") or "unknown-client",
        "targetLlm": target_llm,
        "contentType": content_type,
        "finalAction": final_action,
        "recommendedAction": final_action,
        "degraded": degraded,
        "detections": [],
    }

    # Forward only canonical decision metadata already supplied by Detection.
    # These values are identifiers, not raw prompt/document content.
    reason_code = _value(result, "reason_code")
    if reason_code and reason_code != "none":
        event["reasonCode"] = str(reason_code)
    access_rule_id = _value(result, "access_rule_id")
    if reason_code == "client_blocked" and isinstance(access_rule_id, str) and _ACCESS_RULE_ID.fullmatch(access_rule_id):
        event["accessRuleId"] = access_rule_id

    # matchRate는 아직 보내지 않는다. Security Event v1이 모르는 필드를 거부한다 -
    # 실측(2026-09-29): matchRate를 실으면 HTTP 422 VALIDATION "contains an unsupported field"
    # (path=body.matchRate)로 **이벤트 전체가 버려진다**. 빼면 같은 이벤트가 201로 수락된다.
    # 대시보드가 스키마에 필드를 추가하면 아래 세 줄을 되살린다. 값은 이미
    # DetectionResult.match_rate에 들어와 있다(일치 글자 / 입력 글자, 일치 위치와 무관).
    #     match_rate = _value(result, "match_rate")
    #     if match_rate is not None:
    #         event["matchRate"] = round(float(match_rate), 3)

    # Detection does not currently emit this field, but forwarding it when
    # present keeps the candidate Gateway compatible with the agreed schema.
    policy_version = _value(result, "policy_version")
    if policy_version:
        event["policyVersion"] = str(policy_version)

    tenant_id = (identity or {}).get("tenant_id")
    if tenant_id:
        event["tenantId"] = tenant_id
    if host:
        event["host"] = host
    if endpoint:
        event["endpoint"] = endpoint

    if final_action in {"BLOCK", "MASK"}:
        event["enforcement"] = {
            "applied": enforcement_applied,
        }
        if final_action == "BLOCK":
            event["enforcement"]["httpStatus"] = int(http_status or 403)

    if degraded:
        event["detectionOutcome"] = "UNAVAILABLE"
        reason = _value(result, 'degraded_reason')
        event["degradedReason"] = reason if reason in {'TIMEOUT', 'UNREACHABLE', 'PARSE_ERROR', 'OTHER'} else 'UNREACHABLE'
        # Legacy degraded records have no policy field; derive only from the
        # actual action, never describe a fail-closed block as FAIL_OPEN.
        policy = _value(result, 'failure_policy')
        event["failurePolicy"] = policy if policy in {'FAIL_OPEN', 'FAIL_CLOSED'} else 'FAIL_CLOSED' if final_action == 'BLOCK' else 'FAIL_OPEN'
        return event, None

    if uninspected:
        event["detectionOutcome"] = "UNAVAILABLE"   # 검사하지 않음(장애 아님: degraded false). 접속 차단도 같음
        return event, None

    decided_by = str(_value(result, "decided_by", "none") or "none").lower()
    if decided_by == "windowhash":
        match_rate = _value(result, "match_rate")
        input_span = _span(_value(result, "input_span"))
        document_span = _span(_value(result, "doc_span"))
        document_id = str(_value(result, "doc_id", "") or "").strip()
        if (
            not isinstance(match_rate, (int, float))
            or not 0 <= float(match_rate) <= 1
            or not document_id
            or input_span is None
            or document_span is None
        ):
            return None, "incomplete WindowHash evidence"
        event["detectionOutcome"] = "MATCH"
        event["detections"] = [
            {
                "detector": "WINDOW_HASH",
                "matchType": "TEXT_FRAGMENT",
                "score": float(match_rate),
                "scoreKind": "COVERAGE",
                "matchedDocumentId": document_id,
                "inputSpan": input_span,
                "documentSpan": document_span,
                "action": final_action,
                "recommendedAction": final_action,
            }
        ]
        return event, None

    if decided_by == "signature":
        entity_counts = _entity_counts(_value(result, "pii_hits"))
        if not entity_counts:
            return None, "incomplete Signature evidence"
        event["detectionOutcome"] = "MATCH"
        event["detections"] = [
            {
                "detector": "SIGNATURE",
                "matchType": "SIGNATURE_RULE",
                "entityCounts": entity_counts,
                "action": final_action,
                "recommendedAction": final_action,
            }
        ]
        return event, None

    event["detectionOutcome"] = "NO_MATCH"
    return event, None
