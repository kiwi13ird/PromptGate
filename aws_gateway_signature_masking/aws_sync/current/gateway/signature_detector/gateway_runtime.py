"""8081 Gateway가 호출할 Signature 전용 orchestration 함수.

WindowHash/Signature 판정 순서는 Detection 서비스가 소유한다. 이 모듈은 Detection의 최종
결과를 검증하고 prompt JSON 또는 파일 bytes에 적용하기만 한다.
"""

from __future__ import annotations

from dataclasses import dataclass

from signature_detector.contracts import SegmentFinding, SegmentResult
from signature_detector.document.file_segments import (
    SanitizedArtifacts,
    extract_docx_segments,
    extract_xlsx_segments,
    sanitize_docx_bytes,
    sanitize_xlsx_bytes,
)
from signature_detector.gateway_prompt import apply_openai_prompt_results, extract_openai_prompt_bindings
from signature_detector.policy import PolicyAction


class UnsupportedSecureSanitization(ValueError):
    pass


class BlockedBySignaturePolicy(PermissionError):
    def __init__(self, detection_result):
        super().__init__("blocked by Signature policy")
        self.detection_result = detection_result


@dataclass(frozen=True)
class PromptRewriteOutcome:
    body: dict
    notify: bool


def _to_segment_result(segment_id: str, detection_result) -> SegmentResult:
    raw_action = getattr(detection_result, "action")
    # WindowHash와 장애 폴백의 기존 Gateway 계약은 그대로 수용한다.
    compatible_action = {"block": "block_notify", "allow_degraded": "allow"}.get(raw_action, raw_action)
    action = PolicyAction(compatible_action)
    findings = tuple(
        SegmentFinding(
            entity_type=item["entity_type"],
            start=int(item["start"]),
            end=int(item["end"]),
            replacement=item.get("replacement"),
            policy_action=PolicyAction(item.get("policy_action", action.value)),
            score=float(item.get("score", 0.0)),
        )
        for item in (getattr(detection_result, "findings", None) or [])
    )
    return SegmentResult(segment_id, action, getattr(detection_result, "masked_text", None), findings)


def rewrite_openai_prompt_body(body: dict, request_id: str, detect) -> PromptRewriteOutcome:
    """detect(segment, child_request_id)를 호출해 Responses JSON 복사본을 반환한다."""

    bindings = extract_openai_prompt_bindings(body)
    results = []
    notify = False
    for binding in bindings:
        detection = detect(binding.segment, f"{request_id}#{binding.segment.segment_id}")
        result = _to_segment_result(binding.segment.segment_id, detection)
        if result.action is PolicyAction.BLOCK_NOTIFY:
            raise BlockedBySignaturePolicy(detection)
        results.append(result)
        notify = notify or result.action in {PolicyAction.ALLOW_NOTIFY, PolicyAction.BLOCK_NOTIFY}
    return PromptRewriteOutcome(apply_openai_prompt_results(body, bindings, results), notify)


def sanitize_uploaded_file(
    filename: str,
    file_bytes: bytes,
    request_id: str,
    detect,
) -> SanitizedArtifacts:
    """지원 문서를 segment별 검사하고 sanitized/review bytes를 생성한다."""

    extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if extension == "docx":
        segments = extract_docx_segments(file_bytes)
        sanitizer = sanitize_docx_bytes
    elif extension == "xlsx":
        segments = extract_xlsx_segments(file_bytes)
        sanitizer = sanitize_xlsx_bytes
    elif extension == "pdf":
        raise UnsupportedSecureSanitization("secure PDF redaction is not implemented")
    else:
        raise UnsupportedSecureSanitization(f"unsupported file type: {extension or 'unknown'}")

    results = [
        _to_segment_result(segment.segment_id, detect(segment, f"{request_id}#{segment.segment_id}"))
        for segment in segments
    ]
    return sanitizer(file_bytes, results)
