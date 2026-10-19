"""Gateway와 Detection이 공유할 수 있는 Signature segment 계약."""

from __future__ import annotations

from dataclasses import dataclass

from signature_detector.policy import PolicyAction


@dataclass(frozen=True)
class CheckableSegment:
    segment_id: str
    kind: str
    text: str
    context: str | None = None
    block_order: int | None = None   # 2026-10-11 HWP·HWPX: 그 칸을 품은 최상위 문단 순번(기록 화면 순서 복원용)


class MaskRefused(Exception):
    """가린 파일을 보낼 수 없음(PDF·HWP·HWPX 공통, masking-design/SPEC.md §0.3). Gateway가 403 mask_application_failed +
    이벤트로 끝낸다. reason은 로그용 짧은 이름(값·파일 이름 없음)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SegmentFinding:
    entity_type: str
    start: int
    end: int
    replacement: str | None = None
    policy_action: PolicyAction = PolicyAction.ALLOW
    score: float = 0.0


@dataclass(frozen=True)
class SegmentResult:
    segment_id: str
    action: PolicyAction
    masked_text: str | None
    findings: tuple[SegmentFinding, ...] = ()


def validate_segment_result(segment: CheckableSegment, result: SegmentResult) -> None:
    if result.segment_id != segment.segment_id:
        raise ValueError("Detection returned a different segment_id")
    if result.action in {PolicyAction.MASK_PARTIAL, PolicyAction.MASK_FULL}:
        if result.masked_text is None or result.masked_text == segment.text:
            raise ValueError("mask action requires changed masked_text")
    for finding in result.findings:
        if finding.start < 0 or finding.end <= finding.start or finding.end > len(segment.text):
            raise ValueError("Detection returned an invalid finding span")
