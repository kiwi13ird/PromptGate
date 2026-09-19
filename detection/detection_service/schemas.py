"""Detection API 요청/응답 모델.

응답은 2026-09-14 확정 구조: **DB `decisions` 한 행 = 판정 로그 한 줄 = 응답 본문**. 창 수·JSONB·엔진 내부값은 없고,
Gateway·대시보드가 쓰는 것(문서·구간·일치율·패턴 건수·판정)만 있다. `blocked`·`reason`은 최상위에 둔다 - Gateway의
현재 클라이언트(2026-09-02 판)가 이 둘을 읽는다. 원문(prompt)은 응답에 싣지 않는다(기록에만).

`source`는 판정에 쓰지 않는다(감사용).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceInfo(BaseModel):
    service: str | None = None
    content_type: str | None = None
    format: str | None = None
    endpoint: str | None = None


class DetectRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=200)  # 빈 번호는 422 - 기록을 요청과 잇는 열쇠라서
    normalized_text: str
    source: SourceInfo = Field(default_factory=SourceInfo)


class GatewayDecision(BaseModel):
    """Gateway가 해석 없이 집행할 값.

    action        "block" | "allow". Detection 무응답은 Gateway 클라이언트가 "allow_degraded"로 만든다(여기 없음)
    reason_code   "doc_excerpt"(기밀문서 구간 일치) | "pii"(패턴 적중) | "none"
    user_message  차단 시 사용자에게 보여줄 문구. 문서명·구간은 넣지 않는다(회피 힌트 방지). 통과면 null
    http_status   차단 시 권장 상태 코드(403). 통과면 null
    """

    action: str
    reason_code: str
    user_message: str | None = None
    http_status: int | None = None


class DetectResponse(BaseModel):
    """decisions 행과 같은 열. 순서도 같다."""

    request_id: str
    blocked: bool
    decided_by: str  # "windowhash" | "signature" | "none"
    doc_id: str | None = None  # 해시 차단일 때 근거 문서
    doc_span: str | None = None  # 문서 쪽 구간 "216-516" (정규화 텍스트 좌표)
    input_span: str | None = None  # 입력 쪽 구간 "0-300"
    score: float | None = None  # 일치율 0~1
    pii_hits: str | None = None  # 패턴 차단일 때 "KR_RRN:1,KR_PHONE:2" (값 없음)
    reason: str  # 사람용 한 줄
    hash_status: str  # "ok" | "error"
    signature_status: str  # "ok" | "error" | "skipped"
    total_ms: float = 0.0
    decision: GatewayDecision = Field(default_factory=lambda: GatewayDecision(action="allow", reason_code="none"))
