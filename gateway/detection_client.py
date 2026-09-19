"""Gateway EC2에서 Detection EC2의 `POST /detect`를 호출한다.

`gateway-detection-integration-design.md` §5 스케치의 실제 구현. 표준 라이브러리만 쓴다
(hashdb와 같은 원칙, `hashdb/README.md` "설치" 절 참고) - Gateway EC2에 이미 올라간 것 외에
새 pip 의존성(httpx/requests)을 추가하지 않는다.

fail-open은 잠정값이다(설계 문서 §7 미해결 01) - Detection EC2가 응답하지 않을 때 통과시킬지
차단할지는 아직 정책으로 확정되지 않았다. reason 문자열에 "잠정"을 명시해, 이 결과를 로그로
보는 사람이 실제 판정과 폴백을 착각하지 않도록 한다.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

_TIMEOUT_SECONDS = 0.5  # ADR-0005 P99 캡 - Gateway가 이 이상 Detection을 기다리지 않는다.


@dataclass
class DetectionResult:
    """Detection 응답을 그대로 담는다(2026-09-14 구조: DB decisions 행과 같은 이름). 무응답이면 degraded=True,
    action="allow_degraded"."""

    blocked: bool
    reason: str
    degraded: bool = False  # True면 실제 판정이 아니라 통신 실패로 인한 잠정 결과
    request_id: str = ""
    decided_by: str = "none"  # "windowhash" | "signature" | "none"
    doc_id: str | None = None
    doc_span: str | None = None
    input_span: str | None = None
    score: float | None = None
    pii_hits: str | None = None
    hash_status: str | None = None
    signature_status: str | None = None
    total_ms: float | None = None
    # Gateway가 해석 없이 집행할 값
    action: str = "allow"  # "allow" | "block" | "allow_degraded"
    reason_code: str = "none"  # "doc_excerpt" | "pii" | "none" | "detection_unreachable"
    user_message: str | None = None
    http_status: int | None = None
    # 옛 응답(evidence 블록) 호환 - 새 서버에서는 항상 None
    evidence: dict | None = None


def check(
    base_url: str,
    request_id: str,
    normalized_text: str,
    source: dict | None = None,
    timeout: float = _TIMEOUT_SECONDS,
) -> DetectionResult:
    """Detection EC2에 정규화된 텍스트를 보내고 판정을 받는다.

    통신 실패(타임아웃 포함) 시 예외를 올리지 않고 (잠정) 통과시킨다 - 이 계층에서
    예외가 나면 gateway.py의 나머지 요청 처리 전체가 죽으므로, 실패를 값으로 돌려주는 쪽을
    택한다. degraded=True로 표시되므로 호출자가 로그·알림 여부를 판단할 수 있다.
    """
    payload = json.dumps(
        {"request_id": request_id, "normalized_text": normalized_text, "source": source or {}}
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/detect",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return DetectionResult(
            blocked=False,
            reason=f"detection unreachable - fail-open(잠정, 정책 미확정): {exc}",
            degraded=True,
            action="allow_degraded",
            reason_code="detection_unreachable",
            request_id=request_id,
        )

    decision = body.get("decision") or {}
    return DetectionResult(
        blocked=body["blocked"],
        reason=body["reason"],
        request_id=body.get("request_id") or request_id,
        decided_by=body.get("decided_by", "none"),
        doc_id=body.get("doc_id"), doc_span=body.get("doc_span"), input_span=body.get("input_span"),
        score=body.get("score"), pii_hits=body.get("pii_hits"),
        hash_status=body.get("hash_status"), signature_status=body.get("signature_status"), total_ms=body.get("total_ms"),
        action=decision.get("action", "block" if body["blocked"] else "allow"),
        reason_code=decision.get("reason_code", "none"),
        user_message=decision.get("user_message"),
        http_status=decision.get("http_status"),
        evidence=body.get("evidence"),
    )
