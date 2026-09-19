"""/detect 한 건의 처리 순서: 전처리 → ① 해시 판정 → (차단이면 즉시) → ② 패턴매칭 → 응답 → 기록.

- ① `windowhash.detect`: 기밀문서 창 해시 대조. 차단이면 ②를 돌리지 않는다.
- ② `signature.engine`: 패턴 적중(PII). ①이 통과일 때만. 적중 → 차단 규칙은 `signature_blocks()` 한 곳.
- 격리: ①이 예외를 내면 `hash_status="error"`로 표시하고 ②로 넘어간다. ②가 예외를 내면 `signature_status="error"`,
  판정은 ① 결과. ①이 차단하면 `signature_status="skipped"`.

응답·판정 로그·DB 행은 **같은 dict(row)** 에서 나온다(2026-09-14 확정 구조, `schemas.DetectResponse`). 원문(prompt)은
기록에만 붙이고 응답에는 넣지 않는다.

기록(2026-09-15): 이 함수는 로그 파일(decision_log)에만 쓴다. RDS로는 전송 서비스(log_shipper)가 옮긴다 - RDS 상태가
탐지 응답 시간에 영향을 주지 않게. 판정마다 `decision_id`(UUID)를 새로 만들어 DB 기본키로 쓴다. `ts`는 받은 시각.
처리 중 예상 못 한 예외가 나도 오류 상태(hash_status·signature_status="error")로 한 줄 남긴 뒤 예외를 다시 올린다(500).
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import redis

from preprocessing.normalizer import normalize_text
from signature import engine as signature
from windowhash import detect

from .decision_log import DecisionLog
from .schemas import DetectResponse, GatewayDecision

HASH_DETECTOR = "windowhash"
SIGNATURE_DETECTOR = "signature"

# 차단 시 사용자에게 보여줄 문구. 문서명·구간·점수는 넣지 않는다(관리자는 request_id로 로그에서 본다).
USER_MESSAGE_DOC = "사내 기밀문서 내용이 포함되어 전송이 차단되었습니다. 문의 시 요청 번호를 알려주세요."
USER_MESSAGE_PII = "개인정보로 보이는 내용이 포함되어 전송이 차단되었습니다. 문의 시 요청 번호를 알려주세요."


def preprocess(text: str) -> str:
    """전처리. normalize_text는 멱등이라 Gateway가 이미 정규화한 입력에 다시 적용해도 같다."""
    return normalize_text(text)


def signature_blocks(hits: list[signature.Hit]) -> bool:
    """패턴 적중 → 차단 규칙. 단일 지점. 지금은 적중 1건 이상이면 차단(인식기 정책 확정 전 잠정)."""
    return len(hits) > 0


def gateway_decision(blocked: bool, decided_by: str) -> GatewayDecision:
    """판정을 Gateway가 그대로 집행할 값으로. 규칙은 이 함수 하나."""
    if not blocked:
        return GatewayDecision(action="allow", reason_code="none")
    if decided_by == SIGNATURE_DETECTOR:
        return GatewayDecision(action="block", reason_code="pii", user_message=USER_MESSAGE_PII, http_status=403)
    return GatewayDecision(action="block", reason_code="doc_excerpt", user_message=USER_MESSAGE_DOC, http_status=403)


def run(
    r: redis.Redis,
    raw_text: str,
    *,
    request_id: str = "",
    source: dict[str, Any] | None = None,
    decision_log: DecisionLog | None = None,
) -> DetectResponse:
    received_ts = time.time()
    t_start = time.perf_counter()
    row: dict[str, Any] = {
        "request_id": request_id,
        "blocked": False,
        "decided_by": "none",
        "doc_id": None, "doc_span": None, "input_span": None, "score": None,
        "pii_hits": None,
        "reason": "",
        "hash_status": "ok",
        "signature_status": "skipped",
        "total_ms": 0.0,
    }
    text = raw_text
    try:
        text = preprocess(raw_text)
        _decide(r, text, row)
        row["total_ms"] = round((time.perf_counter() - t_start) * 1000, 1)
        response = DetectResponse(**row, decision=gateway_decision(row["blocked"], row["decided_by"]))
    except Exception as exc:
        # 판정 자체가 깨졌다 - 무엇이 들어왔는지는 남기고 500으로 올린다.
        row.update(blocked=False, decided_by="none", doc_id=None, doc_span=None, input_span=None, score=None,
                   pii_hits=None, reason=f"internal error: {type(exc).__name__}", hash_status="error",
                   signature_status="error", total_ms=round((time.perf_counter() - t_start) * 1000, 1))
        _record(decision_log, row, received_ts, source, text)
        raise
    _record(decision_log, row, received_ts, source, text)
    return response


def _record(decision_log: DecisionLog | None, row: dict[str, Any], received_ts: float,
            source: dict[str, Any] | None, text: str) -> None:
    if decision_log is None:
        return
    decision_log.write({**row, "decision_id": str(uuid.uuid4()), "ts": received_ts,
                        "service": (source or {}).get("service"), "format": (source or {}).get("format"),
                        "text_chars": len(text), "prompt": text})


def _decide(r: redis.Redis, text: str, row: dict[str, Any]) -> None:
    # ① 해시 판정
    try:
        decision = detect.decide(detect.query_text(r, text))
    except Exception:  # Redis 불통 등 - 해시 쪽만 실패로 표시하고 ②로 넘어간다
        decision = detect.Decision(blocked=False, reason=f"{HASH_DETECTOR} error")
        row["hash_status"] = "error"
    row["reason"] = decision.reason
    if decision.blocked and decision.signal is not None:
        s = decision.signal
        row.update(blocked=True, decided_by=HASH_DETECTOR, doc_id=s.x_evidence, doc_span=s.x_chunk_span,
                   input_span=f"{s.start}-{s.end}", score=s.score)
    else:
        # ② 패턴매칭 판정 (①이 통과일 때만)
        try:
            hits = signature.query(text)
            row["signature_status"] = "ok"
        except Exception:
            hits = []
            row["signature_status"] = "error"
        if hits:
            counts: dict[str, int] = {}
            for h in hits:
                counts[h.entity_type] = counts.get(h.entity_type, 0) + 1
            row["pii_hits"] = ",".join(f"{k}:{v}" for k, v in sorted(counts.items()))
        if signature_blocks(hits):
            row.update(blocked=True, decided_by=SIGNATURE_DETECTOR, reason=f"패턴 적중: {row['pii_hits']}")
