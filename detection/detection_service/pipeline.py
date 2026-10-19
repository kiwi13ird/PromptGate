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
from signature import masker
from windowhash import detect

from .decision_log import DecisionLog
from . import policy_store
from .document_evidence import read_epoch, reference
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


def gateway_decision(action: str, decided_by: str) -> GatewayDecision:
    """판정을 Gateway가 그대로 집행할 값으로. 규칙은 이 함수 하나."""
    if action in {"allow", "allow_notify"}:
        return GatewayDecision(action="allow", reason_code="none")
    if action in {"mask_partial", "mask_full"}:
        return GatewayDecision(action=action, reason_code="pii")
    if decided_by == SIGNATURE_DETECTOR:
        # BLOCK is shared by the policy API and established Gateway contract.
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
        "doc_id": None, "doc_span": None, "input_span": None, "score": None, "match_rate": None,
        "pii_hits": None,
        "reason": "",
        "hash_status": "ok",
        "signature_status": "skipped",
        "total_ms": 0.0,
        "mask_spans": [],
        "findings": [],
        "masked_text": None,
        "policy_id": None,
        "policy_version": None,
    }
    text = raw_text
    src = source or {}
    original_file = src.get('content_type') == 'file' and src.get('signature_original_offsets') is True
    try:
        text = preprocess(raw_text)
        evidence_epoch = read_epoch(r)
        action = _decide(r, text, row, signature_text=raw_text if original_file else None,
                         context_label=src.get('context_label'))
        row['document_ref'] = reference(r, row, evidence_epoch)
        row["total_ms"] = round((time.perf_counter() - t_start) * 1000, 1)
        response = DetectResponse(**row, decision=gateway_decision(action, row["decided_by"]))
    except Exception as exc:
        # 판정 자체가 깨졌다 - 무엇이 들어왔는지는 남기고 500으로 올린다.
        row.update(blocked=False, decided_by="none", doc_id=None, doc_span=None, input_span=None, score=None,
                   match_rate=None, pii_hits=None, reason=f"internal error: {type(exc).__name__}", hash_status="error",
                   signature_status="error", total_ms=round((time.perf_counter() - t_start) * 1000, 1),
                   mask_spans=[], findings=[], masked_text=None, policy_id=None, policy_version=None)
        _record(decision_log, row, received_ts, source, text)
        raise
    _record(decision_log, row, received_ts, source, text, signature_text=raw_text if original_file else None)
    return response


# 정규화 앞부분 길이를 잴 때 끝 공백이 잘리지 않게 붙이는 글자(사용 영역 문자 - normalize_text가 지우지 않는다)
_PREFIX_SENTINEL = "\ue000"


def recorded_masking(row: dict[str, Any], text: str, signature_text: str | None) -> tuple[str | None, list[dict] | None]:
    """가린 결과를 기록 원문(`prompt` = 정규화 텍스트) 좌표로 옮긴다.

    파일 칸은 원본 좌표로 가린다(signature_original_offsets). 원본 앞부분을 정규화한 길이로 위치를 옮기고,
    옮긴 자리의 글자가 원본 구간을 정규화한 것과 같을 때만 위치를 남긴다 - 틀린 위치를 남기지 않는다.
    """
    findings = row.get("findings") or []
    masked = row.get("masked_text")
    if masked is None and not findings:
        return None, None
    base = text if signature_text is None else signature_text
    out = []
    for f in findings:
        item = {k: f.get(k) for k in ("entity_type", "replacement", "policy_action")}
        start, end = f.get("start"), f.get("end")
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(base):
            if signature_text is None:
                item.update(start=start, end=end)
            else:
                value = preprocess(base[start:end])
                s = len(preprocess(base[:start] + _PREFIX_SENTINEL)) - len(_PREFIX_SENTINEL)
                if value and text[s:s + len(value)] == value:
                    item.update(start=s, end=s + len(value))
        out.append(item)
    return (preprocess(masked) if masked is not None else None), out


def _record(decision_log: DecisionLog | None, row: dict[str, Any], received_ts: float,
            source: dict[str, Any] | None, text: str, *, signature_text: str | None = None) -> None:
    if decision_log is None:
        return
    src = source or {}
    masked_text, findings = recorded_masking(row, text, signature_text)
    block_order = src.get("block_order")
    decision_log.write({**row, "decision_id": str(uuid.uuid4()), "ts": received_ts,
                        "service": src.get("service"), "content_type": src.get("content_type"),
                        "filename": src.get("filename"), "format": src.get("format"),
                        "text_chars": len(text), "prompt": text,
                        "masked_text": masked_text, "findings": findings,
                        "block_order": block_order if isinstance(block_order, int) else None})


def _decide(r: redis.Redis, text: str, row: dict[str, Any], *,
            signature_text: str | None = None, context_label: str | None = None) -> str:
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
                   input_span=f"{s.start}-{s.end}", score=s.score, match_rate=s.match_rate)
        return "block"
    else:
        # ② 패턴매칭 판정 (①이 통과일 때만)
        try:
            pii_text = text if signature_text is None else signature_text
            hits = signature.query(pii_text, context=context_label) if context_label else signature.query(pii_text)
            row["signature_status"] = "ok"
        except Exception:
            if signature_text is not None:
                raise  # Original-coordinate file detection must never silently allow on failure.
            hits = []
            row["signature_status"] = "error"
        if hits:
            counts: dict[str, int] = {}
            for h in hits:
                counts[h.entity_type] = counts.get(h.entity_type, 0) + 1
            row["pii_hits"] = ",".join(f"{k}:{v}" for k, v in sorted(counts.items()))
        if signature_blocks(hits):
            resolution = policy_store.resolve(hits)
            action = resolution.action.lower()
            # 겹치는 적중은 masker가 받지 않는다(ValueError → 500) - 여기서 한 구간으로 합친다(2026-10-11 명세 §3.4).
            # pii_hits 건수는 위에서 합치기 전 적중으로 이미 셌다.
            merged_hits, merged_actions = _merge_overlaps(hits, resolution.hit_actions)
            masked_text, findings = masker.apply(pii_text, merged_hits, merged_actions)
            row.update(
                blocked=action in {"block", "block_notify"},
                decided_by=SIGNATURE_DETECTOR,
                reason=f"패턴 적중: {row['pii_hits']}",
                policy_id=resolution.policy_id,
                policy_version=resolution.policy_version,
                mask_spans=[
                    {"start": hit.start, "end": hit.end, "entity_type": hit.entity_type}
                    for hit, hit_action in zip(merged_hits, merged_actions)
                    if hit_action in _MASK_ACTIONS
                ],
                findings=findings,
                masked_text=masked_text,
            )
            return action
    return "allow"


_MASK_ACTIONS = frozenset({"MASK_PARTIAL", "MASK_FULL"})


def _merge_overlaps(hits: list[signature.Hit], actions) -> tuple[list[signature.Hit], list[str]]:
    """겹치는 적중 묶음을 한 구간(최소 시작~최대 끝)으로 합친다(명세 §3.4).

    - 동작은 묶음에서 가장 강한 것(`policy_store.ACTION_PRIORITY`), 유형·점수는 그 동작을 가진 적중 중 가장 긴 것.
    - 겹침은 한쪽 시작이 다른 쪽 끝보다 앞일 때만이다. 맞닿은 적중(앞 끝 = 뒤 시작)은 masker도 받으므로 합치지 않는다.
    - 겹치는 적중이 없으면 받은 목록을 그대로 돌려준다 - 겹침 없는 입력은 응답·기록이 바뀌지 않는다.
    - 구간 자체가 잘못된 적중(start < 0 등)은 손대지 않고 넘긴다 - masker가 지금처럼 거절한다.
    """
    actions = list(actions)
    if len(hits) != len(actions):
        return list(hits), actions
    items = sorted(zip(hits, actions), key=lambda item: (item[0].start, item[0].end))
    groups: list[list[tuple[signature.Hit, str]]] = []
    end = None
    for hit, hit_action in items:
        if groups and end is not None and hit.start < end:
            groups[-1].append((hit, hit_action))
            end = max(end, hit.end)
        else:
            groups.append([(hit, hit_action)])
            end = hit.end
    if all(len(group) == 1 for group in groups):
        return list(hits), actions
    merged_hits: list[signature.Hit] = []
    merged_actions: list[str] = []
    for group in groups:
        if len(group) == 1:
            merged_hits.append(group[0][0])
            merged_actions.append(group[0][1])
            continue
        strongest = max((a for _, a in group), key=lambda a: policy_store.ACTION_PRIORITY.get(a, 0))
        chosen = max((h for h, a in group if a == strongest), key=lambda h: (h.end - h.start, -h.start))
        merged_hits.append(signature.Hit(chosen.entity_type, min(h.start for h, _ in group),
                                         max(h.end for h, _ in group), chosen.score))
        merged_actions.append(strongest)
    return merged_hits, merged_actions
