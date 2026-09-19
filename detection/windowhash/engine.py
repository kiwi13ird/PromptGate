"""창 해시 엔진 - 적재(ingest/clear)와 조회(query).

조회 규칙 세 가지가 전부다.
1. 입력을 압축해 모든 창을 해시하고 역색인에서 찾는다.
2. **식별력 규칙**: 2개 이상 문서에 있는 창은 근거에서 뺀다. 창은 정확 일치라 "어느 문서"를 특정하는
   근거인데, 여러 문서에 있으면 어느 문서의 유출인지 말할 수 없다. 문서끼리 공유하는 헤더 줄
   ("작성일: … 작성자: … 배포범위:")이 여기서 걸러진다(실측: 공백만 뺀 압축·창 50에서 20종 중 8종이 공유).
3. 남은 창이 하나라도 있으면 차단. 근거는 일치한 창이 가장 많은 문서, 위치는 그 창들의 원문 구간.

조회 비용은 해시 계산이 아니라 창 수만큼의 Redis 조회다. 그래서 LOOKUP_BATCH개씩 끊어 조회하고,
근거가 나온 뒤에는 SAMPLE_STRIDE개마다 하나만 조회해 덮임 비율과 문서 구간을 추정한다.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict

import redis

from . import index, store
from .hashing import Compact, compact, window_hashes, window_span
from .signal import HashSignal, MatchSpan

NAME = "WindowHash"
ENTITY_TYPE = "DOC_EXCERPT_EXACT"
BLOCK_THRESHOLD = 0.0  # 식별 창이 하나라도 있으면(신호가 있으면) 차단. score는 판정이 아니라 정보(입력 덮임 비율)다

# 식별력 규칙: 이 개수 이상의 문서에 있는 창은 근거가 아니다.
UNIQUE_DOC_CUT = 2
# 한 번에 조회하는 창 수. 이 묶음에서 근거가 나오면 판정은 확정이고, 나머지 창은 SAMPLE_STRIDE개마다 하나씩만
# 조회해 덮임 비율과 문서 구간을 추정한다(비용 제어용 상수 - 판정 결과에는 영향 없음, 점수 정밀도에만 영향).
LOOKUP_BATCH = 2000
SAMPLE_STRIDE = 50
# 로그에 싣는 덩어리 수 상한
MAX_SPANS = 3

Match = tuple[int, int, int, int]  # (hash, in_pos, doc_start, doc_end)


def document_windows(text: str) -> list[tuple[int, int, int]]:
    """정규화 텍스트 → (hash, start, end) 전부. 적재 경로(CLI·인덱서)가 모두 이 함수를 쓴다 - 같은 텍스트면 같은 색인."""
    comp = compact(text)
    return [(h, *window_span(comp, i)) for i, h in enumerate(window_hashes(comp.codes))]


def ingest(conn: sqlite3.Connection, r: redis.Redis, doc_id: str, text: str) -> dict[str, int]:
    """CLI 적재(옛 경로). SQLite 원장에도 쓰고, Redis에는 문서별 창 목록까지 남긴다."""
    windows = document_windows(text)
    index.replace_doc_windows(r, doc_id, windows)
    store.replace_windows(conn, doc_id, windows)
    return {"windows": len(windows)}


def clear(conn: sqlite3.Connection, r: redis.Redis, doc_id: str) -> None:
    index.delete_windows(r, doc_id, store.get_windows(conn, doc_id))  # 문서별 목록이 없던 시절에 넣은 창
    index.remove_doc(r, doc_id)


def query(r: redis.Redis, text: str) -> list[HashSignal]:
    comp = compact(text)
    hashes = window_hashes(comp.codes)
    if not hashes:
        return []

    # 문서별로 (입력 창 위치, 문서 구간) 매치를 모은다. 근거가 나올 때까지는 모든 창을, 그 뒤는 표본만 조회한다.
    matches: dict[str, list[Match]] = defaultdict(list)
    examined = 0
    positions = list(range(len(hashes)))
    b = 0
    while b < len(positions):
        chunk = positions[b : b + LOOKUP_BATCH]
        postings = index.lookup(r, [hashes[i] for i in chunk])
        examined += len(chunk)
        for i in chunk:
            entries = postings.get(hashes[i])
            if not entries:
                continue
            if len({doc_id for doc_id, _, _ in entries}) >= UNIQUE_DOC_CUT:
                continue  # 식별력 없음
            for doc_id, start, end in entries:
                matches[doc_id].append((hashes[i], i, start, end))
        b += LOOKUP_BATCH
        if matches and len(positions) == len(hashes):
            positions = positions[:b] + positions[b::SAMPLE_STRIDE]  # 이후는 표본 조회
    return [_signal(comp, doc_id, doc_matches, examined) for doc_id, doc_matches in matches.items()]


def reason(signal: HashSignal, *, blocked: bool) -> str:
    n = int(signal.x_score_raw)
    if blocked:
        return f"{signal.x_evidence}의 구간 {signal.x_chunk_span}과 그대로 일치 (일치 창 비율 {signal.score:.0%}, 창 {n}개, 입력 {signal.start}-{signal.end}자)"
    return f"{signal.x_evidence}와 일치 창 없음"


def _clusters(doc_matches: list[Match], input_len: int) -> list[list[Match]]:
    """같은 창이 문서 안 여러 곳(예: 두 달치 급여 행)에 있으면 문서 쪽 위치가 흩어지므로, 입력 길이보다 멀리
    떨어진 위치끼리는 다른 덩어리로 본다. (복사한 발췌가 문서에서 차지하는 길이는 입력 길이를 넘을 수 없다 -
    파라미터가 아니라 입력에서 나오는 값.)"""
    by_doc_pos = sorted(doc_matches, key=lambda m: m[2])
    clusters: list[list[Match]] = [[by_doc_pos[0]]]
    for m in by_doc_pos[1:]:
        if m[2] - clusters[-1][-1][3] > input_len:
            clusters.append([m])
        else:
            clusters[-1].append(m)
    return clusters


def _span(comp: Compact, cluster: list[Match]) -> MatchSpan:
    in_spans = [window_span(comp, i) for _, i, _, _ in cluster]
    return MatchSpan(
        in_start=min(s for s, _ in in_spans),
        in_end=max(e for _, e in in_spans),
        doc_start=min(m[2] for m in cluster),
        doc_end=max(m[3] for m in cluster),
        windows=len({h for h, _, _, _ in cluster}),
    )


def _signal(comp: Compact, doc_id: str, doc_matches: list[Match], examined: int) -> HashSignal:
    input_len = comp.offsets[-1] + 1 if comp.offsets else 0
    spans = sorted((_span(comp, c) for c in _clusters(doc_matches, input_len)), key=lambda s: -s.windows)
    best = spans[0]
    return HashSignal(
        entity_type=ENTITY_TYPE,
        start=best.in_start,
        end=best.in_end,
        score=round(len({i for _, i, _, _ in doc_matches}) / examined, 3),
        x_score_raw=float(best.windows),
        x_score_kind="coverage",
        x_detector=NAME,
        x_evidence=doc_id,
        x_chunk_span=f"{best.doc_start}-{best.doc_end}",
        x_examined=examined,
        x_spans=tuple(spans[:MAX_SPANS]),
    )
