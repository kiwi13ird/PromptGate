"""등록 경로 시험: 원본 바이트 → (인덱서와 같은) router.process_input → normalized_text → windowhash.engine.document_windows.
HWP 글자에서 복사한 구간이 등록 색인과 같은 창을 내는지, fakeredis 색인에서 차단 근거가 되는지 본다(Redis 서버 불필요)."""

from __future__ import annotations

import fakeredis
import pytest

import hwp_synth as S
from docstore import indexer
from preprocessing import hwpdoc
from preprocessing.normalizer import normalize_text
from windowhash import engine, index
from windowhash.hashing import compact, window_hashes


def _doc_bytes():
    rows = [(r, c, 1, 1, [S.p(2, f"항목{r}-{c} 가짜 고객 김가짜{r} 계좌 110-{r:03d}-{c:06d} 연락처 010-{r:04d}-{c:04d}")])
            for r in range(6) for c in range(2)]
    sec = (S.p(0, "보안 등급 대외비 - 가짜 사업 계획서 본문 첫 문단입니다. 이 문서는 시험용 합성 문서입니다.")
           + S.p(0, "", S.table(1, rows, 6, 2))
           + S.p(0, "둘째 문단: 신규 서비스 출시 일정은 2026년 4분기이며 예산은 가짜 숫자 12억 3천만 원입니다."))
    return S.build_hwp([sec], summary={2: "가짜 사업 계획서"})


def _passage_hits(full_text: str, passage: str) -> tuple[int, int]:
    doc_hashes = {h for h, _, _ in engine.document_windows(full_text)}
    passage_hashes = window_hashes(compact(normalize_text(passage)).codes)
    return len(passage_hashes), sum(h in doc_hashes for h in passage_hashes)


@pytest.mark.parametrize("filename", ["사업계획.hwp", "noext"])
def test_bytes_to_windows_and_copied_passage_matches(filename):
    data = _doc_bytes()
    text, fmt = indexer.parse_document(filename, data, timeout=120)       # 인덱서와 같은 자식 프로세스 경로
    assert fmt == "hwp"
    windows = engine.document_windows(text)
    assert len(windows) > 100
    lines = hwpdoc.read(data, max_decompressed=20 * 1024 * 1024).lines()
    passage = "\n".join(lines[2:5])                     # 사용자가 표 몇 행을 복사해 붙인 경우
    n, hit = _passage_hits(text, passage)
    assert n > 0 and hit == n
    # 칸 사이 구분자가 달라도(탭) 같은 창
    n, hit = _passage_hits(text, passage.replace(" | ", "\t"))
    assert n > 0 and hit == n


def test_registered_hwp_blocks_copied_excerpt_in_index():
    data = _doc_bytes()
    text, _ = indexer.parse_document("plan.hwp", data, timeout=120)
    r = fakeredis.FakeRedis(decode_responses=True)
    index.replace_doc_windows(r, "plan", engine.document_windows(text))
    index.replace_doc_windows(r, "other", engine.document_windows("관계없는 다른 문서의 글자 " * 20))
    lines = hwpdoc.read(data, max_decompressed=20 * 1024 * 1024).lines()
    signals = engine.query(r, "이 내용 요약해줘\n" + lines[0] + "\n" + lines[3])
    assert signals and signals[0].x_evidence.startswith("plan")
    assert engine.query(r, "오늘 날씨가 좋아서 산책을 다녀왔다. 점심은 비빔밥을 먹었다.") == []


def test_hwpx_and_hwp_same_content_same_windows(tmp_path):
    """같은 구조·글자의 합성 HWP와 HWPX는 본문 창이 같다(부가 글자 줄을 뺀 비교)."""
    from test_hwpdoc_hwp import _sample as hwp_sample
    from test_hwpdoc_hwpx import _sample as hwpx_sample

    a = hwpdoc.read(hwp_sample(), max_decompressed=1 << 24)
    b = hwpdoc.read(hwpx_sample(), max_decompressed=1 << 24)
    body = lambda d: "\n".join(d.lines()[: len(d.lines()) - sum(1 for s in d.side if s.text.strip())])
    assert {h for h, _, _ in engine.document_windows(normalize_text(body(a)))} == \
        {h for h, _, _ in engine.document_windows(normalize_text(body(b)))}
