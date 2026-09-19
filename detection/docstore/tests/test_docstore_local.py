"""로컬 시험 - 파싱 결과가 기존 CLI 적재와 같은지, Redis 문서별 창 목록으로 교체·퇴역이 정확한지.

DB(SQL) 흐름은 실제 PostgreSQL이 필요해서 서버에서 따로 시험한다(verify/docstore_pg_check.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from docstore import indexer, registry  # noqa: E402
from preprocessing.format_detect import detect_format  # noqa: E402
from preprocessing.router import process_input  # noqa: E402
from windowhash import engine, index, store  # noqa: E402
from windowhash.ingest import ingest_file  # noqa: E402

TESTBED = Path(__file__).resolve().parents[3] / "test" / "testbed" / "generated"
SAMPLE_PDF = Path(__file__).resolve().parents[3] / "docs" / "handoff" / "인프라_설계안.pdf"  # 기밀문서 20종에는 PDF가 없다


def _docs() -> list[Path]:
    if not TESTBED.exists():
        pytest.skip("testbed 없음")
    return sorted(p for p in TESTBED.iterdir() if p.suffix.lower() in {".docx", ".xlsx", ".pdf"})


def _postings(r) -> dict[str, set[str]]:
    return {k: r.smembers(k) for k in r.scan_iter("wh:*") if not k.startswith("wh:doc:") and k != "wh:docs"}


def test_format_detection_matches_file_based_detector():
    for p in _docs():
        assert registry.detect_format(p.read_bytes()) == detect_format(p), p.name
    assert registry.detect_format(b"hello") == "binary-unknown"


@pytest.mark.parametrize("suffix", [".docx", ".xlsx", ".pdf"])
def test_parse_document_equals_process_input(suffix):
    if suffix == ".pdf":
        if not SAMPLE_PDF.exists():
            pytest.skip("PDF 샘플 없음")
        p = SAMPLE_PDF
    else:
        p = next(x for x in _docs() if x.suffix == suffix)
    text, fmt = indexer.parse_document(p.name, p.read_bytes(), timeout=300)
    assert text == process_input(str(p)).normalized_text and fmt == suffix[1:]


def test_parse_timeout_and_failure():
    big = max(_docs(), key=lambda x: x.stat().st_size)
    with pytest.raises(indexer.ParseError, match="시간 초과"):
        indexer.parse_document(big.name, big.read_bytes(), timeout=0.001)
    with pytest.raises(indexer.ParseError):
        indexer.parse_document("broken.pdf", b"%PDF-1.4 garbage", timeout=60)


def test_indexer_windows_equal_cli_ingest(tmp_path):
    """CLI(SQLite+Redis) 적재와 인덱서식 적재(replace_doc_windows)가 같은 wh:{hash} 색인을 만든다."""
    docs = _docs()[:6]
    cli_r = fakeredis.FakeRedis(decode_responses=True)
    conn = store.connect(tmp_path / "l.sqlite3")
    for p in docs:
        assert ingest_file(conn, cli_r, p)["ok"]
    idx_r = fakeredis.FakeRedis(decode_responses=True)
    for p in docs:
        text, _ = indexer.parse_document(p.name, p.read_bytes(), timeout=300)
        index.replace_doc_windows(idx_r, p.stem, engine.document_windows(text))
    assert _postings(cli_r) == _postings(idx_r)
    assert cli_r.smembers("wh:docs") == idx_r.smembers("wh:docs")


def test_replace_removes_stale_and_remove_doc_leaves_nothing():
    a, b = _docs()[0], _docs()[1]
    r = fakeredis.FakeRedis(decode_responses=True)
    ta = indexer.parse_document(a.name, a.read_bytes(), timeout=300)[0]
    tb = indexer.parse_document(b.name, b.read_bytes(), timeout=300)[0]
    index.replace_doc_windows(r, "X", engine.document_windows(ta))
    index.replace_doc_windows(r, "other", engine.document_windows(tb))
    before_other = {k: v for k, v in _postings(r).items() if any(m.startswith("other:") for m in v)}

    stats = index.replace_doc_windows(r, "X", engine.document_windows(tb))  # X의 내용을 b로 교체
    assert stats["removed"] > 0 and stats["added"] > 0
    x_members = {(k, m) for k, v in _postings(r).items() for m in v if m.startswith("X:")}
    want = {(f"wh:{h}", f"X:{s}:{e}") for h, s, e in engine.document_windows(tb)}
    assert x_members == want  # 옛 내용(a)의 창은 하나도 안 남는다
    assert index.doc_windows(r, "X") == set(engine.document_windows(tb))

    assert index.remove_doc(r, "X") == len(set(engine.document_windows(tb)))
    assert not any(m.startswith("X:") for v in _postings(r).values() for m in v)
    assert not r.exists(index.doc_key("X")) and "X" not in r.smembers("wh:docs")
    # 다른 문서의 색인은 그대로
    after_other = {k: v for k, v in _postings(r).items() if any(m.startswith("other:") for m in v)}
    assert {k: {m for m in v if m.startswith("other:")} for k, v in after_other.items()} == \
           {k: {m for m in v if m.startswith("other:")} for k, v in before_other.items()}


def test_interrupted_replace_converges_on_retry(monkeypatch):
    """묶음 적용 중간에 죽어도 다시 돌리면 정확한 상태가 된다."""
    a, b = _docs()[0], _docs()[2]
    r = fakeredis.FakeRedis(decode_responses=True)
    wa = engine.document_windows(indexer.parse_document(a.name, a.read_bytes(), timeout=300)[0])
    wb = engine.document_windows(indexer.parse_document(b.name, b.read_bytes(), timeout=300)[0])
    index.replace_doc_windows(r, "X", wa)

    monkeypatch.setattr(index, "CHUNK", 1000)
    real_apply = index._apply
    calls = {"n": 0}

    def dying_apply(rr, doc_id, windows, add):
        calls["n"] += 1
        if calls["n"] == 2:  # 제거 단계에서 죽는다(추가는 끝남)
            real_apply(rr, doc_id, windows[:1500], add)
            raise ConnectionError("killed")
        return real_apply(rr, doc_id, windows, add)

    monkeypatch.setattr(index, "_apply", dying_apply)
    with pytest.raises(ConnectionError):
        index.replace_doc_windows(r, "X", wb)
    monkeypatch.setattr(index, "_apply", real_apply)
    index.replace_doc_windows(r, "X", wb)
    x_members = {(k, m) for k, v in _postings(r).items() for m in v if m.startswith("X:")}
    assert x_members == {(f"wh:{h}", f"X:{s}:{e}") for h, s, e in wb}
    assert index.doc_windows(r, "X") == set(wb)
