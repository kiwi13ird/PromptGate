import random

from windowhash import engine, store
from windowhash.detect import decide, query_text
from windowhash.hashing import WINDOW

_SYL = [chr(c) for c in range(0xAC00, 0xAC00 + 2000)]


def _text(rng, n):
    return " ".join("".join(rng.choice(_SYL) for _ in range(rng.randint(2, 6))) for _ in range(n // 4))


def _ingest(conn, r, doc_id, text):
    engine.clear(conn, r, doc_id)
    store.upsert_document(conn, doc_id, doc_id + ".docx", len(text), WINDOW)
    return engine.ingest(conn, r, doc_id, text)


def test_verbatim_excerpt_is_blocked_with_position(tmp_db, fake_redis):
    rng = random.Random(2)
    doc = _text(rng, 3000)
    assert _ingest(tmp_db, fake_redis, "d1", doc)["windows"] > 0
    excerpt = doc[1000:1200]
    d = decide(query_text(fake_redis, excerpt))
    assert d.blocked and d.signal.x_evidence == "d1"
    lo, hi = (int(x) for x in d.signal.x_chunk_span.split("-"))
    assert lo >= 990 and hi <= 1215  # 문서 쪽 위치가 발췌 구간을 가리킨다


def test_unrelated_text_passes(tmp_db, fake_redis):
    rng = random.Random(3)
    _ingest(tmp_db, fake_redis, "d1", _text(rng, 3000))
    assert not decide(query_text(fake_redis, _text(rng, 800))).blocked


def test_short_input_has_no_window(tmp_db, fake_redis):
    rng = random.Random(4)
    doc = _text(rng, 3000)
    _ingest(tmp_db, fake_redis, "d1", doc)
    assert query_text(fake_redis, doc[100:120]) == []


def test_shared_window_between_documents_is_not_evidence(tmp_db, fake_redis):
    rng = random.Random(5)
    header = "작성일 2026-08-10 작성자 법무팀장 한지원 배포범위 법무팀 한정 대외비"
    a = header + " " + _text(rng, 2000)
    b = header + " " + _text(rng, 2000)
    _ingest(tmp_db, fake_redis, "a", a)
    _ingest(tmp_db, fake_redis, "b", b)
    assert not decide(query_text(fake_redis, header)).blocked  # 두 문서에 있는 줄만으로는 차단 안 함
    d = decide(query_text(fake_redis, a[200:400]))
    assert d.blocked and d.signal.x_evidence == "a"


def test_table_row_copied_with_tabs_is_blocked(tmp_db, fake_redis):
    rows = [f"2026-07 | NW16-{i:04d} | 김도현{i} | 경영기획실 | 대표이사 | 2016-03-02 | 850313-2094941 | 신한은행 242-23-8095{i:02d} | 9000000" for i in range(30)]
    _ingest(tmp_db, fake_redis, "pay", "\n".join(rows))
    pasted = rows[7].replace(" | ", "\t")
    d = decide(query_text(fake_redis, pasted))
    assert d.blocked and d.signal.x_evidence == "pay"


def test_reingest_removes_old_windows(tmp_db, fake_redis):
    rng = random.Random(6)
    old = _text(rng, 2000)
    _ingest(tmp_db, fake_redis, "d1", old)
    _ingest(tmp_db, fake_redis, "d1", _text(rng, 2000))
    assert not decide(query_text(fake_redis, old[500:700])).blocked
    assert store.window_count(tmp_db, "d1") > 0


def test_decide_reason_mentions_document(tmp_db, fake_redis):
    rng = random.Random(7)
    doc = _text(rng, 2000)
    _ingest(tmp_db, fake_redis, "15_NDA", doc)
    d = decide(query_text(fake_redis, doc[300:500]))
    assert "15_NDA" in d.reason and "그대로 일치" in d.reason
