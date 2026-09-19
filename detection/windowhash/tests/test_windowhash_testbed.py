"""테스트베드 20종 실제 적재 - 문서 전체·발췌·표 행·무관 입력. 테스트베드가 없으면 skip."""
import random

import pytest

from windowhash.detect import decide, query_text
from windowhash.ingest import ingest_directory


@pytest.fixture(scope="module")
def loaded(testbed_dir, tmp_path_factory):
    import fakeredis

    from windowhash.store import connect

    r = fakeredis.FakeRedis(decode_responses=True)
    conn = connect(tmp_path_factory.mktemp("db") / "t.sqlite3")
    results = ingest_directory(conn, r, testbed_dir)
    assert all(res["ok"] for res in results) and len(results) == 20
    from preprocessing.router import process_input

    docs = {p.stem: process_input(str(p)).normalized_text for p in sorted(testbed_dir.iterdir()) if p.suffix.lower() in (".docx", ".xlsx")}
    return r, docs


def test_whole_documents_are_blocked(loaded):
    r, docs = loaded
    for doc_id, text in docs.items():
        d = decide(query_text(r, text))
        assert d.blocked and d.signal.x_evidence == doc_id, doc_id


def test_random_excerpts_are_blocked_and_attributed(loaded):
    r, docs = loaded
    rng = random.Random(42)
    ids = list(docs)
    for length in (100, 300, 1000):
        for _ in range(30):
            doc_id = rng.choice(ids)
            text = docs[doc_id]
            start = rng.randrange(0, len(text) - length)
            d = decide(query_text(r, text[start : start + length]))
            assert d.blocked and d.signal.x_evidence == doc_id, (doc_id, length, start)


def test_unrelated_prose_passes(loaded):
    r, _ = loaded
    q = "다음 주 화요일 오전 열 시에 회의 일정 조정이 가능한지 확인 부탁드립니다. 프로젝트 진행 상황을 공유하고 검토 의견을 반영할 예정입니다. " * 5
    assert not decide(query_text(r, q)).blocked
