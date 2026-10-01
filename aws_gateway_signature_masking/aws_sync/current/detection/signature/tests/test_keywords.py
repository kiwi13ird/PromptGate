"""문서 키워드 인식기 단위 테스트 - 매칭 규칙, 위치 보존, 승인 키워드 로딩, 엔진 연결."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from signature import engine
from signature.keywords import CATEGORY, ENTITY_TYPE, KeywordRecognizer, fold, load_approved_keywords

_SIGNATURE_SCHEMA = """
CREATE TABLE signature_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('CREDENTIAL', 'PII')), entity_type TEXT NOT NULL,
    pattern TEXT NOT NULL, score REAL NOT NULL, context_keywords TEXT,
    requires_context INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO signature_rules (rule_id, name, category, entity_type, pattern, score)
VALUES ('SIG-CRED-001', 'GitHub token', 'CREDENTIAL', 'GITHUB_TOKEN', 'ghp_[A-Za-z0-9]{36}', 0.95);
"""

_KEYWORD_TABLE = """
CREATE TABLE doc_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT, keyword TEXT NOT NULL, doc_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', source TEXT NOT NULL DEFAULT 'llm', reason TEXT,
    doc_hits INTEGER, neg_hits INTEGER, created_at TEXT NOT NULL DEFAULT '', created_by TEXT,
    decided_at TEXT, decided_by TEXT, UNIQUE (keyword, doc_id)
);
"""


def _db(tmp_path: Path, *, with_keywords: bool = True, rows: list[tuple[str, str, str]] = ()) -> Path:
    """키워드 DB(운영에서는 KEYWORD_DB, 시그니처 DB와 별도 파일)."""
    path = tmp_path / "keyword.db"
    connection = sqlite3.connect(path)
    if with_keywords:
        connection.executescript(_KEYWORD_TABLE)
        connection.executemany("INSERT INTO doc_keywords (keyword, doc_id, status) VALUES (?, ?, ?)", rows)
    else:
        connection.execute("CREATE TABLE unrelated (x INTEGER)")
    connection.commit()
    connection.close()
    return path


def _sig_db(tmp_path: Path) -> Path:
    """시그니처 DB. 활성 규칙이 1건 이상이어야 load_database_recognizers가 통과한다."""
    path = tmp_path / "signature.db"
    connection = sqlite3.connect(path)
    connection.executescript(_SIGNATURE_SCHEMA)
    connection.commit()
    connection.close()
    return path


@pytest.fixture()
def restore_engine():
    """엔진 전역을 테스트 뒤에 되돌린다 - 다른 테스트가 기본 인식기 상태를 가정한다."""
    saved = {name: getattr(engine, name) for name in ("RECOGNIZERS", "LOADED_AT", "RULE_SOURCE", "DATABASE_RULES",
                                                       "KEYWORDS", "KEYWORD_SOURCE", "KEYWORD_ERROR")}
    yield
    for name, value in saved.items():
        setattr(engine, name, value)


# ---------------------------------------------------------------- 매칭 규칙


def test_substring_hit_ignores_word_boundary():
    """단어 경계를 보지 않는다(2026-10-01 결정) - 더 긴 단어 안에 있어도 적중한다."""
    hits = KeywordRecognizer(["대외비"]).analyze("이건 대외비밀유지 대상입니다")
    assert [(h.start, h.end) for h in hits] == [(3, 6)]


def test_every_occurrence_is_reported():
    hits = KeywordRecognizer(["그린라이트"]).analyze("그린라이트 일정과 그린라이트 예산")
    assert [(h.start, h.end) for h in hits] == [(0, 5), (10, 15)]


def test_ascii_case_is_ignored():
    hits = KeywordRecognizer(["Project Aurora"]).analyze("about PROJECT aurora plans")
    assert [(h.start, h.end) for h in hits] == [(6, 20)]


def test_positions_match_input_even_with_length_changing_characters():
    """casefold()였다면 'ß'가 'ss'로 늘어 뒤의 위치가 한 칸 밀린다. MASK 정책이면 엉뚱한 글자를 가리게 된다."""
    text = "Straße 그린라이트"
    hits = KeywordRecognizer(["그린라이트"]).analyze(text)
    assert len(hits) == 1
    assert text[hits[0].start:hits[0].end] == "그린라이트"


def test_fold_preserves_length():
    for text in ("Straße", "İstanbul", "ǅ", "ＡＢＣ", "그린라이트"):
        assert len(fold(text)) == len(text)


def test_no_hit_returns_empty():
    assert KeywordRecognizer(["그린라이트"]).analyze("오늘 점심 추천해줘") == []


def test_duplicates_are_folded_into_one():
    recognizer = KeywordRecognizer(["그린라이트", "그린라이트", "GREEN", "green"])
    assert len(recognizer) == 2


def test_hit_identity():
    hit = KeywordRecognizer(["그린라이트"]).analyze("그린라이트")[0]
    assert hit.entity_type == ENTITY_TYPE == "DOC_KEYWORD"
    assert KeywordRecognizer.category == CATEGORY == "KEYWORD"


# ---------------------------------------------------------------- 로딩


def test_load_missing_file_is_none(tmp_path: Path):
    assert load_approved_keywords(tmp_path / "nope.db") is None


def test_load_without_table_is_none(tmp_path: Path):
    """탐지 API가 뜨기 전(표를 만들기 전)에 엔진이 먼저 import되는 경우."""
    assert load_approved_keywords(_db(tmp_path, with_keywords=False)) is None


def test_load_with_zero_approved_is_none(tmp_path: Path):
    """키워드 0건은 정상 상태다 - 시그니처 규칙처럼 기동 실패로 다루지 않는다."""
    path = _db(tmp_path, rows=[("그린라이트", "01_사업전략", "pending")])
    assert load_approved_keywords(path) is None


def test_load_reads_only_approved(tmp_path: Path):
    path = _db(tmp_path, rows=[("그린라이트", "01_사업전략", "approved"), ("블루문", "02_이사회", "pending")])
    recognizer = load_approved_keywords(path)
    assert recognizer is not None and len(recognizer) == 1
    assert recognizer.analyze("블루문 그린라이트")[0].start == 4


# ---------------------------------------------------------------- 엔진 연결


def test_engine_loads_keywords_and_counts_them(tmp_path: Path, restore_engine):
    kw = _db(tmp_path, rows=[("그린라이트", "01_사업전략", "approved"), ("블루문", "02_이사회", "approved")])
    engine.configure_database(str(_sig_db(tmp_path)), keyword_db=str(kw))
    assert engine.DATABASE_RULES == 1
    assert engine.KEYWORDS == 2
    assert engine.KEYWORD_ERROR is None
    hits = [h for h in engine.query("그린라이트 일정") if h.entity_type == ENTITY_TYPE]
    assert len(hits) == 1


def test_engine_reads_keyword_db_from_environment(tmp_path: Path, restore_engine, monkeypatch):
    """재로딩 엔드포인트·import 시점 로딩은 인자 없이 부른다 - KEYWORD_DB 환경변수를 써야 한다."""
    kw = _db(tmp_path, rows=[("그린라이트", "01_사업전략", "approved")])
    monkeypatch.setenv("KEYWORD_DB", str(kw))
    engine.configure_database(str(_sig_db(tmp_path)))
    assert engine.KEYWORDS == 1
    assert engine.KEYWORD_SOURCE == str(kw)


def test_engine_without_keywords_has_no_keyword_recognizer(tmp_path: Path, restore_engine):
    engine.configure_database(str(_sig_db(tmp_path)), keyword_db=str(_db(tmp_path)))
    assert engine.KEYWORDS == 0
    assert not any(r.entity_type == ENTITY_TYPE for r in engine.RECOGNIZERS)


def test_policy_category_is_keyword_not_pii(tmp_path: Path, restore_engine):
    """category가 없으면 category_for_hit()가 PII로 간주해 POLICY-PII-MASK에 걸린다(차단 대신 마스킹)."""
    kw = _db(tmp_path, rows=[("그린라이트", "01_사업전략", "approved")])
    engine.configure_database(str(_sig_db(tmp_path)), keyword_db=str(kw))
    hit = engine.query("그린라이트")[0]
    assert engine.category_for_hit(hit) == "KEYWORD"


# ---------------------------------------------------------------- 키워드 DB 장애가 탐지를 멈추지 않는다 (2026-10-01 사고)


def test_corrupt_keyword_db_does_not_raise_and_keeps_previous_keywords(tmp_path: Path, restore_engine):
    """재로딩 중 키워드 DB가 깨져도 예외 없이 쓰던 키워드를 유지하고, 오류를 드러낸다."""
    sig = str(_sig_db(tmp_path))
    good = _db(tmp_path, rows=[("그린라이트", "01_사업전략", "approved")])
    engine.configure_database(sig, keyword_db=str(good))
    assert engine.KEYWORDS == 1

    broken = tmp_path / "broken.db"
    broken.write_bytes(b"this is not a sqlite database at all" * 100)
    engine.configure_database(sig, keyword_db=str(broken))  # 예외가 나면 테스트 실패

    assert engine.KEYWORD_ERROR is not None
    assert engine.KEYWORDS == 1  # 쓰던 키워드 유지
    assert any(h.entity_type == ENTITY_TYPE for h in engine.query("그린라이트"))


def test_corrupt_keyword_db_at_first_load_starts_with_zero_keywords(tmp_path: Path, restore_engine):
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"garbage" * 500)
    engine.configure_database(str(_sig_db(tmp_path)), keyword_db=str(broken))
    assert engine.KEYWORDS == 0
    assert engine.KEYWORD_ERROR is not None
    assert engine.DATABASE_RULES == 1  # 시그니처 규칙은 정상으로 올라왔다


def test_keyword_db_off_disables_keywords(tmp_path: Path, restore_engine):
    engine.configure_database(str(_sig_db(tmp_path)), keyword_db="off")
    assert engine.KEYWORDS == 0
    assert engine.KEYWORD_ERROR is None
