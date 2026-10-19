"""보호 중지 문서의 키워드 제외 · '보호 문서 몇 개에 나오는가' (2026-10-16).

1. 문서 보호를 중지하면(RDS status='retired') 그 문서의 승인 키워드가 탐지 적재에서 빠지고, 다시 보호하면 돌아온다.
   키워드 행·승인 상태는 그대로다. 문서 상태는 인덱서가 키워드 DB doc_states로 옮기고 바뀌면 탐지 재로딩을 부른다.
2. 키워드마다 보호 중인 문서 몇 개의 본문에 나오는지 세어 reason_check에 doc_count·common_in_docs(2개 이상)·doc_count_at을
   쓴다. LLM 판정(specificity·kind 등)은 그대로 둔다.
RDS는 가짜 연결로 둔다.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from detection_service import keyword_store
from docstore import indexer
from signature import engine
from signature.keywords import ENTITY_TYPE, load_approved_keywords

A, B, C = "01_사업전략_방향_보고서", "02_이사회_보고자료", "03_인사평가"
TEXTS = {
    A: "그린라이트 프로젝트 일정. 사업계획 요약.",
    B: "이사회 안건: 블루문 인수. 사업계획 검토.",
    C: "인사평가 기준. 사업계획 부록.",
}


class FakeConn:
    """psycopg 연결 흉내 - 인덱서 키워드 맞추기가 쓰는 두 쿼리만."""

    def __init__(self, docs):
        self.docs = docs          # doc_id -> {"status", "version", "text"}
        self.queries = 0

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=()):
                conn.queries += 1
                if sql.startswith("SELECT doc_id, status, version FROM documents"):
                    self._rows = [(d, v["status"], v["version"]) for d, v in conn.docs.items()]
                elif sql == indexer.ACTIVE_TEXTS_SQL:
                    self._rows = [(v["text"],) for v in conn.docs.values() if v["status"] == "active" and v["text"]]
                else:
                    raise AssertionError(sql)

            def fetchall(self):
                return self._rows

        return Cur()


@pytest.fixture
def kdb(tmp_path):
    path = tmp_path / "keyword.db"
    assert keyword_store.configure_database(str(path))
    yield path
    keyword_store.configure_database(None)


@pytest.fixture
def restore_engine():
    saved = {name: getattr(engine, name) for name in ("RECOGNIZERS", "LOADED_AT", "RULE_SOURCE", "DATABASE_RULES",
                                                       "KEYWORDS", "KEYWORD_SOURCE", "KEYWORD_ERROR")}
    yield
    for name, value in saved.items():
        setattr(engine, name, value)


def _docs(**status):
    return {d: {"status": status.get(k, "active"), "version": 1, "text": TEXTS[d]}
            for k, d in (("a", A), ("b", B), ("c", C))}


def _seed():
    """A·B에 승인 키워드 하나씩, A에 대기 하나, 두 문서 모두에 같은 승인 키워드 하나."""
    ga = keyword_store.add("그린라이트", A, approve=True)
    bm = keyword_store.add("블루문", B, approve=True)
    keyword_store.add("사업계획", A)                      # 대기
    keyword_store.add("공동코드", A, approve=True)
    keyword_store.add("공동코드", B, approve=True)
    return ga, bm


def _loaded(path) -> set[str]:
    rec = load_approved_keywords(path)
    return set() if rec is None else set(rec._keywords)


class Reload:
    def __init__(self, ok=True):
        self.ok, self.calls = ok, 0

    def __call__(self):
        self.calls += 1
        return self.ok


# ---------------------------------------------------------------- 1. 보호 중지 → 탐지 적재에서 빠짐

def test_paused_document_keywords_are_not_loaded_and_return_on_reactivation(kdb):
    _seed()
    keyword_store.sync_doc_states([(A, "retired", 1), (B, "active", 1)])
    assert _loaded(kdb) == {"블루문", "공동코드"}           # A의 그린라이트만 빠짐, B에도 있는 공동코드는 남음
    states_before = {r["id"]: r["status"] for r in keyword_store.list_keywords()}
    keyword_store.sync_doc_states([(A, "active", 2)])
    assert _loaded(kdb) == {"그린라이트", "블루문", "공동코드"}
    assert {r["id"]: r["status"] for r in keyword_store.list_keywords()} == states_before   # 행·승인 상태 그대로


def test_unknown_document_state_keeps_keywords(kdb):
    """상태를 모르면(아직 안 옮김) 탐지를 줄이지 않는다."""
    _seed()
    keyword_store.sync_doc_states([(B, "retired", 1)])
    assert "그린라이트" in _loaded(kdb) and "블루문" not in _loaded(kdb)


def test_old_keyword_db_without_state_table_loads_all(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE doc_keywords (keyword TEXT, doc_id TEXT, status TEXT)")
    con.execute("INSERT INTO doc_keywords VALUES ('그린라이트', ?, 'approved')", (A,))
    con.commit()
    con.close()
    assert _loaded(path) == {"그린라이트"}


def test_all_keywords_paused_means_no_recognizer(kdb):
    keyword_store.add("그린라이트", A, approve=True)
    keyword_store.sync_doc_states([(A, "retired", 1)])
    assert load_approved_keywords(kdb) is None


def test_engine_reload_stops_hitting_paused_document_keyword(kdb, restore_engine):
    _seed()
    engine.configure_database(None, keyword_db=str(kdb))
    assert [h for h in engine.query("그린라이트 일정") if h.entity_type == ENTITY_TYPE]
    keyword_store.sync_doc_states([(A, "retired", 1)])
    engine.configure_database(None, keyword_db=str(kdb))   # /admin/reload-signatures와 같은 경로
    assert not [h for h in engine.query("그린라이트 일정") if h.entity_type == ENTITY_TYPE]
    assert [h for h in engine.query("블루문 인수") if h.entity_type == ENTITY_TYPE]


def test_sync_reports_only_protection_changes(kdb):
    assert keyword_store.sync_doc_states([(A, "active", 1), (B, "active", 1)]) == []   # 처음 본 active = 바뀐 것 아님
    assert keyword_store.sync_doc_states([(A, "active", 1), (B, "retired", 1)]) == [B]
    assert keyword_store.sync_doc_states([(A, "active", 1), (B, "retired", 1)]) == []
    assert keyword_store.sync_doc_states([(C, "retired", 1)]) == [C]                   # 처음 본 중지 = 바뀜
    assert keyword_store.list_doc_states() == {A: "active", B: "retired", C: "retired"}


def test_indexer_sync_reloads_detection_when_protection_changes(kdb):
    _seed()
    reload = Reload()
    sync = indexer.KeywordSync(reload=reload)
    conn = FakeConn(_docs())
    out = sync.step(conn)
    assert reload.calls == 0 and out["state_changed"] == 0          # 전부 보호 중 - 탐지에 바뀔 것 없음
    conn.docs[A]["status"] = "retired"                              # 대시보드 '보호 중지'
    out = sync.step(conn, [{"doc_id": A, "outcome": "retired"}])
    assert reload.calls == 1 and out["reloaded"] is True and "그린라이트" not in _loaded(kdb)
    conn.docs[A]["status"] = "active"                               # 다시 보호
    sync.step(conn)
    assert reload.calls == 2 and "그린라이트" in _loaded(kdb)


def test_indexer_sync_retries_failed_reload_next_cycle(kdb):
    _seed()
    reload = Reload(ok=False)
    sync = indexer.KeywordSync(reload=reload)
    conn = FakeConn(_docs(a="retired"))
    assert sync.step(conn)["reloaded"] is False
    reload.ok = True
    assert sync.step(conn)["reloaded"] is True and reload.calls == 2
    sync.step(conn)
    assert reload.calls == 2                                         # 성공 뒤에는 더 부르지 않음


def test_indexer_sync_failure_does_not_raise(kdb, monkeypatch):
    def broken(rows):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(keyword_store, "sync_doc_states", broken)
    assert indexer.KeywordSync(reload=Reload()).step(FakeConn(_docs())) is None


def test_indexer_sync_without_keyword_db_does_nothing():
    keyword_store.configure_database(None)
    conn = FakeConn(_docs())
    assert indexer.KeywordSync(reload=Reload()).step(conn) is None and conn.queries == 0


# ---------------------------------------------------------------- 2. 보호 문서 몇 개에 나오는가

def _check(keyword, doc_id):
    return next(r for r in keyword_store.list_keywords(doc_id=doc_id) if r["keyword"] == keyword)["reason_check"]


def test_refresh_doc_counts_adds_fields_and_keeps_llm_judgement(kdb):
    keyword_store.add_extracted(A, [
        {"keyword": "사업계획", "reason": "r", "doc_hits": 9, "evidence": "e",
         "reason_check": {"ok": True, "source": "llm", "foreign_tokens": [], "specificity": "고유", "kind": "고유 이름·코드"},
         "reason_version": "v"},
        {"keyword": "그린라이트", "reason": "r", "doc_hits": 1, "evidence": "e",
         "reason_check": {"ok": True, "source": "llm", "foreign_tokens": [], "specificity": "일반", "kind": "표제·항목명"},
         "reason_version": "v"}])
    keyword_store.add("블루문", B)                                    # 직접 추가 - reason_check 없음
    before = {r["id"]: (r["keyword"], r["status"], r["doc_hits"], r["reason"], r["evidence"]) for r in keyword_store.list_keywords()}
    res = keyword_store.refresh_doc_counts(TEXTS.values())
    assert res == {"rows": 3, "changed": 3, "common": 1}
    common = _check("사업계획", A)
    assert common["doc_count"] == 3 and common["common_in_docs"] is True
    assert common["specificity"] == "고유" and common["kind"] == "고유 이름·코드" and common["ok"] is True   # LLM 판정 유지
    one = _check("그린라이트", A)
    assert one["doc_count"] == 1 and one["common_in_docs"] is False and one["specificity"] == "일반"
    manual = _check("블루문", B)
    assert set(manual) == {"doc_count", "common_in_docs", "doc_count_at"} and manual["doc_count"] == 1
    after = {r["id"]: (r["keyword"], r["status"], r["doc_hits"], r["reason"], r["evidence"]) for r in keyword_store.list_keywords()}
    assert after == before                                           # 다른 열은 그대로(doc_hits = 추출 때 값)
    assert keyword_store.refresh_doc_counts(TEXTS.values())["changed"] == 0


def test_threshold_is_two_documents(kdb):
    keyword_store.add("그린라이트", A)
    keyword_store.add("이사회", B)
    texts = [TEXTS[A], TEXTS[B], "그린라이트 언급"]                   # 그린라이트 2개, 이사회 1개
    keyword_store.refresh_doc_counts(texts)
    assert _check("그린라이트", A)["common_in_docs"] is True and _check("그린라이트", A)["doc_count"] == 2
    assert _check("이사회", B)["common_in_docs"] is False
    assert keyword_store.COMMON_MIN_DOCS == 2


def test_count_ignores_ascii_case_like_detection(kdb):
    keyword_store.add("PRJ-07", A)
    keyword_store.refresh_doc_counts(["prj-07 일정", "Prj-07 예산", "무관"])
    assert _check("PRJ-07", A)["doc_count"] == 2


def test_indexer_counts_only_protected_documents_and_recounts_on_changes(kdb):
    keyword_store.add("사업계획", A, approve=True)
    sync = indexer.KeywordSync(reload=Reload())
    conn = FakeConn(_docs())
    out = sync.step(conn)
    assert out["counts"]["common"] == 1 and _check("사업계획", A)["doc_count"] == 3
    out = sync.step(conn)
    assert "counts" not in out                                      # 바뀐 것 없으면 다시 세지 않음
    conn.docs[B]["status"] = "retired"
    conn.docs[C]["status"] = "retired"
    sync.step(conn)
    assert _check("사업계획", A)["doc_count"] == 1 and _check("사업계획", A)["common_in_docs"] is False
    keyword_store.add("블루문", A)                                   # 직접 추가 → 다음 주기에 셈
    sync.step(conn)
    assert _check("블루문", A)["doc_count"] == 0
    conn.docs[C] = {"status": "active", "version": 2, "text": "사업계획 재등록"}
    sync.step(conn, [{"doc_id": C, "outcome": "indexed"}])            # 새 판 색인 완료 → 다시 셈
    assert _check("사업계획", A)["doc_count"] == 2


def test_missing_doc_counts(kdb):
    keyword_store.add("그린라이트", A)
    assert keyword_store.missing_doc_counts() == 1
    keyword_store.refresh_doc_counts(TEXTS.values())
    assert keyword_store.missing_doc_counts() == 0
    row = keyword_store.list_keywords()[0]
    keyword_store.update(row["id"], "그린라이트2")                   # 승인 전 수정은 reason_check를 비움 → 다시 셈 대상
    assert keyword_store.missing_doc_counts() == 1


def test_stored_json_is_compact_and_parsable(kdb):
    keyword_store.add("그린라이트", A)
    keyword_store.refresh_doc_counts(TEXTS.values())
    con = sqlite3.connect(kdb)
    raw = con.execute("SELECT reason_check FROM doc_keywords").fetchone()[0]
    con.close()
    assert json.loads(raw)["doc_count"] == 1 and ", " not in raw
