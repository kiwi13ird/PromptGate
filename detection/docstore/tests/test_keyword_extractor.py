"""키워드 추출 작업 큐·추출 서비스. RDS·GPU는 가짜로 둔다 - 핵심은 GPU가 꺼졌을 때 작업이 사라지지 않는 것."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from detection_service import keyword_store
from docstore import keyword_extractor as kx
from docstore.indexer import enqueue_keyword_job

DOC = "01_사업전략_방향_보고서"
TEXT = ("1. 개요\nPRJ-2026-07 일본 진출 계획은 이사회 승인 안건이다. 협상 상대는 Tokyo Bridge Solutions.\n"
        "담당자 연락처 010-1234-5678. 네오보드 3.0 출시는 내년.\n" * 3)
OTHER = "다른 문서. PRJ-2026-07 예산 배정. 일반 보고서 양식."


class FakeConn:
    """psycopg 연결 흉내 - extractor가 쓰는 두 쿼리만."""

    def __init__(self, docs):
        self.docs = docs

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=()):
                if "WHERE doc_id" in sql:
                    d = conn.docs.get(params[0])
                    self._rows = [(d["version"], d["status"], d["index_status"], d["text"])] if d else []
                else:
                    self._rows = [(d["text"],) for d in conn.docs.values() if d["status"] == "active" and d["text"]]

            def fetchone(self):
                return self._rows[0] if self._rows else None

            def fetchall(self):
                return self._rows

        return Cur()


@pytest.fixture
def kdb(tmp_path):
    assert keyword_store.configure_database(str(tmp_path / "keyword.db"))
    yield tmp_path
    keyword_store.configure_database(None)


@pytest.fixture
def conn():
    return FakeConn({DOC: {"version": 2, "status": "active", "index_status": "indexed", "text": TEXT},
                     "02_이사회_보고자료": {"version": 1, "status": "active", "index_status": "indexed", "text": OTHER}})


def reason_ok(system, user):
    """정상 이유: 용례에 있는 말만 쓴다."""
    kw = user.split("후보: ", 1)[1].split("\n", 1)[0]
    return {"reason": f"{kw}이(가) 외부에 알려지면 사내 계획이 노출될 수 있어 후보로 골랐다.", "specificity": "고유"}


def kind_ok(system, user):
    """정상 종류: 코드명·이름은 고유."""
    return {"kind": "고유 이름·코드"}


def llm_ok(system, user):
    if "종류인지 고른다" in system:                   # 표현 종류 분류 호출
        return kind_ok(system, user)
    if "선정한 이유" in system:                       # 후보별 선정 이유 호출(선별 호출과 같은 가짜 LLM이 둘 다 받는다)
        return reason_ok(system, user)
    assert "기밀" in system and "개인정보" in system
    return {"keywords": [
        {"keyword": "PRJ-2026-07", "importance": "high", "reason": "일본 진출 프로젝트 코드"},
        {"keyword": "tokyo bridge solutions", "importance": "high", "reason": "협상 상대"},   # 대소문자 다름 - 본문 대조 통과
        {"keyword": "010-1234-5678", "importance": "medium", "reason": "연락처"},          # 개인정보 패턴 → 버림
        {"keyword": "그린라이트", "importance": "high", "reason": "없는 표현"},              # 본문에 없음 → 버림
        {"keyword": "네오보드 3.0", "importance": "medium", "reason": "미출시 버전"},
    ]}


def test_split_chunks_covers_text_with_overlap():
    text = "\n".join(f"{i:04d} " + "가" * 90 for i in range(200))
    chunks = kx.split_chunks(text, size=3000, overlap=200)
    assert all(len(c) <= 3000 for c in chunks)
    assert chunks[0] == text[: len(chunks[0])]
    assert text.endswith(chunks[-1])
    joined_lines = {line for c in chunks for line in c.split("\n")}
    assert all(line in joined_lines for line in text.split("\n"))     # 경계에서 잃는 줄이 없다
    assert kx.split_chunks("짧다") == ["짧다"] and kx.split_chunks("  ") == []


def test_select_filters_and_ranks():
    raw = [llm_ok("기밀 개인정보", "")["keywords"], [{"keyword": "PRJ-2026-07", "importance": "high", "reason": "x"},
                                         {"keyword": "2026", "importance": "high", "reason": "숫자"},
                                         {"keyword": "가", "importance": "high", "reason": "짧음"}]]
    kept, dropped = kx.select(raw, TEXT)
    assert [c.keyword for c in kept] == ["PRJ-2026-07", "tokyo bridge solutions", "네오보드 3.0"]
    assert kept[0].chunks == 2 and kept[0].high == 2
    why = {d["keyword"]: d["why"] for d in dropped}
    assert why["010-1234-5678"] == "개인정보 패턴"
    assert why["그린라이트"] == "본문에 없음"
    assert why["2026"] == "숫자·기호만"
    assert why["가"] == "KEYWORD_TOO_SHORT"


def test_select_caps_at_ten():
    text = " ".join(f"코드명{i:02d}" for i in range(15))
    raw = [[{"keyword": f"코드명{i:02d}", "importance": "medium", "reason": ""} for i in range(15)]]
    kept, dropped = kx.select(raw, text)
    assert len(kept) == kx.MAX_KEYWORDS
    assert sum(1 for d in dropped if "상한" in d["why"]) == 5


def test_process_job_inserts_pending_only(kdb, conn):
    job = keyword_store.enqueue_job(DOC, 2)
    claimed = keyword_store.claim_job()
    res = kx.process_job(claimed, conn, chat=llm_ok, neg=["무관 문장", "PRJ-2026-07 아님"])
    assert res["outcome"] == "extracted" and res["inserted"] == 3
    rows = {r["keyword"]: r for r in keyword_store.list_keywords(doc_id=DOC)}
    assert set(rows) == {"PRJ-2026-07", "tokyo bridge solutions", "네오보드 3.0"}
    assert {r["status"] for r in rows.values()} == {"pending"}        # 승인은 사람이 한다
    assert rows["PRJ-2026-07"]["doc_hits"] == 2 and rows["PRJ-2026-07"]["neg_hits"] == 1
    assert rows["네오보드 3.0"]["doc_hits"] == 1 and rows["네오보드 3.0"]["neg_hits"] == 0
    assert keyword_store.get_job(job["id"])["status"] == "done"
    # 같은 문서 재추출 - 이미 있는 키워드는 건너뛴다(승인 상태 보존)
    keyword_store.approve(rows["PRJ-2026-07"]["id"])
    keyword_store.enqueue_job(DOC, 2)
    res2 = kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok)
    assert res2["inserted"] == 0
    assert keyword_store.get(rows["PRJ-2026-07"]["id"])["status"] == "approved"


def test_gpu_down_leaves_jobs_queued(kdb, conn):
    status = kdb / "status.json"
    job = keyword_store.enqueue_job(DOC, 2)
    out = kx.run_pending(conn, ready=lambda: False, chat=llm_ok, status_path=str(status))
    assert out == []
    j = keyword_store.get_job(job["id"])
    assert j["status"] == "queued" and j["attempts"] == 0
    st = json.loads(status.read_text(encoding="utf-8"))
    assert st["gpu"] == "down" and st["queued"] == 1
    # GPU가 켜지면 쌓인 작업이 처리된다
    out = kx.run_pending(conn, ready=lambda: True, chat=llm_ok, status_path=str(status))
    assert [r["outcome"] for r in out] == ["extracted"]
    assert json.loads(status.read_text(encoding="utf-8"))["queued"] == 0


def test_gpu_drop_mid_job_requeues_without_attempt(kdb, conn):
    def dropped(system, user):
        raise kx.GpuUnavailable("URLError: timed out")

    job = keyword_store.enqueue_job(DOC, 2)
    kx.run_pending(conn, ready=lambda: True, chat=dropped, status_path=str(kdb / "s.json"))
    j = keyword_store.get_job(job["id"])
    assert j["status"] == "queued" and j["attempts"] == 0 and j["error"].startswith("gpu:")
    assert keyword_store.list_keywords(doc_id=DOC) == []


def test_bad_llm_output_fails_after_three_attempts_then_retry(kdb, conn):
    def garbage(system, user):
        raise json.JSONDecodeError("Expecting value", "x", 0)

    job = keyword_store.enqueue_job(DOC, 2)
    out = kx.run_pending(conn, ready=lambda: True, chat=garbage, status_path=str(kdb / "s.json"))
    assert [r["outcome"] for r in out] == ["queued", "queued", "failed"]
    j = keyword_store.get_job(job["id"])
    assert j["status"] == "failed" and j["attempts"] == keyword_store.MAX_ATTEMPTS
    with pytest.raises(keyword_store.KeywordError):
        keyword_store.retry_job(keyword_store.enqueue_job("other", 1)["id"])     # failed가 아니면 409
    r = keyword_store.retry_job(job["id"])
    assert r["status"] == "queued" and r["attempts"] == 0


def test_superseded_versions_are_not_extracted(kdb, conn):
    keyword_store.enqueue_job(DOC, 1)                       # 문서는 이미 version 2
    res = kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok)
    assert res["outcome"] == "superseded"
    conn.docs[DOC]["status"] = "retired"
    keyword_store.enqueue_job(DOC, 0)
    assert kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok)["outcome"] == "superseded"
    assert keyword_store.list_keywords(doc_id=DOC) == []


def test_enqueue_dedupes_and_tracks_latest_version(kdb):
    a = keyword_store.enqueue_job(DOC, 1)
    b = keyword_store.enqueue_job(DOC, 2)
    assert a["id"] == b["id"] and b["doc_version"] == 2
    assert keyword_store.job_counts()["queued"] == 1


def test_indexer_hook_is_optional(tmp_path):
    keyword_store.configure_database(None)
    assert enqueue_keyword_job(DOC, 1) is None              # 키워드 DB 없음 - 색인은 그대로 성공
    assert keyword_store.configure_database(str(tmp_path / "k.db"))
    try:
        assert enqueue_keyword_job(DOC, 1)["status"] == "queued"
    finally:
        keyword_store.configure_database(None)


def test_neg_corpus_loader(tmp_path):
    p = tmp_path / "neg.jsonl"
    p.write_text('{"text": "가나다"}\n# 주석\n일반 문장\n', encoding="utf-8")
    assert kx.load_neg_corpus(str(p)) == ["가나다", "일반 문장"]
    assert kx.load_neg_corpus(str(tmp_path / "none")) is None

# ---------------------------------------------------------------- 선정 이유 (2026-10-13)

LONG = ("회의 개요. " + "일반 설명 문장입니다. " * 20 + "PRJ-2026-07 일본 진출 계획은 이사회 승인 안건이며 협상 상대와 일정은 비공개이다. "
        + "뒤쪽 문장은 길게 이어진다. " * 8 + "\nPRJ-2026-07 두 번째 줄 용례.\nPRJ-2026-07 세 번째 줄 용례.")


def test_find_evidence_cuts_original_sentences_only():
    ev = kx.find_evidence(LONG, "prj-2026-07")              # 대소문자 달라도 찾고, 서로 다른 문장 최대 2개
    assert len(ev) == 2 and all("PRJ-2026-07" in e for e in ev)
    squash = lambda t: " ".join(t.split())                  # noqa: E731
    assert all(squash(e.strip("…")) in squash(LONG) for e in ev)     # 시스템이 원문에서 자른 것 - 지어낼 수 없다
    assert all(len(e) <= kx.EVIDENCE_WIDTH + 2 for e in ev)
    assert kx.find_evidence(LONG, "없는표현") == [] and kx.find_evidence("", "x") == []
    assert kx.find_evidence("PRJ-2026-07 짧은 문장.", "PRJ-2026-07") == ["PRJ-2026-07 짧은 문장."]


def test_find_evidence_trims_long_sentence_around_keyword():
    long_sentence = "가" * 300 + " PRJ-2026-07 " + "나" * 300
    [piece] = kx.find_evidence(long_sentence, "PRJ-2026-07", limit=1)
    assert piece.startswith("…") and piece.endswith("…") and "PRJ-2026-07" in piece
    assert len(piece) <= kx.EVIDENCE_WIDTH + 2


def test_check_reason_rejects_invented_numbers_names_and_foreign_scripts():
    pool = "PRJ-2026-07\n01_사업전략_방향_보고서\nPRJ-2026-07 일본 진출 계획은 2027년 1분기 출시이다."
    good = kx.check_reason("일본 진출 계획이 알려지면 2027년 출시 일정이 노출될 수 있다.", pool)
    assert good["ok"] and good["foreign_tokens"] == []
    bad = kx.check_reason("협상 금액 12억이 알려지면 Samsung 쪽에 불리하다.", pool)
    assert not bad["ok"] and {"12", "Samsung"} <= set(bad["foreign_tokens"])
    assert not kx.check_reason("짧다", pool)["ok"]                                  # 너무 짧음
    assert not kx.check_reason("가" * (kx.REASON_MAX + 1), pool)["ok"]              # 너무 김
    # 8B 모델이 한국어 문장에 섞어 쓰는 한자·가나·키릴 글자(실측: '회议실')는 본문·키워드에 없으면 거부
    mixed = kx.check_reason("회议실에서 다뤄지는 일본 진출 계획이 노출될 수 있다.", pool)
    assert not mixed["ok"] and mixed["foreign_tokens"] == ["议"]
    assert kx.check_reason("TCL CSOT社와의 일본 진출 계획이 노출될 수 있다.", pool + "\nTCL CSOT社")["ok"]   # 표현에 든 글자는 허용


def test_process_job_stores_reason_evidence_and_checks(kdb, conn):
    keyword_store.enqueue_job(DOC, 2)
    res = kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok, neg=["무관"])
    assert res["reason_llm"] == 3 and res["reason_short"] == 0 and res["refreshed"] == 0
    rows = {r["keyword"]: r for r in keyword_store.list_keywords(doc_id=DOC)}
    r = rows["PRJ-2026-07"]
    assert "외부에 알려지면" in r["reason"] and "caution" not in r
    assert "PRJ-2026-07" in r["evidence"]
    doc_fields = ("doc_count", "common_in_docs", "doc_count_at")
    assert {k: v for k, v in r["reason_check"].items() if k not in doc_fields} == {
        "ok": True, "source": "llm", "foreign_tokens": [], "kind": "고유 이름·코드", "specificity": "고유"}
    # 문서 수 3칸(2026-10-16): PRJ-2026-07은 보호 문서 2개에 나옴 → 일반 표현일 수 있음, 네오보드 3.0은 1개
    assert r["reason_check"]["doc_count"] == r["doc_hits"] == 2 and r["reason_check"]["common_in_docs"] is True
    assert r["reason_check"]["doc_count_at"].endswith("Z")
    n = rows["네오보드 3.0"]["reason_check"]
    assert n["doc_count"] == 1 and n["common_in_docs"] is False
    assert r["reason_version"] == kx.REASON_VERSION == "keyword_reason.v4+keyword_kind.v1" and r["status"] == "pending"
    squash = lambda t: " ".join(t.split())                  # noqa: E731
    for row in rows.values():                                # 근거 문장은 전부 본문에서 그대로 잘라 온 것
        assert row["evidence"] and all(squash(line.strip("…")) in squash(TEXT) for line in row["evidence"].split("\n"))


def test_invented_reason_falls_back_to_short_reason_but_keeps_evidence(kdb, conn):
    def liar(system, user):
        if "선정한 이유" in system:
            return {"reason": "이 표현은 협상 금액 12억과 Samsung 계약을 가리켜 유출되면 큰 손해가 난다.", "specificity": "고유"}
        return llm_ok(system, user)

    keyword_store.enqueue_job(DOC, 2)
    res = kx.process_job(keyword_store.claim_job(), conn, chat=liar)
    assert res["reason_llm"] == 0 and res["reason_short"] == 3 and res["inserted"] == 3
    r = {x["keyword"]: x for x in keyword_store.list_keywords(doc_id=DOC)}["PRJ-2026-07"]
    assert r["reason"] == "일본 진출 프로젝트 코드"                       # 선별 단계의 짧은 이유로 대체
    assert r["evidence"] and r["reason_check"]["ok"] is False and r["reason_check"]["source"] == "short"
    assert "12" in r["reason_check"]["foreign_tokens"] and "Samsung" in r["reason_check"]["foreign_tokens"]
    assert r["reason_check"]["kind"] == "고유 이름·코드" and r["reason_check"]["specificity"] == "고유"   # 종류 호출은 이유와 독립


def test_reason_call_failure_other_than_gpu_keeps_candidate(kdb, conn):
    def broken(system, user):
        if "선정한 이유" in system:
            raise json.JSONDecodeError("Expecting value", "x", 0)
        return llm_ok(system, user)

    keyword_store.enqueue_job(DOC, 2)
    res = kx.process_job(keyword_store.claim_job(), conn, chat=broken)
    assert res["inserted"] == 3 and res["reason_short"] == 3
    r = {x["keyword"]: x for x in keyword_store.list_keywords(doc_id=DOC)}["네오보드 3.0"]
    assert r["reason"] == "미출시 버전" and r["reason_check"]["error"] == "JSONDecodeError" and r["evidence"]


def test_gpu_drop_during_reason_requeues_and_saves_nothing(kdb, conn):
    def gpu_gone(system, user):
        if "선정한 이유" in system:
            raise kx.GpuUnavailable("URLError: timed out")
        return llm_ok(system, user)

    job = keyword_store.enqueue_job(DOC, 2)
    kx.run_pending(conn, ready=lambda: True, chat=gpu_gone, status_path=str(kdb / "s.json"))
    j = keyword_store.get_job(job["id"])
    assert j["status"] == "queued" and j["attempts"] == 0 and j["error"].startswith("gpu:")
    assert keyword_store.list_keywords(doc_id=DOC) == []                # 선별만 끝난 상태로는 저장하지 않는다


def test_general_flag_merges_inline_judgement_and_kind_call(kdb, conn):
    """일반 여부 = 이유 호출 안의 판정 OR 종류 분류(표제·일반어·공개명·서식). 둘 중 하나만 일반이어도 일반."""
    kinds = {"PRJ-2026-07": "고유 이름·코드", "tokyo bridge solutions": "표제·항목명", "네오보드 3.0": "고유 이름·코드"}
    inline = {"PRJ-2026-07": "고유", "tokyo bridge solutions": "고유", "네오보드 3.0": "일반"}

    def both(system, user):
        if "종류인지 고른다" in system:
            return {"kind": kinds[user.split("후보: ", 1)[1].split("\n", 1)[0]]}
        if "선정한 이유" in system:
            kw = user.split("후보: ", 1)[1].split("\n", 1)[0]
            return {"reason": f"{kw}이(가) 문서에 나오는 표현이다. 용례만으로는 판단이 어렵다.", "specificity": inline[kw]}
        return llm_ok(system, user)

    keyword_store.enqueue_job(DOC, 2)
    kx.process_job(keyword_store.claim_job(), conn, chat=both)
    rows = {x["keyword"]: x["reason_check"] for x in keyword_store.list_keywords(doc_id=DOC)}
    assert rows["PRJ-2026-07"]["specificity"] == "고유" and rows["PRJ-2026-07"]["kind"] == "고유 이름·코드"
    assert rows["tokyo bridge solutions"]["specificity"] == "일반" and rows["tokyo bridge solutions"]["kind"] == "표제·항목명"
    assert rows["네오보드 3.0"]["specificity"] == "일반" and rows["네오보드 3.0"]["kind"] == "고유 이름·코드"


def test_kind_call_failure_or_unknown_values_fall_back_to_inline_judgement(kdb, conn):
    def flaky(system, user):
        kw = user.split("후보: ", 1)[1].split("\n", 1)[0] if "후보: " in user else ""
        if "종류인지 고른다" in system:
            if kw == "PRJ-2026-07":
                raise json.JSONDecodeError("Expecting value", "x", 0)         # 호출 실패 → 이유 호출 판정만
            return {"kind": "아무거나"}                                          # 정해진 종류가 아님 → 쓰지 않음
        if "선정한 이유" in system:
            spec = "일반" if kw == "네오보드 3.0" else "아무거나"                # 정해진 값이 아니면 쓰지 않음
            return {"reason": f"{kw}이(가) 문서에 나오는 표현이다. 용례만으로는 판단이 어렵다.", "specificity": spec}
        return llm_ok(system, user)

    keyword_store.enqueue_job(DOC, 2)
    res = kx.process_job(keyword_store.claim_job(), conn, chat=flaky)
    assert res["inserted"] == 3 and res["reason_llm"] == 3
    rows = {x["keyword"]: x["reason_check"] for x in keyword_store.list_keywords(doc_id=DOC)}
    assert rows["PRJ-2026-07"]["specificity"] is None and rows["PRJ-2026-07"]["kind"] is None   # 둘 다 모름 → 표시 없음
    assert rows["네오보드 3.0"]["specificity"] == "일반" and rows["네오보드 3.0"]["kind"] is None
    assert rows["tokyo bridge solutions"]["specificity"] is None


def test_gpu_drop_during_kind_call_requeues_and_saves_nothing(kdb, conn):
    def gpu_gone(system, user):
        if "종류인지 고른다" in system:
            raise kx.GpuUnavailable("URLError: timed out")
        return llm_ok(system, user)

    job = keyword_store.enqueue_job(DOC, 2)
    kx.run_pending(conn, ready=lambda: True, chat=gpu_gone, status_path=str(kdb / "s.json"))
    j = keyword_store.get_job(job["id"])
    assert j["status"] == "queued" and j["attempts"] == 0 and j["error"].startswith("gpu:")
    assert keyword_store.list_keywords(doc_id=DOC) == []


def test_reextract_refreshes_old_rows_without_touching_status(kdb, conn):
    # 옛 방식으로 저장된 행(근거 없음, 짧은 이유) - 승인된 것과 대기 중인 것, 사람이 넣은 것
    old_a = keyword_store.add("PRJ-2026-07", DOC, source="llm", approve=True, reason="옛 짧은 이유", actor="admin1")
    old_b = keyword_store.add("네오보드 3.0", DOC, source="llm", reason="옛 이유")
    manual = keyword_store.add("tokyo bridge solutions", DOC, source="manual", reason="사람이 쓴 설명")
    keyword_store.enqueue_job(DOC, 2)
    res = kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok)
    assert res["inserted"] == 0 and res["refreshed"] == 2               # llm 출처 둘만 보강, 사람이 넣은 행은 그대로
    a, b, m = (keyword_store.get(x["id"]) for x in (old_a, old_b, manual))
    assert a["status"] == "approved" and a["decided_by"] == "admin1" and a["keyword"] == "PRJ-2026-07"
    assert "외부에 알려지면" in a["reason"] and a["evidence"] and b["evidence"]
    assert m["reason"] == "사람이 쓴 설명" and m["evidence"] is None
    keyword_store.enqueue_job(DOC, 2)                                    # 한 번 보강한 행은 다시 덮어쓰지 않는다
    assert kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok)["refreshed"] == 0


def test_old_schema_db_is_migrated_in_place(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE doc_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT, keyword TEXT NOT NULL, doc_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved')),
            source TEXT NOT NULL DEFAULT 'llm' CHECK (source IN ('llm', 'manual')), reason TEXT, doc_hits INTEGER,
            neg_hits INTEGER, created_at TEXT NOT NULL, created_by TEXT, decided_at TEXT, decided_by TEXT,
            UNIQUE (keyword, doc_id));
        INSERT INTO doc_keywords (keyword, doc_id, status, reason, created_at) VALUES ('옛키워드', 'D', 'approved', '옛 이유', 't');
    """)
    con.commit()
    con.close()
    assert keyword_store.configure_database(str(path))
    try:
        [row] = keyword_store.list_keywords()
        assert row["keyword"] == "옛키워드" and row["status"] == "approved" and row["reason"] == "옛 이유"
        assert row["evidence"] is None and row["reason_check"] is None and row["reason_version"] is None
        assert keyword_store.configure_database(str(path))               # 두 번째 열기(다른 프로세스가 먼저 바꾼 경우)도 안전
        added = keyword_store.add_extracted("D", [{"keyword": "새키워드", "reason": "r", "evidence": "근거",
                                                   "reason_check": {"ok": True}, "reason_version": "v"}])
        assert added[0]["reason_check"] == {"ok": True} and added[0]["evidence"] == "근거"
    finally:
        keyword_store.configure_database(None)
    from signature.keywords import load_approved_keywords           # 탐지 엔진은 keyword 열만 읽는다 - 열이 늘어도 로딩 그대로

    assert len(load_approved_keywords(path)) == 1


def test_editing_a_pending_keyword_clears_stale_evidence_and_check(kdb, conn):
    keyword_store.enqueue_job(DOC, 2)
    kx.process_job(keyword_store.claim_job(), conn, chat=llm_ok, neg=["무관"])
    row = {r["keyword"]: r for r in keyword_store.list_keywords(doc_id=DOC)}["네오보드 3.0"]
    assert row["evidence"] and row["reason_check"] and row["reason_version"]
    edited = keyword_store.update(row["id"], "네오보드 4.0")                 # 승인 전 표현 수정
    assert edited["keyword"] == "네오보드 4.0" and edited["doc_hits"] is None and edited["neg_hits"] is None
    assert edited["evidence"] is None and edited["reason_check"] is None and edited["reason_version"] is None
    assert edited["reason"] == row["reason"]                                 # 이유 글은 그대로
