"""집계 기준(v1 3.3·3.4) - 한국 시각 경계, 시험 제외, 재전송 묶기, 판단 묶음, 서비스 분리, 카드 합계 검사.

기대값은 아래 이벤트 목록을 보고 손으로 셌다(주석의 번호). 값은 전부 가짜.
"""

import re
from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import same_text as st

from synth import FakeConn, dec, doc_prompt, ev, kst

U1, U2, U3, U4, X = "chrome-u1", "chrome-u2", "chrome-u3", "chrome-u4", ag.UNKNOWN_CLIENT


def period_events(with_prev_start=True):
    E = []
    if with_prev_start:
        E.append(ev("2026-09-29 00:00:00", U1, "ChatGPT", "ALLOW", eid="p0"))             # 이전 기간 첫 순간
    E += [
        ev("2026-09-30 23:59:59", U1, "ChatGPT", "ALLOW", eid="e1"),                       # 1 이전 기간
        ev("2026-10-01 00:00:00", U1, "ChatGPT", "ALLOW", eid="e2"),                       # 2 이번(10/1)
        ev("2026-10-01 09:00:00", "demo-x", "ChatGPT", "BLOCK", eid="e3"),                 # 3 시험
        ev("2026-10-01 09:01:00", "gateway", "ChatGPT", "ALLOW", eid="e4"),                # 4 시험(접두어만)
        ev("2026-10-01 09:02:00", "democrat-1", "ChatGPT", "ALLOW", eid="e5"),             # 5 시험 아님
        ev("2026-10-01 10:00:00", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f1", eid="e6a"),
        ev("2026-10-01 10:00:02", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f1", eid="e6b"),  # 재전송
        ev("2026-10-01 10:00:06.350", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f1", eid="e6c"),  # 4.35초
        ev("2026-10-01 10:05:00", U2, "ChatGPT", "ALLOW", eid="e8a"),
        ev("2026-10-01 10:05:02", U2, "ChatGPT", "ALLOW", eid="e8b"),                      # 프롬프트는 안 묶음
        ev("2026-10-01 11:00:00", U3, "ChatGPT", "BLOCK", docs=["doc01"], eid="e9"),
        ev("2026-10-01 11:05:00", U3, "Claude", "BLOCK", ents={"DOC_KEYWORD": 1}, eid="e10"),
        ev("2026-10-01 11:10:00", U3, "Gemini", "MASK", ents={"KR_PHONE_NUMBER": 2}, eid="e11"),
        ev("2026-10-01 12:00:00", X, "ChatGPT", "BLOCK", "file", rc="mask_application_failed", ents={"KR_RRN": 1}, eid="e12"),
        ev("2026-10-01 12:10:00", X, "ChatGPT", "ALLOW", "file", rc="file_uninspectable_image", eid="e13"),
        ev("2026-10-01 12:20:00", X, "ChatGPT", "ALLOW", rc="detection_unreachable", deg=True, eid="e14"),
        ev("2026-10-01 13:00:00", U4, "ChatGPT", "ALLOW", endpoint="/v1/responses", eid="e15"),
        ev("2026-10-01 13:05:00", U4, "Claude", "MASK", endpoint="/claudeai-rpc/abc", ents={"EMAIL_ADDRESS": 1}, eid="e16"),
        ev("2026-10-01 13:10:00", U4, "ChatGPT", "BLOCK", rc="ip_blocked", eid="e17"),     # 접속 차단 - 합계 밖
        ev("2026-10-01 13:20:00", U4, "Gemini", "BLOCK", rc="detection_timeout", deg=True, eid="e19"),  # 그 밖
        ev("2026-10-02 23:59:59", U1, "Claude", "ALLOW", eid="e20"),                       # 이번(10/2)
        ev("2026-10-03 00:00:00", U1, "Claude", "ALLOW", eid="e21"),                       # 다음 기간
    ]
    return E


def _cur(rows, start=date(2026, 10, 1), end=date(2026, 10, 3)):
    t0, t1 = ag.kst_bounds(start, end)
    evs, ex = ag.prepare_events(rows, t0, t1)
    ag.attach_decisions(evs, {})
    return evs, ex, ag.metrics(evs, start, end)


def test_kst_boundaries_exclusion_resend_and_categories():
    evs, ex, m = _cur(period_events())
    ids = [e["id"] for e in evs]
    assert ids == ["e2", "e5", "e6a", "e6c", "e8a", "e8b", "e9", "e10", "e11", "e12", "e13", "e14", "e15", "e16", "e19", "e20"]
    assert ex == {"test": 2, "demo": 0, "resend": 1, "resend_file": 1, "resend_prompt": 0, "access": 1}
    c = m["cards"]
    assert (c["total"], c["prompt"], c["file"]) == (16, 12, 4)
    assert (c["secret"], c["secret_doc"], c["secret_kw"]) == (2, 1, 1)
    assert (c["mask"], c["pii_block"], c["mask_failed"], c["uninsp_block"], c["unchecked"]) == (2, 1, 1, 2, 2)
    assert (c["allow_clean"], c["rest"]) == (6, 1)
    assert {d: sum(v.values()) for d, v in m["daily"].items()} == {"2026-10-01": 15, "2026-10-02": 1}
    cats = {e["id"]: e["cat"] for e in evs}
    assert cats["e9"] == "doc" and cats["e10"] == "keyword" and cats["e12"] == "mask_failed"
    assert cats["e13"] == "uninspectable" and cats["e14"] == "no_check" and cats["e19"] == "no_check"
    svc = {e["id"]: e["svc"] for e in evs}
    assert svc["e15"] == "OpenAI API" and svc["e16"] == "Claude(새 화면)" and svc["e10"] == "Claude"
    assert sum(m["by_svc"].values()) == 16
    assert m["unchecked_by_rc"] == {"file_uninspectable_image": 1, "detection_unreachable": 1}
    assert [p["code"] for p in m["pii"]] == ["EMAIL_ADDRESS", "KR_PHONE_NUMBER", "KR_RRN"]


def test_resend_cutoff_and_processing_time_basis():
    rows = [
        ev("2026-10-11 13:00:00", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f", eid="r1"),
        ev("2026-10-11 13:00:02", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f", eid="r2"),  # 04:00 UTC → 묶음
        ev("2026-10-11 14:00:00", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f", eid="r3"),
        ev("2026-10-11 14:00:02", U2, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", fid="f", eid="r4"),  # 05:00 UTC → Gateway가 묶음
        ev("2026-10-11 11:00:00", U1, "ChatGPT", "ALLOW", pms=19000.0, eid="t1"),           # 처리 시간 기준 전
        ev("2026-10-11 12:00:00", U1, "ChatGPT", "ALLOW", pms=20.0, eid="t2"),
        ev("2026-10-11 12:01:00", U1, "ChatGPT", "ALLOW", pms=30.0, eid="t3"),
    ]
    evs, ex, m = _cur(rows, date(2026, 10, 11), date(2026, 10, 12))
    assert ex["resend"] == 1 and "r2" not in [e["id"] for e in evs] and "r4" in [e["id"] for e in evs]
    assert m["pms"]["n"] == 2 and m["pms"]["p50"] == 25.0 and m["pms"]["max"] == 30.0


def test_resend_gap_exactly_4348ms_is_merged():
    rows = [ev("2026-10-01 10:00:00", U2, "ChatGPT", "ALLOW", "file", fid="f", eid="g1"),
            ev("2026-10-01 10:00:04.348", U2, "ChatGPT", "ALLOW", "file", fid="f", eid="g2"),
            ev("2026-10-01 10:00:08.697", U2, "ChatGPT", "ALLOW", "file", fid="f", eid="g3")]
    evs, ex, _ = _cur(rows)
    assert [e["id"] for e in evs] == ["g1", "g3"] and ex["resend"] == 1


def test_sum_check_fails_on_double_count(monkeypatch):
    rows = period_events()
    t0, t1 = ag.kst_bounds(date(2026, 10, 1), date(2026, 10, 3))
    evs, _ = ag.prepare_events(rows, t0, t1)
    ag.attach_decisions(evs, {})
    monkeypatch.setitem(ag.CARD_FILTERS, "mask", lambda e: e["action"] in ("MASK", "ALLOW"))
    with pytest.raises(ag.ReportSumError) as e:
        ag.metrics(evs, date(2026, 10, 1), date(2026, 10, 3))
    assert "합계 불일치" in str(e.value)


def _conn(with_prev_start=True):
    E = period_events(with_prev_start)
    e9 = next(x for x in E if x["event_id"] == "e9")
    decs = [dec(e9["root"], e9["occurred_at"], doc="doc01", match_rate=0.91),
            dec(e9["root"], e9["occurred_at"], doc="doc01", match_rate=0.99, total_ms=9999.0, suffix="#verify"),  # 재검사 행
            dec("orphan-1", kst("2026-10-01 15:00:00"), ct_="file", filename="x.xlsx"),                  # 판정만 있음
            dec("st-1", kst("2026-10-01 15:00:00"), service="selftest")]                                  # 허용 목록 밖
    docs = [{"doc_id": "doc01", "format": "docx", "status": "active", "index_status": "indexed",
             "classification": None, "registered_at": kst("2026-09-01 00:00:00")}]
    admin = [{"occurred_at": kst("2026-10-01 09:00:00"), "admin_id": "admin", "action": "ADMIN_LOGIN", "target_type": "ADMIN", "result": "FAILURE"},
             {"occurred_at": kst("2026-10-01 09:01:00"), "admin_id": "admin", "action": "DOCUMENT_REGISTER", "target_type": "DOCUMENT", "result": "SUCCESS"},
             {"occurred_at": kst("2026-10-01 09:02:00"), "admin_id": "admin", "action": "REPORT_CREATE", "target_type": "REPORT", "result": "SUCCESS"}]
    gw = [{"version": 1, "settings": {"file": {"timeout": "block"}}, "updated_by": "admin", "updated_at": kst("2026-09-20 00:00:00")},
          {"version": 2, "settings": {"file": {"timeout": "pass"}}, "updated_by": "admin", "updated_at": kst("2026-10-02 10:00:00")}]
    return FakeConn(E, decs, docs, admin, gw)


def test_collect_end_to_end_with_previous_period():
    conn = _conn()
    a = ag.collect(conn, date(2026, 10, 1), date(2026, 10, 3))
    assert a["comparable"] and a["prev"]["cards"]["total"] == 2           # p0 · e1
    assert a["cur"]["cards"]["total"] == 16
    assert a["decisions"]["rows"] == 2                                   # #verify·selftest 제외
    assert a["decisions"]["decision_only_n"] == 1
    best = a["cur"]["docs"][0]["same_max"]                              # 같은 요청 번호의 판정 기록만(재검사 행 '#verify'는 안 셈)
    assert best["state"] == "READY" and best["input_chars"] == sum(not ch.isspace() for ch in doc_prompt("doc01", 0.91))
    assert st.format_summary(best) == "91.3%"                     # 문단 2개(20개 중)를 다른 글로
    assert len(a["admin"]["ops"]) == 2 and len(a["admin"]["changes"]) == 1 and a["admin"]["login_fail"] == 1
    assert a["gateway"]["changes"] == [{"at": kst("2026-10-02 10:00:00"), "key": "file.timeout", "before": "block",
                                        "after": "pass", "by": "admin", "version": 2}]
    # 가린 글은 안 읽음. 입력 원문은 '문서와 같은 글자' 계산(대시보드와 같은 행)에서만 읽고 결과에는 숫자만 남김
    # 원문 열은 '문서와 같은 글자' 조회만 읽음. 이벤트 조회는 질문 본문을 DB 안에서 md5로만 바꿔 받음(2026-10-16 질문 재시도)
    hashed = re.compile(r"case when e\.event->>'content_type' = 'prompt' then\s+\(select case when count\(\*\) = 1 and "
                        r"bool_and\(x\.prompt is not null\)\s+then md5\(btrim\(regexp_replace\(max\(x\.prompt\), '\\s\+', ' ', "
                        r"'g'\)\)\) end\s+from decisions x where x\.request_id = e\.request_id\) end as prompt_hash")
    assert len(hashed.findall(ag.EVENTS_SQL)) == 1
    assert all("masked_text" not in s and ("prompt" not in hashed.sub("", s).split("from")[0] or s == ag.SAME_DECISIONS_SQL)
               for s in conn.sql)
    issues = ag.evaluate_issues(a)
    assert [r["code"] for r in issues if not r["off"]] == ["R1", "R2", "R4", "R5", "R6", "R8"]


def test_collect_without_previous_records_is_not_comparable():
    a = ag.collect(_conn(with_prev_start=False), date(2026, 10, 1), date(2026, 10, 3))
    assert not a["comparable"] and a["prev"] is None and a["prev_events"] is None
