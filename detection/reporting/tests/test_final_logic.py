"""통계 공통 규칙(2026-10-16) + 사용자 이유 '…가 많음' 고침 - 대시보드와 같은 값이 되어야 하는 시험.

공통 규칙: docs/handoff/stats-rules-2026-10-16/SPEC.md (6절 시험 사례 번호를 각 시험 설명에 적음)
  - 시험 접두어에 legacy 추가(Gateway 서비스 가동 전 시험 호출을 되살린 옛 판정 기록)
  - 시연 문서(DEMO_)만 일치한 이벤트 제외 · 등록 문서 수에서 뺌
  - 질문 재시도 접기: 같은 사용자·서비스·조치·사유·질문 본문 해시, 4.348초 안, 기준 시각 없음
사용자 이유: 등급 근거 사실(U번호.BASIS) + 기간 전체 분모 + 프롬프트 v2 + 검사 22(비교 근거 없는 평가, 사용자 이유만)
"""

from __future__ import annotations

import dataclasses
from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import incidents as inc
from reporting import llm, verify
from reporting.compose import Composer

from synth import FakeConn, ev
from test_facts import _built

T0, T1 = ag.kst_bounds(date(2026, 10, 1), date(2026, 10, 20))
U = "chrome-aaaa-0001"


def _p(t, *, h="h1", client=U, llm_="ChatGPT", action="BLOCK", rc="pii", **kw):
    r = ev(t, client, llm_, action, "prompt", rc=rc, **kw)
    r["prompt_hash"] = h
    return r


def _ids(evs):
    return [e["id"] for e in evs]


# ---------------------------------------------------------------- 제외 (SPEC 1·2.1·2.2)

def test_legacy_prefix_is_test_client():
    """사례 1·2: legacy-gateway는 시험, 접두어 뒤가 '-'나 끝이 아니면 시험 아님."""
    rows = [_p("2026-10-05 10:00:00", client="legacy-gateway", h="a", eid="L1"),
            _p("2026-10-05 10:01:00", client="legacyX", h="b", eid="L2"),
            _p("2026-10-05 10:02:00", client="my-legacy", h="c", eid="L3")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert "legacy" in ag.TEST_CLIENT_PREFIXES
    assert _ids(evs) == ["L2", "L3"] and ex["test"] == 1 and ex["demo"] == 0


def test_demo_document_only_events_excluded():
    """사례 3·4: 문서 일치가 시연 문서뿐이면 제외. 다른 문서와 함께·검출 없음·패턴만이면 남김."""
    rows = [ev("2026-10-05 10:00:00", U, "Claude", "BLOCK", rc="doc_excerpt", docs=["DEMO_반도체_공정_시연"], eid="D1"),
            ev("2026-10-05 10:01:00", U, "Claude", "BLOCK", rc="doc_excerpt", docs=["DEMO_반도체_공정_시연", "01_전략_보고서"], eid="D2"),
            ev("2026-10-05 10:02:00", U, "Claude", "ALLOW", eid="D3"),
            ev("2026-10-05 10:03:00", U, "Claude", "BLOCK", rc="pii", ents={"KR_PHONE_NUMBER": 1}, eid="D4")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert _ids(evs) == ["D2", "D3", "D4"] and ex["demo"] == 1 and ex["test"] == 0
    assert ag.is_demo_doc("DEMO_x") and not ag.is_demo_doc("01_DEMO") and not ag.is_demo_doc(None)


def test_registered_documents_exclude_demo_document():
    """사례 13: 등록 문서 수(사실 F_DOCS_REG·보호 문서 표)에서 시연 문서를 뺀다."""
    docs = [{"doc_id": f"{n:02d}_문서", "format": "docx", "status": "active", "index_status": "indexed",
             "classification": None, "registered_at": None} for n in range(1, 21)]
    docs.append({"doc_id": "DEMO_반도체_공정_시연_20261003", "format": "docx", "status": "active",
                 "index_status": "indexed", "classification": None, "registered_at": None})
    conn = FakeConn([ev("2026-10-05 10:00:00", U, "ChatGPT", "ALLOW")], [], documents=docs)
    a = ag.collect(conn, date(2026, 10, 1), date(2026, 10, 13))
    assert len(a["documents"]) == 20 and not any(ag.is_demo_doc(d["doc_id"]) for d in a["documents"])


# ---------------------------------------------------------------- 질문 재시도 접기 (SPEC 2.3)

def test_prompt_retry_folds_at_gap_inclusive():
    """사례 5·6: 4.348초(같음 포함)면 접고 4.349초면 남김."""
    rows = [_p("2026-10-05 10:00:00", eid="A1"), _p("2026-10-05 10:00:04.348", eid="A2"),
            _p("2026-10-05 11:00:00", h="h2", eid="B1"), _p("2026-10-05 11:00:04.349", h="h2", eid="B2")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert _ids(evs) == ["A1", "B1", "B2"]
    assert (ex["resend"], ex["resend_prompt"], ex["resend_file"]) == (1, 1, 0)


def test_prompt_retry_chain_keeps_first_only():
    """사례 7: 접힌 행도 직전 시각이 된다 - 0·3·6초 연쇄는 첫 행만."""
    rows = [_p("2026-10-05 10:00:00", eid="C1"), _p("2026-10-05 10:00:03", eid="C2"), _p("2026-10-05 10:00:06", eid="C3")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert _ids(evs) == ["C1"] and ex["resend_prompt"] == 2


def test_prompt_retry_needs_same_key_and_hash():
    """사례 8·9: 조치·서비스·사용자·본문이 다르거나 해시가 없으면 접지 않음."""
    rows = [_p("2026-10-05 10:00:00", eid="K1"),
            _p("2026-10-05 10:00:01", action="ALLOW", rc=None, eid="K2"),
            _p("2026-10-05 10:00:02", llm_="Gemini", eid="K3"),
            _p("2026-10-05 10:00:03", client="chrome-bbbb-0002", eid="K4"),
            _p("2026-10-05 10:00:04", h="other", eid="K5"),
            _p("2026-10-05 12:00:00", h=None, rc=None, action="ALLOW", eid="N1"),
            _p("2026-10-05 12:00:01", h=None, rc=None, action="ALLOW", eid="N2")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert _ids(evs) == ["K1", "K2", "K3", "K4", "K5", "N1", "N2"] and ex["resend_prompt"] == 0


def test_access_prompts_without_hash_stay_access():
    """사례 9: 판정 기록이 없는 접속 차단 질문은 접지 않고 둘 다 접속 차단."""
    rows = [_p("2026-10-05 10:00:00", h=None, rc="client_id_missing", client=None, eid="X1"),
            _p("2026-10-05 10:00:01", h=None, rc="client_id_missing", client=None, eid="X2")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert evs == [] and ex["access"] == 2 and ex["resend"] == 0 and ex["resend_prompt"] == 0


def test_prompt_retry_has_no_cutoff_but_file_resend_keeps_it():
    """사례 10·11: 10/11 04:23 UTC 뒤에도 질문은 접고, 파일은 기존대로 안 접음."""
    rows = [_p("2026-10-12 10:00:00", eid="P1"), _p("2026-10-12 10:00:01", eid="P2"),
            ev("2026-10-12 11:00:00", U, "ChatGPT", "BLOCK", "file", rc="doc_excerpt", docs=["01_전략_보고서"], fid="f1", eid="F1"),
            ev("2026-10-12 11:00:01", U, "ChatGPT", "BLOCK", "file", rc="doc_excerpt", docs=["01_전략_보고서"], fid="f1", eid="F2")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert _ids(evs) == ["P1", "F1", "F2"] and (ex["resend_prompt"], ex["resend_file"]) == (1, 0)


def test_excluded_rows_do_not_seed_retry_tracking():
    """사례 12: 시연 문서로 빠진 행은 접기 추적에 참여하지 않음."""
    rows = [_p("2026-10-05 10:00:00", rc="doc_excerpt", docs=["DEMO_반도체"], eid="E1"),
            _p("2026-10-05 10:00:01", rc="doc_excerpt", eid="E2")]
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert _ids(evs) == ["E2"] and ex["demo"] == 1 and ex["resend_prompt"] == 0


def test_comparison_needs_first_non_test_record():
    """SPEC 2.5: 비교 가능 판정의 첫 기록은 시험 접두어(legacy 포함)를 뺀 첫 이벤트 - 옛 판정 기록만 있던 기간은 비교 불가."""
    rows = [ev("2026-09-15 18:02:00", "legacy-gateway", "ChatGPT", "BLOCK", eid="G0"),
            ev("2026-09-23 16:05:00", ag.UNKNOWN_CLIENT, "ChatGPT", "ALLOW", eid="G1"),
            ev("2026-10-05 10:00:00", U, "ChatGPT", "ALLOW", eid="G2")]
    a = ag.collect(FakeConn(rows, []), date(2026, 10, 1), date(2026, 10, 13))      # 비교 기간 9/19~9/30
    assert a["first_event"] == ev("2026-09-23 16:05:00", U, "ChatGPT", "ALLOW")["occurred_at"]
    assert a["comparable"] is False and a["prev"] is None
    b = ag.collect(FakeConn(rows, []), date(2026, 10, 1), date(2026, 10, 7))       # 비교 기간 9/24~9/30
    assert b["comparable"] is True


def test_period_first_row_is_not_folded():
    """사례 14: 기간 밖 직전 행과 1초 간격이어도 기간 첫 행은 남음."""
    t0, t1 = ag.kst_bounds(date(2026, 10, 5), date(2026, 10, 6))
    rows = [_p("2026-10-04 23:59:59.500", eid="O1"), _p("2026-10-05 00:00:00.500", eid="O2")]
    evs, ex = ag.prepare_events(rows, t0, t1)
    assert _ids(evs) == ["O2"] and ex["resend_prompt"] == 0


def test_events_sql_hashes_prompt_body_in_db_only():
    """본문 해시는 SQL(md5·공백 정리)에서만 - 원문은 DB 밖으로 안 나옴. 판정 기록이 정확히 1행일 때만."""
    s = ag.EVENTS_SQL
    assert "md5(btrim(regexp_replace(max(x.prompt), '\\s+', ' ', 'g')))" in s
    assert "count(*) = 1 and bool_and(x.prompt is not null)" in s and "as prompt_hash" in s
    assert "x.request_id = e.request_id" in s and "e.event->>'content_type' = 'prompt'" in s


def test_collect_folds_prompt_retry_end_to_end():
    """가짜 DB에서 질문 재시도가 이번 기간 수·제외 기록에 반영된다."""
    rows = [_p("2026-10-05 10:00:00", eid="R1"), _p("2026-10-05 10:00:02", eid="R2"),
            ev("2026-10-05 10:05:00", "legacy-gateway", "ChatGPT", "ALLOW", eid="R3")]
    a = ag.collect(FakeConn(rows, []), date(2026, 10, 1), date(2026, 10, 13))
    assert _ids(a["events"]) == ["R1"]
    assert a["excluded"]["resend_prompt"] == 1 and a["excluded"]["test"] == 1 and a["cur"]["cards"]["total"] == 1


# ---------------------------------------------------------------- 사용자 이유 (설계 v3 측정 10.2)

def _user(**kw):
    u = {"secret": 0, "docs": 0, "cred": 0, "retry": 0, "block": 0}
    u.update(kw)
    return u


@pytest.mark.parametrize("u,level,head", [
    (_user(secret=2, retry=1, block=2), "높음", "높음 근거: 기밀 차단과 차단 뒤 재시도"),
    (_user(secret=2, docs=2, block=2), "높음", "높음 근거: 서로 다른 기밀 문서"),
    (_user(cred=1, retry=1, block=1), "높음", "높음 근거: 인증정보 포함과 차단 뒤 재시도"),
    (_user(secret=1, block=1), "중간", "중간 근거: 기밀 차단은 있으나"),
    (_user(cred=1), "중간", "중간 근거: 인증정보 포함은 있으나"),
    (_user(block=3), "중간", "중간 근거: 기밀·인증정보가 아닌 차단만"),
    (_user(), "낮음", "낮음 근거: 차단·기밀·인증정보 없음"),
])
def test_basis_rule_matches_rule_level(u, level, head):
    assert inc.rule_level(u) == level
    b = inc.basis_rule(u)
    assert b.startswith(head) and not any(ch.isdigit() for ch in b)


def test_user_facts_have_basis_and_period_denominators():
    a, incs, users, fx = _built()
    for u in users:
        b = fx.get(f"{u['id']}.BASIS")
        assert b["type"] == "basis" and b["level"] == u["rule_level"] and b["label"].startswith(u["rule_level"])
        assert fx.render("{%s.BASIS}" % u["id"]) == b["label"]
    u1 = users[0]["id"]
    assert fx.get(f"{u1}.EVENTS")["denom"] == "F_TOTAL"
    for code, den in (("BLOCK", "F_BLOCK"), ("MASK", "F_MASK"), ("SECRET", "F_SECRET")):
        for u in users:
            if f"{u['id']}.{code}" in fx:
                f = fx.get(f"{u['id']}.{code}")
                assert f["denom"] == den and f["ratio_label"] is True
                g = fx.get(den)
                want = f"{g['label']} {fx.value_text(g)} 중 {fx.value_text(f)}({f['value'] / g['value'] * 100:.1f}%)"
                assert fx.render("{%s.%s|비율}" % (u["id"], code)) == want      # '차단 전체 43건 중 26건(60.5%)'
    # 다른 사실의 비율 꼴은 전과 같음(분모 이름표 없음)
    s = fx.get("F_SECRET")
    assert fx.render("{F_SECRET|비율}") == f"{s['value'] / fx.get('F_TOTAL')['value'] * 100:.1f}%({s['value']:,}/{fx.get('F_TOTAL')['value']:,})"
    # 정의가 다른 건수(인증정보·재시도 등)에는 분모를 붙이지 않음
    assert all(fx.get(i).get("denom") is None for i in fx.ids(lambda f: f["id"].endswith((".CRED", ".RETRY", ".DAYS"))))


def test_users_prompt_v2_asks_for_basis_and_ratio():
    system, version = llm.system_prompt("users")
    assert version.startswith("report_users.v2")
    assert "{U번호.BASIS}" in system and "{U번호.SECRET|비율}" in system and "비교 근거 없이" in system


def _composer_with(users_out):
    a, incs, users, fx = _built()
    issues = ag.evaluate_issues(a)
    seen = {}

    def call(task, payload, schema, **kw):
        if task != "users":
            raise RuntimeError("only users")
        seen["payload"], seen["schema"] = payload, schema
        return {"out": users_out(users), "ms": 1, "usage": {}, "prompt": "report_users.v2"}

    comp = Composer(a, fx, incs, users, issues, call=call)
    doc = comp.run(content_on=False)
    return doc, seen, users, fx


def test_users_call_gets_period_and_drops_unsupported_evaluation():
    def out(users):
        u = users[0]["id"]
        return {"users": [{"id": u, "level": users[0]["rule_level"], "why": [
            {"t": "{%s.BASIS} - {%s.SECRET}" % (u, u), "c": [f"{u}.BASIS", f"{u}.SECRET"]},       # 근거 + 건수: 남음
            {"t": "{%s.BLOCK}이 많음" % u, "c": [f"{u}.BLOCK"]},                                     # 비교 근거 없는 평가: 22
            {"t": "기간 차단 중 {%s.BLOCK|비율}로 많음" % u, "c": [f"{u}.BLOCK"]},                       # 분모 비율: 남음
        ]}]}
    doc, seen, users, fx = _composer_with(out)
    u = users[0]["id"]
    assert [p["id"] for p in seen["payload"]["period"]] == ["F_TOTAL", "F_BLOCK", "F_MASK", "F_SECRET"]
    facts0 = {f["id"] for f in seen["payload"]["users"][0]["facts"]}
    assert f"{u}.BASIS" in facts0
    kept = [ln["text"] for ln in doc["user_text"][u]["lines"]]
    assert len(kept) == 2 and kept[0].startswith(fx.get(f"{u}.BASIS")["label"])
    why = [d["why"] for d in doc["dropped"] if d["section"] == "S6"]
    assert any(w.startswith("22 비교 근거 없는 평가") for w in why)


def test_users_reason_must_cite_own_fact_not_only_period():
    def out(users):
        u = users[0]["id"]
        return {"users": [{"id": u, "level": users[0]["rule_level"], "why": [
            {"t": "{F_BLOCK} 기록", "c": ["F_BLOCK"]},
            {"t": "{%s.BASIS}" % u, "c": [f"{u}.BASIS"]}]}]}
    doc, seen, users, fx = _composer_with(out)
    u = users[0]["id"]
    assert [ln["text"] for ln in doc["user_text"][u]["lines"]] == [fx.get(f"{u}.BASIS")["label"]]
    assert any(d["why"] == "12 섹션 범위" for d in doc["dropped"] if d["section"] == "S6")


@pytest.mark.parametrize("t,cites,bad", [
    ("{U2.SECRET|값}", ["U2.SECRET"], True),                 # '2건'만 - 무엇의 건수인지 없음
    ("{U2.SECRET|값}, {U2.EVENTS|값}", ["U2.SECRET"], True),
    ("{U2.SECRET}", ["U2.SECRET"], False),                   # 이름표가 렌더됨('기밀 차단 2건')
    ("{U2.SECRET|값} 기밀 차단", ["U2.SECRET"], False),       # 글로 이름을 붙임
])
def test_check_23_value_without_label(t, cites, bad):
    from test_verify import ctx
    assert "eval_check" in {f.name for f in dataclasses.fields(verify.Ctx)}
    c = ctx()
    c.eval_check = True
    why, _ = verify.check_line({"t": t, "c": cites}, c)
    assert (why or "") .startswith("23") is bad, why
    c.eval_check = False
    assert not (verify.check_line({"t": t, "c": cites}, c)[0] or "").startswith("23")


def test_label_echo_before_user_ratio_is_dropped():
    """'기밀 차단 {U1.SECRET|비율}' → 분모 이름표가 겹치면 앞 글을 지움(뜻 그대로, 21번에 안 걸림)."""
    a, incs, users, fx = _built()
    u = users[0]["id"]
    assert verify.drop_label_echo("기간 기밀 차단 {%s.SECRET|비율}" % u, fx) == "기간 {%s.SECRET|비율}" % u
    assert verify.drop_label_echo("기밀 차단 {F_SECRET|비율}", fx) == "기밀 차단 {F_SECRET|비율}"   # 다른 사실은 그대로


@pytest.mark.parametrize("t,cites,bad", [
    ("{U2.SECRET}가 많음", ["U2.SECRET"], True),
    ("{U2.SECRET} 요청이 잦음", ["U2.SECRET"], True),
    ("{U2.EVENTS} 요청이 빈번함", ["U2.EVENTS"], True),
    ("{U2.SECRET|비율}로 많음", ["U2.SECRET"], False),
    ("{F_SECRET|변화}로 많아짐", ["F_SECRET"], False),
    ("{K3} 몫이 많음", ["K3"], False),                     # 몫(share) 사실 = 비교 근거
    ("{U2.SECRET} · 등급 높음", ["U2.SECRET"], False),       # 등급 이름은 평가 낱말로 안 봄
    ("{U2.SECRET} 적용 확인", ["U2.SECRET"], False),         # '적용'은 '적다'가 아님
])
def test_check_22_only_with_comparison_basis(t, cites, bad):
    from test_verify import ctx
    assert "eval_check" in {f.name for f in dataclasses.fields(verify.Ctx)}   # 기본 꺼짐 칸(사용자 이유에서만 켬)
    c = ctx()
    c.facts.get("U2.SECRET")["denom"] = "F_SECRET"
    c.eval_check = True
    why, _ = verify.check_line({"t": t, "c": cites}, c)
    assert (why or "").startswith("22") is bad, why
    c.eval_check = False                                     # 다른 섹션은 그대로(검사 22 끔)
    why2, _ = verify.check_line({"t": t, "c": cites}, c)
    assert not (why2 or "").startswith("22")
