"""보고서 '일치율' → '문서와 같은 글자'(대시보드와 같은 값, 2026-10-16).

기대값은 대시보드 서버 원본(match-ratio.mjs · match-evidence.mjs)을 node로 돌린 값을 그대로 적었다(키트 check/js_ref.mjs).
same_text는 각 시험 안에서 불러온다 - 수정 전 코드에서는 시험마다 실패한다(모듈 없음).
"""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import date

from reporting import aggregate as ag

from synth import FakeConn, dec, doc_text, ev, kst

DOC = "\n".join(f"제{i}조 본 계약의 당사자는 비밀 정보를 제3자에게 공개하지 아니한다. 위반 시 손해를 배상한다." for i in range(1, 9))
# (이름, 입력, 대시보드 값: 같은 글자, 입력 글자, 다른 곳 수)
JS_VECTORS = [
    ("same", DOC, 328, 328, 0),
    ("spaces", DOC.replace(" ", "  ").replace("\n", "\n\t　"), 328, 328, 0),          # 공백 차이는 안 셈
    ("edit", DOC.replace("제3조 본 계약의", "제3조 이 약정의").replace("배상한다.\n제7조", "배상하여야 한다.\n제7조"), 325, 331, 2),
    ("email", DOC + "\n담당: kim.lee@example.com 010-1234-5678", 333, 333, 0),               # 가린 덩어리 하나 = 한 글자
    ("unrelated", "다음 주 화요일 오후 세 시에 본관 회의실에서 분기 회의가 열립니다. 참석자는 발표 자료를 미리 준비해 주세요.", 1, 46, 1),
    ("shuffled", "\n".join(reversed(DOC.split("\n"))), 320, 328, 8),
]


def _st():
    return importlib.import_module("reporting.same_text")


def _loc(text):
    return {"char_start": 0, "char_end": len(text)}


def _ratio(inp, doc, score=0.9, passages=None):
    st = _st()
    comp = {"coverage": score,
            "matching_passages": st.find_matching_passages(inp, doc, _loc(inp), _loc(doc)) if passages is None else passages}
    return st.compute_match_ratio(st.masked_body(inp), st.masked_body(doc), comp)


def test_values_equal_dashboard_original():
    """대시보드 원본(node)과 같은 글자 수·입력 글자 수·다른 곳 수."""
    for name, inp, same, total, diffs in JS_VECTORS:
        doc = DOC + "\n담당: park@corp.co.kr 010-9999-0000" if name == "email" else DOC
        assert _ratio(inp, doc) == {"state": "READY", "same_chars": same, "input_chars": total, "differences": diffs}, name


def test_format_matches_dashboard_display():
    st = _st()
    assert st.format_same_ratio(1) == "100.0%"
    assert st.format_same_ratio(0.99999) == "99.9%"          # 다른 글자가 있으면 100%로 올리지 않음
    assert st.format_same_ratio(0.9994) == "99.9%"           # 내림
    assert st.format_same_ratio(15326 / 16368) == "93.6%"
    assert st.format_same_ratio(0) == "0.0%"
    assert st.format_summary({"state": "UNAVAILABLE", "reason": "x"}) == "대조 불가"
    assert st.format_summary(None) == "대조 불가"


def test_unavailable_conditions_like_dashboard():
    st = _st()
    # 서버 점수는 있는데 같은 글자가 하나도 없음
    assert _ratio("ABCDEFG", "가나다라마바사")["reason"] == "서버 일치 비율과 대조 결과가 맞지 않아"
    assert _ratio("ABCDEFG", "가나다라마바사", score=0)["state"] == "READY"
    # 검사 서버가 같은 글로 확인한 문장 위치가 대조 결과의 다른 구간 안
    inp = DOC.replace("제3조 본 계약의 당사자는", "제3조 그 밖의 사람들이")
    (changed,) = st.diff_ignoring_whitespace(inp, DOC)["a"]                 # 입력에서 다르게 나온 구간
    bad = [{"input_location": {"char_start": changed[0], "char_end": changed[1]}, "document_location": {"char_start": 0, "char_end": 0}}]
    assert _ratio(inp, DOC, passages=bad)["reason"] == "서버가 같은 글로 확인한 문장과 대조 결과가 맞지 않아"
    # 계산 한도
    comp = {"coverage": 0.5, "matching_passages": []}
    long_a, long_b = " ".join(f"a{i}" for i in range(4000)), " ".join(f"b{i}" for i in range(4000))
    r = st.compute_match_ratio(st.masked_body(long_a), st.masked_body(long_b), comp, budget_s=0)
    assert r == {"state": "UNAVAILABLE", "reason": "본문이 길어 계산 한도를 넘어"}


def _event(doc_id="doc01", n_in=10, n_doc=20, rid="req-1", outcome="MATCH", score=0.5):
    return {"request_id": rid, "detection_outcome": outcome,
            "detections": [{"detector": "WINDOW_HASH", "matched_document_id": doc_id, "score": score,
                            "input_location": {"char_start": 0, "char_end": n_in},
                            "matched_location": {"char_start": 0, "char_end": n_doc}}]}


def _decision(prompt, doc_text_, doc_id="doc01", rid="req-1", **kw):
    return {"request_id": rid, "decided_by": "windowhash", "doc_id": doc_id, "input_span": f"0-{len(prompt)}",
            "doc_span": f"0-{len(doc_text_)}", "prompt_kept": True, "document_ref": None, "prompt_chars": len(prompt),
            "prompt": prompt, **kw}


def test_comparison_body_selection_like_dashboard():
    """대조할 본문이 없거나 기록이 맞지 않으면 '대조할 본문 없음'(해시 점수로 대신하지 않음)."""
    st = _st()
    cur_doc = {"doc_id": "doc01", "version": 2, "normalized_chars": len(DOC), "normalized_text": DOC}
    ok = st.event_same_text(_event(n_in=len(DOC), n_doc=len(DOC)), [_decision(DOC, DOC)], [cur_doc])
    assert ok == {"doc01": {"state": "READY", "same_chars": 328, "input_chars": 328, "differences": 0}}
    none = {"doc01": {"state": "UNAVAILABLE", "reason": "대조할 본문 없음"}}
    e = _event(n_in=len(DOC), n_doc=len(DOC))
    assert st.event_same_text(e, [], [cur_doc]) == none                                          # 판정 기록 없음
    assert st.event_same_text(e, [_decision(DOC, DOC)] * 2, [cur_doc]) == none                   # 2건 = 어느 것인지 모름
    assert st.event_same_text(e, [_decision(DOC, DOC, input_span="0-5")], [cur_doc]) == none     # 위치가 기록과 다름(9월 옛 기록)
    assert st.event_same_text(e, [_decision(DOC, DOC, prompt_kept=False)], [cur_doc]) == none    # 원문 보관 안 함
    assert st.event_same_text(_event(n_in=len(DOC), n_doc=len(DOC), outcome="UNAVAILABLE"), [_decision(DOC, DOC)], [cur_doc]) == none
    assert st.event_same_text(e, [_decision(DOC, DOC)], []) == none                              # 문서 본문 없음
    assert st.event_same_text({"request_id": "r", "detections": [{"detector": "SIGNATURE"}]}, [], []) == {}


def test_archived_version_is_used_when_recorded():
    """판정 기록에 문서 판이 있으면 그 판의 보존본(해시 확인)으로 대조 - 지금 문서가 바뀌어도 값이 같음."""
    st = _st()
    old = DOC
    new = DOC.replace("배상한다", "물어 준다")
    sha = hashlib.sha256(old.encode("utf-8")).hexdigest()
    ref = {"basis": "STABLE_INDEX_VERSION", "doc_id": "doc01", "version": 1, "normalized_sha256": sha}
    e = _event(n_in=len(old), n_doc=len(old))
    d = _decision(old, old, document_ref=ref)
    assert st.archived_ref(e, [d]) == ("doc01", 1, sha)
    docs = [{"doc_id": "doc01", "version": 2, "normalized_text": new, "normalized_chars": len(new)},
            {"doc_id": "doc01", "version": 1, "normalized_sha256": sha, "normalized_text": old, "normalized_chars": len(old),
             "evidence_source": "EVENT_DOCUMENT_VERSION"}]
    assert st.event_same_text(e, [d], docs)["doc01"]["same_chars"] == 328
    # 보존본 해시가 맞지 않으면 지금 문서로 대신하지 않음
    docs[1]["normalized_text"] = new
    assert st.event_same_text(e, [d], docs)["doc01"] == {"state": "UNAVAILABLE", "reason": "대조할 본문 없음"}


def _collect(decs, events, documents=()):
    conn = FakeConn(events, decs, list(documents))
    return ag.collect(conn, date(2026, 10, 1), date(2026, 10, 3)), conn


def test_report_uses_same_text_not_hash_score():
    """해시 점수 100%(match_rate 1.0)라도 입력의 절반이 다른 글이면 보고서 값은 같은 글자 비율."""
    st = _st()
    e1 = ev("2026-10-01 10:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["doc01"], eid="m1")
    a, _ = _collect([dec(e1["root"], e1["occurred_at"], doc="doc01", match_rate=1.0, prompt=_half())], [e1])
    d = a["cur"]["docs"][0]
    assert d["same_max"]["state"] == "READY" and st.format_summary(d["same_max"]) == "54.0%"
    assert a["events"][0]["same"]["doc01"] == d["same_max"]


def test_docs_table_column_and_unavailable_cell():
    from reporting import render as rd
    st = _st()
    e1 = ev("2026-10-01 10:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["doc01"], eid="m1")
    e2 = ev("2026-10-01 11:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["doc01"], eid="m2")
    e3 = ev("2026-10-01 12:00:00", "chrome-bbbb-0002", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["doc02"], eid="m3")
    a, _ = _collect([dec(e1["root"], e1["occurred_at"], doc="doc01", match_rate=0.9)], [e1, e2, e3])   # m2·m3은 판정 기록 없음
    docs = {d["doc"]: d for d in a["cur"]["docs"]}
    assert docs["doc01"]["same_na"] == 1 and st.summary_ratio(docs["doc01"]["same_max"]) is not None
    assert rd._same_cell(docs["doc01"]) == st.format_summary(docs["doc01"]["same_max"]) + " · 대조 불가 1건"
    assert rd._same_cell(docs["doc02"]) == "대조 불가"


def test_rate_down_uses_same_text():
    from reporting.incidents import group
    t0, t1 = ag.kst_bounds(date(2026, 10, 1), date(2026, 10, 3))
    raw = [ev("2026-10-01 10:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["doc01"], eid=f"r{i}")
           for i in range(1, 5)]
    for i, r in enumerate(raw):
        r["occurred_at"] = r["occurred_at"].replace(minute=i)
    # 해시 점수는 내려가지만(1.0 → 0.5) 같은 글자는 올라감 → '낮아짐' 아님 / 다음은 같은 글자 내려감 → '낮아짐' / 마지막은 대조 불가 → 비교 안 함
    decs = [dec(raw[0]["root"], raw[0]["occurred_at"], doc="doc01", match_rate=1.0, prompt=_half()),
            dec(raw[1]["root"], raw[1]["occurred_at"], doc="doc01", match_rate=0.5, prompt=doc_text("doc01")),
            dec(raw[2]["root"], raw[2]["occurred_at"], doc="doc01", match_rate=1.0, prompt=_half())]
    ev_, _ = ag.prepare_events(raw, t0, t1)
    ag.attach_decisions(ev_, {})
    ag.attach_same_text(ev_, ag.fetch_same_text(FakeConn(raw, decs), ag.same_targets(ev_)))
    (inc,) = group(ev_)
    assert [m.role for m in inc.members] == ["FIRST", "REPEAT", "RATE_DOWN", "REPEAT"]


def _half():
    """문서 앞 문단 10개 그대로 + 뒤 10개는 전혀 다른 글."""
    lines = doc_text("doc01").split(chr(10))
    return chr(10).join(lines[:10] + [f"회의 메모 {i}: 다음 주 화요일 오후 본관 회의실 일정 안내와 준비물 목록" for i in range(10)])


def test_facts_and_rendered_report_carry_same_text_only(tmp_path, monkeypatch):
    """LLM 사실·HTML에 '일치율'(해시 점수) 없음, '문서와 같은 글자' 값과 정의가 있음, 입력 원문은 결과에 안 남음."""
    from reporting import facts as fa
    from reporting import frame as fr
    from reporting import render as rd
    st = _st()
    marker = "고유표지문장열두글자확인용"
    e1 = ev("2026-10-01 10:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["doc01"], eid="m1")
    a, _ = _collect([dec(e1["root"], e1["occurred_at"], doc="doc01", match_rate=1.0, prompt=doc_text("doc01") + "\n" + marker)], [e1])
    from reporting.incidents import group, user_facts
    incs = group(a["events"])
    fx = fa.build(a, incs, user_facts(a["events"], incs), issues=ag.evaluate_issues(a))
    d1 = fx.get("D1")
    assert "match_rate_max" not in d1 and d1["same_text_max"] == st.format_summary(a["cur"]["docs"][0]["same_max"]) == "98.1%"
    view = json.dumps(fx.llm_view(fx.ids()), ensure_ascii=False)
    assert marker not in view and "일치율" not in view
    names = [t for t, _ in fr.definitions()]
    assert "문서와 같은 글자" in names
    assert "일치율" not in json.dumps(fr.definitions(), ensure_ascii=False)
    assert all("일치율" not in v for v in __import__("reporting.incidents", fromlist=["ROLE_LABELS"]).ROLE_LABELS.values())
    assert marker not in json.dumps(a["cur"]["docs"], ensure_ascii=False, default=str)
    assert "prompt" not in json.dumps(a["events"][0].get("same"), ensure_ascii=False)
    assert hasattr(rd, "_same_cell")
