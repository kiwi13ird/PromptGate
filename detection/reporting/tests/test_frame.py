"""보고서 틀(설계 v3 A1~A5) 단위 시험 - 상태 기준 경계, 깔때기 산술·불변식, 표본 적음, 이전 대비 줄, 첫 문장 고정 틀,
관측 범위 '확인 불가'·'비교 불가', 차단 뒤 재요청 묶음, 같은 패턴 묶음, 변경 표시선, 깔때기·표시선 SVG, 고정 문구 금지어.

기대값은 아래 이벤트 목록을 보고 손으로 셌다(주석의 번호). 값은 전부 가짜.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import charts as ch
from reporting import facts as fm
from reporting import frame as fr
from reporting import wording
from reporting.facts import Facts
from reporting.incidents import group, user_facts

from render_markers import OLD_STRINGS
from synth import FakeConn, ev
from test_aggregate import _conn as agg_conn
from test_aggregate import period_events
from test_charts import NS, assert_inside, texts
from test_facts import _built
from test_incidents import _events as fixture_events

X = ag.UNKNOWN_CLIENT


# ---------------------------------------------------------------- 표본 적음·1,000건당

@pytest.mark.parametrize("n,pn,small", [(29, 100, True), (30, 30, False), (30, 29, True), (100, 29, True),
                                        (30, None, False), (29, None, True), (0, None, True)])
def test_small_base_edges(n, pn, small):
    assert fr.small_base(n, pn) is small


def test_per1000_only_from_min_base():
    assert fr.per1000(3, 29) is None and fr.rate_text(3, 29) is None and fr.share_text(3, 29) is None
    assert fr.per1000(3, 30) == 100.0 and fr.rate_text(3, 30) == "1,000건당 100.0"
    assert fr.rate_text(11, 244) == "1,000건당 45.1" and fr.share_text(9, 30) == "30.0%"
    assert fr.per1000(0, 0) is None


def test_delta_chip_small_base_drops_percent_only():
    small = ch.delta_chip(55, 1, small=True)              # 운영 생성본의 '+5,400%'(마스킹 1→55)
    assert '<span aria-hidden="true">▲ 54</span>' in small and "%" not in small
    assert "이전 대비 54 늘어남 (비율 생략)" in small
    assert "(+5,400%)" in ch.delta_chip(55, 1)              # 기본값은 그대로(다른 호출 영향 없음)
    assert '<span aria-hidden="true">▼ 19</span>' in ch.delta_chip(2, 21, small=True)
    assert "― 같음" in ch.delta_chip(5, 5, small=True) and "비교 불가" in ch.delta_chip(5, None, comparable=False, small=True)


# ---------------------------------------------------------------- 깔때기

def _bounds():
    return ag.kst_bounds(date(2026, 10, 1), date(2026, 10, 3))


def funnel_events():
    rows = [
        ev("2026-10-01 09:00:00", "chrome-f1", "ChatGPT", "BLOCK", docs=["d1"], eid="f1"),                  # 1 기밀 문서 차단
        ev("2026-10-01 09:10:00", "chrome-f1", "ChatGPT", "BLOCK", ents={"DOC_KEYWORD": 1}, eid="f2"),      # 2 키워드 차단
        ev("2026-10-01 09:20:00", "chrome-f2", "Claude", "MASK", ents={"KR_PHONE_NUMBER": 1}, eid="f3"),    # 3 개인정보 마스킹
        ev("2026-10-01 09:30:00", "chrome-f2", "Claude", "BLOCK", "file", rc="mask_application_failed",
           ents={"KR_RRN": 1}, eid="f4"),                                                                # 4 마스킹 실패 차단
        ev("2026-10-01 09:40:00", "chrome-f3", "Gemini", "BLOCK", "file", rc="file_uninspectable_other", eid="f5"),  # 5 검사 불가 차단
        ev("2026-10-01 09:50:00", "chrome-f3", "Gemini", "ALLOW", "file", rc="file_uninspectable_image", eid="f6"),  # 6 검사 불가 통과
        ev("2026-10-01 10:00:00", X, "ChatGPT", "ALLOW", rc="detection_unreachable", deg=True, eid="f7"),    # 7 응답 없이 통과
        ev("2026-10-01 10:10:00", X, "ChatGPT", "BLOCK", rc="detection_timeout", deg=True, eid="f8"),        # 8 시간 초과 차단
        ev("2026-10-01 10:20:00", "chrome-f4", "ChatGPT", "ALLOW", eid="f9"),                              # 9 문제 없음
        ev("2026-10-01 10:30:00", "chrome-f4", "ChatGPT", "ALLOW", eid="f10"),                             # 10 문제 없음
        ev("2026-10-01 10:40:00", "chrome-f5", "ChatGPT", "ALLOW", docs=["d2"], eid="f11"),                # 11 탐지 후 허용
        ev("2026-10-01 10:50:00", "chrome-f5", "ChatGPT", "WARN", eid="f12"),                              # 12 그 밖 조치
    ]
    evs, _ = ag.prepare_events(rows, *_bounds())
    ag.attach_decisions(evs, {})
    return evs


def test_funnel_counts_hand_counted():
    fc = fr.funnel_counts(funnel_events())
    assert fc == {"total": 12, "block": 5, "mask": 1, "allow": 5, "other_action": 1,
                  "attention": 9, "detected": 5, "unseen": 4, "intervened": 6, "unchecked": 2, "det_allow": 1,
                  "exposed": 3, "clean": 2, "rest": 1, "nocheck_pass": 1, "timeout": 1}


def _assert_invariants(evs):
    fc = fr.funnel_counts(evs)
    assert fc["total"] == fc["block"] + fc["mask"] + fc["allow"] + fc["other_action"]        # 검사 = 차단 + 마스킹 + 허용(+그 밖)
    assert fc["attention"] == fc["intervened"] + fc["exposed"] == fc["detected"] + fc["unseen"]
    assert fc["total"] == fc["intervened"] + fc["exposed"] + fc["clean"] + fc["rest"]
    assert fc["intervened"] == fc["block"] + fc["mask"] and fc["exposed"] == fc["unchecked"] + fc["det_allow"]
    assert fc["total"] >= fc["attention"] >= fc["intervened"] and fc["attention"] >= fc["exposed"]
    assert fc["unchecked"] == sum(1 for e in evs if ag.CARD_FILTERS["unchecked"](e))         # 카드 '검사 없이 통과'와 같은 수
    # 카드 '문제 없음 허용'(allow_clean)은 정책상 허용된 개인정보도 담는다 - 깔때기는 그것을 '탐지 후 허용'으로 떼어 낸다
    assert fc["clean"] == sum(1 for e in evs if ag.CARD_FILTERS["allow_clean"](e) and not fr.detected_allow(e))
    return fc


def test_funnel_invariants_hold_on_every_fixture():
    _assert_invariants(funnel_events())
    _assert_invariants(fixture_events())
    t0, t1 = _bounds()
    evs, _ = ag.prepare_events(period_events(), t0, t1)
    ag.attach_decisions(evs, {})
    fc = _assert_invariants(evs)
    assert fc["total"] == 16 and fc["rest"] == 0 and fc["exposed"] == 2          # test_aggregate 손 계산과 같음
    _assert_invariants([])


def test_funnel_facts_have_prev_and_no_section_tags():
    a, incs, users, fx = _built()
    for fid, _, key in fr.FRAME_FACTS:
        f = fx.get(fid)
        assert f["secs"] == [] and f["prev"] is not None, fid                    # 섹션 태그 없음 → LLM 입력에 안 감
        assert f["value"] == fr.funnel_counts(a["events"])[key]
    assert fx.get("F_BYPASS")["value"] == 3 and fx.get("F_BYPASS")["prev"] == 0
    assert fx.get("F_EXPOSED")["value"] == fx.get("F_UNCHECKED")["value"] + fx.get("F_DET_ALLOW")["value"]


def test_funnel_line_fixed_template():
    assert fr.funnel_line(fr.funnel_counts(funnel_events())) == (
        "검사 12건 중 탐지·검사 못 함 9건 → 차단·마스킹 6건, 노출 3건 · 나머지 2건은 탐지 없이 허용 · 그 밖 조치 1건")
    fc = dict(fr.funnel_counts(funnel_events()), total=300, exposed=3, clean=0, rest=0)
    assert fr.funnel_line(fc).endswith("노출 3건(1,000건당 10.0)")


# ---------------------------------------------------------------- A1 상태

def flags_fx(n, exposed=0, bypass=0, unseen=0) -> Facts:
    fx = Facts()
    fx.add("F_TOTAL", "count", "검사", value=n, prev=None, unit="건")
    fx.add("F_EXPOSED", "count", "노출", value=exposed, prev=None, unit="건")
    fx.add("F_BYPASS", "count", "차단 뒤 통과 사건", value=bypass, prev=None, unit="건")
    fx.add("F_UNSEEN", "count", "검사 못 함", value=unseen, prev=None, unit="건")
    return fx


@pytest.mark.parametrize("kw,label", [
    ({}, "양호"),
    ({"exposed": 9, "unseen": 19}, "양호"),             # 1,000건당 9·19 → 기준 아래
    ({"exposed": 10}, "주의"), ({"exposed": 49}, "주의"), ({"exposed": 50}, "위험"),
    ({"bypass": 1}, "주의"), ({"bypass": 2}, "주의"), ({"bypass": 3}, "위험"),
    ({"unseen": 20}, "주의"), ({"unseen": 99}, "주의"), ({"unseen": 100}, "위험"),
    ({"exposed": 10, "bypass": 3}, "위험"),            # 가장 높은 단계
    ({"exposed": 10, "unseen": 20, "bypass": 1}, "주의"),
])
def test_status_thresholds_at_edges(kw, label):
    st = fr.status(flags_fx(1000, **kw))
    assert st["label"] == label and not st["small"]


def test_status_rate_boundary_is_exact_integer_math():
    assert fr.status(flags_fx(300, exposed=3))["label"] == "주의"      # 정확히 1,000건당 10.0
    assert fr.status(flags_fx(300, exposed=2))["label"] == "양호"      # 6.7
    assert fr.status(flags_fx(301, exposed=3))["label"] == "양호"      # 9.97 - 반올림하지 않음
    st = fr.status(flags_fx(29, exposed=2, bypass=3, unseen=3))
    assert st["label"] == "위험" and st["small"]                       # 건수 기준(차단 뒤 통과)은 표본이 적어도 단계를 매김
    assert [f["level"] for f in st["flags"]] == [None, 2, None]        # 비율 항목은 검사 30건 미만이면 단계 없음(건수만)
    assert fr.flag_value_text(st["flags"][0]) == "2건 · 표본 적음(비율 생략)" and fr.flag_value_text(st["flags"][1]) == "3건"
    assert fr.status(flags_fx(29, exposed=2))["label"] == "표본 적음"      # 단계를 매길 항목이 없으면 '양호'라 하지 않는다


def test_status_with_no_inspection_is_unavailable():
    st = fr.status(flags_fx(0, bypass=0))
    assert st["label"] == fr.NA and st["level"] is None
    assert [fr.flag_value_text(f) for f in st["flags"]] == [fr.NA, "0건", fr.NA]


# ---------------------------------------------------------------- A1 첫 문장·이전 대비

def lead_fx(n=244, block=31, mask=55, unchk=11, det_allow=0) -> Facts:
    fx = Facts()
    for fid, label, v in (("F_TOTAL", "검사", n), ("F_BLOCK", "차단 전체", block), ("F_MASK", "개인정보 마스킹", mask),
                          ("F_UNCHECKED", "검사 없이 통과", unchk), ("F_DET_ALLOW", "탐지 후 허용", det_allow)):
        fx.add(fid, "count", label, value=v, prev=None, unit="건")
    return fx


def test_lead_sentence_fixed_template():
    assert fr.lead_sentence("10/1–10/12", lead_fx()) == "10/1–10/12에 244건을 검사해 31건 차단, 55건 마스킹, 11건은 검사 없이 통과"
    assert fr.lead_sentence("10/1–10/12", lead_fx(n=1234, det_allow=2)) == (
        "10/1–10/12에 1,234건을 검사해 31건 차단, 55건 마스킹, 11건은 검사 없이 통과, 2건은 탐지 후 허용")


def change_fx(total, ptotal, **pairs) -> Facts:
    labels = {"F_SECRET": "기밀 차단", "F_MASK": "개인정보 마스킹", "F_PII_BLOCK": "개인정보 차단", "F_UNINSP_BLOCK": "검사 불가 차단",
              "F_UNCHECKED": "검사 없이 통과", "F_BYPASS": "차단 뒤 통과 사건"}
    fx = Facts()
    fx.add("F_TOTAL", "count", "검사", value=total, prev=ptotal, unit="건")
    for fid, (p, v) in pairs.items():
        fx.add(fid, "count", labels[fid], value=v, prev=p, unit="건")
    return fx


def test_change_clauses_small_base_absolute_only():
    fx = change_fx(29, 1, F_SECRET=(1, 12), F_MASK=(0, 5), F_UNCHECKED=(0, 2), F_BYPASS=(0, 3))
    lines, note = fr.change_clauses(fx, True)
    assert lines == ["기밀 차단 1→12건(+11건)", "개인정보 마스킹 0→5건(+5건)"]       # 절대 증감이 큰 두 개
    assert note == "검사 1→29건 · 표본 적음(검사 30건 미만 기간이 있어 비율 생략)"
    assert not any("%" in x or "1,000건당" in x for x in lines)


def test_change_clauses_large_base_with_rates_and_no_percent():
    fx = change_fx(244, 107, F_SECRET=(16, 17), F_MASK=(1, 55), F_UNCHECKED=(11, 11))
    lines, note = fr.change_clauses(fx, True)
    assert lines == ["개인정보 마스킹 1→55건(+54건) · 1,000건당 9.3→225.4", "기밀 차단 16→17건(+1건) · 1,000건당 149.5→69.7"]
    assert note == "검사 107→244건" and "%" not in "".join(lines)


def test_change_clauses_ties_negative_and_not_comparable():
    fx = change_fx(100, 100, F_UNCHECKED=(5, 2), F_SECRET=(2, 5), F_MASK=(9, 9))
    lines, _ = fr.change_clauses(fx, True)
    assert lines == ["기밀 차단 2→5건(+3건) · 1,000건당 20.0→50.0", "검사 없이 통과 5→2건(-3건) · 1,000건당 50.0→20.0"]   # 같은 차이 → 후보 순서
    same = change_fx(100, 90, F_SECRET=(3, 3))
    assert fr.change_clauses(same, True) == ([], "검사 90→100건 · 위험 지표는 이전과 같음")
    assert fr.change_clauses(change_fx(5, None, F_SECRET=(None, 1)), False) == ([], "이전 기간 기록 없음(비교 불가)")


# ---------------------------------------------------------------- A3 관측 범위

def _cov(with_prev=True, local=None):
    a = ag.collect(agg_conn(with_prev_start=with_prev), date(2026, 10, 1), date(2026, 10, 3))
    incs = group(a["events"])
    users = user_facts(a["events"], incs)
    fx = fm.build(a, incs, users, issues=ag.evaluate_issues(a), local=local)
    return a, fx, {r["key"]: r for r in fr.coverage(a, fx)}


def test_coverage_rows_hand_counted():
    a, fx, rows = _cov()
    get = lambda k: (rows[k]["cur"], rows[k]["prev"])       # noqa: E731
    assert get("unchecked") == ("2건", "0건")
    assert [k for k in rows if k.startswith("unchecked:")] == ["unchecked:detection_unreachable", "unchecked:file_uninspectable_image"]
    assert get("unchecked:detection_unreachable") == ("1건", "0건") and rows["unchecked:detection_unreachable"]["sub"]
    assert get("unident") == ("3건", "0건")                                  # e12·e13·e14, 검사 16건 → 비중(%) 생략
    assert get("uninspectable") == ("3건(그 밖 형식 2 · 이미지 파일 1)", "0건")
    assert rows["uninspectable"]["note"].endswith("차단 2 · 허용 1")
    assert get("det_p95") == ("20ms", "기록 없음")
    assert get("timeout") == ("1건", "0건") and rows["timeout"]["note"] == "이번 처리 차단 1"
    assert get("nocheck_pass") == ("1건", "0건") and get("decision_only") == ("1건", "0건")
    assert get("kw_pending") == (fr.NA, fr.NA) and get("freshness") == (fr.NA, fr.NA)      # 안 읽는 자료는 '확인 불가'
    assert fr.coverage_headline(a, fx) == ("검사 없이 통과 2건 · 검사 불가 파일 3건 · 검사 시간 초과 1건 · 식별 안 됨 3건"
                                           " · 판정만 있는 요청 1건")


def test_coverage_without_previous_period_and_with_keywords():
    _, _, rows = _cov(with_prev=False, local={"keywords": {"approved": 3, "pending": 2}})
    for k in ("unchecked", "unident", "uninspectable", "det_p95", "timeout", "nocheck_pass", "stage_err", "decision_only"):
        assert rows[k]["prev"] == fr.NO_PREV, k
    assert rows["kw_pending"]["cur"] == "2개" and rows["kw_pending"]["prev"] == fr.NA
    assert rows["freshness"]["cur"] == fr.NA


# ---------------------------------------------------------------- A5 차단 뒤 재요청·통과

def test_retry_groups_on_hand_labelled_incidents():
    incs = group(fixture_events())
    user_facts(fixture_events(), incs)
    groups = fr.retry_groups(incs)
    got = [(g["label"], g["n"], g["ident"], g["unident"], g["passed"], g["last"], g["ids"], round(g["avg_after"], 2))
           for g in groups]
    assert got == [
        ("01_전략_보고서", 3, 3, 0, 1, [("BLOCK", 2), ("ALLOW", 1)], ["I1", "I2", "I3"], 2.0),     # 첫 차단 뒤 3·1·2
        ("검사 불가 파일(그 밖 형식)", 1, 1, 0, 1, [("ALLOW", 1)], ["I7"], 1.0),
        ("인증정보 차단(GitHub 토큰)", 1, 1, 0, 1, [("ALLOW", 1)], ["I5"], 1.0),                    # 첫 차단은 둘째 요청
        ("02_채용_평가서", 1, 0, 1, 0, [("BLOCK", 1)], ["I8"], 1.0),                              # 미식별: 통과로 세지 않음
    ]
    assert fr.bypass_count(incs) == 3 and groups[0]["users"] == ["U1"]
    assert fr.group_line(groups[0]) == ("사건 3건 · 식별 3 · 미식별 0 · 첫 차단 뒤 요청 평균 2.0건 · 차단 뒤 통과 1건 · "
                                        "마지막 결과 차단 2 · 허용 1")
    assert fr.bypass_episodes(fixture_events()) == (3, 3)
    assert fr.bypass_headline(3, 3, groups) == ("차단 뒤 통과 3건(식별 사용자 3명) · 차단 뒤 재요청 사건 6건 · "
                                               "첫 차단 대상 01_전략_보고서 1건, 검사 불가 파일(그 밖 형식) 1건 외 1묶음")
    assert fr.bypass_headline(3, 3, groups[:2]).endswith("검사 불가 파일(그 밖 형식) 1건")      # 둘 이하면 '외 N묶음' 없음
    by = {i.id: i for i in incs}
    assert fr.after_first_block(by["I4"]) == 0 and fr.after_first_block(by["I5"]) == 1   # 마스킹만 → 0


def test_retry_groups_empty():
    assert fr.retry_groups([]) == [] and fr.bypass_count([]) == 0
    assert fr.bypass_headline(0, 0, []) == "차단 뒤 통과 0건(식별 사용자 0명) · 차단 뒤 재요청 사건 0건"


def test_same_pattern_groups_identical_steps_and_target_only():
    a, incs, users, fx = _built()
    by = {i.id: i for i in incs}
    ids = ["I8", "I10", "I11", "I12", "I13"]
    steps = {i: fx.get(i)["steps"] for i in ids}
    assert steps["I10"] == steps["I11"] == ["기밀 차단 D2"]
    assert fr.same_pattern(ids, steps, by) == [["I8"], ["I10", "I11"], ["I12"], ["I13"]]
    # 단계 글이 같아도 첫 대상(키)이 다르면 따로: 검사 불가 이미지 vs 그 밖 형식
    assert fr.same_pattern(["I6", "I7"], {"I6": ["같음"], "I7": ["같음"]}, by) == [["I6"], ["I7"]]
    assert fr.same_pattern(["I11", "I10"], steps, by) == [["I11", "I10"]]          # 묶음은 첫 구성원 자리·순서 유지


# ---------------------------------------------------------------- A4 변경 표시선

def test_change_marks_map_days_cap_and_skip():
    fx = Facts()
    for n, at in enumerate(["10/9 16:20", "10/11 13:23", "10/11 11:23", "10/11 15:41", "10/11 18:00", "9/30 10:00", "모름"], 1):
        fx.add(f"E{n}", "change", f"변경 {n}", secs=("S8",), at=at)
    days = [f"2026-10-{d:02d}" for d in range(1, 13)]
    marks = fr.change_marks(fx, days)
    assert [(m["i"], m["n"], m["md"], m["more"]) for m in marks] == [(8, 1, "10/9", 0), (10, 2, "10/11", 1)]
    assert marks[1]["items"] == ["11:23 변경 3", "13:23 변경 2", "15:41 변경 4"] and len(marks[1]["all"]) == 4
    assert fr.change_marks(Facts(), days) == []


def test_line_chart_draws_change_lines_inside_viewbox():
    days = [f"2026-10-{d:02d}" for d in range(1, 8)]
    ser = [{"key": "t", "name": "검사", "cls": "total", "values": [1, 3, 2, 5, 4, 0, 2]}]
    for w in (ch.WIDE, ch.NARROW):
        root = ET.fromstring(ch.line_chart("c", "제목", "설명", days, ser, width=w,
                                           changes=[{"i": 0, "n": 1, "tip": "10/1 변경"}, {"i": 6, "n": 2, "tip": "10/7 변경"},
                                                    {"i": 9, "n": 3}]))
        assert len([ln for ln in root.iter(NS + "line") if ln.get("class") == "g-chg"]) == 2      # 기간 밖(9)은 뺌
        assert [t.text for t in texts(root) if "chg-n" in (t.get("class") or "")] == ["1", "2"]
        assert_inside(root, w)
    plain = ch.line_chart("c", "제목", "설명", days, ser, width=ch.WIDE)
    assert "g-chg" not in plain


# ---------------------------------------------------------------- A2 깔때기 SVG

def stages(unchecked=2):
    return [{"label": "검사", "parts": [{"name": "검사", "cls": "prev", "value": 29}], "sub": "프롬프트 24 · 파일 5"},
            {"label": "탐지·검사 못 함", "parts": [{"name": "탐지", "cls": "secret", "value": 19},
                                             {"name": "검사 못 함", "cls": "total", "value": 3}], "sub": "탐지 19 · 검사 못 함 3"},
            {"label": "차단·마스킹", "parts": [{"name": "차단", "cls": "block", "value": 15},
                                          {"name": "마스킹", "cls": "mask", "value": 5}]},
            {"label": "노출", "parts": [{"name": "검사 없이 통과", "cls": "crit", "value": unchecked},
                                      {"name": "탐지 후 허용", "cls": "serious", "value": 0}],
             "sub": "검사 없이 통과 2 · 탐지 후 허용 0 · 1,000건당 69.0 · 아주아주 긴 덧붙임 글이 좁은 판에서 잘리는지 보는 글"}]


@pytest.mark.parametrize("width", [ch.WIDE, ch.NARROW])
def test_funnel_chart_inside_viewbox_with_values(width):
    root = ET.fromstring(ch.funnel_chart("fn", "제목", "설명", stages(), width=width))
    assert root.get("role") == "img" and root.find(NS + "title").text == "제목"
    assert_inside(root, width)
    ends = [t.text for t in texts(root) if t.get("class") == "tv"]
    assert ends == ["29건", "22건", "20건", "2건"]
    titles = [t.text for t in root.iter(NS + "title") if t.text and " · " in t.text]
    assert "탐지·검사 못 함 · 탐지 19건 (86.4%)" in titles and "노출 · 검사 없이 통과 2건" in titles
    assert not any("탐지 후 허용 0건" in t for t in titles)                       # 0인 조각은 그리지 않음
    paths = list(root.iter(NS + "path"))
    assert [p.get("class") for p in paths] == ["f-prev", "f-secret", "f-total", "f-block", "f-mask", "f-crit"]
    # 막대 길이는 한 눈금(test_charts와 같은 방식: 끝 글자 위치 - 6 - 기준선): 차단·마스킹 20은 검사 29의 20/29
    x0 = float(next(root.iter(NS + "line")).get("x1"))
    end = {t.text: float(t.get("x")) - 6 - x0 for t in texts(root) if t.get("class") == "tv"}
    assert end["20건"] == pytest.approx(end["29건"] * 20 / 29, rel=0.01)
    assert end["22건"] == pytest.approx(end["29건"] * 22 / 29, rel=0.01)


def test_funnel_chart_zero_stage():
    root = ET.fromstring(ch.funnel_chart("fz", "제목", "설명", stages(unchecked=0), width=ch.NARROW))
    assert [t.text for t in texts(root) if t.get("class") == "tv"][-1] == "0건"
    assert_inside(root, ch.NARROW)


# ---------------------------------------------------------------- 고정 문구 금지어

def _all_fixed_strings() -> list[str]:
    a, incs, users, fx = _built()
    out = [fr.lead_sentence("10/1–10/12", fx), fr.funnel_line(fr.funnel_counts(a["events"])), fr.status_rule_line(),
           fr.coverage_headline(a, fx), fr.bypass_headline(*fr.bypass_episodes(a["events"]), fr.retry_groups(incs))]
    out += [fr.group_line(g) for g in fr.retry_groups(incs)]
    for comparable in (True, False):
        lines, note = fr.change_clauses(fx, comparable)
        out += lines + [note]
    out += fr.change_clauses(change_fx(244, 107, F_SECRET=(16, 17), F_MASK=(1, 55)), True)[0]
    st = fr.status(fx)
    out += [st["label"]] + [x for f in st["flags"] for x in (f["label"], f["sub"], fr.flag_value_text(f), fr.flag_rule_text(f))]
    out += [x for t, d in fr.definitions() for x in (t, d)]
    out += [x for r in fr.coverage(a, fx) for x in (r["label"], r["cur"], r["prev"], r["note"])]
    out += [x for m in fr.change_marks(fx, sorted(a["cur"]["daily"])) for x in m["all"]]
    out += ["한 장 요약", "본문", "차단 뒤 재요청", "관측 범위(못 본 것)", "같은 패턴 사건", "정의·기준", "검사에서 노출까지",
            "표본 적음", fr.NA, fr.NO_PREV]
    return out


def test_fixed_strings_pass_wording_rules_and_markers():
    for s in _all_fixed_strings():
        assert wording.find_banned(s) is None, (s, wording.find_banned(s))
        assert not any(m in s for m in OLD_STRINGS), s
        assert "집계" not in s, s


def test_definitions_print_every_threshold_as_our_setting():
    text = " ".join(d for _, d in fr.definitions())
    for v in (fr.EXPOSED_WARN, fr.EXPOSED_RISK, fr.BYPASS_WARN, fr.BYPASS_RISK, fr.UNSEEN_WARN, fr.UNSEEN_RISK, fr.MIN_BASE):
        assert str(v) in text
    assert "업계 기준 아님" in text and "넣지 않음" in text                         # 노출에 넣지 않는 것도 적음


# ---- 이전 건수 적음: 증감 %는 이전 기간 건수가 MIN_PREV_COUNT 이상일 때만
def test_small_prev_edges():
    assert fr.small_prev(None) is False and fr.small_prev(0) is False
    assert fr.small_prev(1) is True and fr.small_prev(fr.MIN_PREV_COUNT - 1) is True
    assert fr.small_prev(fr.MIN_PREV_COUNT) is False


def test_delta_chip_hides_percent_when_previous_count_is_tiny():
    from reporting import charts as ch
    tiny = ch.delta_chip(50, 1, comparable=True, small=fr.small_prev(1))
    assert "▲ 49" in tiny and "%" not in tiny                                    # 1→50건이 '+4,900%'로 읽히지 않는다
    enough = ch.delta_chip(25, fr.MIN_PREV_COUNT, comparable=True, small=fr.small_prev(fr.MIN_PREV_COUNT))
    assert "▲ 15" in enough and "(+150%)" in enough


def test_definitions_mention_small_previous_count():
    text = " ".join(f"{k} {v}" for k, v in fr.definitions())
    assert "이전 건수 적음" in text and str(fr.MIN_PREV_COUNT - 1) in text


# ---------------------------------------------------------------- 검토 반영: 차단 뒤 통과 직접 세기·정책 허용 노출·묶음 서명

def _prep(rows):
    evs, _ = ag.prepare_events(rows, *_bounds())
    ag.attach_decisions(evs, {})
    return evs


def test_bypass_episodes_counts_per_user_block_then_allow_same_service_within_window():
    rows = [
        ev("2026-10-01 09:00:00", "chrome-b1", "ChatGPT", "BLOCK", docs=["d1"], eid="b1"),
        ev("2026-10-01 09:03:00", "chrome-b1", "Claude", "ALLOW", eid="b2"),            # 다른 서비스 → 아님
        ev("2026-10-01 09:05:00", "chrome-b1", "ChatGPT", "MASK", ents={"KR_PHONE_NUMBER": 1}, eid="b3"),   # 중간 다른 요청
        ev("2026-10-01 09:10:00", "chrome-b1", "ChatGPT", "ALLOW", eid="b4"),           # 정확히 10분 → 센다
        ev("2026-10-01 09:11:00", "chrome-b1", "ChatGPT", "ALLOW", eid="b5"),           # 같은 차단은 한 번만
        ev("2026-10-01 11:00:00", "chrome-b2", "ChatGPT", "BLOCK", docs=["d1"], eid="b6"),
        ev("2026-10-01 11:10:01", "chrome-b2", "ChatGPT", "ALLOW", eid="b7"),           # 10분 1초 → 아님
        ev("2026-10-01 12:00:00", "chrome-b3", "Gemini", "BLOCK", docs=["d1"], eid="b8"),
        ev("2026-10-01 12:01:00", "chrome-b3", "Gemini", "ALLOW", eid="b9"),            # 센다
        ev("2026-10-01 12:02:00", "chrome-b3", "Gemini", "BLOCK", docs=["d1"], eid="b10"),
        ev("2026-10-01 12:03:00", "chrome-b3", "Gemini", "ALLOW", eid="b11"),           # 두 번째 쌍도 센다
        ev("2026-10-01 13:00:00", X, "ChatGPT", "BLOCK", docs=["d1"], eid="b12"),
        ev("2026-10-01 13:01:00", X, "ChatGPT", "ALLOW", eid="b13"),                    # 미식별은 세지 않음
    ]
    evs = _prep(rows)
    assert fr.bypass_episodes(evs) == (3, 2)             # chrome-b1 1건, chrome-b3 2건
    assert fr.bypass_episodes([]) == (0, 0)


def test_bypass_episodes_is_not_limited_by_incident_boundaries():
    # 사건 묶기가 중간 요청으로 닫혀도(허용이 11분 사이에 끼는 경우 등) 사용자별 시간순으로 세므로 놓치지 않는다
    rows = [ev("2026-10-01 09:00:00", "chrome-c1", "ChatGPT", "BLOCK", docs=["d1"], eid="c1"),
            ev("2026-10-01 09:04:00", "chrome-c1", "ChatGPT", "BLOCK", ents={"KR_RRN": 1}, eid="c2"),
            ev("2026-10-01 09:09:00", "chrome-c1", "ChatGPT", "ALLOW", eid="c3")]
    assert fr.bypass_episodes(_prep(rows)) == (1, 1)     # 마지막 차단(09:04) 뒤 5분


def test_policy_allowed_pii_counts_as_exposed_and_invariants_hold():
    rows = [ev("2026-10-01 09:00:00", "chrome-p1", "ChatGPT", "ALLOW", ents={"KR_PHONE_NUMBER": 1}, eid="p1"),   # 정책상 허용된 개인정보
            ev("2026-10-01 09:10:00", "chrome-p1", "ChatGPT", "ALLOW", docs=["d2"], eid="p2"),                    # 허용된 기밀 문서 일치
            ev("2026-10-01 09:20:00", "chrome-p2", "ChatGPT", "ALLOW", eid="p3"),                                  # 문제 없음
            ev("2026-10-01 09:30:00", "chrome-p2", "ChatGPT", "ALLOW", "file", rc="file_uninspectable_image", eid="p4")]
    evs = _prep(rows)
    fc = _assert_invariants(evs)
    assert (fc["det_allow"], fc["unchecked"], fc["exposed"], fc["clean"]) == (2, 1, 3, 1)
    assert fc["detected"] == 2 and fc["unseen"] == 1 and fc["attention"] == 3


def test_same_pattern_does_not_merge_incidents_with_different_action_sequences():
    from types import SimpleNamespace as NS_

    def inc(*actions, key="k"):
        mem = [SimpleNamespace_member(a, key) for a in actions]
        return NS_(members=mem)

    def SimpleNamespace_member(action, key):
        return NS_(e={"action": action, "key": key})

    by = {"A": inc("BLOCK", "BLOCK"), "B": inc("BLOCK", "ALLOW"), "C": inc("BLOCK", "BLOCK")}
    steps = {i: ["같은 단계"] for i in by}
    assert fr.same_pattern(["A", "B", "C"], steps, by) == [["A", "C"], ["B"]]          # 허용으로 끝난 사건은 따로


def test_bypass_headline_names_first_two_targets_and_counts_the_rest():
    g = lambda label, passed: {"label": label, "passed": passed, "n": 1}               # noqa: E731
    h = fr.bypass_headline(5, 2, [g("가", 2), g("나", 1), g("다", 1), g("라", 1), g("마", 0)])
    assert h == "차단 뒤 통과 5건(식별 사용자 2명) · 차단 뒤 재요청 사건 5건 · 첫 차단 대상 가 2건, 나 1건 외 2묶음"
    assert "첫 차단 대상" not in fr.bypass_headline(0, 0, [g("가", 0)])


def test_admin_action_and_reason_labels_cover_new_codes():
    for code in ("ACCESS_RULE_ADD", "ACCESS_RULE_REMOVE", "ACCESS_MODE_UPDATE", "CLIENT_ALIAS_UPDATE"):
        assert code in ag.ADMIN_ACTION_LABELS and ag.ADMIN_ACTION_LABELS[code] != code
    assert "detection_parse_error" in ag.RC_LABELS


def test_group_pass_counts_use_the_same_pairs_as_the_headline():
    evs = fixture_events()
    incs = group(evs)
    user_facts(evs, incs)
    pairs = fr.bypass_pairs(evs)
    assert len(pairs) == fr.bypass_episodes(evs)[0] == 3
    by_pairs = fr.retry_groups(incs, pairs)
    assert [(g["label"], g["passed"]) for g in by_pairs] == [(g["label"], g["passed"]) for g in fr.retry_groups(incs)]
    # 한 사람이 같은 서비스에서 '차단→허용'을 세 번 되풀이: 머리 줄·묶음 줄이 같은 3
    rows = []
    for k in range(3):
        m = 9 + k * 4
        rows += [ev(f"2026-10-01 {m:02d}:00:00", "chrome-r1", "ChatGPT", "BLOCK", docs=["d1"], eid=f"r{k}b"),
                 ev(f"2026-10-01 {m:02d}:01:00", "chrome-r1", "ChatGPT", "ALLOW", eid=f"r{k}a")]
    evs = _prep(rows)
    incs = group(evs)
    user_facts(evs, incs)
    pairs = fr.bypass_pairs(evs)
    groups = fr.retry_groups(incs, pairs)
    assert len(pairs) == 3 and sum(g["passed"] for g in groups) <= 3
    assert fr.bypass_headline(*fr.bypass_episodes(evs), groups).startswith("차단 뒤 통과 3건(식별 사용자 1명)")
