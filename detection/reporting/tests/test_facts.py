"""사실 목록·자리표시 렌더러(설계 v2 4.4) - 꼴별 표기, 방향 낱말, 조사 맞춤, 기여(K) 사실, LLM 보기에서 별칭·ID 제외."""

from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import facts as fm
from reporting.facts import Facts, RenderError
from reporting.incidents import group, user_facts

from synth import FakeConn, dec, ev, incident_fixture


def small() -> Facts:
    fx = Facts()
    fx.add("F_TOTAL", "count", "검사", secs=("S1",), value=242, prev=107, unit="건")
    fx.add("F_SECRET", "count", "기밀 차단", secs=("S1", "S3"), value=17, prev=16, unit="건", denom="F_TOTAL")
    fx.add("F_SAME", "count", "검사 없이 통과", secs=("S9",), value=11, prev=11, unit="건")
    fx.add("F_USERS", "count", "식별 사용자", secs=("S6",), value=5, prev=None, unit="명")
    fx.add("F_MASK_RATE", "rate", "마스킹 비율", secs=("S2",), value=22.73, prev=21.5)
    fx.add("F_P95", "time", "처리 시간 p95", secs=("S9",), value=1660.0, prev=None)
    fx.add("F_P50", "time", "처리 시간 중앙값", secs=("S9",), value=19.9, prev=25.0)
    fx.add("I3", "incident", "사건 3", secs=("S5",))
    fx.add("I3.START", "ts", "시작", secs=("S5",), value="10/11 14:02")
    fx.add("I3.SPAN", "span", "길이", secs=("S5",), value=3.2)
    fx.add("I4.SPAN", "span", "길이", secs=("S5",), value=0.4)
    fx.add("U2", "user", "", secs=("S6",), client="chrome-3f0a9b7c-0000", display="영업지원-2")
    fx.add("D1", "doc", "01_사업전략_방향_보고서", secs=("S3",))
    fx.add("K3", "share", "기밀 차단 중 I3", secs=("S1", "S3"), of="F_SECRET", value=9, unit="건", by="I3")
    fx.add("E2", "change", "Gateway 설정 file.timeout", secs=("S8",), at="10/11 13:40", before="block", after="pass")
    return fx


@pytest.mark.parametrize("tpl, out", [
    ("{F_SECRET}", "기밀 차단 17건"),
    ("{F_SECRET|값}", "17건"),
    ("{F_SECRET|이전}", "16건"),
    ("{F_SECRET|변화}", "1건 늘어남(16→17)"),
    ("{F_SECRET|비율}", "7.0%(17/242)"),
    ("{F_TOTAL|변화}", "135건 늘어남(107→242)"),
    ("{F_SAME|변화}", "같음(11건)"),
    ("{F_USERS}", "식별 사용자 5명"),
    ("{F_MASK_RATE|변화}", "1.2%p 높아짐(21.5→22.7%)"),
    ("{F_P95}", "처리 시간 p95 1.66초"),
    ("{F_P50|변화}", "5ms 줄어듦(25→20ms)"),
    ("{I3.START}부터 {I3.SPAN} 동안", "10/11 14:02부터 3분 동안"),
    ("{I4.SPAN}", "1분 미만"),
    ("{U2}", "영업지원-2"),
    ("{D1}", "01_사업전략_방향_보고서"),
    ("{E2}", "10/11 13:40 Gateway 설정 file.timeout(block→pass)"),
    # 설계 4.6-a 예: 조사는 렌더 결과 끝 글자 받침에 맞춘다
    ("{F_SECRET|변화}. {K3}가 {I3}에서 나옴", "1건 늘어남(16→17). 기밀 차단 17건 중 9건이 사건 3에서 나옴"),
    ("{U2}은 확인", "영업지원-2는 확인"),
    ("{D1}을 반복", "01_사업전략_방향_보고서를 반복"),
    ("{F_SECRET|변화}으로 바뀜", "1건 늘어남(16→17)로 바뀜"),
    ("{I3.SPAN}로 끝남", "3분으로 끝남"),
    ("{I3}와 {D1}과", "사건 3과 01_사업전략_방향_보고서와"),
])
def test_render_forms_and_josa(tpl, out):
    assert small().render(tpl) == out


@pytest.mark.parametrize("tpl", ["{F_USERS|변화}", "{F_P95|변화}", "{I3.START|변화}", "{U2|비율}", "{F_P95|비율}",
                                 "{F_LEAK}", "{K3|변화}", "{F_SECRET|퍼센트}"])
def test_bad_forms_raise(tpl):
    with pytest.raises(RenderError):
        small().render(tpl)


def test_llm_view_hides_alias_and_client_id():
    view = small().llm_view(["U2", "F_SECRET"])
    assert view[0] == {"id": "U2", "type": "user"}
    assert "display" not in str(view) and "chrome-3f0a" not in str(view)


def _built():
    rows, decs = incident_fixture()
    rows.append(ev("2026-09-19 00:00:00", "chrome-zz", "ChatGPT", "BLOCK", docs=["01_전략_보고서"], eid="old"))
    conn = FakeConn(rows, decs, aliases={"chrome-aaaa-0001": "영업지원-1"})
    a = ag.collect(conn, date(2026, 10, 1), date(2026, 10, 13))
    incs = group(a["events"])
    users = user_facts(a["events"], incs)
    issues = ag.evaluate_issues(a)
    return a, incs, users, fm.build(a, incs, users, issues=issues)


def test_build_numbers_match_aggregate_and_contributions():
    a, incs, users, fx = _built()
    assert fx.get("F_TOTAL")["value"] == a["cur"]["cards"]["total"] == 29
    assert fx.get("F_TOTAL")["prev"] == 1 and fx.get("F_SECRET")["prev"] == 1
    assert fx.get("F_SECRET")["value"] == 12
    # 변화가 있는 지표마다 몫 상위 3개
    ks = [f for f in fx.by_id.values() if f["type"] == "share" and f["of"] == "F_SECRET"]
    # 손으로 센 값: 서비스 ChatGPT 10, 문서 01_전략_보고서(D1) 7, 사용자 A(U1) 6
    assert [(k["by"] or k["by_service"], k["value"]) for k in ks] == [("ChatGPT", 10), ("D1", 7), ("U1", 6)]
    assert fx.render("{%s}" % ks[1]["id"]) == "기밀 차단 12건 중 7건"
    # 별칭은 렌더에만, LLM 보기에는 없음
    assert fx.render("{U1}") == "영업지원-1"
    assert "영업지원" not in str(fx.llm_view(fx.ids()))
    # 이슈 사실
    assert fx.get("R1")["type"] == "issue" and "D1" in fx.get("R1")["related"]


def test_steps_are_fixed_phrases_without_user_text():
    a, incs, users, fx = _built()
    assert fx.get("I1")["steps"] == ["기밀 차단 D1", "같은 대상 반복(문서와 같은 글자 낮아짐)", "차단 뒤 결과 바뀜(개인정보 마스킹)", "차단 뒤 허용"]
    assert fx.get("I2")["steps"] == ["기밀 차단 D1", "같은 대상 반복"]
