"""시험 1 - 사건 묶기 단위 시험. 손으로 만든 이벤트와 손으로 먼저 적은 기대 사건표를 완전 대조한다(설계 v2 6장).

경우: 차단 뒤 재시도, 차단 뒤 허용, 문서와 같은 글자 낮아짐, 30분 경계(29:59 묶임 · 30:01 안 묶임), 한국 자정을 넘는 사건,
다른 서비스 같은 문서(식별: 묶임 / 식별 안 됨: 안 묶임), 식별 안 됨 사이에 다른 이벤트가 끼어도 같은 서비스·대상은 묶임.
"""

from datetime import date

from reporting import aggregate as ag
from reporting.incidents import candidates, group, rule_order, user_facts

from synth import A, B, C, D, E, X, FakeConn, incident_fixture

# 기대 사건표(손으로 작성). (번호, 사용자, 구성원[(이벤트, 역할)], 등급)
EXPECTED = [
    ("I1", A, [("a1", "FIRST"), ("a2", "RATE_DOWN"), ("a3", "CHANGED"), ("a4", "ALLOW_AFTER")], 1),
    ("I2", A, [("a6", "FIRST"), ("a7", "REPEAT")], 1),                       # 29:59 → 같은 대상 반복
    ("I3", A, [("a8", "FIRST"), ("a9", "REPEAT"), ("a10", "OTHER_TARGET")], 1),  # 30:01 → 새 사건, 다른 서비스 같은 문서 묶임
    ("I4", B, [("b1", "FIRST"), ("b2", "REPEAT")], 5),                       # 한국 자정 넘음
    ("I5", B, [("b3", "FIRST"), ("b4", "REPEAT"), ("b5", "ALLOW_AFTER")], 2),
    ("I6", C, [("c1", "FIRST"), ("c2", "REPEAT")], 3),
    ("I7", C, [("c3", "FIRST"), ("c4", "ALLOW_AFTER")], 4),
    ("I8", X, [("x1", "FIRST"), ("x3", "REPEAT")], 1),                       # 사이에 Gemini 마스킹이 껴도 묶임
    ("I9", X, [("x2", "FIRST")], 5),
    ("I10", X, [("x6", "FIRST")], 1),                                         # 식별 안 됨: 다른 서비스 같은 문서는 따로
    ("I11", X, [("x5", "FIRST")], 1),                                         # 40분 뒤
    ("I12", E, [("e1", "FIRST")], 1),
    ("I13", E, [("e2", "FIRST")], 1),
]
EXPECTED_RULE_ORDER = ["I1", "I3", "I2", "I8", "I10", "I11", "I12", "I13", "I5", "I6", "I7", "I4", "I9"]
# 사용자: (확장 ID, 번호, 규칙 등급, 검사, 기밀 차단, 서로 다른 문서, 인증정보, 차단 뒤 재시도, 차단 뒤 허용, 차단, 마스킹, 활동일)
EXPECTED_USERS = [
    (A, "U1", "높음", 10, 6, 1, 0, 3, 2, 7, 1, 1),
    (E, "U2", "높음", 2, 2, 2, 0, 0, 0, 2, 0, 1),
    (B, "U3", "높음", 5, 0, 0, 2, 1, 1, 1, 3, 2),
    (C, "U4", "중간", 4, 0, 0, 0, 1, 1, 1, 0, 1),
    (D, "U5", "낮음", 2, 0, 0, 0, 0, 0, 0, 0, 1),
]


def _events():
    rows, decs = incident_fixture()
    t0, t1 = ag.kst_bounds(date(2026, 10, 1), date(2026, 10, 13))
    ev, _ = ag.prepare_events(rows, t0, t1)
    roots = {d["request_id"]: {"n": 1, "ext": "docx"} for d in decs}
    ag.attach_decisions(ev, roots)
    ag.attach_same_text(ev, ag.fetch_same_text(FakeConn(rows, decs), ag.same_targets(ev)))
    return ev


def test_incident_table_matches_hand_labels_exactly():
    ev = _events()
    incs = group(ev)
    got = [(i.id, i.client, [(m.e["id"], m.role) for m in i.members], i.grade) for i in incs]
    assert got == EXPECTED


def test_rule_order_and_candidates():
    incs = group(_events())
    assert [i.id for i in rule_order(incs)] == EXPECTED_RULE_ORDER
    assert [i.id for i in candidates(incs)] == EXPECTED_RULE_ORDER[:11]      # 마스킹만(등급 5)은 표에만


def test_user_facts_and_rule_levels():
    ev = _events()
    incs = group(ev)
    users = user_facts(ev, incs)
    got = [(u["client"], u["id"], u["rule_level"], u["events"], u["secret"], u["docs"], u["cred"], u["retry"],
            u["block_then_allow"], u["block"], u["mask"], u["days"]) for u in users]
    assert got == EXPECTED_USERS
    assert users[0]["incidents"] == ["I1", "I2", "I3"]
    assert {i.id: i.user for i in incs}["I8"] == ""          # 식별 안 됨은 U 번호 없음
    assert {i.id: i.user for i in incs}["I5"] == "U3"


def test_unknown_single_stream_mode_differs_only_for_interleaved_unknown():
    """설계 3.2 시뮬레이션 방식(식별 안 됨을 한 흐름으로)과의 차이: 끼어든 이벤트가 있으면 같은 대상도 끊김."""
    incs = group(_events(), unknown_by_target=False)
    unknown = [[m.e["id"] for m in i.members] for i in incs if not i.ident]
    assert unknown == [["x1"], ["x2"], ["x3"], ["x6"], ["x5"]]
    ident = [[m.e["id"] for m in i.members] for i in incs if i.ident]
    assert ident == [[m[0] for m in exp[2]] for exp in EXPECTED if exp[1] != X]


def test_window_boundaries_are_inclusive_at_30_and_10_minutes():
    from synth import ev as mk

    rows = [mk("2026-10-05 10:00:00", A, "ChatGPT", "BLOCK", docs=["d"], eid="p1"),
            mk("2026-10-05 10:30:00", A, "ChatGPT", "BLOCK", docs=["d"], eid="p2"),     # 정확히 30분 → 묶임
            mk("2026-10-05 10:40:00", A, "ChatGPT", "ALLOW", eid="p3"),                 # 차단 뒤 정확히 10분 → 묶임
            mk("2026-10-05 10:40:30", A, "ChatGPT", "ALLOW", eid="p4")]                 # 마지막 차단 뒤 10분 30초 → 안 묶임
    t0, t1 = ag.kst_bounds(date(2026, 10, 5), date(2026, 10, 6))
    ev, _ = ag.prepare_events(rows, t0, t1)
    ag.attach_decisions(ev, {})
    incs = group(ev)
    assert [[(m.e["id"], m.role) for m in i.members] for i in incs] == [[("p1", "FIRST"), ("p2", "REPEAT"), ("p3", "ALLOW_AFTER")]]
