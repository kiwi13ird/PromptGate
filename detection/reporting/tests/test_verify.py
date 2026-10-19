"""시험 6 - 검사기 변형 시험(설계 v2 4.8). 나쁜 문장은 전부 버려지고(사유 번호 확인) 정상 문장은 남는다."""

import pytest

from reporting import verify
from reporting.verify import Ctx, check_action, check_level, check_line, check_order, filter_lines

from test_facts import small


def ctx(scope=None, samples=()):
    fx = small()
    fx.add("U2.SECRET", "count", "기밀 차단", secs=("S6",), value=2, prev=None, unit="건")
    fx.add("U2.EVENTS", "count", "검사", secs=("S6",), value=12, prev=None, unit="건")
    return Ctx(fx, set(fx.ids()), scope, verify.sample_grams(list(samples)))


GOOD = [
    {"t": "{F_SECRET|변화}", "c": ["F_SECRET"]},
    {"t": "{K3}가 {I3}에서 나옴", "c": ["K3"]},
    {"t": "{U2}, {I3.START}부터 {I3.SPAN} 동안 {D1} 일치로 차단", "c": ["I3"]},
    {"t": "{F_SECRET} 일치 문서 확인 · 인터넷 서비스 리셋 없음", "c": []},
    {"t": "차단 뒤 결과 바뀜, 마지막 요청 허용", "c": ["I3"]},
]


@pytest.mark.parametrize("line", GOOD)
def test_good_lines_survive(line):
    why, clean = check_line(line, ctx())
    assert why is None, why
    assert set(clean["c"]) >= {p for p in ("F_SECRET", "K3", "I3", "U2", "D1") if "{" + p in line["t"]}


BAD = [
    ({"t": "기밀 차단 17건", "c": ["F_SECRET"]}, "6"),                   # 숫자 직접
    ({"t": "{F_SECRET}, 두 건 반복", "c": []}, "7"),                     # 숫자 낱말
    ({"t": "{F_SECRET} 대부분 문서 일치", "c": []}, "7"),
    ({"t": "{F_LEAK} 발생", "c": []}, "2"),                              # 없는 번호
    ({"t": "기밀 차단 확인", "c": ["F_LEAK"]}, "2"),
    ({"t": "기밀 차단 확인", "c": []}, "1"),                              # 인용 없음
    ({"t": "{I3.START|변화} 시작", "c": []}, "4"),                        # 꼴 틀림
    ({"t": "{U2|비율}", "c": []}, "4"),
    ({"t": "{F_USERS|변화}", "c": []}, "4"),                              # 이전 값 없는 |변화
    ({"t": "{F_SECRET 반복", "c": ["F_SECRET"]}, "4"),                    # 자리표시 꼴 깨짐
    ({"t": "{F_SECRET}건", "c": []}, "5"),                                # 단위 겹침
    ({"t": "{F_SECRET|비율}%", "c": []}, "5"),
    ({"t": "{F_SECRET} 건이 차단", "c": []}, "5"),
    ({"t": "{F_SECRET} 증가", "c": []}, "8"),                             # 방향어
    ({"t": "{F_SECRET}, 고의로 보임", "c": []}, "9"),                     # 추정어
    ({"t": "{I3}에서 문서 유출됨", "c": []}, "9"),                         # 단정
    ({"t": "{F_SECRET}에 달함", "c": []}, "10"),                          # 문체
    ({"t": "{F_SECRET}입니다", "c": []}, "10"),
    ({"t": "{F_SECRET} 확인 필요?", "c": []}, "10"),
    ({"t": "{F_SECRET} SQL 집계", "c": []}, "11"),                        # 내부 용어
    ({"t": "{F_SECRET} 창 해시 일치", "c": []}, "11"),
    ({"t": "{F_SECRET} block 처리", "c": []}, "11"),
    ({"t": "{F_SECRET} " + "가" * 81, "c": []}, "13"),                    # 길이
    ({"t": "{F_SECRET} [KR_PHONE_NUMBER] 포함", "c": []}, "14"),          # 사용자 글 흔적
    ({"t": "{F_SECRET} 담당 a@b.com", "c": []}, "14"),
    ({"t": "{F_SECRET} example.com 전송", "c": []}, "14"),
]


@pytest.mark.parametrize("line, code", BAD)
def test_bad_lines_dropped_with_reason(line, code):
    why, clean = check_line(line, ctx())
    assert why is not None and why.split(" ")[0] == code, why
    assert clean is None


def test_section_scope():
    c = ctx(scope={"F_SECRET", "K3", "D1"})
    assert check_line({"t": "{F_P95}", "c": []}, c)[0] == "12 섹션 범위"
    assert check_line({"t": "{F_SECRET}", "c": []}, c)[0] is None


def test_sample_overlap_dropped():
    c = ctx(samples=["[CS] 고객 홍길동 님께 연락 바랍니다 ###-####"])
    assert check_line({"t": "{F_SECRET} 홍길동 님께 연락", "c": []}, c)[0] == "14 표본 글 겹침"
    assert check_line({"t": "{F_SECRET} 고객 응대 범주", "c": []}, c)[0] is None


def test_duplicate_in_same_section_dropped():
    kept, dropped = filter_lines([{"t": "{F_SECRET|변화}", "c": []}, {"t": "{F_SECRET|변화} ", "c": ["F_SECRET"]},
                                  {"t": "{F_TOTAL|변화}", "c": []}], ctx(), section="S3")
    assert [k["t"] for k in kept] == ["{F_SECRET|변화}", "{F_TOTAL|변화}"]
    assert dropped == [{"section": "S3", "line": "{F_SECRET|변화} ", "why": "17 중복"}]


def test_level_range_and_high_needs_top_fact():
    assert check_level("U2", "높음", "낮음", [{"c": ["U2.SECRET"]}]) == ("낮음", "15 규칙 등급과 두 단계 차이")
    assert check_level("U2", "높음", "중간", [{"c": ["U2.EVENTS"]}]) == ("중간", "15 근거 없는 높음")
    assert check_level("U2", "높음", "중간", [{"c": ["U2.SECRET"]}]) == ("높음", None)
    assert check_level("U2", "낮음", "중간", []) == ("낮음", None)
    assert check_level("U2", "최고", "중간", []) == ("중간", "15 등급 값")


def test_action_target_rules():
    allowed = {"BLOCK_USER": ["U1"], "DOC_EVENTS": ["D1"], "USER_EVENTS": ["U1", "U2"]}
    assert check_action("BLOCK_USER", "D1", allowed).startswith("16")       # 문서 대상
    assert check_action("BLOCK_USER", "U2", allowed).startswith("16")       # 등급 낮음(후보 아님)
    assert check_action("GATEWAY_SETTINGS", "NONE", allowed).startswith("16")
    assert check_action("DOC_EVENTS", "D1", allowed) is None


def test_rank_check():
    rule = ["I1", "I2", "I3", "I4"]
    assert check_order(["I3", "I1", "I9", "I3"], rule, {"I1"}, 2) == (["I3", "I1", "I2", "I4"], "빠진 후보 규칙 순서로 붙임")
    assert check_order(["I3", "I4", "I1", "I2"], rule, {"I1"}, 2) == (rule, "등급 1 사건 탈락 → 규칙 순위")
    assert check_order("x", rule, set(), 2) == (rule, "빠진 후보 규칙 순서로 붙임")
