"""검사 18~21(숫자 우회) 시험 + 이름표 겹침 정리. 2026-10-13 측정에서 본 우회 꼴과 정상 문장."""

import pytest

from reporting.verify import check_line, drop_label_echo

from test_facts import small
from test_verify import ctx

BAD = [
    ({"t": "{F_SECRET} 중 문서 일치  건", "c": []}, "18"),          # 값 없이 홀로 선 단위
    ({"t": "{F_SECRET|변화}, 이전 (  →  )", "c": []}, "18"),         # 값 없는 화살표
    ({"t": "{F_P95} 유지, 중앙값 (ms)", "c": []}, "18"),
    ({"t": "{F_SECRET} 중 사건  미식별 사용자 요청", "c": []}, "18"),  # 낱말 빠진 두 칸
    ({"t": "{F_SECRET} 중 dozen 건 문서 일치", "c": []}, "19"),      # 영어 수 낱말
    ({"t": "{F_SECRET} 중 Fourteen cases", "c": []}, "19"),
    ({"t": "{F_SECRET} 중 십칠 건 문서 일치", "c": []}, "19"),       # 한자어 수
    ({"t": "{F_SECRET} 중 스물두 건 문서 일치", "c": []}, "19"),     # 열 넘는 고유어 수
    ({"t": "{U2}가 I{I3.START}부터 요청", "c": []}, "20"),           # 자리표시에 붙은 영문자
    ({"t": "{F_SECRET} 중 D 문서 일치", "c": []}, "20"),             # 홀로 선 대문자
    ({"t": "{F_SECRET} ISTART 확인", "c": []}, "20"),                # 이름표에 없는 대문자 낱말
    ({"t": "{F_SECRET} 확인 확인", "c": []}, "21"),                  # 같은 말 반복
    ({"t": "{F_SECRET} 가나가나가나가나", "c": []}, "21"),
]


@pytest.mark.parametrize("line, code", BAD)
def test_evasions_dropped(line, code):
    why, clean = check_line(line, ctx())
    assert why is not None and why.split(" ")[0] == code, why
    assert clean is None


GOOD = [
    {"t": "{F_SECRET} 중 PDF 파일 확인", "c": []},
    {"t": "확장 ID 없는 요청 {F_SECRET|비율}", "c": []},
    {"t": "검사  {F_TOTAL|변화}", "c": []},                           # 두 칸 뒤가 자리표시면 괜찮음
    {"t": "{F_SECRET} · 문서 일치 건수 확인", "c": []},               # '건수'는 단위 홀로가 아님
    {"t": "{I3} 차단 뒤 허용 없음, 차단 단계 확인", "c": []},
]


@pytest.mark.parametrize("line", GOOD)
def test_normal_lines_pass(line):
    why, _ = check_line(line, ctx())
    assert why is None, why


@pytest.mark.parametrize("t, want", [
    ("기밀 차단 {F_SECRET} 중 {K3}", "{F_SECRET} 중 {K3}"),
    ("사건 {I3}에서 차단", "{I3}에서 차단"),
    ("사건  {I3}에서 차단", "{I3}에서 차단"),
    ("문서 일치 {F_SECRET|값}", "문서 일치 {F_SECRET|값}"),           # 꼴 있는 자리표시는 이름표를 안 씀
    ("검사 서버 {F_SECRET}", "검사 서버 {F_SECRET}"),                 # 이름표와 다른 말은 그대로
    ("(기밀 차단 {F_SECRET})", "({F_SECRET})"),
])
def test_label_echo_removed_only_when_exact(t, want):
    assert drop_label_echo(t, small()) == want


def test_label_echo_line_passes_and_renders_once():
    c = ctx()
    why, clean = check_line({"t": "기밀 차단 {F_SECRET} 확인", "c": []}, c)
    assert why is None and clean["t"] == "{F_SECRET} 확인"
    assert c.facts.render(clean["t"]) == "기밀 차단 17건 확인"
