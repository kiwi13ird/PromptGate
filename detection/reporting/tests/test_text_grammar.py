"""설계 v3 B1·B2(문장 글자 문법) 시험.

- 기본 켬(환경 변수 없음). REPORT_LLM_TEXT_GRAMMAR=off로 끄면 LLM 요청 본문이 바뀌기 전 코드와 같다
  (서술 프롬프트 v2 시스템 글만 다름 - 합성 입력 + 가짜 LLM 해시 고정)
- 글자 문법에 맞는 문장은 검사 2·4·6에 걸리지 않고, 숫자(아랍 숫자 포함)·없는 번호·틀린 꼴은 문법이 받지 않는다
"""

from __future__ import annotations

import hashlib
import random
import re
import time

import pytest

from reporting import llm, verify
from reporting.facts import PH

from fake_llm import FakeLLM
from test_facts import small
from test_pipeline import run

# 바뀌기 전 코드(운영 반영본, 2026-10-13 md5 확인)로 같은 합성 입력을 돌린 요청 본문 해시 - harness/golden_bodies.py.
# 2026-10-13 2차: 서술 프롬프트만 바꿈(report_narrate.v2) → 서술 호출의 시스템 프롬프트를 뺀 본문 해시가 전과 같아야 한다
# 2026-10-16: 문서 사실의 일치 값이 '문서와 같은 글자'(same_text_max·same_text_unavailable)로, 사건 단계 이름이 바뀐 것만 다름
# (전 974530a2…·9bc62d42… - 두 칸·이름을 빼면 본문 20개가 그대로 같음, 키트 check/llm_body_cmp.py)
# 2026-10-16 사용자 이유 고침: 사용자 호출만 바뀜(프롬프트 report_users.v2 · 사실 U번호.BASIS·분모 · period) - 나머지 작업
# 9개 본문은 전과 그대로 같음(전 8e321a39…·dea888db…, 키트 check/body_cmp.sh로 작업별 비교)
GOLDEN_MASKED = {"good": ("5f26fb59a71c9e10ddcbc2584cca8c2c262f62902004adbdeaa1ba0adeb9b4f7", 10),
                 "bad": ("4563fd48617bca41690d65084014916a17d3a6c8a6d346332d7743b546a24156", 10)}
SWITCHES = ("REPORT_LLM_TEXT_GRAMMAR",)


@pytest.fixture
def off(monkeypatch):
    """되돌리기 스위치로 끈 상태(2026-10-13 반영부터 기본 켬)."""
    for k in SWITCHES:
        monkeypatch.setenv(k, "off")


@pytest.fixture
def unset(monkeypatch):
    for k in SWITCHES:
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------- 기본 켬 · 끄기 스위치

def test_default_is_on(unset):
    assert llm.text_grammar_on() is True


@pytest.mark.parametrize("v", ["off", "OFF", " off ", "0", "false", "no"])
def test_off_words_turn_it_off(monkeypatch, v):
    monkeypatch.setenv("REPORT_LLM_TEXT_GRAMMAR", v)
    assert llm.text_grammar_on() is False


@pytest.mark.parametrize("v", ["on", "1", "true", "yes", ""])
def test_on_words_and_empty_keep_it_on(monkeypatch, v):
    monkeypatch.setenv("REPORT_LLM_TEXT_GRAMMAR", v)
    assert llm.text_grammar_on() is True


def _hash(fake) -> tuple[str, int]:
    """서술 호출은 시스템 프롬프트를 비운 본문, 나머지는 받은 본문 그대로의 해시(harness/golden_bodies.py와 같은 방식)."""
    import json
    out = []
    for r in fake.requests:
        b = json.loads(r["body"])
        if r["task"] == "narrate":
            b["messages"][0]["content"] = ""
        out.append(json.dumps(b, ensure_ascii=False, sort_keys=True))
    out.sort()
    return hashlib.sha256("\n".join(out).encode("utf-8")).hexdigest(), len(out)


# ---------------------------------------------------------------- 꺼짐 = 전과 같음

@pytest.mark.parametrize("mode", ["good", "bad"])
def test_switches_off_request_bodies_unchanged(tmp_path, monkeypatch, off, mode):
    with FakeLLM(mode) as fake:
        rc, _html, log, _ = run(tmp_path, monkeypatch, fake.url)
    assert rc == 0
    assert _hash(fake) == GOLDEN_MASKED[mode]
    narr = [r["system"] for r in fake.requests if r["task"] == "narrate"]
    assert narr and all("report_narrate" not in x for x in narr)       # 판 번호 줄은 프롬프트 본문에 안 들어감
    assert all("마지막 요청 허용" not in x for x in narr)                  # 복사되던 예시 문장 없음


def test_line_schema_off_is_old_schema(off):
    assert llm.line_schema(["F_A", "F_B"]) == {
        "type": "object",
        "properties": {"t": {"type": "string", "maxLength": 120},
                       "c": {"type": "array", "items": {"type": "string", "enum": ["F_A", "F_B"]}, "minItems": 1, "maxItems": 4}},
        "required": ["t", "c"], "additionalProperties": False}


# ---------------------------------------------------------------- B1·B2 글자 문법

def _pattern():
    fx = small()
    ph = llm.placeholder_forms(fx, fx.ids())
    return fx, ph, re.compile(llm.text_pattern(ph))


def test_placeholder_forms_follow_renderer():
    _fx, ph, _ = _pattern()
    assert ph["F_SECRET"] == (("값", "이전", "변화", "비율"), True)
    assert ph["F_USERS"] == (("값",), True)                  # 이전 값·분모 없음 → |이전 |변화 |비율 못 씀
    assert ph["F_P95"] == (("값",), True)
    assert ph["I3.START"] == ((), True) and ph["D1"] == ((), True)


GRAMMAR_OK = ["기밀 차단 {F_SECRET|변화}", "{K3}가 {I3}에서 나옴", "{U2}, {I3.START}부터 {I3.SPAN} 동안 {D1} 일치로 차단",
              "차단 뒤 결과 바뀜, 마지막 요청 허용", "ChatGPT 검사 중 {F_SECRET|비율} · 확인 필요"]
GRAMMAR_BAD = ["기밀 차단 17건", "기밀 차단 ۱۷건", "기밀 차단 ١٧건", "기밀 차단 １７건", "사건 ③", "Ⅱ단계",
               "{F_LEAK} 발생", "{I3.START|변화} 시작", "{F_USERS|변화}", "{F_TOTAL|비율}", "{F_SECRET 반복", "중괄호 } 하나",
               '따옴표 " 하나', "줄\n바꿈", "", "가" * 121]


@pytest.mark.parametrize("t", GRAMMAR_OK)
def test_grammar_accepts_valid_sentences(t):
    _fx, _ph, pat = _pattern()
    assert pat.fullmatch(t), t


@pytest.mark.parametrize("t", GRAMMAR_BAD)
def test_grammar_rejects_digits_unknown_ids_and_bad_forms(t):
    _fx, _ph, pat = _pattern()
    assert not pat.fullmatch(t), t


def test_grammar_allows_every_hangul_syllable_in_utf8_safe_ranges():
    """한글 음절 11,172자 전부 허용 + 범위마다 UTF-8 앞 두 바이트가 같음('가-힣' 한 범위는 vLLM 0.29.0이 일부를 막음)."""
    cls = re.compile("[%s]" % llm._TEXT_CHARS)
    assert all(cls.fullmatch(chr(c)) for c in range(0xAC00, 0xD7A4))
    ranges = re.findall(r"(.)-(.)", llm._HANGUL)
    assert len(ranges) == 175
    for lo, hi in ranges:
        assert lo.encode("utf-8")[:2] == hi.encode("utf-8")[:2], (lo, hi)
    assert "가-힣" not in llm._TEXT_CHARS


def test_grammar_sentences_never_fail_checks_2_4_6():
    """문법이 받는 문장을 무작위로 만들어 검사 2(없는 번호)·4(꼴)·5 아닌·6(숫자)에 걸리지 않는지 - 문법과 검사기가 어긋나지 않음."""
    fx, ph, pat = _pattern()
    rng = random.Random(0)
    chars = "가나다기밀차단 ABCxyz.,·()/:;~'%&+_<>*…→←‘’“”ㆍ-–—"
    tokens = []
    for fid, (forms, bare) in ph.items():
        if bare:
            tokens.append("{%s}" % fid)
        tokens += ["{%s|%s}" % (fid, f) for f in forms]
    ctx = verify.Ctx(fx, set(fx.ids()))
    for _ in range(3000):
        parts = [rng.choice(tokens) if rng.random() < 0.25 else rng.choice(chars) for _ in range(rng.randint(1, 30))]
        t = "".join(parts)
        assert pat.fullmatch(t)
        why, _ = verify.check_line({"t": t, "c": []}, ctx)
        assert why is None or why.split(" ")[0] not in ("2", "4", "6"), (t, why)


@pytest.mark.parametrize("setting", [None, "on"])   # None = 환경 변수 없음(기본 켬, 운영 서비스 그대로)
def test_grammar_on_puts_pattern_in_every_sentence_schema_and_good_output_fits(tmp_path, monkeypatch, unset, setting):
    if setting is not None:
        monkeypatch.setenv("REPORT_LLM_TEXT_GRAMMAR", setting)
    with FakeLLM("good") as fake:
        rc, _html, log, _ = run(tmp_path, monkeypatch, fake.url)
    assert rc == 0 and log["dropped"] == []
    import json
    n = 0
    for r in fake.requests:
        if r["task"] not in ("commentary", "narrate", "users", "recs"):
            assert '"pattern"' not in r["body"]
            continue
        body = json.loads(r["body"])
        pats = []

        def walk(o):
            if isinstance(o, dict):
                if "pattern" in o:
                    pats.append(o["pattern"])
                    assert "maxLength" not in o        # vLLM 0.29.0: pattern과 같이 주면 무시됨 → 반복 상한으로
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(body["response_format"]["json_schema"]["schema"])
        assert len(set(pats)) == 1
        pat = re.compile(pats[0])
        # 가짜 LLM의 정상 출력(규칙을 지킨 문장)은 문법에 맞아야 한다
        out = getattr(fake, f"good_{r['task']}")(r["payload"])
        for t in re.findall(r'"t":\s*"((?:[^"\\]|\\.)*)"', json.dumps(out, ensure_ascii=False)):
            assert pat.fullmatch(t), (r["task"], t)
            n += 1
    assert n > 10
