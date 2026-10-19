"""LLM 문장 검사기 (설계 v2 4.8). 문장마다 순서대로 보고 하나라도 걸리면 그 문장만 버린다.

 1 인용 있음            2 인용·자리표시 번호가 그 호출 사실에 있음   3 자리표시 번호는 인용에 자동 포함
 4 꼴·형식 일치          5 단위 겹침                              6 자리표시 밖 숫자
 7 숫자 낱말            8 방향어                                 9 추정어·단정어
10 문체                11 내부 용어                              12 섹션 범위
13 길이(자리표시 뺀 80자) 14 사용자 글 흔적                        15 등급 범위(사용자)
16 조치 대상(권고)       17 중복(같은 섹션, 같은 인용 묶음 + 비슷한 글)
18 빈 수 자리            19 수 낱말(영어·한자어·열 넘는 고유어)      20 번호·코드 흔적
21 같은 말 반복          22 비교 근거 없는 평가(사용자 이유만)  23 이름표 없는 값('21건'만, 사용자 이유만)

18~21은 숫자를 직접 못 쓰게 했을 때 모델이 비켜 가는 길(빈칸·'dozen 건'·'I10/1'·'사건 사건')을 막는다
(2026-10-13 측정, docs/design/llm-report-v3-llm-yield-2026-10-13.md 9장). 1~14를 다 통과한 문장에만 본다.
검사기는 틀린 숫자·없는 사실·금지어를 막는다. 인용은 맞는데 해석이 엉뚱한 문장은 못 막는다(시험 4에서 봄).
버린 문장·사유는 호출한 쪽이 생성 기록 JSON에 남긴다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from . import wording
from .facts import FORMS, NUMERIC, PH, Facts, RenderError

_UNITS = r"(?:건|명|개|종|일|%p|%|퍼센트|초|ms|분|회|번|차례|곳|시간)"
# 붙어 있으면 늘 겹침('{F_SECRET}건'), 띄었으면 단위 낱말일 때만('{F_SECRET} 건이'는 겹침, '{D1} 일치'는 아님)
_UNIT_AFTER = re.compile(_UNITS + r"|\s" + _UNITS + r"(?:이|가|은|는|을|를|의|에|도|만|과|와|로|으로)?(?![가-힣A-Za-z])")
_DIGITISH = re.compile(r"[\d①-⑳Ⅰ-Ⅻ]")
_SPACE = re.compile(r"\s+")

# ---- 18 빈 수 자리: 값(자리표시) 없이 홀로 선 단위·화살표, 낱말이 빠진 두 칸 이상 띄움
_JOSA_END = r"(?=$|[\s,.·()]|(?:이|가|은|는|을|를|의|에|도|만|과|와|로|으로)(?![가-힣]))"
_LONE_UNIT = re.compile(r"(?<![^\s(])(?:건|명|개|종|일|초|분|ms|%p|%|회|번|곳)" + _JOSA_END)
_LONE_ARROW = re.compile(r"(?<![^\s(])→(?=$|[\s)])")
_GAP = re.compile(r"\S {2,}(?!§)\S")       # 두 칸 띄움 뒤가 자리표시면 낱말 빠짐이 아님('검사  {F_TOTAL}')
# ---- 19 수 낱말: 영어 수, 한자어 수(십·백·천·만이 든 것), 열 넘는 고유어 수 + 단위 (7은 한·두·세…열·하나 등만 봄)
_EN_NUM = re.compile(
    r"(?<![A-Za-z])(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
    r"fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|"
    r"thousand|million|dozen|half|once|twice|triple|double)(?![A-Za-z])", re.IGNORECASE)
_COUNTERS = r"(?:건|명|개|종|회|번|차례|곳|가지)"
_SINO_NUM = re.compile(r"(?<![가-힣])[일이삼사오육칠팔구]?[십백천만][일이삼사오육칠팔구]?\s?" + _COUNTERS + r"(?![가-힣])")
_NATIVE_NUM = re.compile(r"(?<![가-힣])(?:열|스물|서른|마흔|쉰)(?:한|두|세|네|다섯|여섯|일곱|여덟|아홉)\s?" + _COUNTERS)
# ---- 20 번호·코드 흔적: 자리표시에 붙은 영문자('I{I6.START}'), 홀로 선 대문자('I', 'D-'), 사실 이름표에 없는 대문자 낱말
_GLUED = re.compile(r"[A-Za-z]\{")
_LONE_CAP = re.compile(r"(?<![A-Za-z])[A-Z](?![A-Za-z])")
_CAPS_WORD = re.compile(r"(?<![A-Za-z_])[A-Z][A-Z_]+(?![A-Za-z_])")
COMMON_CAPS = {"ID", "IP", "AI", "LLM", "API", "URL", "OCR", "PDF", "HWP", "HWPX", "DOC", "DOCX", "XLS", "XLSX",
               "PPT", "PPTX", "CSV", "TXT", "PNG", "JPG", "JPEG", "ZIP", "OK"}
# ---- 21 같은 말 반복(렌더한 글): 붙어 나온 같은 낱말 묶음('기밀 차단 기밀 차단'), 같은 조각 네 번 이상('I,I,I,I')
_REPEAT_WORDS = re.compile(r"(?<!\S)(\S+(?: \S+){0,3}) \1(?!\S)")
_REPEAT_CHUNK = re.compile(r"([^\d\s]{1,8}?)\1{3,}")


def drop_label_echo(t: str, facts: Facts) -> str:
    """자리표시 바로 앞에 그 자리표시가 렌더할 이름표 앞부분을 또 쓴 경우 앞 글을 지운다.

    '기밀 차단 {F_SECRET}' → '{F_SECRET}'(렌더 '기밀 차단 17건'), '사건 {I3}' → '{I3}'(렌더 '사건 3').
    낱말 단위로 정확히 같을 때만 지우고 뜻은 그대로다 - 21번(같은 말 반복)이 이런 문장을 버리지 않게 하는 정리.
    꼴이 있는 자리표시({X|값} 등)는 이름표를 렌더하지 않으므로 건드리지 않는다. 사용자 건수 비율({U1.BLOCK|비율})은
    분모 이름표부터 렌더하므로('차단 전체 43건 중 26건(60.5%)') 그 이름표와 견준다.
    """
    out = t
    for m in reversed(list(PH.finditer(t))):
        fid, form = m.group(1), m.group(2)
        if fid not in facts or (form is not None and not (form == "비율" and facts.get(fid).get("ratio_label"))):
            continue
        try:
            words = facts.render_one(fid, form).split()
        except (RenderError, KeyError):
            continue
        before = out[:m.start()].rstrip()
        for k in range(len(words), 0, -1):
            p = " ".join(words[:k])
            if len(p) >= 2 and (before == p or before.endswith((" " + p, "(" + p, "·" + p))):
                out = before[:len(before) - len(p)] + out[m.start():]
                break
    return out


def _caps_vocab(facts: Facts) -> set[str]:
    """사실 이름표에 나온 대문자 낱말(서비스·형식 이름 등) - 20번에서 정상으로 본다."""
    vocab: set[str] = set()
    for f in facts.by_id.values():
        vocab |= set(_CAPS_WORD.findall(str(f.get("label") or "").upper()))
    return vocab


def check_evasion(t: str, facts: Facts) -> str | None:
    """18~21. t는 정리한 문장(자리표시 그대로). 걸리면 사유. 수 낱말(19)을 먼저 본다('dozen 건'은 19)."""
    stripped = PH.sub(" ", t)
    m = _EN_NUM.search(stripped) or _SINO_NUM.search(stripped) or _NATIVE_NUM.search(stripped)
    if m:
        return f"19 수 낱말 '{m.group(0)}'"
    marked = PH.sub("§", t)
    for m in _LONE_UNIT.finditer(marked):
        before = marked[:m.start()].rstrip(" (")
        if not before.endswith("§"):          # 자리표시 바로 뒤 단위는 5번(단위 겹침) 몫
            return f"18 빈 수 자리 '{m.group(0)}'"
    if _LONE_ARROW.search(marked):
        return "18 빈 수 자리 '→'"
    if _GAP.search(marked):
        return "18 빈 수 자리(빈칸)"
    m = _GLUED.search(t) or _LONE_CAP.search(stripped)
    if m:
        return f"20 번호 흔적 '{m.group(0)}'"
    vocab = _caps_vocab(facts)
    for w in _CAPS_WORD.findall(stripped):
        if w not in COMMON_CAPS and w not in vocab:
            return f"20 번호 흔적 '{w}'"
    try:
        rendered = _SPACE.sub(" ", facts.render(t))
    except (RenderError, KeyError):
        return None
    # 낱말 묶음 반복은 렌더한 글에서, 같은 조각 반복은 모델이 쓴 글(자리표시 밖)에서만 본다(이름·ID 글자 제외)
    m = _REPEAT_WORDS.search(rendered) or _REPEAT_CHUNK.search(_SPACE.sub("", stripped))
    if m:
        return f"21 같은 말 반복 '{m.group(1)}'"
    return None


@dataclass
class Ctx:
    facts: Facts
    allowed: set[str]                       # 이 호출에 준 사실 번호
    scope: set[str] | None = None           # 인용 중 하나는 여기 있어야 함(None이면 범위 검사 안 함)
    grams: set[str] = field(default_factory=set)   # 표본 글 8자 조각
    eval_check: bool = False                # 22 비교 근거 없는 평가(사용자 이유에만 켬)


def sample_grams(texts: list[str], n: int = wording.OVERLAP_CHARS) -> set[str]:
    grams = set()
    for t in texts:
        t = _SPACE.sub(" ", t or "")
        for i in range(len(t) - n + 1):
            g = t[i:i + n]
            if g.strip() and not set(g) <= set("# /[]"):
                grams.add(g)
    return grams


def _bare(text: str) -> str:
    return _SPACE.sub(" ", PH.sub("", text)).strip()


def check_line(line, ctx: Ctx) -> tuple[str | None, dict | None]:
    """반환 (버린 사유 또는 None, 정리한 문장 {'t','c'})."""
    if not isinstance(line, dict) or not isinstance(line.get("t"), str) or not isinstance(line.get("c", []), list):
        return "형식 오류", None
    t = drop_label_echo(line["t"].strip().lstrip("-·• ").strip(), ctx.facts).strip()
    cites = [c for c in line.get("c") or [] if isinstance(c, str)]
    phs = [(m.group(1), m.group(2)) for m in PH.finditer(t)]
    if not t:
        return "빈 문장", None
    # 1
    if not cites and not phs:
        return "1 인용 없음", None
    # 2
    for fid in [*cites, *(p for p, _ in phs)]:
        if fid not in ctx.allowed or fid not in ctx.facts:
            return f"2 없는 번호 {fid}", None
    # 3
    cites = list(dict.fromkeys([*cites, *(p for p, _ in phs)]))
    # 4
    if "{" in PH.sub("", t) or "}" in PH.sub("", t):
        return "4 자리표시 꼴", None
    for fid, form in phs:
        f = ctx.facts.get(fid)
        if form is not None and form not in FORMS.get(f["type"], ()):
            return f"4 꼴·형식 {fid}|{form}", None
        try:
            ctx.facts.render_one(fid, form)
        except RenderError:
            return f"4 꼴·형식 {fid}|{form}", None
    # 5
    for m in PH.finditer(t):
        f = ctx.facts.get(m.group(1))
        if (f["type"] in NUMERIC or m.group(2) == "비율") and _UNIT_AFTER.match(t, m.end()):
            return f"5 단위 겹침 {m.group(0)}", None
    bare = _bare(t)
    stripped = PH.sub(" ", t)
    # 6
    d = _DIGITISH.search(stripped)
    if d:
        return f"6 숫자 '{d.group(0)}'", None
    # 7~11
    hit = wording.find_banned(stripped)
    if hit:
        return f"{hit[0]} 금지어 '{hit[1]}'", None
    # 12
    if ctx.scope is not None and not set(cites) & ctx.scope:
        return "12 섹션 범위", None
    # 13
    if len(bare) > wording.MAX_CHARS:
        return f"13 길이 {len(bare)}", None
    # 14
    if wording.TRACE_TAG_RE.search(stripped) or wording.TRACE_ADDR_RE.search(stripped):
        return "14 사용자 글 흔적", None
    if ctx.grams:
        s = _SPACE.sub(" ", bare)
        n = wording.OVERLAP_CHARS
        for i in range(len(s) - n + 1):
            if s[i:i + n] in ctx.grams:
                return "14 표본 글 겹침", None
    # 18~21
    why = check_evasion(t, ctx.facts)
    if why:
        return why, None
    # 22·23 (사용자 이유만)
    if ctx.eval_check:
        why = check_comparison(t, phs, cites, ctx.facts)
        if why:
            return why, None
        if phs and all(form == "값" for _, form in phs) and not _HANGUL.search(stripped):
            return "23 이름표 없는 값", None
    return None, {"t": t, "c": cites}


# ---------------------------------------------------------------- 22 비교 근거 없는 평가 (보조, 2026-10-16)
# 사용자 이유 '…가 많음' 오채택(설계 v3 측정 10장): 평가 낱말은 비교 근거(분모 비율·이전 대비 변화·몫 사실)를
# 인용할 때만 둔다. 낱말 하나만 막지 않는다 - 근거가 있으면 통과. '높음·낮음'은 등급 이름이라 보지 않는다

_EVAL = re.compile(r"(?<![가-힣])(?:많(?:음|다|은|아|이|고|았)|적(?:음|다|은|어|었)|잦(?:음|다|은|아)|드물|빈번|과다|다수|상당수|두드러)")
_COMPARE_FORMS = ("비율", "변화")
_HANGUL = re.compile(r"[가-힣]")
_COMPARE_TYPES = ("share", "rate")


def check_comparison(t: str, phs, cites, facts: Facts) -> str | None:
    m = _EVAL.search(PH.sub(" ", t))
    if not m:
        return None
    if any(form in _COMPARE_FORMS for _, form in phs):
        return None
    if any(c in facts and facts.get(c)["type"] in _COMPARE_TYPES for c in cites):
        return None
    return f"22 비교 근거 없는 평가 '{m.group(0)}'"


def filter_lines(lines, ctx: Ctx, *, section: str = "") -> tuple[list[dict], list[dict]]:
    """여러 문장 검사 + 17 중복. 반환 (남은 문장, 버린 기록[{section, line, why}])."""
    kept, dropped = [], []
    for line in lines or []:
        why, clean = check_line(line, ctx)
        if why is None:
            dup = next((k for k in kept if set(k["c"]) == set(clean["c"]) and _similar(k["t"], clean["t"])), None)
            if dup is not None:
                why = "17 중복"
        if why is None:
            kept.append(clean)
        else:
            text = line.get("t") if isinstance(line, dict) else str(line)
            dropped.append({"section": section, "line": str(text)[:200], "why": why})
    return kept, dropped


def _similar(a: str, b: str) -> bool:
    na, nb = _SPACE.sub("", a), _SPACE.sub("", b)
    return na == nb or SequenceMatcher(None, na, nb).ratio() >= 0.8


# ---------------------------------------------------------------- 15 등급 범위 (사용자)

LEVELS = ("높음", "중간", "낮음")
TOP_FACTS = ("SECRET", "CRED", "RETRY")


def check_level(uid: str, level: str, rule_level: str, kept: list[dict]) -> tuple[str, str | None]:
    """최종 등급과 바꾼 사유. 규칙 등급과 두 단계 차이 금지, '높음'은 기밀 차단·인증정보·차단 뒤 재시도 인용 필수."""
    if level not in LEVELS:
        return rule_level, "15 등급 값"
    if abs(LEVELS.index(level) - LEVELS.index(rule_level)) >= 2:
        return rule_level, "15 규칙 등급과 두 단계 차이"
    if level == "높음":
        cited = {c for line in kept for c in line["c"]}
        if not any(f"{uid}.{x}" in cited for x in TOP_FACTS):
            return rule_level, "15 근거 없는 높음"
    return level, None


# ---------------------------------------------------------------- 16 조치 대상 (권고)

def check_action(action: str, target: str, allowed: dict[str, list[str]]) -> str | None:
    """allowed: 그 이슈에 고를 수 있는 조치 → 대상 후보(대상 없는 조치는 ['NONE']). 어기면 사유."""
    if action not in allowed:
        return f"16 이슈에 없는 조치 {action}"
    if target not in allowed[action]:
        return f"16 조치 대상 {action}→{target}"
    return None


# ---------------------------------------------------------------- 사건 순위 검사 (4.6-b)

def check_order(order, rule_ids: list[str], grade1: set[str], keep: int) -> tuple[list[str], str | None]:
    """중복·없는 번호 제거, 빠진 후보는 규칙 순서로 뒤에. 등급 1 사건이 keep 안에 다 못 들면 규칙 순위로 되돌림."""
    seen, out = set(), []
    for x in order if isinstance(order, list) else []:
        if isinstance(x, str) and x in rule_ids and x not in seen:
            seen.add(x)
            out.append(x)
    note = None
    if len(out) < len(rule_ids):
        note = "빠진 후보 규칙 순서로 붙임"
    out += [x for x in rule_ids if x not in seen]
    if len(grade1) <= keep and not grade1 <= set(out[:keep]):
        return list(rule_ids), "등급 1 사건 탈락 → 규칙 순위"
    return out, note
