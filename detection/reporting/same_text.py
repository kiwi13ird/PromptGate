"""'문서와 같은 글자' 비율 - 대시보드와 같은 값(2026-10-16 '일치 비율' 통일, 보고서 쪽).

정의: 보낸 입력의 공백 뺀 글자 중 보호 문서와 같은 글자의 비율(같은 글자 수 ÷ 입력 글자 수). 화면용 가림 6종(토큰·키·
주민번호·전화·메일)을 적용한 뒤 가린 연속 구간 하나를 한 글자로 센다. 대조할 본문이 없거나, Detection이 확인한 문장
위치가 대조 결과의 다른 구간에 들어가거나, 계산 한도를 넘으면 '대조 불가'(해시 근거 비율로 대신하지 않음).

대시보드 서버 코드를 줄 단위로 옮겼다(값이 같아야 하므로 알고리즘·순서·경계 조건까지 그대로):
  - match-ratio.mjs (화면 src/utils/matchRatio.ts · textDiff.ts · redactedText.ts 묶음, 원본 md5 59b7db26 · 2f609814 · bb0a1082)
  - match-evidence.mjs redactEvidence · findMatchingPassages · evidenceDocument · buildMatchEvidence(비교 상태) · maskedBody · comparisonBodies
  - postgres-event-store.mjs #evidenceRows(판정 기록·문서·보존본 조회) · same-text.mjs(탐지마다 결과, 없으면 '대조할 본문 없음')
좌표는 Python 문자(코드 포인트) = JS Array.from 단위. JS 정규식 \\s·\\b·\\d 범위를 그대로 맞췄다(아래 _WS, re.ASCII).
알려진 차이 하나: 계산 한도는 두 쪽 모두 벽시계 시간이다(대시보드 1.5초, 여기 BUDGET_S). 운영 실측 대시보드 최대 113ms.
"""

from __future__ import annotations

import hashlib
import math
import re
import time

TEXT_LIMIT = 2_000_000          # match-evidence.mjs TEXT_LIMIT (SQL에서 이보다 긴 본문은 NULL)
BUDGET_S = 30.0                 # 대시보드 budgetMs 1500(JS). 파이썬은 느리므로 넉넉히 - 운영 자료는 대시보드에서 한도에 닿은 적 없음
MASK_TOKEN = chr(0xE000)          # 가린 덩어리 표지(화면 redactedText.ts와 같은 글자)
SAME_RATIO_NAME = "문서와 같은 글자"
UNAVAILABLE_LABEL = "대조 불가"
NO_BODY = "대조할 본문 없음"

# JS 정규식 \s(u 플래그 유무 같음): WhiteSpace + LineTerminator
_WS_RANGE = "\\t\\n\\x0b\\x0c\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
_WS = "[" + _WS_RANGE + "]"
_WS_CHARS = frozenset("".join(map(chr, (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF)))
                      + "".join(chr(c) for c in range(0x2000, 0x200B)))
_WS_SUB = re.compile(_WS)

# match-evidence.mjs redactEvidence - 순서·플래그 그대로(JS \b·\d는 ASCII → re.ASCII, \s는 위 _WS)
_REDACT = (
    re.compile(r"\b(?:Bearer" + _WS + r"+)[A-Za-z0-9._~+/-]+=*", re.IGNORECASE | re.ASCII),
    re.compile(r"(?:api[_ -]?key|access[_ -]?token|secret|password|비밀번호)" + _WS + r"*[=:]" + _WS
               + r"*[\"']?[^" + _WS_RANGE + r"\"',;]+", re.IGNORECASE | re.ASCII),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", re.ASCII),
    re.compile(r"\b\d{6}" + _WS + r"*[-–]?" + _WS + r"*[1-8]\d{6}\b", re.ASCII),
    re.compile(r"(?<!\d)(?:\+82[- .]?)?0?1[016789][- .]?\d{3,4}[- .]?\d{4}(?!\d)", re.ASCII),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.ASCII),
)
_SENTENCE_END = frozenset(".!?。")


def _block(m: re.Match) -> str:
    return "█" * len(m.group(0))


def redact(value) -> str:
    """대시보드 redactEvidence(화면용 가림). 글자 수는 그대로."""
    s = "" if value is None else str(value)
    for pattern in _REDACT:
        s = pattern.sub(_block, s)
    return s


def masked_body(text) -> dict:
    """match-evidence.mjs maskedBody: 가린 글 + 가린 구간(원문과 글자가 달라진 곳)."""
    original = "" if text is None else str(text)
    chars = redact(original)
    runs: list[list[int]] = []
    for at, (c, o) in enumerate(zip(chars, original)):
        if c == o:
            continue
        if runs and runs[-1][1] == at:
            runs[-1][1] = at + 1
        else:
            runs.append([at, at + 1])
    return {"text": chars, "runs": [{"start": s, "end": e} for s, e in runs]}


# ---------------------------------------------------------------- redactedText.ts

def collapse_redactions(original: str, runs: list[dict]) -> dict:
    n = len(original)
    sorted_runs = sorted((r for r in runs if r["end"] > r["start"]), key=lambda r: r["start"])
    units: list = []
    to_unit = [0] * (n + 1)
    at = 0
    for run in sorted_runs:
        start = max(at, min(n, run["start"]))
        end = max(start, min(n, run["end"]))
        while at < start:
            to_unit[at] = len(units)
            units.append(original[at])
            at += 1
        if end > start:
            while at < end:
                to_unit[at] = len(units)
                at += 1
            units.append(None)          # 가린 한 덩어리
    while at < n:
        to_unit[at] = len(units)
        units.append(original[at])
        at += 1
    to_unit[n] = len(units)
    return {"text": "".join(MASK_TOKEN if u is None else u for u in units), "to_unit": to_unit}


# ---------------------------------------------------------------- textDiff.ts

class _Prepared:
    __slots__ = ("at", "chars", "word_start", "words", "length")

    def __init__(self, text: str) -> None:
        at, chars, word_start, words = [], [], [], []
        current: list[str] = []
        for index, char in enumerate(text):
            if char in _WS_CHARS:
                if current:
                    words.append("".join(current))
                    current = []
                continue
            if not current:
                word_start.append(len(chars))
            current.append(char)
            at.append(index)
            chars.append(ord(char))
        if current:
            words.append("".join(current))
        word_start.append(len(chars))
        self.at, self.chars, self.word_start, self.words, self.length = at, chars, word_start, words, len(text)


class _State:
    __slots__ = ("timed_out", "deadline")

    def __init__(self, deadline: float) -> None:
        self.timed_out = False
        self.deadline = deadline


def _bisect(a, a_lo, a_hi, b, b_lo, b_hi, state):
    n = a_hi - a_lo
    m = b_hi - b_lo
    max_d = (n + m + 1) // 2           # Math.ceil((n+m)/2)
    offset = max_d
    length = 2 * max_d + 2
    v1 = [-1] * length
    v2 = [-1] * length
    v1[offset + 1] = 0
    v2[offset + 1] = 0
    delta = n - m
    front = delta % 2 != 0
    k1start = k1end = k2start = k2end = 0
    for d in range(max_d):
        if (d & 15) == 0 and time.perf_counter() > state.deadline:
            state.timed_out = True
            return None
        k1 = -d + k1start
        while k1 <= d - k1end:
            k1o = offset + k1
            if k1 == -d or (k1 != d and v1[k1o - 1] < v1[k1o + 1]):
                x1 = v1[k1o + 1]
            else:
                x1 = v1[k1o - 1] + 1
            y1 = x1 - k1
            while x1 < n and y1 < m and a[a_lo + x1] == b[b_lo + y1]:
                x1 += 1
                y1 += 1
            v1[k1o] = x1
            if x1 > n:
                k1end += 2
            elif y1 > m:
                k1start += 2
            elif front:
                k2o = offset + delta - k1
                if 0 <= k2o < length and v2[k2o] != -1 and x1 >= n - v2[k2o]:
                    return x1, y1
            k1 += 2
        k2 = -d + k2start
        while k2 <= d - k2end:
            k2o = offset + k2
            if k2 == -d or (k2 != d and v2[k2o - 1] < v2[k2o + 1]):
                x2 = v2[k2o + 1]
            else:
                x2 = v2[k2o - 1] + 1
            y2 = x2 - k2
            while x2 < n and y2 < m and a[a_lo + n - x2 - 1] == b[b_lo + m - y2 - 1]:
                x2 += 1
                y2 += 1
            v2[k2o] = x2
            if x2 > n:
                k2end += 2
            elif y2 > m:
                k2start += 2
            elif not front:
                k1o = offset + delta - k2
                if 0 <= k1o < length and v1[k1o] != -1:
                    x1 = v1[k1o]
                    y1 = offset + x1 - k1o
                    if x1 >= n - x2:
                        return x1, y1
            k2 += 2
    return None


def _changed_blocks(a, a_lo0, a_hi0, b, b_lo0, b_hi0, state) -> list[list[int]]:
    out: list[list[int]] = []         # [aLo, aHi, bLo, bHi]

    def push(a_lo, a_hi, b_lo, b_hi):
        if a_lo == a_hi and b_lo == b_hi:
            return
        if out and out[-1][1] == a_lo and out[-1][3] == b_lo:
            out[-1][1] = a_hi
            out[-1][3] = b_hi
        else:
            out.append([a_lo, a_hi, b_lo, b_hi])

    stack = [(a_lo0, a_hi0, b_lo0, b_hi0)]
    while stack:
        a_lo, a_hi, b_lo, b_hi = stack.pop()
        while a_lo < a_hi and b_lo < b_hi and a[a_lo] == b[b_lo]:
            a_lo += 1
            b_lo += 1
        while a_lo < a_hi and b_lo < b_hi and a[a_hi - 1] == b[b_hi - 1]:
            a_hi -= 1
            b_hi -= 1
        if a_lo == a_hi or b_lo == b_hi or state.timed_out:
            push(a_lo, a_hi, b_lo, b_hi)
            continue
        middle = _bisect(a, a_lo, a_hi, b, b_lo, b_hi, state)
        if not middle:
            push(a_lo, a_hi, b_lo, b_hi)
            continue
        x, y = middle
        stack.append((a_lo + x, a_hi, b_lo + y, b_hi))
        stack.append((a_lo, a_lo + x, b_lo, b_lo + y))
    return out


def _absorb(blocks: list[list[int]], len_a, len_b) -> list[list[int]]:
    out = [list(b) for b in blocks]
    index = 0
    while index < len(out) - 1:
        left, right = out[index], out[index + 1]
        equal = max(len_a(left[1], right[0]), len_b(left[3], right[2]))
        around_a = len_a(left[0], left[1]) + len_a(right[0], right[1])
        around_b = len_b(left[2], left[3]) + len_b(right[2], right[3])
        if equal <= around_a and equal <= around_b:
            out[index:index + 2] = [[left[0], right[1], left[2], right[3]]]
            index = max(0, index - 1)
        else:
            index += 1
    return out


def _js_get(arr, i):
    """JS 배열 읽기(범위 밖 = undefined)."""
    return arr[i] if 0 <= i < len(arr) else None


def _slide_one_sided(hunks: list[list[int]], a: _Prepared, b: _Prepared) -> None:
    def boundary(p: _Prepared, index: int) -> bool:
        return index <= 0 or index >= len(p.chars) or p.at[index] - p.at[index - 1] > 1

    for index, hunk in enumerate(hunks):
        a_lo, a_hi, b_lo, b_hi = hunk
        deletion = a_lo == a_hi and b_hi > b_lo
        insertion = b_lo == b_hi and a_hi > a_lo
        if not deletion and not insertion:
            continue
        side = b if deletion else a
        lo = b_lo if deletion else a_lo
        hi = b_hi if deletion else a_hi
        prev = hunks[index - 1] if index > 0 else None
        nxt = hunks[index + 1] if index + 1 < len(hunks) else None
        room_left = min(a_lo - (prev[1] if prev else 0), b_lo - (prev[3] if prev else 0))
        room_right = min((nxt[0] if nxt else len(a.chars)) - a_hi, (nxt[2] if nxt else len(b.chars)) - b_hi)
        left = 0
        while left < room_left and _js_get(side.chars, lo - left - 1) == _js_get(side.chars, hi - left - 1):
            left += 1
        right = 0
        while right < room_right and _js_get(side.chars, lo + right) == _js_get(side.chars, hi + right):
            right += 1
        best = 0
        best_score = -1
        for shift in range(-left, right + 1):
            start, end = lo + shift, hi + shift
            score = (4 if (start == 0 or end == len(side.chars)) else 0) + (1 if boundary(side, start) else 0) \
                + (1 if boundary(side, end) else 0)
            if score > best_score or (score == best_score and abs(shift) < abs(best)):
                best = shift
                best_score = score
        if not best:
            continue
        hunk[0] += best
        hunk[1] += best
        hunk[2] += best
        hunk[3] += best


def _to_ranges(p: _Prepared, changed: bytearray) -> list[tuple[int, int]]:
    ranges: list[list[int]] = []
    for index, flag in enumerate(changed):
        if not flag:
            continue
        start = p.at[index]
        if ranges and index > 0 and changed[index - 1]:
            ranges[-1][1] = start + 1
        else:
            ranges.append([start, start + 1])
    return [(s, e) for s, e in ranges]


def diff_ignoring_whitespace(a_text: str, b_text: str, *, budget_s: float = BUDGET_S) -> dict:
    """textDiff.ts diffIgnoringWhitespace - 단어 대조 뒤 바뀐 단어 구간 안에서 글자 대조, 짧은 우연 일치 흡수."""
    state = _State(time.perf_counter() + budget_s)
    a = _Prepared(a_text)
    b = _Prepared(b_text)
    ids: dict[str, int] = {}

    def wid(word: str) -> int:
        v = ids.get(word)
        if v is None:
            v = len(ids)
            ids[word] = v
        return v

    a_words = [wid(w) for w in a.words]
    b_words = [wid(w) for w in b.words]
    a_changed = bytearray(len(a.chars))
    b_changed = bytearray(len(b.chars))
    aws, bws = a.word_start, b.word_start

    def a_len(lo, hi):
        return aws[hi] - aws[lo]

    def b_len(lo, hi):
        return bws[hi] - bws[lo]

    def span(lo, hi):
        return hi - lo

    word_blocks = _absorb(_changed_blocks(a_words, 0, len(a_words), b_words, 0, len(b_words), state), a_len, b_len)
    compact: list[list[int]] = []

    def add(block):
        if compact and compact[-1][1] == block[0] and compact[-1][3] == block[2]:
            compact[-1][1] = block[1]
            compact[-1][3] = block[3]
        else:
            compact.append(list(block))

    for blk in word_blocks:
        a_from, a_to = aws[blk[0]], aws[blk[1]]
        b_from, b_to = bws[blk[2]], bws[blk[3]]
        if a_from == a_to or b_from == b_to or state.timed_out:
            add([a_from, a_to, b_from, b_to])
            continue
        for inner in _absorb(_changed_blocks(a.chars, a_from, a_to, b.chars, b_from, b_to, state), span, span):
            add(inner)
    _slide_one_sided(compact, a, b)
    for h in compact:
        a_changed[h[0]:h[1]] = b"\x01" * (h[1] - h[0])
        b_changed[h[2]:h[3]] = b"\x01" * (h[3] - h[2])

    def rng(p: _Prepared, lo: int, hi: int):
        return (p.at[lo], p.at[hi - 1] + 1) if hi > lo else None

    first_same = b_changed.find(0)
    last_same = b_changed.rfind(0)
    return {
        "a": _to_ranges(a, a_changed), "b": _to_ranges(b, b_changed),
        "a_changed": sum(a_changed), "b_changed": sum(b_changed),
        "a_chars": len(a.chars), "b_chars": len(b.chars),
        "complete": not state.timed_out,
        "hunks": [(rng(a, h[0], h[1]), rng(b, h[2], h[3])) for h in compact],
        "b_span": (b.at[first_same], b.at[last_same] + 1) if first_same >= 0 else None,
    }


# ---------------------------------------------------------------- matchRatio.ts

def _js_gt0(value) -> bool:
    """JS `value > 0` (숫자·숫자 글만 의미 있음)."""
    if value is None or isinstance(value, bool):
        return bool(value) and value > 0
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def diff_distrust(diff: dict, comparison: dict, maps: dict | None) -> str | None:
    if not diff["complete"]:
        return "본문이 길어 계산 한도를 넘어"

    def mp(table, loc):
        if not table:
            return loc
        last = len(table) - 1
        return {"char_start": table[min(loc["char_start"], last)], "char_end": table[min(loc["char_end"], last)]}

    def covered(ranges, loc):
        return loc["char_end"] > loc["char_start"] and any(s <= loc["char_start"] and e >= loc["char_end"] for s, e in ranges)

    for passage in comparison.get("matching_passages") or []:
        if covered(diff["a"], mp((maps or {}).get("input"), passage["input_location"])) \
                or covered(diff["b"], mp((maps or {}).get("document"), passage["document_location"])):
            return "서버가 같은 글로 확인한 문장과 대조 결과가 맞지 않아"
    if _js_gt0(comparison.get("coverage")) and diff["a_chars"] > 0 and diff["a_changed"] == diff["a_chars"]:
        return "서버 일치 비율과 대조 결과가 맞지 않아"
    return None


def difference_count(diff: dict) -> int:
    span = diff["b_span"]
    return sum(1 for ha, hb in diff["hunks"]
               if ha or (hb and span and hb[1] > span[0] and hb[0] < span[1]))


def compute_match_ratio(input_body: dict, document_body: dict, comparison: dict, *, budget_s: float = BUDGET_S) -> dict:
    """matchRatio.ts computeMatchRatio → matchRatioSummary 모양: READY {same_chars, input_chars, differences} · UNAVAILABLE {reason}."""
    left = collapse_redactions(input_body["text"], input_body["runs"])
    right = collapse_redactions(document_body["text"], document_body["runs"])
    diff = diff_ignoring_whitespace(left["text"], right["text"], budget_s=budget_s)
    reason = diff_distrust(diff, comparison, {"input": left["to_unit"], "document": right["to_unit"]})
    if reason:
        return {"state": "UNAVAILABLE", "reason": reason}
    return {"state": "READY", "same_chars": diff["a_chars"] - diff["a_changed"], "input_chars": diff["a_chars"],
            "differences": difference_count(diff)}


def ratio_of(same_chars: int, input_chars: int) -> float:
    return same_chars / input_chars if input_chars else 0


def summary_ratio(summary: dict | None) -> float | None:
    """READY면 같은 글자 ÷ 입력 글자, 아니면 None."""
    if not summary or summary.get("state") != "READY":
        return None
    return ratio_of(summary["same_chars"], summary["input_chars"])


def format_same_ratio(ratio: float) -> str:
    """matchRatio.ts formatSameRatio: 소수 첫째 자리 내림, 다른 글자가 있으면 100%로 올리지 않음."""
    value = 100.0 if ratio >= 1 else min(math.floor(ratio * 1000) / 10, 99.9)
    return f"{value:,.1f}%"


def format_summary(summary: dict | None) -> str:
    r = summary_ratio(summary)
    return UNAVAILABLE_LABEL if r is None else format_same_ratio(r)


# ---------------------------------------------------------------- match-evidence.mjs (본문·비교 상태)

def _js_truthy(v) -> bool:
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0 and not (isinstance(v, float) and math.isnan(v))
    if isinstance(v, str):
        return v != ""
    return True                        # 객체·배열은 비어 있어도 참


def _is_int(v) -> bool:
    """JS Number.isInteger."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and v.is_integer()


def _js_str(v) -> str:
    """JS 템플릿 문자열의 값 표기(정수인 실수는 소수점 없이)."""
    if v is None:
        return "undefined"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _safe_number(v):
    if v is None or isinstance(v, bool):
        return None if v is None else (float(v) if v >= 0 else None)
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) and x >= 0 else None


def _span_ok(loc, size: int) -> bool:
    if not _js_truthy(loc) or not isinstance(loc, dict):
        return False
    s, e = loc.get("char_start"), loc.get("char_end")
    return _is_int(s) and _is_int(e) and s >= 0 and e > s and e <= size


def find_matching_passages(inp: str, doc: str, input_location: dict, document_location: dict) -> list[dict]:
    """match-evidence.mjs findMatchingPassages(위치만 - 같은 글자 비율의 '대조 불가' 판단에 쓰임)."""
    left, right = inp, doc
    if not _span_ok(input_location, len(left)) or not _span_ok(document_location, len(right)):
        return []
    safe_input = redact(inp)
    ds, de = int(document_location["char_start"]), int(document_location["char_end"])
    doc_end = min(de, ds + 120000)
    compact_chars, coord = [], []
    for i in range(ds, doc_end):
        if right[i] in _WS_CHARS:
            continue
        compact_chars.append(right[i])
        coord.append(i)
    compact_doc = "".join(compact_chars)
    candidates = []
    i_s, i_e = int(input_location["char_start"]), int(input_location["char_end"])
    end = min(i_e, i_s + 120000)
    start = i_s

    def candidate(begin, stop):
        while begin < stop and left[begin] in _WS_CHARS:
            begin += 1
        while stop > begin and left[stop - 1] in _WS_CHARS:
            stop -= 1
        if 32 <= stop - begin <= 360:
            candidates.append((begin, stop, left[begin:stop]))

    for at in range(start, end):
        length = at - start
        nxt = left[at + 1] if at + 1 < len(left) else " "
        if left[at] == "\n" or (left[at] in _SENTENCE_END and nxt in _WS_CHARS) or (length >= 220 and left[at] in _WS_CHARS):
            candidate(start, at + 1)
            start = at + 1
    candidate(start, end)
    passages = []
    stride = max(1, len(candidates) // 30)
    index = 0
    while index < len(candidates) and len(passages) < 8:
        c_start, c_end, text = candidates[index]
        index += stride
        needle = _WS_SUB.sub("", text)
        if _utf16_len(needle) < 24:
            continue
        found = compact_doc.find(needle)
        if found < 0 or compact_doc.find(needle, found + 1) >= 0:
            continue
        doc_start, doc_stop = coord[found], coord[found + len(needle) - 1] + 1
        left_text = safe_input[c_start:c_end]
        if _utf16_len(re.sub("[█" + _WS_RANGE + "]", "", left_text)) < 24:
            continue
        passages.append({"input_location": {"char_start": c_start, "char_end": c_end},
                         "document_location": {"char_start": doc_start, "char_end": doc_stop}})
    return passages


def _utf16_len(s: str) -> int:
    return len(s) + sum(1 for ch in s if ord(ch) > 0xFFFF)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _num_eq(a, b) -> bool:
    """JS Number(a) === b."""
    try:
        return a is not None and b is not None and not isinstance(b, bool) and float(a) == float(b)
    except (TypeError, ValueError):
        return False


def evidence_document(decision: dict, documents: list[dict], doc_id) -> dict | None:
    ref = decision.get("document_ref")
    if not _js_truthy(ref):
        return next((d for d in documents if d.get("doc_id") == doc_id and d.get("evidence_source") != "EVENT_DOCUMENT_VERSION"), None)
    if not isinstance(ref, dict) or ref.get("basis") != "STABLE_INDEX_VERSION" or ref.get("doc_id") != doc_id:
        return None
    for d in documents:
        if (d.get("doc_id") == doc_id and d.get("evidence_source") == "EVENT_DOCUMENT_VERSION"
                and _num_eq(d.get("version"), ref.get("version")) and d.get("normalized_sha256") == ref.get("normalized_sha256")
                and (not isinstance(d.get("normalized_text"), str) or _sha256(d["normalized_text"]) == ref.get("normalized_sha256"))):
            return d
    return None


def window_docs(event: dict) -> list:
    """same-text.mjs windowDocs: 문서 구간 일치(WINDOW_HASH) 탐지의 문서(순서 유지, 중복 제거)."""
    out = []
    for d in event.get("detections") or []:
        if isinstance(d, dict) and d.get("detector") == "WINDOW_HASH" and _js_truthy(d.get("matched_document_id")):
            if d["matched_document_id"] not in out:
                out.append(d["matched_document_id"])
    return out


def archived_ref(event: dict, decisions: list[dict]) -> tuple | None:
    """postgres-event-store #evidenceRows: 판정 당시 보존본을 찾을 조건이면 (doc_id, version, sha256)."""
    if len(decisions) != 1:
        return None
    ref = decisions[0].get("document_ref")
    ids = [d.get("matched_document_id") for d in event.get("detections") or [] if isinstance(d, dict) and d.get("detector") == "WINDOW_HASH"]
    if not isinstance(ref, dict) or ref.get("basis") != "STABLE_INDEX_VERSION" or ref.get("doc_id") not in ids:
        return None
    v = ref.get("version")
    if not (_is_int(v) and abs(v) <= 2 ** 53 - 1):
        return None
    sha = ref.get("normalized_sha256")
    if not (isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha)):
        return None
    return ref["doc_id"], int(v), sha


def comparison_bodies(event: dict, decisions: list[dict], documents: list[dict]) -> list[dict]:
    """match-evidence.mjs buildMatchEvidence(비교 상태 부분) + comparisonBodies."""
    if not _js_truthy(event.get("request_id")) or not decisions:
        return []
    if len(decisions) != 1 or decisions[0].get("request_id") != event.get("request_id"):
        return []                                                   # AMBIGUOUS
    decision = decisions[0]
    by = decision.get("decided_by")
    detector = "WINDOW_HASH" if by == "windowhash" else "SIGNATURE" if by == "signature" else None
    detections = event.get("detections") or []
    outcome = event.get("detection_outcome")
    if (outcome == "UNAVAILABLE"
            or (outcome == "MATCH" and not any(isinstance(d, dict) and d.get("detector") == detector for d in detections))
            or (outcome == "NO_MATCH" and detector)):
        return []                                                   # MISMATCH
    prompt = decision.get("prompt")
    out = []
    for detection in detections:
        if not isinstance(detection, dict) or detection.get("detector") != "WINDOW_HASH":
            continue
        doc_id = detection.get("matched_document_id")
        document = evidence_document(decision, documents, doc_id)
        exp_in, exp_doc = detection.get("input_location"), detection.get("matched_location")
        if (decision.get("doc_id") != doc_id or not _js_truthy(exp_in) or not _js_truthy(exp_doc)
                or decision.get("input_span") != f"{_js_str(_get(exp_in, 'char_start'))}-{_js_str(_get(exp_in, 'char_end'))}"
                or decision.get("doc_span") != f"{_js_str(_get(exp_doc, 'char_start'))}-{_js_str(_get(exp_doc, 'char_end'))}"):
            continue                                                # MISMATCH
        pc, dc = _safe_number(decision.get("prompt_chars")), _safe_number((document or {}).get("normalized_chars"))
        if (pc is not None and pc > TEXT_LIMIT) or (dc is not None and dc > TEXT_LIMIT):
            continue                                                # TOO_LARGE
        doc_text = (document or {}).get("normalized_text")
        if not (_js_truthy(decision.get("prompt_kept")) and isinstance(prompt, str) and isinstance(doc_text, str)):
            continue                                                # NOT_RECORDED
        if not _span_ok(exp_in, len(prompt)) or not _span_ok(exp_doc, len(doc_text)):
            continue                                                # INVALID_RANGE (가림은 글자 수를 바꾸지 않음)
        comparison = {"document_id": doc_id, "coverage": detection.get("score"),
                      "matching_passages": find_matching_passages(prompt, doc_text, exp_in, exp_doc)}
        out.append({"document_id": doc_id, "comparison": comparison, "prompt": prompt, "document": doc_text})
    return out


def _get(obj, key):
    return obj.get(key) if isinstance(obj, dict) else None


def event_same_text(event: dict, decisions: list[dict], documents: list[dict], *, cache: dict | None = None,
                    budget_s: float = BUDGET_S) -> dict:
    """same-text.mjs: 이벤트의 문서 구간 일치 탐지 문서마다 결과 {doc_id: READY/UNAVAILABLE 요약}.
    문서 구간 일치가 없거나 요청 번호가 없으면 {} (대시보드도 붙이지 않음)."""
    if not _js_truthy(event.get("request_id")) or not isinstance(event.get("detections"), list):
        return {}
    docs = window_docs(event)
    if not docs:
        return {}
    results: dict = {}
    try:
        bodies = comparison_bodies(event, decisions, documents)
    except Exception:                                               # 대시보드 목록: 뒤 계산 실패 = 빈 결과
        bodies = []
    for body in bodies:
        c = body["comparison"]
        key = (_sha256(body["prompt"]), _sha256(body["document"]),
               tuple((p["input_location"]["char_start"], p["input_location"]["char_end"],
                      p["document_location"]["char_start"], p["document_location"]["char_end"]) for p in c["matching_passages"]),
               _js_gt0(c.get("coverage")))
        if cache is not None and key in cache:
            results[body["document_id"]] = cache[key]
            continue
        try:
            summary = compute_match_ratio(masked_body(body["prompt"]), masked_body(body["document"]), c, budget_s=budget_s)
        except Exception:
            summary = {"state": "UNAVAILABLE", "reason": "계산 오류"}
        if cache is not None and not (summary.get("state") == "UNAVAILABLE" and "한도" in summary.get("reason", "")):
            cache[key] = summary
        results[body["document_id"]] = summary
    return {doc: results.get(doc) or {"state": "UNAVAILABLE", "reason": NO_BODY} for doc in docs}
