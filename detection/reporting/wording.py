"""금지 낱말·문체 규칙 한 곳 (설계 v2 4.8 검사 7~11, 문체 메모 feedback_terse_report_style).

검사기(verify.py)와 프롬프트(prompts/common.txt의 {{BANNED}})가 같은 목록을 쓴다 - 둘이 어긋나면
LLM은 허용된 줄 알고 쓴 말이 검사에서 버려진다.
"""

from __future__ import annotations

import re

# 7. 숫자 낱말 - 수 + 단위, 양 표현. 숫자는 자리표시가 쓴다
NUMBER_WORDS = ("한", "두", "세", "네", "다섯", "여섯", "일곱", "여덟", "아홉", "열", "스무", "몇", "여러",
                "수십", "수백", "수천", "십", "백", "천", "만")
COUNT_UNITS = ("건", "명", "번", "개", "차례", "종", "곳", "회", "가지", "일", "시간", "분")
QUANTITY_WORDS = ("절반", "대부분", "전부", "과반", "다수", "최다", "유일", "모두")
# 뒤에 조사가 붙어도 잡는다('두 건이'). 앞은 낱말 시작만('변경한 일'의 '한'은 수가 아님)
NUMBER_WORD_RE = re.compile(r"(?<![가-힣])(?:%s)\s?(?:%s)" % ("|".join(NUMBER_WORDS), "|".join(COUNT_UNITS)))
# 한 글자 수 낱말은 낱말 경계로만('인터넷'의 '넷', '리셋'의 '셋'은 수가 아님)
SHORT_NUMBER_RE = re.compile(r"(?<![가-힣])(?:하나|둘|셋|넷)(?![가-힣])")

# 8. 방향어 - 변화는 렌더러가 `|변화`로 쓴다
DIRECTION_WORDS = ("증가", "감소", "급증", "급감", "늘어", "늘었", "늘음", "줄어", "줄었", "줄음", "상승", "하락",
                   "높아", "낮아", "많아", "적어", "커졌", "작아")

# 9. 추정어·단정어 - 의도 추정, '유출됨' 단정 금지
GUESS_WORDS = ("의도", "고의", "악의", "추정", "보임", "듯", "가능성", "우려", "의심", "아마", "것으로",
               "유출됨", "유출되", "유출됐", "유출된", "유출했", "유출함",
               "수정 후", "고쳐서")   # 원문을 안 보므로 '수정 후 재시도'라고 쓰지 않는다(설계 4.5)

# 10. 문체 - 서술조·질문·감탄
STYLE_WORDS = ("기간 동안", "에 달함", "에 해당함", "를 차지함", "을 차지함", "으로 나타남", "습니다", "입니다",
               "했다", "였다", "한다.", "?", "!", "？", "！")

# 11. 내부 용어 - 문서에 쓰지 않는 팀 내부 이름·직역어
INTERNAL_TERMS_KO = ("자격증명", "시그니처", "창 해시", "색인", "인덱서")
INTERNAL_TERMS_EN = ("SQL", "Redis", "windowhash", "allow", "mask", "block", "masked_text", "client_id",
                     "request_id", "event_id", "decisions", "pii_hits", "prompt")
INTERNAL_EN_RE = re.compile(r"(?<![A-Za-z])(?:%s)(?![A-Za-z])" % "|".join(INTERNAL_TERMS_EN), re.IGNORECASE)

# 14. 사용자 글 흔적
TRACE_TAG_RE = re.compile(r"\[[A-Z][A-Z_]{2,}\]|\[KR_")
TRACE_ADDR_RE = re.compile(r"@|https?://|www\.|\b[\w-]+\.(?:com|net|org|kr|io|co|ai|dev|app|gov|edu|jp)\b", re.IGNORECASE)
OVERLAP_CHARS = 8

MAX_CHARS = 80  # 13. 자리표시 뺀 글자 수


def banned_for_prompt() -> str:
    """프롬프트에 넣을 금지 목록 한 줄(검사기와 같은 목록)."""
    words = [*DIRECTION_WORDS[:12], *GUESS_WORDS[:11], "유출됨", *STYLE_WORDS[:8], *INTERNAL_TERMS_KO,
             "SQL", "Redis", "allow", "mask", "block"]
    seen, out = set(), []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return " · ".join(out) + " · 한·두·세+건·명 같은 수 낱말 · 절반·대부분·전부·최다"


def find_banned(text: str) -> tuple[int, str] | None:
    """검사 7~11. 걸리면 (검사 번호, 걸린 말). text는 자리표시를 지운 글."""
    m = NUMBER_WORD_RE.search(text) or SHORT_NUMBER_RE.search(text)
    if m:
        return 7, m.group(0)
    for w in QUANTITY_WORDS:
        if w in text:
            return 7, w
    for w in DIRECTION_WORDS:
        if w in text:
            return 8, w
    for w in GUESS_WORDS:
        if w in text:
            return 9, w
    for w in STYLE_WORDS:
        if w in text:
            return 10, w
    for w in INTERNAL_TERMS_KO:
        if w in text:
            return 11, w
    m = INTERNAL_EN_RE.search(text)
    if m:
        return 11, m.group(0)
    return None
