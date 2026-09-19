"""FR-PRE-001 자연어 입력 정규화.

macOS(HFS+는 한글을 NFD 자모 분리형으로 저장), Notion(스마트 따옴표/특수 대시 자동
치환), DOCX(Windows, NFC 완성형) 등 서로 다른 환경에서 만들어진 입력이 시각적으로는
동일해 보여도 코드포인트 수준에서 달라, 이후 시그니처 정규식·해시 지문·임베딩 비교
단계에서 서로 다른 문자열로 취급되는 문제를 막기 위한 표준화 단계다.

검증 기준(SRS): "동일한 내용을 서로 다른 환경에서 작성한 입력에 대해 정규화 결과가
동일해야 한다" - 이 모듈의 유일한 책임은 그 동등성을 보장하는 것이다.

가독성을 위해 모든 특수 유니코드 문자는 리터럴이 아닌 \\uXXXX 이스케이프로 명시한다
(에디터/터미널마다 렌더링이 달라 리터럴로 쓰면 무슨 문자인지 육안 확인이 불가능하다).
"""

from __future__ import annotations

import re
import unicodedata

# 화면에는 보이지 않지만 문자열 비교/매칭을 깨뜨리는 문자들.
_ZERO_WIDTH_SPACE = "​"
_ZERO_WIDTH_NON_JOINER = "‌"
_ZERO_WIDTH_JOINER = "‍"
_BOM = "﻿"
_WORD_JOINER = "⁠"
_SOFT_HYPHEN = "­"
_INVISIBLE_CHARS = (
    _ZERO_WIDTH_SPACE
    + _ZERO_WIDTH_NON_JOINER
    + _ZERO_WIDTH_JOINER
    + _BOM
    + _WORD_JOINER
    + _SOFT_HYPHEN
)
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE_CHARS}]")

# C0/DEL 제어문자(탭/개행/캐리지리턴 제외 - 이미 위/아래 단계에서 의미 있게 처리됨).
# PDF 폰트의 ToUnicode 매핑이 깨진 글리프를 pdfplumber가 NUL(U+0000)로 뱉는 사례를
# 실제로 관측했다(예: "Command and Control)" 앞의 "(" 글리프) - 원래 글자를 복원할
# 방법은 없지만, 제어문자를 그대로 정규화 결과에 흘려보내면 이후 로그/탐지 모듈에서
# 문자열 처리 오류(널바이트로 인한 절단 등)를 일으킬 수 있어 제거한다.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# NBSP, 전각 공백, 유니코드 공백 블록(U+2000~U+200A), 좁은/중간 공백류
# -> 일반 공백(U+0020)으로 통일.
_SPACE_VARIANTS = (
    " "  # NO-BREAK SPACE
    "           "
    " "  # NARROW NO-BREAK SPACE
    " "  # MEDIUM MATHEMATICAL SPACE
    "　"  # IDEOGRAPHIC SPACE (전각 공백)
)
_SPACE_RE = re.compile(f"[\t{_SPACE_VARIANTS}]")

# 에디터별로 자동 치환되는(Notion 스마트 따옴표 등) 문자 -> 표준 ASCII/한국어 표기.
_QUOTE_MAP = {
    "‘": "'", "’": "'",   # ' '  (smart single quotes)
    "“": '"', "”": '"',   # " "  (smart double quotes)
    "′": "'", "″": '"',   # prime / double prime
}
_DASH_MAP = {
    "‐": "-", "‑": "-", "‒": "-",  # hyphen 계열
    "–": "-", "—": "-", "―": "-",  # en dash / em dash / horizontal bar
    "−": "-",                                 # minus sign
}
_BULLET_MAP = {
    "•": "-", "●": "-", "▪": "-", "◦": "-",
    "‣": "-", "⁃": "-", "·": "-",
}
_CHAR_MAP = {**_QUOTE_MAP, **_DASH_MAP, **_BULLET_MAP}
_CHAR_RE = re.compile("|".join(re.escape(c) for c in _CHAR_MAP))

_MULTI_SPACE_RE = re.compile(r"[ ]{2,}")
_MULTI_BLANK_LINE_RE = re.compile(r"\n{3,}")
_TRAILING_WS_RE = re.compile(r"[ \t]+\n")


def normalize_text(text: str) -> str:
    """공백·개행·특수문자·한글 표기(NFC/NFD)를 표준 형태로 통일한다.

    NFKC가 아닌 NFC(정준 결합)만 적용한다: 원 개연성 정보(예: 로마 숫자, 반각 기호가
    실제로 다른 의미를 가지는 경우)를 보존하면서 macOS(NFD)-Windows(NFC) 간 자모
    분리/완성형 차이만 제거하는 것이 FR-PRE-001의 범위다.
    """
    if not text:
        return ""

    # 1) 개행 통일 (CRLF/CR -> LF)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # 2) 유니코드 정규화: NFD(macOS) / NFC(Windows·DOCX) 표기 차이 제거
    text = unicodedata.normalize("NFC", text)

    # 3) 보이지 않는 문자 / 제어문자 제거
    text = _INVISIBLE_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)

    # 4) 공백류 통일
    text = _SPACE_RE.sub(" ", text)

    # 5) 따옴표/대시/불릿 기호 표준화
    text = _CHAR_RE.sub(lambda m: _CHAR_MAP[m.group(0)], text)

    # 6) 줄 끝 공백 제거, 연속 공백/빈 줄 축약
    text = _TRAILING_WS_RE.sub("\n", text)
    text = _MULTI_SPACE_RE.sub(" ", text)
    text = _MULTI_BLANK_LINE_RE.sub("\n\n", text)

    return text.strip()


def normalize_for_matching(text: str) -> str:
    """탐지 모듈(시그니처/해시)이 참조하는 완전 표준화 버전.

    normalize_text() 결과에서 한 걸음 더 나아가 공백 자체를 제거한다. 사용자가
    민감정보를 "010 - 1234 - 5678"처럼 공백/구두점을 끼워 넣어 정규식 우회를
    시도하는 경우를 대비한 보조 표현이며, 로그/표시용으로는 사용하지 않는다.
    """
    normalized = normalize_text(text)
    return re.sub(r"\s+", "", normalized)


def is_normalization_stable(text: str) -> bool:
    """이미 정규화된 텍스트인지 확인 (idempotency 점검용)."""
    return normalize_text(text) == text
