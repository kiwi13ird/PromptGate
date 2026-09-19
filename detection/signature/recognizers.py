"""AWS Detection Server용 경량 PII/Credential 인식기.

외부 NLP 모델이나 Presidio 없이 표준 라이브러리만 사용한다. 운영 응답과 로그에는
매치된 값 자체를 넣지 않고 :class:`signature.engine.Hit`의 위치와 종류만 전달한다.
MVP 정책은 적중 1건 이상이면 기존 pipeline이 BLOCK으로 집행하는 것이다.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Callable, Pattern

from .engine import Hit

Validator = Callable[[re.Match[str]], bool]


class RegexRecognizer:
    def __init__(
        self,
        entity_type: str,
        pattern: str,
        score: float,
        *,
        flags: int = 0,
        validator: Validator | None = None,
        negative_contexts: tuple[str, ...] = (),
        required_contexts: tuple[str, ...] = (),
    ) -> None:
        self.entity_type = entity_type
        self._pattern: Pattern[str] = re.compile(pattern, flags)
        self._score = score
        self._validator = validator
        self._negative_contexts = tuple(x.lower() for x in negative_contexts)
        self._required_contexts = tuple(x.lower() for x in required_contexts)

    def analyze(self, text: str) -> list[Hit]:
        hits: list[Hit] = []
        lowered = text.lower()
        for match in self._pattern.finditer(text):
            if self._validator is not None and not self._validator(match):
                continue
            before = lowered[max(0, match.start() - 20) : match.start()]
            if any(context in before for context in self._negative_contexts):
                continue
            surrounding = lowered[max(0, match.start() - 30) : min(len(text), match.end() + 30)]
            if self._required_contexts and not any(context in surrounding for context in self._required_contexts):
                continue
            hits.append(Hit(self.entity_type, match.start(), match.end(), self._score))
        return hits


def _valid_registration_number(match: re.Match[str]) -> bool:
    year_2digit = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    discriminator = int(match.group(4))
    year = (1900 if discriminator in (1, 2, 5, 6) else 2000) + year_2digit
    try:
        return date(year, month, day) <= date.today()
    except ValueError:
        return False


def _valid_date_of_birth(match: re.Match[str]) -> bool:
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3))) <= date.today()
    except ValueError:
        return False


PII_RECOGNIZERS = (
    RegexRecognizer(
        "KR_RRN",
        r"(?<!\d)(\d{2})(\d{2})(\d{2})[- ]?([1-4])(\d{6})(?!\d)",
        0.95,
        validator=_valid_registration_number,
    ),
    RegexRecognizer(
        "KR_FOREIGN_REGISTRATION_NUMBER",
        r"(?<!\d)(\d{2})(\d{2})(\d{2})[- ]?([5-8])(\d{6})(?!\d)",
        0.95,
        validator=_valid_registration_number,
    ),
    RegexRecognizer(
        "KR_PHONE_NUMBER",
        r"(?<!\d)(?:010(?:[- .]?\d{4}){2}|\+82[- .]?10[- .]?\d{4}[- .]?\d{4})(?!\d)",
        0.90,
        negative_contexts=("문서번호", "사번", "계약번호", "문서 id", "문서id", "document id"),
    ),
    RegexRecognizer(
        "EMAIL_ADDRESS",
        r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])",
        0.90,
    ),
    RegexRecognizer(
        "KR_DATE_OF_BIRTH",
        r"(?<!\d)(\d{4})[-./](\d{1,2})[-./](\d{1,2})(?!\d)",
        0.85,
        validator=_valid_date_of_birth,
        negative_contexts=("계약일", "작성일", "발행일", "기준일"),
        required_contexts=("생년월일", "생일", "출생일", "date of birth", "dob"),
    ),
)
