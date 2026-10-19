import re
from datetime import date

from presidio_analyzer import EntityRecognizer, RecognizerResult


class KRRRNRecognizer(EntityRecognizer):

    SUPPORTED_ENTITY = "KR_RRN"

    # 주민등록번호
    # YYMMDD-XXXXXXX / YYMMDDXXXXXXX
    # 뒤 첫 자리: 1~4
    RRN_PATTERN = re.compile(
        r"(?<!\d)"
        r"(\d{2})(\d{2})(\d{2})[- ]?([1-4])(\d{6})"
        r"(?!\d)"
    )

    CONTEXT_WORDS = [
        "주민등록번호",
        "주민번호",
        "주민등록",
        "rrn",
    ]

    def __init__(self):
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="en",
            name="KRRRNRecognizer",
        )

    def analyze(self, text, entities, nlp_artifacts=None):

        results = []

        if self.SUPPORTED_ENTITY not in entities:
            return results

        for match in self.RRN_PATTERN.finditer(text):

            year_2digit = int(match.group(1))
            month = int(match.group(2))
            day = int(match.group(3))
            discriminator = int(match.group(4))

            # ------------------------------------------
            # 1, 2 → 1900년대
            # 3, 4 → 2000년대
            # ------------------------------------------

            if discriminator in [1, 2]:
                year = 1900 + year_2digit

            elif discriminator in [3, 4]:
                year = 2000 + year_2digit

            else:
                continue

            # ------------------------------------------
            # 실제 생년월일 검증
            # ------------------------------------------

            try:
                birth_date = date(
                    year,
                    month,
                    day
                )
            except ValueError:
                continue

            # 미래 날짜 제외
            if birth_date > date.today():
                continue

            # ------------------------------------------
            # Context 확인
            # ------------------------------------------

            context_window = 30

            context_start = max(
                0,
                match.start() - context_window
            )

            context_end = min(
                len(text),
                match.end() + context_window
            )

            context_text = text[
                context_start:context_end
            ].lower()

            has_context = any(
                keyword.lower() in context_text
                for keyword in self.CONTEXT_WORDS
            )

            # 구조 자체가 강하므로 Context는 필수 아님
            score = 0.95 if has_context else 0.85

            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=score,
                )
            )

        return results
