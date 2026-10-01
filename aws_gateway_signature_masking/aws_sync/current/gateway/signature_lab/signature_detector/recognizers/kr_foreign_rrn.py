import re
from datetime import date

from presidio_analyzer import EntityRecognizer, RecognizerResult


class KRForeignRegistrationNumberRecognizer(EntityRecognizer):

    SUPPORTED_ENTITY = "KR_FOREIGN_REGISTRATION_NUMBER"

    # YYMMDD-XXXXXXX / YYMMDDXXXXXXX
    # 뒤 첫 자리: 5, 6, 7, 8
    FOREIGN_RRN_PATTERN = re.compile(
        r"(?<!\d)"
        r"(\d{2})(\d{2})(\d{2})[- ]?([5-8])(\d{6})"
        r"(?!\d)"
    )

    CONTEXT_WORDS = [
        "외국인등록번호",
        "외국인번호",
        "외국인등록",
        "alien registration",
        "foreign registration",
    ]

    def __init__(self):
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="en",
            name="KRForeignRegistrationNumberRecognizer",
        )

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []

        if self.SUPPORTED_ENTITY not in entities:
            return results

        for match in self.FOREIGN_RRN_PATTERN.finditer(text):

            year_2digit = int(match.group(1))
            month = int(match.group(2))
            day = int(match.group(3))
            discriminator = int(match.group(4))

            # 5,6 -> 1900년대
            # 7,8 -> 2000년대
            if discriminator in [5, 6]:
                year = 1900 + year_2digit

            elif discriminator in [7, 8]:
                year = 2000 + year_2digit

            else:
                continue

            # 실제 생년월일인지 검증
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

            # Context 확인
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

            # 구조가 강한 식별자이므로 context는 보조
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

