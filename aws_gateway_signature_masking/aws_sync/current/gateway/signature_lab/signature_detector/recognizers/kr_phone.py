import re

from presidio_analyzer import (
    EntityRecognizer,
    RecognizerResult,
)


class KRPhoneNumberRecognizer(EntityRecognizer):

    SUPPORTED_ENTITY = "KR_PHONE_NUMBER"

    # 지원 형식
    # 010-1234-5678
    # 010 1234 5678
    # 010.1234.5678
    # 01012345678
    # +82-10-1234-5678
    PHONE_PATTERN = re.compile(
        r"(?<!\d)"
        r"(?:"
        r"010(?:[- .]?\d{4}){2}"
        r"|"
        r"\+82[- .]?10[- .]?\d{4}[- .]?\d{4}"
        r")"
        r"(?!\d)"
    )

    NEGATIVE_CONTEXTS = [
        "문서번호",
        "사번",
        "계약번호",
        "문서 id",
        "문서id",
        "document id",
    ]

    def __init__(self):
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="en",
            name="KRPhoneNumberRecognizer",
        )

    def analyze(self, text, entities, nlp_artifacts=None):

        results = []

        if self.SUPPORTED_ENTITY not in entities:
            return results

        lowered_text = text.lower()

        for match in self.PHONE_PATTERN.finditer(text):

            # ------------------------------------------
            # 후보 앞쪽 문맥 확인
            # ------------------------------------------

            context_window = 20

            context_start = max(
                0,
                match.start() - context_window,
            )

            before_text = lowered_text[
                context_start:match.start()
            ]

            # 강한 negative label이 바로 앞에 있으면 제외
            has_negative_context = any(
                context in before_text
                for context in self.NEGATIVE_CONTEXTS
            )

            if has_negative_context:
                continue

            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=0.90,
                )
            )

        return results


kr_phone_recognizer = KRPhoneNumberRecognizer()