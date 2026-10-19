import re
from datetime import date

from presidio_analyzer import (
    EntityRecognizer,
    RecognizerResult,
)


class KRDateOfBirthRecognizer(EntityRecognizer):

    SUPPORTED_ENTITY = "KR_DATE_OF_BIRTH"

    MAX_AGE = 120

    # 강한 DOB 레이블
    STRONG_CONTEXTS = [
        "생년월일",
        "출생일",
        "dob",
        "date of birth",
    ]

    # 약한 DOB 레이블
    # 단독 사용 시 오탐 가능성이 있어서 Key-Value 형태에서만 허용
    WEAK_CONTEXTS = [
        "생일",
    ]

    # 일반 날짜 표현
    DATE_PATTERN = re.compile(
        r"(?<!\d)"
        r"((?:19|20)\d{2})[.\-/](\d{1,2})[.\-/](\d{1,2})"
        r"(?!\d)"
    )

    # 한국어 날짜 표현
    KOREAN_DATE_PATTERN = re.compile(
        r"(?<!\d)"
        r"((?:19|20)\d{2})년\s*"
        r"(\d{1,2})월\s*"
        r"(\d{1,2})일"
        r"(?!\d)"
    )

    # 다른 날짜 의미를 가진 레이블
    NEGATIVE_DATE_CONTEXTS = [
        "작성일",
        "입사일",
        "계약일",
        "면접일",
        "면접일시",
        "퇴사일",
        "발행일",
        "신청일",
        "회의일",
    ]

    def __init__(self):
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="en",
            name="KRDateOfBirthRecognizer",
        )

    def analyze(self, text, entities, nlp_artifacts=None):

        results = []

        if self.SUPPORTED_ENTITY not in entities:
            return results

        lowered_text = text.lower()

        # --------------------------------------------------
        # 1. DOB 레이블 후보 찾기
        # --------------------------------------------------

        context_matches = []

        for context in self.STRONG_CONTEXTS:
            for match in re.finditer(
                re.escape(context.lower()),
                lowered_text,
            ):
                context_matches.append(
                    {
                        "start": match.start(),
                        "end": match.end(),
                        "type": "strong",
                    }
                )

        # 생일은 ":" "|" "=" 등이 뒤따르는 필드 형태만 허용
        for context in self.WEAK_CONTEXTS:

            pattern = re.compile(
                rf"{re.escape(context)}\s*(?:[:|=]|은|는)"
            )

            for match in pattern.finditer(lowered_text):
                context_matches.append(
                    {
                        "start": match.start(),
                        "end": match.end(),
                        "type": "weak",
                    }
                )

        if not context_matches:
            return results

        # --------------------------------------------------
        # 2. 문장 안의 모든 날짜 후보 수집
        # --------------------------------------------------

        date_candidates = []

        for pattern in [
            self.DATE_PATTERN,
            self.KOREAN_DATE_PATTERN,
        ]:

            for match in pattern.finditer(text):

                year = int(match.group(1))
                month = int(match.group(2))
                day = int(match.group(3))

                # 실제 존재하는 날짜인지 검증
                try:
                    detected_date = date(
                        year,
                        month,
                        day,
                    )
                except ValueError:
                    continue

                today = date.today()

                # 미래 날짜 제외
                if detected_date > today:
                    continue

                # 최대 나이 검증
                age = (
                    today.year
                    - detected_date.year
                    - (
                        (today.month, today.day)
                        <
                        (detected_date.month, detected_date.day)
                    )
                )

                if age > self.MAX_AGE:
                    continue

                date_candidates.append(
                    {
                        "match": match,
                        "date": detected_date,
                    }
                )

        if not date_candidates:
            return results

        # --------------------------------------------------
        # 3. DOB 레이블별 가장 가까운 뒤쪽 날짜 선택
        # --------------------------------------------------

        MAX_CONTEXT_DISTANCE = 20

        selected_spans = set()

        for context in context_matches:

            candidates_after_context = []

            for candidate in date_candidates:

                match = candidate["match"]

                # DOB 레이블보다 앞에 있는 날짜는 제외
                if match.start() < context["end"]:
                    continue

                distance = match.start() - context["end"]

                # 너무 멀리 떨어져 있으면 제외
                if distance > MAX_CONTEXT_DISTANCE:
                    continue

                # ------------------------------------------
                # 4. DOB context와 날짜 사이에
                #    다른 날짜 레이블이 존재하면 제외
                # ------------------------------------------

                between_text = lowered_text[
                    context["end"]:match.start()
                ]

                has_negative_context = any(
                    negative in between_text
                    for negative in self.NEGATIVE_DATE_CONTEXTS
                )

                if has_negative_context:
                    continue

                candidates_after_context.append(
                    (
                        distance,
                        candidate,
                    )
                )

            if not candidates_after_context:
                continue

            # 가장 가까운 날짜 하나만 선택
            candidates_after_context.sort(
                key=lambda item: item[0]
            )

            _, selected = candidates_after_context[0]

            match = selected["match"]

            span = (
                match.start(),
                match.end(),
            )

            # 같은 날짜 중복 탐지 방지
            if span in selected_spans:
                continue

            selected_spans.add(span)

            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=0.90,
                )
            )

        return results