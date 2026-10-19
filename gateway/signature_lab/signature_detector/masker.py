REPLACEMENTS = {
    "EMAIL_ADDRESS": "[EMAIL_ADDRESS]",
    "KR_PHONE_NUMBER": "[PHONE_NUMBER]",
    "KR_DATE_OF_BIRTH": "[DATE_OF_BIRTH]",
    "KR_RRN": "[RRN]",
    "KR_FOREIGN_REGISTRATION_NUMBER": "[FOREIGN_RRN]",
}


def mask_text(text, results):
    """
    Presidio RecognizerResult의 start/end를 기준으로
    민감정보를 Entity 이름으로 치환한다.
    """

    masked_text = text

    # 뒤쪽 span부터 치환해야 앞쪽 index가 안 깨짐
    sorted_results = sorted(
        results,
        key=lambda r: r.start,
        reverse=True,
    )

    for result in sorted_results:
        replacement = REPLACEMENTS.get(
            result.entity_type,
            "[MASKED]",
        )

        masked_text = (
            masked_text[:result.start]
            + replacement
            + masked_text[result.end:]
        )

    return masked_text
