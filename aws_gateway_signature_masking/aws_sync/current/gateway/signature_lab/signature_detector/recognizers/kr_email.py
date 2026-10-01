from presidio_analyzer import (
    Pattern,
    PatternRecognizer,
)

kr_email_pattern = Pattern(
    name="kr_email_pattern",
    regex=r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])",
    score=0.90,
)

kr_email_recognizer = PatternRecognizer(
    supported_entity="EMAIL_ADDRESS",
    patterns=[kr_email_pattern],
    supported_language="en",
)