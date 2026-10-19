"""프로젝트 전체에서 공유하는 Presidio Analyzer 설정."""

from presidio_analyzer import AnalyzerEngine

from signature_detector.recognizers.kr_dob import KRDateOfBirthRecognizer
from signature_detector.recognizers.kr_email import kr_email_recognizer
from signature_detector.recognizers.kr_foreign_rrn import KRForeignRegistrationNumberRecognizer
from signature_detector.recognizers.kr_phone import kr_phone_recognizer
from signature_detector.recognizers.kr_rrn import KRRRNRecognizer

TARGET_ENTITIES = [
    "EMAIL_ADDRESS",
    "KR_PHONE_NUMBER",
    "KR_DATE_OF_BIRTH",
    "KR_RRN",
    "KR_FOREIGN_REGISTRATION_NUMBER",
]


def create_analyzer() -> AnalyzerEngine:
    """등록 규칙이 일관된 Analyzer 인스턴스를 만든다."""
    analyzer = AnalyzerEngine()
    # 기본 이메일 검증의 외부 캐시 의존성을 제거하고 프로젝트 규칙으로 대체한다.
    analyzer.registry.remove_recognizer("EmailRecognizer")
    analyzer.registry.add_recognizer(kr_email_recognizer)
    analyzer.registry.add_recognizer(kr_phone_recognizer)
    analyzer.registry.add_recognizer(KRDateOfBirthRecognizer())
    analyzer.registry.add_recognizer(KRRRNRecognizer())
    analyzer.registry.add_recognizer(KRForeignRegistrationNumberRecognizer())
    return analyzer
