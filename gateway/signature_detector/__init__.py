"""한국형 PII 탐지 및 문서 마스킹 도구.

Analyzer 의존성은 실제 탐지기를 만들 때만 불러온다. 정책/재구성 모듈은 AWS Gateway와
Detection의 경량 테스트에서도 독립적으로 사용할 수 있어야 한다.
"""

__all__ = ["TARGET_ENTITIES", "create_analyzer"]


def __getattr__(name):
    if name in __all__:
        from signature_detector import analyzer

        return getattr(analyzer, name)
    raise AttributeError(name)
