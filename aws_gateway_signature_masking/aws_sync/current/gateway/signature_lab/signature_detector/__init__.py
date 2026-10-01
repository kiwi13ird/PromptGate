"""한국형 PII 탐지 및 문서 마스킹 도구."""

from signature_detector.analyzer import TARGET_ENTITIES, create_analyzer

__all__ = ["TARGET_ENTITIES", "create_analyzer"]
