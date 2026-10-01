"""문서 추출 및 마스킹 기능."""

from signature_detector.document.docx_sanitizer import sanitize_docx
from signature_detector.document.extractor import extract_docx

__all__ = ["extract_docx", "sanitize_docx"]
