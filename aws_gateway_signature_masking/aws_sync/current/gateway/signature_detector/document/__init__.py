"""Gateway 문서 세그먼트 추출 및 안전한 재구성."""

from signature_detector.document.file_segments import (
    extract_docx_segments,
    extract_xlsx_segments,
    sanitize_docx_bytes,
    sanitize_xlsx_bytes,
)

__all__ = [
    "extract_docx_segments",
    "extract_xlsx_segments",
    "sanitize_docx_bytes",
    "sanitize_xlsx_bytes",
]
