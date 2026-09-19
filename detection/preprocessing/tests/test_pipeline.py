import pytest

from preprocessing.pipeline import parse_document


def test_docx_end_to_end_success(sample_docx):
    result = parse_document(sample_docx)
    assert result.success
    assert result.format == "docx"
    assert "대외비" in result.normalized_text
    assert result.error_type is None


def test_pdf_end_to_end_success(fixtures_dir):
    p = fixtures_dir / "sample_en.pdf"
    if not p.exists():
        pytest.skip(f"PDF fixture가 없습니다: {p}")
    result = parse_document(p)
    assert result.success
    assert result.format == "pdf"
    assert "architecture" in result.normalized_text


def test_unsupported_extension_is_fr_pre_008():
    result = parse_document("memo.txt")
    assert result.success is False
    assert result.error_type == "UnsupportedFormatError"


def test_xlsx_end_to_end_success(generated_dir):
    p = generated_dir / "06_급여대장.xlsx"
    if not p.exists():
        pytest.skip(f"xlsx 샘플이 없습니다: {p}")
    result = parse_document(p)
    assert result.success
    assert result.format == "xlsx"
    assert result.error_type is None


def test_corrupted_xlsx_does_not_raise(tmp_path):
    p = tmp_path / "dummy.xlsx"
    p.write_bytes(b"placeholder")
    result = parse_document(p)
    assert result.success is False
    assert result.error_type == "CorruptedDocumentError"


def test_missing_file_reported():
    result = parse_document("this/path/does/not/exist.docx")
    assert result.success is False
    assert result.error_type == "FileNotFoundError"


def test_corrupted_docx_does_not_raise(tmp_path):
    """FR-PRE-007: 파싱 실패는 예외로 전체 요청을 끊지 않고 실패 사유를 기록해야 한다."""
    bad = tmp_path / "bad.docx"
    bad.write_bytes(b"not a docx")
    result = parse_document(bad)
    assert result.success is False
    assert result.error_type == "CorruptedDocumentError"
    assert result.error_message


def test_normalization_applied_across_document(sample_docx):
    """정규화가 전체 문서에 일괄 적용되어, 파서 단계의 원시 공백/기호가 남지 않아야 한다."""
    result = parse_document(sample_docx)
    assert "　" not in result.normalized_text  # 전각 공백
    assert " " not in result.normalized_text  # NBSP
