import pytest

from preprocessing.docx_parser import parse_docx
from preprocessing.errors import CorruptedDocumentError


def test_header_footer_extracted(sample_docx):
    blocks = parse_docx(sample_docx)
    types = {b["type"] for b in blocks}
    assert "header" in types
    assert "footer" in types
    header = next(b for b in blocks if b["type"] == "header")
    assert "대외비" in header["text"]


def test_table_extracted_with_rows(sample_docx):
    blocks = parse_docx(sample_docx)
    tables = [b for b in blocks if b["type"] == "table"]
    assert len(tables) >= 1
    approval_table = tables[0]
    assert approval_table["rows"][0] == ["기안", "검토", "승인"]


def test_reading_order_preserved(sample_docx):
    """머리말 다음 -> 본문 순으로, 본문 내에서는 원본 문서 순서(문단/표 교차)가 유지되어야 한다."""
    blocks = parse_docx(sample_docx)
    body_types = [b["type"] for b in blocks if b["type"] not in ("header", "footer")]
    # 승인선 표(approval line) 바로 뒤에 제목 문단이 와야 한다 (docgen.py 조립 순서)
    assert body_types[0] == "table"
    assert body_types[1] == "paragraph"


def test_all_paragraphs_nonempty(sample_docx):
    blocks = parse_docx(sample_docx)
    for b in blocks:
        if b["type"] in ("paragraph", "heading"):
            assert b["text"].strip() != ""


def test_corrupted_docx_raises(tmp_path):
    bad = tmp_path / "bad.docx"
    bad.write_bytes(b"this is not a zip file")
    with pytest.raises(CorruptedDocumentError):
        parse_docx(bad)
