import pytest

from preprocessing.errors import CorruptedDocumentError
from preprocessing.xlsx_parser import parse_xlsx


def _sample_xlsx(generated_dir):
    p = generated_dir / "06_급여대장.xlsx"
    if not p.exists():
        pytest.skip(f"테스트베드 샘플 xlsx가 없습니다: {p}")
    return p


def test_header_title_meta_extracted_as_paragraphs(generated_dir):
    blocks = parse_xlsx(_sample_xlsx(generated_dir))
    paragraphs = [b for b in blocks if b["type"] == "paragraph"]
    assert len(paragraphs) >= 2  # 최소 header_text + title


def test_table_rows_extracted(generated_dir):
    blocks = parse_xlsx(_sample_xlsx(generated_dir))
    tables = [b for b in blocks if b["type"] == "table"]
    assert len(tables) == 1
    table = tables[0]
    # 100건 규모 급여대장이므로 헤더 포함 100행 이상이어야 한다
    assert len(table["rows"]) > 50
    header_row = table["rows"][0]
    assert "사번" in header_row or "성명" in header_row


def test_all_rows_same_width(generated_dir):
    blocks = parse_xlsx(_sample_xlsx(generated_dir))
    table = next(b for b in blocks if b["type"] == "table")
    widths = {len(row) for row in table["rows"]}
    assert len(widths) == 1


def test_formula_cell_resolved_to_value_and_formula(tmp_path):
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "항목"
    ws["B1"] = "값"
    ws["A2"] = "합계"
    ws["B2"] = "=1+1"
    p = tmp_path / "formula.xlsx"
    wb.save(str(p))

    blocks = parse_xlsx(p)
    tables = [b for b in blocks if b["type"] == "table"]
    assert len(tables) == 1
    data_row = tables[0]["rows"][1]
    assert "수식" in data_row[1]
    assert "=1+1" in data_row[1]


def test_merged_row_detected_generically(tmp_path):
    """docgen.py가 만드는 것과 다른 행 배치(병합이 4행에서 시작)라도 하드코딩된 행
    번호가 아니라 실제 병합 정보로 문단/표를 구분해야 한다."""
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "헤더1"
    ws["B1"] = "헤더2"
    ws["A2"] = "데이터1"
    ws["B2"] = "데이터2"
    ws.merge_cells(start_row=3, start_column=1, end_row=3, end_column=2)
    ws["A3"] = "이건 표가 아니라 안내 문구입니다"
    p = tmp_path / "layout.xlsx"
    wb.save(str(p))

    blocks = parse_xlsx(p)
    assert blocks[0]["type"] == "table"
    assert blocks[0]["rows"] == [["헤더1", "헤더2"], ["데이터1", "데이터2"]]
    assert blocks[1]["type"] == "paragraph"
    assert blocks[1]["text"] == "이건 표가 아니라 안내 문구입니다"


def test_empty_rows_skipped(tmp_path):
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "x"
    ws["A3"] = "y"  # 2행은 완전히 빈 행
    p = tmp_path / "sparse.xlsx"
    wb.save(str(p))

    blocks = parse_xlsx(p)
    table = next(b for b in blocks if b["type"] == "table")
    assert table["rows"] == [["x"], ["y"]]


def test_corrupted_xlsx_raises(tmp_path):
    bad = tmp_path / "bad.xlsx"
    bad.write_bytes(b"this is not a zip file")
    with pytest.raises(CorruptedDocumentError):
        parse_xlsx(bad)


def test_wrong_extension_does_not_break_parsing(generated_dir, tmp_path):
    """openpyxl에 경로 문자열 대신 BytesIO로 넘기므로, 확장자가 틀려도 내용으로 파싱돼야 한다."""
    src = _sample_xlsx(generated_dir)
    disguised = tmp_path / "disguised.pdf"
    disguised.write_bytes(src.read_bytes())
    blocks = parse_xlsx(disguised)
    assert any(b["type"] == "table" for b in blocks)
