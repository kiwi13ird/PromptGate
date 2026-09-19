import pytest

from preprocessing.router import process_input


def test_plain_sentence_routes_to_natural_language():
    result = process_input("이 문장은 파일이 아니라 그냥 자연어 입력입니다.")
    assert result.success
    assert result.format == "text"
    assert "자연어" in result.normalized_text


def test_docx_path_routes_to_docx_parser(sample_docx):
    result = process_input(str(sample_docx))
    assert result.success
    assert result.format == "docx"
    assert any(b.type == "table" for b in result.blocks)


def test_pdf_path_routes_to_pdf_parser(fixtures_dir):
    p = fixtures_dir / "sample_en.pdf"
    if not p.exists():
        pytest.skip(f"PDF fixture가 없습니다: {p}")
    result = process_input(str(p))
    assert result.success
    assert result.format == "pdf"
    assert "architecture" in result.normalized_text


def test_docx_with_wrong_extension_still_routes_correctly(sample_docx, tmp_path):
    """확장자가 아니라 내용으로 라우팅되는지 확인 - .txt로 위장한 docx도 docx로 파싱돼야 한다."""
    disguised = tmp_path / "disguised.txt"
    disguised.write_bytes(sample_docx.read_bytes())
    result = process_input(str(disguised))
    assert result.success
    assert result.format == "docx"


def test_plain_text_file_routes_to_natural_language(tmp_path):
    p = tmp_path / "memo.log"  # 확장자는 임의 - 내용으로만 판단
    p.write_text("메모 파일도 자연어로 처리되어야 합니다.", encoding="utf-8")
    result = process_input(str(p))
    assert result.success
    assert result.format == "text"
    assert "메모 파일도" in result.normalized_text


def test_xlsx_path_routes_to_xlsx_parser(generated_dir):
    p = generated_dir / "06_급여대장.xlsx"
    if not p.exists():
        pytest.skip(f"xlsx 샘플이 없습니다: {p}")
    result = process_input(str(p))
    assert result.success
    assert result.format == "xlsx"
    assert any(b.type == "table" for b in result.blocks)


def test_random_binary_file_is_unsupported(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(bytes(range(256)))
    result = process_input(str(p))
    assert result.success is False
    assert result.error_type == "UnsupportedFormatError"


def test_corrupted_zip_reported_not_raised(tmp_path):
    p = tmp_path / "fakezip.docx"
    # ZIP 시그니처는 맞지만 내부 구조가 없는 손상된 파일 - 자연어로 새지 않고
    # 명시적 실패로 처리되어야 한다.
    p.write_bytes(b"PK\x03\x04" + bytes(range(200, 256)))
    result = process_input(str(p))
    assert result.success is False
    assert result.error_type == "UnsupportedFormatError"


def test_generic_zip_is_unsupported_not_natural_language(tmp_path):
    import zipfile

    p = tmp_path / "archive.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "hello")
    result = process_input(str(p))
    assert result.success is False
    assert result.error_type == "UnsupportedFormatError"


def test_index_present_for_natural_language_input():
    result = process_input("탐지 위치 인덱싱도 자연어 입력에서 잘 되는지 확인.")
    assert result.index is not None
    pos = result.normalized_text.find("인덱싱")
    assert pos != -1
    loc = result.index.locate(pos, pos + 3)
    assert loc is not None
    assert loc.block_type == "paragraph"
