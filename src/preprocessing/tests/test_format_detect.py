from preprocessing.format_detect import detect_format


def test_detect_pdf(fixtures_dir):
    p = fixtures_dir / "sample_en.pdf"
    if not p.exists():
        import pytest

        pytest.skip(f"PDF fixture가 없습니다: {p}")
    assert detect_format(p) == "pdf"


def test_detect_docx(sample_docx):
    assert detect_format(sample_docx) == "docx"


def test_detect_docx_with_wrong_extension(sample_docx, tmp_path):
    """확장자가 틀려도(.pdf라고 우겨도) 내용을 보고 docx로 판별해야 한다."""
    fake = tmp_path / "disguised.pdf"
    fake.write_bytes(sample_docx.read_bytes())
    assert detect_format(fake) == "docx"


def test_detect_xlsx(generated_dir):
    p = generated_dir / "06_급여대장.xlsx"
    if not p.exists():
        import pytest

        pytest.skip(f"xlsx 샘플이 없습니다: {p}")
    assert detect_format(p) == "xlsx"


def test_detect_plain_text(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("그냥 평범한 텍스트 파일입니다.", encoding="utf-8")
    assert detect_format(p) == "binary-unknown"


def test_detect_random_binary(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(bytes(range(256)))
    assert detect_format(p) == "binary-unknown"


def test_detect_generic_zip(tmp_path):
    import zipfile

    p = tmp_path / "archive.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "hello")
    assert detect_format(p) == "zip-unknown"
