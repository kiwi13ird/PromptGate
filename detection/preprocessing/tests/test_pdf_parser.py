import pytest

from preprocessing.errors import CorruptedDocumentError, EncryptedDocumentError
from preprocessing.pdf_parser import parse_pdf


def _fixture(fixtures_dir, name):
    p = fixtures_dir / name
    if not p.exists():
        pytest.skip(f"PDF fixture가 없습니다: {p} (fixtures 생성 스크립트를 먼저 실행하세요)")
    return p


def test_dehyphenation_and_line_unwrap(fixtures_dir):
    """줄 끝 영문 하이픈은 제거·결합되고, 문단 내 줄바꿈(wrap)은 공백으로 합쳐져야 한다."""
    blocks = parse_pdf(_fixture(fixtures_dir, "sample_en.pdf"))
    paragraphs = [b["text"] for b in blocks if b["type"] == "paragraph"]
    joined = " ".join(paragraphs)
    assert "architecture" in joined
    assert "recommendation" in joined
    assert "planning" in joined
    assert "archi-" not in joined
    assert "recommen-" not in joined


def test_bullet_lines_kept_separate(fixtures_dir):
    blocks = parse_pdf(_fixture(fixtures_dir, "sample_en.pdf"))
    paragraphs = [b["text"] for b in blocks if b["type"] == "paragraph"]
    assert any(p.startswith("- First bullet") for p in paragraphs)


def test_korean_multiline_paragraph_joined(fixtures_dir):
    blocks = parse_pdf(_fixture(fixtures_dir, "sample_ko.pdf"))
    paragraphs = [b["text"] for b in blocks if b["type"] == "paragraph"]
    assert any("추천 엔진 시스템의 전체 아키텍처와 향후 확장 계획을 설명한다" in p for p in paragraphs)


def test_corrupted_pdf_raises(tmp_path):
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(b"%PDF-1.4 not a real pdf body")
    with pytest.raises(CorruptedDocumentError):
        parse_pdf(bad)
