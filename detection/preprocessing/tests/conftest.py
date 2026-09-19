import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GENERATED_DIR = Path(__file__).resolve().parents[3] / "test" / "testbed" / "generated"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def generated_dir() -> Path:
    return GENERATED_DIR


@pytest.fixture(scope="session")
def sample_docx(generated_dir) -> Path:
    p = generated_dir / "01_사업전략_방향_보고서.docx"
    if not p.exists():
        pytest.skip(f"테스트베드 샘플 문서가 없습니다: {p}")
    return p
