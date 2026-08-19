import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
# 사내 테스트베드 문서(합성 기밀문서 20종)는 이 공개 저장소에는 포함하지 않는다.
# 이 디렉터리에 같은 이름의 파일을 직접 넣지 않는 한, 이 픽스처를 쓰는 테스트는 자동으로 skip된다.
GENERATED_DIR = Path(__file__).resolve().parent / "fixtures" / "generated"


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
