"""실행 위치와 무관한 프로젝트 경로."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_DIR = PROJECT_ROOT / "evaluation"
DATASETS_DIR = EVALUATION_DIR / "datasets"
DOCX_FIXTURES_DIR = EVALUATION_DIR / "fixtures" / "docx"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
SANITIZED_DIR = ARTIFACTS_DIR / "sanitized"
