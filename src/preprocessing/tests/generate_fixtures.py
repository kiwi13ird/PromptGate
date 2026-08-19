"""PDF 파서 테스트용 fixture를 생성한다.

reportlab이 없는 환경도 있어(이 저장소는 pymupdf가 항상 설치돼 있음을 확인했다)
PyMuPDF(fitz)로 직접 최소 PDF를 만든다. 단순 텍스트 삽입이라 docgen.py가 만드는
정식 문서 서식과는 무관하며, 오직 PDF 파서의 줄바꿈 재조립(하이픈 결합/문단 이어붙임)
로직을 검증하기 위한 용도다.

실행: python -m src.preprocessing.tests.generate_fixtures
"""

from pathlib import Path

import fitz

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _write_lines(path: Path, lines: list[str], fontname: str) -> None:
    doc = fitz.open()
    page = doc.new_page()
    y = 72
    for line in lines:
        if line:
            page.insert_text((72, y), line, fontsize=11, fontname=fontname)
        y += 16 if fontname == "helv" else 20
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    doc.save(str(path))


def generate():
    _write_lines(
        FIXTURES_DIR / "sample_en.pdf",
        [
            "Confidential Project Overview",
            "",
            "This document describes the overall archi-",
            "tecture of the internal recommen-",
            "dation engine that we are plan-",
            "ning to launch next quarter.",
            "",
            "- First bullet item here",
            "- Second bullet item here",
            "",
            "Please contact the security team",
            "if you have any questions.",
        ],
        fontname="helv",
    )

    _write_lines(
        FIXTURES_DIR / "sample_ko.pdf",
        [
            "기밀 프로젝트 개요",
            "",
            "본 문서는 사내망 환경에서 운영되는 추천",
            "엔진 시스템의 전체 아키텍처와 향후 확장",
            "계획을 설명한다.",
            "",
            "- 첫번째 항목입니다",
            "- 두번째 항목입니다",
            "",
            "문의사항은 보안팀으로 연락 바랍니다.",
        ],
        fontname="korea-s",
    )
    print(f"fixtures written to {FIXTURES_DIR}")


if __name__ == "__main__":
    generate()
