"""FR-PRE-002 PDF 파싱: 기호·하이픈 정규화 및 압축된 내용의 자연어 문장화.

PDF는 DOCX와 달리 논리적 문단 구조를 저장하지 않는다 - 페이지 레이아웃 상의 줄바꿈만
남아 있어서, 그대로 추출하면 한 문장이 여러 줄로 쪼개진 채 넘어온다("압축된 내용").
이 모듈은 두 단계로 나눠 처리한다.

  1. PyMuPDF(fitz)로 페이지별 원시 텍스트/표를 추출한다.
  2. _reconstruct_paragraphs()가 줄바꿈을 문장/문단 경계와 줄바꿈-랩(wrap)을 구분해
     실제 문단 단위 문장으로 재조립하고, 영문 하이픈 개행(word-\\nword)을 복원한다.

암호화 여부는 pypdf로 먼저 확인한다.

주의 - PyMuPDF는 AGPL-3.0(또는 Artifex 상용 라이선스) 라이브러리다. 이 파일은 실험/데모
환경에서 pdfplumber 대비 성능(특히 벡터그래픽이 많은 PDF)을 검증하려고 임시로 바꾼
버전이다. 상용 배포 전에는 pdfplumber(MIT)로 되돌리거나 Artifex 상용 라이선스를
구매해야 한다 - `llm-dlp-design.html`과 `CLAUDE_CODE_PROMPT.md` 14번 참고.
"""

from __future__ import annotations

import re
from pathlib import Path

import fitz  # PyMuPDF
import pypdf
from pypdf.errors import PdfReadError

from .errors import CorruptedDocumentError, EncryptedDocumentError

_BULLET_START_RE = re.compile(r"^\s*([-•▪◦‣*]|\d+[.)]|[가나다라마][.)]|\([0-9가-힣]+\))\s+")
_SENTENCE_END_RE = re.compile(r"[.!?:다요함음됨죠]$")
_HYPHEN_WRAP_RE = re.compile(r"[A-Za-z]-$")


def _check_encryption(path: Path) -> None:
    try:
        reader = pypdf.PdfReader(str(path))
    except PdfReadError as e:
        raise CorruptedDocumentError(f"손상된 PDF입니다: {path.name}") from e
    except Exception as e:  # pypdf raises plain Exception for some malformed headers
        raise CorruptedDocumentError(f"PDF를 열 수 없습니다: {path.name}") from e

    if reader.is_encrypted:
        try:
            result = reader.decrypt("")
        except Exception as e:
            raise EncryptedDocumentError(f"암호로 보호된 PDF입니다: {path.name}") from e
        if result == pypdf.PasswordType.NOT_DECRYPTED:
            raise EncryptedDocumentError(f"암호로 보호된 PDF입니다: {path.name}")


def _normalize_symbols(line: str) -> str:
    """PDF 추출 과정에서 흔한 깨짐 기호를 정규화한다 (ligature/soft hyphen 등)."""
    replacements = {
        "ﬁ": "fi", "ﬂ": "fl",  # 합자(ligature) 글리프
        "­": "",                     # soft hyphen
        "": "",                     # form feed (페이지 구분자 잔재)
    }
    for src, dst in replacements.items():
        line = line.replace(src, dst)
    return line


def _reconstruct_paragraphs(raw_text: str) -> list[str]:
    """페이지 원시 텍스트의 줄바꿈을 문단 경계/줄-wrap으로 구분해 재조립한다."""
    paragraphs: list[str] = []
    current = ""

    for raw_line in raw_text.split("\n"):
        line = _normalize_symbols(raw_line).strip()
        if not line:
            if current:
                paragraphs.append(current)
                current = ""
            continue

        if not current:
            current = line
            continue

        if _HYPHEN_WRAP_RE.search(current):
            # 영문 하이픈 개행: "word-" + "word" -> "wordword" (하이픈 제거 후 결합)
            current = current[:-1] + line
        elif _SENTENCE_END_RE.search(current) or _BULLET_START_RE.match(line):
            # 이전 줄이 문장을 끝맺었거나, 새 줄이 목록 항목으로 시작 -> 문단 구분
            paragraphs.append(current)
            current = line
        else:
            # 같은 문단이 레이아웃상 줄바꿈된 것 -> 공백으로 이어붙여 한 문장으로 문장화
            current = current + " " + line

    if current:
        paragraphs.append(current)

    return paragraphs


def parse_pdf(path: str | Path) -> list[dict]:
    """PDF를 순서 보존 Block dict 리스트로 반환한다.

    반환되는 각 dict는 pipeline.Block으로 감싸지기 전 원시 형태다:
      {"type": "paragraph"|"table", "level": None, "text": str|None,
       "rows": list[list[str]]|None, "page": int}
    """
    path = Path(path)
    _check_encryption(path)

    blocks: list[dict] = []

    try:
        doc = fitz.open(str(path))
        try:
            if doc.page_count == 0:
                raise CorruptedDocumentError(f"페이지가 없는 PDF입니다: {path.name}")

            for page_idx, page in enumerate(doc, start=1):
                raw_text = page.get_text("text")
                for paragraph in _reconstruct_paragraphs(raw_text):
                    blocks.append(
                        {"type": "paragraph", "level": None, "text": paragraph, "rows": None, "page": page_idx}
                    )

                for table in page.find_tables().tables:
                    rows = [[cell or "" for cell in row] for row in table.extract()]
                    if any(any(cell.strip() for cell in row) for row in rows):
                        blocks.append(
                            {"type": "table", "level": None, "text": None, "rows": rows, "page": page_idx}
                        )
        finally:
            doc.close()
    except (CorruptedDocumentError, EncryptedDocumentError):
        raise
    except Exception as e:
        raise CorruptedDocumentError(f"PDF 파싱 중 오류가 발생했습니다: {path.name} ({e})") from e

    return blocks
