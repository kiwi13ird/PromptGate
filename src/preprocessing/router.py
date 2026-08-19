"""FR-GW-005(입력 유형 식별) 개념을 흉내낸 통합 입력 라우터.

실제 시스템에서는 게이트웨이가 OpenAI API 요청 Body를 보고 자연어/문서를 나누지만,
이 테스트베드에는 아직 게이트웨이가 없다. process_input()은 그 앞단이 있다고 가정하고
"입력이 자연어든 PDF든 DOCX든, 뭐가 됐든 하나의 함수에 넣으면 정규화까지 끝난
ParsedDocument가 나온다"를 보장한다.

라우팅 규칙:
  1. 존재하는 파일 경로  -> 파일 내용(매직바이트, format_detect.py)으로 실제 포맷 판별
       pdf  -> pdf_parser.parse_pdf()  -> 정규화
       docx -> docx_parser.parse_docx() -> 정규화
       xlsx -> xlsx_parser.parse_xlsx() -> 정규화
       그 외(포맷 시그니처가 안 잡힘) -> UTF-8 텍스트로 읽어본다.
           읽히면 자연어 입력으로 간주해 정규화만 수행 (예: 순수 .txt 파일)
           안 읽히면 지원 대상이 아닌 바이너리로 보고 실패 반환 (FR-PRE-008)
  2. 존재하지 않는 경로(=파일이 아닌 일반 문자열) -> 자연어 입력으로 간주해 정규화만 수행

확장자는 판단에 전혀 관여하지 않는다 - 실제로 파일에 뭐가 들어있는지만 본다.
무엇이 들어오든 결과는 항상 pipeline.ParsedDocument 하나로 통일되므로, 다음 단계
(FR-PRE-006 병렬 분배)는 입력이 원래 자연어였는지 문서였는지 알 필요가 없다.
"""

from __future__ import annotations

from pathlib import Path

from .docx_parser import parse_docx
from .errors import UnsupportedFormatError
from .format_detect import detect_format
from .pdf_parser import parse_pdf
from .pipeline import ParsedDocument, build_text_document, run_parser
from .xlsx_parser import parse_xlsx

_CONTENT_PARSERS = {"pdf": parse_pdf, "docx": parse_docx, "xlsx": parse_xlsx}


def _is_existing_file(value: str) -> bool:
    try:
        p = Path(value)
        return p.exists() and p.is_file()
    except OSError:
        # 너무 길거나 유효하지 않은 경로 문자열 -> 파일이 아니라 그냥 텍스트로 취급
        return False


def process_input(value: str) -> ParsedDocument:
    """자연어 문자열 또는 PDF/DOCX(/XLSX) 파일 경로를 받아 정규화된 ParsedDocument를 만든다."""
    if not _is_existing_file(value):
        return build_text_document(value, source_label="<자연어 입력>")

    path = Path(value)
    fmt = detect_format(path)

    parser = _CONTENT_PARSERS.get(fmt)
    if parser is not None:
        return run_parser(parser, path, fmt)

    if fmt == "zip-unknown":
        # ZIP 시그니처는 있지만 docx/xlsx 내부 구조가 없다 - 손상된 docx/xlsx이거나
        # 지원 대상이 아닌 다른 zip 기반 포맷(pptx, odt, 일반 zip 등)이다. 둘 다
        # "자연어로 읽어보자"가 아니라 명시적 실패로 다뤄야 한다.
        err = UnsupportedFormatError("zip (docx/xlsx 시그니처 없음 - 손상되었거나 지원 대상이 아님)")
        return ParsedDocument(
            path=str(path),
            format=fmt,
            success=False,
            error_type=type(err).__name__,
            error_message=str(err),
        )

    # pdf/docx/xlsx/zip 시그니처가 전부 아니었다 -> 일반 텍스트 파일일 가능성 -> 읽어서 자연어로 처리
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        err = UnsupportedFormatError(f"{fmt} (확장자: {path.suffix or '없음'})")
        return ParsedDocument(
            path=str(path),
            format=fmt,
            success=False,
            error_type=type(err).__name__,
            error_message=str(err),
        )

    return build_text_document(text, source_label=str(path))
