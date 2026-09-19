"""FR-PRE-002/003 파싱과 FR-PRE-001 정규화를 하나의 흐름으로 묶는다.

extract(문서별 파서) -> normalize(정규화 모듈) 순서로 실행하며, 이후 단계인 FR-PRE-005
(탐지 위치 인덱싱)/FR-PRE-006(탐지 모듈 병렬 분배)는 여기서 만들어지는 ParsedDocument를
입력으로 삼아 다음 작업에서 이어 붙인다.

파서가 던지는 예외(FR-PRE-007/008)는 여기서 잡아 success=False인 ParsedDocument로
변환한다 - 실패해도 예외로 요청 처리를 끊지 않고, 실패 사유를 구조화된 형태로 남겨
게이트웨이가 "정의된 기본 조치"를 적용할 수 있게 하기 위함이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .docx_parser import parse_docx
from .errors import (
    CorruptedDocumentError,
    DocumentParsingError,
    EncryptedDocumentError,
    UnsupportedFormatError,
)
from .indexer import IndexedDocument, build_index
from .normalizer import normalize_text
from .pdf_parser import parse_pdf
from .xlsx_parser import parse_xlsx

SUPPORTED_EXTENSIONS = {".pdf": parse_pdf, ".docx": parse_docx, ".xlsx": parse_xlsx}


@dataclass
class Block:
    """파서가 만든 원시 조각 1건 + 그 정규화 결과."""

    type: str  # heading | paragraph | table | header | footer
    raw_text: str | None
    normalized_text: str | None
    raw_rows: list[list[str]] | None
    normalized_rows: list[list[str]] | None
    level: int | None = None
    page: int | None = None
    section: int | None = None


@dataclass
class ParsedDocument:
    path: str
    format: str
    success: bool
    blocks: list[Block] = field(default_factory=list)
    normalized_text: str = ""
    index: IndexedDocument | None = None  # FR-PRE-005: locate(start, end)로 원문 위치 역추적
    error_type: str | None = None
    error_message: str | None = None

    def block_texts(self) -> list[str]:
        """표는 행 단위로 이어붙인 문자열, 문단/제목은 그대로 - 인덱싱 단계 입력용."""
        out = []
        for b in self.blocks:
            if b.normalized_text is not None:
                out.append(b.normalized_text)
            elif b.normalized_rows is not None:
                out.extend(" | ".join(row) for row in b.normalized_rows)
        return out


def _normalize_rows(rows: list[list[str]] | None) -> list[list[str]] | None:
    if rows is None:
        return None
    return [[normalize_text(cell) for cell in row] for row in rows]


def to_blocks(raw_blocks: list[dict]) -> list[Block]:
    blocks = []
    for rb in raw_blocks:
        raw_text = rb.get("text")
        blocks.append(
            Block(
                type=rb["type"],
                raw_text=raw_text,
                normalized_text=normalize_text(raw_text) if raw_text is not None else None,
                raw_rows=rb.get("rows"),
                normalized_rows=_normalize_rows(rb.get("rows")),
                level=rb.get("level"),
                page=rb.get("page"),
                section=rb.get("section"),
            )
        )
    return blocks


def run_parser(parser, path: Path, fmt: str) -> ParsedDocument:
    """문서별 파서를 실행해 결과를 ParsedDocument로 감싼다.

    parse_document()(확장자 기반 라우팅)와 router.process_input()(콘텐츠 기반
    라우팅) 양쪽에서 포맷을 무엇으로 판별했든, 실제 파싱+정규화+인덱싱 처리는
    이 함수 하나로 통일한다.
    """
    try:
        raw_blocks = parser(path)
    except (EncryptedDocumentError, CorruptedDocumentError, DocumentParsingError) as e:
        return ParsedDocument(
            path=str(path),
            format=fmt,
            success=False,
            error_type=type(e).__name__,
            error_message=str(e),
        )

    blocks = to_blocks(raw_blocks)
    index = build_index(blocks)

    return ParsedDocument(
        path=str(path),
        format=fmt,
        success=True,
        blocks=blocks,
        normalized_text=index.text,
        index=index,
    )


def build_text_document(text: str, source_label: str = "<자연어 입력>") -> ParsedDocument:
    """자연어 입력을 문서 파서 없이 곧바로 정규화해 ParsedDocument로 감싼다.

    FR-GW-005가 "자연어"로 분류한 입력은 문서별 파서를 거칠 필요가 없다. 블록이
    하나뿐인 문서와 동일한 모양으로 만들어서, 문서 입력과 똑같은 인터페이스
    (ParsedDocument.normalized_text / .index)로 다음 단계에 넘길 수 있게 한다 -
    FR-PRE-006 이후 단계는 입력이 원래 자연어였는지 문서였는지 구분할 필요가 없어진다.
    """
    normalized = normalize_text(text)
    block = Block(
        type="paragraph",
        raw_text=text,
        normalized_text=normalized,
        raw_rows=None,
        normalized_rows=None,
    )
    index = build_index([block])
    return ParsedDocument(
        path=source_label,
        format="text",
        success=True,
        blocks=[block],
        normalized_text=index.text,
        index=index,
    )


def parse_document(path: str | Path) -> ParsedDocument:
    """문서를 파싱하고 정규화까지 수행한 ParsedDocument를 반환한다 (확장자 기반 라우팅).

    호출자가 이미 "이건 PDF/DOCX 파일이다"라고 알고 있는 상황(직접 지정한 파일 경로)을
    위한 함수다. 파일 내용이 아니라 확장자로 포맷을 정하므로 확장자가 틀리면 오판할 수
    있다 - 출처를 신뢰할 수 없는 자유 입력에는 router.process_input()을 쓴다.

    파싱/정규화 어느 단계에서 실패하더라도 예외를 던지지 않고 success=False로
    표시된 ParsedDocument를 반환한다 (FR-PRE-007/008: 실패 사유 기록).
    """
    path = Path(path)
    ext = path.suffix.lower()

    parser = SUPPORTED_EXTENSIONS.get(ext)
    if parser is None:
        err = UnsupportedFormatError(ext)
        return ParsedDocument(
            path=str(path),
            format=ext.lstrip(".") or "unknown",
            success=False,
            error_type=type(err).__name__,
            error_message=str(err),
        )

    if not path.exists():
        return ParsedDocument(
            path=str(path),
            format=ext.lstrip("."),
            success=False,
            error_type="FileNotFoundError",
            error_message=f"파일을 찾을 수 없습니다: {path}",
        )

    return run_parser(parser, path, ext.lstrip("."))
