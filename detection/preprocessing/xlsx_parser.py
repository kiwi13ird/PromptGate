"""FR-PRE-004 XLSX 파싱: 표 및 수식을 단순 자연어 배열 형태로 처리한다.

DOCX와 달리 XLSX는 "문단"이 없다 - 전부 셀이다. docgen.py가 만드는 문서들도 실제로는
1행 머리말, 2행 제목, 3행 문서정보처럼 열 전체를 병합한 "한 줄짜리 텍스트" 행과, 그
아래 일반 표(헤더+데이터) 행이 섞여 있는 구조다. 이 파서는 그 구분을 하드코딩된 행
번호가 아니라 실제 병합 셀 정보(worksheet.merged_cells)로 판별한다:
  - 1열부터 시작해 그 행 전체를 가로지르는 병합 셀 -> "paragraph" 블록 (제목/머리말류)
  - 그 외 일반 행 -> 연속된 행을 모아 "table" 블록 (헤더 행도 포함, 구분 안 함 -
    FR-PRE-004 요구사항이 "셀 내용이 순차적 텍스트 배열로 추출"이라고만 하지 헤더/
    데이터를 구분하라고 하지 않는다)

수식 셀은 캐시된 계산값이 있으면 "값 (수식: =SUM(...))" 형태로, 없으면 "(수식: =SUM(...))"
형태로 풀어서 자연어 배열에 들어가게 한다.
"""

from __future__ import annotations

import io
import zipfile
from datetime import date, datetime
from pathlib import Path

import openpyxl
from openpyxl.utils.exceptions import InvalidFileException

from .errors import CorruptedDocumentError, EncryptedDocumentError

# 레거시 OLE 복합 문서 시그니처 - 암호가 설정된 xlsx는 OOXML(zip)이 아니라 OLE
# 컨테이너로 저장되므로 zip으로 열리지 않는다 (docx_parser.py와 동일한 판별 방식).
_OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _is_encrypted_ole(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        return head == _OLE_SIGNATURE
    except OSError:
        return False


def _cell_text(formula_cell, value_cell) -> str:
    if formula_cell.data_type == "f":
        formula = str(formula_cell.value)
        cached = value_cell.value
        if cached is not None:
            return f"{_scalar_text(cached)} (수식: {formula})"
        return f"(수식: {formula})"
    return _scalar_text(formula_cell.value)


def _scalar_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.time() == datetime.min.time():
            return value.date().isoformat()
        return value.isoformat(sep=" ")
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _full_row_merge_span(ws, row_idx: int) -> int | None:
    """이 행이 1열부터 시작해 행 전체를 가로지르는 병합 셀이면 병합 열 수를, 아니면 None을 반환."""
    for merged_range in ws.merged_cells.ranges:
        if (
            merged_range.min_row == row_idx
            and merged_range.max_row == row_idx
            and merged_range.min_col == 1
            and merged_range.max_col > 1
        ):
            return merged_range.max_col
    return None


def parse_xlsx(path: str | Path) -> list[dict]:
    """XLSX를 순서 보존 Block dict 리스트로 반환한다.

    반환되는 각 dict는 pipeline.Block으로 감싸지기 전 원시 형태다:
      {"type": "paragraph"|"table", "level": None, "text": str|None,
       "rows": list[list[str]]|None, "section": int|None(시트 인덱스)}
    """
    path = Path(path)

    if _is_encrypted_ole(path):
        raise EncryptedDocumentError(f"암호로 보호된 XLSX 파일입니다: {path.name}")

    try:
        raw_bytes = path.read_bytes()
        # 확장자에 상관없이 내용만으로 열기 위해 BytesIO로 전달한다 (경로 문자열을
        # 직접 넘기면 openpyxl이 확장자만 보고 InvalidFileException을 던질 수 있다).
        wb_formulas = openpyxl.load_workbook(io.BytesIO(raw_bytes), data_only=False)
        wb_values = openpyxl.load_workbook(io.BytesIO(raw_bytes), data_only=True)
    except zipfile.BadZipFile as e:
        raise CorruptedDocumentError(f"손상된 ZIP 컨테이너입니다: {path.name}") from e
    except InvalidFileException as e:
        raise CorruptedDocumentError(f"유효한 XLSX가 아닙니다: {path.name}") from e
    except KeyError as e:
        raise CorruptedDocumentError(f"필수 구성요소가 누락된 XLSX입니다: {path.name}") from e

    blocks: list[dict] = []

    for sheet_idx, sheet_name in enumerate(wb_formulas.sheetnames):
        ws_f = wb_formulas[sheet_name]
        ws_v = wb_values[sheet_name]

        table_buffer: list[list[str]] = []

        def flush_table():
            if table_buffer:
                rows_copy = [row[:] for row in table_buffer]
                if any(any(cell.strip() for cell in row) for row in rows_copy):
                    blocks.append(
                        {"type": "table", "level": None, "text": None, "rows": rows_copy, "section": sheet_idx}
                    )
                table_buffer.clear()

        max_row = ws_f.max_row or 0
        max_col = ws_f.max_column or 0
        # ws.cell(row=, column=)로 셀을 하나씩 무작위 접근하면 큰 시트(수만 행)에서
        # 극도로 느려진다(관측: 15,724행짜리 파일에서 60초 이상). openpyxl은 순차
        # 순회(iter_rows)에 최적화돼 있으므로 두 워크북(수식/값)을 같은 순서로 병렬
        # 순회한다 - 셀 접근 방식만 바뀔 뿐 결과(수식+캐시값 조합)는 동일하다.
        rows_f = ws_f.iter_rows(min_row=1, max_row=max_row, max_col=max_col)
        rows_v = ws_v.iter_rows(min_row=1, max_row=max_row, max_col=max_col)

        for row_idx, (cells_f, cells_v) in enumerate(zip(rows_f, rows_v), start=1):
            span = _full_row_merge_span(ws_f, row_idx)
            if span is not None:
                flush_table()
                text = _scalar_text(cells_f[0].value) if cells_f else ""
                if text.strip():
                    blocks.append(
                        {"type": "paragraph", "level": None, "text": text, "rows": None, "section": sheet_idx}
                    )
                continue

            row_cells = [_cell_text(cf, cv) for cf, cv in zip(cells_f, cells_v)]
            if any(cell.strip() for cell in row_cells):
                table_buffer.append(row_cells)

        flush_table()

    return blocks
