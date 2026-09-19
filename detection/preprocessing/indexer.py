"""FR-PRE-005 탐지 위치 인덱싱.

시그니처/해시/임베딩 탐지 모듈(FR-SIG/FR-HSH/FR-EMB, 아직 미구현)은 파이프라인이 만든
`ParsedDocument.normalized_text` 위에서 매치를 찾고 (start, end) 문자 오프셋만 돌려줄
것이다. 그 오프셋 자체는 "어느 블록의, 원문 상 어디"인지 말해주지 않으므로, 로그에
탐지 근거를 남기려면(검증 기준: "탐지 대상의 원문 내 위치가 로그에서 확인되어야 한다")
역방향 매핑이 필요하다. 이 모듈이 그 매핑을 만든다.

세 단계로 나눠 처리한다.
  1. 블록별로 (표는 셀 좌표까지) local 텍스트를 만들고 문서 전체 텍스트에서의
     global 오프셋 구간을 부여한다.
  2. 정규화 과정에서 문자가 삭제/치환되며 길이가 달라지므로, 블록 단위(문단 하나·표
     셀 텍스트 정도의 크기)로 스코프를 좁혀 difflib로 raw<->normalized 오프셋을
     정렬한다. 전체 문서를 통째로 diff하지 않고 블록 단위로 쪼개는 이유는 그 정도
     크기에서는 diff 비용이 무시할 만하고, 대부분의 블록은 애초에 raw==normalized라
     diff 자체를 건너뛸 수 있기 때문이다.
  3. 공백 기준 단어 인덱스를 부여한다("각 단어 또는 문자에 인덱스를 부여").

`locate(start, end)`가 이 모든 걸 조합해, 탐지 모듈이 돌려준 global 오프셋 하나를
"몇 번째 블록/어떤 타입/원문 오프셋/원문 스니펫/단어 번호/(표라면) 몇 행 몇 열"로
변환한다.
"""

from __future__ import annotations

import bisect
import difflib
import re
from dataclasses import dataclass

# NOTE: pipeline.Block을 import하면 순환 참조가 생기므로 타입 힌트는 문자열로만 남기고
# 실제로는 duck-typing한다 (type: heading|paragraph|table|header|footer, raw_text,
# normalized_text, raw_rows, normalized_rows, page, section 속성만 있으면 된다).

_WORD_RE = re.compile(r"\S+")
_ROW_SEPARATOR = " | "


@dataclass
class WordSpan:
    text: str
    start: int  # 블록 local 텍스트 기준 시작 오프셋
    end: int
    index: int  # 블록 내 단어 순번 (0-based)


@dataclass
class CellSpan:
    row: int
    col: int
    start: int  # 표 블록 local 텍스트(행을 " | "로 이은 문자열) 기준 오프셋
    end: int


@dataclass
class IndexedBlock:
    block: object  # pipeline.Block
    local_text: str
    raw_local_text: str
    global_start: int
    global_end: int
    offset_map: list[int]  # local_text[i] -> raw_local_text 상의 대응 위치
    words: list[WordSpan]
    cells: list[CellSpan] | None = None


@dataclass
class DetectionLocation:
    block_index: int
    block_type: str
    page: int | None
    section: int | None
    local_start: int
    local_end: int
    raw_start: int | None
    raw_end: int | None
    raw_snippet: str | None
    word_indices: list[int]
    cell: CellSpan | None = None

    def describe(self) -> str:
        loc_bits = []
        if self.page is not None:
            loc_bits.append(f"{self.page}페이지")
        if self.section is not None:
            loc_bits.append(f"섹션 {self.section}")
        loc_bits.append(f"{self.block_index}번 블록({self.block_type})")
        if self.cell is not None:
            loc_bits.append(f"{self.cell.row + 1}행 {self.cell.col + 1}열")
        if self.word_indices:
            loc_bits.append(f"단어 #{self.word_indices[0]}")
        where = ", ".join(loc_bits)
        if self.raw_snippet:
            return f"{where} - 원문: ...{self.raw_snippet}..."
        return where


@dataclass
class IndexedDocument:
    text: str
    blocks: list[IndexedBlock]

    def locate(self, start: int, end: int | None = None) -> DetectionLocation | None:
        """text[start:end] 구간의 매치가 원문 어디서 왔는지 찾는다."""
        if end is None:
            end = start + 1
        if not self.blocks or start < 0 or start >= len(self.text):
            return None

        starts = [ib.global_start for ib in self.blocks]
        idx = bisect.bisect_right(starts, start) - 1
        if idx < 0:
            return None
        ib = self.blocks[idx]
        if not (ib.global_start <= start < ib.global_end):
            return None

        local_start = start - ib.global_start
        local_end = max(local_start + 1, min(end - ib.global_start, len(ib.local_text)))

        raw_start = None
        raw_end = None
        if ib.offset_map and local_start < len(ib.offset_map):
            raw_start = ib.offset_map[local_start]
            last_idx = min(local_end, len(ib.offset_map)) - 1
            if last_idx >= local_start:
                raw_end = ib.offset_map[last_idx] + 1

        raw_snippet = None
        if raw_start is not None and ib.raw_local_text:
            ctx_start = max(0, raw_start - 10)
            ctx_end = min(len(ib.raw_local_text), (raw_end or raw_start + 1) + 10)
            raw_snippet = ib.raw_local_text[ctx_start:ctx_end]

        word_indices = [w.index for w in ib.words if w.start < local_end and w.end > local_start]

        cell = None
        if ib.cells:
            for c in ib.cells:
                if c.start <= local_start < c.end:
                    cell = c
                    break

        return DetectionLocation(
            block_index=idx,
            block_type=ib.block.type,
            page=ib.block.page,
            section=ib.block.section,
            local_start=local_start,
            local_end=local_end,
            raw_start=raw_start,
            raw_end=raw_end,
            raw_snippet=raw_snippet,
            word_indices=word_indices,
            cell=cell,
        )


def tokenize_words(text: str) -> list[WordSpan]:
    return [
        WordSpan(text=m.group(0), start=m.start(), end=m.end(), index=i)
        for i, m in enumerate(_WORD_RE.finditer(text))
    ]


def linearize_table(rows: list[list[str]]) -> tuple[str, list[CellSpan]]:
    """표를 "셀 | 셀 | 셀\\n셀 | 셀" 형태의 한 문자열로 펴면서 셀별 좌표를 함께 기록한다."""
    line_texts = []
    cells: list[CellSpan] = []
    running_offset = 0

    for row_idx, row in enumerate(rows):
        pos = running_offset
        for col_idx, cell in enumerate(row):
            start = pos
            end = start + len(cell)
            cells.append(CellSpan(row=row_idx, col=col_idx, start=start, end=end))
            pos = end
            if col_idx != len(row) - 1:
                pos += len(_ROW_SEPARATOR)
        line = _ROW_SEPARATOR.join(row)
        line_texts.append(line)
        running_offset += len(line)
        if row_idx != len(rows) - 1:
            running_offset += 1  # "\n"

    return "\n".join(line_texts), cells


def build_offset_map(raw: str, normalized: str) -> list[int]:
    """normalized의 각 문자 위치 -> raw에서의 대응 위치 (근사).

    삭제/치환된 구간은 정확한 1:1 대응이 없으므로 해당 raw 구간의 시작점으로 근사한다.
    "탐지된 지점이 원문의 대략 어디인지" 로그에 남기는 용도이지, 바이트 단위로 정확한
    복원이 필요한 용도가 아니므로 이 정도 근사면 충분하다.
    """
    if raw == normalized:
        return list(range(len(normalized)))
    if not normalized:
        return []
    if not raw:
        return [0] * len(normalized)

    offset_map = [0] * len(normalized)
    matcher = difflib.SequenceMatcher(a=raw, b=normalized, autojunk=False)
    last_raw_pos = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for k in range(j2 - j1):
                offset_map[j1 + k] = i1 + k
            last_raw_pos = i2
        elif tag == "replace":
            span = max(i2 - i1, 1)
            count = max(j2 - j1, 1)
            for k in range(j2 - j1):
                offset_map[j1 + k] = min(i1 + (k * span) // count, max(i2 - 1, i1))
            last_raw_pos = i2
        elif tag == "insert":
            for k in range(j2 - j1):
                offset_map[j1 + k] = last_raw_pos
        elif tag == "delete":
            last_raw_pos = i2

    return offset_map


def build_index(blocks: list) -> IndexedDocument:
    """블록 리스트로부터 전체 검색 텍스트 + 위치 인덱스를 만든다.

    pipeline.ParsedDocument.normalized_text는 이 함수가 만드는 text와 동일해야
    한다 - 탐지 모듈이 매치를 찾는 텍스트와 위치를 되짚는 텍스트가 어긋나면 인덱싱
    자체가 무의미해지기 때문에, pipeline.py는 이 함수를 단일 진실 공급원으로 사용한다.
    """
    indexed_blocks: list[IndexedBlock] = []
    text_parts: list[str] = []
    offset = 0

    for b in blocks:
        cells = None
        if b.type == "table":
            if not b.normalized_rows:
                continue
            local_text, cells = linearize_table(b.normalized_rows)
            raw_local_text, _ = linearize_table(b.raw_rows) if b.raw_rows else ("", [])
        else:
            if not b.normalized_text:
                continue
            local_text = b.normalized_text
            raw_local_text = b.raw_text or ""

        if not local_text:
            continue

        offset_map = build_offset_map(raw_local_text, local_text)
        words = tokenize_words(local_text)

        start = offset
        end = start + len(local_text)
        indexed_blocks.append(
            IndexedBlock(
                block=b,
                local_text=local_text,
                raw_local_text=raw_local_text,
                global_start=start,
                global_end=end,
                offset_map=offset_map,
                words=words,
                cells=cells,
            )
        )
        text_parts.append(local_text)
        offset = end + 1  # 다음 블록과 "\n"으로 이어붙일 것을 가정한 오프셋

    return IndexedDocument(text="\n".join(text_parts), blocks=indexed_blocks)
