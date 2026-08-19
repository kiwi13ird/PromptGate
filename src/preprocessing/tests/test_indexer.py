from preprocessing.indexer import (
    build_index,
    build_offset_map,
    linearize_table,
    tokenize_words,
)
from preprocessing.pipeline import Block, parse_document


def test_offset_map_identical_text():
    assert build_offset_map("hello", "hello") == [0, 1, 2, 3, 4]


def test_offset_map_deleted_chars():
    # raw: "A  B" (스페이스 2개) -> normalized: "A B" (정규화가 중복 공백을 1칸으로 축약)
    raw = "A  B"
    normalized = "A B"
    offset_map = build_offset_map(raw, normalized)
    assert len(offset_map) == len(normalized)
    # 'A'와 'B'는 정확히 대응되어야 한다
    assert raw[offset_map[0]] == "A"
    assert raw[offset_map[2]] == "B"


def test_offset_map_removed_invisible_char():
    raw = "AB​CD"  # 중간에 제로폭 공백
    normalized = "ABCD"
    offset_map = build_offset_map(raw, normalized)
    # normalized의 각 문자는 raw에서 같은 문자를 가리켜야 한다
    for i, ch in enumerate(normalized):
        assert raw[offset_map[i]] == ch


def test_tokenize_words():
    words = tokenize_words("hello world  foo")
    assert [w.text for w in words] == ["hello", "world", "foo"]
    assert [w.index for w in words] == [0, 1, 2]
    assert words[0].start == 0 and words[0].end == 5


def test_linearize_table_roundtrip():
    rows = [["기안", "검토", "승인"], ["홍길동", "김철수", "이영희"]]
    text, cells = linearize_table(rows)
    assert text == "기안 | 검토 | 승인\n홍길동 | 김철수 | 이영희"
    for c in cells:
        original = rows[c.row][c.col]
        assert text[c.start : c.end] == original


def _make_block(type_, text=None, rows=None, page=None, section=None):
    return Block(
        type=type_,
        raw_text=text,
        normalized_text=text,
        raw_rows=rows,
        normalized_rows=rows,
        page=page,
        section=section,
    )


def test_build_index_locate_paragraph():
    blocks = [
        _make_block("header", "대외비 문서", section=0),
        _make_block("paragraph", "이 문서는 기밀입니다"),
    ]
    index = build_index(blocks)
    pos = index.text.find("기밀")
    assert pos != -1

    loc = index.locate(pos, pos + 2)
    assert loc is not None
    assert loc.block_type == "paragraph"
    assert loc.raw_start is not None and loc.raw_end is not None
    ib = index.blocks[loc.block_index]
    assert ib.raw_local_text[loc.raw_start : loc.raw_end] == "기밀"


def test_build_index_locate_table_cell():
    blocks = [
        _make_block("table", rows=[["기안", "검토", "승인"], ["홍길동", "김철수", "이영희"]]),
    ]
    index = build_index(blocks)
    pos = index.text.find("김철수")
    assert pos != -1

    loc = index.locate(pos, pos + 3)
    assert loc is not None
    assert loc.block_type == "table"
    assert loc.cell is not None
    assert loc.cell.row == 1
    assert loc.cell.col == 1


def test_index_matches_normalized_text_exactly():
    blocks = [
        _make_block("paragraph", "first"),
        _make_block("table", rows=[["a", "b"]]),
        _make_block("paragraph", "last"),
    ]
    index = build_index(blocks)
    assert "first" in index.text
    assert "a | b" in index.text
    assert "last" in index.text


def test_pipeline_exposes_index_on_real_document(sample_docx):
    result = parse_document(sample_docx)
    assert result.success
    assert result.index is not None
    assert result.index.text == result.normalized_text

    pos = result.normalized_text.find("대외비")
    assert pos != -1
    loc = result.index.locate(pos, pos + 3)
    assert loc is not None
    assert loc.block_type == "header"
    ib = result.index.blocks[loc.block_index]
    assert ib.raw_local_text[loc.raw_start : loc.raw_end] == "대외비"


def test_pipeline_index_locates_table_cell_on_real_document(sample_docx):
    result = parse_document(sample_docx)
    pos = result.normalized_text.find("기안")
    assert pos != -1
    loc = result.index.locate(pos, pos + 2)
    assert loc is not None
    assert loc.block_type == "table"
    assert loc.cell is not None
    assert loc.cell.row == 0
