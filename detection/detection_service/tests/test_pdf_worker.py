"""pdf_worker 단위 시험 - 같은 프로세스에서 함수를 직접 부른다(묶음·문자열 풀기·쪽 글자·지우는 상자·정리·사전 검사)."""

from __future__ import annotations

import io
import math
from array import array

import fitz
import pytest

import pdf_synth as synth
from detection_service import pdf_worker as W


# ---------------------------------------------------------------- 묶음


def test_frame_roundtrip_and_limits():
    buf = io.BytesIO()
    W.write_frame(buf, W.encode_json({"op": "x", "v": "한글"}))
    W.write_frame(buf, b"%PDF-1.7 data")
    buf.seek(0)
    assert W.decode_json(W.read_frame(buf, 100)) == {"op": "x", "v": "한글"}
    assert W.read_frame(buf, 100) == b"%PDF-1.7 data"
    with pytest.raises(EOFError):
        W.read_frame(buf, 100)
    big = io.BytesIO()
    W.write_frame(big, b"x" * 101)
    big.seek(0)
    with pytest.raises(ValueError):
        W.read_frame(big, 100)
    with pytest.raises(ValueError):
        W.decode_json(b"[1, 2]")


# ---------------------------------------------------------------- PDF 문자열 풀기


def test_pdf_strings_decodes_literal_hex_and_utf16():
    rrn = synth.RRN
    utf16 = "FEFF" + rrn.encode("utf-16-be").hex().upper()
    src = (f"<< /A ({rrn}) /B (a\\(b\\)c \\101\\102 nested (x) end) /C <{utf16}> /D <{rrn.encode().hex()}> "
           f"/E <<  /F (line\\\ncontinued) >> >>").encode("latin-1")
    got = list(W.pdf_strings(src))
    assert got[0] == rrn
    assert got[1] == "a(b)c AB nested (x) end"
    assert got[2] == rrn and got[3] == rrn
    assert got[4] == "linecontinued"


def test_outside_streams_keeps_dicts_between_streams():
    """'endstream'의 꼬리를 스트림 시작으로 잡으면 다음 객체 사전을 건너뛴다(고친 실수)."""
    data = (b"1 0 obj <</Length 5>> stream\nABCDE\nendstream\nendobj\n2 0 obj <</Title (900101-1234567)>>\nendobj\n"
            b"3 0 obj <</Length 3>> stream\r\nxyz\nendstream endobj")
    parts = list(W._outside_streams(data))
    assert any(b"(900101-1234567)" in p for p in parts)
    assert not any(b"ABCDE" in p or b"xyz" in p for p in parts)


def test_dict_scan_finds_values_in_objects_and_ignores_case_and_spaces():
    data, _, _ = synth.plain()
    doc = fitz.open(stream=data, filetype="pdf")
    doc.set_metadata({"title": "HONG.GILDONG@EXAMPLE.COM", "author": "900101 - 1234567"})
    out = doc.tobytes()
    check = fitz.open(stream=out, filetype="pdf")
    assert W.dict_scan(check, [synth.EMAIL, synth.RRN, synth.PHONE], out) == [0, 1]


def test_dict_scan_reads_stale_objects_inside_object_streams():
    """garbage=1 + 객체 스트림은 지운 주석 객체를 객체 스트림 안에 남긴다(실측) - ②가 그것을 잡아야 한다."""
    data, values, _ = synth.annotations_and_form()
    doc = fitz.open(stream=data, filetype="pdf")
    W.scrub_document(fitz, doc)
    stale = doc.tobytes(garbage=1, deflate=True, use_objstms=1)
    check = fitz.open(stream=stale, filetype="pdf")
    live = [s for x in range(1, check.xref_length())
            for s in W.pdf_strings(check.xref_object(x, compressed=True).encode("latin-1"))]
    assert not any(W._squash(v) in W._squash(s) for v in values for s in live)   # xref 객체만 보면 놓친다
    assert W.dict_scan(check, values, stale)               # 객체 스트림 본문까지 보면 잡힌다
    assert W.dict_scan(check, values)                      # (파일 바이트 없이도 ②로)
    fixed = fitz.open(stream=data, filetype="pdf")
    W.scrub_document(fitz, fixed)
    clean = fixed.tobytes(garbage=2, deflate=True, use_objstms=1)
    assert W.dict_scan(fitz.open(stream=clean, filetype="pdf"), values, clean) == []


# ---------------------------------------------------------------- 쪽 글자


def test_page_layout_text_structure_and_boxes():
    data, _, _ = synth.annotations_and_form()
    doc = fitz.open(stream=data, filetype="pdf")
    lay = W.page_layout(fitz, doc[0])
    body = lay.text[:lay.body_len]
    assert body.endswith("\n\n")                           # 줄 끝·블록 끝 줄바꿈
    assert synth.PHONE in body
    tail = lay.text[lay.body_len:]
    assert f"메모 주민번호 {synth.RRN}" in tail and synth.PHONE2 in tail   # 주석 Contents·양식 값 줄
    assert len(lay.box) == 4 * lay.body_len and len(lay.line) == lay.body_len
    for i, c in enumerate(body):
        if c == "\n" and lay.line[i] < 0:
            assert math.isnan(lay.box[4 * i])
    i = body.index(synth.PHONE)
    assert lay.box_at(i) is not None


@pytest.mark.parametrize("build", [synth.plain, synth.table, synth.rotated_text, synth.annotations_and_form,
                                   lambda: synth.actual_text("hidden"),
                                   lambda: (_fixture("chrome_ligature_fake.pdf").read_bytes(), [], [])])
def test_reextract_text_equals_layout_text(build):
    """재추출(boxes=False)은 처음 추출과 같은 글자를 만들어야 한다(같은 함수 - 명세 §3.3 재추출)."""
    doc = fitz.open(stream=build()[0], filetype="pdf")
    for page in doc:
        full, fast = W.page_layout(fitz, page), W.page_layout(fitz, page, boxes=False)
        assert (full.text, full.body_len, full.actual) == (fast.text, fast.body_len, fast.actual)


def test_page_layout_budget():
    data, _, _ = synth.multipage(3, 25)
    doc = fitz.open(stream=data, filetype="pdf")
    budget = [10 ** 6, 500]
    with pytest.raises(W.Unsupported, match="text_too_large"):
        for page in doc:
            W.page_layout(fitz, page, budget=budget)


def test_actualtext_layer_is_reported_when_it_differs():
    data, _, _ = synth.actual_text("hidden")
    lay = W.page_layout(fitz, fitz.open(stream=data, filetype="pdf")[0])
    assert synth.RRN not in lay.text and lay.actual is not None and synth.RRN in lay.actual
    data, _, _ = synth.plain()
    assert W.page_layout(fitz, fitz.open(stream=data, filetype="pdf")[0]).actual is None


def test_ligatures_are_split_into_letters():
    doc = fitz.open(str(_fixture("chrome_ligature_fake.pdf")))
    lay = W.page_layout(fitz, doc[0])
    assert "office.affiliate@example.com" in lay.text and "ﬁ" not in lay.text and "ﬃ" not in lay.text


def _fixture(name):
    from pathlib import Path

    return Path(__file__).resolve().parent / "fixtures" / name


# ---------------------------------------------------------------- 지우는 상자


def _rects_for(data, value, page=0):
    doc = fitz.open(stream=data, filetype="pdf")
    lay = W.page_layout(fitz, doc[page])
    s = lay.text.index(value)
    return lay, W.plan_rects(lay, [(s, s + len(value))]), (s, s + len(value))


def test_band_avoids_neighbour_lines_and_covers_every_target_glyph():
    data, _, _ = synth.tight_lines(pitch=9.0)
    lay, rects, (s, e) = _rects_for(data, synth.RRN)
    assert len(rects) == 1
    rect = rects[0]
    for i in range(s, e):
        assert W._overlaps(lay.box_at(i), rect)            # 지울 글자는 모두 겹친다
    for i in range(lay.body_len):
        if s <= i < e or lay.line[i] == lay.line[s] or lay.text[i].isspace() or lay.box_at(i) is None:
            continue
        assert not W._overlaps(lay.box_at(i), rect), lay.text[i]   # 이웃 줄 글자는 안 겹친다


def test_band_for_vertical_text():
    data, _, _ = synth.rotated_text()
    lay, rects, (s, e) = _rects_for(data, synth.PHONE)
    (rect,) = rects
    boxes = [lay.box_at(i) for i in range(s, e) if not lay.text[i].isspace()]
    assert rect[2] - rect[0] < max(b[2] for b in boxes) - min(b[0] for b in boxes)   # 줄 방향 수직(x)으로 좁힘
    assert all(W._overlaps(b, rect) for b in boxes)


def test_value_split_across_lines_gets_one_rect_per_line():
    data, _, _ = synth.password_label()
    doc = fitz.open(stream=data, filetype="pdf")
    lay = W.page_layout(fitz, doc[0])
    s = lay.text.index("비밀번호")
    e = lay.text.index(synth.PASSWORD) + len(synth.PASSWORD)
    assert len(W.plan_rects(lay, [(s, e)])) == 1
    s2 = lay.text.index("서버 접속")
    assert len(W.plan_rects(lay, [(s2, e)])) == 2


def test_missing_box_is_unsupported_and_annotation_span_needs_none():
    text = "abc\n"
    box = array("d", [0, 0, 1, 1, float("nan"), 0, 0, 0, 2, 0, 3, 1, float("nan")] + [float("nan")] * 3)
    lay = W.PageLayout(text + "note\n", 4, box, array("l", [0, 0, 0, -1]), [(0, 0, 3, 1, 0, 0, 3)], None)
    with pytest.raises(W.Unsupported, match="no_box"):
        W.plan_rects(lay, [(0, 3)])
    assert W.plan_rects(lay, [(4, 8)]) == []               # 주석 줄 구간 - 문서 정리에서 지운다


# ---------------------------------------------------------------- 문서 정리


def test_scrub_document_removes_document_level_text():
    data, values, _ = synth.document_level()
    doc = fitz.open(stream=data, filetype="pdf")
    W.scrub_document(fitz, doc)
    out = doc.tobytes(garbage=2, deflate=True, use_objstms=1)
    check = fitz.open(stream=out, filetype="pdf")
    assert check.get_toc() == [] and not check.get_xml_metadata()
    assert not [p for p in check if list(p.annots()) or list(p.widgets())]
    # 본문 값은 지우기 전이라 남아 있고, 사전 문자열에는 없다
    assert W.dict_scan(check, values, out) == []
    assert synth.RRN in check[0].get_text()
