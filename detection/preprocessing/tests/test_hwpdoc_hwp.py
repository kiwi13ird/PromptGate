"""hwpdoc HWP 5.0 단위 시험 - 합성 HWP(가짜 개인정보)로 추출 규칙·닫힌 목록·경계·상한을 확인한다."""

from __future__ import annotations

import struct
import tracemalloc

import pytest

import hwp_synth as S
from preprocessing import hwpdoc

MAX = 20 * 1024 * 1024


def _sample_sections():
    """본문·머리말·표(병합·중첩 표·칸 안 글상자)·수식·필드·덧말·그림·메모·각주·꼬리말이 든 두 구역."""
    sec0 = (
        S.p(0, "문서 제목 홍길동", S.header_ctrl(1, [S.p(2, "머리말 글자")]))
        + S.para(0, S.ext_ctrl(11, "tbl "), S.table(1, [
            (0, 0, 1, 1, [S.p(2, "성명")]),
            (0, 1, 1, 1, [S.p(2, "김가짜")]),
            (1, 0, 1, 1, [S.p(2, "주민등록번호")]),
            (1, 1, 1, 1, [S.p(2, "900101-1234567"), S.p(2, "둘째 줄"),
                          S.para(2, S.ext_ctrl(11, "tbl "), S.table(3, [
                              (0, 0, 1, 1, [S.p(4, "중첩A")]), (0, 1, 1, 1, [S.p(4, "중첩B")])], 1, 2))]),
            (2, 0, 1, 2, [S.p(2, "병합 칸"), S.para(2, S.ext_ctrl(11, "gso "), S.textbox(3, [S.p(4, "칸 글상자")]))]),
        ], 3, 2, desc="표입니다."))
        + S.p(0, "본문 끝 문단",
              S.equation(1, "1 over 2", desc="수식입니다."),
              S.field(1, "%hlk", "mailto:fake@example.com;1;0;0;"),
              S.dutmal(1, "본말", "덧말"),
              S.picture(1, desc="그림입니다. 원본 그림의 이름: fake.png"),
              S.memo(1, [S.p(1, "메모 글자")]))
    )
    sec1 = S.p(0, "둘째 구역 문단",
               S.header_ctrl(1, [S.p(2, "각주 글자")], which="fn  "),
               S.header_ctrl(1, [S.p(2, "꼬리말")], which="foot"))
    return [sec0, sec1]


def _sample(**kw):
    return S.build_hwp(_sample_sections(), summary={2: "가짜 제목", 4: "가짜 작성자"}, prvtext="미리보기 글자", **kw)


def test_layout_lines_and_locators():
    doc = hwpdoc.read(_sample(), max_decompressed=MAX)
    assert doc.kind == "hwp"
    assert doc.lines() == [
        "문서 제목 홍길동",
        "머리말 글자",
        "성명 | 김가짜",
        "주민등록번호 | 900101-1234567\n둘째 줄",
        "중첩A | 중첩B",
        "병합 칸",
        "칸 글상자",
        "본문 끝 문단",
        "메모 글자",
        "둘째 구역 문단",
        "각주 글자",
        "꼬리말",
        "표입니다.", "수식입니다.", "1 over 2", "mailto:fake@example.com;1;0;0;", "본말", "덧말",
        "그림입니다. 원본 그림의 이름: fake.png", "가짜 제목", "가짜 작성자",
    ]
    by = {p.locator: p for p in doc.paragraphs}
    assert len(by) == len(doc.paragraphs)                       # locator 중복 없음
    assert by["body:p0"].text == "문서 제목 홍길동" and by["body:p0"].block_order == 0
    assert by["header0:p0"].text == "머리말 글자" and by["header0:p0"].block_order == 0
    assert by["body:t0:r1:c1:p1"].text == "둘째 줄" and by["body:t0:r1:c1:p1"].cell == (0, 1, 1, 1, 1)
    assert by["body:t0:r1:c1:t0:r0:c1:p0"].text == "중첩B" and by["body:t0:r1:c1:t0:r0:c1:p0"].cell == (1, 0, 1, 1, 1)
    assert by["body:t0:r2:c0:p0"].cell == (0, 2, 0, 1, 2)          # 열 병합 2
    assert by["body:t0:r2:c0:p2"].text == "칸 글상자"              # 칸 안 글상자는 칸 순번을 이어 씀
    assert by["body:p3"].text == "메모 글자" and by["body:p3"].block_order == 2
    assert by["body:p4"].text == "둘째 구역 문단" and by["body:p4"].block_order == 3   # 구역 넘어 이어 셈
    assert by["body:p5"].text == "각주 글자" and by["footer0:p0"].text == "꼬리말"
    assert by["body:p4"].stream == "BodyText/Section1"
    assert [s.locator for s in doc.side][:3] == ["side:desc0", "side:desc1", "side:eq0"]
    assert {s.kind for s in doc.side} == {"desc", "eq", "field", "dutmal", "summary"}
    assert doc.preview_text() == "미리보기 글자"
    assert doc.stats["sections"] == 2 and doc.stats["tables"] == 2
    # layout은 표 행을 칸 목록으로
    assert doc.layout()[2] == ["성명", "김가짜"] and doc.layout()[0] == "문서 제목 홍길동"


def test_control_chars_surrogates_and_offsets():
    raw = (S.text_units("가") + S.ext_ctrl(9) + S.text_units("나") + struct.pack("<H", 10) + S.text_units("다")
           + struct.pack("<HHH", 30, 31, 24) + S.ext_ctrl(3, "%hlk") + S.text_units("링크") + S.ext_ctrl(4)
           + "😀".encode("utf-16-le") + b"\x00\xd8" + S.text_units("끝") + S.ext_ctrl(11, "tbl ") + struct.pack("<H", 0))
    sec = S.para(0, raw)
    doc = hwpdoc.read(S.build_hwp([sec], flags=0), max_decompressed=MAX)
    (para,) = doc.paragraphs
    assert para.text == "가\t나\n다  -링크😀�끝"
    assert len(para.offsets) == len(para.text)
    for ch, off in zip(para.text, para.offsets):
        if ch in "\t\n -":
            assert off == -1
            continue
        width = 4 if ord(ch) > 0xFFFF else 2
        unit = sec[off:off + width]
        assert (unit == b"\x00\xd8") if ch == "�" else (unit.decode("utf-16-le") == ch)
    # 압축 문서도 같은 위치(압축을 푼 구역 기준)
    doc2 = hwpdoc.read(S.build_hwp([sec], flags=1), max_decompressed=MAX)
    assert doc2.paragraphs[0].offsets == para.offsets


def test_long_paragraph_fast_path_offsets():
    text = "가나다라마바사" * 5000 + "1234"
    sec = S.p(0, text)
    doc = hwpdoc.read(S.build_hwp([sec], flags=0), max_decompressed=MAX)
    para = doc.paragraphs[0]
    assert para.text == text
    off0 = para.offsets[0]
    assert sec[off0:off0 + 2].decode("utf-16-le") == "가"
    assert list(para.offsets) == list(range(off0, off0 + 2 * len(text), 2))


@pytest.mark.parametrize("flags,kind", [
    (0x1 | 0x2, "hwp_encrypted"), (0x1 | 0x4, "hwp_distribution"),
    (0x1 | 0x10, "hwp_drm"), (0x1 | 0x100, "hwp_drm"), (0x1 | 0x400, "hwp_drm"),
])
def test_flags_unsupported(flags, kind):
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(_sample(flags=flags), max_decompressed=MAX)
    assert e.value.kind == kind and kind in hwpdoc.ENCRYPTED_KINDS
    assert hwpdoc.sniff(_sample(flags=flags)) == "hwp"


@pytest.mark.parametrize("extra,kind", [
    ({"DocHistory/VersionLog0": b"x" * 10}, "hwp_history"),
    ({"ViewText/Section0": b"x" * 10}, "hwp_distribution"),
    ({"BinData/BIN0001.ole": b"x" * 10}, "hwp_unsupported_object"),
    ({"BinData/BIN0001": b"x" * 10}, "hwp_unsupported_object"),
    ({"XMLTemplate/Schema": b"x" * 10}, "hwp_unsupported_object"),
    ({"\x05DocumentSummaryInformation": b"x" * 10}, "hwp_unsupported_object"),
    ({"BodyText/Extra": b"x" * 10}, "hwp_unsupported_object"),
])
def test_streams_closed_list(extra, kind):
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(_sample(extra=extra), max_decompressed=MAX)
    assert e.value.kind == kind


def test_image_bindata_and_ignored_storages_pass():
    extra = {"BinData/BIN0001.png": b"\x89PNG" + b"0" * 100, "BinData/BIN0002.JPG": b"0" * 10,
             "Scripts/DefaultJScript": b"\x00" * 10, "DocOptions/_LinkDoc": b"\x00" * 10}
    doc = hwpdoc.read(_sample(extra=extra), max_decompressed=MAX)
    assert doc.media == 2


@pytest.mark.parametrize("record", [
    S.rec(84, 1, b"\x00" * 8),      # OLE
    S.rec(87, 1, b"\x00" * 8),      # CTRL_DATA(필드 이름·책갈피 이름)
    S.rec(90, 1, b"\x00" * 8),      # 글맵시
    S.rec(91, 1, b"\x00" * 8),      # 양식 개체
    S.rec(95, 1, b"\x00" * 8),      # 차트
    S.rec(96, 1, b"\x00" * 8),      # 변경 추적
    S.rec(98, 1, b"\x00" * 8),      # 동영상
    S.rec(300, 1, b"\x00" * 8),     # 모르는 번호
    S.plain_ctrl(1, "tcps"),        # 글자 겹침인데 규격 배치가 아님(아래 test_compose_* 참고)
    S.plain_ctrl(1, "idxm"),        # 찾아보기 표식
    S.plain_ctrl(1, "zzzz"),        # 모르는 컨트롤
])
def test_records_closed_list(record):
    sec = S.p(0, "본문", record)
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwp([sec]), max_decompressed=MAX)
    assert e.value.kind == "hwp_unsupported_object"


def test_plain_controls_pass():
    sec = S.p(0, "본문", *(S.plain_ctrl(1, c) for c in ("secd", "cold", "atno", "nwno", "pghd", "pgct", "pgnp", "bokm")),
              S.header_ctrl(1, [S.p(2, "숨은 설명")], which="tcmt"))
    assert hwpdoc.read(S.build_hwp([sec]), max_decompressed=MAX).lines() == ["본문", "숨은 설명"]


@pytest.mark.parametrize("section", [
    struct.pack("<I", 66 | (100 << 20)) + b"\x00" * 10,                       # 레코드가 구역 밖으로
    S.p(0, "본문") + b"\x01\x02",                                              # 잘린 레코드 머리
    S.rec(66, 0, b"\x00" * 22) + S.rec(67, 2, S.text_units("가")),            # 단계 건너뜀
    S.rec(66, 0, b"\x00" * 22) + S.rec(67, 1, b"\x41"),                        # 홀수 PARA_TEXT
    S.rec(66, 0, b"\x00" * 22) + S.rec(67, 1, struct.pack("<HH", 9, 0)),       # 잘린 인라인 제어
    S.rec(67, 0, S.text_units("가")),                                          # 문단 밖 PARA_TEXT
    S.p(0, "", S.rec(71, 1, S.obj_common("tbl ")) + S.rec(77, 2, b"\x00" * 8) + S.rec(66, 2, b"\x00" * 22)),  # 칸 머리 없는 칸 문단
    S.p(0, "", S.table(1, [(0, 0, 1, 1, [S.p(2, "a")]), (0, 0, 1, 1, [S.p(2, "b")])], 1, 1)),               # 칸 주소 중복
    S.p(0, "", S.rec(71, 1, S.ctrl_id("%hlk") + struct.pack("<IB", 0, 0) + struct.pack("<H", 500))),          # 필드 명령 길이 넘침
])
def test_corrupt_sections(section):
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(S.build_hwp([section], flags=0), max_decompressed=MAX)


def test_deflate_truncated_garbage_and_trailing_bytes():
    secs = _sample_sections()
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(_sample(compress_raw=lambda s: S.deflate(s)[: len(S.deflate(s)) // 2]), max_decompressed=MAX)
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(_sample(compress_raw=lambda s: b"\xff" * 64), max_decompressed=MAX)
    # 압축열 뒤 남는 바이트(팀 파일 끝 8바이트와 같은 모양)는 허용
    doc = hwpdoc.read(S.build_hwp(secs, compress_raw=lambda s: S.deflate(s) + b"\x00" * 8), max_decompressed=MAX)
    assert doc.lines()[0] == "문서 제목 홍길동"


def test_declared_stream_size_larger_than_file():
    data = S.set_stream_size(_sample(), "Section0", 10 ** 9)
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(data, max_decompressed=MAX)


def test_fake_cfb_and_non_hwp_cfb():
    fake = S.CFB_MAGIC + bytes(range(256)) * 8
    assert hwpdoc.sniff(fake) is None
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(fake, max_decompressed=MAX)
    ooxml = S.write_cfb({"EncryptionInfo": b"\x04\x00\x04\x00" + b"\x00" * 200, "EncryptedPackage": b"\x00" * 5000})
    doc97 = S.write_cfb({"WordDocument": b"\xec\xa5" + b"\x00" * 5000, "1Table": b"\x00" * 600})
    for data in (ooxml, doc97):
        assert hwpdoc.sniff(data) is None
        with pytest.raises(hwpdoc.HwpCorrupt):
            hwpdoc.read(data, max_decompressed=MAX)
    bad_sig = S.write_cfb({"FileHeader": b"HWP Document Filf".ljust(256, b"\x00"), "BodyText/Section0": b""})
    assert hwpdoc.sniff(bad_sig) is None
    assert hwpdoc.sniff(b"") is None and hwpdoc.sniff(S.CFB_MAGIC) is None and hwpdoc.sniff(b"hello world") is None


def test_no_body_text_sections_is_corrupt():
    data = S.write_cfb({"FileHeader": S.file_header(0), "DocInfo": b""})
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(data, max_decompressed=MAX)


def test_decompression_bomb_is_too_large_and_memory_bounded():
    huge = S.rec(66, 0, b"\x00" * 22) + S.rec(67, 1, b"\x41\x00" * (15 * 1024 * 1024))   # 30MiB 풀림
    data = S.build_hwp([huge])
    assert len(data) < 200_000
    limit = 4 * 1024 * 1024
    tracemalloc.start()
    try:
        with pytest.raises(hwpdoc.HwpTooLarge):
            hwpdoc.read(data, max_decompressed=limit)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < len(data) * 4 + limit * 2 + (1 << 20), peak     # 풀린 크기(30MiB)만큼 쓰지 않음


def test_small_budget_is_too_large():
    with pytest.raises(hwpdoc.HwpTooLarge):
        hwpdoc.read(_sample(), max_decompressed=100)
    with pytest.raises(hwpdoc.HwpTooLarge):
        hwpdoc.read(_sample(flags=0), max_decompressed=300)      # 비압축 문서는 읽은 스트림 크기로


def test_callbacks_called_and_exceptions_propagate():
    ticks, added = [], []
    doc = hwpdoc.read(_sample(), max_decompressed=MAX, tick=lambda: ticks.append(1), add=added.append)
    assert len(ticks) >= doc.stats["records"]
    assert "900101-1234567" in added and "가짜 제목" in added and "1 over 2" in added

    class Stop(Exception):
        pass

    def boom(_text):
        raise Stop

    with pytest.raises(Stop):
        hwpdoc.read(_sample(), max_decompressed=MAX, add=boom)
    calls = []

    def tick():
        calls.append(1)
        if len(calls) > 5:
            raise Stop

    with pytest.raises(Stop):
        hwpdoc.read(_sample(), max_decompressed=MAX, tick=tick)


def test_lines_with_spans_maps_paragraph_offsets():
    doc = hwpdoc.read(_sample(), max_decompressed=MAX)
    marks = {"body:t0:r1:c1:p0": [(0, 6)], "body:t0:r1:c1:p1": [(0, 2)], "body:p0": [(6, 9)], "body:p3": [(0, 2)]}
    lines, spans = doc.lines_with_spans(marks)
    assert lines == doc.lines()
    text = "\n".join(lines)
    assert [text[a:b] for a, b in spans] == ["홍길동", "900101", "둘째", "메모"]
    with pytest.raises(ValueError):
        doc.lines_with_spans({"side:eq0": [(0, 1)]})
    with pytest.raises(ValueError):
        doc.lines_with_spans({"body:p0": [(0, 99)]})
    # 공백뿐인 문단(줄에 없음)의 구간은 옮기지 않는다
    assert doc.lines_with_spans({"body:p1": [(0, 0)]})[1] == []


def test_summary_parser_bounds():
    good = S.summary_stream({2: "가짜 제목", 9: "x"})
    assert hwpdoc._summary_strings(good) == ["가짜 제목", "x"]
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc._summary_strings(good[:60])
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc._summary_strings(b"\x00" * 64)


def test_old_object_header_without_description():
    short = S.rec(71, 1, S.ctrl_id("gso ") + b"\x00" * 30)          # 옛 판: 개체 공통 속성이 46바이트보다 짧음
    doc = hwpdoc.read(S.build_hwp([S.p(0, "본문", short)]), max_decompressed=MAX)
    assert doc.lines() == ["본문"]


# ---------------------------------------------------------------- 글자 겹침(tcps) - 2026-10-11 검토 지적(한컴 서식 .hwt 23/334)

def _compose(level: int, chars: str, ids=(7, 7), tail: bytes = b"") -> bytes:
    """글자 겹침 컨트롤(HWP 5.0 규격 배치): ctrl ID, 겹칠 글자(WORD 길이 + WCHAR), 테두리 종류·안 글자 크기·펼침(BYTE 3),
    안 글자 모양 수 cnt(BYTE), 안 글자 모양 ID(UINT × cnt). 한컴 서식 359개 레코드가 모두 이 배치로 끝까지 맞음."""
    return S.rec(71, level, S.ctrl_id("tcps") + S.wstr(chars) + bytes([1, 0xFD, 0, len(ids)])
                 + b"".join(struct.pack("<I", i) for i in ids) + tail)


def test_compose_text_is_side_text_checked_not_body():
    raw = S.text_units("번호 ") + S.ext_ctrl(23, "tcps") + S.text_units(" 항목")    # 본문 자리에는 확장 제어 글자만
    sec = S.para(0, raw, _compose(1, "가9"), _compose(1, " ", ids=(3,)))
    doc = hwpdoc.read(S.build_hwp([sec]), max_decompressed=MAX)
    assert [p.text for p in doc.paragraphs] == ["번호  항목"]
    assert [(s.locator, s.kind, s.text) for s in doc.side] == [("side:compose0", "compose", "가9"),
                                                             ("side:compose1", "compose", " ")]
    assert doc.lines() == ["번호  항목", "가9", " "]                      # 검사 글자에 들어감


@pytest.mark.parametrize("record,error", [
    (_compose(1, "가", tail=b"\x00"), hwpdoc.HwpUnsupported),            # 규격보다 1바이트 김
    (S.rec(71, 1, S.ctrl_id("tcps") + S.wstr("가") + bytes([1, 0xFD, 0, 2]) + struct.pack("<I", 1)),
     hwpdoc.HwpUnsupported),                                             # cnt만큼 ID가 없음
    (S.rec(71, 1, S.ctrl_id("tcps") + S.wstr("가")), hwpdoc.HwpUnsupported),  # 글자 뒤 칸 없음
    (S.rec(71, 1, S.ctrl_id("tcps") + struct.pack("<H", 40) + b"\x00\x00"), hwpdoc.HwpCorrupt),  # 글자 길이가 레코드를 넘음
])
def test_compose_with_unexpected_layout_is_not_guessed(record, error):
    with pytest.raises(error) as e:
        hwpdoc.read(S.build_hwp([S.p(0, "본문", record)]), max_decompressed=MAX)
    if error is hwpdoc.HwpUnsupported:
        assert e.value.kind == "hwp_unsupported_object" and e.value.detail == "ctrl:tcps"


# ---------------------------------------------------------------- PARA_TEXT 조각 훑기·tick - 2026-10-11 검토 지적(tick 간격)

def _reference_para_text(raw: bytes):
    """독립 기준 해석기(단위마다 파이썬 반복, 규칙은 HWP 5.0 규격): (글자, 위치) 또는 'corrupt'."""
    if len(raw) % 2:
        return "corrupt"
    units = struct.unpack(f"<{len(raw) // 2}H", raw)
    text, offs, k = [], [], 0
    while k < len(units):
        c = units[k]
        if c < 32:
            if c in (0, 10, 13) or 24 <= c <= 31:
                ch = {10: "\n", 24: "-", 30: " ", 31: " "}.get(c)
                if ch:
                    text.append(ch)
                    offs.append(-1)
                k += 1
            else:
                if k + 8 > len(units):
                    return "corrupt"
                if c == 9:
                    text.append("\t")
                    offs.append(-1)
                k += 8
        elif 0xD800 <= c <= 0xDBFF and k + 1 < len(units) and 0xDC00 <= units[k + 1] <= 0xDFFF:
            text.append(chr(0x10000 + ((c - 0xD800) << 10) + (units[k + 1] - 0xDC00)))
            offs.append(2 * k)
            k += 2
        elif 0xD800 <= c <= 0xDFFF:
            text.append("�")
            offs.append(2 * k)
            k += 1
        else:
            text.append(chr(c))
            offs.append(2 * k)
            k += 1
    return "".join(text), offs


def _decode(raw: bytes):
    try:
        text, offs = hwpdoc._para_text(raw, 0, len(raw), lambda: None)
    except hwpdoc.HwpCorrupt:
        return "corrupt"
    return text, list(offs)


def test_para_text_chunk_boundaries_match_reference():
    """조각(64KiB) 경계에 인라인 제어(16바이트)·서로게이트 쌍·문단 끝이 걸쳐도 규격대로 해석."""
    chunk = hwpdoc._PT_CHUNK
    fill = S.text_units("가") * (chunk // 2)
    inline = struct.pack("<8H", 11, 0x6274, 0x206C, 0, 0, 0, 0, 11)
    pair = "😀".encode("utf-16-le")
    cases = []
    for back in (2, 4, 6, 14, 16):
        for piece in (inline, pair, struct.pack("<H", 13), struct.pack("<H", 0xDC00), struct.pack("<H", 0xD800)):
            body = fill[:chunk - back] + piece + S.text_units("나다") * 100
            cases.append(body)
    cases.append(fill[:chunk - 4] + inline[:6])                       # 경계 넘어 잘린 인라인 제어
    cases.append(S.text_units("䇘곘A가") * 40_000)             # 홀수 위치에 특수 바이트 모양이 많은 글자
    for raw in cases:
        assert _decode(raw) == _reference_para_text(raw)


def test_para_text_random_payloads_match_reference():
    import random

    rnd = random.Random(20261011)
    pool = [0x0D, 0x0A, 0x09, 0x18, 0x1E, 0x1F, 0x00, 0x02, 0x0B, 0x15, 0x17, 0xD800, 0xDBFF, 0xDC00, 0xDFFF,
            0x41D8, 0xACD8, 0x0041, 0xAC00, 0x00D8, 0xD83D, 0xDE00]
    for i in range(300):
        n = rnd.choice((0, 1, 3, 8, 9, 50, 400)) if i % 20 else rnd.choice((32_760, 32_768, 32_775, 70_000))
        units = [rnd.choice(pool) if rnd.random() < 0.4 else rnd.randrange(0x10000) for _ in range(n)]
        raw = struct.pack(f"<{n}H", *units)
        if i % 7 == 0 and raw:
            raw = raw[:-1]
        assert _decode(raw) == _reference_para_text(raw), i


def _tick_count(data: bytes) -> int:
    ticks = []
    hwpdoc.read(data, max_decompressed=MAX, tick=lambda: ticks.append(1))
    return len(ticks)


def test_long_para_text_ticks_per_chunk_and_per_specials():
    """긴 PARA_TEXT 하나 안에서도 tick이 불림 - 수정 전에는 특수 글자 4,096개마다만(일반 글자·홀수 위치 재탐색 구간은 0)."""
    base = _tick_count(S.build_hwp([S.p(0, "가")]))
    n = 400_000                                                        # 800KB = 64KiB 조각 13개
    assert _tick_count(S.build_hwp([S.p(0, "䇘" * n)])) - base >= (2 * n) // hwpdoc._PT_CHUNK - 1
    nbsp = S.para(0, struct.pack("<H", 30) * 20_000)                   # 40KB(조각 하나) 안 특수 글자 2만 개
    assert _tick_count(S.build_hwp([nbsp])) - base >= 20_000 // hwpdoc._PT_TICK_SPECIALS


def test_long_para_text_is_stopped_by_tick_inside_the_paragraph():
    class Stop(Exception):
        pass

    data = S.build_hwp([S.p(0, "䇘" * 400_000)])
    base = _tick_count(S.build_hwp([S.p(0, "가")]))
    calls = []

    def tick():
        calls.append(1)
        if len(calls) > base + 2:                  # 레코드·스트림 몫을 넘긴 뒤 = 문단 해석 도중
            raise Stop

    with pytest.raises(Stop):
        hwpdoc.read(data, max_decompressed=MAX, tick=tick)
