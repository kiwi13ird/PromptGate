"""hwpdoc HWPX 단위 시험 - 합성 HWPX(가짜 개인정보)로 추출 규칙·닫힌 목록·강화 파서·압축 해제 상한을 확인한다."""

from __future__ import annotations

import io
import struct
import tracemalloc
import zipfile

import pytest

import hwp_synth as S
from hwp_synth import hp_p, hp_run, hp_t, hp_tbl, hp_tc
from preprocessing import hwpdoc

MAX = 20 * 1024 * 1024


def _ctrl(inner: str) -> str:
    return hp_run(f"<hp:ctrl>{inner}</hp:ctrl>")


def _sub(*paras: str) -> str:
    return f'<hp:subList id="" textDirection="HORIZONTAL">{"".join(paras)}</hp:subList>'


def _sample_sections():
    textbox = hp_run(f'<hp:rect id="5"><hp:sz width="1" height="1"/><hp:drawText>{_sub(hp_p(hp_t("칸 글상자")))}</hp:drawText></hp:rect>')
    nested = hp_tbl([[hp_tc(0, 0, hp_p(hp_t("중첩A"))), hp_tc(0, 1, hp_p(hp_t("중첩B")))]])
    sec0 = (
        hp_p(hp_t("문서 제목 홍길동"), _ctrl(f'<hp:header id="1" applyPageType="BOTH">{_sub(hp_p(hp_t("머리말 글자")))}</hp:header>'))
        + hp_p(hp_tbl([
            [hp_tc(0, 0, hp_p(hp_t("성명"))), hp_tc(0, 1, hp_p(hp_t("김가짜")))],
            [hp_tc(1, 0, hp_p(hp_t("주민등록번호"))),
             hp_tc(1, 1, hp_p(hp_t("900101-1234567")) + hp_p(hp_t("둘째 줄")) + hp_p(nested))],
            [hp_tc(2, 0, hp_p(hp_t("병합 칸")) + hp_p(textbox), colspan=2)],
        ], comment="표입니다."))
        + hp_p(hp_t("본문 끝 문단"),
               hp_run('<hp:equation id="7"><hp:shapeComment>수식입니다.</hp:shapeComment><hp:script>1 over 2</hp:script></hp:equation>'),
               _ctrl('<hp:fieldBegin id="9" type="HYPERLINK" name=""><hp:parameters cnt="1" name="">'
                     '<hp:stringParam name="Command">mailto:fake@example.com;1;0;0;</hp:stringParam></hp:parameters></hp:fieldBegin>'),
               hp_run('<hp:dutmal posType="TOP"><hp:mainText>본말</hp:mainText><hp:subText>덧말</hp:subText></hp:dutmal>'),
               hp_run('<hp:pic id="8"><hp:shapeComment>그림입니다. 원본 그림의 이름: fake.png</hp:shapeComment>'
                      '<hp:img binaryItemIDRef="image1"/></hp:pic>'),
               _ctrl(f"<hp:hiddenComment>{_sub(hp_p(hp_t('메모 글자')))}</hp:hiddenComment>"))
    )
    sec1 = hp_p(hp_t("둘째 구역 문단"),
                _ctrl(f'<hp:footNote number="1">{_sub(hp_p(hp_t("각주 글자")))}</hp:footNote>'),
                _ctrl(f'<hp:footer id="2" applyPageType="BOTH">{_sub(hp_p(hp_t("꼬리말")))}</hp:footer>'))
    return [sec0, sec1]


MASTER = (f'<?xml version="1.0" encoding="UTF-8"?><hm:masterPage {S.NSDECL} id="m0" type="BOTH">'
          f'{_sub(hp_p(hp_t("바탕쪽 글자")))}</hm:masterPage>')


def _sample(**kw):
    extra = {"Contents/masterpage0.xml": MASTER, "BinData/image1.png": b"\x89PNG" + b"0" * 10}
    extra.update(kw.pop("extra", {}))
    return S.build_hwpx(_sample_sections(), meta={"creator": "가짜 작성자"}, prvtext="미리보기 글자", extra=extra, **kw)


def test_layout_lines_and_locators():
    data = _sample()
    assert hwpdoc.sniff(data) == "hwpx"
    doc = hwpdoc.read(data, max_decompressed=MAX)
    assert doc.kind == "hwpx" and doc.media == 1
    assert doc.lines() == [
        "문서 제목 홍길동", "머리말 글자",
        "성명 | 김가짜", "주민등록번호 | 900101-1234567\n둘째 줄", "중첩A | 중첩B", "병합 칸", "칸 글상자",
        "본문 끝 문단", "메모 글자",
        "둘째 구역 문단", "각주 글자", "꼬리말",
        "표입니다.", "수식입니다.", "1 over 2", "mailto:fake@example.com;1;0;0;", "본말", "덧말",
        "그림입니다. 원본 그림의 이름: fake.png", "바탕쪽 글자", "ko", "가짜 작성자",
    ]
    by = {p.locator: p for p in doc.paragraphs}
    assert len(by) == len(doc.paragraphs)
    assert by["header0:p0"].text == "머리말 글자" and by["header0:p0"].block_order == 0
    assert by["body:t0:r1:c1:p1"].cell == (0, 1, 1, 1, 1)
    assert by["body:t0:r1:c1:t0:r0:c1:p0"].text == "중첩B"
    assert by["body:t0:r2:c0:p0"].cell == (0, 2, 0, 1, 2)
    assert by["body:t0:r2:c0:p2"].text == "칸 글상자"
    assert by["body:p3"].text == "메모 글자" and by["body:p4"].block_order == 3
    assert by["body:p5"].text == "각주 글자" and by["footer0:p0"].text == "꼬리말"
    assert by["body:p4"].stream == "Contents/section1.xml"
    assert {s.kind for s in doc.side} == {"desc", "eq", "field", "dutmal", "master", "meta"}
    assert doc.preview_text() == "미리보기 글자"


def test_same_structure_as_hwp_gives_same_body_lines():
    """같은 구조의 합성 HWP와 HWPX는 본문 줄이 같다(부가 글자 종류만 다름: 요약 정보 vs 바탕쪽·메타)."""
    from test_hwpdoc_hwp import _sample as hwp_sample

    hwp = hwpdoc.read(hwp_sample(), max_decompressed=MAX)
    hwpx = hwpdoc.read(_sample(), max_decompressed=MAX)
    assert hwp.lines()[:12] == hwpx.lines()[:12]
    assert [(p.locator, p.cell, p.block_order) for p in hwp.paragraphs if p.text.strip()] == \
        [(p.locator, p.cell, p.block_order) for p in hwpx.paragraphs if p.text.strip()]


def test_inline_elements_runs_and_offsets():
    para = hp_p(hp_t('가<hp:tab width="1" leader="0" type="1"/>나<hp:lineBreak/>다<hp:nbSpace/><hp:fwSpace/><hp:hyphen/>끝'
                     '<hp:markpenBegin color="#FFFF00"/>형광<hp:markpenEnd/>'),
                hp_t("010-1234-"), hp_t("5678"))
    doc = hwpdoc.read(S.build_hwpx([para]), max_decompressed=MAX)
    (p,) = doc.paragraphs
    assert p.text == "가\t나\n다  -끝형광010-1234-5678"
    assert list(p.offsets[:12]) == [0, -1, 1, -1, 2, -1, -1, -1, 3, 4, 5, 6]
    assert len(p.offsets) == len(p.text)


def test_table_without_cell_address_falls_back_to_positions():
    tbl = hp_run('<hp:tbl><hp:tr><hp:tc><hp:subList>' + hp_p(hp_t("가")) + '</hp:subList></hp:tc>'
                 '<hp:tc><hp:subList>' + hp_p(hp_t("나")) + '</hp:subList></hp:tc></hp:tr>'
                 '<hp:tr><hp:tc><hp:subList>' + hp_p(hp_t("다")) + '</hp:subList></hp:tc></hp:tr></hp:tbl>')
    doc = hwpdoc.read(S.build_hwpx([hp_p(tbl)]), max_decompressed=MAX)
    assert doc.lines()[:2] == ["가 | 나", "다"]
    assert [p.locator for p in doc.paragraphs[1:]] == ["body:t0:r0:c0:p0", "body:t0:r0:c1:p0", "body:t0:r1:c0:p0"]


@pytest.mark.parametrize("body,where", [
    (hp_p(hp_run("<hp:foo>비밀 값</hp:foo>")), "foo"),
    (hp_p('<hp:run charPrIDRef="0">앞 글자<hp:t>x</hp:t></hp:run>'), "run"),
    (hp_p('<hp:run charPrIDRef="0"><hp:t>x</hp:t>뒤 글자</hp:run>'), "tail:t"),
    (hp_p(hp_t("x")) + "문단 사이 글자", "tail:p"),
    ("앞 글자" + hp_p(hp_t("x")), "sec"),
])
def test_unknown_text_in_section(body, where):
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwpx([body]), max_decompressed=MAX)
    assert e.value.kind == "hwpx_unknown_text" and where in str(e.value)


@pytest.mark.parametrize("kw", [
    {"extra": {"settings.xml": '<?xml version="1.0"?><ha:s xmlns:ha="urn:x">비밀</ha:s>'}},
    {"extra": {"META-INF/container.rdf": '<?xml version="1.0"?><r>비밀</r>'}},
    {"extra": {"Contents/unknown.xml": '<?xml version="1.0"?><r><x>비밀</x></r>'}},
    {"header": S.HEADER.replace("</hh:refList>", "</hh:refList><hh:foo>비밀</hh:foo>")},
    {"extra": {"Contents/content.hpf": S.hpf().replace("<opf:spine>", "<opf:spine>비밀")}},
])
def test_unknown_text_in_other_parts(kw):
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwpx([hp_p(hp_t("본문"))], **kw), max_decompressed=MAX)
    assert e.value.kind == "hwpx_unknown_text"


@pytest.mark.parametrize("inner", [
    '<hp:ole id="1" binaryItemIDRef="ole1"/>', '<hp:textart text="글맵시 가짜"/>', '<hp:chart id="1"/>',
    '<hp:btn caption="버튼"/>', '<hp:edit/>', '<hp:video/>',
    '<hp:ctrl><hp:indexmark><hp:firstKey>열쇠</hp:firstKey></hp:indexmark></hp:ctrl>',
    '<hp:t>앞<hp:compose composeText="겹침"/></hp:t>',                 # 속성 글자 요소가 hp:t 안(정해진 자리 아님)
    '<hp:t>앞<hp:fieldBegin name="가짜 필드 이름"/></hp:t>',
])
def test_unsupported_objects(inner):
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwpx([hp_p(hp_t("본문"), hp_run(inner))]), max_decompressed=MAX)
    assert e.value.kind == "hwpx_unsupported_object"


# 글자 겹침(OWPML hp:compose - hp:run 직속, 글자는 composeText 속성, 안 글자 모양은 hp:charPr 자식)
_COMPOSE = ('<hp:compose circleType="SHAPE_CIRCLE" charSz="-3" composeType="SPREAD" charPrCnt="2" composeText="{}">'
            '<hp:charPr prIDRef="7"/><hp:charPr prIDRef="7"/></hp:compose>')


def test_compose_text_is_side_text():
    para = hp_p(hp_t("번호 "), hp_run(_COMPOSE.format("가9")), hp_t(" 항목"))
    doc = hwpdoc.read(S.build_hwpx([para]), max_decompressed=MAX)
    assert [p.text for p in doc.paragraphs] == ["번호  항목"]
    assert [(s.locator, s.text) for s in doc.side if s.kind == "compose"] == [("side:compose0", "가9")]
    assert doc.lines()[:2] == ["번호  항목", "가9"]                      # 본문 다음 부가 글자(발견 순서: 섹션 → 메타)


def test_compose_with_element_text_is_unknown_text():
    inner = '<hp:compose composeText="가">숨은 글자</hp:compose>'
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwpx([hp_p(hp_t("본문"), hp_run(inner))]), max_decompressed=MAX)
    assert e.value.kind == "hwpx_unknown_text"


@pytest.mark.parametrize("extra", [{"BinData/ole1.ole": b"x"}, {"BinData/noext": b"x"}, {"Contents/blob.bin": b"x"}])
def test_unsupported_entries(extra):
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwpx([hp_p(hp_t("본문"))], extra=extra), max_decompressed=MAX)
    assert e.value.kind == "hwpx_unsupported_object"


@pytest.mark.parametrize("name", ["Preview/PrvImage.png", "Preview/PrvImage.bmp", "Preview/PrvImage.gif",
                                  "Preview/PrvImage.jpg", "Scripts/headerScripts", "Scripts/sourceScripts"])
def test_known_preview_image_and_script_entries_are_skipped(name):
    extra = {name: b"\x89PNG" if name.startswith("Preview/") else "var x = 1;"}
    doc = hwpdoc.read(S.build_hwpx([hp_p(hp_t("본문"))], extra=extra), max_decompressed=MAX)
    assert [p.text for p in doc.paragraphs] == ["본문"] and {s.kind for s in doc.side} == {"meta"}


_HIDDEN_SECTION = S.section_xml(hp_p(hp_t("가짜 주민번호 900101-1234567")))


@pytest.mark.parametrize("name,kind", [
    # 2026-10-11 검토 재현(stage1-verify/v7_preview.py): 수정 전에는 모두 통과하고 lines()에 그 값이 없었음
    ("Preview/section1.xml", "hwpx_unknown_text"),
    ("Preview/x.txt", "hwpx_unsupported_object"),
    ("Scripts/section1.xml", "hwpx_unknown_text"),
    ("Scripts/foo.js", "hwpx_unsupported_object"),
    ("Preview/PrvText2.txt", "hwpx_unsupported_object"),
    ("Preview/PrvImage.svg", "hwpx_unsupported_object"),
    ("Preview/prvimage.png", "hwpx_unsupported_object"),            # 이름은 대소문자까지 정확히
    ("Scripts/headerScripts.bak", "hwpx_unsupported_object"),
    ("Preview/sub/PrvImage.png", "hwpx_unsupported_object"),
])
def test_other_preview_and_script_entries_are_checked_like_any_entry(name, kind):
    content = _HIDDEN_SECTION if name.endswith(".xml") else "가짜 주민번호 900101-1234567"
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(S.build_hwpx([hp_p(hp_t("평범한 본문 글자입니다"))], extra={name: content}), max_decompressed=MAX)
    assert e.value.kind == kind


def test_encrypted_declarations():
    manifest = ('<?xml version="1.0"?><odf:manifest xmlns:odf="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
                '<odf:file-entry odf:full-path="Contents/section0.xml"><odf:encryption-data/></odf:file-entry></odf:manifest>')
    for data in (S.build_hwpx([hp_p(hp_t("본문"))], manifest=manifest),
                 S.build_hwpx([hp_p(hp_t("본문"))], extra={"META-INF/encryption.xml": "<x/>"})):
        with pytest.raises(hwpdoc.HwpUnsupported) as e:
            hwpdoc.read(data, max_decompressed=MAX)
        assert e.value.kind == "hwpx_encrypted" and e.value.kind in hwpdoc.ENCRYPTED_KINDS
    # ZIP 항목 자체가 암호(일반 비트 0)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), "application/hwp+zip")
        z.writestr("Contents/section0.xml", b"\x00" * 40)
    raw = bytearray(buf.getvalue())             # zipfile은 암호 비트를 쓰지 않으므로 머리 두 곳에 직접 켠다
    for sig, at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = raw.rfind(sig)
        raw[pos + at] |= 0x1
    with pytest.raises(hwpdoc.HwpUnsupported) as e:
        hwpdoc.read(bytes(raw), max_decompressed=MAX)
    assert e.value.kind == "hwpx_encrypted"


def test_external_entity_and_entity_expansion_rejected(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("FILE-CONTENT-MARKER", encoding="utf-8")
    xxe = (f'<?xml version="1.0"?><!DOCTYPE hs:sec [<!ENTITY x SYSTEM "file:///{secret.as_posix()}">]>'
           f'<hs:sec {S.NSDECL}>{hp_p(hp_t("&x;"))}</hs:sec>')
    lol = ('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
           '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>'
           f'<hs:sec {S.NSDECL}>{hp_p(hp_t("&d;"))}</hs:sec>')
    for xml in (xxe, lol):
        data = S.build_hwpx([], extra={"Contents/section0.xml": xml})
        with pytest.raises(hwpdoc.HwpCorrupt):
            hwpdoc.read(data, max_decompressed=MAX)


@pytest.mark.parametrize("data", [
    S.build_hwpx([hp_p(hp_t("본문"))], mimetype="application/zip"),
    S.build_hwpx([hp_p(hp_t("본문"))], drop=("Contents/section0.xml",)),
    S.build_hwpx(["<hp:p><hp:run><hp:t>닫히지 않음</hp:run></hp:p>"]),
    b"PK\x03\x04" + b"\x00" * 100,
])
def test_corrupt_packages(data):
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(data, max_decompressed=MAX)


def test_sniff_rules():
    assert hwpdoc.sniff(S.build_hwpx([hp_p(hp_t("본문"))])) == "hwpx"
    no_mime = S.build_hwpx([hp_p(hp_t("본문"))], mimetype=None)
    assert hwpdoc.sniff(no_mime) == "hwpx"
    assert hwpdoc.read(no_mime, max_decompressed=MAX).lines()[0] == "본문"
    assert hwpdoc.sniff(S.build_hwpx([hp_p(hp_t("본문"))], mimetype="application/zip")) is None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
    assert hwpdoc.sniff(buf.getvalue()) is None
    assert hwpdoc.sniff(b"PK\x03\x04garbage") is None


def test_declared_entry_size_over_budget_is_too_large_before_reading():
    big = hp_p(hp_t("가" * (2 * 1024 * 1024)))
    data = S.build_hwpx([big])
    with pytest.raises(hwpdoc.HwpTooLarge):
        hwpdoc.read(data, max_decompressed=1024 * 1024)


def test_zip_bomb_section_is_too_large_and_memory_bounded():
    bomb = hp_p(hp_t("가")) + " " * (40 * 1024 * 1024)       # 40MiB 공백(압축하면 수십 KB)
    data = S.build_hwpx([bomb])
    assert len(data) < 500_000
    tracemalloc.start()
    try:
        with pytest.raises(hwpdoc.HwpTooLarge):
            hwpdoc.read(data, max_decompressed=MAX)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < len(data) * 4 + (4 << 20), peak


def _patch_declared_size(data: bytes, name: str, size: int) -> bytes:
    """로컬 머리·중앙 디렉터리의 '압축 푼 크기'를 거짓으로 줄인 사본."""
    out = bytearray(data)
    raw = name.encode()
    pos = 0
    while True:
        pos = out.find(b"PK\x03\x04", pos)
        if pos < 0:
            break
        nlen = struct.unpack_from("<H", out, pos + 26)[0]
        if out[pos + 30:pos + 30 + nlen] == raw:
            struct.pack_into("<I", out, pos + 22, size)
        pos += 4
    pos = 0
    while True:
        pos = out.find(b"PK\x01\x02", pos)
        if pos < 0:
            break
        nlen = struct.unpack_from("<H", out, pos + 28)[0]
        if out[pos + 46:pos + 46 + nlen] == raw:
            struct.pack_into("<I", out, pos + 24, size)
        pos += 4
    return bytes(out)


def test_declared_size_lie_is_corrupt():
    data = _patch_declared_size(S.build_hwpx([hp_p(hp_t("가" * 5000))]), "Contents/section0.xml", 100)
    with pytest.raises(hwpdoc.HwpCorrupt):
        hwpdoc.read(data, max_decompressed=MAX)


def test_callbacks_and_spans():
    ticks, added = [], []
    doc = hwpdoc.read(_sample(), max_decompressed=MAX, tick=lambda: ticks.append(1), add=added.append)
    assert len(ticks) >= doc.stats["elements"] > 0
    assert "900101-1234567" in added and "가짜 작성자" in added and "바탕쪽 글자" in added
    lines, spans = doc.lines_with_spans({"body:t0:r1:c1:p0": [(7, 14)], "body:p0": [(6, 9)]})
    text = "\n".join(lines)
    assert [text[a:b] for a, b in spans] == ["홍길동", "1234567"]
