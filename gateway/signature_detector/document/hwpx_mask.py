"""HWPX 표시 치환 가림 (2026-10-11, masking-design/SPEC.md §4.2, 3단계 Gateway).

문단마다 findings(칸 원문 좌표)로 새 글자를 만든다: 구간의 쓰기 가능 첫 위치(hp:t 글자 칸)에 replacement, 나머지 쓰기 가능
글자는 지우고, 요소 글자(탭·줄바꿈 등 -1)는 그대로. 구간에 쓰기 가능 위치가 없으면 MaskRefused.
  - 바뀐 문단만 hp:linesegarray 삭제(한컴이 열 때 줄 배치를 다시 계산)
  - zip을 새로 쓴다: 항목 순서·이름·날짜·압축 방식 유지, mimetype 맨 앞·무압축. zip 주석·추가 필드·항목 사이 빈 공간은
    옮기지 않는다(옛 바이트가 남지 않음)
  - Preview/PrvText.txt: 공백 아닌 글자를 모두 공백으로(줄바꿈 유지). Preview/PrvImage.*: 흰 그림(PNG·GIF·BMP, 그 밖은 MaskRefused)
문단 번호는 hwpdoc과 같은 순서로 다시 훑어 정한다(hwpdoc._Hwpx를 상속해 hp:t 글자 칸만 기록). hwpdoc이 뽑은 문단과
locator·글자·위치가 하나라도 다르면 MaskRefused. 새 글자가 Detection masked_text와 같은지는 부르는 쪽(hwp_segments)이 본다.
손대지 않음(DOCX와 같은 한계): 그림 속 글자. 하이퍼링크·메타데이터·바탕쪽은 부가 글자로 검사만 하고, 가려야 하면 MaskRefused.
"""

from __future__ import annotations

import io
import struct
import zipfile
from array import array

from signature_detector.contracts import MaskRefused
from signature_detector.document import hwpdoc
from signature_detector.document.hwp_mask import _WHITE_GIF, png_size, white_png

_LINESEG = hwpdoc._HP + "linesegarray"
_PREVIEW_TEXT = "Preview/PrvText.txt"


class _Recorder(hwpdoc._Hwpx):
    """hwpdoc._Hwpx와 같은 순서로 훑으며 문단마다 (hp:p 요소, 글자 칸 조각 [(요소, 'text'|'tail', 칸 시작, 길이)])를 남긴다."""

    def __init__(self, b):
        super().__init__(b)
        self.found: dict[int, tuple] = {}
        self._pieces = None

    def para(self, p, ctx):
        b = self.b
        pi = b.new_para(ctx, self.stream)
        parts: list[str] = []
        offs = array("i")
        slot = [0]
        controls: list = []
        if not hwpdoc._ws(p.text):
            self.unknown("p")
        pieces: list = []
        saved, self._pieces = self._pieces, pieces
        try:
            self.scan(list(p), parts, offs, slot, controls)
        finally:
            self._pieces = saved
        b.set_text(pi, "".join(parts), offs, ctx)
        if pi >= 0:
            self.found[pi] = (p, pieces)
        self.run_controls(controls, ctx)

    def t(self, t, parts, offs, slot):
        pieces = self._pieces

        def piece(node, attr, text):
            if text:
                pieces.append((node, attr, slot[0], len(text)))
                parts.append(text)
                offs.extend(range(slot[0], slot[0] + len(text)))
                slot[0] += len(text)

        piece(t, "text", t.text)
        for child in t:
            self.tick()
            if isinstance(child.tag, str):
                ch = hwpdoc._HX_CHARS.get(child.tag)
                self.check_no_text(child)
                if ch is not None:
                    parts.append(ch)
                    offs.append(-1)
            piece(child, "tail", child.tail)


def _walk_sections(zf, names: dict, doc, max_decompressed: int):
    """섹션 XML을 hwpdoc 순서로 훑어 {섹션 이름: (원본 바이트, 루트)}와 문단 기록을 돌려준다."""
    budget = hwpdoc._Budget(max_decompressed)
    builder = hwpdoc._Builder("hwpx", None, None, budget)
    recorder = _Recorder(builder)
    sections = sorted((int(m.group(1)), name) for name in names
                      if (m := hwpdoc._HX_SECTION_RE.fullmatch(name)))
    roots = {}
    for _, name in sections:
        recorder.stream = name
        raw = hwpdoc._zip_read(zf, names[name], budget)
        root = hwpdoc._xml(raw)
        roots[name] = (raw, root)
        recorder.para_list(root, builder.body, top=True)
    ours, theirs = builder.paragraphs, doc.paragraphs
    if len(ours) != len(theirs) or any(
            (a.locator, a.text, a.offsets.tobytes()) != (b.locator, b.text, b.offsets.tobytes())
            for a, b in zip(ours, theirs)):
        raise MaskRefused("hwpx_walk_mismatch")
    return roots, recorder.found


def _apply(para, pieces, spans) -> tuple[str, list[tuple[int, int]]]:
    """문단 하나의 글자 칸을 고친다(요소의 text·tail을 바꿈). 반환 (가린 뒤 문단 글자, 바꾼 구간(새 글자 좌표))."""
    text, offsets = para.text, para.offsets
    slots: list[str] = []
    for node, attr, start, length in pieces:
        value = node.text if attr == "text" else node.tail
        if start != len(slots) or value is None or len(value) != length:
            raise MaskRefused("hwpx_slot_mismatch")
        slots.extend(value)
    for index, at in enumerate(offsets):
        if at >= 0 and (at >= len(slots) or slots[at] != text[index]):
            raise MaskRefused("hwpx_slot_mismatch")
    out: list[str] = []
    marks: list[tuple[int, int]] = []
    cursor = length = 0
    for start, end, replacement in spans:
        out.append(text[cursor:start])
        length += start - cursor
        writable = [index for index in range(start, end) if offsets[index] >= 0]
        if not writable:
            raise MaskRefused("hwpx_no_writable_position")
        span: list[str] = []
        for index in range(start, end):
            at = offsets[index]
            if at < 0:
                span.append(text[index])            # 요소 글자(탭 등)는 그대로
            elif index == writable[0]:
                slots[at] = replacement
                span.append(replacement)
            else:
                slots[at] = ""
        piece = "".join(span)
        out.append(piece)
        marks.append((length, length + len(piece)))
        length += len(piece)
        cursor = end
    out.append(text[cursor:])
    try:
        for node, attr, start, size in pieces:
            value = "".join(slots[start:start + size]) or None
            if attr == "text":
                node.text = value
            else:
                node.tail = value
    except ValueError:                               # XML에 쓸 수 없는 글자(제어 문자 등)
        raise MaskRefused("hwpx_unwritable_text") from None
    return "".join(out), marks


def _drop_linesegarray(p) -> None:
    for child in list(p):
        if child.tag == _LINESEG:
            if child.tail:                           # 공백뿐(hwpdoc이 확인함)이지만 옮겨 둔다
                previous = child.getprevious()
                if previous is not None:
                    previous.tail = (previous.tail or "") + child.tail
                else:
                    p.text = (p.text or "") + child.tail
            p.remove(child)


def _serialize(raw: bytes, root) -> bytes:
    """원본 XML 선언(UTF-8이면 그대로)을 붙여 다시 쓴다. 다른 인코딩이면 lxml 선언."""
    from lxml import etree  # noqa: PLC0415 - 지연 import

    tree = root.getroottree()
    bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    body = raw[len(bom):]
    if body.startswith(b"<?xml"):
        end = body.find(b"?>")
        declaration = body[:end + 2] if end > 0 else b""
        encoding = (tree.docinfo.encoding or "UTF-8").upper()
        if declaration and encoding in ("UTF-8", "UTF8"):
            return bom + declaration + etree.tostring(tree, encoding="UTF-8", xml_declaration=False)
        return etree.tostring(tree, encoding=tree.docinfo.encoding or "UTF-8", xml_declaration=True,
                              standalone=tree.docinfo.standalone)
    return bom + etree.tostring(tree, encoding="UTF-8", xml_declaration=False)


def _blank_preview_text(raw: bytes) -> bytes:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        codec, bom = ("utf-16-le", raw[:2]) if raw[:2] == b"\xff\xfe" else ("utf-16-be", raw[:2])
        text = raw[2:].decode(codec, errors="replace")
    else:
        bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
        codec, text = "utf-8", raw[len(bom):].decode("utf-8", errors="replace")
    blank = "".join(char if char.isspace() or char == "\x00" else " " for char in text)
    return bom + blank.encode(codec)


def _white_bmp() -> bytes:
    pixels = b"\xff\xff\xff\x00"                     # 1×1 24비트 + 행 채움
    return (b"BM" + struct.pack("<IHHI", 14 + 40 + len(pixels), 0, 0, 54)
            + struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels), 2835, 2835, 0, 0) + pixels)


def _blank_preview_image(name: str, raw: bytes) -> bytes:
    ext = name.rsplit(".", 1)[-1].lower()
    if ext == "png":
        dims = png_size(raw) or (1, 1)
        return white_png(*dims)
    if ext == "gif":
        return _WHITE_GIF
    if ext == "bmp":
        return _white_bmp()
    raise MaskRefused("hwpx_preview_image")


def mask_hwpx(data: bytes, doc, edits: dict, *, max_decompressed: int):
    """edits = {문단 번호: [(start, end, replacement), ...]}(문단 글자 좌표, 겹치지 않게 정렬됨).
    반환 (가린 바이트, {문단 번호: 가린 뒤 글자}, {locator: [바꾼 구간(새 글자 좌표)]}). 실패는 MaskRefused."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        raise MaskRefused("hwpx_zip") from None
    with zf:
        infos = zf.infolist()
        names = {info.filename: info for info in infos}
        if len(names) != len(infos):
            raise MaskRefused("hwpx_zip")
        roots, found = _walk_sections(zf, names, doc, max_decompressed)
        new_texts: dict[int, str] = {}
        marks: dict[str, list] = {}
        changed_sections = set()
        for pi, spans in edits.items():
            para = doc.paragraphs[pi]
            if pi not in found:
                raise MaskRefused("hwpx_walk_mismatch")
            p, pieces = found[pi]
            new_texts[pi], marks[para.locator] = _apply(para, pieces, spans)
            _drop_linesegarray(p)
            changed_sections.add(para.stream)

        replaced: dict[str, bytes] = {}
        for name in changed_sections:
            raw, root = roots[name]
            replaced[name] = _serialize(raw, root)
        for name in names:
            if name == _PREVIEW_TEXT:
                replaced[name] = _blank_preview_text(zf.read(name))
            elif hwpdoc._HX_SKIPPED_RE.fullmatch(name) and name.startswith("Preview/PrvImage."):
                replaced[name] = _blank_preview_image(name, zf.read(name))

        out = io.BytesIO()
        ordered = sorted(infos, key=lambda info: info.filename != "mimetype")     # mimetype 맨 앞, 나머지 순서 그대로
        with zipfile.ZipFile(out, "w") as target:
            for info in ordered:
                entry = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                entry.compress_type = zipfile.ZIP_STORED if info.filename == "mimetype" else info.compress_type
                entry.external_attr = info.external_attr
                entry.create_system = info.create_system
                payload = replaced[info.filename] if info.filename in replaced else zf.read(info.filename)
                target.writestr(entry, payload)
    return out.getvalue(), new_texts, marks
