"""시험용 합성 HWP(CFB)·HWPX(ZIP) 만들기 - 표준 라이브러리만. 글자는 모두 가짜 값.

CFB 쓰기는 olefile이 못 하므로(같은 크기 덮어쓰기만 됨) 여기서 직접 만든다: 512바이트 섹터 v3, 4096바이트 미만
스트림은 미니 스트림(64바이트), 디렉터리는 이름 순 균형 트리. HWP 레코드·HWPX XML은 명세(HWP 5.0 rev1.3, OWPML)의
최소 모양만 채운다 - 추출기가 보는 칸(레코드 머리·PARA_TEXT·LIST_HEADER 칸 주소·컨트롤 ID·개체 설명문 등)은 정확히.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

SECTOR = 512
MINI = 64
CUTOFF = 4096
FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


# ------------------------------------------------------------------ CFB

class _Node:
    def __init__(self, name, kind, data=b""):
        self.name, self.kind, self.data = name, kind, data   # kind 5 root, 1 storage, 2 stream
        self.children: dict[str, _Node] = {}
        self.sid = 0
        self.left = self.right = self.child = NOSTREAM
        self.start = ENDOFCHAIN
        self.size = 0


def _cfb_key(name: str):
    return (len(name), name.upper())


def write_cfb(streams: dict[str, bytes]) -> bytes:
    """{"FileHeader": b"…", "BodyText/Section0": b"…"} → CFB 바이트."""
    root = _Node("Root Entry", 5)
    for path, data in streams.items():
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.children.setdefault(part, _Node(part, 1))
        node.children[parts[-1]] = _Node(parts[-1], 2, bytes(data))

    order: list[_Node] = []

    def number(node):
        node.sid = len(order)
        order.append(node)
        for child in sorted(node.children.values(), key=lambda n: _cfb_key(n.name)):
            number(child)

    number(root)

    def tree(nodes):
        if not nodes:
            return NOSTREAM
        mid = len(nodes) // 2
        n = nodes[mid]
        n.left, n.right = tree(nodes[:mid]), tree(nodes[mid + 1:])
        return n.sid

    for node in order:
        if node.kind in (1, 5):
            node.child = tree(sorted(node.children.values(), key=lambda n: _cfb_key(n.name)))

    streams_list = [n for n in order if n.kind == 2]
    minis = [n for n in streams_list if len(n.data) < CUTOFF]
    regs = [n for n in streams_list if len(n.data) >= CUTOFF]

    # 미니 스트림
    mini_fat: list[int] = []
    container = bytearray()
    for n in minis:
        n.size = len(n.data)
        if not n.data:
            n.start = ENDOFCHAIN
            continue
        count = -(-len(n.data) // MINI)
        n.start = len(mini_fat)
        for k in range(count):
            mini_fat.append(n.start + k + 1 if k < count - 1 else ENDOFCHAIN)
        container += n.data + b"\x00" * (count * MINI - len(n.data))
    n_dir = -(-len(order) // 4)
    n_minifat = -(-len(mini_fat) // 128) if mini_fat else 0
    n_container = -(-len(container) // SECTOR) if container else 0
    reg_counts = [-(-len(n.data) // SECTOR) for n in regs]
    nonfat = n_dir + n_minifat + n_container + sum(reg_counts)
    n_fat = 1
    while n_fat * 128 < n_fat + nonfat:
        n_fat += 1
    if n_fat > 109:
        raise ValueError("synthetic CFB too large for header DIFAT")

    fat = [FREESECT] * (n_fat * 128)
    pos = 0

    def chain(count):
        nonlocal pos
        start = pos
        for k in range(count):
            fat[pos] = pos + 1 if k < count - 1 else ENDOFCHAIN
            pos += 1
        return start if count else ENDOFCHAIN

    for _ in range(n_fat):
        fat[pos] = FATSECT
        pos += 1
    dir_start = chain(n_dir)
    minifat_start = chain(n_minifat)
    container_start = chain(n_container)
    for n, count in zip(regs, reg_counts):
        n.start = chain(count)
        n.size = len(n.data)
    root.start = container_start if container else ENDOFCHAIN
    root.size = len(container)

    def entry(n: _Node) -> bytes:
        name = n.name.encode("utf-16-le") + b"\x00\x00"
        if len(name) > 64:
            raise ValueError("CFB name too long")
        return (name.ljust(64, b"\x00") + struct.pack("<HBB", len(name), n.kind, 1)
                + struct.pack("<III", n.left, n.right, n.child) + b"\x00" * 16 + b"\x00" * 4 + b"\x00" * 16
                + struct.pack("<IQ", n.start, n.size))

    dirs = b"".join(entry(n) for n in order)
    dirs += (b"\x00" * 64 + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
             + b"\x00" * 36 + struct.pack("<IQ", 0, 0)) * (n_dir * 4 - len(order))
    difat = list(range(n_fat)) + [FREESECT] * (109 - n_fat)
    header = (CFB_MAGIC + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, CUTOFF,
                            minifat_start if n_minifat else ENDOFCHAIN, n_minifat, ENDOFCHAIN, 0)
              + struct.pack("<109I", *difat))
    assert len(header) == SECTOR

    def pad(b: bytes, count: int) -> bytes:
        return b + b"\x00" * (count * SECTOR - len(b))

    body = struct.pack(f"<{len(fat)}I", *fat)
    body += pad(dirs, n_dir)
    if n_minifat:
        body += pad(struct.pack(f"<{len(mini_fat)}I", *mini_fat) + struct.pack("<I", FREESECT) * (n_minifat * 128 - len(mini_fat)), n_minifat)
    if n_container:
        body += pad(bytes(container), n_container)
    for n, count in zip(regs, reg_counts):
        body += pad(n.data, count)
    return header + body


def set_stream_size(cfb: bytes, name: str, size: int) -> bytes:
    """디렉터리 항목 하나의 선언 크기를 바꾼 사본(조작 CFB 시험용)."""
    data = bytearray(cfb)
    dir_start = struct.unpack_from("<I", data, 48)[0]
    off = SECTOR + dir_start * SECTOR
    target = name.encode("utf-16-le") + b"\x00\x00"
    while off + 128 <= len(data):
        if data[off:off + len(target)] == target:
            struct.pack_into("<Q", data, off + 120, size)
            return bytes(data)
        off += 128
    raise KeyError(name)


# ------------------------------------------------------------------ HWP 레코드

def rec(tag: int, level: int, payload: bytes = b"") -> bytes:
    size = len(payload)
    if size >= 0xFFF:
        return struct.pack("<II", tag | (level << 10) | (0xFFF << 20), size) + payload
    return struct.pack("<I", tag | (level << 10) | (size << 20)) + payload


def wstr(s: str) -> bytes:
    raw = s.encode("utf-16-le")
    return struct.pack("<H", len(raw) // 2) + raw


def ctrl_id(cid: str) -> bytes:
    return cid.encode("latin-1")[::-1]


def ext_ctrl(code: int, cid: str = "") -> bytes:
    """확장·인라인 제어 글자 8 WCHAR(코드, 컨트롤 ID 2 WCHAR, 4 WCHAR 예약, 코드)."""
    return struct.pack("<H", code) + (ctrl_id(cid) if cid else b"\x00" * 4) + b"\x00" * 8 + struct.pack("<H", code)


def text_units(s: str) -> bytes:
    return s.encode("utf-16-le")


def para(level: int, raw_text: bytes | None, *children: bytes) -> bytes:
    """PARA_HEADER + PARA_TEXT(raw_text 끝에 문단 끝 13을 붙임) + 글자 모양 + 하위 레코드(level+1에 맞춰 만든 것)."""
    n_units = (len(raw_text) // 2 + 1) if raw_text is not None else 1
    out = rec(66, level, struct.pack("<IIHBBHHHI", n_units, 0, 0, 0, 0, 1, 0, 1, 0) + b"\x00\x00")
    if raw_text is not None:
        out += rec(67, level + 1, raw_text + struct.pack("<H", 13))
    out += rec(68, level + 1, struct.pack("<II", 0, 0))
    return out + b"".join(children)


def p(level: int, text: str, *children: bytes) -> bytes:
    return para(level, text_units(text) if text else None, *children)


def obj_common(cid: str, desc: str = "") -> bytes:
    """컨트롤 ID + 개체 공통 속성(46바이트 + 개체 설명문)."""
    return ctrl_id(cid) + struct.pack("<IiiIIi", 0, 0, 0, 1000, 1000, 0) + b"\x00" * 8 + struct.pack("<Ii", 1, 0) + wstr(desc)


def cell_header(level: int, row: int, col: int, rowspan: int = 1, colspan: int = 1, nparas: int = 1) -> bytes:
    payload = struct.pack("<hIH", nparas, 0, 0) + struct.pack("<HHHH", col, row, colspan, rowspan)
    payload += struct.pack("<II", 1000, 1000) + b"\x00" * 8 + struct.pack("<H", 1)
    return rec(72, level, payload)


def table(level: int, cells: list, rows: int, cols: int, desc: str = "", caption: list | None = None) -> bytes:
    """cells: [(row, col, rowspan, colspan, [문단 레코드(level+1)…]), …]. caption: 캡션 문단 레코드 목록."""
    out = rec(71, level, obj_common("tbl ", desc))
    if caption is not None:
        out += rec(72, level + 1, struct.pack("<hI", len(caption), 0) + b"\x00" * 8)
        out += b"".join(caption)
    out += rec(77, level + 1, struct.pack("<IHH", 0, rows, cols) + b"\x00" * 10 + struct.pack("<H", cols) * rows)
    for row, col, rowspan, colspan, paras in cells:
        out += cell_header(level + 1, row, col, rowspan, colspan, len(paras)) + b"".join(paras)
    return out


def textbox(level: int, paras: list, desc: str = "") -> bytes:
    """글상자: gso 컨트롤 아래 SHAPE_COMPONENT(+사각형), LIST_HEADER, 문단(level+1) - 팀 HWP 실측 모양."""
    out = rec(71, level, obj_common("gso ", desc))
    out += rec(76, level + 1, ctrl_id("$rec") * 2 + b"\x00" * 20) + rec(79, level + 2, b"\x00" * 20)
    out += rec(72, level + 1, struct.pack("<hI", len(paras), 0) + b"\x00" * 8)
    return out + b"".join(paras)


def picture(level: int, desc: str = "") -> bytes:
    out = rec(71, level, obj_common("gso ", desc))
    return out + rec(76, level + 1, ctrl_id("$pic") * 2 + b"\x00" * 20) + rec(85, level + 2, b"\x00" * 40)


def equation(level: int, script: str, desc: str = "") -> bytes:
    return rec(71, level, obj_common("eqed", desc)) + rec(88, level + 1, struct.pack("<I", 0) + wstr(script) + b"\x00" * 10)


def field(level: int, cid: str, command: str) -> bytes:
    return rec(71, level, ctrl_id(cid) + struct.pack("<IB", 0, 0) + wstr(command) + struct.pack("<I", 7))


def dutmal(level: int, main: str, sub: str) -> bytes:
    return rec(71, level, ctrl_id("tdut") + wstr(main) + wstr(sub) + b"\x00" * 20)


def header_ctrl(level: int, paras: list, which: str = "head") -> bytes:
    out = rec(71, level, ctrl_id(which) + struct.pack("<I", 0))
    out += rec(72, level + 1, struct.pack("<hI", len(paras), 0) + b"\x00" * 8)
    return out + b"".join(paras)


def plain_ctrl(level: int, cid: str, *children: bytes) -> bytes:
    return rec(71, level, ctrl_id(cid) + b"\x00" * 12) + b"".join(children)


def memo(level: int, paras: list) -> bytes:
    """메모: 문단의 하위(level)에 MEMO_LIST + LIST_HEADER + 메모 문단(같은 level)."""
    return rec(93, level, struct.pack("<I", 1)) + rec(72, level, struct.pack("<hI", len(paras), 0) + b"\x00" * 8) + b"".join(paras)


def summary_stream(props: dict[int, str]) -> bytes:
    """OLE 속성 집합(요약 정보) - 문자열 속성을 VT_LPWSTR로."""
    entries = []
    for pid, value in props.items():
        raw = (value + "\x00").encode("utf-16-le")
        body = struct.pack("<II", 0x1F, len(raw) // 2) + raw
        body += b"\x00" * (-len(body) % 4)
        entries.append((pid, body))
    head_len = 8 + 8 * len(entries)
    offsets, blob, pos = [], b"", head_len
    for pid, body in entries:
        offsets.append((pid, pos))
        blob += body
        pos += len(body)
    section = struct.pack("<II", head_len + len(blob), len(entries))
    section += b"".join(struct.pack("<II", pid, off) for pid, off in offsets) + blob
    fmtid = bytes.fromhex("60b6a29f6110d411b4c6006097c09d8c")   # {9FA2B660-1061-11D4-B4C6-006097C09D8C}
    header = struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\x00" * 16 + struct.pack("<I", 1) + fmtid + struct.pack("<I", 48)
    return header + section


def file_header(flags: int = 1, version: int = 0x05010100) -> bytes:
    return b"HWP Document File".ljust(32, b"\x00") + struct.pack("<II", version, flags) + b"\x00" * 216


def deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def build_hwp(sections: list[bytes], *, flags: int = 1, version: int = 0x05010100, summary: dict | None = None,
              prvtext: str | None = "", extra: dict | None = None, compress_raw=None) -> bytes:
    """sections: 구역마다 레코드 바이트. flags bit0이면 구역을 raw deflate. extra: 추가 스트림 {경로: 바이트}."""
    streams = {"FileHeader": file_header(flags, version), "DocInfo": rec(16, 0, b"\x00" * 26)}
    for i, sec in enumerate(sections):
        if flags & 1:
            streams[f"BodyText/Section{i}"] = compress_raw(sec) if compress_raw else deflate(sec)
        else:
            streams[f"BodyText/Section{i}"] = sec
    if summary is not None:
        streams["\x05HwpSummaryInformation"] = summary_stream(summary)
    if prvtext is not None:
        streams["PrvText"] = (prvtext + "\x00").encode("utf-16-le")
    streams.update(extra or {})
    return write_cfb(streams)


# ------------------------------------------------------------------ HWPX

HP = "http://www.hancom.co.kr/hwpml/2011/paragraph"
HS = "http://www.hancom.co.kr/hwpml/2011/section"
HH = "http://www.hancom.co.kr/hwpml/2011/head"
HM = "http://www.hancom.co.kr/hwpml/2011/master-page"
NSDECL = f'xmlns:hp="{HP}" xmlns:hs="{HS}" xmlns:hh="{HH}" xmlns:hm="{HM}"'

CONTAINER = ('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><ocf:container '
             'xmlns:ocf="urn:oasis:names:tc:opendocument:xmlns:container"><ocf:rootfiles>'
             '<ocf:rootfile full-path="Contents/content.hpf" media-type="application/hwpml-package+xml"/>'
             '</ocf:rootfiles></ocf:container>')
MANIFEST = ('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'
            '<odf:manifest xmlns:odf="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>')
HEADER = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><hh:head {NSDECL} version="1.4" secCnt="1">'
          '<hh:refList><hh:numberings itemCnt="1"><hh:numbering id="1" start="0">'
          '<hh:paraHead start="1" level="1" align="LEFT">^1.</hh:paraHead></hh:numbering></hh:numberings>'
          '</hh:refList></hh:head>')


def hpf(meta: dict | None = None) -> str:
    items = "".join(f'<opf:meta name="{k}" content="text">{v}</opf:meta>' for k, v in (meta or {}).items())
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><opf:package xmlns:opf="http://www.idpf.org/2007/opf/" '
            f'version="" unique-identifier="" id=""><opf:metadata><opf:title/><opf:language>ko</opf:language>{items}'
            '</opf:metadata><opf:manifest><opf:item id="section0" href="Contents/section0.xml" media-type="application/xml"/>'
            '</opf:manifest><opf:spine><opf:itemref idref="section0" linear="yes"/></opf:spine></opf:package>')


def section_xml(body: str) -> str:
    return f'<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><hs:sec {NSDECL}>{body}</hs:sec>'


def hp_p(*runs: str, pid: int = 0) -> str:
    return f'<hp:p id="{pid}" paraPrIDRef="0" styleIDRef="0">{"".join(runs)}<hp:linesegarray/></hp:p>'


def hp_run(inner: str) -> str:
    return f'<hp:run charPrIDRef="0">{inner}</hp:run>'


def hp_t(inner: str) -> str:
    return hp_run(f"<hp:t>{inner}</hp:t>")


def hp_tc(row: int, col: int, paras: str, rowspan: int = 1, colspan: int = 1) -> str:
    return (f'<hp:tc name="" header="0" borderFillIDRef="1"><hp:subList id="" textDirection="HORIZONTAL">{paras}</hp:subList>'
            f'<hp:cellAddr colAddr="{col}" rowAddr="{row}"/><hp:cellSpan colSpan="{colspan}" rowSpan="{rowspan}"/>'
            '<hp:cellSz width="1000" height="1000"/><hp:cellMargin left="0" right="0" top="0" bottom="0"/></hp:tc>')


def hp_tbl(rows: list[list[str]], *, caption: str = "", comment: str = "") -> str:
    """rows: [[tc xml…], …] (행마다 hp:tr)."""
    cap = f'<hp:caption side="TOP"><hp:subList>{caption}</hp:subList></hp:caption>' if caption else ""
    com = f"<hp:shapeComment>{comment}</hp:shapeComment>" if comment else ""
    trs = "".join(f"<hp:tr>{''.join(r)}</hp:tr>" for r in rows)
    return hp_run(f'<hp:tbl id="1" rowCnt="{len(rows)}" colCnt="2"><hp:sz width="1" height="1"/>{cap}{com}'
                  f'<hp:inMargin left="0" right="0" top="0" bottom="0"/>{trs}</hp:tbl>')


def build_hwpx(sections: list[str], *, meta: dict | None = None, extra: dict | None = None, prvtext: str = "",
               mimetype: str | None = "application/hwp+zip", manifest: str = MANIFEST, header: str = HEADER,
               drop: tuple = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if mimetype is not None:
            z.writestr(zipfile.ZipInfo("mimetype"), mimetype, compress_type=zipfile.ZIP_STORED)
        parts = {"version.xml": '<?xml version="1.0" encoding="UTF-8"?><hv:HCFVersion xmlns:hv="http://www.hancom.co.kr/hwpml/2011/version" major="5"/>',
                 "META-INF/container.xml": CONTAINER, "META-INF/manifest.xml": manifest,
                 "Contents/header.xml": header, "Contents/content.hpf": hpf(meta),
                 "settings.xml": '<?xml version="1.0" encoding="UTF-8"?><ha:HWPApplicationSetting xmlns:ha="http://www.hancom.co.kr/hwpml/2011/app"/>',
                 "Preview/PrvText.txt": prvtext}
        for i, sec in enumerate(sections):
            parts[f"Contents/section{i}.xml"] = section_xml(sec)
        parts.update(extra or {})
        for name, value in parts.items():
            if name in drop:
                continue
            z.writestr(name, value, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()
