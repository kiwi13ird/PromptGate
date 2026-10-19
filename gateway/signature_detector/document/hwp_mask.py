"""HWP 5.0 같은 길이 가림 (2026-10-11, masking-design/SPEC.md §4.3, 3단계 Gateway).

가린 글자는 같은 자리에 같은 길이로 덮어쓴다(UTF-16 단위 수가 그대로라 레코드 크기가 바뀌지 않음).
  - 완전 가림(2026-10-12 사용자 결정, 모든 형식 같은 표시): 표시 '[유형]'(replacement가 '[A-Z0-9_]+' 꼴이면 그것, 아니면
    '[' + entity_type + ']' = 프롬프트·DOCX·HWPX와 같은 글자) + 원래 UTF-16 단위 수까지 공백. 표시가 더 길면 단위마다 '*'.
    표시를 쓴 구역이 원래 압축 크기를 못 맞추면 그 구역의 완전 가림만 '*'로 다시 시도(예전 결과, 그래도 못 맞추면 거절)
  - 부분 가림(그대로): replacement 길이가 구간과 같으면 그 글자, 아니면 '*'. 서로게이트 쌍·쓸 수 없는 글자는 단위마다 '*'
  - 구간 안에 제어 글자(-1, 탭·줄바꿈 등)가 있으면 MaskRefused
  - 바뀐 구역은 원래 압축 크기 그대로 다시 압축(deflate_exact). 못 맞추면 MaskRefused(사용자 결정: 차단)
  - 바뀐 구역의 레코드 (tag, level, size) 목록이 같아야 함
  - PrvText: 같은 길이, 공백·NUL 아닌 단위를 모두 U+0020. PrvImage: 같은 형식(PNG·GIF)·같은 바이트 수의 흰 그림, 못 만들면 MaskRefused
  - CFB는 스트림 크기가 그대로라 같은 섹터에 덮어쓴다. 쓴 뒤 안 쓰는 바이트(FAT 빈 섹터, FAT가 덮지 않는 섹터·파일 끝 조각,
    스트림 마지막 섹터 꼬리, 빈 미니 섹터, 미니 스트림 꼬리, 미니 스트림 컨테이너 꼬리)를 모두 0으로(팀 HWP 2/19의 빈 섹터에
    옛 글자가 있었음).
    다시 열어 모든 스트림이 기대한 바이트와 같은지 확인한다(다르면 MaskRefused). 파일 크기 = 원본
손대지 않음(한계): BinData 그림 속 글자, 디렉터리 빈 항목 이름, 디렉터리에서 닿지 않는 스트림.
olefile·hwpdoc 내부(_ole_open·_records·_inflate)는 hwpdoc과 같은 판으로만 쓴다(Detection과 md5가 같은 파일이라 고치지 않음).
"""

from __future__ import annotations

import re
import struct
import zlib

from signature_detector.contracts import MaskRefused
from signature_detector.document import hwpdoc
from signature_detector.policy import PolicyAction

FREESECT, ENDOFCHAIN = 0xFFFFFFFF, 0xFFFFFFFE
_STGTY_STREAM = 2
_PREVIEW_KEEP = frozenset({0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20})   # NUL·탭·줄바꿈 등은 그대로(나머지는 U+0020)
_TOKEN_RE = re.compile(r"\[[A-Z0-9_]+\]")      # Detection 완전 가림 표시(masker REPLACEMENTS·'[유형]')


# ------------------------------------------------------------------ 같은 크기 deflate

class _Bits:
    def __init__(self):
        self.bits: list[int] = []

    def put(self, value: int, n: int) -> None:      # deflate 머리 칸은 낮은 비트부터
        for i in range(n):
            self.bits.append((value >> i) & 1)

    def tobytes(self) -> bytes:
        while len(self.bits) % 8:
            self.bits.append(0)
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            out.append(sum(self.bits[i + j] << j for j in range(8)))
        return bytes(out)


def _empty_tail(n_fixed: int, final_stored: bool) -> bytes:
    """빈 고정 허프만 블록 n_fixed개(+ 마지막 빈 저장 블록). final_stored가 거짓이면 마지막 고정 블록이 BFINAL=1."""
    w = _Bits()
    for k in range(n_fixed):
        w.put(1 if (k == n_fixed - 1 and not final_stored) else 0, 1)
        w.put(1, 2)        # BTYPE=01 고정
        w.put(0, 7)        # 블록 끝(코드 256)
    if final_stored:
        w.put(1, 1)
        w.put(0, 2)
        return w.tobytes() + b"\x00\x00\xff\xff"
    return w.tobytes()


def _tails() -> dict[int, bytes]:
    tails: dict[int, bytes] = {}
    for n_fixed in range(8):
        for final_stored in (False, True):
            if n_fixed or final_stored:
                tail = _empty_tail(n_fixed, final_stored)
                tails.setdefault(len(tail), tail)
    return tails


_TAILS = _tails()
_FILLER = b"\x00\x00\x00\xff\xff"        # 바이트 경계의 빈 '마지막 아님' 저장 블록
# (level, memLevel, strategy): 스파이크(feasibility hwp5lite.deflate_exact)의 9→1 순서에 앞에 두 가지를 더 둔다
_ATTEMPTS = ([(9, 9, zlib.Z_DEFAULT_STRATEGY), (9, 9, zlib.Z_FILTERED)]
             + [(level, 8, zlib.Z_DEFAULT_STRATEGY) for level in range(9, 0, -1)])


def deflate_exact(data: bytes, target: int) -> bytes | None:
    """data의 raw deflate로 길이가 정확히 target인 것(뒤 쓰레기 없는 온전한 압축열). 못 만들면 None."""
    low, high = min(_TAILS), max(_TAILS)
    for level, mem_level, strategy in _ATTEMPTS:
        c = zlib.compressobj(level, zlib.DEFLATED, -15, mem_level, strategy)
        body = c.compress(data) + c.flush(zlib.Z_FULL_FLUSH)      # 바이트 경계, 마지막 아님
        pad = target - len(body)
        if pad < low:
            continue
        fill = b""
        while pad - len(fill) not in _TAILS and pad - len(fill) > high:
            fill += _FILLER
        rest = pad - len(fill)
        if rest in _TAILS:
            return body + fill + _TAILS[rest]
    return None


def _inflates_to(blob: bytes, expected: bytes) -> bool:
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(blob, len(expected) + 1)
    except zlib.error:
        return False
    return out == expected and d.eof and not d.unused_data and not d.unconsumed_tail


# ------------------------------------------------------------------ 같은 크기 흰 그림

def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def white_png(width: int = 1, height: int = 1, level: int = 9) -> bytes:
    """흰 8비트 회색조 PNG. 너무 큰 크기(4M 화소 초과)는 1×1."""
    if not (0 < width and 0 < height and width * height <= 4_000_000):
        width = height = 1
    raw = (b"\x00" + b"\xff" * width) * height
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(raw, level)) + _png_chunk(b"IEND", b""))


def png_size(data: bytes) -> tuple[int, int] | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR" and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    return None


def _png_exact(size: int, original: bytes) -> bytes | None:
    """흰 PNG(원래 크기 → 1×1, 압축 수준 9 → 0) 뒤에 채움 칸을 넣어 size 바이트로. 채움 칸은 20바이트 이상이면 표준
    tEXt('Comment\\0' + 공백, 스파이크와 같음), 12~19바이트면 비공개 보조 칸 'prVw'(읽는 쪽이 건너뜀)."""
    dims = png_size(original)
    for width, height in ([dims] if dims else []) + [(1, 1)]:
        for level in range(9, -1, -1):
            base = white_png(width, height, level)
            pad = size - len(base)
            if pad == 0:
                return base
            if pad >= 12:
                iend = len(base) - 12
                chunk = (_png_chunk(b"tEXt", b"Comment\x00" + b" " * (pad - 20)) if pad >= 20
                         else _png_chunk(b"prVw", b" " * (pad - 12)))
                return base[:iend] + chunk + base[iend:]
    return None


_WHITE_GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\xff\xff\xff"
              b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")


def _gif_exact(size: int) -> bytes | None:
    """흰 1×1 GIF + 주석 확장(21 FE … 00)으로 크기를 맞춤. 채울 양이 1·2·4바이트면 못 맞춤."""
    pad = size - len(_WHITE_GIF)
    if pad == 0:
        return _WHITE_GIF
    if pad == 3 or pad >= 5:
        blocks, left = [], pad - 3
        while left:
            n = min(255, left - 1)
            if left - (n + 1) == 1:
                n -= 1
            blocks.append(bytes([n]) + b" " * n)
            left -= n + 1
        return _WHITE_GIF[:-1] + b"\x21\xfe" + b"".join(blocks) + b"\x00" + _WHITE_GIF[-1:]
    return None


def blank_image_same_size(original: bytes) -> bytes | None:
    """미리보기 그림(PrvImage)을 같은 형식·같은 바이트 수의 흰 그림으로. PNG·GIF만, 못 맞추면 None."""
    if original[:8] == b"\x89PNG\r\n\x1a\n":
        return _png_exact(len(original), original)
    if original[:6] in (b"GIF87a", b"GIF89a"):
        return _gif_exact(len(original))
    return None


def blank_preview_text_units(raw: bytes) -> bytes:
    """UTF-16LE 미리보기 글자: 같은 길이, 공백·NUL 아닌 단위를 모두 U+0020."""
    if len(raw) % 2:
        raise MaskRefused("hwp_preview_text_odd")
    units = struct.unpack(f"<{len(raw) // 2}H", raw)
    return struct.pack(f"<{len(units)}H", *(u if u in _PREVIEW_KEEP or chr(u).isspace() else 0x20 for u in units))


# ------------------------------------------------------------------ CFB 배치

def _chain(table, start: int, limit: int, need: int) -> list[int]:
    """start부터 사슬을 따라간 섹터 번호 need개. 길이가 다르거나 범위 밖·순환이면 MaskRefused."""
    out: list[int] = []
    sector = start
    while sector not in (ENDOFCHAIN, FREESECT):
        if len(out) >= need or sector >= limit or sector >= len(table):
            raise MaskRefused("hwp_cfb_chain")
        out.append(sector)
        sector = table[sector]
    if len(out) != need:
        raise MaskRefused("hwp_cfb_chain")
    return out


class _Layout:
    """olefile이 읽은 FAT·미니 FAT·디렉터리로 스트림 바이트가 파일 어디에 있는지 계산한다(크기 그대로 덮어쓰기·0 처리용)."""

    def __init__(self, ole, total: int):
        self.ole = ole
        self.ss = ole.sectorsize
        self.mss = ole.minisectorsize
        self.cutoff = ole.minisectorcutoff
        self.nsec = (total - self.ss) // self.ss
        self.fat = ole.fat
        self.total = total
        root = ole.root
        self.mini_chain: list[int] = []
        self.minifat = []
        if root.size:
            self.mini_chain = _chain(self.fat, root.isectStart, self.nsec, -(-root.size // self.ss))
            ole.loadminifat()
            self.minifat = ole.minifat

    def off(self, sector: int) -> int:
        return (sector + 1) * self.ss

    def mini_off(self, pos: int) -> int:
        """미니 스트림 컨테이너 안 위치 → 파일 위치."""
        index = pos // self.ss
        if index >= len(self.mini_chain):
            raise MaskRefused("hwp_cfb_chain")
        return self.off(self.mini_chain[index]) + pos % self.ss

    def runs(self, entry) -> list[tuple[int, int]]:
        """스트림 바이트의 (파일 위치, 길이) 목록(앞에서부터)."""
        size = entry.size
        if not size:
            return []
        if size >= self.cutoff:
            sectors = _chain(self.fat, entry.isectStart, self.nsec, -(-size // self.ss))
            return [(self.off(s), min(self.ss, size - k * self.ss)) for k, s in enumerate(sectors)]
        minis = _chain(self.minifat, entry.isectStart, len(self.minifat), -(-size // self.mss))
        return [(self.mini_off(m * self.mss), min(self.mss, size - k * self.mss)) for k, m in enumerate(minis)]

    def entry(self, path: str):
        try:
            return self.ole.direntries[self.ole._find(path)]
        except Exception:  # noqa: BLE001
            raise MaskRefused("hwp_cfb_entry") from None

    def write(self, buf: bytearray, path: str, data: bytes) -> None:
        entry = self.entry(path)
        if entry.size != len(data):
            raise MaskRefused("hwp_stream_size")
        pos = 0
        for at, length in self.runs(entry):
            buf[at:at + length] = data[pos:pos + length]
            pos += length

    def zero_unused(self, buf: bytearray) -> None:
        """스트림이 쓰지 않는 바이트를 모두 0으로(명세 §4.3, exp/critic2/cfb_zero_free.py의 zero_unused와 같은 범위)."""
        ss, mss = self.ss, self.mss

        def wipe(a: int, b: int) -> None:
            b = min(b, len(buf))
            if b > a:
                buf[a:b] = bytes(b - a)

        for sector in range(min(self.nsec, len(self.fat))):          # ① FAT 빈 섹터
            if self.fat[sector] == FREESECT:
                wipe(self.off(sector), self.off(sector) + ss)
        # ①' FAT가 덮지 않는 섹터·파일 끝의 섹터 크기 미만 조각(어느 스트림도 못 읽는 자리, 2026-10-12 보강)
        wipe(self.off(min(self.nsec, len(self.fat))), self.total)
        for entry in self.ole.direntries:                            # ② 스트림 마지막 (미니) 섹터의 꼬리
            if entry is None or entry.entry_type != _STGTY_STREAM or not entry.size:
                continue
            at, length = self.runs(entry)[-1]        # at = 그 (미니) 섹터의 시작 위치. 미니 섹터는 섹터를 넘지 않음
            wipe(at + length, at + (ss if entry.size >= self.cutoff else mss))
        if self.mini_chain:                                          # ③ 빈 미니 섹터 + 컨테이너 꼬리
            limit = len(self.mini_chain) * ss
            for mini, value in enumerate(self.minifat):
                if value == FREESECT and (mini + 1) * mss <= limit:
                    at = self.mini_off(mini * mss)
                    wipe(at, at + mss)
            tail = self.ole.root.size - (len(self.mini_chain) - 1) * ss
            if 0 < tail < ss:
                wipe(self.off(self.mini_chain[-1]) + tail, self.off(self.mini_chain[-1]) + ss)


def _all_streams(data: bytes) -> dict[str, bytes]:
    ole = hwpdoc._ole_open(data)
    try:
        return {"/".join(entry): ole.openstream(entry).read() for entry in ole.listdir(streams=True, storages=False)}
    finally:
        ole.close()


# ------------------------------------------------------------------ 가림

def _writable(char: str) -> bool:
    code = ord(char)
    return 0x20 <= code <= 0xFFFF and not 0xD800 <= code <= 0xDFFF


def full_mask_token(finding) -> str | None:
    """완전 가림 값에 쓸 표시(프롬프트·DOCX·HWPX와 같은 글자). replacement가 '[A-Z0-9_]+' 꼴이면 그것(정책이 부분 가림이어도
    부분 가림 규칙이 없는 유형은 Detection이 표시를 준다), 정책이 MASK_FULL인데 표시 꼴이 아니면 '[' + entity_type + ']'.
    그 밖(부분 가림 글자)은 None."""
    replacement = finding.replacement
    if replacement is not None and _TOKEN_RE.fullmatch(replacement):
        return replacement
    if finding.policy_action is PolicyAction.MASK_FULL:
        return f"[{finding.entity_type}]"
    return None


def _plan_paragraph(para, spans, tokens: bool = True) -> tuple[list[tuple[int, str]], str, list[tuple[int, int]]]:
    """문단 하나의 덮어쓰기 목록 [(구역 안 바이트 위치, 한 단위 글자)], 가린 뒤 문단 글자, 바꾼 구간(새 글자 좌표).
    spans = [(start, end, replacement[, token])]. token(full_mask_token)이 있으면 완전 가림: 표시 + 공백(구간의 UTF-16 단위
    수까지), 표시가 더 길거나 쓸 수 없는 글자가 있거나 tokens=False(크기 못 맞춘 구역 재시도)면 단위마다 '*'.
    token이 없으면 부분 가림(예전과 같음). 바꾼 구간은 tokens와 상관없이 같다."""
    text, offsets = para.text, para.offsets
    writes: list[tuple[int, str]] = []
    out: list[str] = []
    marks: list[tuple[int, int]] = []
    cursor = length = 0
    for start, end, replacement, *rest in spans:
        token = rest[0] if rest else None
        out.append(text[cursor:start])
        length += start - cursor
        same = len(replacement) == end - start
        slots: list[tuple[int, str]] = []           # 구간의 UTF-16 단위마다 (바이트 위치, 부분 가림 규칙의 글자)
        for index in range(start, end):
            at = offsets[index]
            if at < 0:
                raise MaskRefused("hwp_control_in_span")
            units = 2 if ord(text[index]) > 0xFFFF else 1
            char = replacement[index - start] if same else "*"
            if units == 2 or not _writable(char):
                char = "*"
            slots.extend((at + 2 * unit, char) for unit in range(units))
        if token is not None:
            fits = tokens and len(token) <= len(slots) and all(_writable(char) for char in token)
            chars = token.ljust(len(slots)) if fits else "*" * len(slots)
            slots = [(at, char) for (at, _), char in zip(slots, chars)]
        new: list[str] = []
        for at, char in slots:
            writes.append((at, char))
            new.append(char)
        out.append("".join(new))
        marks.append((length, length + len(new)))
        length += len(new)
        cursor = end
    out.append(text[cursor:])
    return writes, "".join(out), marks


def mask_hwp(data: bytes, doc, edits: dict, *, max_decompressed: int):
    """edits = {문단 번호: [(start, end, replacement[, token]), ...]}(문단 글자 좌표, 겹치지 않게 정렬됨, token은 _plan_paragraph).
    반환 (가린 바이트, {문단 번호: 가린 뒤 글자}, {locator: [바꾼 구간(새 글자 좌표)]}). 실패는 MaskRefused."""
    plans: dict[str, list] = {}         # 구역 → [(문단 번호, (덮어쓰기, 글자) 표시판, '*'판)]
    new_texts: dict[int, str] = {}
    marks: dict[str, list] = {}
    for pi, spans in edits.items():
        para = doc.paragraphs[pi]
        writes, new_text, para_marks = _plan_paragraph(para, spans)
        stars = (writes, new_text)
        if any(len(span) > 3 and span[3] is not None for span in spans):
            stars = _plan_paragraph(para, spans, tokens=False)[:2]
        plans.setdefault(para.stream, []).append((pi, (writes, new_text), stars))
        marks[para.locator] = para_marks

    ole = hwpdoc._ole_open(data)
    try:
        budget = hwpdoc._Budget(max_decompressed)
        header = hwpdoc._ole_read(ole, "FileHeader", len(data), budget, count=False)
        compressed = bool(struct.unpack_from("<I", header, 36)[0] & hwpdoc.FLAG_COMPRESSED)
        layout = _Layout(ole, len(data))
        replaced: dict[str, bytes] = {}
        for stream, paras in plans.items():
            raw = hwpdoc._ole_read(ole, stream, len(data), budget, count=not compressed)
            plain = hwpdoc._inflate(raw, budget) if compressed else raw
            records = [(tag, level, size) for tag, level, _, size in hwpdoc._records(plain)]
            variants = [[tokened for _, tokened, _ in paras]]
            if any(stars is not tokened for _, tokened, stars in paras):
                variants.append([stars for _, _, stars in paras])
            blob = None
            for number, variant in enumerate(variants):
                buf = bytearray(plain)
                for writes, _ in variant:
                    for at, char in writes:
                        if not 0 <= at <= len(buf) - 2:
                            raise MaskRefused("hwp_offset")
                        struct.pack_into("<H", buf, at, ord(char))
                new_plain = bytes(buf)
                if [(tag, level, size) for tag, level, _, size in hwpdoc._records(new_plain)] != records:
                    raise MaskRefused("hwp_record_structure")
                if not compressed:
                    blob = new_plain
                    break
                blob = deflate_exact(new_plain, len(raw))
                if blob is not None and _inflates_to(blob, new_plain):
                    break
                blob = None
            if blob is None:
                print(f"[HWP-MASK] section size cannot be matched bytes={len(raw)}")
                raise MaskRefused("hwp_section_size")
            if number:
                print(f"[HWP-MASK] section size kept only with '*' for full masks bytes={len(raw)}")
            for (pi, _, _), (_, new_text) in zip(paras, variant):
                new_texts[pi] = new_text
            replaced[stream] = blob
        if ole.exists("PrvText"):
            raw = hwpdoc._ole_read(ole, "PrvText", len(data), budget, count=False)
            replaced["PrvText"] = blank_preview_text_units(raw)
        if ole.exists("PrvImage"):
            raw = hwpdoc._ole_read(ole, "PrvImage", len(data), budget, count=False)
            blank = blank_image_same_size(raw)
            if blank is None or len(blank) != len(raw):
                raise MaskRefused("hwp_preview_image")
            replaced["PrvImage"] = blank
        out = bytearray(data)
        for path, blob in replaced.items():
            layout.write(out, path, blob)
        layout.zero_unused(out)
    finally:
        ole.close()

    masked = bytes(out)
    expected = _all_streams(data)
    expected.update(replaced)
    if len(masked) != len(data) or _all_streams(masked) != expected:
        raise MaskRefused("hwp_stream_check")
    return masked, new_texts, marks
