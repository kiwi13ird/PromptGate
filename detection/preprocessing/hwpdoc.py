"""HWP 5.0·HWPX 글자 추출 - Detection·Gateway 공통 모듈 (2026-10-11, 명세 masking-design/SPEC.md §2.1).

같은 파일을 두 곳에 둔다(md5 동일): Detection `preprocessing/hwpdoc.py`, Gateway `signature_detector/document/hwpdoc.py`.
창 해시는 글자 내용·순서만 보므로, 등록(Detection)과 업로드 검사(Gateway)가 같은 코드로 글자를 뽑으면 일치가 보장된다.
그래서 이 파일은 패키지 상대 import를 쓰지 않고, 맨 위에서는 표준 라이브러리만 부른다(olefile·lxml은 함수 안에서).
Python 3.11 문법까지만 쓴다.

닫힌 목록: 아는 글자 위치만 뽑고, 모르는 글자 개체가 있으면 HwpUnsupported(호출한 쪽에서 '그 밖 형식'으로 차단).
  HWP  본문 글자     PARA_TEXT(67)                                  → paragraphs
       부가 글자     수식(EQEDIT 88), 필드 명령(%로 시작하는 컨트롤), 덧말(tdut), 글자 겹침(tcps, 규격 배치일 때만),
                     개체 설명문(표·그리기·수식 컨트롤의 개체 공통 속성), 요약 정보 문자열 → side (검사만, 가리지 않음)
       글자 없는 구조 66, 68~75, 77, 76·78~83·86(도형), 85(그림), 92·93(메모 머리)
       그 밖 전부    OLE(84)·CTRL_DATA(87)·글맵시(90)·양식(91)·차트(95)·변경 추적(96·97)·동영상(98)·모르는 번호,
                     모르는 컨트롤 ID(찾아보기 idxm 포함), 그림 아닌 BinData, 모르는 스트림 → hwp_unsupported_object
  HWPX 섹션 XML의 글자 데이터는 hp:t(하위 요소 꼬리 포함)만 본문. hp:script(수식)·*Param(필드 매개변수)·
       hp:mainText/hp:subText(덧말)·hp:shapeComment(개체 설명문), fieldBegin·bookmark의 name 속성,
       hp:compose(글자 겹침)의 composeText 속성 → side.
       바탕쪽(masterpage*.xml) 글자 → side(master), content.hpf 메타데이터 → side(meta).
       다른 요소에 글자 데이터 → hwpx_unknown_text, 속성에 글자를 담는 개체(OLE·차트·글맵시·양식·동영상·찾아보기)·
       그림 아닌 BinData·모르는 비 XML 항목 → hwpx_unsupported_object.
       미리보기는 Preview/PrvText.txt·PrvImage.(png|bmp|gif|jpg)만, 스크립트는 Scripts/headerScripts·sourceScripts만
       이름으로 건너뛴다. 그 밖 이름은 일반 항목과 같이(XML이면 글자 검사, 아니면 hwpx_unsupported_object)
  손대지 않음(한계): HWP `Scripts`·`DocOptions` 스트림·DocInfo(글꼴·스타일·번호 형식), HWPX Scripts/headerScripts·
       sourceScripts·header.xml의 번호 형식(hh:paraHead)·금칙 문자·스타일 메타, 속성 값 전반, 그림 속 글자,
       디렉터리 빈 항목 이름

공개 API
  sniff(data) -> 'hwp' | 'hwpx' | None
  read(data, *, max_decompressed, tick=None, add=None) -> HwpDoc
      tick(): HWP 레코드·HWPX 요소마다, PARA_TEXT 안에서는 64KiB·특수 글자 4,096개마다 부른다(호출한 쪽의 시간 한도).
      add(text): 문단·부가 글자를 뽑을 때마다(글자 수 한도). 두 콜백이 던진 예외는 그대로 밖으로 나간다.
  HwpDoc.lines() / layout() / lines_with_spans(marks) / preview_text() / paragraph_text()(미리보기 대조용)
  HwpDoc.body_lines() / body_layout(): 부가 글자 줄을 뺀 본문만 = lines()의 앞부분(Detection 등록용, Gateway 검사는 lines())
  예외 HwpUnsupported(kind) / HwpCorrupt / HwpTooLarge (모두 HwpError)

상한(모두 max_decompressed 하나에서 정함, 넘으면 HwpTooLarge)
  압축을 푼(HWPX는 읽은) 바이트 합 ≤ max_decompressed, 문단·표·표 칸·부가 글자 수 ≤ max_decompressed // 64,
  HWPX XML의 '<' 수 합 ≤ max_decompressed // 16(파싱 전에 셈). CFB는 olefile에 넘기기 전에 머리 칸을 확인하고
  olefile 안의 제곱 시간 함수 셋을 선형판으로 바꿔 연다(_cfb_header_check·_ole_class). olefile이 여는 동안은 tick()이
  불리지 않는다(20MiB 조작 파일 최악 실측은 STAGE1_NOTES).

칸 번호(locator, DOCX 문법): 표 밖 문단 `{영역}:p{N}`(영역 body·header{i}·footer{i}), 표 안
`{영역}:t{T}:r{R}:c{C}:p{K}`(중첩 표는 `…:c{C}:t{순번}:r..:c..:p{K}`), 부가 글자 `side:{kind}{N}`.
N·K는 그 영역·칸 안 문단 순번(빈 문단 포함, 글상자·각주·메모처럼 표가 아닌 하위 목록의 문단도 같은 순번을 이어 씀).
R·C는 칸 주소(HWP LIST_HEADER +10·+8, HWPX hp:cellAddr). block_order = 그 문단을 품은 최상위 문단 순번(구역 넘어 이어 셈).

글자 배치(lines): 표 밖 문단 한 줄, 표는 행마다 칸 글자(칸 안 문단은 '\\n')를 ' | '로 잇고, 칸 안의 중첩 표·글상자 등은
그 행 뒤에(Gateway DOCX `_block_lines`와 같은 규칙). 문단 안 표·글상자·머리말·각주·메모는 그 문단 줄 뒤에.
본문 뒤에 부가 글자를 발견 순서대로 한 줄씩(body_lines()에는 없음). 공백뿐인 줄은 뺀다.
"""

from __future__ import annotations

import io
import re
import struct
import sys
import zipfile
import zlib
from array import array
from dataclasses import dataclass, field

__all__ = [
    "sniff", "read", "HwpDoc", "Para", "Side",
    "HwpError", "HwpUnsupported", "HwpCorrupt", "HwpTooLarge",
    "ENCRYPTED_KINDS", "IMAGE_EXTENSIONS",
]

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"
HWP_SIGNATURE = b"HWP Document File"
HWPX_MIMETYPE = "application/hwp+zip"
IMAGE_EXTENSIONS = frozenset({"bmp", "png", "jpg", "jpeg", "gif", "tif", "tiff", "wmf", "emf"})
# 암호·배포용·DRM - 내용을 열 수 없는 문서(Detection은 EncryptedDocumentError로)
ENCRYPTED_KINDS = frozenset({"hwp_encrypted", "hwp_distribution", "hwp_drm", "hwpx_encrypted"})


# ------------------------------------------------------------------ 예외

class HwpError(Exception):
    """이 모듈이 내는 예외의 공통 부모. 메시지에 문서 글자·파일 이름을 넣지 않는다."""


class HwpUnsupported(HwpError):
    """열 수 없거나(암호·배포용·DRM·문서 이력) 닫힌 목록 밖 개체가 든 문서. kind는 짧은 사유 코드."""

    def __init__(self, kind: str, detail: str | None = None):
        self.kind = kind
        self.detail = detail
        super().__init__(f"{kind}: {detail}" if detail else kind)


class HwpCorrupt(HwpError):
    """구조가 깨진 문서(레코드·압축열·CFB·ZIP·XML 해석 실패, 잘린 압축열, 선언 크기 이상 등)."""


class HwpTooLarge(HwpError):
    """압축을 푼 크기가 max_decompressed를 넘거나, 그 예산에서 정한 구조 수·XML 요소 수 상한을 넘음."""


# ------------------------------------------------------------------ 결과

@dataclass
class Para:
    """본문 문단 하나.

    offsets[i]는 text[i]의 원래 위치(마스킹용, array('i')).
      HWP : 압축을 푼 구역 스트림(stream) 안 바이트 위치. 서로게이트 쌍은 한 글자로 묶고 첫 단위의 위치(둘째는 +2).
            제어 글자에서 나온 글자(줄바꿈·탭·묶음 빈칸 등)는 -1.
      HWPX: 그 문단의 글자 칸(hp:t의 text와 하위 요소 tail을 문서 순서로 이은 것) 안 글자 위치. 요소 글자(탭 등)는 -1.
    cell = (표 일련번호, 행, 열, 행 병합, 열 병합) - 표 일련번호는 문서 전체에서 나온 순서(중첩 표 포함).
    """

    locator: str
    text: str
    block_order: int
    cell: tuple[int, int, int, int, int] | None
    offsets: array
    stream: str


@dataclass
class Side:
    """본문 밖 글자(검사만 하고 가리지 않음). kind: eq field summary meta master dutmal desc compose."""

    locator: str
    kind: str
    text: str


@dataclass
class HwpDoc:
    kind: str                       # 'hwp' | 'hwpx'
    paragraphs: list[Para]
    side: list[Side]
    media: int                      # 그림 BinData 수(글자 없는 문서를 '그림만'과 '빈 문서'로 나눌 때)
    stats: dict
    _layout: list = field(default_factory=list, repr=False)
    _preview: str = field(default="", repr=False)

    def preview_text(self) -> str:
        """미리보기 글자(HWP PrvText, HWPX Preview/PrvText.txt). 검사·등록 글자에는 넣지 않는다."""
        return self._preview

    def layout(self) -> list:
        """lines()와 같은 순서의 항목. 문단·부가 글자 줄은 str, 표 행은 칸 글자 목록 list[str]."""
        return [item for item, _ in self._render()]

    def body_layout(self) -> list:
        """layout()에서 부가 글자 줄을 뺀 것(본문 문단·표 행만). Detection 등록은 이것만 색인한다 - 요약 정보·그림 설명문·
        메타·바탕쪽처럼 같은 양식 문서끼리 겹치는 글자로 본문이 무관한 문서가 차단되지 않게(2026-10-11 검토 지적 1)."""
        return [item for item, _ in self._render(side=False)]

    def lines(self) -> list[str]:
        """업로드 검사 글자 배치(줄 목록) = body_lines() 뒤에 부가 글자 줄. Gateway는 '\\n'.join(lines())를 보낸다."""
        return [item if isinstance(item, str) else " | ".join(item) for item, _ in self._render()]

    def body_lines(self) -> list[str]:
        """등록 글자 배치 = lines()의 앞부분(부가 글자 줄 제외). 등록 압축열은 검사 압축열의 앞부분이다."""
        return [item if isinstance(item, str) else " | ".join(item) for item, _ in self._render(side=False)]

    def text(self) -> str:
        return "\n".join(self.lines())

    def paragraph_text(self) -> str:
        """본문 문단 글자를 레코드(요소) 순서대로 '\\n'으로 이은 것. 미리보기 대조(PrvText 압축열이 이것의 부분열인지)에 쓴다.
        lines()는 칸 안 중첩 표를 그 행 뒤로 옮기므로 한컴 미리보기 순서와 다르다(팀 HWP 19개 중 2개가 lines() 기준으로는
        부분열이 아님, 이 순서로는 19/19)."""
        return "\n".join(p.text for p in self.paragraphs)

    def lines_with_spans(self, marks: dict) -> tuple[list[str], list[tuple[int, int]]]:
        """lines()와 같은 줄 + marks(locator → 문단 글자 좌표 [(start, end), ...])를 '\\n'.join(lines) 좌표로 옮긴 구간.

        공백뿐이라 줄에 들어가지 않은 문단의 구간은 옮기지 않는다(보낸 글자에 없음). 부가 글자·모르는 locator → ValueError.
        """
        by_locator = {p.locator: i for i, p in enumerate(self.paragraphs)}
        for loc, spans in marks.items():
            if loc not in by_locator:
                raise ValueError(f"unknown locator {loc!r}")
            size = len(self.paragraphs[by_locator[loc]].text)
            for start, end in spans:
                if not 0 <= start <= end <= size:
                    raise ValueError(f"span {start}-{end} outside paragraph {loc!r}")
        lines: list[str] = []
        spans_out: list[tuple[int, int]] = []
        cursor = 0
        for item, starts in self._render():
            line = item if isinstance(item, str) else " | ".join(item)
            for pi, local in starts:
                for start, end in marks.get(self.paragraphs[pi].locator, ()):
                    spans_out.append((cursor + local + start, cursor + local + end))
            lines.append(line)
            cursor += len(line) + 1
        spans_out.sort()
        return lines, spans_out

    def _render(self, side: bool = True):
        """[(항목, [(문단 번호, 줄 안 시작 위치), ...]), ...]. 항목은 str(문단·부가) 또는 list[str](표 행).
        side=False면 부가 글자 줄을 붙이지 않는다(본문만)."""
        paras = self.paragraphs
        out = []
        for entry in self._layout:
            if entry[0] == "p":
                pi = entry[1]
                text = paras[pi].text
                if text.strip():
                    out.append((text, [(pi, 0)]))
                continue
            cells: list[str] = []
            starts: list[tuple[int, int]] = []
            pos = 0
            for plist in entry[1]:
                texts = []
                cell_pos = pos
                for pi in plist:
                    text = paras[pi].text
                    if text.strip():
                        if texts:
                            cell_pos += 1
                        starts.append((pi, cell_pos))
                        texts.append(text)
                        cell_pos += len(text)
                cell = "\n".join(texts)
                cells.append(cell)
                pos += len(cell) + 3
            if any(cell.strip() for cell in cells):
                out.append((cells, starts))
        if side:
            for s in self.side:
                if s.text.strip():
                    out.append((s.text, []))
        return out


# ------------------------------------------------------------------ 공통 내부

def _noop(*_args):
    return None


# 구조(문단·표·표 칸·부가 글자) 하나가 예산에서 차지한다고 보는 바이트. 구조 하나는 파이썬 객체 여러 개로 약 0.4KB를 쓰므로
# 개수를 예산/64로 묶으면 최악 메모리가 예산의 약 6배다(20MiB → 327,680개). 한컴 저장본은 문단 하나에 레코드 78바이트 이상
# (PARA_HEADER 24 + 글자 모양 8 + 줄 정보 36 + 머리 3개)을 쓰므로 구조 상한보다 바이트 상한에 먼저 닿는다
# (10/11 실측, 쓴 예산 바이트/구조: 팀 HWP 19개 최소 85.5, 한컴 견본 323개 최소 66.0, 한컴 HWPX 서식 10개 최소 589.
# 구조 수 최대 2,192개).
_ITEM_BYTES = 64
# HWPX XML 요소('<' 수) 하나가 예산에서 차지한다고 보는 바이트. libxml2 요소 하나가 약 0.1KB라 예산/16이면 트리 메모리가
# 예산의 약 6배. 한컴 XML은 쓴 예산 바이트/'<'가 약 50(10/11 실측 최소: 한컴 서식 49.8, 프로젝트 합성 52.5).
_XML_TAG_BYTES = 16


class _Budget:
    """압축을 푼(또는 읽은) 바이트 합의 남은 몫 + 그 예산에서 정한 구조 수·XML 요소 수의 남은 몫(검토 지적 3: 4바이트짜리
    빈 문단 레코드 하나가 객체 여러 개를 만들어 바이트 예산만으로는 메모리가 수백 배로 부풂)."""

    __slots__ = ("left", "items", "tags")

    def __init__(self, limit: int):
        if limit is None or limit < 0:
            raise ValueError("max_decompressed must be a non-negative int")
        self.left = int(limit)
        self.items = self.left // _ITEM_BYTES
        self.tags = self.left // _XML_TAG_BYTES

    def take(self, n: int) -> None:
        if n > self.left:
            raise HwpTooLarge("decompressed size over limit")
        self.left -= n

    def item(self) -> None:
        if self.items <= 0:
            raise HwpTooLarge("too many paragraphs/cells/side texts for the size limit")
        self.items -= 1

    def take_tags(self, n: int) -> None:
        if n > self.tags:
            raise HwpTooLarge("too many XML elements for the size limit")
        self.tags -= n


class _Ctx:
    """문단이 들어갈 자리. prefix·문단 순번·표 순번은 영역(본문·머리말·꼬리말) 또는 칸 단위로 공유한다.

    plist가 있으면 표 칸의 직속 문단 목록(칸 글자), 없으면 out에 ("p", 문단 번호)를 넣는다.
    out은 그 자리에서 생긴 하위 내용(표·글상자·각주 등)이 놓일 줄 목록 - 칸이면 그 행 뒤 목록.
    side가 있으면(HWPX 바탕쪽) 문단을 만들지 않고 그 kind의 부가 글자로 넣는다.
    """

    __slots__ = ("prefix", "pcount", "tcount", "out", "plist", "cell", "side")

    def __init__(self, prefix, pcount, tcount, out, plist=None, cell=None, side=None):
        self.prefix, self.pcount, self.tcount, self.out = prefix, pcount, tcount, out
        self.plist, self.cell, self.side = plist, cell, side

    def nested(self) -> "_Ctx":
        """이 자리 안의 표 아닌 하위 목록(글상자·각주·메모·캡션 등): 같은 순번을 이어 쓰고 줄은 out으로."""
        return _Ctx(self.prefix, self.pcount, self.tcount, self.out, None, self.cell, self.side)


class _Table:
    __slots__ = ("tid", "prefix", "target", "rows", "nested", "seen", "side", "budget")

    def __init__(self, tid, prefix, target, side, budget: _Budget):
        self.tid, self.prefix, self.target, self.side, self.budget = tid, prefix, target, side, budget
        self.rows: dict = {}      # 행 → [(열, 직속 문단 목록)]
        self.nested: dict = {}    # 행 → 그 행 뒤에 둘 줄 목록
        self.seen: set = set()

    def cell(self, r: int, c: int, rs: int, cs: int) -> _Ctx:
        if (r, c) in self.seen:
            raise HwpCorrupt("duplicate table cell address")
        self.budget.item()
        self.seen.add((r, c))
        plist: list = []
        self.rows.setdefault(r, []).append((c, plist))
        nested = self.nested.setdefault(r, [])
        return _Ctx(f"{self.prefix}:r{r}:c{c}", [0], [0], nested, plist, (self.tid, r, c, rs, cs), self.side)

    def emit(self) -> None:
        for r in sorted(self.rows):
            self.target.append(("row", [plist for _, plist in sorted(self.rows[r], key=lambda x: x[0])]))
            self.target.extend(self.nested.get(r, ()))


class _Builder:
    """두 형식이 함께 쓰는 문단·부가 글자·표 순번 관리."""

    def __init__(self, kind, tick, add, budget: _Budget):
        self.kind = kind
        self.tick = tick or _noop
        self.add = add or _noop
        self.budget = budget
        self.paragraphs: list[Para] = []
        self.side: list[Side] = []
        self.layout: list = []
        self.side_counts: dict = {}
        self.pieces: dict = {}     # 문단 번호 → 글자 조각(한 문단에 PARA_TEXT가 둘 이상일 때, finish()에서 한 번에 이음)
        self.top = -1              # 최상위 문단 순번(block_order)
        self.ntables = 0
        self.header_count = 0
        self.footer_count = 0
        self.body = _Ctx("body", [0], [0], self.layout)

    def area(self, which: str, out: list, side=None) -> _Ctx:
        if which == "header":
            name, self.header_count = f"header{self.header_count}", self.header_count + 1
        else:
            name, self.footer_count = f"footer{self.footer_count}", self.footer_count + 1
        return _Ctx(name, [0], [0], out, None, None, side)

    def table(self, ctx: _Ctx) -> _Table:
        self.budget.item()
        t = ctx.tcount[0]
        ctx.tcount[0] += 1
        tid = self.ntables
        self.ntables += 1
        return _Table(tid, f"{ctx.prefix}:t{t}", ctx.out, ctx.side, self.budget)

    def new_para(self, ctx: _Ctx, stream: str) -> int:
        """빈 문단을 만들고 자리에 넣는다. 반환: 문단 번호(바탕쪽 등 side 자리면 -1)."""
        if ctx.side is not None:
            return -1
        self.budget.item()
        locator = f"{ctx.prefix}:p{ctx.pcount[0]}"
        ctx.pcount[0] += 1
        pi = len(self.paragraphs)
        self.paragraphs.append(Para(locator, "", max(self.top, 0), ctx.cell, array("i"), stream))
        if ctx.plist is not None:
            ctx.plist.append(pi)
        else:
            ctx.out.append(("p", pi))
        return pi

    def set_text(self, pi: int, text: str, offsets: array, ctx: _Ctx) -> None:
        if pi < 0:
            self.add_side(ctx.side, text)
            return
        para = self.paragraphs[pi]
        if para.text:                       # 한 문단에 글자 레코드가 둘 이상(비정상이지만 잇는다)
            parts = self.pieces.get(pi)     # 매번 이어 붙이면 레코드 수의 제곱 시간 → 모았다가 finish()에서 한 번에
            if parts is None:
                parts = self.pieces[pi] = [para.text]
            parts.append(text)
            para.offsets.extend(offsets)
        else:
            para.text, para.offsets = text, offsets
        if text:
            self.add(text)

    def finish(self) -> None:
        """모아 둔 글자 조각을 문단 글자로(구역이 끝날 때 - 문단은 구역을 넘지 않음)."""
        for pi, parts in self.pieces.items():
            self.paragraphs[pi].text = "".join(parts)
        self.pieces.clear()

    def add_side(self, kind: str, text: str) -> None:
        if not text or not text.strip():
            return
        self.budget.item()
        n = self.side_counts.get(kind, 0)
        self.side_counts[kind] = n + 1
        self.side.append(Side(f"side:{kind}{n}", kind, text))
        self.add(text)


def sniff(data) -> str | None:
    """바이트만 보고 'hwp' | 'hwpx' | None. olefile이 없으면 CFB에 대해 ImportError.

    hwp : CFB 머리 + olefile.isOleFile + FileHeader 첫 32바이트가 'HWP Document File'(암호 OOXML·DOC·XLS는 FileHeader 없음)
    hwpx: ZIP 머리 + mimetype 항목이 application/hwp+zip (mimetype 항목이 없으면 Contents/content.hpf가 있을 때)
    """
    head = bytes(data[:8])
    if head == CFB_MAGIC:
        import olefile  # noqa: PLC0415 - 지연 import(기동 경로에 싣지 않음)

        buf = bytes(data)
        if not olefile.isOleFile(data=buf):
            return None
        try:
            ole = _ole_open(buf)
        except HwpCorrupt:              # 깨지거나 머리 칸이 범위 밖인 CFB는 HWP가 아님
            return None
        try:
            if not ole.exists("FileHeader"):
                return None
            size = ole.get_size("FileHeader")
            if size < 32 or size > len(buf):
                return None
            sig = ole.openstream("FileHeader").read(32)
        except Exception:  # noqa: BLE001
            return None
        finally:
            ole.close()
        return "hwp" if sig.rstrip(b"\x00") == HWP_SIGNATURE else None
    if head[:4] == ZIP_MAGIC:
        try:
            with zipfile.ZipFile(io.BytesIO(bytes(data))) as zf:
                names = set(zf.namelist())
                if "mimetype" in names:
                    info = zf.getinfo("mimetype")
                    if info.file_size > 64 or info.flag_bits & 0x1:
                        return None
                    with zf.open(info) as handle:
                        value = handle.read(64).decode("ascii", errors="replace").strip()
                    return "hwpx" if value == HWPX_MIMETYPE else None
                return "hwpx" if "Contents/content.hpf" in names else None
        except Exception:  # noqa: BLE001 - 깨진 ZIP은 HWPX가 아님
            return None
    return None


def read(data, *, max_decompressed: int, tick=None, add=None) -> HwpDoc:
    """HWP·HWPX 바이트 → HwpDoc. 형식은 머리 바이트로 정한다(호출 전에 sniff로 확인해 두는 것을 전제로 함)."""
    data = bytes(data)
    budget = _Budget(max_decompressed)
    if data[:8] == CFB_MAGIC:
        return _read_hwp(data, budget, _Builder("hwp", tick, add, budget))
    if data[:4] == ZIP_MAGIC:
        return _read_hwpx(data, budget, _Builder("hwpx", tick, add, budget))
    raise HwpCorrupt("not an HWP or HWPX document")


# ------------------------------------------------------------------ HWP 5.0

TAG_PARA_HEADER = 66
TAG_PARA_TEXT = 67
TAG_CTRL_HEADER = 71
TAG_LIST_HEADER = 72
TAG_TABLE = 77
TAG_EQEDIT = 88
# 글자 없는 구조(무시): 문단 머리·글자 모양·줄 정보·영역 태그·목록 머리·용지·각주 모양·쪽 테두리·표·도형·그림·메모 머리
_HWP_STRUCT_TAGS = frozenset({66, 68, 69, 70, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 85, 86, 92, 93})
# 글자가 없는 컨트롤 ID(그 안의 문단 목록은 PARA_TEXT로 따로 나옴)
_HWP_CTRL_PLAIN = frozenset({"secd", "cold", "head", "foot", "fn  ", "en  ", "atno", "nwno", "pghd", "pgct",
                             "pgnp", "bokm", "tcmt"})
# 개체 공통 속성(개체 설명문)을 가진 컨트롤
_HWP_CTRL_OBJECT = frozenset({"tbl ", "gso ", "eqed"})
_HWP_ROOT_STREAMS = frozenset({"FileHeader", "DocInfo", "PrvText", "PrvImage", "\x05HwpSummaryInformation"})
_HWP_IGNORED_STORAGES = frozenset({"DocOptions", "Scripts"})   # 한계(명세 §6): 검사하지 않음
_SUMMARY = "\x05HwpSummaryInformation"

FLAG_COMPRESSED = 1 << 0
FLAG_PASSWORD = 1 << 1
FLAG_DISTRIBUTION = 1 << 2
FLAG_DRM = 1 << 4
FLAG_CERT_ENCRYPTED = 1 << 8
FLAG_CERT_DRM = 1 << 10

# 1 WCHAR짜리 문자 제어(0 사용 안 함, 10 줄바꿈, 13 문단 끝, 24 하이픈, 25~29 예약, 30 묶음 빈칸, 31 고정폭 빈칸).
# 1~31의 나머지(인라인·확장 제어)는 8 WCHAR(16바이트).
_CHAR_CONTROLS = frozenset({0, 10, 13} | set(range(24, 32)))
_CHAR_OUT = {10: "\n", 24: "-", 30: " ", 31: " "}
# PARA_TEXT는 이 바이트씩 끊어 훑고 끊을 때마다 tick()을 부른다(짝수 = 코드 단위 경계). 특수 글자도 이 수마다 tick()
_PT_CHUNK = 1 << 16
_PT_TICK_SPECIALS = 4096
# 코드 단위(하위 바이트 lo, 상위 바이트 hi)가 제어 글자(hi 0, lo < 32)인지·서로게이트(hi D8~DF)인지 가리는 바이트 변환표
_T_HI_SURROGATE = bytes(int(0xD8 <= i <= 0xDF) for i in range(256))
_T_HI_ZERO = bytes(int(i == 0) for i in range(256))
_T_LO_C0 = bytes(int(i < 0x20) for i in range(256))


def _ole_read(ole, path, total: int, budget: _Budget, *, count: bool) -> bytes:
    """스트림 하나를 읽는다. 선언 크기가 파일보다 크면 HwpCorrupt, count면 예산에서 뺀다."""
    try:
        size = ole.get_size(path)
    except Exception:  # noqa: BLE001
        raise HwpCorrupt("stream size unreadable") from None
    if size < 0 or size > total:
        raise HwpCorrupt("declared stream size larger than file")
    if count:
        budget.take(size)
    try:
        raw = ole.openstream(path).read()
    except Exception:  # noqa: BLE001
        raise HwpCorrupt("stream unreadable") from None
    if len(raw) != size:
        raise HwpCorrupt("stream shorter than declared")
    return raw


def _inflate(raw: bytes, budget: _Budget) -> bytes:
    """raw deflate 풀기. 예산을 넘으면 HwpTooLarge, 끝 표지 없이 끝나면(잘린 압축열) HwpCorrupt. 뒤 남는 바이트는 허용."""
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(raw, budget.left + 1)
    except zlib.error:
        raise HwpCorrupt("broken deflate stream") from None
    if len(out) > budget.left:
        raise HwpTooLarge("decompressed size over limit")
    if not d.eof:
        if d.unconsumed_tail:
            raise HwpTooLarge("decompressed size over limit")
        raise HwpCorrupt("truncated deflate stream")
    budget.take(len(out))
    return out


def _records(buf: bytes):
    """(tag, level, payload offset, size)를 차례로 낸다. 구역 밖으로 넘치거나 뒤에 남는 바이트가 있으면 HwpCorrupt."""
    pos, n = 0, len(buf)
    unpack = struct.unpack_from
    while pos < n:
        if pos + 4 > n:
            raise HwpCorrupt("truncated record header")
        h = unpack("<I", buf, pos)[0]
        pos += 4
        size = h >> 20
        if size == 0xFFF:
            if pos + 4 > n:
                raise HwpCorrupt("truncated record header")
            size = unpack("<I", buf, pos)[0]
            pos += 4
        if pos + size > n:
            raise HwpCorrupt("record overruns section")
        yield h & 0x3FF, (h >> 10) & 0x3FF, pos, size
        pos += size


def _special_units(chunk: bytes) -> bytes:
    """짝수 길이 chunk의 코드 단위마다 1(제어 글자 < 32 또는 서로게이트) 또는 0인 바이트열.

    바이트 변환표와 큰 정수 비트 연산만 써서 글자 수에 비례하는 파이썬 반복이 없고, 단위 경계가 아닌 자리(홀수 위치)를
    잘못 짚는 일도 없다. 1 = 상위 바이트가 서로게이트 | (상위 바이트 0 & 하위 바이트 < 32)."""
    lo, hi = chunk[0::2], chunk[1::2]
    flags = (int.from_bytes(hi.translate(_T_HI_SURROGATE), "little")
             | (int.from_bytes(hi.translate(_T_HI_ZERO), "little") & int.from_bytes(lo.translate(_T_LO_C0), "little")))
    return flags.to_bytes(len(lo), "little")


def _para_text(buf: bytes, off: int, size: int, tick) -> tuple[str, array]:
    """PARA_TEXT → (보이는 글자, 글자마다 바이트 위치). 규칙은 모듈 머리말·Para 참고.

    _PT_CHUNK 바이트씩 끊어 특수 단위(제어·서로게이트)를 찾고, 두 번째 조각부터 조각마다·특수 단위 _PT_TICK_SPECIALS개마다
    tick()을 부른다(긴 문단 하나가 호출한 쪽의 시간 한도를 넘지 않게). 첫 조각은 레코드마다 부르는 tick()이 덮는다."""
    if size % 2:
        raise HwpCorrupt("odd PARA_TEXT size")
    end = off + size
    parts: list[str] = []
    offs = array("i")
    p = off
    specials = 0
    while p < end:
        if p != off:
            tick()
        base = p
        limit = min(end, base + _PT_CHUNK)
        flags = _special_units(buf[base:limit])
        while p < limit:
            j = flags.find(1, (p - base) // 2)
            q = base + 2 * j if j >= 0 else limit
            if q > p:                               # 제어·서로게이트가 없는 구간: 단위 하나 = 글자 하나
                parts.append(buf[p:q].decode("utf-16-le"))
                offs.extend(range(p, q, 2))
                p = q
            if j < 0:
                break
            c = buf[q] | (buf[q + 1] << 8)
            if c < 32:
                if c in _CHAR_CONTROLS:
                    ch = _CHAR_OUT.get(c)
                    if ch is not None:
                        parts.append(ch)
                        offs.append(-1)
                    p = q + 2
                else:
                    if q + 16 > end:
                        raise HwpCorrupt("truncated inline/extended control")
                    if c == 9:
                        parts.append("\t")
                        offs.append(-1)
                    p = q + 16                      # 조각 끝을 넘을 수 있음 - 다음 조각은 p에서 시작
            elif c <= 0xDBFF and q + 4 <= end and 0xDC00 <= (buf[q + 2] | (buf[q + 3] << 8)) <= 0xDFFF:
                c2 = buf[q + 2] | (buf[q + 3] << 8)
                parts.append(chr(0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00)))
                offs.append(q)
                p = q + 4
            else:                                   # 짝 없는 서로게이트
                parts.append("�")
                offs.append(q)
                p = q + 2
            specials += 1
            if specials % _PT_TICK_SPECIALS == 0:
                tick()
    return "".join(parts), offs


def _wstr(buf: bytes, off: int, end: int, what: str) -> tuple[str, int]:
    """WORD 길이 + WCHAR 배열. 반환 (글자, 다음 위치)."""
    if off + 2 > end:
        raise HwpCorrupt(f"truncated {what}")
    n = struct.unpack_from("<H", buf, off)[0]
    start = off + 2
    if start + 2 * n > end:
        raise HwpCorrupt(f"truncated {what}")
    return buf[start:start + 2 * n].decode("utf-16-le", errors="replace"), start + 2 * n


class _Frame:
    """레코드 스택 한 칸. cur = 이 레코드 아래 PARA_HEADER가 들어갈 자리(LIST_HEADER가 정함).
    table = 표 컨트롤의 _Table, started = TABLE 레코드를 지났는지(앞의 LIST_HEADER는 캡션, 뒤는 칸)."""

    __slots__ = ("level", "kind", "ctx", "cur", "table", "started", "area", "pi")

    def __init__(self, level, kind, ctx, pi=-1):
        self.level, self.kind, self.ctx, self.pi = level, kind, ctx, pi
        self.cur = self.table = self.area = None
        self.started = False


def _hwp_section(b: _Builder, buf: bytes, stream: str, stats: dict) -> None:
    """구역 하나의 레코드를 차례로 읽으며 문단·표·부가 글자를 만든다(레코드 단계 스택, 재귀 없음)."""
    root = _Frame(-1, "root", b.body)
    stack = [root]
    nrec = 0

    def close(frame: _Frame) -> None:
        if frame.table is not None:
            frame.table.emit()      # 표가 끝나면 행을 순서대로(칸 안 중첩 내용은 그 행 뒤에) 내보낸다

    for tag, level, off, size in _records(buf):
        b.tick()
        nrec += 1
        while stack[-1].level >= level:
            close(stack.pop())
        parent = stack[-1]
        if level > parent.level + 1:
            raise HwpCorrupt("record level jump")
        end = off + size

        if tag == TAG_PARA_HEADER:
            if parent.kind == "root":
                b.top += 1
                ctx = b.body
            elif parent.table is not None and parent.started:
                if parent.cur is None:
                    raise HwpCorrupt("table paragraph without cell header")
                ctx = parent.cur
            else:
                if parent.cur is None:
                    parent.cur = parent.ctx.nested()
                ctx = parent.cur
            stack.append(_Frame(level, "para", ctx, pi=b.new_para(ctx, stream)))
            continue

        if tag == TAG_PARA_TEXT:
            if parent.kind != "para":
                raise HwpCorrupt("PARA_TEXT outside paragraph")
            text, offs = _para_text(buf, off, size, b.tick)
            b.set_text(parent.pi, text, offs, parent.ctx)
            stack.append(_Frame(level, "leaf", parent.ctx))
            continue

        if tag == TAG_CTRL_HEADER:
            if size < 4:
                raise HwpCorrupt("short CTRL_HEADER")
            cid = buf[off:off + 4][::-1].decode("latin-1")
            base = parent.ctx
            frame = _Frame(level, "ctrl", base)
            if cid in _HWP_CTRL_OBJECT:
                if size >= 46:          # 개체 공통 속성 46바이트 + 개체 설명문(옛 판은 짧아 설명문이 없음)
                    desc, _ = _wstr(buf, off + 44, end, "object description")
                    b.add_side("desc", desc)
                if cid == "tbl ":
                    frame.table = b.table(base)
            elif cid[0] == "%":         # 필드 시작: ctrl ID 4, 속성 4, 기타 속성 1, command(WORD 길이 + WCHAR)
                command, _ = _wstr(buf, off + 9, end, "field command")
                b.add_side("field", command)
            elif cid == "tdut":         # 덧말: ctrl ID 4, 본말(WORD+WCHAR), 덧말(WORD+WCHAR), ...
                main, nxt = _wstr(buf, off + 4, end, "dutmal")
                sub, _ = _wstr(buf, nxt, end, "dutmal")
                b.add_side("dutmal", main)
                b.add_side("dutmal", sub)
            elif cid == "tcps":         # 글자 겹침: ctrl ID 4, 겹칠 글자(WORD 길이 + WCHAR), 테두리 종류·안 글자 크기·펼침
                chars, nxt = _wstr(buf, off + 4, end, "compose")    # (BYTE 3), cnt(BYTE), 안 글자 모양 ID(UINT × cnt)
                if nxt + 4 > end or nxt + 4 + 4 * buf[nxt + 3] != end:
                    # 규격과 다른 배치면 글자 자리를 확신할 수 없다 → 모르는 컨트롤과 같이
                    raise HwpUnsupported("hwp_unsupported_object", "ctrl:tcps")
                b.add_side("compose", chars)
            elif cid in ("head", "foot"):
                frame.area = "header" if cid == "head" else "footer"
            elif cid not in _HWP_CTRL_PLAIN:
                raise HwpUnsupported("hwp_unsupported_object", f"ctrl:{cid.strip() or '?'}")
            stack.append(frame)
            continue

        if tag == TAG_LIST_HEADER:
            if parent.table is not None and parent.started:
                if size < 16:
                    raise HwpCorrupt("short cell LIST_HEADER")
                col, row, colspan, rowspan = struct.unpack_from("<HHHH", buf, off + 8)
                parent.cur = parent.table.cell(row, col, rowspan, colspan)
            elif parent.area is not None:
                parent.cur = b.area(parent.area, parent.ctx.out, parent.ctx.side)
            else:
                parent.cur = parent.ctx.nested()
            frame = _Frame(level, "leaf", parent.ctx)
            frame.cur = parent.cur      # 문단이 LIST_HEADER 아래 단계로 와도 같은 목록에 넣는다
            stack.append(frame)
            continue

        if tag == TAG_TABLE:
            if parent.table is None:
                raise HwpCorrupt("TABLE outside table control")
            parent.started = True       # 이후 LIST_HEADER는 칸(앞의 것은 캡션)
            parent.cur = None
            stats["tables"] += 1
            stack.append(_Frame(level, "leaf", parent.ctx))
            continue

        if tag == TAG_EQEDIT:           # 수식: 속성 4, 스크립트(WORD 길이 + WCHAR)
            script, _ = _wstr(buf, off + 4, end, "equation script")
            b.add_side("eq", script)
            stack.append(_Frame(level, "leaf", parent.ctx))
            continue

        if tag not in _HWP_STRUCT_TAGS:
            raise HwpUnsupported("hwp_unsupported_object", f"tag{tag}")
        stack.append(_Frame(level, "other", parent.ctx))

    while len(stack) > 1:
        close(stack.pop())
    b.finish()
    stats["records"] += nrec


_VT_LPSTR, _VT_LPWSTR = 0x1E, 0x1F


def _summary_strings(raw: bytes) -> list[str]:
    """OLE 속성 집합(MS-OLEPS) 첫 구역의 문자열 속성(VT_LPWSTR·VT_LPSTR)을 속성 번호 순으로.

    olefile 0.47 getproperties는 VT_LPWSTR 길이를 글자 자리에서 읽어(offset+4) 값 뒤의 바이트까지 붙이므로 직접 푼다.
    """
    n = len(raw)
    if n < 48 or struct.unpack_from("<H", raw, 0)[0] != 0xFFFE:
        raise HwpCorrupt("bad summary information header")
    if struct.unpack_from("<I", raw, 24)[0] < 1:
        return []
    sec = struct.unpack_from("<I", raw, 44)[0]
    if sec + 8 > n:
        raise HwpCorrupt("summary section out of range")
    sec_size, count = struct.unpack_from("<II", raw, sec)
    end = min(n, sec + sec_size)
    if sec + 8 + 8 * count > end:
        raise HwpCorrupt("summary property table out of range")
    props = []
    for i in range(count):
        pid, poff = struct.unpack_from("<II", raw, sec + 8 + 8 * i)
        p = sec + poff
        if p + 8 > end:
            raise HwpCorrupt("summary property out of range")
        vtype, length = struct.unpack_from("<II", raw, p)
        if vtype == _VT_LPWSTR:
            stop = p + 8 + 2 * length
            if stop > end:
                raise HwpCorrupt("summary string out of range")
            value = raw[p + 8:stop].decode("utf-16-le", errors="replace")
        elif vtype == _VT_LPSTR:
            stop = p + 8 + length
            if stop > end:
                raise HwpCorrupt("summary string out of range")
            value = raw[p + 8:stop].decode("cp949", errors="replace")
        else:
            continue
        props.append((pid, value.split("\x00", 1)[0]))
    return [value for _, value in sorted(props, key=lambda x: x[0])]


def _cfb_header_check(data: bytes) -> None:
    """olefile에 넘기기 전에 CFB 머리 칸을 확인한다(검토 지적 2). olefile 0.47은 머리의 FAT·DIFAT 섹터 수를 믿고 그만큼
    읽어 FAT을 만들고(순환·반복 확인 없음, DEFECT_INCORRECT도 기본 설정에서는 예외가 아님) 이 단계는 tick()이 닿지 않는다.
    규칙은 모두 MS-CFB 그대로: 바이트 순서 FFFE, 섹터 512(3판)·4096(4판), 미니 섹터 64, FAT 섹터 1개 이상이고 파일 섹터
    수 이하(FAT 섹터도 파일 안의 섹터), DIFAT 섹터 수 = FAT 섹터 수에서 정해지는 값, 미니 FAT 섹터 수 ≤ 파일 섹터 수,
    디렉터리 시작 섹터가 파일 안. 한컴 저장본은 FAT 섹터를 필요 수보다 1~2개 더 두기도 해서(10/11 실측 팀 7/19) 'FAT 섹터
    수 ≤ 필요 수'로는 막지 않는다 - 대신 FAT 적재를 선형 시간으로 바꾼다(_ole_class)."""
    if len(data) < 1536 or data[:8] != CFB_MAGIC:
        raise HwpCorrupt("not a CFB file")
    major, order, sector_shift, mini_shift = struct.unpack_from("<HHHH", data, 0x1A)
    _, n_fat, dir_start, _, _, _, n_minifat, _, n_difat = struct.unpack_from("<9I", data, 0x28)
    if order != 0xFFFE or (major, sector_shift) not in ((3, 9), (4, 12)) or mini_shift != 6:
        raise HwpCorrupt("bad CFB header")
    size = 1 << sector_shift
    nb_sect = (len(data) + size - 1) // size - 1
    per_difat = size // 4 - 1
    need_difat = max(0, -(-(n_fat - 109) // per_difat))
    if not 1 <= n_fat <= nb_sect or n_difat != need_difat or n_minifat > nb_sect or dir_start >= nb_sect:
        raise HwpCorrupt("CFB header counts out of range")


_OLE_CLASS: list = []


def _ole_class():
    """olefile 0.47 OleFileIO에서 입력 크기의 제곱 시간이 드는 내부 함수 셋을 같은 결과의 선형 시간판으로 바꾼 하위 클래스.

      loadfat_sect             FAT 배열을 섹터마다 새로 이어 붙임(self.fat = self.fat + nextfat) → 제자리 extend
      _check_duplicate_stream  시작 섹터를 목록에서 선형 검색(디렉터리 항목마다) → 집합
      _find                    경로 조각마다 형제를 처음부터 훑음(구역 스트림을 읽을 때마다) → 저장소별 kids_dict
                               (이름 소문자, 같은 이름은 DEFECT_INCORRECT로 열 때 이미 거절)
    수정 전 실측: 길이 0 구역 6,000개 2.4초·DIFAT 사슬 100개 5.2초·1바이트 스트림 16,000개 0.8초(모두 제곱으로 늘어남).
    olefile==0.47 고정(시험 test_olefile_version_is_pinned) - 판이 바뀌면 이 세 함수를 다시 확인한다."""
    if not _OLE_CLASS:
        import olefile  # noqa: PLC0415 - 지연 import

        end_marks = (olefile.ENDOFCHAIN, olefile.FREESECT)
        not_streams = (olefile.DIFSECT, olefile.FATSECT, olefile.ENDOFCHAIN, olefile.FREESECT)

        class _OleFile(olefile.OleFileIO):
            def loadfat_sect(self, sect):
                fat1 = sect if isinstance(sect, array) else self.sect2array(sect)
                isect = None
                for isect in fat1:
                    isect &= 0xFFFFFFFF
                    if isect in end_marks:
                        break
                    self.fat.extend(self.sect2array(self.getsect(isect)))
                return isect

            def _check_duplicate_stream(self, first_sect, minifat=False):
                if not minifat and first_sect in not_streams:
                    return
                used = self.__dict__.setdefault("_hwpdoc_used_mini" if minifat else "_hwpdoc_used_fat", set())
                if first_sect in used:
                    self._raise_defect(olefile.DEFECT_INCORRECT, "Stream referenced twice")
                else:
                    used.add(first_sect)

            def _find(self, filename):
                if isinstance(filename, str):
                    filename = filename.split("/")
                node = self.root
                for name in filename:
                    node = node.kids_dict.get(name.lower())
                    if node is None:
                        raise OSError("file not found")
                return node.sid

        _OLE_CLASS.append(_OleFile)
    return _OLE_CLASS[0]


def _ole_open(data: bytes):
    """CFB 머리 확인 → olefile(DEFECT_INCORRECT부터 예외, 선형 시간판)로 열기 → 미니 스트림(루트 항목) 선언 크기 확인.
    루트 크기를 확인하지 않으면 순환 미니 스트림 사슬을 선언 크기만큼 되풀이해 읽는다(3KB 파일에 256MB 선언 → +591MB).
    olefile이 없으면 ImportError를 그대로 낸다."""
    _cfb_header_check(data)
    import olefile  # noqa: PLC0415 - 지연 import

    cls = _ole_class()
    try:
        ole = cls(io.BytesIO(data), raise_defects=olefile.DEFECT_INCORRECT)
    except Exception as exc:  # noqa: BLE001 - olefile의 여러 오류(재귀 한도 포함)를 하나로
        raise HwpCorrupt(f"CFB unreadable ({type(exc).__name__})") from None
    if ole.root is None or not 0 <= ole.root.size <= len(data):
        ole.close()
        raise HwpCorrupt("declared mini stream size larger than file")
    return ole


def _read_hwp(data: bytes, budget: _Budget, b: _Builder) -> HwpDoc:
    import olefile  # noqa: PLC0415 - 지연 import

    if not olefile.isOleFile(data=data):
        raise HwpCorrupt("not a CFB file")
    ole = _ole_open(data)
    try:
        return _read_hwp_ole(ole, len(data), budget, b)
    finally:
        ole.close()


def _read_hwp_ole(ole, total: int, budget: _Budget, b: _Builder) -> HwpDoc:
    if not ole.exists("FileHeader"):
        raise HwpCorrupt("no FileHeader (not an HWP document)")
    header = _ole_read(ole, "FileHeader", total, budget, count=True)
    if len(header) < 40 or header[:32].rstrip(b"\x00") != HWP_SIGNATURE:
        raise HwpCorrupt("bad FileHeader signature")
    version, flags = struct.unpack_from("<II", header, 32)
    if flags & FLAG_PASSWORD:
        raise HwpUnsupported("hwp_encrypted")
    if flags & FLAG_DISTRIBUTION:
        raise HwpUnsupported("hwp_distribution")
    if flags & (FLAG_DRM | FLAG_CERT_ENCRYPTED | FLAG_CERT_DRM):
        raise HwpUnsupported("hwp_drm")
    if version >> 24 != 5:
        raise HwpUnsupported("hwp_unsupported_object", "version")
    compressed = bool(flags & FLAG_COMPRESSED)

    try:
        entries = ole.listdir(streams=True, storages=False)
    except Exception:  # noqa: BLE001
        raise HwpCorrupt("CFB directory unreadable") from None
    tops = {entry[0] for entry in entries}
    if "DocHistory" in tops:
        raise HwpUnsupported("hwp_history")
    if "ViewText" in tops:                      # 배포용 본문(플래그가 없어도)
        raise HwpUnsupported("hwp_distribution")
    sections: list[tuple[int, list]] = []
    media = 0
    for entry in entries:
        b.tick()
        top = entry[0]
        if len(entry) == 1 and top in _HWP_ROOT_STREAMS:
            continue
        if top in _HWP_IGNORED_STORAGES and len(entry) > 1:
            continue
        if top == "BodyText" and len(entry) == 2 and re.fullmatch(r"Section\d{1,6}", entry[1]):
            sections.append((int(entry[1][7:]), entry))
            continue
        if top == "BinData" and len(entry) == 2:
            ext = entry[1].rsplit(".", 1)[-1].lower() if "." in entry[1] else ""
            if ext not in IMAGE_EXTENSIONS:
                raise HwpUnsupported("hwp_unsupported_object", "bindata")
            media += 1
            continue
        raise HwpUnsupported("hwp_unsupported_object", "stream")
    if not sections:
        raise HwpCorrupt("no BodyText sections")
    sections.sort(key=lambda x: x[0])

    stats = {"version": f"{version >> 24}.{(version >> 16) & 0xFF}.{(version >> 8) & 0xFF}.{version & 0xFF}",
             "flags": flags, "sections": len(sections), "records": 0, "tables": 0}
    for _, entry in sections:
        b.tick()                                # 레코드가 없는 빈 구역이 아주 많아도 호출한 쪽 시간 한도가 듣게
        raw = _ole_read(ole, entry, total, budget, count=not compressed)
        buf = _inflate(raw, budget) if compressed else raw
        _hwp_section(b, buf, "/".join(entry), stats)

    if ole.exists(_SUMMARY):
        for value in _summary_strings(_ole_read(ole, _SUMMARY, total, budget, count=True)):
            b.add_side("summary", value)

    preview = ""
    if ole.exists("PrvText"):
        raw = _ole_read(ole, "PrvText", total, budget, count=True)
        preview = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    return HwpDoc("hwp", b.paragraphs, b.side, media, stats, b.layout, preview)


# ------------------------------------------------------------------ HWPX (OWPML)

_HP = "{http://www.hancom.co.kr/hwpml/2011/paragraph}"
_HP_P, _HP_T, _HP_TBL, _HP_TR, _HP_TC = (_HP + x for x in ("p", "t", "tbl", "tr", "tc"))
_HP_SUBLIST, _HP_PARALIST = _HP + "subList", _HP + "paraList"
_HP_CELLADDR, _HP_CELLSPAN = _HP + "cellAddr", _HP + "cellSpan"
_HP_HEADER, _HP_FOOTER = _HP + "header", _HP + "footer"
# hp:t 안 요소 글자(그 밖 하위 요소 - 형광펜·변경 추적 표지 등 - 는 글자 없음)
_HX_CHARS = {_HP + "tab": "\t", _HP + "lineBreak": "\n", _HP + "nbSpace": " ", _HP + "fwSpace": " ",
             _HP + "hyphen": "-"}
# 글자 데이터를 허용하는 요소 → 부가 글자 kind
_HX_SIDE_TEXT = {_HP + "script": "eq", _HP + "mainText": "dutmal", _HP + "subText": "dutmal",
                 _HP + "shapeComment": "desc"}
_HX_PARAM_SUFFIX = "Param"          # hp:stringParam·integerParam·booleanParam·floatParam·listParam → field
# 글자를 속성에 담는 요소 → (속성 이름, 부가 글자 kind). 섹션 문단 안(scan)에서만 허용, 다른 자리면 hwpx_unsupported_object
_HX_ATTR_TEXT = {_HP + "fieldBegin": ("name", "field"), _HP + "bookmark": ("name", "field"),
                 _HP + "compose": ("composeText", "compose")}
# 속성에 글자를 담거나 내용을 알 수 없는 개체(HWP 쪽 other 태그와 같은 종류) + 찾아보기 표식
_HX_FORBIDDEN = frozenset(_HP + x for x in (
    "ole", "chart", "textart", "video", "btn", "radioBtn", "checkBtn", "comboBox", "listBox", "edit", "scrollBar",
    "indexmark"))
_HX_HEADER_TEXT = frozenset({"paraHead", "forbiddenWord", "metaTag"})   # header.xml: 번호 형식·금칙 문자·스타일 메타(무시)
_HX_SECTION_RE = re.compile(r"Contents/section(\d{1,6})\.xml")
_HX_MASTER_RE = re.compile(r"Contents/masterpage(\d{1,6})\.xml")
# 이름만 보고 건너뛰는 항목: 미리보기 그림, 스크립트(한계 - HWP Scripts 저장소와 같음). 그 밖 Preview/·Scripts/ 항목은 일반 항목
_HX_SKIPPED_RE = re.compile(r"Preview/PrvImage\.(?:png|bmp|gif|jpg)|Scripts/(?:headerScripts|sourceScripts)")


def _xml(raw: bytes):
    from lxml import etree  # noqa: PLC0415 - 지연 import

    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, recover=False,
                             load_dtd=False, dtd_validation=False)
    try:
        root = etree.fromstring(raw, parser)
    except (etree.LxmlError, ValueError):
        raise HwpCorrupt("XML unreadable") from None
    if root.getroottree().docinfo.doctype:
        raise HwpCorrupt("XML DTD not allowed")
    return root


def _ws(text) -> bool:
    return not text or not text.strip()


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


class _Hwpx:
    def __init__(self, b: _Builder):
        self.b = b
        self.elements = 0
        self.tables = 0
        self.stream = ""

    def tick(self):
        self.elements += 1
        self.b.tick()

    # -- 공통 검사 ------------------------------------------------------------
    def unknown(self, where: str):
        raise HwpUnsupported("hwpx_unknown_text", where)

    def check_tail(self, node):
        if not _ws(node.tail):
            self.unknown(f"tail:{_local(node.tag) or 'node'}")

    def check_no_text(self, node):
        """node와 그 아래에 공백 아닌 글자 데이터·tail이 없어야 한다(node 자신의 tail은 보지 않음)."""
        for e in node.iter():
            self.tick()
            if not isinstance(e.tag, str):
                if e is not node and not _ws(e.tail):
                    self.unknown("tail:node")
                continue
            if e.tag in _HX_FORBIDDEN or e.tag in _HX_ATTR_TEXT:   # 속성 글자 요소가 문단 밖·hp:t 안에 있으면 막음
                raise HwpUnsupported("hwpx_unsupported_object", _local(e.tag))
            if not _ws(e.text):
                self.unknown(_local(e.tag))
            if e is not node and not _ws(e.tail):
                self.unknown(f"tail:{_local(e.tag)}")

    # -- 문단 ------------------------------------------------------------------
    def para_list(self, container, ctx: _Ctx, *, top: bool = False):
        if not _ws(container.text):
            self.unknown(_local(container.tag))
        for child in container:
            self.tick()
            if isinstance(child.tag, str) and child.tag == _HP_P:
                if top:
                    self.b.top += 1
                self.para(child, ctx)
            else:
                self.generic(child, ctx)
            self.check_tail(child)

    def para(self, p, ctx: _Ctx):
        b = self.b
        pi = b.new_para(ctx, self.stream)
        parts: list[str] = []
        offs = array("i")
        slot = [0]
        controls: list = []
        if not _ws(p.text):
            self.unknown("p")
        self.scan(list(p), parts, offs, slot, controls)
        b.set_text(pi, "".join(parts), offs, ctx)
        self.run_controls(controls, ctx)

    def generic(self, node, ctx: _Ctx):
        """문단 밖 요소(표의 캡션·개체 설명문, 목록 안 문단 아닌 요소 등): 글자 칸 없이 훑고 하위 내용을 처리한다."""
        controls: list = []
        self.scan([node], None, None, None, controls)
        self.run_controls(controls, ctx)

    def scan(self, nodes, parts, offs, slot, controls):
        """문서 순서로 훑으며 문단 자신의 글자(hp:t)를 모으고, 표·하위 목록·부가 글자는 controls에 순서대로 둔다.
        parts가 None이면 문단 밖이라 hp:t가 있으면 안 된다."""
        stack = [(n, None) for n in reversed(nodes)]
        while stack:
            node, mode = stack.pop()
            self.tick()
            tag = node.tag
            if not isinstance(tag, str):            # 주석·처리 지시(엔티티는 DTD 거부로 들어오지 않음)
                self.check_tail(node)
                continue
            if tag == _HP_T:
                if parts is None:
                    self.unknown("t")
                self.t(node, parts, offs, slot)
                self.check_tail(node)
                continue
            if tag in _HX_FORBIDDEN:
                raise HwpUnsupported("hwpx_unsupported_object", _local(tag))
            if tag == _HP_TBL:
                controls.append(("tbl", node))
                self.check_tail(node)
                continue
            if tag in (_HP_SUBLIST, _HP_PARALIST):
                controls.append(("list", node, mode))
                self.check_tail(node)
                continue
            if tag == _HP_P:                       # 하위 목록 밖에 놓인 문단(비정상이지만 하위 목록 하나로 본다)
                controls.append(("p", node))
                self.check_tail(node)
                continue
            kind = _HX_SIDE_TEXT.get(tag)
            if kind is None and _local(tag).endswith(_HX_PARAM_SUFFIX):
                kind = "field"
            if kind is not None:
                if not _ws(node.text):
                    controls.append(("side", kind, node.text))
            elif not _ws(node.text):
                self.unknown(_local(tag))
            attr = _HX_ATTR_TEXT.get(tag)
            if attr is not None:
                value = node.get(attr[0])
                if value:
                    controls.append(("side", attr[1], value))
            self.check_tail(node)
            if tag == _HP_HEADER:
                mode = "header"
            elif tag == _HP_FOOTER:
                mode = "footer"
            children = list(node)
            for child in reversed(children):
                stack.append((child, mode))

    def t(self, t, parts, offs, slot):
        """hp:t 하나: text와 하위 요소 tail은 글자 칸(위치 기억), 요소 글자는 -1."""
        def piece(text):
            if text:
                parts.append(text)
                offs.extend(range(slot[0], slot[0] + len(text)))
                slot[0] += len(text)

        piece(t.text)
        for child in t:
            self.tick()
            if isinstance(child.tag, str):
                ch = _HX_CHARS.get(child.tag)
                self.check_no_text(child)
                if ch is not None:
                    parts.append(ch)
                    offs.append(-1)
            piece(child.tail)

    def run_controls(self, controls, ctx: _Ctx):
        b = self.b
        for item in controls:
            what = item[0]
            if what == "tbl":
                self.table(item[1], ctx)
            elif what == "list":
                mode = item[2]
                sub = b.area(mode, ctx.out, ctx.side) if mode in ("header", "footer") else ctx.nested()
                self.para_list(item[1], sub)
            elif what == "p":
                self.para(item[1], ctx.nested())
            else:
                b.add_side(item[1], item[2])

    # -- 표 --------------------------------------------------------------------
    def table(self, tbl, ctx: _Ctx):
        table = self.b.table(ctx)
        self.tables += 1
        if not _ws(tbl.text):
            self.unknown("tbl")
        caption_ctx = ctx.nested()
        ri = 0                                        # hp:tr 순번(cellAddr가 없을 때의 행 번호)
        for child in tbl:
            self.tick()
            if isinstance(child.tag, str) and child.tag == _HP_TR:
                if not _ws(child.text):
                    self.unknown("tr")
                for ci, tc in enumerate(child):
                    self.tick()
                    if not (isinstance(tc.tag, str) and tc.tag == _HP_TC):
                        self.check_no_text(tc)
                        self.check_tail(tc)
                        continue
                    self.cell(tc, table, ci, ri)
                    self.check_tail(tc)
                ri += 1
            else:
                self.generic(child, caption_ctx)      # 캡션(하위 목록)·개체 설명문·크기 등
            self.check_tail(child)
        table.emit()

    def cell(self, tc, table: _Table, ci: int, ri: int):
        """ci·ri = 이 칸의 hp:tr 안 순번·hp:tr 순번(cellAddr가 없을 때의 열·행). 행 순번은 table()이 세어 넘긴다 -
        칸마다 형제 hp:tr 목록에서 찾으면 행 수의 제곱 시간(검토 지적 4: 8,000행 16.5초)."""
        addr = tc.find(_HP_CELLADDR)
        span = tc.find(_HP_CELLSPAN)
        try:
            if addr is not None:
                c, r = int(addr.get("colAddr", ci)), int(addr.get("rowAddr", 0))
            else:
                c, r = ci, ri
            cs = int(span.get("colSpan", 1)) if span is not None else 1
            rs = int(span.get("rowSpan", 1)) if span is not None else 1
        except ValueError:
            raise HwpCorrupt("bad cell address") from None
        if min(r, c) < 0:
            raise HwpCorrupt("bad cell address")
        cctx = table.cell(r, c, rs, cs)
        if not _ws(tc.text):
            self.unknown("tc")
        for child in tc:
            self.tick()
            if isinstance(child.tag, str) and child.tag == _HP_SUBLIST:
                self.para_list(child, cctx)
            else:
                self.generic(child, cctx.nested())
            self.check_tail(child)


def _read_hwpx(data: bytes, budget: _Budget, b: _Builder) -> HwpDoc:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 - BadZipFile·NotImplementedError(모르는 ZIP 판) 등 zipfile의 여러 오류를 하나로
        raise HwpCorrupt(f"ZIP unreadable ({type(exc).__name__})") from None
    try:
        return _read_hwpx_zip(zf, budget, b)
    finally:
        zf.close()


def _zip_read(zf, info, budget: _Budget) -> bytes:
    if info.flag_bits & 0x1:
        raise HwpUnsupported("hwpx_encrypted", "zip")
    budget.take(info.file_size)
    try:
        with zf.open(info) as handle:
            raw = handle.read(info.file_size + 1)
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError, NotImplementedError, RuntimeError):
        raise HwpCorrupt("ZIP entry unreadable") from None
    if len(raw) != info.file_size:
        raise HwpCorrupt("ZIP entry size mismatch")
    if info.filename.lower().endswith((".xml", ".rdf", ".hpf")):
        budget.take_tags(raw.count(b"<"))       # 파싱 전에 요소 수(이하) 상한 - lxml 트리 메모리를 예산에 묶음
    return raw


def _read_hwpx_zip(zf, budget: _Budget, b: _Builder) -> HwpDoc:
    infos = zf.infolist()
    names = {}
    for info in infos:
        if info.filename in names:
            raise HwpCorrupt("duplicate ZIP entry")
        names[info.filename] = info
    if "mimetype" in names:
        if names["mimetype"].file_size > 64:
            raise HwpCorrupt("bad mimetype entry")
        if _zip_read(zf, names["mimetype"], budget).decode("ascii", errors="replace").strip() != HWPX_MIMETYPE:
            raise HwpCorrupt("not an HWPX package (mimetype)")
    elif "Contents/content.hpf" not in names:
        raise HwpCorrupt("not an HWPX package")

    # 암호 선언(META-INF/manifest.xml의 encryption-data, META-INF 아래 encrypt가 든 이름)을 가장 먼저 본다
    for name, info in names.items():
        b.tick()
        if name.startswith("META-INF/") and "encrypt" in name.lower():
            raise HwpUnsupported("hwpx_encrypted")
    manifest = None
    if "META-INF/manifest.xml" in names:
        manifest = _xml(_zip_read(zf, names["META-INF/manifest.xml"], budget))
        for e in manifest.iter():
            b.tick()
            if _local(e.tag) in ("encryption-data", "EncryptionData", "encryption"):
                raise HwpUnsupported("hwpx_encrypted")

    hx = _Hwpx(b)
    if manifest is not None:
        hx.check_no_text(manifest)
    sections, masters, xml_parts = [], [], []
    media = 0
    preview = ""
    hpf = header = None
    for name, info in names.items():
        b.tick()
        if name.endswith("/") or name in ("mimetype", "META-INF/manifest.xml"):
            continue
        m = _HX_SECTION_RE.fullmatch(name)
        if m:
            sections.append((int(m.group(1)), name))
            continue
        m = _HX_MASTER_RE.fullmatch(name)
        if m:
            masters.append((int(m.group(1)), name))
            continue
        if name == "Contents/content.hpf":
            hpf = name
        elif name == "Contents/header.xml":
            header = name
        elif name == "Preview/PrvText.txt":
            raw = _zip_read(zf, info, budget)
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                preview = raw.decode("utf-16", errors="replace")
            else:
                preview = raw.decode("utf-8-sig", errors="replace")
        elif _HX_SKIPPED_RE.fullmatch(name):
            continue                                    # 미리보기 그림 / 스크립트(한계, HWP와 같음)
        elif name.startswith("BinData/"):
            ext = name.rsplit(".", 1)[-1].lower() if "." in name.rsplit("/", 1)[-1] else ""
            if ext not in IMAGE_EXTENSIONS:
                raise HwpUnsupported("hwpx_unsupported_object", "bindata")
            media += 1
        elif name.lower().endswith((".xml", ".rdf", ".hpf")):
            xml_parts.append(name)                      # version.xml·settings.xml·META-INF/* 등: 글자 데이터 없어야 함
        else:
            raise HwpUnsupported("hwpx_unsupported_object", "entry")
    if not sections:
        raise HwpCorrupt("no section XML")

    for name in xml_parts:
        hx.check_no_text(_xml(_zip_read(zf, names[name], budget)))
    if header is not None:
        root = _xml(_zip_read(zf, names[header], budget))
        for e in root.iter():
            b.tick()
            if not isinstance(e.tag, str):
                if not _ws(e.tail):
                    hx.unknown("header:tail")
                continue
            if e.tag in _HX_FORBIDDEN:
                raise HwpUnsupported("hwpx_unsupported_object", _local(e.tag))
            if not _ws(e.text) and _local(e.tag) not in _HX_HEADER_TEXT:
                hx.unknown(f"header:{_local(e.tag)}")
            if e is not root and not _ws(e.tail):
                hx.unknown(f"header:tail:{_local(e.tag)}")

    sections.sort()
    for _, name in sections:
        hx.stream = name
        hx.para_list(_xml(_zip_read(zf, names[name], budget)), b.body, top=True)

    masters.sort()
    for _, name in masters:
        hx.stream = name
        ctx = _Ctx("master", [0], [0], [], side="master")
        hx.generic(_xml(_zip_read(zf, names[name], budget)), ctx)

    if hpf is not None:
        root = _xml(_zip_read(zf, names[hpf], budget))
        for e in root.iter():
            b.tick()
            if not isinstance(e.tag, str):
                if not _ws(e.tail):
                    hx.unknown("hpf:tail")
                continue
            in_meta = any(_local(a.tag) == "metadata" for a in e.iterancestors()) or _local(e.tag) == "metadata"
            if in_meta:
                if not _ws(e.text):
                    b.add_side("meta", e.text)
                content = e.get("content")
                if content and content != "text":       # content="text"는 값 종류 표시
                    b.add_side("meta", content)
            elif not _ws(e.text):
                hx.unknown(f"hpf:{_local(e.tag)}")
            if e is not root and not _ws(e.tail):
                hx.unknown("hpf:tail")

    stats = {"sections": len(sections), "masterpages": len(masters), "elements": hx.elements,
             "tables": hx.tables}
    return HwpDoc("hwpx", b.paragraphs, b.side, media, stats, b.layout, preview.rstrip("\x00"))


if sys.version_info < (3, 11):  # pragma: no cover - 두 서비스 모두 3.11 이상
    raise ImportError("hwpdoc requires Python 3.11+")
