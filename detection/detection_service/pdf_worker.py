"""PDF 가림 자식 프로세스 (2026-10-11 명세 §3.3). PyMuPDF(fitz)는 이 프로세스에서만 연다.

부모(`detection_service/redact_pdf.py`)가 `python -I <이 파일>`로 띄운다. 그래서 이 파일은 혼자 돌아야 한다:
맨 위 import는 표준 라이브러리만, 패키지 import 없음, fitz는 작업 함수 안에서 처음 쓸 때 불러온다.

주고받기: 표준 입출력에 [4바이트 길이(big-endian)][내용] 묶음. 명령·결과는 JSON 묶음 하나, PDF는 그 뒤 바이트 묶음
하나(JSON에 "blob": true). pickle은 쓰지 않는다. 받는 묶음은 크기 상한을 넘으면 읽지 않고 끝낸다.

명령(op)
  (시작)   자식이 먼저 {"op": "hello", "protocol": 1}을 보낸다(fitz를 불러오기 전).
  probe    제한 상태(환경변수 이름 목록·RLIMIT_AS·nice·oom_score_adj)와 fitz 판 - 시험·배포 확인용. 값은 보내지 않는다
  extract  +PDF. 열람 암호면 unsupported. 쪽마다 글자(글리프 기준) + 주석·양식 값 줄, ActualText 쪽 글자가 다르면 그것도
  redact   쪽별 지울 구간 → 지우기 → 문서 정리 → 저장 → 저장본 다시 열어 모든 쪽 재추출 + 객체 사전 문자열 검사 → +PDF
  release  들고 있는 문서·글자 상자를 버린다

판정·재검사(인식기·정책)는 부모가 한다 - 자식은 `/admin/reload-signatures` 뒤의 규칙을 모르고, 정책 DB를 쓰면 안 된다.
"""

from __future__ import annotations

import json
import math
import os
import re
import struct
import sys
import time
from array import array

PROTOCOL = 1
HEADER = struct.Struct(">I")
MAX_COMMAND_JSON = 16 * 1024 * 1024      # 부모 → 자식 명령(지울 구간·값 목록)
MAX_INPUT_PDF = 20 * 1024 * 1024         # 부모가 받는 본문 상한과 같다(명세 §3.2)

# 글자 추출 플래그(PyMuPDF 1.27 TEXT_* 값). 명세 §3.3 A의 TEXTFLAGS_RAWDICT & ~TEXT_MEDIABOX_CLIP에서 둘을 더 뺐다:
#  - TEXT_PRESERVE_LIGATURES: 합자(U+FB01 등)를 낱글자로 풀어야 'ﬁ' 든 메일 주소를 인식기가 잡는다
#  - TEXT_PRESERVE_IMAGES: 그림 블록(그림 바이트까지 dict로 복사)은 쓰지 않는다
# 그리고 TEXT_IGNORE_ACTUALTEXT를 더했다: 상자는 실제 글리프의 것이어야 지운 자리가 맞는다. ActualText(표시 글자와 다른
# 대체 글자 - pdfium·MuPDF 기본 추출이 쓰는 쪽)는 FLAGS_ACTUAL로 따로 뽑아 재검사에 넣는다.
TEXT_PRESERVE_WHITESPACE = 2
TEXT_CID_FOR_UNKNOWN_UNICODE = 128
TEXT_IGNORE_ACTUALTEXT = 2048
FLAGS_GLYPH = TEXT_PRESERVE_WHITESPACE | TEXT_CID_FOR_UNKNOWN_UNICODE | TEXT_IGNORE_ACTUALTEXT
FLAGS_ACTUAL = TEXT_PRESERVE_WHITESPACE | TEXT_CID_FOR_UNKNOWN_UNICODE

# 지우는 상자: 줄 방향에 수직으로 가운데 50%만(명세 §3.3 B). MuPDF는 글리프 상자가 지우는 상자와 조금이라도 겹치면
# 그 글자를 지운다(로컬 실측) - 그래서 이웃 줄 글자 상자와 겹치면 띠를 더 줄이고, 줄 방향 양 끝은 첫·끝 글자 폭의 10%
# (최대 0.5pt)만큼 안으로 들인다. 띠를 더 줄일 수 없으면 50% 띠를 그대로 쓴다(이웃 글자가 같이 지워짐 - 누출 방향 아님).
BAND_FRACTION = 0.5
END_INSET_FRACTION = 0.1
END_INSET_MAX = 0.5
MIN_BAND = 0.2
EPS = 0.05
REDACT_BATCH = 64   # 한 번에 적용하는 지우기 주석 수(로컬 실측: 1,000개 한 쪽 25~200개 묶음이 모두 1.5초 안팎)

# 저장 뒤 문서 수준에서 지우는 키(명세 §3.3 정리 + 그리기에 쓰이지 않는 글자 보관 키 몇 개)
CATALOG_KEYS = ("StructTreeRoot", "MarkInfo", "AcroForm", "PageLabels", "Names", "Dests", "Outlines", "Threads",
                "OpenAction", "AA", "Metadata", "PieceInfo", "SpiderInfo", "Collection", "URI")
PAGE_KEYS = ("Annots", "B", "PieceInfo", "Metadata", "AA")

NAN = float("nan")


class Unsupported(Exception):
    """이 PDF는 가릴 수 없다(열람 암호·글자 상한·상자 없는 값 등). detail은 짧은 사유 코드."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


# ---------------------------------------------------------------- 묶음 주고받기 (부모도 이 함수들을 쓴다)


def write_frame(stream, payload: bytes) -> None:
    stream.write(HEADER.pack(len(payload)))
    stream.write(payload)


def read_exact(stream, size: int) -> bytes:
    chunks, left = [], size
    while left:
        chunk = stream.read(left)
        if not chunk:
            raise EOFError("stream closed")
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def read_frame(stream, maxlength: int) -> bytes:
    (size,) = HEADER.unpack(read_exact(stream, HEADER.size))
    if size > maxlength:
        raise ValueError("frame too large")
    return read_exact(stream, size)


def encode_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def decode_json(data: bytes) -> dict:
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("frame is not a JSON object")
    return value


# ---------------------------------------------------------------- 자식 제한


def harden(rlimit_as: int) -> None:
    """fitz를 불러오기 전에 부른다. nice 10, OOM 때 먼저 죽기, 주소 공간 상한, 코어 파일 없음, 부모가 죽으면 같이 죽기."""
    if os.name != "posix":
        return
    try:
        os.nice(10)
    except OSError:
        pass
    try:
        with open("/proc/self/oom_score_adj", "w") as f:
            f.write("1000")
    except OSError:
        pass
    import resource

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    if rlimit_as > 0:
        resource.setrlimit(resource.RLIMIT_AS, (rlimit_as, rlimit_as))
    try:  # Linux: 부모(uvicorn)가 사라지면 SIGKILL을 받는다
        import ctypes
        import signal

        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, int(signal.SIGKILL), 0, 0, 0)  # PR_SET_PDEATHSIG
    except Exception:
        pass


def probe() -> dict:
    out: dict = {"env_keys": sorted(os.environ.keys()), "pid": os.getpid()}
    if os.name == "posix":
        import resource

        out["rlimit_as"] = resource.getrlimit(resource.RLIMIT_AS)[0]
        out["rlimit_core"] = resource.getrlimit(resource.RLIMIT_CORE)[0]
        try:
            out["nice"] = os.getpriority(os.PRIO_PROCESS, 0)
        except OSError:
            out["nice"] = None
        try:
            with open("/proc/self/oom_score_adj") as f:
                out["oom_score_adj"] = int(f.read().strip())
        except (OSError, ValueError):
            out["oom_score_adj"] = None
    fitz = _fitz()
    out["fitz"] = getattr(fitz, "VersionBind", None)
    return out


def memory_peaks_kb() -> dict:
    """Linux /proc/self/status의 VmHWM(실제 메모리 최대)·VmPeak(주소 공간 최대 - RLIMIT_AS가 보는 값). 없으면 빈 dict."""
    out = {}
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    out["vm_hwm_kb"] = int(line.split()[1])
                elif line.startswith("VmPeak:"):
                    out["vm_peak_kb"] = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return out


_FITZ = None


def _fitz():
    global _FITZ
    if _FITZ is None:
        import fitz  # PyMuPDF - 이 프로세스에서만

        try:
            fitz.TOOLS.mupdf_display_errors(False)
            fitz.TOOLS.mupdf_display_warnings(False)
        except Exception:
            pass
        _FITZ = fitz
    return _FITZ


# ---------------------------------------------------------------- 쪽 글자와 상자


class PageLayout:
    """쪽 하나의 검사 글자와 글자별 상자.

    text = 본문(줄 끝 '\\n', 블록 끝 '\\n') + 주석 Contents·양식 칸 값을 한 줄씩. 본문 글자만 상자가 있다(body_len 앞).
    box는 글자마다 4칸(x0, y0, x1, y1, 쪽 좌표 - 회전 전), 상자 없는 글자(줄바꿈)는 NaN. line은 글자의 줄 번호(-1 = 없음).
    lines는 (x0, y0, x1, y1, 방향, 첫 글자, 끝 글자+1). 방향 0 = 가로(dir.y≈0), 1 = 세로(dir.x≈0), 2 = 그 밖.
    """

    __slots__ = ("text", "body_len", "box", "line", "lines", "actual")

    def __init__(self, text, body_len, box, line, lines, actual):
        self.text = text
        self.body_len = body_len
        self.box = box
        self.line = line
        self.lines = lines
        self.actual = actual

    def box_at(self, i: int):
        x0, y0, x1, y1 = self.box[4 * i:4 * i + 4]
        if not (math.isfinite(x0) and math.isfinite(y0) and math.isfinite(x1) and math.isfinite(y1)):
            return None
        if x1 < x0 or y1 < y0:
            return None
        return x0, y0, x1, y1


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


def annotation_strings(page) -> list[str]:
    """Gateway(pypdfium2) 검사와 같은 범위: 주석의 Contents, 양식 칸 값(V). 읽기 실패는 숨기지 않는다."""
    out = []
    for annot in page.annots() or ():
        content = (annot.info or {}).get("content")
        if isinstance(content, str) and content.strip():
            out.append(content)
    for widget in page.widgets() or ():
        value = widget.field_value
        if isinstance(value, (list, tuple)):
            value = " ".join(str(v) for v in value)
        if isinstance(value, str) and value.strip():
            out.append(value)
    return out


def page_layout(fitz, page, *, budget: list[int] | None = None, annotations: bool = True,
                boxes: bool = True) -> PageLayout:
    """`budget` = [남은 전체 글자, 남은 공백 아닌 글자]. 넘으면 Unsupported('text_too_large') - rawdict를 만들기 전에 센다.

    boxes=False(재추출)는 글자만 만든다 - 글자는 boxes=True와 똑같다(같은 rawdict, 같은 줄바꿈 규칙).
    """
    infinite = fitz.INFINITE_RECT()
    textpage = page.get_textpage(clip=infinite, flags=FLAGS_GLYPH)
    if budget is not None:
        plain = textpage.extractText()
        budget[0] -= len(plain)
        budget[1] -= len(_squash(plain))
        if budget[0] < 0 or budget[1] < 0:
            raise Unsupported("text_too_large")
    raw = textpage.extractRAWDICT()
    del textpage
    parts: list[str] = []
    box = array("d")
    line_of = array("l")
    lines: list[tuple] = []
    none4 = (NAN, NAN, NAN, NAN)
    for block in raw.get("blocks", ()):
        if block.get("type") != 0:
            continue
        for ln in block.get("lines", ()):
            if not boxes:
                parts.extend(ch.get("c") or "" for span in ln.get("spans", ()) for ch in span.get("chars", ()))
                parts.append("\n")
                continue
            dx, dy = ln.get("dir", (1.0, 0.0))
            code = 0 if abs(dy) <= 0.02 else (1 if abs(dx) <= 0.02 else 2)
            lid = len(lines)
            first = len(parts)
            for span in ln.get("spans", ()):
                for ch in span.get("chars", ()):
                    c = ch.get("c") or ""
                    bb = ch.get("bbox")
                    for k, cp in enumerate(c):
                        parts.append(cp)
                        box.extend(bb if (k == 0 and bb is not None and len(bb) == 4) else none4)
                        line_of.append(lid)
            lb = ln.get("bbox") or none4
            lines.append((lb[0], lb[1], lb[2], lb[3], code, first, len(parts)))
            parts.append("\n")
            box.extend(none4)
            line_of.append(-1)
        parts.append("\n")
        if boxes:
            box.extend(none4)
            line_of.append(-1)
    body = "".join(parts)
    text = body
    if annotations:
        try:
            extra = annotation_strings(page)
        except Exception as exc:
            raise Unsupported("annotations_unreadable") from exc
        if extra:
            text = body + "".join(s.replace("\r\n", "\n") + "\n" for s in extra)
            if budget is not None:
                budget[0] -= len(text) - len(body)
                budget[1] -= len(_squash(text[len(body):]))
                if budget[0] < 0 or budget[1] < 0:
                    raise Unsupported("text_too_large")
    actual = page.get_textpage(clip=infinite, flags=FLAGS_ACTUAL).extractText()
    if _squash(actual) == _squash(body):
        actual = None
    elif budget is not None:  # 부모가 재검사에서 이 글자도 보므로 같은 예산에서 뺀다
        budget[0] -= len(actual)
        budget[1] -= len(_squash(actual))
        if budget[0] < 0 or budget[1] < 0:
            raise Unsupported("text_too_large")
    return PageLayout(text, len(body), box, line_of, lines, actual)


# ---------------------------------------------------------------- 지울 상자


def _overlaps(a, b) -> bool:
    return a[2] > b[0] and a[0] < b[2] and a[3] > b[1] and a[1] < b[3]


def _band_rect(lay: PageLayout, lid: int, boxes: list, target: bytearray) -> tuple:
    """줄 하나 안의 지울 글자 상자들 → 지우는 상자 하나(명세 §3.3 B: 줄 방향에 수직으로 가운데 50%)."""
    x0 = min(b[0] for b in boxes)
    y0 = min(b[1] for b in boxes)
    x1 = max(b[2] for b in boxes)
    y1 = max(b[3] for b in boxes)
    code = lay.lines[lid][4]
    if code == 2:
        return x0, y0, x1, y1
    # 축 이름을 줄 방향(u)·수직 방향(v)으로 바꿔 한 번만 쓴다. 가로 줄: u=x, v=y / 세로 줄: u=y, v=x
    if code == 0:
        u0, v0, u1, v1 = x0, y0, x1, y1
        uv = [(b[0], b[1], b[2], b[3]) for b in boxes]
    else:
        u0, v0, u1, v1 = y0, x0, y1, x1
        uv = [(b[1], b[0], b[3], b[2]) for b in boxes]
    first = min(uv, key=lambda b: b[0])
    last = max(uv, key=lambda b: b[2])
    ru0 = u0 + min(END_INSET_FRACTION * (first[2] - first[0]), END_INSET_MAX)
    ru1 = u1 - min(END_INSET_FRACTION * (last[2] - last[0]), END_INSET_MAX)
    if ru1 <= ru0:
        ru0, ru1 = u0, u1
    h = v1 - v0
    a = v0 + h * (1 - BAND_FRACTION) / 2
    b = v1 - h * (1 - BAND_FRACTION) / 2
    v_top_min = min(bx[3] for bx in uv)    # 모든 지울 글자와 겹쳐야 한다: 띠 시작 < 이 값
    v_bottom_max = max(bx[1] for bx in uv)  # 띠 끝 > 이 값
    a2, b2 = a, b
    band = (ru0, a, ru1, b)
    for other, (lx0, ly0, lx1, ly1, _code, start, end) in enumerate(lay.lines):
        if other == lid:
            continue
        lbox = (lx0, ly0, lx1, ly1) if code == 0 else (ly0, lx0, ly1, lx1)
        if not all(math.isfinite(v) for v in lbox) or not _overlaps(lbox, band):
            continue
        for i in range(start, end):
            if target[i]:
                continue
            bx = lay.box_at(i)
            if bx is None or lay.text[i].isspace():
                continue
            c = bx if code == 0 else (bx[1], bx[0], bx[3], bx[2])
            if not _overlaps(c, band):
                continue
            if (c[1] + c[3]) / 2 < (a + b) / 2:
                a2 = max(a2, c[3] + EPS)
            else:
                b2 = min(b2, c[1] - EPS)
    if b2 - a2 >= MIN_BAND and a2 < v_top_min - EPS and b2 > v_bottom_max + EPS:
        a, b = a2, b2
    if code == 0:
        return ru0, a, ru1, b
    return a, ru0, b, ru1


def plan_rects(lay: PageLayout, spans: list) -> list[tuple]:
    """지울 구간(쪽 글자 좌표) → 줄마다 지우는 상자. 본문 밖(주석·양식 줄) 구간은 상자가 필요 없다(문서 정리에서 통째 삭제).

    본문의 보이는 글자인데 쓸 상자가 없으면 Unsupported('no_box') - 그 글자를 지울 방법이 없다.
    """
    return plan_redaction(lay, spans)[0]


def plan_redaction(lay: PageLayout, spans: list) -> tuple[list[tuple], list[tuple]]:
    """plan_rects + 표시 자리. 구간은 (시작, 끝) 또는 (시작, 끝, 표시).

    표시는 구간의 첫 줄 상자 하나에만 넣는다. 왼쪽→오른쪽 가로 줄만(세로·기울어진·거꾸로 줄은 검은 상자만).
    """
    n = lay.body_len
    target = bytearray(len(lay.text))
    for item in spans:
        for i in range(max(0, item[0]), min(item[1], n)):
            target[i] = 1
    rects = []
    labels = []
    for item in spans:
        s, e = item[0], item[1]
        label = item[2] if len(item) > 2 else None
        groups: dict[int, list] = {}
        for i in range(max(0, s), min(e, n)):
            lid = lay.line[i]
            if lid < 0 or lay.text[i].isspace():
                continue
            bx = lay.box_at(i)
            if bx is None:
                raise Unsupported("no_box")
            groups.setdefault(lid, []).append(bx)
        for k, (lid, boxes) in enumerate(groups.items()):
            rect = _band_rect(lay, lid, boxes, target)
            if not (rect[2] > rect[0] and rect[3] > rect[1]):
                raise Unsupported("no_box")
            rects.append(rect)
            if k == 0 and label and lay.lines[lid][4] == 0 and boxes[0][0] <= boxes[-1][0]:
                labels.append((rect, label))
    return rects, labels


LABEL_RE = re.compile(r"\[[A-Z][A-Z0-9_]{1,40}\]")
LABEL_MIN_FONT = 2.5


def draw_labels(fitz, page, labels: list) -> int:
    """지운 자리(검은 상자) 안에 흰 글씨 표시(예: [KR_RRN]). 영문 기본 글꼴 Helvetica - 글꼴을 심지 않아도 된다.

    상자 높이·폭에 맞춰 글자 크기를 줄인다(최소 2.5pt, 그보다 좁으면 상자 밖으로 조금 나간다 - 글자 층에만 영향).
    회전한 쪽은 좌표 변환을 피하려고 표시하지 않는다(검은 상자만).
    """
    if page.rotation:
        return 0
    drawn = 0
    for (x0, y0, x1, y1), label in labels:
        w, h = x1 - x0, y1 - y0
        if w <= 0 or h <= 0 or not LABEL_RE.fullmatch(label):
            continue
        unit = fitz.get_text_length(label, fontname="helv", fontsize=1)
        size = min(h * 0.95, w / unit) if unit > 0 else h * 0.95
        size = max(size, LABEL_MIN_FONT)
        page.insert_text((x0, y0 + (h + size * 0.72) / 2), label, fontname="helv", fontsize=size, color=(1, 1, 1))
        drawn += 1
    return drawn


# ---------------------------------------------------------------- 문서 정리·저장·재검사


def scrub_document(fitz, doc) -> None:
    """명세 §3.3 정리: 모든 쪽 주석·양식 칸 삭제 → scrub → 책갈피 삭제 → 카탈로그 키 null."""
    for page in doc:
        for key in PAGE_KEYS:
            doc.xref_set_key(page.xref, key, "null")
    doc.scrub(attached_files=True, clean_pages=False, embedded_files=True, hidden_text=False, javascript=True,
              metadata=True, redactions=False, remove_links=True, reset_fields=True, reset_responses=True,
              thumbnails=True, xml_metadata=True)
    doc.set_toc([])
    catalog = doc.pdf_catalog()
    for key in CATALOG_KEYS:
        doc.xref_set_key(catalog, key, "null")


_LITERAL_ESCAPES = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b", ord("f"): b"\f",
                    ord("("): b"(", ord(")"): b")", ord("\\"): b"\\"}
_STRING_START = re.compile(rb"[(<]")
_HEX_BODY = re.compile(rb"<([0-9A-Fa-f\s]*)>")


def _literal(src: bytes, i: int) -> tuple[bytes, int]:
    """src[i] == '(' 인 리터럴 문자열 → (풀린 바이트, 다음 위치)."""
    out = bytearray()
    depth, j, n = 1, i + 1, len(src)
    while j < n:
        c = src[j]
        if c == 0x5C:  # backslash
            if j + 1 >= n:
                break
            d = src[j + 1]
            if d in _LITERAL_ESCAPES:
                out += _LITERAL_ESCAPES[d]
                j += 2
            elif 0x30 <= d <= 0x37:
                k = j + 1
                while k < n and k < j + 4 and 0x30 <= src[k] <= 0x37:
                    k += 1
                out.append(int(src[j + 1:k], 8) & 0xFF)
                j = k
            elif d in (0x0A, 0x0D):  # 줄 이음
                j += 2
                if d == 0x0D and j < n and src[j] == 0x0A:
                    j += 1
            else:
                out.append(d)
                j += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(out), j + 1
        out.append(c)
        j += 1
    return bytes(out), n


def _decode_pdf_string(raw: bytes) -> str:
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace")
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


def pdf_strings(src: bytes):
    """객체 원문(스트림 본문 제외)의 리터럴·16진 문자열을 풀어 돌려준다(PDFDocEncoding≈latin-1, UTF-16BE/LE BOM, UTF-8 BOM)."""
    i, n = 0, len(src)
    while i < n:
        m = _STRING_START.search(src, i)
        if not m:
            return
        i = m.start()
        if src[i] == 0x28:
            raw, i = _literal(src, i)
            yield _decode_pdf_string(raw)
        elif src[i + 1:i + 2] == b"<":
            i += 2
        else:
            h = _HEX_BODY.match(src, i)
            if not h:
                i += 1
                continue
            digits = re.sub(rb"\s", b"", h.group(1))
            if len(digits) % 2:
                digits += b"0"
            i = h.end()
            yield _decode_pdf_string(bytes.fromhex(digits.decode("ascii")))


# "endstream"의 꼬리 "stream"을 스트림 시작으로 잡으면 다음 객체 사전까지 건너뛴다 - 앞 글자가 영문자가 아닐 때만
_STREAM_BODY = re.compile(rb"(?<![A-Za-z])stream(?:\r\n|\n|\r)(.*?)(?<![A-Za-z])endstream", re.S)


def _outside_streams(data: bytes):
    """파일 바이트에서 스트림 본문을 뺀 나머지 조각(객체 사전·트레일러). 경계를 잘못 잡으면 더 보게 될 뿐이다."""
    pos = 0
    for m in _STREAM_BODY.finditer(data):
        yield data[pos:m.start(1)]
        pos = m.end(1)
    yield data[pos:]


def dict_scan(doc, values: list[str], data: bytes | None = None) -> list[int]:
    """저장본의 객체 사전 문자열에서, 공백을 뺀 값(대소문자 무시)이 든 값 번호 목록(스트림 본문 제외 - 명세 §3.3).

    보는 곳 세 가지: ① xref에 있는 모든 객체와 트레일러 ② 객체 스트림(/Type/ObjStm) 본문 전체 - xref에서 빠졌는데 객체
    스트림에 남은 옛 객체(MuPDF garbage=1 + 객체 스트림에서 실측)까지 ③ 파일 바이트에서 스트림 본문을 뺀 나머지 전부.
    """
    wanted = [(k, _squash(v).casefold()) for k, v in enumerate(values) if _squash(v)]
    if not wanted:
        return []
    found: set[int] = set()

    def scan(src: bytes) -> bool:
        if not src or (b"(" not in src and b"<" not in src):
            return False
        for s in pdf_strings(src):
            s = _squash(s).casefold()
            if not s:
                continue
            for k, v in wanted:
                if k not in found and v in s:
                    found.add(k)
        return len(found) == len(wanted)

    def sources():
        yield doc.pdf_trailer(compressed=True).encode("latin-1", "replace")
        for x in range(1, doc.xref_length()):
            src = doc.xref_object(x, compressed=True)
            yield src.encode("latin-1", "replace")
            if doc.xref_is_stream(x) and "/ObjStm" in src:
                yield doc.xref_stream(x) or b""
        if data is not None:
            yield from _outside_streams(data)

    for src in sources():
        if scan(src):
            break
    return sorted(found)


def page_payload(lay: PageLayout) -> dict:
    out = {"t": lay.text}
    if lay.actual is not None:
        out["a"] = lay.actual
    return out


# ---------------------------------------------------------------- 명령


class State:
    def __init__(self) -> None:
        self.doc = None
        self.layouts: list[PageLayout] = []

    def reset(self) -> None:
        if self.doc is not None:
            try:
                self.doc.close()
            except Exception:
                pass
        self.doc = None
        self.layouts = []


def op_extract(state: State, cmd: dict, data: bytes) -> tuple[dict, bytes | None]:
    fitz = _fitz()
    state.reset()
    max_total = int(cmd.get("max_total_chars", 0))
    max_nonspace = int(cmd.get("max_nonspace_chars", 0))
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception:
        return {"ok": True, "status": "unsupported", "detail": "unreadable"}, None
    if not doc.is_pdf:
        doc.close()
        return {"ok": True, "status": "unsupported", "detail": "not_pdf"}, None
    if doc.needs_pass:
        doc.close()
        return {"ok": True, "status": "unsupported", "detail": "encrypted"}, None
    state.doc = doc
    budget = [max_total, max_nonspace]
    pages = []
    try:
        for page in doc:
            lay = page_layout(fitz, page, budget=budget)
            state.layouts.append(lay)
            pages.append(page_payload(lay))
    except Unsupported as exc:
        state.reset()
        return {"ok": True, "status": "unsupported", "detail": exc.detail}, None
    except MemoryError:
        raise
    except Exception:
        state.reset()
        return {"ok": True, "status": "unsupported", "detail": "page_unreadable"}, None
    return {"ok": True, "status": "ok", "page_count": doc.page_count, "pages": pages}, None


def _spans(cmd: dict, state: State) -> dict[int, list]:
    raw = cmd.get("spans")
    if not isinstance(raw, dict):
        raise ValueError("spans")
    out: dict[int, list] = {}
    for key, items in raw.items():
        pno = int(key)
        if not 0 <= pno < len(state.layouts) or not isinstance(items, list):
            raise ValueError("spans")
        size = len(state.layouts[pno].text)
        clean = []
        for item in items:
            s, e = int(item[0]), int(item[1])
            if not 0 <= s < e <= size:
                raise ValueError("spans")
            label = item[2] if len(item) > 2 else None
            if label is not None and not (isinstance(label, str) and LABEL_RE.fullmatch(label)):
                raise ValueError("spans")
            clean.append((s, e, label))
        out[pno] = clean
    return out


def op_redact(state: State, cmd: dict) -> tuple[dict, bytes | None]:
    fitz = _fitz()
    doc = state.doc
    if doc is None:
        raise RuntimeError("no document")
    spans = _spans(cmd, state)
    values = [str(v) for v in cmd.get("values", [])]
    max_output = int(cmd.get("max_output", MAX_INPUT_PDF))
    timings = {}
    labels_drawn = 0
    t = time.perf_counter()
    try:
        for pno in sorted(spans):
            rects, labels = plan_redaction(state.layouts[pno], spans[pno])
            if not rects:
                continue
            page = doc[pno]
            # 한 쪽에 지우기 주석이 많으면 추가·적용 시간이 개수의 제곱으로 는다(1,000개 4.4초) - 묶어서 여러 번 적용(1.5초)
            for i in range(0, len(rects), REDACT_BATCH):
                for rect in rects[i:i + REDACT_BATCH]:
                    page.add_redact_annot(fitz.Rect(rect), fill=(0, 0, 0))
                page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE, graphics=fitz.PDF_REDACT_LINE_ART_NONE,
                                      text=fitz.PDF_REDACT_TEXT_REMOVE)
            # 표시는 그 쪽 지우기를 모두 적용한 뒤에 쓴다(다음 묶음 적용이 앞서 쓴 표시를 지우지 않게)
            labels_drawn += draw_labels(fitz, page, labels)
    except Unsupported as exc:
        state.reset()
        return {"ok": True, "status": "unsupported", "detail": exc.detail}, None
    timings["redact_ms"] = round((time.perf_counter() - t) * 1000, 1)
    t = time.perf_counter()
    scrub_document(fitz, doc)
    # garbage=2(안 쓰는 객체 제거 + 번호 압축). garbage=1 + 객체 스트림은 지운 주석·책갈피 객체가 객체 스트림 안에 그대로
    # 남는다(실측). garbage=3(중복 병합)은 큰 파일에서 수십 초(명세 §1.2)라 쓰지 않는다. 시간은 garbage=1과 같다(실측).
    out = doc.tobytes(garbage=2, deflate=True, use_objstms=1, encryption=fitz.PDF_ENCRYPT_NONE)
    timings["save_ms"] = round((time.perf_counter() - t) * 1000, 1)
    page_count = doc.page_count
    state.reset()  # 원본 문서는 더 쓰지 않는다
    if len(out) > max_output:
        return {"ok": True, "status": "unsupported", "detail": "result_too_large"}, None
    t = time.perf_counter()
    check = fitz.open(stream=out, filetype="pdf")
    try:
        if check.page_count != page_count or check.needs_pass:
            raise RuntimeError("saved document does not reopen")
        pages = [page_payload(page_layout(fitz, page, boxes=False)) for page in check]
        timings["reextract_ms"] = round((time.perf_counter() - t) * 1000, 1)
        t = time.perf_counter()
        hits = dict_scan(check, values, out)
        timings["dict_scan_ms"] = round((time.perf_counter() - t) * 1000, 1)
    finally:
        check.close()
    return {"ok": True, "status": "ok", "page_count": page_count, "pages": pages, "dict_hits": hits,
            "size": len(out), "timings": timings, "labels": labels_drawn}, out


def op_test(cmd: dict) -> dict:
    """시험 전용(--test-ops로 띄운 자식만): 멈춤·비정상 종료·메모리 잡기."""
    what = cmd.get("what")
    if what == "sleep":
        time.sleep(float(cmd.get("seconds", 1)))
    elif what == "exit":
        os._exit(3)
    elif what == "alloc":
        block = bytearray(int(cmd.get("mb", 1)) * 1024 * 1024)
        block[::4096] = b"\x01" * len(block[::4096])
        return {"ok": True, "allocated": len(block)}
    elif what == "oversize":
        return {"ok": True, "junk": "x" * int(cmd.get("chars", 1))}
    return {"ok": True}


def dispatch(state: State, cmd: dict, blob: bytes | None, test_ops: bool) -> tuple[dict, bytes | None]:
    op = cmd.get("op")
    if op == "extract":
        if blob is None:
            raise ValueError("extract needs a PDF")
        return op_extract(state, cmd, blob)
    if op == "redact":
        return op_redact(state, cmd)
    if op == "release":
        state.reset()
        return {"ok": True}, None
    if op == "probe":
        return {"ok": True, **probe()}, None
    if op == "test" and test_ops:
        return op_test(cmd), None
    raise ValueError("unknown op")


def serve(inp, out, *, test_ops: bool = False) -> int:
    state = State()
    write_frame(out, encode_json({"ok": True, "op": "hello", "protocol": PROTOCOL, "pid": os.getpid()}))
    out.flush()
    while True:
        try:
            cmd = decode_json(read_frame(inp, MAX_COMMAND_JSON))
            blob = read_frame(inp, MAX_INPUT_PDF) if cmd.get("blob") else None
        except EOFError:
            return 0
        except Exception:
            return 2  # 부모가 약속을 어겼다 - 더 읽지 않는다
        try:
            reply, data = dispatch(state, cmd, blob, test_ops)
        except MemoryError:
            state.reset()
            reply, data = {"ok": False, "error": "MemoryError"}, None
        except Exception as exc:
            state.reset()
            reply, data = {"ok": False, "error": type(exc).__name__}, None
        reply.update(memory_peaks_kb())
        if data is not None:
            reply["blob"] = True
        write_frame(out, encode_json(reply))
        if data is not None:
            write_frame(out, data)
        out.flush()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rlimit_as = 0
    test_ops = False
    while argv:
        arg = argv.pop(0)
        if arg == "--rlimit-as" and argv:
            rlimit_as = int(argv.pop(0))
        elif arg == "--test-ops":
            test_ops = True
    harden(rlimit_as)
    # 표준 입출력 번호(0·1)는 /dev/null로 돌려 놓고 복제본으로만 주고받는다 - C 코드가 무심코 찍는 글자가 묶음을 깨지 않게
    inp = os.fdopen(os.dup(0), "rb", buffering=0)
    out = os.fdopen(os.dup(1), "wb")
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    sys.stdin = open(os.devnull)
    sys.stdout = open(os.devnull, "w")
    try:
        return serve(inp, out, test_ops=test_ops)
    finally:
        try:
            out.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
