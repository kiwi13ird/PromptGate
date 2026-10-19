"""가린 PDF의 누출 판정(시험 정답 대조용, 명세 T2-1·T2-2). 가림 코드와 따로 짰다 - 같은 코드로 검사하면 같은 실수를 놓친다.

- 글자 추출 3종: PyMuPDF(ActualText 반영·무시 둘 다), pypdf, pypdfium2(설치돼 있을 때 - Gateway가 쓰는 추출기)
- 문서 수준: **모든 xref**의 객체 원문과 스트림 본문(압축 해제)에서 리터럴·16진 문자열을 PDFDocEncoding·UTF-16BE로 풀고,
  원문 바이트 자체도 같이 본다(단순 글꼴은 내용 스트림에 글자가 그대로)
- 값 비교는 공백을 모두 빼고 한다(줄바꿈·자간으로 나뉜 값도 잡히게)
"""

from __future__ import annotations

import io
import re
import zlib

import fitz


def squash(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _unescape(body: bytes) -> bytes:
    out, i = bytearray(), 0
    esc = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}
    while i < len(body):
        c = body[i:i + 1]
        if c == b"\\" and i + 1 < len(body):
            n = body[i + 1:i + 2]
            if n in esc:
                out += esc[n]
                i += 2
                continue
            m = re.match(rb"[0-7]{1,3}", body[i + 1:i + 4])
            if m:
                out.append(int(m.group(), 8) & 0xFF)
                i += 1 + len(m.group())
                continue
            i += 1
            continue
        out += c
        i += 1
    return bytes(out)


def strings(src: bytes):
    i, n = 0, len(src)
    while i < n:
        c = src[i:i + 1]
        if c == b"(":
            depth, j = 1, i + 1
            while j < n and depth:
                if src[j:j + 1] == b"\\":
                    j += 2
                    continue
                depth += {b"(": 1, b")": -1}.get(src[j:j + 1], 0)
                j += 1
            raw = _unescape(src[i + 1:j - 1])
            i = j
        elif c == b"<" and src[i + 1:i + 2] != b"<":
            j = src.find(b">", i)
            if j < 0:
                break
            hx = re.sub(rb"\s", b"", src[i + 1:j])
            i = j + 1
            if not re.fullmatch(rb"[0-9A-Fa-f]*", hx):
                continue
            raw = bytes.fromhex((hx + b"0" * (len(hx) % 2)).decode())
        elif c == b"<":
            i += 2
            continue
        else:
            i += 1
            continue
        yield raw.decode("utf-16-be", "replace") if raw[:2] == b"\xfe\xff" else raw.decode("latin-1")


def extract_texts(data: bytes) -> dict[str, str]:
    out = {}
    doc = fitz.open(stream=data, filetype="pdf")
    inf = fitz.INFINITE_RECT()
    out["pymupdf_glyph"] = "\n".join(p.get_text(flags=2 | 128 | 2048, clip=inf) for p in doc)
    out["pymupdf_actual"] = "\n".join(p.get_text(flags=2 | 128, clip=inf) for p in doc)
    out["pymupdf_annots"] = "\n".join(str((a.info or {}).get("content", "")) for p in doc for a in (p.annots() or ()))
    out["pymupdf_widgets"] = "\n".join(str(w.field_value) for p in doc for w in (p.widgets() or ()))
    out["pymupdf_toc"] = "\n".join(t[1] for t in doc.get_toc())
    out["pymupdf_meta"] = "\n".join(str(v) for v in (doc.metadata or {}).values() if v)
    out["pymupdf_xmp"] = doc.get_xml_metadata() or ""
    import pypdf

    reader = pypdf.PdfReader(io.BytesIO(data))
    out["pypdf"] = "\n".join(page.extract_text() or "" for page in reader.pages)
    try:
        import pypdfium2 as pdfium
    except ImportError:
        pass
    else:
        pdf = pdfium.PdfDocument(data)
        texts = []
        for i in range(len(pdf)):
            textpage = pdf[i].get_textpage()
            texts.append(textpage.get_text_range())
            textpage.close()
        pdf.close()
        out["pypdfium2"] = "\n".join(texts)
    return out


def object_strings(data: bytes) -> list[tuple[int, str]]:
    doc = fitz.open(stream=data, filetype="pdf")
    found = []
    for x in range(1, doc.xref_length()):
        try:
            src = doc.xref_object(x, compressed=False).encode("latin-1", "replace")
        except Exception:
            continue
        parts = list(strings(src))
        if doc.xref_is_stream(x):
            try:
                body = doc.xref_stream(x) or b""
            except Exception:
                body = doc.xref_stream_raw(x) or b""
                try:
                    body = zlib.decompress(body)
                except Exception:
                    pass
            parts.append(body.decode("latin-1"))
            parts += list(strings(body))
        parts.append(src.decode("latin-1"))
        found += [(x, s) for s in parts]
    found.append((0, doc.pdf_trailer()))
    return found


def leaks(data: bytes, values: list[str]) -> dict[str, list[str]]:
    """값마다 남아 있는 곳 목록. 빈 dict면 누출 0."""
    result: dict[str, list[str]] = {}
    texts = {k: squash(v) for k, v in extract_texts(data).items()}
    objs = [(x, squash(s)) for x, s in object_strings(data)]
    for value in values:
        v = squash(value)
        where = [k for k, t in texts.items() if v in t]
        where += sorted({f"xref{x}" for x, s in objs if v in s})
        if where:
            result[value] = where
    return result


def kept(data: bytes, words: list[str]) -> list[str]:
    text = squash(extract_texts(data)["pymupdf_glyph"])
    return [w for w in words if squash(w) in text]
