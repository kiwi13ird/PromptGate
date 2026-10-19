"""Gateway 시험 공용 도구(2026-10-10). 가짜 값만 쓴다. 실제 Detection·대시보드에 연결하지 않는다."""

from __future__ import annotations

import asyncio
import io
import struct
import zipfile
import zlib

REVISION_1 = "00000000-0000-4000-8000-000000000001"
REVISION_2 = "00000000-0000-4000-8000-000000000002"


def settings_doc(prompt=("forward", 0.5), file=("block", 2.0), image="allow", scanned_pdf="block", other="block",
                 notify=False, version=1, revision=REVISION_1, updated_by="test-admin"):
    """대시보드 지표 응답의 gateway_settings 문서(칸 7개)."""
    return {
        "version": version,
        "revision": revision,
        "updated_at": "2026-10-10T05:12:00.000Z",
        "updated_by": updated_by,
        "timeout": {"prompt": {"action": prompt[0], "seconds": prompt[1]},
                    "file": {"action": file[0], "seconds": file[1]}},
        "uninspectable": {"image": image, "scanned_pdf": scanned_pdf, "other": other},
        "notify_on_allow": notify,
    }


class FixedSettings:
    """gateway.GATEWAY_SETTINGS 대신 쓰는 고정 설정(current()만)."""

    def __init__(self, **kwargs):
        from gateway_settings import parse_settings   # 운영본(이 묶음 전)으로 시험을 돌릴 때도 모듈은 불러지게
        self.settings = parse_settings(settings_doc(**kwargs))

    def current(self):
        return self.settings


# ------------------------------------------------------------------ 파일 만들기

def pdf_from(content: bytes, *, extra_objects=(), page_extra=b"", catalog_extra=b"", resources=None) -> bytes:
    """쪽 하나짜리 PDF. content = 쪽 내용 스트림. extra_objects는 6번부터 번호가 붙는다."""
    resources = resources if resources is not None else b"<< /Font << /F1 5 0 R >> >>"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b">>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources " + resources
        + b" " + page_extra + b">>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        *extra_objects,
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def text_pdf(text: str, x=72, y=720) -> bytes:
    return pdf_from(f"BT /F1 12 Tf {x} {y} Td ({text}) Tj ET".encode("latin-1"))


def scanned_pdf() -> bytes:
    """글자 없이 그림(이미지 XObject) 한 장만 그린 쪽 = 스캔 PDF."""
    pixels = b"\x80\x80\x80" * 4
    image = (b"<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8 "
             b"/Length " + str(len(pixels)).encode() + b" >>\nstream\n" + pixels + b"\nendstream")
    return pdf_from(b"q 200 0 0 200 100 400 cm /Im1 Do Q", extra_objects=[image],
                    resources=b"<< /XObject << /Im1 6 0 R >> >>")


def vector_only_pdf() -> bytes:
    lines = b"\n".join(f"{x} {x} m {x + 50} {x + 20} l S".encode() for x in range(10, 500, 10))
    return pdf_from(lines, resources=b"<< >>")


def empty_pdf() -> bytes:
    return pdf_from(b"", resources=b"<< >>")


def annotation_pdf(contents: str) -> bytes:
    annot = (b"<< /Type /Annot /Subtype /FreeText /Rect [100 100 300 150] /DA (/Helv 12 Tf 0 g) /Contents ("
             + contents.encode("latin-1") + b") >>")
    return pdf_from(b"", extra_objects=[annot], page_extra=b"/Annots [6 0 R]", resources=b"<< >>")


def form_field_pdf(value: str) -> bytes:
    widget = (b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (field1) /V (" + value.encode("latin-1")
              + b") /Rect [100 100 300 150] /P 3 0 R >>")
    return pdf_from(b"", extra_objects=[widget], page_extra=b"/Annots [6 0 R]", resources=b"<< >>",
                    catalog_extra=b"/AcroForm << /Fields [6 0 R] >> ")


def attachment_pdf(text: str) -> bytes:
    """본문 글자 + 첨부 파일(EmbeddedFiles). 안의 파일은 검사하지 않으므로 other."""
    payload = b"RRN 900101-1234567"
    embedded = b"<< /Type /EmbeddedFile /Length " + str(len(payload)).encode() + b" >>\nstream\n" + payload + b"\nendstream"
    spec = b"<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F 6 0 R >> >>"
    return pdf_from(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1"), extra_objects=[embedded, spec],
                    catalog_extra=b"/Names << /EmbeddedFiles << /Names [(a.txt) 7 0 R] >> >> ")


def xfa_pdf(text: str) -> bytes:
    xfa = b"<< /Length 20 >>\nstream\n<xdp:xdp></xdp:xdp>\nendstream"
    return pdf_from(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1"), extra_objects=[xfa],
                    catalog_extra=b"/AcroForm << /Fields [] /XFA 6 0 R /NeedsRendering true >> ")


def png_bytes(width=2, height=2, trailer=b"") -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"") + trailer)


def gif_bytes() -> bytes:
    # 1x1 GIF89a (전역 색표 2색, 이미지 블록, 끝 3B)
    return (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
            b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")


def webp_bytes() -> bytes:
    body = b"WEBP" + b"VP8L" + struct.pack("<I", 5) + b"\x2f\x00\x00\x00\x00" + b"\x00"
    return b"RIFF" + struct.pack("<I", len(body)) + body


def jpeg_bytes(progressive=False) -> bytes:
    """구조 확인용 최소 JPEG(SOI·APP0·DQT·SOF·DHT·SOS·압축 데이터·EOI). 화면에 그릴 수 있는지는 보지 않는다."""
    def segment(marker, data):
        return b"\xff" + bytes([marker]) + struct.pack(">H", len(data) + 2) + data
    sof = 0xC2 if progressive else 0xC0
    return (b"\xff\xd8" + segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
            + segment(0xDB, b"\x00" + bytes(range(1, 65)))
            + segment(sof, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00")
            + segment(0xC4, b"\x00" + b"\x01" + b"\x00" * 15 + b"\x00")
            + segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
            + b"\x12\x34\xff\x00\x56\xff\xd0\x78"     # 데이터 안 FF00(채움)·RST0
            + b"\xff\xd9")


def mpo_bytes(trailer=b"") -> bytes:
    """여러 장 JPEG(MPF): 첫 JPEG에 APP2 'MPF\\0' 머리, 끝 표지(EOI) 뒤에 둘째 JPEG(Ultra HDR 이득 지도 등).
    MP 색인 값은 구조 확인에 쓰지 않으므로 형식만 맞춘다."""
    first = jpeg_bytes()
    mpf = b"MPF\x00" + b"MM\x00\x2a\x00\x00\x00\x08" + b"\x00\x00"
    app2 = b"\xff\xe2" + struct.pack(">H", len(mpf) + 2) + mpf
    return first[:2] + app2 + first[2:] + jpeg_bytes(progressive=True) + trailer


def raw_docx(body_xml: str) -> bytes:
    """python-docx 없이 만든 최소 DOCX(본문 XML을 그대로 넣음). 비정상 구조(깊은 중첩 등) 시험용."""
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
             '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
             '<Default Extension="xml" ContentType="application/xml"/>'
             '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.'
             'wordprocessingml.document.main+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'officeDocument" Target="word/document.xml"/></Relationships>')
    document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{w}">'
                f'<w:body>{body_xml}</w:body></w:document>')
    return zip_bytes({"[Content_Types].xml": types, "_rels/.rels": rels, "word/document.xml": document})


def nested_text_boxes(depth: int, leaves: int, text: str = "a") -> str:
    """글상자 안 문단 안 글상자 … depth겹, 가장 안 문단에 w:t leaves개(작은 파일로 큰 추출 비용을 만드는 모양)."""
    inner = "<w:p><w:r>" + f"<w:t>{text}</w:t>" * leaves + "</w:r></w:p>"
    for _ in range(depth):
        inner = f"<w:p><w:r><w:txbxContent>{inner}</w:txbxContent></w:r></w:p>"
    return inner


def wrapper_chain(depth: int, leaves: int, text: str = "a") -> str:
    """문단 안 depth겹 감싼 요소 아래 w:t leaves개."""
    return "<w:p><w:r>" + "<w:x>" * depth + f"<w:t>{text}</w:t>" * leaves + "</w:x>" * depth + "</w:r></w:p>"


def zip_bytes(entries: dict) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return stream.getvalue()


def rewrite_zip(data: bytes, replace: dict) -> bytes:
    """기존 ZIP(DOCX 등)의 파트를 바꾸거나 더한다."""
    source = zipfile.ZipFile(io.BytesIO(data))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in source.infolist():
            if info.filename not in replace:
                archive.writestr(info, source.read(info.filename))
        for name, value in replace.items():
            archive.writestr(name, value)
    return stream.getvalue()


def zip_bomb_declared(declared_size: int) -> bytes:
    """압축을 푼 선언 크기만 큰 ZIP(중앙 디렉터리의 file_size를 바꿈). 실제로 풀지 않아도 상한에 걸려야 한다."""
    data = bytearray(zip_bytes({"word/document.xml": b"<w:document/>"}))
    eocd = data.rfind(b"PK\x05\x06")
    (cd_offset,) = struct.unpack("<I", data[eocd + 16:eocd + 20])
    struct.pack_into("<I", data, cd_offset + 24, declared_size)   # 중앙 디렉터리 uncompressed size
    return bytes(data)


# ------------------------------------------------------------------ 훅 부르기

def run_hook(result):
    """훅을 직접 부른 결과를 끝까지 돌린다: run_hook(gateway.request(flow)).

    2026-10-11부터 gateway.request는 async다(파일 업로드는 전용 작업 스레드에서 처리하고 기다림). 직접 부르면 코루틴만
    만들고 아무것도 하지 않으므로 끝까지 돌려야 한다. 동기 훅(그 전 운영본)이면 받은 값을 그대로 돌려준다."""
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result
