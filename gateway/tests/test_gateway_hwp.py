"""HWP 5.0·HWPX 업로드 검사(2026-10-11, masking-design/SPEC.md §2.3 1단계 Gateway). 가짜 값만 쓴다.

1. 분류(inspect_upload): 공통 모듈 hwpdoc으로 뽑은 글자 = '\\n'.join(lines()), 닫힌 목록·암호·배포용·손상·폭탄·그림만·
   미리보기 불일치·olefile 없음·시간/글자 한도. 10/11 검토 지적: 다른 리더가 읽는 숨은 바이트(덧붙인·BinData 안 DOCX·HWPX·
   PDF, 앞에 붙인 ZIP, 항목 사이 빈틈, 지역 머리 이름 바꿈, ZIP 주석), HWPX + DOCX·XLSX 부품 혼합, FileHeader 이름 없는 CFB는
   olefile을 부르지 않음
2. 실제 mitmproxy flow(request()·response() 훅): ChatGPT 원본 PUT·multipart, Claude multipart ×
   (깨끗한 HWP·HWPX, 개인정보 HWP·HWPX, 보호 문서 HWP, 배포용 HWP, 닫힌 목록 밖 HWP, 손상·폭탄 HWPX 등)
   → 전달·403(mask_application_failed·doc_excerpt·file_uninspectable_other·file_too_large)·이벤트·재시도 기록 한 번
   (2026-10-11 3단계부터 HWP·HWPX도 칸 검사·가림. 가림 성공·거절·재검사는 tests/test_gateway_hwp_mask.py)
3. 실제 DumpMaster + 로컬 upstream: 깨끗한 HWP는 바이트 그대로, 개인정보 HWP는 upstream에 가지 않음
4. 배포 경계: olefile·hwpdoc 없이도 gateway가 뜨고 HWP만 other, Detection 사본과 hwpdoc md5 동일, 등록 글자와 창 일치
실행: python -m unittest tests.test_gateway_hwp -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from tests.test_gateway_bundle_flows import (  # noqa: E402
    CFB, CLAUDE_UPLOAD_PATH, DOCX, FILE_ID, RRN, SECRET, Base, docx_bytes, fake_detection, xlsx_bytes,
)
from tests.test_gateway_dedupe_proto import FILE_ID_2, DedupeBase  # noqa: E402
from tests import hwp_synth as S  # noqa: E402
from tests.gw_support import png_bytes, text_pdf  # noqa: E402

import gateway  # noqa: E402
import gateway_file_classes  # noqa: E402
from gateway_file_classes import inspect_upload  # noqa: E402
from gateway_settings import file_max_chars  # noqa: E402
from signature_detector.document import hwpdoc  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 20 * 1024 * 1024
MAX_CHARS = file_max_chars(2.0)
# Detection 작업 사본(hwpdoc 원본·등록 경로). 없으면 그 시험만 건너뛴다
DETECTION_DIR = Path(os.environ.get(
    "GW_TEST_DETECTION_DIR",
    "C:/Users/user/AppData/Local/Temp/claude/C--Users-user-Desktop-kisia-project/"
    "66c16aaa-f943-4135-8e5f-e20fe54ffdc3/scratchpad/det-work"))


def classify(data, *, max_bytes=MAX_BYTES, max_chars=MAX_CHARS, seconds=2.0, clock=time.monotonic):
    return inspect_upload(data, max_bytes=max_bytes, max_chars=max_chars, deadline=clock() + seconds, clock=clock)


def cell_count(data):
    """칸 검사 호출 수(3단계): 글자 있는 문단 + 부가 글자."""
    from signature_detector.document import hwp_segments

    kind = "hwp" if data[:4] == b"\xd0\xcf\x11\xe0" else "hwpx"
    return len(hwp_segments.extract_segments(hwp_segments.read_document(data), kind))


# ------------------------------------------------------------------ 가짜 HWP·HWPX

def _table(rows):
    cells = []
    for r, (label, value) in enumerate(rows):
        cells += [(r, 0, 1, 1, [S.p(2, label)]), (r, 1, 1, 1, [S.p(2, value)])]
    return S.para(0, S.ext_ctrl(11, "tbl "), S.table(1, cells, len(rows), 2, desc="표입니다."))


def hancom_preview(paragraphs, rows):
    """한컴 미리보기(PrvText)와 같은 모양: 레코드 순서, 줄은 CRLF, 표 칸은 <…>."""
    out = [paragraphs[0]]
    if rows:
        out.append("".join(f"<{label}><{value}>" for label, value in rows))
    out += list(paragraphs[1:])
    return "\r\n".join(out) + "\r\n"


def make_hwp(paragraphs, rows=(), *, summary=None, prvtext=None, flags=1, extra=None, children=()):
    sec = S.p(0, paragraphs[0], *children) + (_table(rows) if rows else b"")
    sec += b"".join(S.p(0, text) for text in paragraphs[1:])
    if prvtext is None:
        prvtext = hancom_preview(paragraphs, rows)
    return S.build_hwp([sec], flags=flags, summary=summary, prvtext=prvtext, extra=extra)


def make_hwpx(paragraphs, *, prvtext="", meta=None, extra=None, mimetype="application/hwp+zip"):
    body = "".join(S.hp_p(S.hp_t(text)) for text in paragraphs)
    return S.build_hwpx([body], prvtext=prvtext, meta=meta, extra=extra, mimetype=mimetype)


CLEAN_LINES = ["주간 회의록 (가짜)", "다음 회의는 목요일 오후 2시입니다."]
CLEAN_ROWS = [("안건", "분기 일정 검토"), ("담당", "기획팀")]
CLEAN_HWP = make_hwp(CLEAN_LINES, CLEAN_ROWS, summary={2: "주간 회의록", 4: "가짜 작성자"})
CLEAN_HWPX = make_hwpx(CLEAN_LINES, prvtext="주간 회의록 (가짜)\r\n다음 회의는", meta={"creator": "가짜 작성자"})
PII_HWP = make_hwp(["가짜 인사 기록 카드"], [("성명", "김가짜"), ("주민등록번호", RRN)])
PII_HWPX = make_hwpx(["가짜 인사 기록 카드", f"주민등록번호 {RRN}"])
SECRET_HWP = make_hwp([f"{SECRET} 3분기 출시 계획(가짜)", "세부 일정은 별첨 참고"])
DIST_HWP = make_hwp(["배포용 문서(가짜)"], flags=1 | 4)
PASSWORD_HWP = make_hwp(["암호 문서(가짜)"], flags=1 | 2)
CLOSED_HWP = make_hwp(["양식 개체가 든 문서(가짜)"], children=(S.rec(87, 1, b"\x00" * 8),))
OLE_BINDATA_HWP = make_hwp(["OLE 개체가 든 문서(가짜)"], extra={"BinData/BIN0001.ole": b"x" * 10})
PICTURE_ONLY_HWP = S.build_hwp([S.para(0, S.ext_ctrl(11, "gso "), S.picture(1, desc="그림입니다."))],
                               extra={"BinData/BIN0001.png": png_bytes()}, prvtext="")
STALE_PREVIEW_HWP = make_hwp(["새 판 본문(가짜)"], prvtext=f"옛 판 본문\r\n주민등록번호 {RRN}\r\n")
CORRUPT_HWPX = S.build_hwpx(["<hp:p>깨진 문단"])
BOMB_HWPX = S.build_hwpx([S.hp_p(S.hp_t("가")) + " " * (21 * 1024 * 1024)])     # 압축하면 수십 KB, 풀면 21MiB
BOMB_HWP = S.build_hwp([S.p(0, "가짜") + S.rec(69, 1, bytes(21 * 1024 * 1024))], prvtext="")
CLOSED_HWPX = S.build_hwpx([S.hp_p(S.hp_t("본문(가짜)"), S.hp_run('<hp:ole id="1" binaryItemIDRef="ole1"/>'))])
UNKNOWN_TEXT_HWPX = S.build_hwpx([S.hp_p(S.hp_t("본문(가짜)"), S.hp_run("<hp:unknownThing>숨은 글자</hp:unknownThing>"))])
ENCRYPTED_HWPX = S.build_hwpx([S.hp_p(S.hp_t("본문"))], manifest=(
    '<?xml version="1.0" encoding="UTF-8"?><odf:manifest xmlns:odf="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
    '<odf:file-entry odf:full-path="Contents/section0.xml"><odf:encryption-data/></odf:file-entry></odf:manifest>'))


# ------------------------------------------------------------------ 다른 리더가 읽는 숨은 바이트(10/11 검토 지적 1·3)
# 깨끗한 HWP·HWPX에 개인정보 DOCX·HWPX·PDF를 숨긴 파일. 우리가 읽는 HWP·HWPX는 깨끗하지만 받는 쪽 ZIP·PDF 리더는 개인정보를 읽는다

PII_DOCX = docx_bytes("성명 김가짜", f"주민등록번호 {RRN}")
PII_PDF = text_pdf(f"RRN {RRN}")
PLAIN_HWPX = make_hwpx(["평범한 회의 메모(가짜)"])


def after(prefix: bytes, pdf: bytes) -> bytes:
    """prefix 뒤에 PDF를 붙이고 xref·startxref 위치를 파일 처음부터 센 값으로 고친다(PDF 리더가 복구 없이 읽음)."""
    head, xref = pdf.split(b"xref\n", 1)
    xref = re.sub(rb"(?m)^(\d{10})( 00000 n )", lambda m: b"%010d%s" % (int(m.group(1)) + len(prefix), m.group(2)), xref)
    xref = re.sub(rb"startxref\n(\d+)", lambda m: b"startxref\n%d" % (int(m.group(1)) + len(prefix)), xref)
    return prefix + head + b"xref\n" + xref


def zip_parts(*archives) -> bytes:
    """여러 ZIP의 항목을 한 패키지로(이름이 겹치면 앞 것)."""
    out, seen = io.BytesIO(), set()
    with zipfile.ZipFile(out, "w") as merged:
        for archive in archives:
            with zipfile.ZipFile(io.BytesIO(archive)) as source:
                for info in source.infolist():
                    if info.filename not in seen:
                        seen.add(info.filename)
                        merged.writestr(info, source.read(info.filename))
    return out.getvalue()


def hwpx_with_gap(hidden_zip: bytes) -> bytes:
    """깨끗한 HWPX의 첫 항목(mimetype) 뒤에 다른 ZIP의 지역 항목을 끼워 넣는다. 중앙 디렉터리는 HWPX 항목만 가리킨다
    (위치는 맞게 고침) - zipfile·hwpdoc은 HWPX만, 앞에서부터 읽는 리더는 끼운 항목까지 본다."""
    hidden = hidden_zip[:struct.unpack_from("<I", hidden_zip, len(hidden_zip) - 6)[0]]   # 지역 항목들(중앙 디렉터리 앞)
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(PLAIN_HWPX)) as source, zipfile.ZipFile(out, "w") as target:
        for index, info in enumerate(source.infolist()):
            target.writestr(info, source.read(info.filename))
            if index == 0:
                out.seek(target.start_dir)
                out.write(hidden)
                target.start_dir = out.tell()
    return out.getvalue()


def hwpx_with_renamed_local_header(content: bytes) -> bytes:
    """중앙 디렉터리 이름은 BinData/image.png(그림이라 hwpdoc이 내용을 읽지 않음), 지역 머리 이름은 word/document.xml."""
    data = bytearray(make_hwpx(["평범한 회의 메모(가짜)"], extra={"BinData/image.png": content}))
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        local = archive.getinfo("BinData/image.png").header_offset
    assert data[local + 30:local + 47] == b"BinData/image.png"          # 두 이름 모두 17바이트
    data[local + 30:local + 47] = b"word/document.xml"
    return bytes(data)


def hwpx_rewritten(*, comment: bytes = b"", stored: dict | None = None) -> bytes:
    """깨끗한 HWPX에 ZIP 주석을 달거나 저장(무압축) 항목을 더한다."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(PLAIN_HWPX)) as source, zipfile.ZipFile(out, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info.filename))
        for name, value in (stored or {}).items():
            target.writestr(name, value, compress_type=zipfile.ZIP_STORED)
        target.comment = comment
    return out.getvalue()


def streamed_entries(data: bytes) -> dict:
    """앞에서부터 지역 머리를 따라 읽는 리더(libarchive·Java ZipInputStream 방식): 이름 → 풀어낸 내용."""
    entries, pos = {}, 0
    while data[pos:pos + 4] == b"PK\x03\x04":
        method, size, name_len, extra_len = (struct.unpack_from("<H", data, pos + 8)[0],
                                             *struct.unpack_from("<I", data, pos + 18), *struct.unpack_from("<HH", data, pos + 26))
        start = pos + 30 + name_len + extra_len
        raw = data[start:start + size]
        entries[data[pos + 30:pos + 30 + name_len].decode("utf-8", "replace")] = (
            zlib.decompressobj(-15).decompress(raw) if method == 8 else raw)
        pos = start + size
    return entries


def zip_read(name):
    return lambda data: zipfile.ZipFile(io.BytesIO(data)).read(name).decode("utf-8")


def stream_read(name):
    return lambda data: streamed_entries(data)[name].decode("utf-8")


def pdf_read(data):
    import logging

    import pypdf

    logging.getLogger("pypdf").setLevel(logging.ERROR)            # 'invalid pdf header' 경고(의도한 입력)
    return "".join(page.extract_text() or "" for page in pypdf.PdfReader(io.BytesIO(data)).pages)


HIDDEN = {   # 이름: (바이트, 올리는 이름, 우리 분류 kind, 받는 쪽 리더)
    "hwp + docx": (CLEAN_HWP + PII_DOCX, "a.docx", "hwp", zip_read("word/document.xml")),
    "hwp + hwpx": (CLEAN_HWP + PII_HWPX, "a.hwpx", "hwp", zip_read("Contents/section0.xml")),
    "hwp + pdf": (after(CLEAN_HWP, PII_PDF), "a.pdf", "hwp", pdf_read),
    # 머리(%PDF-)를 지운 PDF: 표지로는 못 잡지만 pypdf·PyMuPDF는 읽는다 → 파일이 마지막 할당 섹터에서 끝나야 함
    "hwp + headerless pdf": (after(CLEAN_HWP, PII_PDF).replace(b"%PDF-1.4", b"%XYZ-1.4"), "a.pdf", "hwp", pdf_read),
    "hwp + sector-padded text": (CLEAN_HWP + f"주민등록번호 {RRN}".encode().ljust(512, b" "), "a.hwp", "hwp", None),
    "hwp bindata docx": (make_hwp(CLEAN_LINES, CLEAN_ROWS, extra={"BinData/BIN0001.png": PII_DOCX}), "a.docx", "hwp",
                         zip_read("word/document.xml")),
    "hwpx + pdf": (after(CLEAN_HWPX, PII_PDF), "a.pdf", "hwpx", pdf_read),
    "hwpx stored pdf entry": (hwpx_rewritten(stored={"BinData/image1.png": PII_PDF}), "a.pdf", "hwpx", None),
    "docx + hwpx": (PII_DOCX + PLAIN_HWPX, "a.docx", "hwpx", stream_read("word/document.xml")),
    "hwpx gap": (hwpx_with_gap(PII_DOCX), "a.docx", "hwpx", stream_read("word/document.xml")),
    "hwpx renamed local header": (
        hwpx_with_renamed_local_header(zipfile.ZipFile(io.BytesIO(PII_DOCX)).read("word/document.xml")),
        "a.docx", "hwpx", stream_read("word/document.xml")),
    "hwpx comment": (hwpx_rewritten(comment=f"주민등록번호 {RRN}".encode()), "a.hwpx", "hwpx",
                     lambda data: zipfile.ZipFile(io.BytesIO(data)).comment.decode("utf-8")),
}
# HWPX 표지(mimetype·content.hpf)와 DOCX·XLSX 부품이 한 패키지에(10/11 검토 지적 3): DOCX 리더는 깨끗한 부품, HWPX 섹션에 개인정보
MIXED = {
    "hwpx + docx parts": zip_parts(PII_HWPX, docx_bytes("평범한 메모(가짜)")),
    "hwpx + xlsx parts": zip_parts(PII_HWPX, xlsx_bytes([("A1", "평범한 표(가짜)")])),
    "hpf-only hwpx + docx parts": zip_parts(make_hwpx(["가짜 인사", f"주민등록번호 {RRN}"], mimetype=None),
                                            docx_bytes("평범한 메모(가짜)")),
}


# ------------------------------------------------------------------ 1. 분류

class ClassifyTests(unittest.TestCase):
    def test_clean_hwp_text_is_hwpdoc_lines(self):
        result = classify(CLEAN_HWP)
        self.assertEqual((result.kind, result.group, result.detail), ("hwp", None, "hwp"))
        doc = hwpdoc.read(CLEAN_HWP, max_decompressed=MAX_BYTES)
        self.assertEqual(result.text, "\n".join(doc.lines()))
        self.assertEqual(result.text.split("\n")[:4],
                         ["주간 회의록 (가짜)", "안건 | 분기 일정 검토", "담당 | 기획팀", "다음 회의는 목요일 오후 2시입니다."])
        # 부가 글자(개체 설명문·요약 정보)도 검사 글자에 들어가고, 등록 글자(본문)는 그 앞부분
        self.assertTrue(result.text.startswith("\n".join(doc.body_lines()) + "\n"))
        for side in ("표입니다.", "주간 회의록", "가짜 작성자"):
            self.assertIn(side, result.text.split("\n")[4:])

    def test_clean_hwpx_and_hwpx_without_mimetype(self):
        result = classify(CLEAN_HWPX)
        self.assertEqual((result.kind, result.group), ("hwpx", None))
        # 본문 뒤에 content.hpf 메타데이터(언어·작성자)가 부가 글자로
        self.assertEqual(result.text, "\n".join(CLEAN_LINES + ["ko", "가짜 작성자"]))
        no_mimetype = make_hwpx(CLEAN_LINES, mimetype=None)
        self.assertEqual(hwpdoc.sniff(no_mimetype), "hwpx")
        self.assertEqual((classify(no_mimetype).kind, classify(no_mimetype).group), ("hwpx", None))

    def test_hwp_and_hwpx_of_the_same_body_send_the_same_body_lines(self):
        hwp = classify(make_hwp(CLEAN_LINES, prvtext=""))
        hwpx = classify(make_hwpx(CLEAN_LINES))
        self.assertEqual(hwp.text.split("\n")[:2], hwpx.text.split("\n")[:2])

    def test_pii_values_reach_the_text(self):
        for data in (PII_HWP, PII_HWPX):
            result = classify(data)
            self.assertIsNone(result.group)
            self.assertIn(RRN, result.text)
        self.assertIn(f"주민등록번호 | {RRN}", classify(PII_HWP).text.split("\n"))

    def test_side_text_pii_is_inspected(self):
        cases = {
            "summary": make_hwp(["본문(가짜)"], summary={2: f"제목 {RRN}"}),
            "equation": make_hwp(["본문(가짜)"], children=(S.equation(1, f"rm {RRN}"),)),
            "hyperlink": make_hwp(["본문(가짜)"], children=(S.field(1, "%hlk", "mailto:hong.gildong@example.test;1;0;0;"),)),
            "hwpx meta": make_hwpx(["본문(가짜)"], meta={"creator": f"작성자 {RRN}"}),
        }
        for name, data in cases.items():
            result = classify(data)
            self.assertIsNone(result.group, name)
            self.assertTrue(RRN in result.text or "hong.gildong@example.test" in result.text, name)

    def test_uninspectable_hwp_and_hwpx_are_other_with_reason(self):
        cases = {
            "distribution": (DIST_HWP, "hwp", "hwp_distribution"),
            "password": (PASSWORD_HWP, "hwp", "hwp_encrypted"),
            "drm": (make_hwp(["DRM(가짜)"], flags=1 | 16), "hwp", "hwp_drm"),
            "history": (make_hwp(["이력(가짜)"], extra={"DocHistory/VersionLog0": b"x" * 10}), "hwp", "hwp_history"),
            "ctrl_data": (CLOSED_HWP, "hwp", "hwp_unsupported_object"),
            "ole bindata": (OLE_BINDATA_HWP, "hwp", "hwp_unsupported_object"),
            "picture only": (PICTURE_ONLY_HWP, "hwp", "hwp_media_only"),
            "truncated deflate": (S.build_hwp([S.p(0, "가짜 본문")], compress_raw=lambda b: S.deflate(b)[:-4]),
                                  "hwp", "hwp_corrupt"),
            "declared size > file": (S.set_stream_size(make_hwp(["가짜 본문"], prvtext=""), "Section0", 1 << 30),
                                     "hwp", "hwp_corrupt"),
            "declared size > stream": (S.set_stream_size(make_hwp(["가짜 본문"], prvtext=""), "Section0", 5000),
                                       "hwp", "hwp_corrupt"),
            "hwpx ole": (CLOSED_HWPX, "hwpx", "hwpx_unsupported_object"),
            "hwpx unknown text": (UNKNOWN_TEXT_HWPX, "hwpx", "hwpx_unknown_text"),
            "hwpx encrypted": (ENCRYPTED_HWPX, "hwpx", "hwpx_encrypted"),
            "hwpx corrupt": (CORRUPT_HWPX, "hwpx", "hwpx_corrupt"),
            "hwpx empty": (S.build_hwpx([""]), "hwpx", "empty"),
            "hwpx external entity": (S.build_hwpx([], extra={"Contents/section0.xml": (
                '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
                f'<hs:sec {S.NSDECL}><hp:p><hp:run><hp:t>&e;</hp:t></hp:run></hp:p></hs:sec>')}), "hwpx", "hwpx_corrupt"),
        }
        for name, (data, kind, detail) in cases.items():
            result = classify(data)
            self.assertEqual((result.kind, result.group, result.detail), (kind, "other", detail), name)
            self.assertIsNone(result.text, name)

    def test_non_hwp_cfb_stays_cfb(self):
        doc_like = S.write_cfb({"WordDocument": b"\x00" * 600, "1Table": b"\x00" * 600})   # Word 97 비슷(FileHeader 없음)
        encrypted_ooxml = S.write_cfb({"EncryptionInfo": b"\x00" * 300, "EncryptedPackage": b"\x00" * 5000})
        for name, data in (("fake cfb", CFB), ("doc", doc_like), ("encrypted ooxml", encrypted_ooxml),
                           ("cfb header only", S.CFB_MAGIC + b"\xff" * 2000)):
            self.assertEqual((classify(data).kind, classify(data).group, classify(data).detail), ("cfb", "other", "cfb"),
                             name)

    def test_cfb_kind_follows_the_fileheader_name_and_olefile_opens_at_most_once(self):
        # 10/11 검토 지적 2: 'FileHeader' 스트림 이름(UTF-16, 대소문자 무시 - olefile과 같음)이 없는 CFB는 olefile을 부르지
        # 않고 cfb. 이름이 있으면 kind는 hwp이고, read가 깨짐을 내도 sniff로 다시 열지 않는다(hwp_corrupt)
        doc_like = S.write_cfb({"WordDocument": b"\x00" * 600, "1Table": b"\x00" * 600})
        truncated = S.build_hwp([S.p(0, "가짜 본문")], compress_raw=lambda b: S.deflate(b)[:-4])
        short_header = S.write_cfb({"FileHeader": b"HWP Document File".ljust(36, b"\x00"), "BodyText/Section0": b"x"})
        wrong_signature = S.write_cfb({"FileHeader": b"NOT AN HWP FILE".ljust(40, b"\x00"), "BodyText/Section0": b"x"})
        empty_header = S.write_cfb({"WordDocument": b"\x00" * 600, "FileHeader": b""})
        for data in (CLEAN_HWP, PII_HWP, DIST_HWP, CLOSED_HWP, BOMB_HWP, PICTURE_ONLY_HWP, truncated, short_header,
                     wrong_signature, empty_header):
            self.assertEqual(classify(data).kind, "hwp")
        for data in (doc_like, CFB, S.CFB_MAGIC + b"\xff" * 2000):
            self.assertEqual((classify(data).kind, classify(data).group, classify(data).detail), ("cfb", "other", "cfb"))
        self.assertIsNone(hwpdoc.sniff(wrong_signature))
        bad_sector_shift = wrong_signature[:0x1E] + b"\x0a\x00" + wrong_signature[0x20:]   # 섹터 크기 1024(MS-CFB 밖)
        for data in (short_header, wrong_signature, empty_header, bad_sector_shift):
            self.assertEqual((classify(data).kind, classify(data).group, classify(data).detail),
                             ("hwp", "other", "hwp_corrupt"))
        for data, opens in ((CLEAN_HWP, 1), (doc_like, 0), (CFB, 0), (wrong_signature, 1), (empty_header, 1)):
            with mock.patch.object(hwpdoc, "_ole_open", wraps=hwpdoc._ole_open) as opened:
                classify(data)
            self.assertEqual(opened.call_count, opens)

    def test_fileheader_name_is_matched_without_case_like_olefile(self):
        upper = CLEAN_HWP.replace("FileHeader".encode("utf-16-le"), "FILEHEADER".encode("utf-16-le"))
        self.assertNotEqual(upper, CLEAN_HWP)
        self.assertEqual(hwpdoc.sniff(upper), "hwp")                  # olefile은 스트림 이름 대소문자를 가리지 않는다
        with mock.patch.object(hwpdoc, "_ole_open", wraps=hwpdoc._ole_open) as opened:
            result = classify(upper)
        self.assertEqual(opened.call_count, 1)                        # 미리 거르지 않고 hwpdoc이 판단(닫힌 목록 밖 스트림 이름)
        self.assertEqual((result.kind, result.group, result.detail), ("hwp", "other", "hwp_unsupported_object"))

    def test_non_hwp_cfb_is_decided_without_olefile(self):
        # 운영 venv에 olefile이 없을 때(10/11)도 DOC·XLS·암호 OOXML은 기준판과 같은 cfb이고 경고도 남기지 않는다
        gateway_file_classes._HWP_IMPORT_WARNED.clear()
        self.addCleanup(gateway_file_classes._HWP_IMPORT_WARNED.clear)
        doc_like = S.write_cfb({"WordDocument": b"\x00" * 600, "1Table": b"\x00" * 600})
        encrypted_ooxml = S.write_cfb({"EncryptionInfo": b"\x00" * 300, "EncryptedPackage": b"\x00" * 5000})
        out = io.StringIO()
        with mock.patch.dict(sys.modules, {"olefile": None}), contextlib.redirect_stdout(out), \
                mock.patch.object(hwpdoc, "_ole_open", side_effect=AssertionError("olefile used")):
            results = [classify(data) for data in (doc_like, encrypted_ooxml, CFB, doc_like + PII_DOCX)]
        self.assertEqual([(r.kind, r.group, r.detail) for r in results], [("cfb", "other", "cfb")] * 4)
        self.assertEqual(out.getvalue(), "")

    def test_hidden_bytes_other_readers_see_make_hwp_and_hwpx_other(self):
        # 10/11 검토 지적 1: 기준판은 모두 cfb·hwpx other(기본 차단)였다. 우리가 읽는 HWP·HWPX는 깨끗하다
        for name, (data, _, kind, reader) in HIDDEN.items():
            with self.subTest(name):
                if reader is not None:
                    self.assertIn(RRN, reader(data))                    # 받는 쪽 리더는 개인정보를 읽는다
                result = classify(data)
                self.assertEqual((result.kind, result.group, result.detail),
                                 (kind, "other", f"{kind}_embedded_container"))
                self.assertIsNone(result.text)

    def test_mixed_hwpx_and_docx_or_xlsx_packages_are_other(self):
        for name, data in MIXED.items():
            with self.subTest(name):
                self.assertEqual(hwpdoc.sniff(data), "hwpx")
                result = classify(data)
                self.assertEqual((result.kind, result.group, result.detail), ("zip", "other", "ambiguous_package"))
        # 한 형식만 든 패키지는 그대로
        self.assertEqual(classify(docx_bytes("plain agenda")).kind, "docx")
        self.assertEqual(classify(xlsx_bytes([("A1", "plain")])).kind, "xlsx")
        self.assertEqual((classify(PII_HWPX).kind, classify(PII_HWPX).group), ("hwpx", None))
        self.assertEqual((classify(make_hwpx(CLEAN_LINES, mimetype=None)).kind,
                          classify(make_hwpx(CLEAN_LINES, mimetype=None)).group), ("hwpx", None))

    def test_package_layout_rule_accepts_ordinary_zip_writers(self):
        # 중앙 디렉터리가 가리키는 항목이 파일을 빈틈없이 채운 HWPX(zipfile 저장 방식 둘·항목 수십 개)는 그대로 검사
        many = make_hwpx(CLEAN_LINES, extra={f"BinData/image{i}.png": png_bytes() for i in range(40)})
        stored = hwpx_rewritten(stored={"BinData/image9.png": png_bytes()})
        for data in (CLEAN_HWPX, many, stored, make_hwpx(CLEAN_LINES, mimetype=None)):
            self.assertEqual((classify(data).kind, classify(data).group), ("hwpx", None))
        infos = zipfile.ZipFile(io.BytesIO(many)).infolist()
        self.assertTrue(gateway_file_classes._zip_layout_exact(many, infos, deadline=1.0, clock=lambda: 0.0))
        with self.assertRaises(gateway_file_classes._Limit):            # 항목을 훑는 동안에도 시간 한도를 본다
            gateway_file_classes._zip_layout_exact(many, infos, deadline=0.0, clock=lambda: 1.0)

    def test_bombs_are_too_large(self):
        self.assertLess(len(BOMB_HWPX), 200_000)
        self.assertEqual(classify(BOMB_HWPX).group, "too_large")
        result = classify(BOMB_HWP)
        self.assertLess(len(BOMB_HWP), 200_000)
        self.assertEqual((result.kind, result.group, result.detail), ("hwp", "too_large", "hwp_decompressed"))
        # 선언 크기 합은 상한 안이지만 XML 요소 수가 예산(바이트/16)을 넘는 HWPX
        many = S.build_hwpx([S.hp_p(S.hp_t("가")) + "<hp:p/>" * 20_000])
        result = classify(many, max_bytes=256 * 1024)
        self.assertEqual((result.kind, result.group, result.detail), ("hwpx", "too_large", "hwpx_decompressed"))

    def test_time_and_char_limits(self):
        ticks = iter(range(10_000))
        result = classify(CLEAN_HWP, seconds=5, clock=lambda: next(ticks) * 1.0)   # 부를 때마다 1초씩
        self.assertEqual((result.group, result.detail), ("too_large", "time"))
        self.assertIn(result.kind, ("hwp", "unknown"))
        result = classify(make_hwp(["가" * 200], prvtext=""), max_chars=100)
        self.assertEqual((result.kind, result.group, result.detail), ("hwp", "too_large", "chars"))

    def test_preview_rule_catches_a_line_whose_characters_are_scattered_in_the_body(self):
        body = ["생년 900101 기록(가짜)", "번호 1234567 보관"]
        # 미리보기 글자 전체는 본문의 부분열(명세 규칙 ①만으로는 통과)이지만 이어진 줄은 본문에 없다
        data = make_hwp(body, prvtext=f"생년 {RRN}\r\n")
        # 2026-10-14: 불일치는 막지 않고 미리보기 글자를 검사 글자 끝에 붙인다(이전: other, hwp_preview_mismatch)
        result = classify(data)
        self.assertEqual((result.group, result.detail), (None, "hwp_preview_extra"))
        self.assertEqual(result.text.split("\n")[-1], f"생년 {RRN}")
        # 한컴처럼 본문 앞부분을 잘라 담은 미리보기는 통과
        self.assertIsNone(classify(make_hwp(body, prvtext="생년 900101 기록(가짜)\r\n번호 12")).group)
        self.assertIsNone(classify(make_hwpx(body, prvtext="")).group)
        result = classify(make_hwpx(body, prvtext=f"생년 {RRN}"))
        self.assertEqual((result.group, result.detail), (None, "hwpx_preview_extra"))
        self.assertTrue(result.text.endswith(f"\n생년 {RRN}"))

    def test_preview_is_compared_in_record_order(self):
        # 칸 안 중첩 표: lines()는 중첩 표를 행 뒤로 옮기지만 한컴 미리보기는 레코드 순서(성명 → 중첩A·B → 김가짜)
        nested = S.para(2, S.ext_ctrl(11, "tbl "), S.table(3, [(0, 0, 1, 1, [S.p(4, "중첩A")]),
                                                              (0, 1, 1, 1, [S.p(4, "중첩B")])], 1, 2))
        sec = S.para(0, S.ext_ctrl(11, "tbl "), S.table(1, [(0, 0, 1, 1, [S.p(2, "성명"), nested]),
                                                          (0, 1, 1, 1, [S.p(2, "김가짜")])], 1, 2))
        data = S.build_hwp([sec], prvtext="<성명><중첩A><중첩B><김가짜>\r\n")
        result = classify(data)
        self.assertEqual((result.group, result.text.split("\n")), (None, ["성명 | 김가짜", "중첩A | 중첩B"]))
        # 명세 규칙 ①(부분열): 줄마다는 본문에 있어도 순서가 본문과 다르면 불일치
        data = make_hwp(["첫째 문단(가짜)", "둘째 문단(가짜)"], prvtext="둘째 문단(가짜)\r\n첫째 문단(가짜)\r\n")
        self.assertEqual(classify(data).detail, "hwp_preview_extra")

    def test_preview_check_is_bounded_by_the_time_limit(self):
        # 서로 다른 조각이 많은 조작 미리보기: 조각마다 시계를 본다(같은 조각은 한 번만 찾음)
        digits = "0123456789" * 2000
        pieces = sorted({digits[i:i + k] for i in range(10) for k in range(1, 11)})
        preview = "\r\n".join(pieces * 3)
        calls = []

        def tick():
            calls.append(1)
            if len(calls) > 50:
                raise gateway_file_classes._Limit("hwp", "time")
        with self.assertRaises(gateway_file_classes._Limit):
            gateway_file_classes._preview_mismatch(preview, digits, tick)
        calls.clear()
        self.assertFalse(gateway_file_classes._preview_mismatch(preview, digits, lambda: calls.append(1)))
        self.assertEqual(len(calls), len(pieces))
        # 본문보다 긴 미리보기는 조각을 보기 전에 불일치
        self.assertTrue(gateway_file_classes._preview_mismatch("가" * 50, "가" * 49, lambda: self.fail("tick")))
        # 시계가 넘으면 분류 결과는 시간 초과(too_large)
        ticks = {"n": 0}

        def clock():
            ticks["n"] += 1
            return 0.0 if ticks["n"] < 12 else 10.0
        result = classify(make_hwp([digits], prvtext=preview), seconds=5, clock=clock)
        self.assertEqual((result.group, result.detail), ("too_large", "time"))

    def test_logs_and_details_carry_no_document_text(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            results = [classify(data) for data in (PII_HWP, STALE_PREVIEW_HWP, CLOSED_HWP, UNKNOWN_TEXT_HWPX)]
        for result in results:
            for value in (RRN, "900101", "김가짜", "숨은 글자", "unknownThing"):
                self.assertNotIn(value, result.detail)
        self.assertEqual(out.getvalue(), "")


class MissingDependencyTests(unittest.TestCase):
    def setUp(self):
        gateway_file_classes._HWP_IMPORT_WARNED.clear()
        self.addCleanup(gateway_file_classes._HWP_IMPORT_WARNED.clear)

    def test_without_olefile_hwp_is_other_and_hwpx_still_inspected(self):
        out = io.StringIO()
        with mock.patch.dict(sys.modules, {"olefile": None}), contextlib.redirect_stdout(out):
            hwp = [classify(CLEAN_HWP), classify(PII_HWP)]
            hwpx = classify(CLEAN_HWPX)
            pdf_like = classify(b"plain memo")
        self.assertEqual([(r.kind, r.group, r.detail) for r in hwp], [("cfb", "other", "error:ImportError")] * 2)
        self.assertEqual((hwpx.kind, hwpx.group), ("hwpx", None))
        self.assertEqual(pdf_like.group, None)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines, ["[FILE] HWP/HWPX inspection unavailable (missing module: olefile); treated as other"])

    def test_without_hwpdoc_both_formats_are_other(self):
        import signature_detector.document as package

        saved = package.__dict__.pop("hwpdoc")         # from … import hwpdoc는 패키지 속성을 먼저 본다
        self.addCleanup(setattr, package, "hwpdoc", saved)
        with mock.patch.dict(sys.modules, {"signature_detector.document.hwpdoc": None}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual((classify(CLEAN_HWP).kind, classify(CLEAN_HWP).detail), ("cfb", "error:ImportError"))
            self.assertEqual((classify(CLEAN_HWPX).kind, classify(CLEAN_HWPX).group), ("hwpx", "other"))


# ------------------------------------------------------------------ 2. 실제 flow

PATHS = ("chatgpt_put", "chatgpt_multipart", "claude")


class HwpFlowTests(Base):
    """request()·response() 훅. 기대 = (응답 상태, reason_code, Detection 호출 수, 이벤트)."""

    def setUp(self):
        super().setUp()
        self.use_settings()          # 기본값: 파일 처리 차단 2초, 그 밖 형식 차단, 이미지 허용

    def send(self, path, data, filename):
        if path == "chatgpt_put":
            return self.chatgpt_put(data, filename)
        if path == "chatgpt_multipart":
            return self.chatgpt_multipart(data, filename)
        return self.claude_upload((filename, "application/x-hwp", data))

    def check(self, data, filename, *, status, reason, calls):
        for path in PATHS:
            with self.subTest(path=path, filename=filename):
                self.calls.clear()
                self.reports.clear()
                flow = self.finish(self.send(path, data, filename))
                self.assertEqual(len(self.calls), calls)
                if status is None:
                    self.assertEqual(flow.response.status_code, 200)        # upstream 응답(전달됨)
                    self.assertEqual(flow.request.raw_content, self.sent)    # 원본 그대로
                    self.assertEqual(flow.metadata.get("gw_action"), "allow")
                    self.assertEqual(self.got(), [("allow", "file", False, reason)])
                else:
                    self.assertEqual(flow.response.status_code, status)
                    body = json.loads(flow.response.get_text())
                    self.assertEqual(body["error"]["reason_code"], reason)
                    self.assertEqual(self.got(), [("block", "file", True, reason)])
                    self.assertEqual(self.reports[0].http_status, status)
                llm = "Claude" if path == "claude" else "ChatGPT"
                self.assertEqual(self.reports[0].context["targetLlm"], llm)
                if calls:
                    sent_text = self.calls[0]["text"]
                    self.assertEqual(sent_text, classify(data).text.strip())
                    self.assertEqual(self.calls[0]["source"]["content_type"], "file")
                    self.assertEqual(self.calls[0]["timeout"], 2.0)
                yield flow

    def run_case(self, *args, **kwargs):
        return list(self.check(*args, **kwargs))

    def test_clean_hwp_and_hwpx_are_forwarded_unchanged(self):
        # 3단계: 파일 전체 1회 + 칸 검사(DOCX·XLSX와 같음), 바꾼 칸 없음 → 원본 그대로
        self.run_case(CLEAN_HWP, "회의록.hwp", status=None, reason="none", calls=1 + cell_count(CLEAN_HWP))
        self.run_case(CLEAN_HWPX, "회의록.hwpx", status=None, reason="none", calls=1 + cell_count(CLEAN_HWPX))
        self.run_case(CLEAN_HWP, "renamed.bin", status=None, reason="none",           # 형식은 바이트로
                      calls=1 + cell_count(CLEAN_HWP))

    def test_pii_hwp_and_hwpx_are_refused_when_the_recheck_is_not_ok(self):
        # 3단계: 칸 가림까지 되지만 이 가짜 Detection은 signature_status를 주지 않는다 → 재검사 실패 = 403 + 이벤트
        # (원본·가린 파일 모두 나가지 않음). 재검사 통과·가린 파일 전달은 tests/test_gateway_hwp_mask.py
        for flow in self.run_case(PII_HWP, "인사.hwp", status=403, reason="mask_application_failed",
                                  calls=1 + cell_count(PII_HWP) + 1):
            self.assertEqual(flow.metadata["gw_action"], "block")
            self.assertIn(RRN, self.calls[0]["text"])
            self.assertTrue(self.calls[-1]["request_id"].endswith("#verify"))
            self.assertNotIn(RRN, self.calls[-1]["text"])
        self.run_case(PII_HWPX, "인사.hwpx", status=403, reason="mask_application_failed",
                      calls=1 + cell_count(PII_HWPX) + 1)

    def test_protected_document_hwp_is_blocked(self):
        self.run_case(SECRET_HWP, "계획.hwp", status=403, reason="doc_excerpt", calls=1)

    def test_uninspectable_hwp_and_hwpx_are_blocked_before_detection(self):
        for data in (DIST_HWP, PASSWORD_HWP, CLOSED_HWP, OLE_BINDATA_HWP, PICTURE_ONLY_HWP,
                     CORRUPT_HWPX, CLOSED_HWPX, UNKNOWN_TEXT_HWPX, ENCRYPTED_HWPX):
            self.run_case(data, "a.hwp", status=403, reason="file_uninspectable_other", calls=0)

    def test_hidden_bytes_and_mixed_packages_are_blocked_before_detection(self):
        # 10/11 검토 지적 1·3: 바꾸기 전에는 hwp/hwpx/docx 검사 가능으로 200·원본 그대로·Detection 1~2회(개인정보 없는 글자)
        for name, (data, filename, _, _) in HIDDEN.items():
            with self.subTest(name):
                self.run_case(data, filename, status=403, reason="file_uninspectable_other", calls=0)
        for name, data in MIXED.items():
            with self.subTest(name):
                self.run_case(data, "a.hwpx", status=403, reason="file_uninspectable_other", calls=0)
                self.run_case(data, "a.docx", status=403, reason="file_uninspectable_other", calls=0)

    def test_bombs_follow_the_too_large_rule(self):
        self.run_case(BOMB_HWPX, "bomb.hwpx", status=403, reason="file_too_large", calls=0)
        self.run_case(BOMB_HWP, "bomb.hwp", status=403, reason="file_too_large", calls=0)

    def test_other_allowed_setting_forwards_uninspectable_hwp_with_a_record(self):
        self.use_settings(other="allow")
        self.run_case(DIST_HWP, "a.hwp", status=None, reason="file_uninspectable_other", calls=0)

    def test_claude_docx_with_pii_and_a_clean_hwp_masks_the_docx_and_keeps_the_hwp(self):
        # 3단계: HWP도 칸 가림 대상 - DOCX는 가리고, 바꿀 칸이 없는 HWP는 원본 그대로(재검사 없음)
        flow = self.finish(self.claude_upload(("a.docx", DOCX, docx_bytes(f"주민번호 {RRN}")),
                                              ("b.hwp", "application/x-hwp", CLEAN_HWP)))
        self.assertEqual(flow.response.status_code, 200)
        files = gateway.extract_claude_file_upload_info(flow)
        self.assertNotIn(RRN, "\n".join(p.text for p in bundle.Document(io.BytesIO(files[0]["file_bytes"])).paragraphs))
        self.assertEqual(files[1]["file_bytes"], CLEAN_HWP)
        self.assertEqual(self.got(), [("mask_full", "file", True, "pii")])
        self.assertFalse(any("#verify" in call["request_id"] for call in self.calls))

    def test_claude_clean_docx_and_clean_hwp_pass_with_one_whole_file_call(self):
        flow = self.finish(self.claude_upload(("a.docx", DOCX, docx_bytes("plain agenda")),
                                              ("b.hwp", "application/x-hwp", CLEAN_HWP)))
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.request.raw_content, self.sent)
        self.assertIn("주간 회의록 (가짜)", self.calls[0]["text"])        # 파일 전체 1회: 두 파일 글자
        self.assertIn("plain agenda", self.calls[0]["text"])
        # 나머지는 칸 검사: DOCX(파일 0)와 HWP(파일 1, 3단계). HWP 본문 칸은 block_order를 싣는다
        self.assertTrue(self.calls[1:])
        self.assertTrue(all("#file:0#f:0:docx:" in call["request_id"] or "#file:1#f:0:hwp:" in call["request_id"]
                            for call in self.calls[1:]))
        hwp_calls = [call for call in self.calls if "#file:1#f:0:hwp:" in call["request_id"]]
        self.assertEqual(len(hwp_calls), cell_count(CLEAN_HWP))
        self.assertTrue(all(isinstance(call["source"].get("block_order"), int)
                            for call in hwp_calls if ":hwp:side:" not in call["request_id"]))

    def test_claude_protected_hwp_next_to_an_uninspectable_hwp(self):
        flow = self.finish(self.claude_upload(("a.hwp", "application/x-hwp", DIST_HWP),
                                              ("b.hwp", "application/x-hwp", SECRET_HWP)))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.got(), [("block", "file", True, "file_uninspectable_other")])
        self.assertEqual(self.calls, [])

    def test_detection_timeout_on_hwp_follows_the_file_rule(self):
        gateway.check_detection = lambda *a, **k: bundle.failure_result("TIMEOUT", k["failure_policy"], k["request_id"])
        flow = self.finish(self.chatgpt_put(CLEAN_HWP, "a.hwp"))
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(self.got(), [("block", "file", True, "detection_timeout")])


class HwpRetryRecordTests(DedupeBase):
    """같은 업로드 재시도: 시도마다 막고 대시보드 이벤트·확장 알림은 한 번(실제 report_dashboard_event·mapper)."""

    def test_chatgpt_put_retries_of_hwp_files_record_once(self):
        cases = [(FILE_ID, PII_HWP, "인사.hwp", "mask_application_failed"),
                 (FILE_ID_2, DIST_HWP, "배포.hwp", "file_uninspectable_other"),
                 ("00000000-aaaa-8206-bbbb-000000000003", PII_HWPX, "인사.hwpx", "mask_application_failed")]
        for file_id, content, filename, reason in cases:
            for _ in range(3):
                flow = self.attempt(lambda: self.put(content, file_id, filename))
                self.assertFalse(flow.metadata["test_forwarded"])
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(json.loads(flow.response.get_text())["error"]["reason_code"], reason)
        self.assertEqual([(e["finalAction"], e["reasonCode"], e["fileId"], e["contentType"]) for e in self.queued],
                         [("BLOCK", reason, gateway.canonical_file_ref(file_id), "file") for file_id, _, _, reason in cases])
        self.assertEqual(len(self.extension), 3)
        self.assertEqual([line.rsplit("suppressed=", 1)[1] for line in self.dedupe_lines()], ["1", "2"] * 3)
        for value in (RRN, "김가짜", "인사.hwp", "배포.hwp"):
            self.assertNotIn(value, "\n".join(self.dedupe_lines()))

    def test_claude_multipart_retries_record_once_and_clean_hwp_records_nothing(self):
        for index in range(3):
            flow = self.attempt(lambda: self.claude_retry("인사.hwp", "application/x-hwp", PII_HWP, index))
            self.assertEqual(flow.response.status_code, 403)
        for index in range(3):
            flow = self.attempt(lambda: self.claude_retry("회의록.hwp", "application/x-hwp", CLEAN_HWP, 10 + index))
            self.assertTrue(flow.metadata["test_forwarded"])
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued],
                         [("BLOCK", "mask_application_failed")])
        self.assertEqual(len(self.extension), 1)

    def test_chatgpt_multipart_retries_use_bytes_and_name(self):
        self.attempt(lambda: self.chatgpt_multipart(SECRET_HWP, "a.hwp"))
        self.attempt(lambda: self.chatgpt_multipart(SECRET_HWP, "a.hwp"))
        self.attempt(lambda: self.chatgpt_multipart(SECRET_HWP, "b.hwp"))
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued], [("BLOCK", "doc_excerpt")] * 2)


# ------------------------------------------------------------------ 3. 실제 DumpMaster

class HwpProxyEndToEndTests(unittest.TestCase):
    """실제 mitmproxy(DumpMaster)에 gateway를 올리고 로컬 upstream이 받은 본문을 본다."""

    def test_clean_hwp_reaches_upstream_byte_identical_and_pii_hwp_never_does(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        received = []

        class Upstream(BaseHTTPRequestHandler):
            def _take(self):
                received.append((self.command, self.path, self.rfile.read(int(self.headers.get("content-length") or 0))))
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_PUT = do_POST = _take

            def log_message(self, *args):
                pass
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)

        class Redirect:
            def request(self, flow):
                flow.request.host, flow.request.port, flow.request.scheme = "127.0.0.1", upstream.server_address[1], "http"

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        state = {}

        async def run_master():
            master = DumpMaster(options.Options(listen_host="127.0.0.1", listen_port=port),
                                with_termlog=False, with_dumper=False)
            master.addons.add(gateway, Redirect())
            state["master"] = master
            await master.run()

        boundary = "----gwhwpe2e"

        def claude_body(data):
            return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.hwp\"\r\n"
                    f"Content-Type: application/x-hwp\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()

        sends = [("PUT", f"http://sdmntprkoreacentral.oaiusercontent.com/files/{FILE_ID}/raw?se=2026-10-11", CLEAN_HWP,
                  "application/octet-stream", 200),
                 ("PUT", f"http://sdmntprkoreacentral.oaiusercontent.com/files/{FILE_ID_2}/raw?se=2026-10-11", PII_HWP,
                  "application/octet-stream", 403),
                 ("POST", f"http://claude.ai{CLAUDE_UPLOAD_PATH}", claude_body(CLEAN_HWPX),
                  f"multipart/form-data; boundary={boundary}", 200),
                 ("POST", f"http://claude.ai{CLAUDE_UPLOAD_PATH}", claude_body(PII_HWPX),
                  f"multipart/form-data; boundary={boundary}", 403)]
        calls, statuses, out = [], [], io.StringIO()
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=lambda: loop.run_until_complete(run_master()), daemon=True)
        with mock.patch.object(gateway, "check_detection", fake_detection(calls)), \
                mock.patch.object(gateway, "send_to_next_module", lambda event: None), \
                mock.patch.object(gateway, "report_dashboard_event", lambda *a, **k: None), \
                mock.patch.object(gateway, "GATEWAY_SETTINGS", bundle.FixedSettings()), \
                contextlib.redirect_stdout(out):
            gateway.CHATGPT_FILE_META.clear()
            getattr(gateway, "_dedupe_seen", {}).clear()
            thread.start()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
                time.sleep(0.1)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
            for method, url, body, ctype, _ in sends:
                request = urllib.request.Request(url, method=method, data=body, headers={"content-type": ctype})
                try:
                    with opener.open(request, timeout=15) as response:
                        statuses.append(response.status)
                except urllib.error.HTTPError as exc:
                    statuses.append(exc.code)
                    exc.close()
            time.sleep(0.2)
            loop.call_soon_threadsafe(state["master"].shutdown)
            thread.join(10)
        self.assertEqual(statuses, [expected for *_, expected in sends])
        self.assertEqual([(method, body) for method, _, body in received],
                         [("PUT", CLEAN_HWP), ("POST", sends[2][2])])
        self.assertEqual(len([call for call in calls if "#" not in call["request_id"]]), 4)   # 파일 전체 검사
        for _, _, body in received:
            self.assertNotIn(RRN.encode("utf-16-le"), body)


# ------------------------------------------------------------------ 4. 배포 경계·등록 대조

class HwpDeployTests(bundle.DeployOrderTests):
    """olefile이 없는 운영 venv(10/11 확인)나 hwpdoc.py를 빠뜨린 배포에서도 애드온은 뜨고 HWP만 other."""

    CODE = ("import sys, time; {block}import gateway, gateway_file_classes as g; "
            "data = open(sys.argv[1], 'rb').read(); "
            "r = g.inspect_upload(data, max_bytes=1 << 24, max_chars=80000, deadline=time.monotonic() + 5); "
            "p = g.inspect_upload(b'plain memo', max_bytes=1 << 24, max_chars=80000, deadline=time.monotonic() + 5); "
            "print('RESULT', r.kind, r.group, r.detail, p.group, sys.modules.get('olefile') is not None)")

    def run_code(self, folder, block, data):
        path = folder / "sample.bin"
        path.write_bytes(data)
        env = {**os.environ, "DASHBOARD_OUTBOX_PATH": str(folder / "outbox.sqlite3"),
               "SIGNATURE_REVIEW_DIR": str(folder / "review"), "PYTHONIOENCODING": "utf-8"}
        for key in ("DASHBOARD_EVENT_URL", "DASHBOARD_INGEST_TOKEN", "GATEWAY_SETTINGS_CACHE_PATH"):
            env.pop(key, None)
        return subprocess.run([sys.executable, "-c", self.CODE.format(block=block), str(path)], cwd=folder, env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)

    def test_gateway_import_does_not_load_hwpdoc_or_olefile(self):
        result = self.import_gateway(self.staged(), code=(
            "import sys, gateway; print('LOADED', 'olefile' in sys.modules, "
            "'signature_detector.document.hwpdoc' in sys.modules)"))
        self.assertIn("LOADED False False", result.stdout, result.stderr[-2000:])

    def test_with_olefile(self):
        result = self.run_code(self.staged(), "", CLEAN_HWP)
        self.assertIn("RESULT hwp None hwp None True", result.stdout, result.stderr[-2000:])

    def test_without_olefile_the_addon_loads_and_hwp_is_other(self):
        result = self.run_code(self.staged(), "sys.modules['olefile'] = None; ", CLEAN_HWP)
        self.assertIn("RESULT cfb other error:ImportError None False", result.stdout, result.stderr[-2000:])
        self.assertIn("missing module: olefile", result.stdout)

    def test_without_the_hwpdoc_file_the_addon_loads_and_hwpx_is_other(self):
        folder = self.staged()
        (folder / "signature_detector" / "document" / "hwpdoc.py").unlink()
        result = self.run_code(folder, "", CLEAN_HWPX)
        self.assertIn("RESULT hwpx other error:ImportError None", result.stdout, result.stderr[-2000:])

    test_new_gateway_with_the_old_metrics_module_fails_to_import = None
    test_all_new_files_import = None
    test_environment_fallback_and_disk_cache_at_start = None


class OlefilePinTests(unittest.TestCase):
    def test_olefile_version_is_pinned_when_installed(self):
        """hwpdoc은 olefile 0.47의 내부 함수 셋을 선형 시간판으로 바꿔 쓴다(Detection test_olefile_version_is_pinned와 같음).
        운영 venv에는 배포 때 olefile==0.47을 설치한다. 설치 전이면 건너뜀(그동안 HWP는 other, MissingDependencyTests)."""
        try:
            import olefile
        except ImportError:
            self.skipTest("olefile not installed: HWP stays other until olefile==0.47 is installed")
        self.assertEqual(olefile.__version__, "0.47")


class DetectionParityTests(unittest.TestCase):
    """Detection과 같은 hwpdoc(md5)·등록 글자와 창 일치(명세 T1-2). Detection 작업 사본이 없으면 건너뜀."""

    def setUp(self):
        if not (DETECTION_DIR / "preprocessing" / "hwpdoc.py").is_file():
            self.skipTest("Detection work copy not available")

    def test_hwpdoc_is_byte_identical_to_the_detection_copy(self):
        ours = (ROOT / "signature_detector" / "document" / "hwpdoc.py").read_bytes()
        theirs = (DETECTION_DIR / "preprocessing" / "hwpdoc.py").read_bytes()
        self.assertEqual(hashlib.md5(ours).hexdigest(), hashlib.md5(theirs).hexdigest())
        self.assertNotIn(b"\r\n", ours)

    def test_inspected_text_windows_match_the_registration_index(self):
        script = (
            "import json, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from preprocessing.router import process_input\n"
            "from preprocessing.normalizer import normalize_text\n"
            "from windowhash.hashing import compact, window_hashes\n"
            "out = []\n"
            "for path, text_path in zip(sys.argv[2::2], sys.argv[3::2]):\n"
            "    reg = process_input(path)\n"
            "    gw = open(text_path, encoding='utf-8').read()\n"
            "    reg_codes = compact(reg.normalized_text).codes\n"
            "    gw_codes = compact(normalize_text(gw)).codes\n"
            "    reg_h = set(window_hashes(reg_codes))\n"
            "    gw_h = window_hashes(gw_codes)\n"
            "    out.append({'ok': reg.success, 'format': reg.format, 'prefix': gw_codes[:len(reg_codes)] == reg_codes,\n"
            "                'reg_windows': len(reg_h), 'reg_in_gw': len(reg_h & set(gw_h)),\n"
            "                'gw_windows_in_index': sum(h in reg_h for h in gw_h)})\n"
            "print('RESULT ' + json.dumps(out))\n")
        cases = [("a.hwp", CLEAN_HWP), ("b.hwpx", CLEAN_HWPX), ("c.hwp", PII_HWP), ("d.hwp", SECRET_HWP),
                 ("e.hwpx", make_hwpx(["가짜 사업 계획서 본문 첫 문단입니다. 이 문서는 시험용 합성 문서입니다.",
                                       "둘째 문단: 신규 서비스 출시 일정은 2026년 4분기입니다."]))]
        with tempfile.TemporaryDirectory(prefix="gw-hwp-parity-") as tmp:
            argv = []
            for name, data in cases:
                (Path(tmp) / name).write_bytes(data)
                (Path(tmp) / (name + ".txt")).write_text(classify(data).text, encoding="utf-8")
                argv += [str(Path(tmp) / name), str(Path(tmp) / (name + ".txt"))]
            result = subprocess.run([sys.executable, "-P", "-c", script, str(DETECTION_DIR), *argv], cwd=tmp,
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
                                    env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        line = next((x for x in result.stdout.splitlines() if x.startswith("RESULT ")), None)
        self.assertIsNotNone(line, result.stderr[-3000:])
        rows = json.loads(line[len("RESULT "):])
        for (name, _), row in zip(cases, rows):
            self.assertTrue(row["ok"], name)
            self.assertEqual(row["format"], name.rsplit(".", 1)[1], name)
            self.assertTrue(row["prefix"], name)                         # 등록 압축열 = 검사 압축열의 앞부분
            self.assertEqual(row["reg_in_gw"], row["reg_windows"], name)  # 등록 창이 모두 검사 글자에 있음
            if row["reg_windows"]:
                self.assertGreater(row["gw_windows_in_index"], 0, name)    # 창 해시가 차단할 근거가 있음


if __name__ == "__main__":
    unittest.main()
