"""Detection HWP·HWPX 등록 파서 시험 - 파서 계약, 형식 판별(경로·바이트), 예외 변환, 기동 경로 분리."""

from __future__ import annotations

import io
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import hwp_synth as S
from hwp_synth import hp_p, hp_t
from docstore import registry
from preprocessing import hwp_parser, hwpdoc
from preprocessing.format_detect import detect_format
from preprocessing.normalizer import normalize_text
from preprocessing.pipeline import SUPPORTED_EXTENSIONS, parse_document
from preprocessing.router import _CONTENT_PARSERS, process_input
from windowhash.hashing import compact

ROOT = Path(__file__).resolve().parents[2]


def _hwp():
    from test_hwpdoc_hwp import _sample

    return _sample()


def _hwpx():
    from test_hwpdoc_hwpx import _sample

    return _sample()


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_parser_contract_blocks(tmp_path):
    blocks = hwp_parser.parse_hwp(_write(tmp_path, "a.hwp", _hwp()))
    assert blocks[0] == {"type": "paragraph", "text": "문서 제목 홍길동"}
    assert blocks[2] == {"type": "table", "rows": [["성명", "김가짜"]]}
    assert blocks[3] == {"type": "table", "rows": [["주민등록번호", "900101-1234567\n둘째 줄"]]}
    assert all(set(b) in ({"type", "text"}, {"type", "rows"}) for b in blocks)
    # 등록 블록은 본문만(부가 글자 줄 없음) → 같은 구조의 HWP·HWPX는 블록 전체가 같다
    assert len(blocks) == 12 and not any("mailto:" in str(b) or "표입니다." in str(b) for b in blocks)
    xblocks = hwp_parser.parse_hwpx(_write(tmp_path, "a.hwpx", _hwpx()))
    assert xblocks == blocks


@pytest.mark.parametrize("name,maker,fmt", [("a.hwp", _hwp, "hwp"), ("a.hwpx", _hwpx, "hwpx"),
                                            ("noext", _hwp, "hwp"), ("wrong.docx", _hwpx, "hwpx")])
def test_router_registration_text_is_body_prefix_of_gateway_text(tmp_path, name, maker, fmt):
    """등록(router.process_input) 정규화 글자 = 본문 줄(body_lines)의 정규화 글자이고, 그 압축열은 Gateway가 보낼
    '\\n'.join(lines())(본문 + 부가 글자) 압축열의 앞부분이다(T1-2 Detection 쪽, 검토 지적 1 반영)."""
    data = maker()
    doc = process_input(str(_write(tmp_path, name, data)))
    assert doc.success and doc.format == fmt, (doc.error_type, doc.error_message)
    parsed = hwpdoc.read(data, max_decompressed=hwp_parser.MAX_DECOMPRESSED)
    reg = compact(doc.normalized_text).codes
    assert reg == compact(normalize_text("\n".join(parsed.body_lines()))).codes
    gateway = compact(normalize_text("\n".join(parsed.lines()))).codes
    assert gateway[: len(reg)] == reg and len(gateway) > len(reg)
    assert "900101-1234567" in doc.normalized_text and "mailto:fake@example.com" not in doc.normalized_text
    assert "mailto:fake@example.com" in "\n".join(parsed.lines())


def test_extension_routing(tmp_path):
    assert ".hwp" in SUPPORTED_EXTENSIONS and ".hwpx" in SUPPORTED_EXTENSIONS
    assert "hwp" in _CONTENT_PARSERS and "hwpx" in _CONTENT_PARSERS
    d = parse_document(_write(tmp_path, "b.HWP", _hwp()))
    assert d.success and d.format == "hwp"
    d = parse_document(_write(tmp_path, "b.hwpx", _hwpx()))
    assert d.success and d.format == "hwpx"


def _zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in entries.items():
            z.writestr(k, v)
    return buf.getvalue()


@pytest.mark.parametrize("data,expected", [
    (lambda: _hwp(), "hwp"),
    (lambda: _hwpx(), "hwpx"),
    (lambda: S.build_hwpx([hp_p(hp_t("본문"))], mimetype=None), "hwpx"),
    (lambda: S.build_hwpx([hp_p(hp_t("본문"))], mimetype="application/zip"), "zip-unknown"),
    (lambda: S.CFB_MAGIC + bytes(range(256)) * 8, "binary-unknown"),                        # 가짜 CFB
    (lambda: S.write_cfb({"EncryptionInfo": b"\x04\x00" * 100, "EncryptedPackage": b"\x00" * 5000}), "binary-unknown"),  # 암호 OOXML
    (lambda: S.write_cfb({"WordDocument": b"\xec\xa5" + b"\x00" * 5000, "1Table": b"\x00" * 600}), "binary-unknown"),   # DOC
    (lambda: _zip({"word/document.xml": "<w:document/>"}), "docx"),
    (lambda: _zip({"xl/workbook.xml": "<workbook/>"}), "xlsx"),
    (lambda: _zip({"a.txt": "x"}), "zip-unknown"),
    (lambda: b"%PDF-1.4 x", "pdf"),
    (lambda: b"hello", "binary-unknown"),
])
def test_format_detection_path_and_bytes_agree(tmp_path, data, expected):
    raw = data()
    assert detect_format(_write(tmp_path, "x.bin", raw)) == expected
    assert registry.detect_format(raw) == expected
    assert ("hwp" in registry.SUPPORTED_FORMATS) and ("hwpx" in registry.SUPPORTED_FORMATS)


@pytest.mark.parametrize("make,error_type,needle", [
    (lambda: S.build_hwp([S.p(0, "본문")], flags=0x3), "EncryptedDocumentError", "hwp_encrypted"),
    (lambda: S.build_hwp([S.p(0, "본문")], flags=0x5), "EncryptedDocumentError", "hwp_distribution"),
    (lambda: S.build_hwp([S.p(0, "본문")], flags=0x11), "EncryptedDocumentError", "hwp_drm"),
    (lambda: S.build_hwpx([hp_p(hp_t("본문"))], extra={"META-INF/encryption.xml": "<x/>"}), "EncryptedDocumentError", "hwpx_encrypted"),
    (lambda: S.build_hwp([S.p(0, "본문", S.rec(87, 1, b"\x00" * 8))]), "DocumentParsingError", "hwp_unsupported_object"),
    (lambda: S.build_hwp([S.p(0, "본문")], extra={"DocHistory/VersionLog0": b"x"}), "DocumentParsingError", "hwp_history"),
    (lambda: S.build_hwpx([hp_p(S.hp_run("<hp:foo>비밀</hp:foo>"))]), "DocumentParsingError", "hwpx_unknown_text"),
    (lambda: S.build_hwpx([hp_p(S.hp_run('<hp:ole id="1"/>'))]), "DocumentParsingError", "hwpx_unsupported_object"),
    (lambda: S.build_hwp([S.p(0, "본문") + b"\x01\x02"], flags=0), "CorruptedDocumentError", "truncated record header"),
    (lambda: S.build_hwp([S.rec(66, 0, b"\x00" * 22) + S.rec(67, 1, b"\x41\x00" * (11 * 1024 * 1024))]),
     "CorruptedDocumentError", "상한"),
    (lambda: S.build_hwp([S.p(0, "")], extra={"BinData/BIN0001.png": b"x"}), "DocumentParsingError", "그림만"),
    (lambda: S.build_hwp([S.p(0, "")], summary={2: "제목만 있음"}), "DocumentParsingError", "빈"),
])
def test_error_mapping_through_router(tmp_path, make, error_type, needle):
    doc = process_input(str(_write(tmp_path, "e.bin", make())))
    assert not doc.success and doc.error_type == error_type, (doc.error_type, doc.error_message)
    assert needle in doc.error_message


def test_missing_olefile_is_parsing_error(tmp_path, monkeypatch):
    path = _write(tmp_path, "m.hwp", _hwp())
    monkeypatch.setitem(sys.modules, "olefile", None)       # import olefile → ImportError
    from preprocessing.errors import DocumentParsingError

    with pytest.raises(DocumentParsingError, match="olefile"):
        hwp_parser.parse_hwp(path)
    with pytest.raises(ImportError):
        detect_format(path)                                  # 배포 누락은 조용히 넘기지 않는다


def test_hwp_modules_stay_out_of_detect_startup_path():
    code = ("import sys; sys.path.insert(0, sys.argv[1]);"
            "import preprocessing, preprocessing.router, preprocessing.format_detect, preprocessing.pipeline;"
            "import detection_service.pipeline, docstore.registry;"
            "bad = [m for m in ('preprocessing.hwpdoc', 'preprocessing.hwp_parser', 'olefile') if m in sys.modules];"
            "print(bad); sys.exit(1 if bad else 0)")
    proc = subprocess.run([sys.executable, "-c", code, str(ROOT)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_hwpdoc_top_level_imports_are_stdlib_only():
    src = (ROOT / "preprocessing" / "hwpdoc.py").read_text(encoding="utf-8")
    import ast

    tree = ast.parse(src)
    top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = {a.name.split(".")[0] for n in top if isinstance(n, ast.Import) for a in n.names} | \
        {n.module.split(".")[0] for n in top if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= {"__future__", "io", "re", "struct", "sys", "zipfile", "zlib", "array", "dataclasses"}, names
    assert not any(isinstance(n, ast.ImportFrom) and n.level for n in ast.walk(tree))   # 상대 import 없음
    ast.parse(src, feature_version=(3, 11))                                               # 3.11 문법
