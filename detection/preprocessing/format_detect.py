"""콘텐츠(매직바이트) 기반 실제 문서 포맷 판별.

파일 확장자는 신뢰할 수 없다 - 실제 게이트웨이가 받는 건 바이트지 파일명이 아니고,
확장자가 틀렸거나 아예 없을 수도 있다(우회 목적으로 속일 수도 있다). router.py가
"자유 입력"을 라우팅할 때는 이름이 아니라 내용으로 실제 포맷을 확정해야 한다.

PDF는 `%PDF-`로 시작한다. DOCX/XLSX는 둘 다 ZIP 컨테이너(`PK\\x03\\x04`)라 시그니처만
으로는 구분이 안 되고, 내부에 `word/document.xml`이 있으면 DOCX, `xl/workbook.xml`이
있으면 XLSX로 구분된다.

HWP(5.0)는 CFB 컨테이너(`D0 CF 11 E0`)이고 `FileHeader` 스트림 첫 32바이트가 "HWP Document File"이다.
같은 CFB인 DOC·XLS·암호 걸린 OOXML(EncryptionInfo·EncryptedPackage)에는 FileHeader가 없어 binary-unknown.
HWPX는 ZIP이고 `mimetype` 항목이 application/hwp+zip(없으면 Contents/content.hpf). 판별은 Gateway와 같은
hwpdoc.sniff로 한다 - 이 모듈은 /detect 기동 경로(preprocessing/__init__.py)에 있으므로 hwpdoc은 함수 안에서
import한다(olefile이 없으면 CFB 판별에서 ImportError).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _sniff_hwp(path: Path) -> str | None:
    from .hwpdoc import sniff  # noqa: PLC0415 - 기동 경로에 싣지 않는다

    return sniff(path.read_bytes())


def detect_format(path: str | Path) -> str:
    """"pdf" | "docx" | "xlsx" | "hwp" | "hwpx" | "zip-unknown" | "binary-unknown" 중 하나를 반환한다."""
    path = Path(path)

    with open(path, "rb") as f:
        head = f.read(8)

    if head.startswith(_PDF_MAGIC):
        return "pdf"

    if any(head.startswith(magic) for magic in _ZIP_MAGICS):
        try:
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
        except zipfile.BadZipFile:
            return "zip-unknown"
        if "word/document.xml" in names:
            return "docx"
        if "xl/workbook.xml" in names:
            return "xlsx"
        if _sniff_hwp(path) == "hwpx":
            return "hwpx"
        return "zip-unknown"

    if head == _CFB_MAGIC and _sniff_hwp(path) == "hwp":
        return "hwp"

    return "binary-unknown"
