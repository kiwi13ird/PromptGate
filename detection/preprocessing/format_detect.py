"""콘텐츠(매직바이트) 기반 실제 문서 포맷 판별.

파일 확장자는 신뢰할 수 없다 - 실제 게이트웨이가 받는 건 바이트지 파일명이 아니고,
확장자가 틀렸거나 아예 없을 수도 있다(우회 목적으로 속일 수도 있다). router.py가
"자유 입력"을 라우팅할 때는 이름이 아니라 내용으로 실제 포맷을 확정해야 한다.

PDF는 `%PDF-`로 시작한다. DOCX/XLSX는 둘 다 ZIP 컨테이너(`PK\\x03\\x04`)라 시그니처만
으로는 구분이 안 되고, 내부에 `word/document.xml`이 있으면 DOCX, `xl/workbook.xml`이
있으면 XLSX로 구분된다.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def detect_format(path: str | Path) -> str:
    """"pdf" | "docx" | "xlsx" | "zip-unknown" | "binary-unknown" 중 하나를 반환한다."""
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
        return "zip-unknown"

    return "binary-unknown"
