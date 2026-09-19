"""RDS `documents` 등록·퇴역·조회. 연결(psycopg, autocommit)을 받아 SQL만 한다 - 나중에 대시보드의 관리 API가 그대로 가져다 쓴다.

등록은 원본 바이트를 저장하고 `index_status='pending'`으로 둔다. 파싱은 하지 않는다(무거운 PDF가 등록 요청을 붙잡지 않게) -
형식은 매직바이트로만 확인하고, 실제 파싱·정규화·색인은 Detection EC2의 인덱서가 한다. 파싱 실패는 `index_status='error'`로 보인다.

doc_id 기본값은 파일 이름에서 확장자를 뺀 것 - 지금 Redis 색인·판정 기록의 doc_id와 같은 규칙.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_FORMATS = ("pdf", "docx", "xlsx")

_LIST_COLUMNS = ("doc_id", "filename", "format", "version", "title", "classification", "status", "index_status",
                 "index_windows", "text_chars", "index_error", "registered_at", "registered_by", "indexed_at",
                 "retired_at")


class UnsupportedDocument(ValueError):
    pass


def detect_format(data: bytes) -> str:
    """preprocessing.format_detect.detect_format과 같은 규칙을 바이트에 적용한다."""
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = set(z.namelist())
        except zipfile.BadZipFile:
            return "zip-unknown"
        if "word/document.xml" in names:
            return "docx"
        if "xl/workbook.xml" in names:
            return "xlsx"
        return "zip-unknown"
    return "binary-unknown"


@dataclass
class RegisterResult:
    doc_id: str
    version: int
    outcome: str  # "created" | "updated" | "unchanged"
    format: str


def register(conn: Any, filename: str, data: bytes, *, doc_id: str | None = None, title: str | None = None,
             classification: str | None = None, registered_by: str | None = None) -> RegisterResult:
    fmt = detect_format(data)
    if fmt not in SUPPORTED_FORMATS:
        raise UnsupportedDocument(f"{filename}: 지원하지 않는 형식({fmt}). 지원: {', '.join(SUPPORTED_FORMATS)}")
    doc_id = doc_id or Path(filename).stem
    if not doc_id:
        raise UnsupportedDocument("doc_id가 비었습니다")

    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("SELECT version, original = %s, status, index_status FROM documents WHERE doc_id = %s FOR UPDATE",
                        (data, doc_id))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO documents (doc_id, filename, original, version, title, classification, status, "
                    "index_status, registered_at, registered_by) "
                    "VALUES (%s, %s, %s, 1, %s, %s, 'active', 'pending', now(), %s)",
                    (doc_id, filename, data, title, classification, registered_by))
                return RegisterResult(doc_id, 1, "created", fmt)
            version, same, status, index_status = row
            if same and status == "active" and index_status != "error":
                cur.execute("UPDATE documents SET title = COALESCE(%s, title), classification = COALESCE(%s, classification) "
                            "WHERE doc_id = %s", (title, classification, doc_id))
                return RegisterResult(doc_id, version, "unchanged", fmt)
            cur.execute(
                "UPDATE documents SET filename = %s, original = %s, version = version + 1, "
                "title = COALESCE(%s, title), classification = COALESCE(%s, classification), status = 'active', "
                "index_status = 'pending', index_error = NULL, retired_at = NULL, registered_at = now(), registered_by = %s "
                "WHERE doc_id = %s RETURNING version",
                (filename, data, title, classification, registered_by, doc_id))
            return RegisterResult(doc_id, cur.fetchone()[0], "updated", fmt)


def retire(conn: Any, doc_id: str) -> bool:
    """퇴역: 색인에서 빼도록 pending으로 둔다. 행·원본·텍스트는 남긴다(과거 판정의 doc_id가 가리키므로)."""
    with conn.cursor() as cur:
        cur.execute("UPDATE documents SET status = 'retired', retired_at = now(), index_status = 'pending', index_error = NULL "
                    "WHERE doc_id = %s AND status = 'active'", (doc_id,))
        return cur.rowcount == 1


def request_reindex(conn: Any, doc_id: str | None = None) -> int:
    with conn.cursor() as cur:
        if doc_id is None:
            cur.execute("UPDATE documents SET index_status = 'pending', index_error = NULL WHERE index_status <> 'indexing'")
        else:
            cur.execute("UPDATE documents SET index_status = 'pending', index_error = NULL "
                        "WHERE doc_id = %s AND index_status <> 'indexing'", (doc_id,))
        return cur.rowcount


def list_documents(conn: Any, status: str | None = None) -> list[dict[str, Any]]:
    """메타만. 원본 바이트·정규화 텍스트는 내보내지 않는다."""
    sql = f"SELECT {', '.join(_LIST_COLUMNS)} FROM documents"
    params: tuple = ()
    if status:
        sql += " WHERE status = %s"
        params = (status,)
    with conn.cursor() as cur:
        cur.execute(sql + " ORDER BY doc_id", params)
        return [dict(zip(_LIST_COLUMNS, r)) for r in cur.fetchall()]


def get_span(conn: Any, doc_id: str, start: int, end: int) -> str | None:
    """판정의 doc_span("start-end", 정규화 텍스트 좌표) 구간 원문. 문서나 텍스트가 없으면 None."""
    if start < 0 or end < start:
        raise ValueError(f"잘못된 구간 {start}-{end}")
    with conn.cursor() as cur:
        cur.execute("SELECT substr(normalized_text, %s, %s) FROM documents WHERE doc_id = %s AND normalized_text IS NOT NULL",
                    (start + 1, end - start, doc_id))
        row = cur.fetchone()
        return row[0] if row else None


def summary(conn: Any) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute("SELECT status || '/' || index_status, count(*) FROM documents GROUP BY 1 ORDER BY 1")
        return {k: v for k, v in cur.fetchall()}
