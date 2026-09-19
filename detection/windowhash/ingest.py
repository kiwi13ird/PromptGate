"""기존 문서를 읽어 색인에 적재하는 배치. hashdb/ingest.py에서 가져왔고 언어 판정만 뺐다(창 길이는 언어와 무관).

`preprocessing.router.process_input()`으로 normalized_text를 얻고, 엔진마다 clear()(옛 색인 제거) → ingest().
SQLite(conn)는 원장, Redis(r)는 실시간 조회 색인이다.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from preprocessing.router import process_input  # noqa: E402

from .detect import ENGINES  # noqa: E402
from .hashing import WINDOW  # noqa: E402
from .store import upsert_document  # noqa: E402

_SUPPORTED_SUFFIXES = {".docx", ".xlsx", ".pdf"}


def ingest_file(conn: sqlite3.Connection, r: redis.Redis, path: Path) -> dict:
    """파일 하나를 파싱하고 모든 엔진에 적재한다. 실패해도 예외를 던지지 않는다."""
    doc = process_input(str(path))
    if not doc.success:
        return {"path": str(path), "ok": False, "error": doc.error_message}

    text = doc.normalized_text
    doc_id = path.stem
    for e in ENGINES:
        e.clear(conn, r, doc_id)
    upsert_document(conn, doc_id, path, len(text), WINDOW)
    stats: dict[str, int] = {}
    for e in ENGINES:
        stats.update(e.ingest(conn, r, doc_id, text))
    return {"path": str(path), "ok": True, "doc_id": doc_id, **stats}


def ingest_directory(conn: sqlite3.Connection, r: redis.Redis, directory: Path) -> list[dict]:
    """디렉터리 최상위의 docx/xlsx/pdf만 훑는다(재귀 안 함)."""
    results = []
    for p in sorted(directory.iterdir()):
        if p.is_dir() or p.suffix.lower() not in _SUPPORTED_SUFFIXES:
            continue
        results.append(ingest_file(conn, r, p))
    return results
