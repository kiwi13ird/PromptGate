"""SQLite 원장 - 무엇을 언제 넣었고 어떤 창을 가졌는지의 기록. 실시간 조회는 읽지 않는다.

필요한 이유는 재적재와 삭제다. Redis 색인은 hash -> 문서 방향이라 "이 문서의 창을 전부 빼라"를 하려면
문서 -> hash 목록이 어딘가 있어야 한다. Redis가 날아가도 여기서 다시 채울 수 있다. 원문은 저장하지 않는다.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    length INTEGER NOT NULL,
    window INTEGER NOT NULL,
    ingested_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS windows (
    doc_id TEXT NOT NULL REFERENCES documents(doc_id),
    hash INTEGER NOT NULL,
    start INTEGER NOT NULL,
    end INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_windows_doc_id ON windows(doc_id);
"""


def connect(db_path: str | Path, *, check_same_thread: bool = True) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=check_same_thread)
    conn.executescript(_SCHEMA)
    return conn


def upsert_document(conn: sqlite3.Connection, doc_id: str, source_path: str | Path, length: int, window: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO documents (doc_id, source_path, length, window, ingested_at) VALUES (?, ?, ?, ?, ?)",
        (doc_id, str(source_path), length, window, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def replace_windows(conn: sqlite3.Connection, doc_id: str, windows: list[tuple[int, int, int]]) -> None:
    """문서 하나의 (hash, start, end) 목록을 통째로 교체한다 - idempotent."""
    conn.execute("DELETE FROM windows WHERE doc_id = ?", (doc_id,))
    conn.executemany("INSERT INTO windows (doc_id, hash, start, end) VALUES (?, ?, ?, ?)", [(doc_id, h, s, e) for h, s, e in windows])
    conn.commit()


def get_windows(conn: sqlite3.Connection, doc_id: str) -> list[tuple[int, int, int]]:
    return [(row[0], row[1], row[2]) for row in conn.execute("SELECT hash, start, end FROM windows WHERE doc_id = ? ORDER BY start", (doc_id,))]


def delete_document(conn: sqlite3.Connection, doc_id: str) -> bool:
    existed = conn.execute("SELECT 1 FROM documents WHERE doc_id = ?", (doc_id,)).fetchone() is not None
    conn.execute("DELETE FROM windows WHERE doc_id = ?", (doc_id,))
    conn.execute("DELETE FROM documents WHERE doc_id = ?", (doc_id,))
    conn.commit()
    return existed


def document_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]


def window_count(conn: sqlite3.Connection, doc_id: str | None = None) -> int:
    if doc_id is None:
        return conn.execute("SELECT COUNT(*) FROM windows").fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM windows WHERE doc_id = ?", (doc_id,)).fetchone()[0]
