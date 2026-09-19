"""RDS PostgreSQL `decisions` 표에 판정 기록을 여러 줄씩 넣는다. **전송 서비스(log_shipper)만 쓴다** - 탐지 API는 쓰지 않는다.

- DSN은 환경변수 `DETECTION_PG_DSN`(예: postgresql://postgres:***@host:5432/dlp?sslmode=require).
- 한 묶음 = 한 트랜잭션. 전부 들어가거나 전부 안 들어간다. 실패는 예외로 올려 호출자(전송 서비스)가 재시도한다.
- 기본키는 `decision_id`. `ON CONFLICT (decision_id) DO NOTHING`이라 같은 줄을 다시 보내도 행이 늘지 않는다.
- 연결이 조용히 끊겨 멈추는 것을 막으려고 TCP keepalive와 `tcp_user_timeout`, 서버 쪽 `statement_timeout`을 건다.
- 표 생성·변경은 여기서 하지 않는다(`infra/postgres/`).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

log = logging.getLogger("detection.pg_store")

INSERT_COLUMNS = ("decision_id", "request_id", "ts", "service", "format", "text_chars", "blocked", "decided_by",
                  "doc_id", "doc_span", "input_span", "score", "pii_hits", "reason", "hash_status",
                  "signature_status", "total_ms", "prompt", "prompt_kept")

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


def insert_sql(table: str = "decisions") -> str:
    if not _IDENT.match(table):
        raise ValueError(f"bad table name: {table!r}")
    cols = ", ".join(INSERT_COLUMNS)
    marks = ", ".join(["%s"] * len(INSERT_COLUMNS))
    return f"INSERT INTO {table} ({cols}) VALUES ({marks}) ON CONFLICT (decision_id) DO NOTHING"


def to_params(record: dict[str, Any]) -> tuple:
    return (
        record["decision_id"],
        record.get("request_id"),
        datetime.fromtimestamp(record["ts"], tz=timezone.utc),
        record.get("service"), record.get("format"), record.get("text_chars"),
        record.get("blocked"), record.get("decided_by"), record.get("doc_id"), record.get("doc_span"),
        record.get("input_span"), record.get("score"), record.get("pii_hits"), record.get("reason"),
        record.get("hash_status"), record.get("signature_status"), record.get("total_ms"),
        record.get("prompt"), True,
    )


def _default_connect(dsn: str):
    import psycopg  # 지연 임포트 - PG 없는 환경에서 모듈 임포트만으로 실패하지 않게

    return psycopg.connect(
        dsn,
        autocommit=True,
        connect_timeout=5,
        keepalives=1, keepalives_idle=15, keepalives_interval=5, keepalives_count=3,
        tcp_user_timeout=20000,
        options="-c statement_timeout=20000",
    )


class PgWriter:
    def __init__(self, dsn: str, *, table: str = "decisions", connect: Callable[[str], Any] | None = None):
        self.dsn = dsn
        self.sql = insert_sql(table)
        self._connect = connect  # None이면 호출 시점의 모듈 _default_connect (테스트가 바꿔 끼울 수 있게)
        self._conn = None

    @property
    def conn(self):
        if self._conn is None:
            self._conn = (self._connect or _default_connect)(self.dsn)
        return self._conn

    def insert_many(self, records: Iterable[dict[str, Any]]) -> int:
        """한 트랜잭션으로 넣는다. 성공하면 넘긴 줄 수를 돌려주고, 실패하면 연결을 닫고 예외를 올린다."""
        params = [to_params(r) for r in records]
        if not params:
            return 0
        try:
            conn = self.conn
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.executemany(self.sql, params)
            return len(params)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None
