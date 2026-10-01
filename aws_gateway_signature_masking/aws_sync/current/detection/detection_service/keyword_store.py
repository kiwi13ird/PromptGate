"""문서 키워드 저장소 - Signature SQLite DB의 `doc_keywords`를 관리 API가 읽고 쓴다.

설계: docs/pipelines/keyword-detection-design.md §3, §5

흐름: 키워드가 `pending`으로 들어온다(LLM 추출 또는 관리자 직접 입력) → 관리자가 대시보드에서
승인하면 `approved` → `/admin/reload-signatures`로 탐지 엔진에 반영된다. **거부는 삭제다**(거부 이력을
기억하지 않는다 - 2026-10-01 결정). 재추출하면 같은 키워드가 다시 제안될 수 있다.

반영 시점은 아직 정하지 않았다(설계 §5). 지금은 승인해도 **바로 반영되지 않고** 재로딩을 불러야
반영된다. 승인 응답에 `reload_required: true`를 실어 그 사실을 드러낸다.

탐지 요청은 이 모듈을 거치지 않는다. 탐지 엔진은 `signature.keywords.load_approved_keywords`로
시작·재로딩 때 승인 키워드만 읽어 메모리에 둔다. 이 모듈은 관리 API 전용이다.

표는 `configure_database()`가 없으면 만든다 - 정책 저장소(policy_store)가 이력 표를 만드는 것과
같은 방식이라, 운영 DB에 따로 마이그레이션을 돌리지 않아도 된다.

**저장 위치는 시그니처 DB와 따로다**(`KEYWORD_DB`, 운영 `/var/lib/detection-keyword/keyword.db`).
시그니처 DB가 있는 `/var/lib/detection/`은 root 소유라 서비스(ubuntu)가 쓸 수 없다 - SQLite가 같은
디렉터리에 `-journal`을 못 만들어 `attempt to write a readonly database`가 난다. 정책 DB(`POLICY_DB`)가
따로 있는 것과 같은 이유다.

**`configure_database()`는 예외를 올리지 않는다.** 2026-10-01에 이 함수가 시그니처 DB에 표를 만들다
실패해 탐지 API 기동이 막혔고, 탐지가 20초 멈췄다. 키워드는 부가 기능이라 설정에 실패하면 이 모듈의
API만 503을 내고 탐지는 계속 돈다. 실패 사유는 `unavailable_reason()`으로 드러난다.

키워드 목록은 **그 자체로 기밀**(프로젝트 코드명·고객사명)이다. 로그에 값을 남기지 않는다.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from preprocessing.normalizer import normalize_text

MIN_LENGTH = 2  # 1자 키워드는 거의 모든 입력에 걸린다. 최종 기준은 식별력 실험(설계 §6)으로 다시 정한다
MAX_LENGTH = 100
STATUSES = ("pending", "approved")
SOURCES = ("llm", "manual")

_db_path: Path | None = None
_unavailable: str | None = "not configured"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS doc_keywords (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword     TEXT    NOT NULL,
    doc_id      TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved')),
    source      TEXT    NOT NULL DEFAULT 'llm'     CHECK (source IN ('llm', 'manual')),
    reason      TEXT,
    doc_hits    INTEGER,
    neg_hits    INTEGER,
    created_at  TEXT    NOT NULL,
    created_by  TEXT,
    decided_at  TEXT,
    decided_by  TEXT,
    UNIQUE (keyword, doc_id)
);
CREATE INDEX IF NOT EXISTS ix_doc_keywords_status ON doc_keywords(status);

CREATE TABLE IF NOT EXISTS keyword_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id      TEXT    NOT NULL,
    doc_version INTEGER NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    created_at  TEXT    NOT NULL,
    finished_at TEXT
);
"""

_COLUMNS = ("id", "keyword", "doc_id", "status", "source", "reason", "doc_hits", "neg_hits",
            "created_at", "created_by", "decided_at", "decided_by")


class KeywordError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 400, code: str = "KEYWORD_ERROR") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def configure_database(db_path: str | None) -> bool:
    """DB 경로를 정하고 표가 없으면 만든다. 성공하면 True.

    **예외를 올리지 않는다**(모듈 docstring 참고). 경로가 없거나 `off`이거나 표를 못 만들면 False를
    돌려주고, 이후 관리 API는 503을 낸다. 탐지에는 영향이 없다.
    """
    global _db_path, _unavailable
    _db_path = None
    if not db_path or db_path.lower() == "off":
        _unavailable = "not configured"
        return False
    path = Path(db_path)
    try:
        connection = _connect(path)
        try:
            connection.executescript(_SCHEMA)
            connection.commit()
        finally:
            connection.close()
    except Exception as exc:  # noqa: BLE001 - 어떤 실패든 탐지 API 기동을 막지 않는다
        _unavailable = f"{type(exc).__name__}: {exc}"
        return False
    _db_path = path
    _unavailable = None
    return True


def unavailable_reason() -> str | None:
    """관리 API를 쓸 수 없는 이유. 쓸 수 있으면 None."""
    return _unavailable


def _require_db() -> Path:
    if _db_path is None:
        raise KeywordError(f"Keyword database is unavailable: {_unavailable}", status_code=503,
                           code="KEYWORD_UNAVAILABLE")
    return _db_path


def _dto(row: sqlite3.Row) -> dict:
    return {column: row[column] for column in _COLUMNS}


def clean_keyword(keyword: str) -> str:
    """저장 형태로 바꾼다. 탐지 엔진이 정규화한 입력과 같은 규칙으로 맞춰야 NFD·전각 공백 차이로 놓치지 않는다."""
    cleaned = normalize_text(keyword or "").strip()
    if "\n" in cleaned:
        raise KeywordError("Keyword must be a single line.", code="INVALID_KEYWORD")
    if len(cleaned) < MIN_LENGTH:
        raise KeywordError(f"Keyword must be at least {MIN_LENGTH} characters.", code="KEYWORD_TOO_SHORT")
    if len(cleaned) > MAX_LENGTH:
        raise KeywordError(f"Keyword must be at most {MAX_LENGTH} characters.", code="KEYWORD_TOO_LONG")
    return cleaned


def list_keywords(status: str | None = None, doc_id: str | None = None) -> list[dict]:
    if status is not None and status not in STATUSES:
        raise KeywordError(f"status must be one of {', '.join(STATUSES)}.", code="INVALID_STATUS")
    where, params = [], []
    if status is not None:
        where.append("status = ?")
        params.append(status)
    if doc_id is not None:
        where.append("doc_id = ?")
        params.append(doc_id)
    sql = f"SELECT {', '.join(_COLUMNS)} FROM doc_keywords"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY doc_id, id"
    connection = _connect(_require_db())
    try:
        return [_dto(row) for row in connection.execute(sql, params)]
    finally:
        connection.close()


def get(keyword_id: int) -> dict:
    connection = _connect(_require_db())
    try:
        row = connection.execute(f"SELECT {', '.join(_COLUMNS)} FROM doc_keywords WHERE id = ?", (keyword_id,)).fetchone()
    finally:
        connection.close()
    if row is None:
        raise KeywordError("Keyword not found.", status_code=404, code="NOT_FOUND")
    return _dto(row)


def add(keyword: str, doc_id: str, *, source: str = "manual", approve: bool = False,
        reason: str | None = None, actor: str | None = None) -> dict:
    """키워드 하나를 넣는다. 같은 문서에 같은 키워드가 있으면 409."""
    if source not in SOURCES:
        raise KeywordError(f"source must be one of {', '.join(SOURCES)}.", code="INVALID_SOURCE")
    cleaned = clean_keyword(keyword)
    now = _now()
    status = "approved" if approve else "pending"
    connection = _connect(_require_db())
    try:
        try:
            cursor = connection.execute(
                "INSERT INTO doc_keywords (keyword, doc_id, status, source, reason, created_at, created_by,"
                " decided_at, decided_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cleaned, doc_id, status, source, reason, now, actor,
                 now if approve else None, actor if approve else None),
            )
        except sqlite3.IntegrityError as exc:
            raise KeywordError("This keyword already exists for the document.", status_code=409,
                               code="DUPLICATE") from exc
        connection.commit()
        keyword_id = cursor.lastrowid
    finally:
        connection.close()
    return get(keyword_id)


def approve(keyword_id: int, actor: str | None = None) -> dict:
    """승인한다. 이미 승인된 것이면 그대로 돌려준다(멱등)."""
    current = get(keyword_id)
    if current["status"] == "approved":
        return current
    connection = _connect(_require_db())
    try:
        connection.execute(
            "UPDATE doc_keywords SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ?",
            (_now(), actor, keyword_id),
        )
        connection.commit()
    finally:
        connection.close()
    return get(keyword_id)


def delete(keyword_id: int) -> None:
    """거부 = 삭제. 승인된 키워드를 지울 때도 같다(지운 뒤 재로딩해야 탐지에서 빠진다)."""
    connection = _connect(_require_db())
    try:
        deleted = connection.execute("DELETE FROM doc_keywords WHERE id = ?", (keyword_id,)).rowcount
        connection.commit()
    finally:
        connection.close()
    if not deleted:
        raise KeywordError("Keyword not found.", status_code=404, code="NOT_FOUND")
