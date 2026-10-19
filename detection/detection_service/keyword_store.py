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

import json
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
    evidence    TEXT,
    reason_check TEXT,
    reason_version TEXT,
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

CREATE TABLE IF NOT EXISTS doc_states (
    doc_id      TEXT    PRIMARY KEY,
    status      TEXT    NOT NULL,
    version     INTEGER,
    updated_at  TEXT    NOT NULL
);
"""

_COLUMNS = ("id", "keyword", "doc_id", "status", "source", "reason", "doc_hits", "neg_hits",
            "created_at", "created_by", "decided_at", "decided_by",
            "evidence", "reason_check", "reason_version")

# 선정 이유 보강(2026-10-13)으로 늘린 열. 옛 DB에는 없으므로 표를 열 때 없는 것만 덧붙인다(데이터는 그대로).
#   evidence       근거 문장: 시스템이 본문에서 키워드가 든 문장을 그대로 잘라 둔 것(LLM이 쓰지 않음, 최대 2개, 줄바꿈으로 이음)
#   reason_check   자동 검사 결과(JSON): {ok, source('llm'|'short'), foreign_tokens[], specificity('고유'|'일반'|null)}
#                  specificity는 LLM의 참고 판정 - '일반'이면 화면이 '일반적인 표현일 수 있음'을 붙인다(맹검 평가에서 일반 표현의 86%를 짚음)
#   reason_version 이유 프롬프트 판
#   reason_check에 문서 수 3칸(2026-10-16, refresh_doc_counts): doc_count(지금 보호 중인 문서 중 본문에 이 키워드가 든 문서 수,
#                  자기 문서 포함) · common_in_docs(doc_count >= COMMON_MIN_DOCS) · doc_count_at. 계약: handoff/detection-keyword-logic-2026-10-16
_NEW_COLUMNS = (("evidence", "TEXT"), ("reason_check", "TEXT"), ("reason_version", "TEXT"))


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
            _migrate(connection)
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
    dto = {column: row[column] for column in _COLUMNS}
    check = dto.get("reason_check")
    if isinstance(check, str):
        try:
            dto["reason_check"] = json.loads(check)
        except ValueError:
            dto["reason_check"] = None
    return dto


def _migrate(connection: sqlite3.Connection) -> None:
    """옛 doc_keywords에 없는 열만 덧붙인다. 동시에 다른 프로세스(추출 서비스·탐지 API)가 같은 일을 해도 안전하다."""
    have = {row[1] for row in connection.execute("PRAGMA table_info(doc_keywords)")}
    for name, kind in _NEW_COLUMNS:
        if name in have:
            continue
        try:
            connection.execute(f"ALTER TABLE doc_keywords ADD COLUMN {name} {kind}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise


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


def update(keyword_id: int, keyword: str) -> dict:
    """승인 대기 키워드의 표현을 고친다(승인 전 검토). 승인된 것은 탐지에 쓰이는 중이라 고치지 않는다 → 409
    (지우고 새로 넣는다). 등장 횟수(doc_hits·neg_hits)와 근거 문장·이유 검사 결과(evidence·reason_check)는 고치기 전
    표현으로 만든 값이라 비운다(None = 미측정·없음). 이유(reason) 글은 그대로 둔다."""
    current = get(keyword_id)
    if current["status"] != "pending":
        raise KeywordError("Only pending keywords can be edited.", status_code=409, code="NOT_PENDING")
    cleaned = clean_keyword(keyword)
    if cleaned == current["keyword"]:
        return current
    connection = _connect(_require_db())
    try:
        try:
            changed = connection.execute(
                "UPDATE doc_keywords SET keyword = ?, doc_hits = NULL, neg_hits = NULL, evidence = NULL, reason_check = NULL,"
                " reason_version = NULL WHERE id = ? AND status = 'pending'",
                (cleaned, keyword_id),
            ).rowcount
        except sqlite3.IntegrityError as exc:
            raise KeywordError("This keyword already exists for the document.", status_code=409,
                               code="DUPLICATE") from exc
        connection.commit()
    finally:
        connection.close()
    if not changed:  # 읽은 뒤 그사이 다른 관리자가 승인·삭제했다
        raise KeywordError("Only pending keywords can be edited.", status_code=409, code="NOT_PENDING")
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


# ---------------------------------------------------------------- 추출 작업 큐 (설계 §7)
#
# 인덱서가 문서를 색인하면 작업을 넣고(enqueue_job), 추출 서비스(docstore.keyword_extractor)가 하나씩 잡아 처리한다.
# GPU가 꺼져 있으면 작업은 queued로 **쌓이기만** 한다 - 시도 횟수를 쓰지 않으므로 GPU를 켜면 그대로 처리된다.
# doc_version 0 = "처리 시점의 최신 버전"(관리자가 재추출을 요청할 때. API는 RDS를 보지 않아 버전을 모른다).

MAX_ATTEMPTS = 3
LATEST_VERSION = 0
JOB_STATUSES = ("queued", "running", "done", "failed")
_JOB_COLUMNS = ("id", "doc_id", "doc_version", "status", "attempts", "error", "created_at", "finished_at")


def _job(row: sqlite3.Row) -> dict:
    return {column: row[column] for column in _JOB_COLUMNS}


def enqueue_job(doc_id: str, doc_version: int = LATEST_VERSION) -> dict:
    """작업을 넣는다. 같은 문서의 대기·진행 중 작업이 있으면 새로 넣지 않고 그것을 돌려준다(재등록이 겹쳐도 한 번만)."""
    connection = _connect(_require_db())
    try:
        row = connection.execute(
            f"SELECT {', '.join(_JOB_COLUMNS)} FROM keyword_jobs WHERE doc_id = ? AND status IN ('queued', 'running') "
            "ORDER BY id DESC LIMIT 1", (doc_id,)).fetchone()
        if row is not None:
            if row["status"] == "queued" and row["doc_version"] != doc_version:
                # 대기 중에 다시 등록됐다 - 새 버전으로 바꿔 둔다(옛 버전을 뽑을 이유가 없다)
                connection.execute("UPDATE keyword_jobs SET doc_version = ? WHERE id = ?", (doc_version, row["id"]))
                connection.commit()
            return get_job(row["id"])
        cursor = connection.execute(
            "INSERT INTO keyword_jobs (doc_id, doc_version, status, created_at) VALUES (?, ?, 'queued', ?)",
            (doc_id, doc_version, _now()))
        connection.commit()
        job_id = cursor.lastrowid
    finally:
        connection.close()
    return get_job(job_id)


def get_job(job_id: int) -> dict:
    connection = _connect(_require_db())
    try:
        row = connection.execute(f"SELECT {', '.join(_JOB_COLUMNS)} FROM keyword_jobs WHERE id = ?", (job_id,)).fetchone()
    finally:
        connection.close()
    if row is None:
        raise KeywordError("Job not found.", status_code=404, code="NOT_FOUND")
    return _job(row)


def list_jobs(status: str | None = None, limit: int = 200) -> list[dict]:
    if status is not None and status not in JOB_STATUSES:
        raise KeywordError(f"status must be one of {', '.join(JOB_STATUSES)}.", code="INVALID_STATUS")
    sql = f"SELECT {', '.join(_JOB_COLUMNS)} FROM keyword_jobs"
    params: list = []
    if status is not None:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    connection = _connect(_require_db())
    try:
        return [_job(row) for row in connection.execute(sql, params)]
    finally:
        connection.close()


def job_counts() -> dict[str, int]:
    connection = _connect(_require_db())
    try:
        rows = connection.execute("SELECT status, count(*) FROM keyword_jobs GROUP BY status").fetchall()
    finally:
        connection.close()
    return {status: 0 for status in JOB_STATUSES} | {row[0]: row[1] for row in rows}


def claim_job() -> dict | None:
    """가장 오래된 queued 작업 하나를 running으로 잡는다. 추출 서비스는 하나만 돈다는 전제."""
    connection = _connect(_require_db())
    try:
        row = connection.execute("SELECT id FROM keyword_jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        changed = connection.execute("UPDATE keyword_jobs SET status = 'running' WHERE id = ? AND status = 'queued'",
                                     (row["id"],)).rowcount
        connection.commit()
    finally:
        connection.close()
    return get_job(row["id"]) if changed else None


def finish_job(job_id: int, error: str | None = None) -> dict:
    connection = _connect(_require_db())
    try:
        connection.execute("UPDATE keyword_jobs SET status = 'done', error = ?, finished_at = ? WHERE id = ?",
                           (error, _now(), job_id))
        connection.commit()
    finally:
        connection.close()
    return get_job(job_id)


def requeue_job(job_id: int, error: str | None = None, *, count_attempt: bool) -> dict:
    """다시 대기로. count_attempt=False는 GPU가 없어서 못 한 경우 - 문서 탓이 아니므로 횟수를 쓰지 않는다.
    횟수를 써서 MAX_ATTEMPTS에 닿으면 failed로 멈춘다(관리자가 retry_job으로 다시 살린다)."""
    connection = _connect(_require_db())
    try:
        if count_attempt:
            connection.execute(
                "UPDATE keyword_jobs SET attempts = attempts + 1, error = ?, "
                "status = CASE WHEN attempts + 1 >= ? THEN 'failed' ELSE 'queued' END, "
                "finished_at = CASE WHEN attempts + 1 >= ? THEN ? ELSE NULL END WHERE id = ?",
                (error, MAX_ATTEMPTS, MAX_ATTEMPTS, _now(), job_id))
        else:
            connection.execute("UPDATE keyword_jobs SET status = 'queued', error = ? WHERE id = ?", (error, job_id))
        connection.commit()
    finally:
        connection.close()
    return get_job(job_id)


def retry_job(job_id: int) -> dict:
    current = get_job(job_id)
    if current["status"] != "failed":
        raise KeywordError("Only failed jobs can be retried.", status_code=409, code="NOT_FAILED")
    connection = _connect(_require_db())
    try:
        connection.execute("UPDATE keyword_jobs SET status = 'queued', attempts = 0, error = NULL, finished_at = NULL "
                           "WHERE id = ?", (job_id,))
        connection.commit()
    finally:
        connection.close()
    return get_job(job_id)


def recover_running() -> int:
    """추출 서비스 시작 시 running에 멈춘 작업을 되돌린다(처리 중 재시작)."""
    connection = _connect(_require_db())
    try:
        n = connection.execute("UPDATE keyword_jobs SET status = 'queued' WHERE status = 'running'").rowcount
        connection.commit()
    finally:
        connection.close()
    return n


def add_extracted(doc_id: str, items: list[dict]) -> list[dict]:
    """LLM 추출 결과를 pending으로 넣는다. 같은 문서에 이미 있는 키워드(승인됐든 대기든)는 건너뛴다.
    items: [{keyword(저장 형태), reason, doc_hits, neg_hits, evidence?, reason_check?(dict), reason_version?}].
    반환: 새로 들어간 것. 이미 있는 것의 이유 보강은 refresh_reasons가 한다."""
    now = _now()
    inserted_ids = []
    connection = _connect(_require_db())
    try:
        for item in items:
            try:
                cursor = connection.execute(
                    "INSERT INTO doc_keywords (keyword, doc_id, status, source, reason, doc_hits, neg_hits, created_at,"
                    " created_by, evidence, reason_check, reason_version)"
                    " VALUES (?, ?, 'pending', 'llm', ?, ?, ?, ?, 'keyword-extractor', ?, ?, ?)",
                    (item["keyword"], doc_id, item.get("reason"), item.get("doc_hits"), item.get("neg_hits"), now,
                     item.get("evidence"), _check_text(item.get("reason_check")), item.get("reason_version")))
                inserted_ids.append(cursor.lastrowid)
            except sqlite3.IntegrityError:
                continue
        connection.commit()
    finally:
        connection.close()
    return [get(i) for i in inserted_ids]


def _check_text(check) -> str | None:
    return None if check is None else json.dumps(check, ensure_ascii=False, separators=(",", ":"))


def refresh_reasons(doc_id: str, items: list[dict]) -> int:
    """이미 있는 LLM 키워드(승인됐든 대기든)에 선정 이유·근거를 채운다. 근거(evidence)가 아직 없는 행만 바꾼다.

    재추출하면 같은 키워드는 add_extracted가 건너뛰므로(승인 상태 보존), 이 함수가 옛 짧은 이유를 새 설명으로 보강한다.
    **키워드 값·상태·승인자는 건드리지 않는다.** 반환: 바뀐 행 수."""
    changed = 0
    connection = _connect(_require_db())
    try:
        for item in items:
            changed += connection.execute(
                "UPDATE doc_keywords SET reason = ?, evidence = ?, reason_check = ?, reason_version = ?,"
                " doc_hits = COALESCE(?, doc_hits), neg_hits = COALESCE(?, neg_hits)"
                " WHERE doc_id = ? AND keyword = ? AND source = 'llm' AND evidence IS NULL",
                (item.get("reason"), item.get("evidence"), _check_text(item.get("reason_check")),
                 item.get("reason_version"), item.get("doc_hits"), item.get("neg_hits"), doc_id, item["keyword"]),
            ).rowcount
        connection.commit()
    finally:
        connection.close()
    return changed


# ---------------------------------------------------------------- 문서 상태 · 문서 수 (2026-10-16)
#
# 문서 상태의 원본은 RDS `documents.status`('active' | 'retired')다. 탐지 API는 RDS를 보지 않으므로 인덱서가 주기마다
# 상태를 `doc_states`로 옮긴다. 탐지 적재(signature.keywords.load_approved_keywords)는 보호 중이 아닌 문서의 승인 키워드를
# 뺀다 - 키워드 행·승인 상태는 그대로라 다시 보호하면 돌아온다.
#
# '일반 표현일 수 있음' 표시: 키워드가 보호 문서 몇 개의 본문에 나오는지 센다. 2개 이상이면 어느 한 문서의 고유 표현이라
# 말할 수 없다 - 창 해시의 식별력 규칙(windowhash/engine.py: 2개 이상 문서에 있는 창은 근거에서 뺀다)과 같은 근거.

COMMON_MIN_DOCS = 2


def sync_doc_states(rows) -> list[str]:
    """RDS 문서 상태를 doc_states에 옮긴다. rows: [(doc_id, status, version)].
    반환: 보호 여부(active인지)가 바뀐 문서 id - 처음 들어온 문서는 'active가 아님'일 때만 바뀐 것으로 친다
    (상태를 모르던 문서는 탐지에 쓰이고 있었으므로). RDS에서 사라진 문서는 마지막 상태를 그대로 둔다."""
    now = _now()
    changed: list[str] = []
    connection = _connect(_require_db())
    try:
        connection.execute("BEGIN IMMEDIATE")
        known = {row["doc_id"]: row["status"] for row in connection.execute("SELECT doc_id, status FROM doc_states")}
        for doc_id, status, version in rows:
            before = known.get(doc_id)
            if before == status:
                continue
            was_active = before is None or before == "active"
            if was_active != (status == "active"):
                changed.append(doc_id)
            connection.execute(
                "INSERT INTO doc_states (doc_id, status, version, updated_at) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(doc_id) DO UPDATE SET status = excluded.status, version = excluded.version,"
                " updated_at = excluded.updated_at",
                (doc_id, status, version, now))
        connection.commit()
    finally:
        connection.close()
    return changed


def list_doc_states() -> dict[str, str]:
    connection = _connect(_require_db())
    try:
        return {row["doc_id"]: row["status"] for row in connection.execute("SELECT doc_id, status FROM doc_states")}
    finally:
        connection.close()


def doc_count_fields(keyword: str, folded_texts, at: str | None = None) -> dict:
    """reason_check에 넣을 문서 수 3칸. folded_texts: 보호 중인 문서 본문을 signature.keywords.fold로 접은 것."""
    import signature.engine  # noqa: F401 - signature.keywords를 먼저 부르면 순환 import가 난다
    from signature.keywords import fold

    k = fold(keyword)
    n = sum(1 for t in folded_texts if k in t)
    return {"doc_count": n, "common_in_docs": n >= COMMON_MIN_DOCS, "doc_count_at": at or _now()}


def missing_doc_counts() -> int:
    """문서 수를 아직 안 센 키워드 수(직접 추가·승인 전 수정으로 reason_check가 비었거나 옛 행)."""
    connection = _connect(_require_db())
    try:
        rows = connection.execute("SELECT reason_check FROM doc_keywords").fetchall()
    finally:
        connection.close()
    missing = 0
    for row in rows:
        try:
            check = json.loads(row[0]) if row[0] else None
        except ValueError:
            check = None
        if not isinstance(check, dict) or "doc_count" not in check:
            missing += 1
    return missing


def refresh_doc_counts(texts) -> dict:
    """모든 키워드의 reason_check에 문서 수 3칸을 다시 쓴다(재추출 없이). texts: 보호 중인 문서 본문들.
    다른 칸(ok·source·specificity·kind 등)과 키워드 값·상태·doc_hits는 건드리지 않는다. 한 트랜잭션.
    반환: {rows, changed(문서 수나 판정이 바뀐 행), common(2개 이상 문서에 나오는 행)}."""
    import signature.engine  # noqa: F401
    from signature.keywords import fold

    folded = [fold(t) for t in texts if t]
    at = _now()
    changed = common = 0
    connection = _connect(_require_db())
    try:
        connection.execute("BEGIN IMMEDIATE")   # 추출 서비스가 같은 행의 reason_check를 그사이 바꾸지 못하게 읽기부터 잠근다
        rows = connection.execute("SELECT id, keyword, reason_check FROM doc_keywords").fetchall()
        for row in rows:
            try:
                check = json.loads(row["reason_check"]) if row["reason_check"] else None
            except ValueError:
                check = None
            if not isinstance(check, dict):
                check = {}
            fields = doc_count_fields(row["keyword"], folded, at)
            common += fields["common_in_docs"]
            if (check.get("doc_count"), check.get("common_in_docs")) != (fields["doc_count"], fields["common_in_docs"]):
                changed += 1
            connection.execute("UPDATE doc_keywords SET reason_check = ? WHERE id = ?",
                               (_check_text({**check, **fields}), row["id"]))
        connection.commit()
    finally:
        connection.close()
    return {"rows": len(rows), "changed": changed, "common": common}
