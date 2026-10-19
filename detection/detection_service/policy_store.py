"""Detection enforcement policies backed by the existing Signature SQLite DB.

Requests never query SQLite.  The current policy set is loaded into memory at
startup and atomically replaced after a successful administrative mutation.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from signature import engine as signature_engine

Hit = signature_engine.Hit


ACTIONS = {"ALLOW", "BLOCK", "MASK_PARTIAL", "MASK_FULL"}
ACTION_PRIORITY = {"ALLOW": 0, "MASK_PARTIAL": 1, "MASK_FULL": 2, "BLOCK": 3}
LEGACY_TO_V2 = {"ALLOW": "ALLOW", "MASK": "MASK_FULL", "BLOCK": "BLOCK"}
V2_TO_LEGACY = {
    "ALLOW": "ALLOW", "MASK_PARTIAL": "MASK", "MASK_FULL": "MASK", "BLOCK": "BLOCK",
}
CREDENTIAL_ENTITIES = {"GITHUB_TOKEN", "GENERIC_API_KEY", "PASSWORD"}
TARGET_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,47}$")


def normalize_action(value: str) -> str:
    """Read old policies/history without rewriting or removing their records."""
    action = str(value).strip().upper()
    return {"MASK": "MASK_FULL", "ALLOW_NOTIFY": "ALLOW", "BLOCK_NOTIFY": "BLOCK"}.get(action, action)


def _validate_credential_action(target: str, action: str) -> None:
    if target in CREDENTIAL_ENTITIES | {"CREDENTIAL"} and action == "MASK_PARTIAL":
        raise PolicyError("Credential partial masking is not supported.", status_code=422,
                          code="CREDENTIAL_PARTIAL_MASK_FORBIDDEN")


class PolicyError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 400, code: str = "POLICY_ERROR") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


@dataclass(frozen=True)
class Policy:
    policy_id: str
    target_type: str
    target_value: str
    action: str
    priority: int
    version: int
    enabled: bool
    updated_at: str
    updated_by: str


@dataclass(frozen=True)
class Resolution:
    action: str
    mask_hits: tuple[Hit, ...]
    policy_id: str | None
    policy_version: int | None
    hit_actions: tuple[str, ...] = ()


_lock = threading.RLock()
_db_path: Path | None = None
_policies: tuple[Policy, ...] = ()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def _prepare_schema(connection: sqlite3.Connection) -> None:
    columns = _columns(connection, "detection_policies")
    if not columns:
        raise RuntimeError("detection_policies table is missing")
    if "updated_at" not in columns:
        connection.execute("ALTER TABLE detection_policies ADD COLUMN updated_at TEXT")
    if "updated_by" not in columns:
        connection.execute("ALTER TABLE detection_policies ADD COLUMN updated_by TEXT")
    if "action_v2" not in columns:
        connection.execute("ALTER TABLE detection_policies ADD COLUMN action_v2 TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_policy_history (
            history_id TEXT PRIMARY KEY,
            policy_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            action TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            changed_by TEXT NOT NULL,
            UNIQUE(policy_id, version)
        )
        """
    )
    history_columns = _columns(connection, "detection_policy_history")
    if "action_v2" not in history_columns:
        connection.execute("ALTER TABLE detection_policy_history ADD COLUMN action_v2 TEXT")
    now = _now()
    connection.execute(
        "UPDATE detection_policies SET updated_at = COALESCE(updated_at, ?), updated_by = COALESCE(updated_by, 'bootstrap')",
        (now,),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO detection_policy_history
            (history_id, policy_id, version, action, enabled, created_at, changed_by)
        SELECT lower(hex(randomblob(16))), policy_id, version, upper(action), enabled,
               COALESCE(updated_at, ?), COALESCE(updated_by, 'bootstrap')
        FROM detection_policies
        """,
        (now,),
    )


def _read(connection: sqlite3.Connection) -> tuple[Policy, ...]:
    rows = connection.execute(
        """
        SELECT policy_id, upper(target_type) AS target_type,
               upper(target_value) AS target_value, upper(action) AS legacy_action,
               upper(action_v2) AS action_v2,
               priority, version, enabled, updated_at, updated_by
        FROM detection_policies
        ORDER BY priority DESC, policy_id
        """
    ).fetchall()
    policies = []
    for row in rows:
        action = normalize_action(row["action_v2"] or row["legacy_action"])
        if row["target_value"] in CREDENTIAL_ENTITIES | {"CREDENTIAL"} and action == "MASK_PARTIAL":
            action = "MASK_FULL"  # Expose safety enforcement without rewriting old DB rows.
        if action not in ACTIONS:
            raise RuntimeError(f"unsupported action in {row['policy_id']}: {action}")
        policies.append(
            Policy(
                policy_id=row["policy_id"],
                target_type=row["target_type"],
                target_value=row["target_value"],
                action=action,
                priority=int(row["priority"]),
                version=int(row["version"]),
                enabled=bool(row["enabled"]),
                updated_at=row["updated_at"] or _now(),
                updated_by=row["updated_by"] or "bootstrap",
            )
        )
    return tuple(policies)


def configure_database(db_path: str | None) -> int:
    global _db_path, _policies
    if not db_path or db_path.lower() == "off":
        with _lock:
            _db_path = None
            _policies = ()
        return 0
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Policy DB not found: {path}")
    connection = _connect(path)
    try:
        _prepare_schema(connection)
        connection.commit()
        loaded = _read(connection)
    finally:
        connection.close()
    with _lock:
        _db_path = path
        _policies = loaded
    return len(loaded)


def _policy_for_hit(hit: Hit) -> Policy | None:
    entity_type = str(hit.entity_type).upper()
    category = ("CREDENTIAL" if entity_type in CREDENTIAL_ENTITIES
                else signature_engine.category_for_hit(hit))
    with _lock:
        candidates = [
            policy
            for policy in _policies
            if policy.enabled
            and (
                (policy.target_type == "CATEGORY" and policy.target_value == category)
                or (policy.target_type in {"ENTITY", "ENTITY_TYPE"} and policy.target_value == entity_type)
            )
        ]
    # Specificity takes precedence over stored numeric priority. Preserve the
    # existing priority/id ordering only between policies of the same scope.
    return next(
        (policy for policy in candidates if policy.target_type in {"ENTITY", "ENTITY_TYPE"}),
        candidates[0] if candidates else None,
    )


def resolve(hits: Iterable[Hit]) -> Resolution:
    selected: list[tuple[Hit, Policy | None, str]] = []
    for hit in hits:
        policy = _policy_for_hit(hit)
        # Backward-compatible fail-safe when the DB has no matching policy.
        action = policy.action if policy else "BLOCK"
        if str(hit.entity_type).upper() in CREDENTIAL_ENTITIES and action == "MASK_PARTIAL":
            action = "MASK_FULL"
        selected.append((hit, policy, action))
    if not selected:
        return Resolution("ALLOW", (), None, None, ())
    action = max((item[2] for item in selected), key=ACTION_PRIORITY.__getitem__)
    mask_hits = tuple(item[0] for item in selected if item[2] in {"MASK_PARTIAL", "MASK_FULL"})
    deciding = next((item[1] for item in selected if item[2] == action and item[1]), None)
    return Resolution(
        action,
        mask_hits,
        deciding.policy_id if deciding else None,
        deciding.version if deciding else None,
        tuple(item[2] for item in selected),
    )


def _require_db() -> Path:
    if _db_path is None:
        raise PolicyError("Policy database is not configured.", status_code=503, code="POLICY_UNAVAILABLE")
    return _db_path


def _dto(policy: Policy) -> dict:
    return {
        "policy_id": policy.policy_id,
        "detector": "SIGNATURE",
        "detection_target": policy.target_value,
        "action": policy.action,
        "recommended_action": policy.action,
        "enforcement_action": policy.action,
        "target_llms": ["ChatGPT", "Gemini", "Claude"],
        "priority": policy.priority,
        "updated_by": policy.updated_by,
        "updated_at": policy.updated_at,
        "version": policy.version,
        "enabled": policy.enabled,
    }


def list_policies() -> list[dict]:
    with _lock:
        return [_dto(policy) for policy in _policies]


def get_policy(policy_id: str) -> dict:
    with _lock:
        policy = next((item for item in _policies if item.policy_id == policy_id), None)
    if policy is None:
        raise PolicyError("Policy not found.", status_code=404, code="NOT_FOUND")
    return _dto(policy)


def history(policy_id: str) -> list[dict]:
    path = _require_db()
    connection = _connect(path)
    try:
        rows = connection.execute(
            """
            SELECT version, upper(action) AS legacy_action, upper(action_v2) AS action_v2,
                   created_at, changed_by, enabled
            FROM detection_policy_history
            WHERE policy_id = ? ORDER BY version DESC
            """,
            (policy_id,),
        ).fetchall()
    finally:
        connection.close()
    if not rows and not any(item.policy_id == policy_id for item in _policies):
        raise PolicyError("Policy not found.", status_code=404, code="NOT_FOUND")
    return [
        {
            "version": int(row["version"]),
            "action": normalize_action(row["action_v2"] or row["legacy_action"]),
            "created_at": row["created_at"],
            "changed_by": row["changed_by"],
            "enabled": bool(row["enabled"]),
        }
        for row in rows
    ]


def _reload(connection: sqlite3.Connection) -> None:
    global _policies
    loaded = _read(connection)
    with _lock:
        _policies = loaded


def create(target: str, action: str, actor: str) -> dict:
    target = target.strip().upper()
    action = normalize_action(action)
    if not TARGET_PATTERN.fullmatch(target) or action not in ACTIONS:
        raise PolicyError("Invalid policy target or action.", status_code=422, code="VALIDATION")
    _validate_credential_action(target, action)
    path = _require_db()
    connection = _connect(path)
    now = _now()
    policy_id = f"POLICY-{target}-{uuid.uuid4().hex[:8].upper()}"
    try:
        if connection.execute(
            "SELECT 1 FROM detection_policies WHERE upper(target_value) = ?", (target,)
        ).fetchone():
            raise PolicyError("A policy for this target already exists.", status_code=409, code="CONFLICT")
        priority = 100
        connection.execute(
            """
            INSERT INTO detection_policies
                (policy_id, target_type, target_value, action, action_v2, priority, version, enabled, updated_at, updated_by)
            VALUES (?, 'entity_type', ?, ?, ?, ?, 1, 1, ?, ?)
            """,
            (policy_id, target, V2_TO_LEGACY[action], action, priority, now, actor),
        )
        connection.execute(
            """
            INSERT INTO detection_policy_history
                (history_id, policy_id, version, action, action_v2, enabled, created_at, changed_by)
            VALUES (?, ?, 1, ?, ?, 1, ?, ?)
            """,
            (uuid.uuid4().hex, policy_id, V2_TO_LEGACY[action], action, now, actor),
        )
        connection.commit()
        _reload(connection)
    finally:
        connection.close()
    return get_policy(policy_id)


def _mutate(policy_id: str, expected_version: int, actor: str, *, action: str | None, enabled: bool | None) -> dict:
    path = _require_db()
    connection = _connect(path)
    now = _now()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT action, action_v2, enabled, version, target_value FROM detection_policies WHERE policy_id = ?", (policy_id,)
        ).fetchone()
        if row is None:
            raise PolicyError("Policy not found.", status_code=404, code="NOT_FOUND")
        if int(row["version"]) != expected_version:
            raise PolicyError("Policy version conflict.", status_code=409, code="VERSION_CONFLICT")
        current_action = normalize_action(row["action_v2"] or row["action"])
        new_action = normalize_action(action) if action is not None else current_action
        if new_action not in ACTIONS:
            raise PolicyError("Invalid policy action.", status_code=422, code="VALIDATION")
        if action is not None:
            _validate_credential_action(str(row["target_value"]).upper(), new_action)
        new_enabled = bool(row["enabled"]) if enabled is None else bool(enabled)
        new_version = expected_version + 1
        connection.execute(
            """
            UPDATE detection_policies
            SET action = ?, action_v2 = ?, enabled = ?, version = ?, updated_at = ?, updated_by = ?
            WHERE policy_id = ?
            """,
            (V2_TO_LEGACY[new_action], new_action, int(new_enabled), new_version, now, actor, policy_id),
        )
        connection.execute(
            """
            INSERT INTO detection_policy_history
                (history_id, policy_id, version, action, action_v2, enabled, created_at, changed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (uuid.uuid4().hex, policy_id, new_version, V2_TO_LEGACY[new_action], new_action,
             int(new_enabled), now, actor),
        )
        connection.commit()
        _reload(connection)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return get_policy(policy_id)


def update(policy_id: str, action: str, expected_version: int, actor: str) -> dict:
    return _mutate(policy_id, expected_version, actor, action=action, enabled=None)


def change_status(policy_id: str, enabled: bool, expected_version: int, actor: str) -> dict:
    return _mutate(policy_id, expected_version, actor, action=None, enabled=enabled)
