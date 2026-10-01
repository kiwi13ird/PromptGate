import sqlite3

from detection_service import policy_store
from signature.engine import Hit


def _legacy_db(path):
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE detection_policies (
            policy_id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_value TEXT NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('ALLOW', 'MASK', 'BLOCK')),
            priority INTEGER NOT NULL, version INTEGER NOT NULL, enabled INTEGER NOT NULL
        );
        INSERT INTO detection_policies VALUES
            ('POLICY-PII', 'CATEGORY', 'PII', 'MASK', 100, 1, 1),
            ('POLICY-CREDENTIAL', 'CATEGORY', 'CREDENTIAL', 'MASK', 100, 1, 1);
    """)
    connection.commit()
    connection.close()


def test_legacy_check_constraint_is_preserved_while_v2_action_is_stored(tmp_path):
    path = tmp_path / "signature.db"
    _legacy_db(path)
    assert policy_store.configure_database(str(path)) == 2
    pii = next(item for item in policy_store.list_policies() if item["policy_id"] == "POLICY-PII")
    assert pii["action"] == "MASK_FULL"

    updated = policy_store.update("POLICY-PII", "mask_partial", 1, "test")
    assert updated["action"] == "MASK_PARTIAL"
    connection = sqlite3.connect(path)
    assert connection.execute(
        "SELECT action, action_v2 FROM detection_policies WHERE policy_id='POLICY-PII'"
    ).fetchone() == ("MASK", "MASK_PARTIAL")
    connection.close()


def test_credentials_cannot_use_partial_mask(tmp_path):
    path = tmp_path / "signature.db"
    _legacy_db(path)
    policy_store.configure_database(str(path))
    policy_store.update("POLICY-CREDENTIAL", "mask_partial", 1, "test")
    resolution = policy_store.resolve([Hit("PASSWORD", 0, 8, 0.9)])
    assert resolution.action == "MASK_FULL"
    assert resolution.hit_actions == ("MASK_FULL",)
