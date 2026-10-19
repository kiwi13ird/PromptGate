CREATE TABLE IF NOT EXISTS signature_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('CREDENTIAL', 'PII')),
    entity_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    score REAL NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
    context_keywords TEXT,
    requires_context INTEGER NOT NULL DEFAULT 0 CHECK (requires_context IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_policies (
    policy_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL CHECK (target_type IN ('category', 'entity_type', 'detector_rule_id')),
    target_value TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('ALLOW', 'MASK')),
    priority INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    UNIQUE (target_type, target_value, version)
);
