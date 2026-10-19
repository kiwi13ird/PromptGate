CREATE TABLE IF NOT EXISTS dashboard_security_events (
  event_id text PRIMARY KEY,
  fingerprint char(64) NOT NULL,
  occurred_at timestamptz NOT NULL,
  request_id text,
  client_id text NOT NULL,
  target_llm text NOT NULL CHECK (target_llm IN ('ChatGPT', 'Gemini', 'Claude')),
  final_action text NOT NULL CHECK (final_action IN ('ALLOW', 'BLOCK', 'MASK')),
  detection_outcome text CHECK (detection_outcome IN ('MATCH', 'NO_MATCH', 'UNAVAILABLE')),
  status text NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED')),
  assignee text,
  event jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dashboard_events_occurred_at_idx
  ON dashboard_security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS dashboard_events_request_id_idx
  ON dashboard_security_events (request_id)
  WHERE request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dashboard_events_client_id_idx
  ON dashboard_security_events (client_id);
CREATE INDEX IF NOT EXISTS dashboard_events_action_idx
  ON dashboard_security_events (final_action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS dashboard_events_status_idx
  ON dashboard_security_events (status, occurred_at DESC);

CREATE TABLE IF NOT EXISTS dashboard_admin_activity_history (
  audit_id text PRIMARY KEY,
  occurred_at timestamptz NOT NULL,
  admin_id text NOT NULL,
  action text NOT NULL CHECK (
    action IN ('EVENT_STATUS_CHANGED', 'EVENT_ASSIGNED', 'EVENT_NOTE_ADDED')
  ),
  target_type text NOT NULL CHECK (target_type = 'EVENT'),
  target_id text NOT NULL REFERENCES dashboard_security_events(event_id) ON DELETE RESTRICT,
  result text NOT NULL CHECK (result IN ('SUCCESS', 'FAILURE')),
  changes jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dashboard_activity_occurred_at_idx
  ON dashboard_admin_activity_history (occurred_at DESC);
CREATE INDEX IF NOT EXISTS dashboard_activity_target_idx
  ON dashboard_admin_activity_history (target_id, occurred_at DESC);

COMMENT ON TABLE dashboard_security_events IS
  'Metadata-only Gateway security events; raw prompts and protected document text are forbidden.';
COMMENT ON TABLE dashboard_admin_activity_history IS
  'Administrator investigation activity; note bodies are intentionally not copied into changes.';
