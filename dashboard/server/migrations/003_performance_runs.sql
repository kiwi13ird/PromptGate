CREATE TABLE IF NOT EXISTS dashboard_performance_runs (
  run_id TEXT PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL,
  duration_sec DOUBLE PRECISION NOT NULL CHECK (duration_sec > 0),
  concurrent_clients INTEGER NOT NULL CHECK (concurrent_clients > 0),
  total_requests INTEGER NOT NULL CHECK (total_requests >= 0),
  throughput_rps DOUBLE PRECISION NOT NULL CHECK (throughput_rps >= 0),
  avg_latency_ms DOUBLE PRECISION NOT NULL CHECK (avg_latency_ms >= 0),
  p95_latency_ms DOUBLE PRECISION NOT NULL CHECK (p95_latency_ms >= 0),
  timeout_rate DOUBLE PRECISION NOT NULL CHECK (timeout_rate >= 0 AND timeout_rate <= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dashboard_performance_runs_started_at_idx
  ON dashboard_performance_runs (started_at DESC);
