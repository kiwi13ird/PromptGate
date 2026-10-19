-- Additive only: retain all historical measurements and identify real trial scope.
ALTER TABLE dashboard_performance_runs ADD COLUMN IF NOT EXISTS test_context JSONB;
