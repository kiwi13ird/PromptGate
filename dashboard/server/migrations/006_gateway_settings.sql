-- 2026-10-10 Gateway 처리 설정(검사 지연·검사할 수 없는 파일·허용 알림).
-- 저장할 때마다 한 행을 더한다(고치지 않음). 가장 큰 version이 현재 설정. 다시 실행해도 안전하다.
CREATE TABLE IF NOT EXISTS dashboard_gateway_settings (
  version integer PRIMARY KEY CHECK (version >= 1),
  revision text NOT NULL UNIQUE CHECK (revision ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  settings jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object'),
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION dashboard_immutable_gateway_settings()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Gateway settings versions are append-only';
END;
$$;

DROP TRIGGER IF EXISTS dashboard_gateway_settings_immutable ON dashboard_gateway_settings;
CREATE TRIGGER dashboard_gateway_settings_immutable
  BEFORE UPDATE OR DELETE ON dashboard_gateway_settings
  FOR EACH ROW EXECUTE FUNCTION dashboard_immutable_gateway_settings();

COMMENT ON TABLE dashboard_gateway_settings IS
  'Gateway handling settings, one row per saved version; the highest version is current.';
