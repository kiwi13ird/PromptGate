-- 2026-10-12 접속 차단: 확장 프로그램 ID 차단 목록·'확장 ID 없는 접속 차단' 방식, ID 별칭.
-- dashboard_gateway_access는 저장할 때마다 한 행을 더한다(고치지 않음). 가장 큰 version이 현재 판이고, rules에는 해제·만료된 규칙까지 전체 기록이 들어 있다.
-- migrate.mjs가 매번 모든 파일을 다시 적용하므로 이 파일은 다시 실행해도 안전하다(감사 action 목록은 002에 있다).
CREATE TABLE IF NOT EXISTS dashboard_gateway_access (
  version integer PRIMARY KEY CHECK (version >= 1),
  revision text NOT NULL UNIQUE CHECK (revision ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  require_client_id boolean NOT NULL DEFAULT false,
  rules jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(rules) = 'array'),
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION dashboard_immutable_gateway_access()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Gateway access versions are append-only';
END;
$$;

DROP TRIGGER IF EXISTS dashboard_gateway_access_immutable ON dashboard_gateway_access;
CREATE TRIGGER dashboard_gateway_access_immutable
  BEFORE UPDATE OR DELETE ON dashboard_gateway_access
  FOR EACH ROW EXECUTE FUNCTION dashboard_immutable_gateway_access();

COMMENT ON TABLE dashboard_gateway_access IS
  'Gateway access control (extension client id block rules and the require-client-id mode), one row per saved version; the highest version is current.';

CREATE TABLE IF NOT EXISTS dashboard_client_aliases (
  client_id text PRIMARY KEY CHECK (client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$'),
  alias text NOT NULL CHECK (char_length(alias) BETWEEN 1 AND 40),
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE dashboard_client_aliases IS
  'Display names for extension client ids (dashboard only; never sent to the Gateway).';
