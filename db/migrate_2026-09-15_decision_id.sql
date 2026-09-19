-- 2026-09-15 판정 기록 전송 구조 변경: decisions 기본키를 request_id에서 decision_id(판정마다 UUID)로.
-- 이유: 같은 request_id가 두 번 오면 두 번째 판정이 DB에서 사라지고, 빈 request_id는 첫 건만 남았다(9/15 실측).
--       전송 서비스가 같은 줄을 다시 보내도 중복되지 않게 하는 열쇠도 decision_id다.
-- 순서: 새 탐지 API 배포(RDS 쓰기 중지) 뒤, 전송 서비스 시작 전에 실행.
-- 실행: psql "$DETECTION_PG_DSN" -v ON_ERROR_STOP=1 -f migrate_2026-09-15_decision_id.sql
-- 되돌리기: decision_id 기본키를 지우고 request_id 기본키를 다시 만든다(같은 request_id 행이 생겼으면 먼저 정리 필요).

BEGIN;
DELETE FROM decisions WHERE request_id = '';                          -- 9/15 실측 중 생긴 빈 번호 행
ALTER TABLE decisions ADD COLUMN IF NOT EXISTS decision_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE decisions DROP CONSTRAINT IF EXISTS decisions_pkey;
ALTER TABLE decisions ADD CONSTRAINT decisions_pkey PRIMARY KEY (decision_id);
ALTER TABLE decisions ALTER COLUMN decision_id DROP DEFAULT;           -- 이후 값은 탐지 API가 만든다
CREATE INDEX IF NOT EXISTS idx_decisions_request ON decisions (request_id);
COMMIT;
