ALTER TABLE dashboard_admin_activity_history
  DROP CONSTRAINT IF EXISTS dashboard_admin_activity_history_action_check;

ALTER TABLE dashboard_admin_activity_history
  DROP CONSTRAINT IF EXISTS dashboard_admin_activity_history_target_type_check;

ALTER TABLE dashboard_admin_activity_history
  DROP CONSTRAINT IF EXISTS dashboard_admin_activity_history_target_id_fkey;

ALTER TABLE dashboard_admin_activity_history
  ADD CONSTRAINT dashboard_admin_activity_history_action_check CHECK (
    action IN (
      'ADMIN_LOGIN',
      'ADMIN_LOGOUT',
      'POLICY_CREATE',
      'POLICY_UPDATE',
      'POLICY_ENABLE',
      'POLICY_DISABLE',
      'DOCUMENT_REGISTER',
      'DOCUMENT_ENABLE',
      'DOCUMENT_DISABLE',
      'EVENT_STATUS_CHANGED',
      'EVENT_ASSIGNED',
      'EVENT_NOTE_ADDED',
      -- 2026-10 리포트·키워드 승인(HITL). migrate.mjs가 매번 모든 파일을 다시 적용하므로
      -- 새 파일을 따로 두지 않고 이 목록을 넓힌다(따로 두면 다음 실행 때 여기서 기존 기록에 막힌다)
      'REPORT_CREATE',
      'KEYWORD_CREATE',
      'KEYWORD_APPROVE',
      'KEYWORD_REJECT',
      'KEYWORD_UPDATE',
      'KEYWORD_EXTRACT_REQUEST',
      -- 2026-10-07 대시보드 GPU 켜기·끄기
      'GPU_START',
      'GPU_STOP',
      -- 2026-10-10 Gateway 처리 설정 저장(006_gateway_settings.sql). 되돌릴 때도 이 목록은 줄이지 않는다
      'GATEWAY_SETTINGS_UPDATE',
      -- 2026-10-12 접속 차단(007_gateway_access.sql): 확장 ID 차단 등록·해제, 방식 변경, ID 별칭. 이 목록도 줄이지 않는다
      'ACCESS_RULE_ADD',
      'ACCESS_RULE_REMOVE',
      'ACCESS_MODE_UPDATE',
      'CLIENT_ALIAS_UPDATE',
      -- 2026-10-13 보호 문서 본문 보기: 열 때마다·내려받을 때마다 1건(기록 실패 = 열람 불가). 이 목록도 줄이지 않는다
      'DOCUMENT_VIEW',
      'DOCUMENT_DOWNLOAD'
    )
  );

ALTER TABLE dashboard_admin_activity_history
  ADD CONSTRAINT dashboard_admin_activity_history_target_type_check CHECK (
    target_type IN ('ADMIN', 'POLICY', 'DOCUMENT', 'EVENT', 'REPORT', 'KEYWORD', 'GPU', 'GATEWAY')
  );

