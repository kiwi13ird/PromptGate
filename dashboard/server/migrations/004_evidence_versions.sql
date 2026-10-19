-- 2026-10-10: 운영 DB에는 있으나 설치 파일에 없던 근거 화면용 정의. 운영 DB 정의를 그대로 옮겼고, 다시 실행해도 안전하다.
-- 마스킹 전후 증거(Gateway가 보낸 가린 결과)
ALTER TABLE dashboard_security_events ADD COLUMN IF NOT EXISTS gateway_evidence jsonb;

-- 사건 당시 보호 문서 본문 스냅숏(문서 일치 근거 비교용). 추가만 가능, 수정·삭제 불가
CREATE TABLE IF NOT EXISTS dashboard_document_versions (
  doc_id text NOT NULL,
  version bigint NOT NULL,
  filename text NOT NULL,
  normalized_text text NOT NULL,
  normalized_sha256 text NOT NULL CHECK (normalized_sha256 ~ '^[0-9a-f]{64}$'),
  captured_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (doc_id, version)
);

CREATE OR REPLACE FUNCTION dashboard_immutable_document_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'Document evidence versions are append-only';
END;
$$;

DROP TRIGGER IF EXISTS dashboard_document_versions_immutable ON dashboard_document_versions;
CREATE TRIGGER dashboard_document_versions_immutable
  BEFORE UPDATE OR DELETE ON dashboard_document_versions
  FOR EACH ROW EXECUTE FUNCTION dashboard_immutable_document_version();
