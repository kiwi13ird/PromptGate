-- 기밀문서 단일 저장소 + 판정·검토·Judge 표. 설계: docs/pipelines/confidential-document-store-design.md §2
-- PostgreSQL 16 기준. 실행: psql -h <RDS endpoint> -U dlp_admin -d dlp -f schema.sql
-- 2026-09-10 · 아직 실행 전(설계 산출물)

BEGIN;

-- 1. 기밀문서 (세 소비자가 공유하는 유일한 본문)
CREATE TABLE IF NOT EXISTS documents (
    doc_id          text PRIMARY KEY,
    version         integer NOT NULL DEFAULT 1,
    title           text,
    classification  text,
    source_uri      text NOT NULL,
    source_sha256   text NOT NULL,
    normalized_text text NOT NULL,
    text_chars      integer NOT NULL,
    status          text NOT NULL DEFAULT 'active'  CHECK (status IN ('active', 'retired')),
    index_status    text NOT NULL DEFAULT 'pending' CHECK (index_status IN ('pending', 'indexing', 'indexed', 'error')),
    index_window    integer,
    index_windows   integer,
    index_error     text,
    registered_at   timestamptz NOT NULL DEFAULT now(),
    registered_by   text,
    indexed_at      timestamptz,
    retired_at      timestamptz
);
CREATE INDEX IF NOT EXISTS idx_documents_index_status ON documents (index_status) WHERE index_status IN ('pending', 'error');

-- 문서 추가·교체·퇴역마다 +1. decisions.corpus_version 이 가리킨다.
CREATE TABLE IF NOT EXISTS corpus_versions (
    version     bigserial PRIMARY KEY,
    changed_at  timestamptz NOT NULL DEFAULT now(),
    doc_id      text NOT NULL,
    action      text NOT NULL CHECK (action IN ('add', 'replace', 'retire'))
);

-- 인덱서 알림(선택: 폴링만 쓰면 없어도 됨)
CREATE OR REPLACE FUNCTION notify_documents_changed() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('documents_changed', NEW.doc_id);
    RETURN NEW;
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_documents_changed ON documents;
CREATE TRIGGER trg_documents_changed
    AFTER INSERT OR UPDATE OF normalized_text, status ON documents
    FOR EACH ROW EXECUTE FUNCTION notify_documents_changed();

-- 2. 판정 로그 (detection-decision-log-design.md §3 스키마)
CREATE TABLE IF NOT EXISTS decisions (
    request_id      text PRIMARY KEY,
    ts              timestamptz NOT NULL,
    service         text,
    format          text,
    text_chars      integer NOT NULL,
    compact_chars   integer NOT NULL,
    blocked         boolean NOT NULL,
    decided_by      text NOT NULL CHECK (decided_by IN ('windowhash', 'signature', 'none')),
    reason          text NOT NULL,
    hash            jsonb NOT NULL,
    signature       jsonb NOT NULL,
    total_ms        real NOT NULL,
    engine          jsonb NOT NULL,
    corpus_version  bigint,
    judge           jsonb
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions (ts);
CREATE INDEX IF NOT EXISTS idx_decisions_blocked_ts ON decisions (blocked, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_doc ON decisions ((hash->>'doc_id'));

-- 3. 검토용 본문 (원문. 짧게 보관, 접근 제한)
CREATE TABLE IF NOT EXISTS review_texts (
    request_id  text PRIMARY KEY REFERENCES decisions (request_id) ON DELETE CASCADE,
    ts          timestamptz NOT NULL,
    text        text NOT NULL,
    expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_expires ON review_texts (expires_at);

-- 4. Judge 라벨·사람 검토·리포트 (llm-judge-model-and-prompt-design.md §2.5, llm-judge-implementation-design.md E)
CREATE TABLE IF NOT EXISTS judge_labels (
    request_id      text PRIMARY KEY REFERENCES decisions (request_id),
    judged_at       timestamptz NOT NULL DEFAULT now(),
    model           text NOT NULL,
    prompt_version  text NOT NULL,
    votes           jsonb NOT NULL,
    verdict         text NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'false_negative', 'true_negative', 'expired', 'error')),
    agreement       real,
    cause           text,
    confidence      real,
    matched_doc_id  text,
    rationale       text,
    needs_human     boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_judge_labels_verdict ON judge_labels (verdict, judged_at);

CREATE TABLE IF NOT EXISTS human_queue (
    request_id   text PRIMARY KEY REFERENCES decisions (request_id),
    queued_at    timestamptz NOT NULL DEFAULT now(),
    reason       text NOT NULL,
    resolved_at  timestamptz,
    resolved_by  text,
    resolution   text
);

CREATE TABLE IF NOT EXISTS judge_reports (
    id            bigserial PRIMARY KEY,
    period_start  date NOT NULL,
    period_end    date NOT NULL,
    generated_at  timestamptz NOT NULL DEFAULT now(),
    model         text,
    report        jsonb NOT NULL,
    approved_by   text,
    approved_at   timestamptz,
    applied       boolean NOT NULL DEFAULT false
);

-- 5. 역할 (비밀번호는 생성 시 별도 지정. GRANT는 표 생성 뒤)
-- dlp_indexer   : documents 읽기 + index_* 갱신
-- dlp_detection : decisions/review_texts 쓰기, documents/corpus_versions 메타 읽기
-- dlp_judge     : documents.normalized_text 읽기, review_texts 읽기, judge_labels/human_queue/judge_reports 쓰기
-- dlp_dashboard : 메타·집계 읽기(본문 열은 별도 권한자 뷰로만)
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dlp_indexer')   THEN CREATE ROLE dlp_indexer   LOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dlp_detection') THEN CREATE ROLE dlp_detection LOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dlp_judge')     THEN CREATE ROLE dlp_judge     LOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dlp_dashboard') THEN CREATE ROLE dlp_dashboard LOGIN; END IF;
END $$;

GRANT SELECT ON documents, corpus_versions TO dlp_indexer, dlp_detection, dlp_judge;
GRANT UPDATE (index_status, index_window, index_windows, index_error, indexed_at) ON documents TO dlp_indexer;
GRANT INSERT ON decisions, review_texts TO dlp_detection;
GRANT SELECT ON decisions TO dlp_detection, dlp_judge, dlp_dashboard;
GRANT SELECT, DELETE ON review_texts TO dlp_judge;
GRANT DELETE ON review_texts TO dlp_detection;                       -- 보존 기간 지난 행 삭제
GRANT SELECT, INSERT, UPDATE ON judge_labels, human_queue, judge_reports TO dlp_judge;
GRANT USAGE, SELECT ON SEQUENCE judge_reports_id_seq, corpus_versions_version_seq TO dlp_judge, dlp_indexer, dlp_detection;
GRANT SELECT ON judge_labels, human_queue, judge_reports TO dlp_dashboard;
GRANT SELECT (doc_id, version, title, classification, status, index_status, index_windows, registered_at, indexed_at, retired_at) ON documents TO dlp_dashboard;

COMMIT;
