-- MVP 스키마 (2026-09-14 확정) — 표 2개. Judge·역할·코퍼스 이력·본문 캐시는 만들지 않는다.
-- 실행: PGSSLMODE=require psql -h <endpoint> -U postgres -d dlp -v ON_ERROR_STOP=1 -f schema_mvp.sql
-- 원칙: DB는 원본·상태·판정과, Detection 인덱서가 만든 정규화 텍스트(2026-09-15)를 갖는다. 파싱·정규화·창 해시는 Detection이 하고, 창 해시는 Redis에만 있다.

BEGIN;

-- 1. 기밀문서: 원본 파일 + 등록·색인 상태
CREATE TABLE IF NOT EXISTS documents (
    doc_id         text PRIMARY KEY,                 -- 파일 이름(확장자 제외). Redis·판정 기록의 doc_id와 동일
    filename       text NOT NULL,                    -- 원본 파일명(확장자 포함) — 파서가 형식을 고르는 근거
    original       bytea NOT NULL,                   -- 원본 파일 바이트 (docx / xlsx / pdf)
    version        integer NOT NULL DEFAULT 1,       -- 같은 doc_id 재등록마다 +1
    title          text,
    classification text,                             -- 대외비 등급 (대시보드 표시용)
    status         text NOT NULL DEFAULT 'active'  CHECK (status IN ('active', 'retired')),
    index_status   text NOT NULL DEFAULT 'pending' CHECK (index_status IN ('pending', 'indexing', 'indexed', 'error')),
    index_windows  integer,                          -- Detection 인덱서가 채움: 적재된 창 수
    format         text,                             -- 인덱서가 판별한 실제 형식 pdf | docx | xlsx (2026-09-15)
    normalized_text text,                            -- 인덱서가 원본에서 만든 정규화 텍스트. doc_span 좌표 기준 (2026-09-15)
    text_chars     integer,                          -- normalized_text 글자 수 (2026-09-15)
    index_error    text,
    registered_at  timestamptz NOT NULL DEFAULT now(),
    registered_by  text,
    indexed_at     timestamptz,
    retired_at     timestamptz
);
CREATE INDEX IF NOT EXISTS idx_documents_pending ON documents (index_status) WHERE index_status IN ('pending', 'error');

-- 2. 판정 기록: /detect 한 건 = 한 행. 탐지 API는 로그 파일에 쓰고 detection-logshipper가 옮긴다(2026-09-15). PII 값·사용자 식별자는 없다(입력 본문은 prompt).
CREATE TABLE IF NOT EXISTS decisions (
    decision_id      uuid PRIMARY KEY,               -- 판정마다 탐지 API가 만든 UUID (2026-09-15). 전송 서비스 재전송 시 중복 방지
    request_id       text NOT NULL,                  -- Gateway 발급. 같은 값이 두 번 올 수 있다(두 판정 모두 남긴다)
    ts               timestamptz NOT NULL,
    service          text,                           -- OpenAI / ChatGPT …
    format           text,                           -- chatgpt_web / openai_responses …
    text_chars       integer NOT NULL,
    blocked          boolean NOT NULL,
    decided_by       text NOT NULL CHECK (decided_by IN ('windowhash', 'signature', 'none')),
    doc_id           text,                           -- 해시 차단일 때 근거 문서
    doc_span         text,                           -- 문서 쪽 구간 "216-516" (정규화 텍스트 좌표)
    input_span       text,                           -- 입력 쪽 구간 "0-300"
    score            real,                           -- 일치율 0~1 (입력 중 문서와 그대로 겹친 비율)
    pii_hits         text,                           -- 패턴 차단일 때 "KR_RRN:1,KR_PHONE:2" (값 없음)
    reason           text NOT NULL,                  -- 사람용 한 줄
    hash_status      text NOT NULL CHECK (hash_status IN ('ok', 'error')),
    signature_status text NOT NULL CHECK (signature_status IN ('ok', 'error', 'skipped')),
    total_ms         real NOT NULL,
    prompt           text,                           -- 정규화된 입력 본문 (차단·통과 모두). 보존 기간 지나면 null
    prompt_kept      boolean NOT NULL DEFAULT true    -- prompt를 지웠으면 false
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts        ON decisions (ts);
CREATE INDEX IF NOT EXISTS idx_decisions_blocked   ON decisions (blocked, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_doc       ON decisions (doc_id);
CREATE INDEX IF NOT EXISTS idx_decisions_request   ON decisions (request_id);

COMMIT;
