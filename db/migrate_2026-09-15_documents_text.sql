-- 2026-09-15 documents에 인덱서가 만든 정규화 텍스트를 저장한다.
-- 이유: 판정의 doc_span 좌표는 정규화 텍스트 기준이다. 대시보드·LLM Judge가 파서 없이 SQL로 구간을 자르게 한다.
--       텍스트는 Detection 인덱서가 원본에서 만든 것이라 탐지 색인과 좌표가 정확히 맞는다. 원본(original)은 그대로 둔다.
-- 실행: psql "$DETECTION_PG_DSN" -v ON_ERROR_STOP=1 -f migrate_2026-09-15_documents_text.sql

BEGIN;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS format text;             -- 인덱서가 판별한 실제 형식 pdf | docx | xlsx
ALTER TABLE documents ADD COLUMN IF NOT EXISTS normalized_text text;    -- 인덱서가 원본에서 만든 정규화 텍스트 (doc_span 좌표 기준)
ALTER TABLE documents ADD COLUMN IF NOT EXISTS text_chars integer;      -- normalized_text 글자 수
COMMIT;
