-- 판정 기록에 가린 결과·위치·본문 순번 (2026-10-09, 운영 RDS 적용 완료)
-- Detection이 계산해 Gateway에 주던 가린 결과를 기록에도 남긴다. 파일 업로드의 칸별 전·후 비교 화면이 쓴다.
-- 비어 있는 열 추가라 기존 행은 바뀌지 않는다. 다시 실행해도 된다.
ALTER TABLE decisions
  ADD COLUMN IF NOT EXISTS masked_text text,
  ADD COLUMN IF NOT EXISTS findings jsonb,
  ADD COLUMN IF NOT EXISTS block_order integer;

COMMENT ON COLUMN decisions.masked_text IS '가린 뒤 텍스트(prompt와 같은 정규화 좌표). 가렸을 때만 (2026-10-09)';
COMMENT ON COLUMN decisions.findings IS '가린 위치·유형·바꾼 값(값 없음). prompt 좌표, 옮길 수 없으면 위치 생략 (2026-10-09)';
COMMENT ON COLUMN decisions.block_order IS '파일 칸의 본문 순번(문단·표 앞뒤 복원용) (2026-10-09)';
