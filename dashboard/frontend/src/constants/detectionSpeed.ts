// Detection 실측 최악 속도(2026-10-10, 판정 기록 28,487행 중 5천 자 이상·일치 없음의 천 자당 최댓값).
// Gateway `gateway_settings.py`의 DETECTION_WORST_MS_PER_1K_CHARS와 같은 값이어야 한다. 배포 전 왕복 측정으로만 바꾼다.
export const WORST_MS_PER_1K_CHARS = 24.8;

/** 대기 시간(초) 안에 Detection이 검사할 수 있는 글자 수. Gateway와 같은 식(floor(T × 1,000,000 ÷ 24.8))·같은 계산 순서. */
export function maxCharsForWait(seconds: number): number {
  if (!Number.isFinite(seconds) || seconds <= 0) return 0;
  return Math.floor((seconds * 1_000_000) / WORST_MS_PER_1K_CHARS);
}
