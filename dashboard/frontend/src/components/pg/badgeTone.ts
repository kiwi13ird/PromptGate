// 배지 값 → 색 계열(설계 3.2·4.4). 상태 표시는 이 다섯 계열만 쓴다. 브랜드 초록은 상태에 쓰지 않는다.
export type BadgeTone = 'block' | 'mask' | 'allow' | 'info' | 'neutral';

/**
 * 설계 4.4 표 그대로 + 표에 없던 값(각 줄의 '추가' 뒤). 표에 없는 값은 중립.
 * 추가: 상태 띠와 같은 단어(이상·주의), 위험도 높음·중간·낮음(3.2 위험도 단계), 조치 코드 BLOCK·MASK·ALLOW,
 *       보호 문서 상태(분석 실패·준비 확인 필요·보호 중지 — documentProtectionStage의 글자).
 */
export const BADGE_TONE_VALUES: Readonly<Record<BadgeTone, readonly string[]>> = {
  block: ['차단', '끊김', '추출 실패', '인스턴스 이상', '차단 중', /* 추가 */ '이상', '높음', '위험 높음', 'BLOCK', '분석 실패'],
  mask: ['마스킹', '느림', '일반 표현', '탐지 반영 실패', /* 추가 */ '주의', '중간', '위험 중간', 'MASK', '준비 확인 필요'],
  allow: ['허용', '정상', '보호 중', '완료', '실행 중', '활성', '연결 중', /* 추가 */ 'ALLOW'],
  info: ['승인 대기', '분석 중', '처리 중', '시작 중', '생성 중', '조사 중'],
  neutral: ['확인 불가', '중지됨', '비활성', '최근 활동', '해당 없음', /* 추가 */ '낮음', '위험 낮음', '보호 중지'],
};

const TONE_BY_VALUE: ReadonlyMap<string, BadgeTone> = new Map(
  (Object.entries(BADGE_TONE_VALUES) as Array<[BadgeTone, readonly string[]]>).flatMap(([tone, values]) => values.map((value) => [value, tone] as const)),
);

/** 값(화면에 보이는 글자 또는 조치 코드) → 계열. 앞뒤 공백은 무시. 모르는 값은 중립 */
export function badgeTone(value: string | null | undefined): BadgeTone {
  if (!value) return 'neutral';
  return TONE_BY_VALUE.get(value.trim()) ?? 'neutral';
}
