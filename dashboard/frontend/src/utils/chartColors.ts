// 차트 색: 색 코드를 차트 코드에 직접 쓰지 않고 디자인 값(CSS 변수, src/styles/tokens.css)에서 읽는다(설계 3.2).
// 돌려주는 값은 var(--pg-…) 참조라 브라우저가 그릴 때 그 순간의 값을 쓴다 → 라이트·다크(OS 설정)가 바뀌어도 다시 그릴 필요가 없다.
// SVG 속성(fill·stroke)과 인라인 style 모두 var()를 받는다. 이벤트 화면 차트에는 쓰지 않는다(이벤트 화면은 옛 모양 유지, 설계 5.2).

/** 차트에서 쓰는 이름 → 디자인 값 이름(--pg-*) */
export const CHART_TOKENS = {
  block: 'block-solid', // 차단·끊김·실패
  mask: 'mask-solid', // 마스킹·느림·주의
  allow: 'allow-solid', // 허용·정상 (막대는 ALLOW_OPACITY로 흐리게)
  info: 'info-solid', // 진행·안내(처리 시간 P95 등)
  neutral: 'neutral-solid', // 중립(평균 등 보조 선)
  grid: 'border', // 격자선
  axis: 'text-3', // 축 글자
  cursor: 'surface-3', // 막대 위 마우스 표시
  tooltipBackground: 'surface',
  tooltipBorder: 'border',
  tooltipText: 'text',
  legendText: 'text-2', // 범례 글자(Recharts 기본은 계열 색이라 옅은 계열은 읽기 어려움)
} as const;

export type ChartColorName = keyof typeof CHART_TOKENS;

/** 허용은 정상 계열 50% 투명(눈이 차단·마스킹 쪽으로 가게, 설계 3.2) */
export const ALLOW_OPACITY = 0.5;

/** 차트 축 글자 크기: 최소 글자 크기(--pg-t-xs, 12px)와 같은 값. Recharts tick의 fontSize는 숫자만 받는다 */
export const CHART_TICK_FONT_SIZE = 12;

export function chartColor(name: ChartColorName): string {
  return `var(--pg-${CHART_TOKENS[name]})`;
}

export type ChartColors = Record<ChartColorName, string> & { allowOpacity: number };

/** 차트 색 한 벌(var(--pg-…) 참조). 상태 색 5계열 + 격자·축·툴팁 */
export function chartColors(): ChartColors {
  const colors = Object.fromEntries(
    (Object.keys(CHART_TOKENS) as ChartColorName[]).map((name) => [name, chartColor(name)]),
  ) as Record<ChartColorName, string>;
  return { ...colors, allowOpacity: ALLOW_OPACITY };
}
