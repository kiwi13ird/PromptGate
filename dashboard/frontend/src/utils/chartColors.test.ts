import { describe, expect, it } from 'vitest';
import { ALLOW_OPACITY, CHART_TOKENS, chartColor, chartColors } from './chartColors';

describe('차트 색 함수', () => {
  it('상태 색은 디자인 값(--pg-*-solid) 참조로만 돌려준다(색 코드 없음)', () => {
    expect(chartColor('block')).toBe('var(--pg-block-solid)');
    expect(chartColor('mask')).toBe('var(--pg-mask-solid)');
    expect(chartColor('allow')).toBe('var(--pg-allow-solid)');
    const colors = chartColors();
    for (const name of Object.keys(CHART_TOKENS) as (keyof typeof CHART_TOKENS)[]) {
      expect(colors[name]).toMatch(/^var\(--pg-[a-z0-9-]+\)$/);
    }
  });

  it('허용은 50% 투명', () => {
    expect(chartColors().allowOpacity).toBe(ALLOW_OPACITY);
    expect(ALLOW_OPACITY).toBe(0.5);
  });
});
