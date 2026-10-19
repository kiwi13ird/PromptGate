import { describe, expect, it } from 'vitest';
import { collapseRedactions } from './redactedText';
import { anchorOn, renderedRanges, structureUnits } from './textStructure';

const units = (text: string) => collapseRedactions(text, []).units;
const textOf = (all: ReturnType<typeof units>, range: { start: number; end: number }) => all.slice(range.start, range.end).join('');

describe('추출 텍스트의 글 구조', () => {
  it('번호 제목·문단·빈 줄·" | " 표 묶음을 나눈다(표 첫 줄은 머리글 자리)', () => {
    const text = ['14. 상세 로드맵 (스프린트/월 단위)', '13절 개요를 실행 단위인 2주 스프린트로 세분화한 일정은 표7과 같다.', '', '시기 | 마일스톤 | 게이트/승인', '2026-08 (Sprint 1-2) | 모델 후보 비교 완료 | AI팀 승인', '2026-09 (Sprint 3-4) | 데이터 파이프라인 | 보안팀 검수 통과', '2-1. TBS (Tokyo Bridge Solutions K.K.)'].join('\n');
    const all = units(text);
    const blocks = structureUnits(all);
    expect(blocks.map((block) => block.kind)).toEqual(['heading', 'paragraph', 'blank', 'table', 'heading']);
    const table = blocks[3];
    if (table.kind !== 'table') throw new Error('표가 아님');
    expect(table.rows.map((row) => row.cells.map((cell) => textOf(all, cell)))).toEqual([
      ['시기', '마일스톤', '게이트/승인'], ['2026-08 (Sprint 1-2)', '모델 후보 비교 완료', 'AI팀 승인'], ['2026-09 (Sprint 3-4)', '데이터 파이프라인', '보안팀 검수 통과']]);
  });
  it('번호로 시작해도 문장으로 끝나면 문단, 숫자 뒤 마침표 없는 줄도 문단', () => {
    const blocks = structureUnits(units('3. 선정 모델은 후보 D로 확정하였다.\n2 개 후보는 탈락\n1.2 적용 범위'));
    expect(blocks.map((block) => block.kind)).toEqual(['paragraph', 'paragraph', 'heading']);
  });
  it('가림 덩어리가 있는 표 칸도 칸 하나로 남는다', () => {
    const collapsed = collapseRedactions('항목 | 값\n접속키 | ██████', [{ start: 13, end: 19 }]);
    const blocks = structureUnits(collapsed.units);
    if (blocks[0].kind !== 'table') throw new Error('표가 아님');
    expect(blocks[0].rows[1].cells.at(-1)).toEqual({ start: collapsed.toUnit[13], end: collapsed.units.length });
    expect(collapsed.units.at(-1)).toEqual({ redacted: 6 });
  });
  it('이동 표시는 그려지는 글자 위로(줄바꿈·칸 구분 자리 → 다음 글자, 글 끝 → 마지막 글자)', () => {
    const all = units('가나\n다 | 라');
    const drawn = renderedRanges(structureUnits(all));
    expect(drawn).toEqual([{ start: 0, end: 2 }, { start: 3, end: 4 }, { start: 7, end: 8 }]);
    expect(anchorOn(drawn, 2)).toBe(3);
    expect(anchorOn(drawn, 4)).toBe(7);
    expect(anchorOn(drawn, 8)).toBe(7);
  });
});
