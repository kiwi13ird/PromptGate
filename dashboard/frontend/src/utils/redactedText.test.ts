import { describe, expect, it } from 'vitest';
import { MASK_TOKEN, collapseRedactions, joinSegments } from './redactedText';
import { diffIgnoringWhitespace } from './textDiff';

describe('가림(█) 덩어리 접기', () => {
  it('쪽 조각의 redacted 표시를 이어 붙여 가림 구간을 만들고(쪽 경계를 넘어도 한 덩어리)', () => {
    const joined = joinSegments([[{ text: '키 ', redacted: false }, { text: '██', redacted: true }], [{ text: '███', redacted: true }, { text: ' 끝', redacted: false }]]);
    expect(joined.text).toBe('키 █████ 끝');
    expect(joined.runs).toEqual([{ start: 2, end: 7 }]);
  });
  it('가림 한 덩어리는 단위 하나·대조 글자 하나가 되고, 원래 좌표 → 단위 좌표를 준다', () => {
    const collapsed = collapseRedactions('키 █████ 끝', [{ start: 2, end: 7 }]);
    expect(collapsed.units).toEqual(['키', ' ', { redacted: 5 }, ' ', '끝']);
    expect(collapsed.text).toBe(`키 ${MASK_TOKEN} 끝`);
    expect(Array.from(collapsed.toUnit)).toEqual([0, 1, 2, 2, 2, 2, 2, 3, 4, 5]);
    expect(collapsed.redactions).toBe(1);
  });
  it('양쪽이 같은 자리를 가렸으면 가린 글자 수가 달라도 다름이 아니다', () => {
    const left = collapseRedactions('접속키 ████████████ 끝', [{ start: 4, end: 16 }]);
    const right = collapseRedactions('접속키 ██████ 끝', [{ start: 4, end: 10 }]);
    expect(diffIgnoringWhitespace(left.text, right.text).a).toEqual([]);
  });
  it('redacted 표시가 없는 진짜 █ 글자는 그대로 둔다', () => {
    expect(collapseRedactions('표 █ 칸', []).units).toEqual(['표', ' ', '█', ' ', '칸']);
  });
});
