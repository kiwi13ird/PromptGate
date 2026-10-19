import { describe, expect, it } from 'vitest';
import { diffIgnoringWhitespace } from './textDiff';

const pick = (text: string, ranges: { start: number; end: number }[]) => ranges.map(range => Array.from(text).slice(range.start, range.end).join(''));

describe('보낸 입력 ↔ 보호 문서 다른 부분', () => {
  it('같은 글(공백·줄바꿈만 다름)은 다른 부분이 없다', () => {
    const result = diffIgnoringWhitespace('문서번호: NW-SEC-2026\n작성일: 2026-08-10', '문서번호:  NW-SEC-2026 작성일:\n\n2026-08-10');
    expect(result.a).toEqual([]);
    expect(result.b).toEqual([]);
    expect(result.complete).toBe(true);
  });
  it('조사 하나만 바뀌면 그 글자만 강조한다', () => {
    const a = '보안팀은 점검을 마쳤다.';
    const b = '보안팀이 점검을 마쳤다.';
    const result = diffIgnoringWhitespace(a, b);
    expect(pick(a, result.a)).toEqual(['은']);
    expect(pick(b, result.b)).toEqual(['이']);
  });
  it('끼워 넣은 문장·지운 문장은 한쪽에만 강조된다', () => {
    const a = '첫 문장입니다. 새로 넣은 문장입니다. 마지막 문장입니다.';
    const b = '첫 문장입니다. 마지막 문장입니다. 문서에만 있는 끝.';
    const result = diffIgnoringWhitespace(a, b);
    expect(pick(a, result.a)).toEqual(['새로 넣은 문장입니다.']);
    expect(pick(b, result.b)).toEqual(['문서에만 있는 끝.']);
  });
  it('좌표는 코드 포인트(이모지·4바이트 글자도 한 칸)', () => {
    const a = '😀 같은 글 차이A';
    const b = '😀 같은 글 차이B';
    const result = diffIgnoringWhitespace(a, b);
    expect(result.a).toEqual([{ start: 9, end: 10 }]);
    expect(pick(a, result.a)).toEqual(['A']);
  });
  it('공통 글자가 하나도 없으면 전부 다름', () => {
    const result = diffIgnoringWhitespace('가나다', '라마바');
    expect(result.aChangedChars).toBe(3);
    expect(result.bChangedChars).toBe(3);
  });
  it('빈 글', () => {
    expect(diffIgnoringWhitespace('', '')).toMatchObject({ a: [], b: [], complete: true });
    expect(pick('있음', diffIgnoringWhitespace('있음', '').a)).toEqual(['있음']);
  });
  it('1만 자 넘는 글에서 몇 군데만 바꿔도 바뀐 곳만 찾는다', () => {
    const lines = Array.from({ length: 400 }, (_, index) => `제${index + 1}조 보안 점검 항목 ${index}번은 정기적으로 확인한다.`);
    const doc = lines.join('\n');
    const edited = lines.map((line, index) => (index === 37 ? line.replace('정기적으로', '매주') : index === 250 ? `${line} 추가 문구.` : line)).join('\n');
    expect(doc.length).toBeGreaterThan(10_000);
    const result = diffIgnoringWhitespace(edited, doc);
    expect(result.complete).toBe(true);
    expect(pick(edited, result.a)).toEqual(['매주', '추가 문구.']);
    expect(pick(doc, result.b)).toEqual(['정기적으로']);
  });
  it('계산 한도를 넘으면 남은 부분을 통째로 다름으로 두고 complete=false', () => {
    const a = Array.from({ length: 3000 }, (_, index) => `가${index % 97}`).join(' ');
    const b = Array.from({ length: 3000 }, (_, index) => `가${(index * 7) % 101}`).join(' ');
    const result = diffIgnoringWhitespace(a, b, { budgetMs: 0 });
    expect(result.complete).toBe(false);
    expect(result.aChangedChars).toBeGreaterThan(0);
  });
});

describe('우연히 같은 짧은 조각', () => {
  it('넣은 문장이 문서의 흩어진 글자와 맞아도 문장 하나로 강조한다', () => {
    const doc = '목표 일정은 10월 계약 체결이며 최종 조건 확정은 대표이사 승인을 거친다.\n당사 초기 제시안: 수수료율 20%.';
    const input = '이 협상 조건 정리해서 일본어 메일로 바꿔줘.\n\n당사 초기 제시안: 수수료율 20%.';
    const result = diffIgnoringWhitespace(input, doc);
    // 끝의 '.'은 양쪽 묶음 끝에 같이 있어 같은 글자로 남는다(묶음 경계의 같은 글자는 흡수 대상이 아님)
    expect(pick(input, result.a)).toEqual(['이 협상 조건 정리해서 일본어 메일로 바꿔줘']);
    expect(pick(doc, result.b)).toEqual(['목표 일정은 10월 계약 체결이며 최종 조건 확정은 대표이사 승인을 거친다']);
  });
  it('긴 같은 부분은 흡수하지 않는다(두 군데 수정은 두 곳)', () => {
    const doc = '가 문장은 그대로 둔다 그리고 이 문장도 길게 그대로 남겨 둔다 나';
    const input = '다 문장은 그대로 둔다 그리고 이 문장도 길게 그대로 남겨 둔다 라';
    const result = diffIgnoringWhitespace(input, doc);
    expect(pick(input, result.a)).toEqual(['다', '라']);
  });
});

describe('보호 문서 일부만 붙여 넣은 입력(운영에서 흔한 모양, 2026-10-16 수정)', () => {
  it('문서 가운데 일부를 그대로 붙여 넣으면 붙여 넣은 본문은 같은 부분이고 앞의 질문만 다르다', () => {
    const lines = Array.from({ length: 120 }, (_, index) => `${index + 1}. 협상 조건 항목 ${index}에 대한 설명 문장으로 수수료율과 계약 기간을 다룬다.`);
    const doc = lines.join('\n');
    const excerpt = lines.slice(40, 46).join('\n');
    const input = `이 협상 조건 정리해서 일본어 메일로 바꿔줘.\n\n${excerpt}`;
    const result = diffIgnoringWhitespace(input, doc);
    expect(pick(input, result.a)).toEqual(['이 협상 조건 정리해서 일본어 메일로 바꿔줘']);
    // 문서 쪽: 붙여 넣은 6줄 앞뒤가 다른 부분(가운데 6줄은 같은 부분)
    expect(result.bChars - result.bChangedChars).toBeGreaterThanOrEqual(Array.from(excerpt.replace(/\s/gu, '')).length);
    expect(result.aChars - result.aChangedChars).toBe(Array.from(excerpt.replace(/\s/gu, '')).length + 1);   // 붙여 넣은 본문 + 질문 끝 '.'
  });
});

describe('붙여 넣은 본문 앞뒤에 질문이 있어도', () => {
  it('앞 질문·뒤 요청만 다르고 가운데 문서 본문은 같은 부분이다(문서 쪽은 붙여 넣지 않은 앞뒤만 다름)', () => {
    const lines = Array.from({ length: 80 }, (_, index) => `제${index + 1}항 공정 조건 ${index}번은 분기마다 점검하고 결과를 경영기획실에 보고한다.`);
    const doc = lines.join('\n');
    const excerpt = lines.slice(30, 34).join('\n');
    const input = `다음 내용 요약해줘.\n${excerpt}\n위 내용 표로 정리해줘.`;
    const result = diffIgnoringWhitespace(input, doc);
    expect(pick(input, result.a)).toEqual(['다음 내용 요약해줘', '위 내용 표로 정리해줘']);
    expect(pick(doc, result.b).join('')).not.toContain('제31항');
  });
});

describe('입력에 대응하는 문서 범위(bSpan)·대응 묶음(hunks)', () => {
  it('문서 뒤 부록을 지운 자리를 글 끝으로 밀어, 우연히 같은 끝 글자로 범위가 늘지 않는다', () => {
    const doc = '머리말은 입력에 없다.\n본문 첫 문장이다.\n본문 둘째 문장이다.\n부록도 입력에 없다.';
    const input = '본문 첫 문장이다.\n본문 둘째 문장이다.';
    const result = diffIgnoringWhitespace(input, doc);
    expect(pick(doc, result.bSpan ? [result.bSpan] : [])).toEqual(['본문 첫 문장이다.\n본문 둘째 문장이다.']);
    expect(result.a).toEqual([]);
    expect(result.hunks.every((hunk) => !hunk.a)).toBe(true);   // 입력 쪽은 다른 곳 없음
  });
  it('대응 묶음은 양쪽 위치를 함께 준다(한쪽에만 있으면 다른 쪽은 그 자리만)', () => {
    const result = diffIgnoringWhitespace('가 나 다 라 마', '가 나 바 라 마 사');
    expect(result.hunks.map((hunk) => [hunk.a && pick('가 나 다 라 마', [hunk.a])[0], hunk.b && pick('가 나 바 라 마 사', [hunk.b])[0]])).toEqual([['다', '바'], [undefined, '사']]);
  });
});
