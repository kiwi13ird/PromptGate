import { describe, expect, it } from 'vitest';
import { preferredPassageIndex } from './evidencePresentation';

describe('matched passage display preference', () => {
  it('preserves the order of actual matches rather than favoring presentation content', () => {
    const passages=[{input_text:'이 문서는 가상의 반도체 공정을 설명하는 시연용 문서입니다.'},{input_text:'실제 기업의 기술이나 사람에 관한 정보는 포함하지 않습니다.'},{input_text:'목표는 외부 AI로 보낸 입력과 등록 문서의 일치 구간을 검증하는 것입니다.'},{input_text:'공정의 상세 내용과 승인 절차입니다.'}];
    expect(preferredPassageIndex(passages)).toBe(0);
    expect(passages[0].input_text).toContain('시연용 문서');
  });
  it('keeps the only available match, including a disclaimer, and handles no matches', () => {
    expect(preferredPassageIndex([{input_text:'시연용 문서'}])).toBe(0);
    expect(preferredPassageIndex([])).toBe(0);
    expect(preferredPassageIndex([{input_text:'가상 공정에서 사용하는 부품 목록'}])).toBe(0);
    expect(preferredPassageIndex([{input_text:'  '},{input_text:'기록된 첫 본문'}])).toBe(1);
  });
});
