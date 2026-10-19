import { describe, expect, it } from 'vitest';
import { displayRequestPath, missingDetectionTitle } from './eventPresentation';

describe('truthful and safe event presentation', () => {
  it('does not confuse failed detection or missing evidence with no match', () => {
    expect(missingDetectionTitle('UNAVAILABLE')).toBe('탐지 결과 확인 불가');
    expect(missingDetectionTitle('MATCH')).toBe('탐지됨 · 상세 근거 미기록');
    expect(missingDetectionTitle('NO_MATCH')).toBe('일치한 문서·민감정보 없음');
  });
  it('hides all query and fragment values while retaining the host and route', () => {
    expect(displayRequestPath('example.test', '/prompt?token=private&query=text#private')).toBe('example.test/prompt');
    expect(displayRequestPath('example.test', '/prompt#private')).toBe('example.test/prompt');
    expect(displayRequestPath('example.test', '/prompt')).toBe('example.test/prompt');
    expect(displayRequestPath()).toBe('—');
  });
});
