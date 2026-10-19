// '일치 비율' 하나의 정의(2026-10-16): 입력 중 보호 문서와 같은 글자 비율. 화면·대시보드 서버가 같은 원본을 쓰는지까지 본다.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { computeMatchRatio, formatSameRatio, matchRatioSummary, ratioOf } from './matchRatio';

const plain = (text: string) => ({ text, runs: [] });
const doc = ['머리말은 입력에 없다.', '당사 초기 제시안은 수수료율 20%이다.', '계약 기간은 2년으로 한다.', '부록도 입력에 없다.'].join('\n');
const input = ['이걸 메일로 바꿔줘.', '당사 초기 제시안은 수수료율 18%이다.', '계약 기간은 2년으로 한다.'].join('\n');

describe('같은 글자 비율', () => {
  it('= (입력의 공백 뺀 글자 - 다른 글자) ÷ 입력의 공백 뺀 글자, 다른 곳 = 입력에 대응하는 범위 안의 다른 곳', () => {
    const result = computeMatchRatio(plain(input), plain(doc), { coverage: 0.5 });
    if (result.state !== 'READY') throw new Error(result.reason);
    expect(result.differences).toBe(2);
    expect(result.ratio).toBeCloseTo((result.diff.aChars - result.diff.aChangedChars) / result.diff.aChars, 12);
    const summary = matchRatioSummary(result);
    expect(summary).toEqual({ state: 'READY', same_chars: result.diff.aChars - result.diff.aChangedChars, input_chars: result.diff.aChars, differences: 2 });
    expect(formatSameRatio(ratioOf(summary.same_chars!, summary.input_chars!))).toBe(formatSameRatio(result.ratio));
  });
  it('표시는 소수 첫째 자리 내림, 다른 글자가 있으면 100%로 올리지 않는다', () => {
    expect(formatSameRatio(1)).toBe('100.0%');
    expect(formatSameRatio(0.99999)).toBe('99.9%');
    expect(formatSameRatio(0.9989)).toBe('99.8%');
    expect(formatSameRatio(0)).toBe('0.0%');
  });
  it('서버 확인과 어긋나면 대조 불가(전부 다름이라 하지 않음)', () => {
    const result = computeMatchRatio(plain('전혀 다른 글'), plain('문서 본문'), { coverage: 0.9 });
    expect(result.state).toBe('UNAVAILABLE');
    expect(matchRatioSummary(result)).toEqual({ state: 'UNAVAILABLE', reason: '서버 일치 비율과 대조 결과가 맞지 않아' });
  });
});

describe('대시보드 서버 모듈(match-ratio.mjs)은 이 원본을 묶은 것이라 결과가 같다', () => {
  it('scripts/build-match-ratio.mjs로 만든 모듈과 같은 값', async () => {
    const cache = path.join(process.cwd(), 'node_modules', '.cache');   // 시험 로더가 프로젝트 밖 파일은 못 읽는다
    mkdirSync(cache, { recursive: true });
    const dir = mkdtempSync(path.join(cache, 'match-ratio-'));
    try {
      const out = path.join(dir, 'match-ratio.mjs');
      execFileSync(process.execPath, ['scripts/build-match-ratio.mjs', out], { cwd: process.cwd(), stdio: 'pipe' });
      const server = await import(/* @vite-ignore */ pathToFileURL(out).href);
      const masked = { text: '접속키 ██████ 끝\n당사 초기 제시안은 수수료율 18%이다.', runs: [{ start: 4, end: 10 }] };
      const maskedDoc = { text: '접속키 ████ 끝\n당사 초기 제시안은 수수료율 20%이다.\n부록', runs: [{ start: 4, end: 8 }] };
      for (const [a, b, facts] of [[plain(input), plain(doc), { coverage: 0.5 }], [masked, maskedDoc, { coverage: 0.7 }], [plain('전혀 다른 글'), plain('문서 본문'), { coverage: 0.9 }]] as const) {
        expect(server.matchRatioSummary(server.computeMatchRatio(a, b, facts))).toEqual(matchRatioSummary(computeMatchRatio(a, b, facts)));
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
