// 근거 본문의 가림 표시 정리(2026-10-16). 서버(match-evidence.mjs redactEvidence)는 토큰·비밀번호·키·주민번호·전화·이메일을
// 값의 글자 수만큼 '█'로 바꾸고, 쪽 응답 조각마다 redacted:true를 단다. 이 길이 그대로 그리면 █ 줄이 길게 이어져 줄을 넘기므로
// 가림 한 덩어리를 짧은 표시 하나로 접고, 대조할 때도 한 글자(사용자 영역 U+E000)로 바꿔 양쪽이 같은 자리를 가렸으면 '같음'으로 본다
// (가린 값끼리는 실제로 같은지 알 수 없으므로 세부 정보에 그 기준을 적는다).
import type { DiffRange } from './textDiff';

export const MASK_TOKEN = '';
export type TextUnit = string | { redacted: number };

export interface CollapsedText {
  /** 화면·대조 단위: 글자 하나 또는 가림 한 덩어리(원래 글자 수) */
  units: TextUnit[];
  /** 대조용 글: 가림 덩어리 = MASK_TOKEN 한 글자 */
  text: string;
  /** 원래 코드 포인트 위치 → 단위 위치(길이 = 원래 길이 + 1) */
  toUnit: Int32Array;
  redactions: number;
}

/** runs: 가림 구간(원래 코드 포인트 좌표, 쪽 응답의 redacted 조각을 이어 붙인 것) */
export function collapseRedactions(original: string, runs: readonly DiffRange[]): CollapsedText {
  const chars = Array.from(original);
  const sorted = runs.filter((run) => run.end > run.start).slice().sort((a, b) => a.start - b.start);
  const units: TextUnit[] = [];
  const toUnit = new Int32Array(chars.length + 1);
  let at = 0;
  for (const run of sorted) {
    const start = Math.max(at, Math.min(chars.length, run.start));
    const end = Math.max(start, Math.min(chars.length, run.end));
    for (; at < start; at++) { toUnit[at] = units.length; units.push(chars[at]); }
    if (end > start) {
      for (; at < end; at++) toUnit[at] = units.length;
      units.push({ redacted: end - start });
    }
  }
  for (; at < chars.length; at++) { toUnit[at] = units.length; units.push(chars[at]); }
  toUnit[chars.length] = units.length;
  return { units, text: units.map((unit) => (typeof unit === 'string' ? unit : MASK_TOKEN)).join(''), toUnit, redactions: units.filter((unit) => typeof unit !== 'string').length };
}

/** 쪽 응답 조각들 → 이어 붙인 글 + 가림 구간 */
export function joinSegments(pages: ReadonlyArray<ReadonlyArray<{ text: string; redacted?: boolean }>>) {
  let text = '';
  let at = 0;
  const runs: DiffRange[] = [];
  for (const segments of pages) for (const segment of segments) {
    const size = Array.from(segment.text).length;
    if (segment.redacted && size) {
      const last = runs.at(-1);
      if (last && last.end === at) last.end = at + size; else runs.push({ start: at, end: at + size });
    }
    text += segment.text;
    at += size;
  }
  return { text, runs };
}
