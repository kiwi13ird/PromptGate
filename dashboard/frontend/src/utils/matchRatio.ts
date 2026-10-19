// '일치 비율'의 하나뿐인 정의(2026-10-16 사용자 피드백 "비율을 하나로 통일하자"):
//   입력 중 보호 문서와 같은 글자 비율 = 보낸 입력의 공백 뺀 글자 중, 보호 문서 본문과 대조해 같은 글자의 비율.
// 이 파일이 화면(이벤트 상세 '보호 문서 일치 구간')과 대시보드 서버(이벤트 목록·상세 응답의 same_char_ratio)가 함께 쓰는 원본이다.
// 서버용은 이 파일을 그대로 묶은 server/match-ratio.mjs(esbuild, 머리 주석에 이 파일 md5)라 두 곳의 결과가 같다.
// 입력·문서 본문은 서버 근거 쪽(match-evidence.mjs documentPage)과 같은 가림(█) 본문 + 가림 구간을 받는다.
import { collapseRedactions, type CollapsedText } from './redactedText';
import { diffIgnoringWhitespace, type DiffRange, type TextDiffResult } from './textDiff';

/** 화면 어디서나 같은 이름(이벤트 목록·상세 요약·보호 문서 상세의 연결 이벤트). 뜻(보낸 입력 중 문서와 같은 글자의 비율)은 마우스를 올리면 */
export const SAME_RATIO_NAME = '문서와 같은 글자';

export interface MaskedBody { text: string; runs: DiffRange[] }
interface Location { char_start: number; char_end: number }
export interface ComparisonFacts {
  coverage: number;
  matching_passages?: ReadonlyArray<{ input_location: Location; document_location: Location }>;
}

/**
 * 화면 대조를 믿지 않을 이유(없으면 undefined). 서버가 확인한 사실과 어긋나면 전부 칠하지 않는다.
 *  ① 계산 한도를 넘김 ② 서버가 '공백 제외 같은 글'로 확인한 문장(matching_passages, 문서 안에서 하나뿐인 문장)이 통째로 '다름'으로 칠해짐
 *  ③ 서버는 확인된 일치 구간이 있다는데(비율 > 0) 화면 대조로는 같은 글자가 하나도 없음
 * 서버 좌표(원래 코드 포인트)는 가림을 접은 단위 좌표로 바꿔 비교한다(toUnit, 없으면 그대로)
 */
export function diffDistrust(diff: TextDiffResult, comparison: ComparisonFacts, maps?: { input?: Int32Array; document?: Int32Array }): string | undefined {
  if (!diff.complete) return '본문이 길어 계산 한도를 넘어';
  const map = (table: Int32Array | undefined, location: Location) => table
    ? { char_start: table[Math.min(location.char_start, table.length - 1)], char_end: table[Math.min(location.char_end, table.length - 1)] }
    : location;
  const covered = (ranges: DiffRange[], location: Location) =>
    location.char_end > location.char_start && ranges.some((range) => range.start <= location.char_start && range.end >= location.char_end);
  const passages = comparison.matching_passages ?? [];
  if (passages.some((passage) => covered(diff.a, map(maps?.input, passage.input_location)) || covered(diff.b, map(maps?.document, passage.document_location))))
    return '서버가 같은 글로 확인한 문장과 대조 결과가 맞지 않아';
  if (comparison.coverage > 0 && diff.aChars > 0 && diff.aChangedChars === diff.aChars)
    return '서버 일치 비율과 대조 결과가 맞지 않아';
  return undefined;
}

export type MatchRatio =
  | { state: 'READY'; ratio: number; differences: number; left: CollapsedText; right: CollapsedText; diff: TextDiffResult }
  | { state: 'UNAVAILABLE'; reason: string; left: CollapsedText; right: CollapsedText; diff: TextDiffResult };

/** 같은 글자 비율(0~1) = (입력의 공백 뺀 글자 - 다른 글자) ÷ 입력의 공백 뺀 글자. 가림 덩어리는 한 글자. 입력이 비면 0 */
export function sameCharRatio(diff: TextDiffResult) {
  return diff.aChars ? (diff.aChars - diff.aChangedChars) / diff.aChars : 0;
}

/** 다른 곳 수: 입력에 대응하는 문서 범위 밖(입력에 쓰이지 않은 문서 앞뒤)만 다른 곳은 세지 않는다(화면 ↑↓ 개수와 같음) */
export function differenceCount(diff: TextDiffResult) {
  const span = diff.bSpan;
  return diff.hunks.filter((hunk) => hunk.a || (hunk.b && span && hunk.b.end > span.start && hunk.b.start < span.end)).length;
}

export function computeMatchRatio(input: MaskedBody, document: MaskedBody, comparison: ComparisonFacts, options?: { budgetMs?: number }): MatchRatio {
  const left = collapseRedactions(input.text, input.runs);
  const right = collapseRedactions(document.text, document.runs);
  const diff = diffIgnoringWhitespace(left.text, right.text, options);
  const reason = diffDistrust(diff, comparison, { input: left.toUnit, document: right.toUnit });
  if (reason) return { state: 'UNAVAILABLE', reason, left, right, diff };
  return { state: 'READY', ratio: sameCharRatio(diff), differences: differenceCount(diff), left, right, diff };
}

/** 화면 표시: 소수 첫째 자리 내림, 다른 글자가 있으면 100%로 올리지 않는다(99.9%) */
export function formatSameRatio(ratio: number) {
  const value = ratio >= 1 ? 100 : Math.min(Math.floor(ratio * 1000) / 10, 99.9);
  return `${value.toLocaleString('ko-KR', { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;
}

/** 서버가 실어 줄 값(목록·상세 응답): 본문 등은 빼고 글자 수·상태만(비율은 받는 쪽이 같은 식으로 — 반올림 차이 없음) */
export function matchRatioSummary(result: MatchRatio) {
  return result.state === 'READY'
    ? { state: 'READY' as const, same_chars: result.diff.aChars - result.diff.aChangedChars, input_chars: result.diff.aChars, differences: result.differences }
    : { state: 'UNAVAILABLE' as const, reason: result.reason };
}

/** 응답의 글자 수 → 비율(화면 대조와 같은 식) */
export const ratioOf = (sameChars: number, inputChars: number) => (inputChars ? sameChars / inputChars : 0);
