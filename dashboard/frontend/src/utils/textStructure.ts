// 근거 본문의 글 구조(2026-10-16 사용자 피드백 "왜 파일 레이아웃 형식이 없지?").
// 화면이 받는 본문은 Detection이 파일에서 뽑은 정규화 텍스트다(문단 = 줄, 표 = 칸을 ' | '로 이은 줄, 원본 서식 없음 —
// 입력 파일 원본은 보관하지 않는다). 그 텍스트의 모양만으로 문서처럼 그린다: ' | ' 줄 묶음 = 표(첫 줄 머리글),
// '1. 개요'·'2-1. TBS'처럼 번호로 시작하고 문장으로 끝나지 않는 줄 = 제목, 나머지 = 문단, 빈 줄 = 간격.
// 좌표는 가림을 접은 단위(utils/redactedText) 그대로라 강조·가림 표시·이동 표시를 표 칸 안에서도 같은 규칙으로 쓴다.
import type { TextUnit } from './redactedText';
import type { DiffRange } from './textDiff';

export interface TableRow { start: number; end: number; cells: DiffRange[] }
export type TextBlock =
  | { kind: 'heading' | 'paragraph'; start: number; end: number }
  | { kind: 'blank'; start: number; end: number }
  | { kind: 'table'; start: number; end: number; rows: TableRow[] };

const SEPARATOR = ' | ';
const HEADING = /^\s*(?:\d+(?:-\d+)*\.|\d+(?:\.\d+)+\.?)\s+\S/u;   // '1. 개요' · '2-1. TBS' · '1.2 범위' (숫자 뒤 마침표 없는 '2 개'는 아님)
const SENTENCE_END = /[.。!?:;]\s*$/u;

const unitText = (unit: TextUnit) => (typeof unit === 'string' ? unit : '');

/** 줄 [start, end)의 표 칸(' | ' 사이). 칸 구분이 없으면 null */
function cellsOf(units: TextUnit[], start: number, end: number): DiffRange[] | null {
  const cells: DiffRange[] = [];
  let cell = start;
  for (let at = start; at + 2 < end; at++) {
    if (units[at] === ' ' && units[at + 1] === '|' && units[at + 2] === ' ') {
      cells.push({ start: cell, end: at });
      cell = at + SEPARATOR.length;
      at += SEPARATOR.length - 1;
    }
  }
  if (!cells.length) return null;
  cells.push({ start: cell, end });
  return cells;
}

export function structureUnits(units: TextUnit[]): TextBlock[] {
  const blocks: TextBlock[] = [];
  let lineStart = 0;
  for (let at = 0; at <= units.length; at++) {
    if (at < units.length && units[at] !== '\n') continue;
    let end = at;
    if (end > lineStart && units[end - 1] === '\r') end--;
    const text = units.slice(lineStart, end).map(unitText).join('');
    const cells = cellsOf(units, lineStart, end);
    if (!text.trim()) blocks.push({ kind: 'blank', start: lineStart, end });
    else if (cells) {
      const last = blocks.at(-1);
      const row = { start: lineStart, end, cells };
      if (last?.kind === 'table') { last.rows.push(row); last.end = end; } else blocks.push({ kind: 'table', start: lineStart, end, rows: [row] });
    } else blocks.push({ kind: HEADING.test(text) && !SENTENCE_END.test(text) ? 'heading' : 'paragraph', start: lineStart, end });
    lineStart = at + 1;
  }
  return blocks;
}

/** 화면에 실제로 그려지는 구간(문단·제목·표 칸). 줄바꿈·' | '는 그리지 않는다 */
export function renderedRanges(blocks: TextBlock[]): DiffRange[] {
  return blocks.flatMap((block) => (block.kind === 'table' ? block.rows.flatMap((row) => row.cells)
    : block.kind === 'blank' ? [] : [{ start: block.start, end: block.end }])).filter((range) => range.end > range.start);
}

/** 이동 표시 위치를 그려지는 글자 위로 옮긴다(줄바꿈·칸 구분 자리면 다음 글자, 글 끝이면 마지막 글자) */
export function anchorOn(ranges: DiffRange[], at: number): number {
  if (!ranges.length) return at;
  let lo = 0, hi = ranges.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (ranges[mid].end > at) hi = mid; else lo = mid + 1; }
  if (lo >= ranges.length) return ranges[ranges.length - 1].end - 1;
  return Math.max(at, ranges[lo].start);
}
