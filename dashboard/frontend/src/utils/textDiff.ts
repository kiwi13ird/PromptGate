// 보낸 입력 ↔ 보호 문서 '다른 부분' 계산(2026-10-16 이벤트 상세 문서 한 페이지 보기).
// 공백·줄바꿈은 비교하지 않는다(서버의 같은 문장 기준 SAME_TEXT_IGNORING_WHITESPACE와 같음).
// 1) 낱말(공백 사이 글자 묶음) 단위 Myers 차이 → 2) 서로 다른 낱말 묶음 안에서만 글자 단위로 다시 맞춰
// 조사 하나만 바뀐 곳도 그 글자만 강조한다. 좌표는 화면 전체가 쓰는 유니코드 코드 포인트 위치.
// 계산이 한도(기본 1.5초)를 넘으면 남은 묶음은 통째로 '다름'으로 둔다(덜 강조하지 않는 쪽) → complete=false.

export interface DiffRange { start: number; end: number }
export interface TextDiffResult {
  /** 첫 글(보낸 입력)에서 둘째 글(보호 문서)과 다른 부분 */
  a: DiffRange[];
  /** 둘째 글에서 첫 글과 다른 부분 */
  b: DiffRange[];
  /** 공백 뺀 글자 중 다른 글자 수 */
  aChangedChars: number;
  bChangedChars: number;
  aChars: number;
  bChars: number;
  /** 계산 한도 안에 끝났는지(false면 일부 묶음은 통째로 '다름') */
  complete: boolean;
  /** 서로 대응하는 다른 부분(양쪽 함께 이동용). 한쪽에만 있으면 다른 쪽은 없고 그 자리(at)만 */
  hunks: DiffHunk[];
  /** 둘째 글에서 첫 글과 같은 글자가 처음·마지막으로 나오는 범위(입력에 대응하는 문서 범위). 같은 글자가 없으면 없음 */
  bSpan?: DiffRange;
}
export interface DiffHunk { a?: DiffRange; b?: DiffRange; aAt: number; bAt: number }

const SPACE = /\s/u;
const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

interface Prepared {
  /** 공백이 아닌 글자의 원래 위치 */
  at: Int32Array;
  /** 공백이 아닌 글자(코드 포인트 값) */
  chars: Int32Array;
  /** 낱말 경계: 낱말 i = chars[wordStart[i] .. wordStart[i+1]) */
  wordStart: Int32Array;
  words: string[];
  /** 원래 글의 코드 포인트 수 */
  length: number;
}

function prepare(text: string): Prepared {
  const all = Array.from(text);
  const at: number[] = [];
  const chars: number[] = [];
  const wordStart: number[] = [];
  const words: string[] = [];
  let current = '';
  for (let index = 0; index < all.length; index++) {
    const char = all[index];
    if (SPACE.test(char)) {
      if (current) { words.push(current); current = ''; }
      continue;
    }
    if (!current) wordStart.push(chars.length);
    current += char;
    at.push(index);
    chars.push(char.codePointAt(0) ?? 0);
  }
  if (current) words.push(current);
  wordStart.push(chars.length);
  return { at: Int32Array.from(at), chars: Int32Array.from(chars), wordStart: Int32Array.from(wordStart), words, length: all.length };
}

interface Block { aLo: number; aHi: number; bLo: number; bHi: number }

/** Myers 중간 뱀(diff-match-patch bisect와 같은 방식). 겹치는 지점이 없거나 한도를 넘으면 null */
function bisect(a: Int32Array, aLo: number, aHi: number, b: Int32Array, bLo: number, bHi: number, deadline: number, state: { timedOut: boolean }): [number, number] | null {
  const n = aHi - aLo;
  const m = bHi - bLo;
  const maxD = Math.ceil((n + m) / 2);
  const offset = maxD;
  const length = 2 * maxD + 2;
  const v1 = new Int32Array(length).fill(-1);
  const v2 = new Int32Array(length).fill(-1);
  v1[offset + 1] = 0;
  v2[offset + 1] = 0;
  const delta = n - m;
  const front = delta % 2 !== 0;
  let k1start = 0, k1end = 0, k2start = 0, k2end = 0;
  for (let d = 0; d < maxD; d++) {
    if ((d & 15) === 0 && now() > deadline) { state.timedOut = true; return null; }
    for (let k1 = -d + k1start; k1 <= d - k1end; k1 += 2) {
      const k1Offset = offset + k1;
      let x1 = k1 === -d || (k1 !== d && v1[k1Offset - 1] < v1[k1Offset + 1]) ? v1[k1Offset + 1] : v1[k1Offset - 1] + 1;
      let y1 = x1 - k1;
      while (x1 < n && y1 < m && a[aLo + x1] === b[bLo + y1]) { x1++; y1++; }
      v1[k1Offset] = x1;
      if (x1 > n) k1end += 2;
      else if (y1 > m) k1start += 2;
      else if (front) {
        const k2Offset = offset + delta - k1;
        if (k2Offset >= 0 && k2Offset < length && v2[k2Offset] !== -1 && x1 >= n - v2[k2Offset]) return [x1, y1];
      }
    }
    for (let k2 = -d + k2start; k2 <= d - k2end; k2 += 2) {
      const k2Offset = offset + k2;
      let x2 = k2 === -d || (k2 !== d && v2[k2Offset - 1] < v2[k2Offset + 1]) ? v2[k2Offset + 1] : v2[k2Offset - 1] + 1;
      let y2 = x2 - k2;
      while (x2 < n && y2 < m && a[aLo + n - x2 - 1] === b[bLo + m - y2 - 1]) { x2++; y2++; }
      v2[k2Offset] = x2;
      if (x2 > n) k2end += 2;
      else if (y2 > m) k2start += 2;
      else if (!front) {
        const k1Offset = offset + delta - k2;
        if (k1Offset >= 0 && k1Offset < length && v1[k1Offset] !== -1) {
          const x1 = v1[k1Offset];
          const y1 = offset + x1 - k1Offset;
          if (x1 >= n - x2) return [x1, y1];
        }
      }
    }
  }
  return null;
}

/** a[aLo..aHi)·b[bLo..bHi)의 '같지 않은 묶음'을 순서대로(이웃한 묶음은 합침) */
function changedBlocks(a: Int32Array, aLo0: number, aHi0: number, b: Int32Array, bLo0: number, bHi0: number, deadline: number, state: { timedOut: boolean }): Block[] {
  const out: Block[] = [];
  const push = (block: Block) => {
    if (block.aLo === block.aHi && block.bLo === block.bHi) return;
    const last = out.at(-1);
    if (last && last.aHi === block.aLo && last.bHi === block.bLo) { last.aHi = block.aHi; last.bHi = block.bHi; }
    else out.push({ ...block });
  };
  // 재귀 대신 쌓기(긴 글에서 호출 깊이 제한을 피함). 순서를 지키려고 뒤쪽 일을 먼저 쌓는다
  const stack: Block[] = [{ aLo: aLo0, aHi: aHi0, bLo: bLo0, bHi: bHi0 }];
  while (stack.length) {
    let { aLo, aHi, bLo, bHi } = stack.pop()!;
    while (aLo < aHi && bLo < bHi && a[aLo] === b[bLo]) { aLo++; bLo++; }
    while (aLo < aHi && bLo < bHi && a[aHi - 1] === b[bHi - 1]) { aHi--; bHi--; }
    if (aLo === aHi || bLo === bHi || state.timedOut) { push({ aLo, aHi, bLo, bHi }); continue; }
    const middle = bisect(a, aLo, aHi, b, bLo, bHi, deadline, state);
    if (!middle) { push({ aLo, aHi, bLo, bHi }); continue; }
    const [x, y] = middle;
    stack.push({ aLo: aLo + x, aHi, bLo: bLo + y, bHi });
    stack.push({ aLo, aHi: aLo + x, bLo, bHi: bLo + y });
  }
  return out;
}

/**
 * 우연히 같은 짧은 조각 흡수: 두 '다른 묶음' 사이의 같은 부분이 **두 글 각각에서** 그 양옆 다른 부분 길이의 합(공백 뺀 글자 수)
 * 이하이면 둘을 하나로 합친다. 넣은 문장 속 '협상'·'이' 같은 낱말·글자가 문서 어딘가와 맞아 강조가 조각나는 것을 막는다.
 * 2026-10-16 수정: 처음에는 diff-match-patch cleanupSemantic처럼 양옆 묶음마다 '긴 쪽' 길이로 재서, 문서 일부만 붙여 넣은 입력
 * (앞 질문 + 문서 가운데 본문)에서 문서 쪽 앞뒤의 긴 나머지 때문에 붙여 넣은 본문 전체가 '다름'으로 흡수됐다.
 * 이제는 보낸 입력 쪽 양옆 변화가 짧으면(질문 한 줄) 그보다 긴 같은 본문은 흡수하지 않는다. len(lo, hi) = 그 구간의 공백 뺀 글자 수
 */
function absorbCoincidences(blocks: Block[], lenA: (lo: number, hi: number) => number, lenB: (lo: number, hi: number) => number): Block[] {
  const out = blocks.map(block => ({ ...block }));
  let index = 0;
  while (index < out.length - 1) {
    const left = out[index];
    const right = out[index + 1];
    const equal = Math.max(lenA(left.aHi, right.aLo), lenB(left.bHi, right.bLo));
    const aroundA = lenA(left.aLo, left.aHi) + lenA(right.aLo, right.aHi);
    const aroundB = lenB(left.bLo, left.bHi) + lenB(right.bLo, right.bHi);
    if (equal <= aroundA && equal <= aroundB) {
      out.splice(index, 2, { aLo: left.aLo, aHi: right.aHi, bLo: left.bLo, bHi: right.bHi });
      index = Math.max(0, index - 1);
    } else index++;
  }
  return out;
}

/**
 * 한쪽에만 있는 묶음(넣음·지움) 자리 맞추기(diff-match-patch cleanupSemanticLossless와 같은 생각): 같은 글자가 이어지면
 * 묶음을 그 같은 부분 안에서 앞뒤로 밀 수 있다. 예) 입력 '…한다.' · 문서 '…한다. 부록…없다.'에서 지운 부분이 '다. 부록…없'으로
 * 잡히면 끝의 '다.'가 우연히 같은 글자가 되어 입력에 대응하는 문서 범위가 문서 끝까지 늘어난다. 밀 수 있는 자리 중
 * 글의 처음·끝에 닿는 자리 > 낱말 경계에서 시작·끝나는 자리 > 지금 자리 순으로 고른다. 같은 부분을 넘지 않으므로 결과 글자는 같다
 */
function slideOneSided(hunks: Block[], a: Prepared, b: Prepared) {
  const boundary = (p: Prepared, index: number) => index <= 0 || index >= p.chars.length || p.at[index] - p.at[index - 1] > 1;
  hunks.forEach((hunk, index) => {
    const deletion = hunk.aLo === hunk.aHi && hunk.bHi > hunk.bLo;
    const insertion = hunk.bLo === hunk.bHi && hunk.aHi > hunk.aLo;
    if (!deletion && !insertion) return;
    const side = deletion ? b : a;
    const lo = deletion ? hunk.bLo : hunk.aLo;
    const hi = deletion ? hunk.bHi : hunk.aHi;
    const prev = hunks[index - 1];
    const next = hunks[index + 1];
    // 앞뒤 같은 부분의 길이(두 글 모두에서 같은 부분이어야 하므로 짧은 쪽)
    const roomLeft = Math.min(hunk.aLo - (prev?.aHi ?? 0), hunk.bLo - (prev?.bHi ?? 0));
    const roomRight = Math.min((next?.aLo ?? a.chars.length) - hunk.aHi, (next?.bLo ?? b.chars.length) - hunk.bHi);
    let left = 0;
    while (left < roomLeft && side.chars[lo - left - 1] === side.chars[hi - left - 1]) left++;
    let right = 0;
    while (right < roomRight && side.chars[lo + right] === side.chars[hi + right]) right++;
    let best = 0;
    let bestScore = -1;
    for (let shift = -left; shift <= right; shift++) {
      const start = lo + shift, end = hi + shift;
      const score = (start === 0 || end === side.chars.length ? 4 : 0) + (boundary(side, start) ? 1 : 0) + (boundary(side, end) ? 1 : 0);
      if (score > bestScore || (score === bestScore && Math.abs(shift) < Math.abs(best))) { best = shift; bestScore = score; }
    }
    if (!best) return;
    hunk.aLo += best; hunk.aHi += best; hunk.bLo += best; hunk.bHi += best;
  });
}

/** 다른 글자 표시(공백 뺀 글자 기준) → 원래 위치의 범위. 다른 글자 사이의 공백만 있으면 한 범위로 잇는다 */
function toRanges(prepared: Prepared, changed: Uint8Array): DiffRange[] {
  const ranges: DiffRange[] = [];
  for (let index = 0; index < changed.length; index++) {
    if (!changed[index]) continue;
    const start = prepared.at[index];
    const end = start + 1;
    const last = ranges.at(-1);
    if (last && index > 0 && changed[index - 1]) last.end = end;
    else ranges.push({ start, end });
  }
  return ranges;
}

export function diffIgnoringWhitespace(aText: string, bText: string, { budgetMs = 1500 }: { budgetMs?: number } = {}): TextDiffResult {
  const deadline = now() + budgetMs;
  const state = { timedOut: false };
  const a = prepare(aText);
  const b = prepare(bText);
  const ids = new Map<string, number>();
  const id = (word: string) => { let value = ids.get(word); if (value === undefined) { value = ids.size; ids.set(word, value); } return value; };
  const aWords = Int32Array.from(a.words, id);
  const bWords = Int32Array.from(b.words, id);
  const aChanged = new Uint8Array(a.chars.length);
  const bChanged = new Uint8Array(b.chars.length);
  const aLen = (lo: number, hi: number) => a.wordStart[hi] - a.wordStart[lo];
  const bLen = (lo: number, hi: number) => b.wordStart[hi] - b.wordStart[lo];
  const span = (lo: number, hi: number) => hi - lo;
  const wordBlocks = absorbCoincidences(changedBlocks(aWords, 0, aWords.length, bWords, 0, bWords.length, deadline, state), aLen, bLen);
  const compactHunks: Block[] = [];   // 공백 뺀 글자 좌표의 대응 묶음
  const addHunk = (block: Block) => {
    const last = compactHunks.at(-1);
    if (last && last.aHi === block.aLo && last.bHi === block.bLo) { last.aHi = block.aHi; last.bHi = block.bHi; } else compactHunks.push({ ...block });
  };
  for (const block of wordBlocks) {
    const aFrom = a.wordStart[block.aLo], aTo = a.wordStart[block.aHi];
    const bFrom = b.wordStart[block.bLo], bTo = b.wordStart[block.bHi];
    if (aFrom === aTo || bFrom === bTo || state.timedOut) { addHunk({ aLo: aFrom, aHi: aTo, bLo: bFrom, bHi: bTo }); continue; }
    // 낱말이 다르게 나뉜 곳·조사만 바뀐 곳: 이 묶음 안에서 글자 단위로 다시 맞춘다
    for (const inner of absorbCoincidences(changedBlocks(a.chars, aFrom, aTo, b.chars, bFrom, bTo, deadline, state), span, span)) addHunk(inner);
  }
  slideOneSided(compactHunks, a, b);
  for (const hunk of compactHunks) { aChanged.fill(1, hunk.aLo, hunk.aHi); bChanged.fill(1, hunk.bLo, hunk.bHi); }
  const count = (marks: Uint8Array) => marks.reduce((total, value) => total + value, 0);
  const range = (p: Prepared, lo: number, hi: number) => (hi > lo ? { start: p.at[lo], end: p.at[hi - 1] + 1 } : undefined);
  const point = (p: Prepared, lo: number) => (lo < p.at.length ? p.at[lo] : p.length);
  const firstSame = bChanged.indexOf(0);
  const lastSame = bChanged.lastIndexOf(0);
  return {
    a: toRanges(a, aChanged), b: toRanges(b, bChanged),
    aChangedChars: count(aChanged), bChangedChars: count(bChanged),
    aChars: a.chars.length, bChars: b.chars.length,
    complete: !state.timedOut,
    hunks: compactHunks.map((h) => ({ a: range(a, h.aLo, h.aHi), b: range(b, h.bLo, h.bHi), aAt: point(a, h.aLo), bAt: point(b, h.bLo) })),
    bSpan: firstSame >= 0 ? { start: b.at[firstSame], end: b.at[lastSame] + 1 } : undefined,
  };
}
