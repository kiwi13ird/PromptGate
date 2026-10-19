// 자동 생성 — 손으로 고치지 말 것. 화면(dashboard-frontend-final)의 같은 글자 비율 원본을 그대로 묶음: src/utils/matchRatio.ts md5 59b7db26 · src/utils/textDiff.ts md5 2f609814 · src/utils/redactedText.ts md5 bb0a1082

// src/utils/redactedText.ts
var MASK_TOKEN = "\uE000";
function collapseRedactions(original, runs) {
  const chars = Array.from(original);
  const sorted = runs.filter((run) => run.end > run.start).slice().sort((a, b) => a.start - b.start);
  const units = [];
  const toUnit = new Int32Array(chars.length + 1);
  let at = 0;
  for (const run of sorted) {
    const start = Math.max(at, Math.min(chars.length, run.start));
    const end = Math.max(start, Math.min(chars.length, run.end));
    for (; at < start; at++) {
      toUnit[at] = units.length;
      units.push(chars[at]);
    }
    if (end > start) {
      for (; at < end; at++) toUnit[at] = units.length;
      units.push({ redacted: end - start });
    }
  }
  for (; at < chars.length; at++) {
    toUnit[at] = units.length;
    units.push(chars[at]);
  }
  toUnit[chars.length] = units.length;
  return { units, text: units.map((unit) => typeof unit === "string" ? unit : MASK_TOKEN).join(""), toUnit, redactions: units.filter((unit) => typeof unit !== "string").length };
}

// src/utils/textDiff.ts
var SPACE = /\s/u;
var now = () => typeof performance !== "undefined" ? performance.now() : Date.now();
function prepare(text) {
  const all = Array.from(text);
  const at = [];
  const chars = [];
  const wordStart = [];
  const words = [];
  let current = "";
  for (let index = 0; index < all.length; index++) {
    const char = all[index];
    if (SPACE.test(char)) {
      if (current) {
        words.push(current);
        current = "";
      }
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
function bisect(a, aLo, aHi, b, bLo, bHi, deadline, state) {
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
    if ((d & 15) === 0 && now() > deadline) {
      state.timedOut = true;
      return null;
    }
    for (let k1 = -d + k1start; k1 <= d - k1end; k1 += 2) {
      const k1Offset = offset + k1;
      let x1 = k1 === -d || k1 !== d && v1[k1Offset - 1] < v1[k1Offset + 1] ? v1[k1Offset + 1] : v1[k1Offset - 1] + 1;
      let y1 = x1 - k1;
      while (x1 < n && y1 < m && a[aLo + x1] === b[bLo + y1]) {
        x1++;
        y1++;
      }
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
      let x2 = k2 === -d || k2 !== d && v2[k2Offset - 1] < v2[k2Offset + 1] ? v2[k2Offset + 1] : v2[k2Offset - 1] + 1;
      let y2 = x2 - k2;
      while (x2 < n && y2 < m && a[aLo + n - x2 - 1] === b[bLo + m - y2 - 1]) {
        x2++;
        y2++;
      }
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
function changedBlocks(a, aLo0, aHi0, b, bLo0, bHi0, deadline, state) {
  const out = [];
  const push = (block) => {
    if (block.aLo === block.aHi && block.bLo === block.bHi) return;
    const last = out.at(-1);
    if (last && last.aHi === block.aLo && last.bHi === block.bLo) {
      last.aHi = block.aHi;
      last.bHi = block.bHi;
    } else out.push({ ...block });
  };
  const stack = [{ aLo: aLo0, aHi: aHi0, bLo: bLo0, bHi: bHi0 }];
  while (stack.length) {
    let { aLo, aHi, bLo, bHi } = stack.pop();
    while (aLo < aHi && bLo < bHi && a[aLo] === b[bLo]) {
      aLo++;
      bLo++;
    }
    while (aLo < aHi && bLo < bHi && a[aHi - 1] === b[bHi - 1]) {
      aHi--;
      bHi--;
    }
    if (aLo === aHi || bLo === bHi || state.timedOut) {
      push({ aLo, aHi, bLo, bHi });
      continue;
    }
    const middle = bisect(a, aLo, aHi, b, bLo, bHi, deadline, state);
    if (!middle) {
      push({ aLo, aHi, bLo, bHi });
      continue;
    }
    const [x, y] = middle;
    stack.push({ aLo: aLo + x, aHi, bLo: bLo + y, bHi });
    stack.push({ aLo, aHi: aLo + x, bLo, bHi: bLo + y });
  }
  return out;
}
function absorbCoincidences(blocks, lenA, lenB) {
  const out = blocks.map((block) => ({ ...block }));
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
function slideOneSided(hunks, a, b) {
  const boundary = (p, index) => index <= 0 || index >= p.chars.length || p.at[index] - p.at[index - 1] > 1;
  hunks.forEach((hunk, index) => {
    const deletion = hunk.aLo === hunk.aHi && hunk.bHi > hunk.bLo;
    const insertion = hunk.bLo === hunk.bHi && hunk.aHi > hunk.aLo;
    if (!deletion && !insertion) return;
    const side = deletion ? b : a;
    const lo = deletion ? hunk.bLo : hunk.aLo;
    const hi = deletion ? hunk.bHi : hunk.aHi;
    const prev = hunks[index - 1];
    const next = hunks[index + 1];
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
      if (score > bestScore || score === bestScore && Math.abs(shift) < Math.abs(best)) {
        best = shift;
        bestScore = score;
      }
    }
    if (!best) return;
    hunk.aLo += best;
    hunk.aHi += best;
    hunk.bLo += best;
    hunk.bHi += best;
  });
}
function toRanges(prepared, changed) {
  const ranges = [];
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
function diffIgnoringWhitespace(aText, bText, { budgetMs = 1500 } = {}) {
  const deadline = now() + budgetMs;
  const state = { timedOut: false };
  const a = prepare(aText);
  const b = prepare(bText);
  const ids = /* @__PURE__ */ new Map();
  const id = (word) => {
    let value = ids.get(word);
    if (value === void 0) {
      value = ids.size;
      ids.set(word, value);
    }
    return value;
  };
  const aWords = Int32Array.from(a.words, id);
  const bWords = Int32Array.from(b.words, id);
  const aChanged = new Uint8Array(a.chars.length);
  const bChanged = new Uint8Array(b.chars.length);
  const aLen = (lo, hi) => a.wordStart[hi] - a.wordStart[lo];
  const bLen = (lo, hi) => b.wordStart[hi] - b.wordStart[lo];
  const span = (lo, hi) => hi - lo;
  const wordBlocks = absorbCoincidences(changedBlocks(aWords, 0, aWords.length, bWords, 0, bWords.length, deadline, state), aLen, bLen);
  const compactHunks = [];
  const addHunk = (block) => {
    const last = compactHunks.at(-1);
    if (last && last.aHi === block.aLo && last.bHi === block.bLo) {
      last.aHi = block.aHi;
      last.bHi = block.bHi;
    } else compactHunks.push({ ...block });
  };
  for (const block of wordBlocks) {
    const aFrom = a.wordStart[block.aLo], aTo = a.wordStart[block.aHi];
    const bFrom = b.wordStart[block.bLo], bTo = b.wordStart[block.bHi];
    if (aFrom === aTo || bFrom === bTo || state.timedOut) {
      addHunk({ aLo: aFrom, aHi: aTo, bLo: bFrom, bHi: bTo });
      continue;
    }
    for (const inner of absorbCoincidences(changedBlocks(a.chars, aFrom, aTo, b.chars, bFrom, bTo, deadline, state), span, span)) addHunk(inner);
  }
  slideOneSided(compactHunks, a, b);
  for (const hunk of compactHunks) {
    aChanged.fill(1, hunk.aLo, hunk.aHi);
    bChanged.fill(1, hunk.bLo, hunk.bHi);
  }
  const count = (marks) => marks.reduce((total, value) => total + value, 0);
  const range = (p, lo, hi) => hi > lo ? { start: p.at[lo], end: p.at[hi - 1] + 1 } : void 0;
  const point = (p, lo) => lo < p.at.length ? p.at[lo] : p.length;
  const firstSame = bChanged.indexOf(0);
  const lastSame = bChanged.lastIndexOf(0);
  return {
    a: toRanges(a, aChanged),
    b: toRanges(b, bChanged),
    aChangedChars: count(aChanged),
    bChangedChars: count(bChanged),
    aChars: a.chars.length,
    bChars: b.chars.length,
    complete: !state.timedOut,
    hunks: compactHunks.map((h) => ({ a: range(a, h.aLo, h.aHi), b: range(b, h.bLo, h.bHi), aAt: point(a, h.aLo), bAt: point(b, h.bLo) })),
    bSpan: firstSame >= 0 ? { start: b.at[firstSame], end: b.at[lastSame] + 1 } : void 0
  };
}

// src/utils/matchRatio.ts
var SAME_RATIO_NAME = "\uBB38\uC11C\uC640 \uAC19\uC740 \uAE00\uC790";
function diffDistrust(diff, comparison, maps) {
  if (!diff.complete) return "\uBCF8\uBB38\uC774 \uAE38\uC5B4 \uACC4\uC0B0 \uD55C\uB3C4\uB97C \uB118\uC5B4";
  const map = (table, location) => table ? { char_start: table[Math.min(location.char_start, table.length - 1)], char_end: table[Math.min(location.char_end, table.length - 1)] } : location;
  const covered = (ranges, location) => location.char_end > location.char_start && ranges.some((range) => range.start <= location.char_start && range.end >= location.char_end);
  const passages = comparison.matching_passages ?? [];
  if (passages.some((passage) => covered(diff.a, map(maps?.input, passage.input_location)) || covered(diff.b, map(maps?.document, passage.document_location))))
    return "\uC11C\uBC84\uAC00 \uAC19\uC740 \uAE00\uB85C \uD655\uC778\uD55C \uBB38\uC7A5\uACFC \uB300\uC870 \uACB0\uACFC\uAC00 \uB9DE\uC9C0 \uC54A\uC544";
  if (comparison.coverage > 0 && diff.aChars > 0 && diff.aChangedChars === diff.aChars)
    return "\uC11C\uBC84 \uC77C\uCE58 \uBE44\uC728\uACFC \uB300\uC870 \uACB0\uACFC\uAC00 \uB9DE\uC9C0 \uC54A\uC544";
  return void 0;
}
function sameCharRatio(diff) {
  return diff.aChars ? (diff.aChars - diff.aChangedChars) / diff.aChars : 0;
}
function differenceCount(diff) {
  const span = diff.bSpan;
  return diff.hunks.filter((hunk) => hunk.a || hunk.b && span && hunk.b.end > span.start && hunk.b.start < span.end).length;
}
function computeMatchRatio(input, document, comparison, options) {
  const left = collapseRedactions(input.text, input.runs);
  const right = collapseRedactions(document.text, document.runs);
  const diff = diffIgnoringWhitespace(left.text, right.text, options);
  const reason = diffDistrust(diff, comparison, { input: left.toUnit, document: right.toUnit });
  if (reason) return { state: "UNAVAILABLE", reason, left, right, diff };
  return { state: "READY", ratio: sameCharRatio(diff), differences: differenceCount(diff), left, right, diff };
}
function formatSameRatio(ratio) {
  const value = ratio >= 1 ? 100 : Math.min(Math.floor(ratio * 1e3) / 10, 99.9);
  return `${value.toLocaleString("ko-KR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;
}
function matchRatioSummary(result) {
  return result.state === "READY" ? { state: "READY", same_chars: result.diff.aChars - result.diff.aChangedChars, input_chars: result.diff.aChars, differences: result.differences } : { state: "UNAVAILABLE", reason: result.reason };
}
var ratioOf = (sameChars, inputChars) => inputChars ? sameChars / inputChars : 0;
export {
  SAME_RATIO_NAME,
  computeMatchRatio,
  diffDistrust,
  differenceCount,
  formatSameRatio,
  matchRatioSummary,
  ratioOf,
  sameCharRatio
};
