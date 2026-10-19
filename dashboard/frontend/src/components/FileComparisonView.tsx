import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import type { EventEvidence } from '@/src/services/evidenceService';
import { uiLabel } from '@/src/utils/labels';
import '@/src/detection-ops.css';

// 파일 업로드의 가림 전·후 (2026-10-09). Gateway가 칸 단위로 검사한 판정 기록(칸 번호·원문·보낸 내용·가린 위치)으로
// 문서 구조를 다시 그린다. 파일 원본은 저장하지 않으므로 글꼴·병합 셀·그림은 없다.
export type FileComparison = NonNullable<EventEvidence['file_comparison']>;
type Segment = FileComparison['segments'][number];
type Span = Segment['spans'][number];
type Format = Segment['format'];
type Side = 'before' | 'after';
type Mode = 'side' | Side;

const columnName = (index: number) => {
  let n = index + 1;
  let name = '';
  while (n > 0) {
    const rest = (n - 1) % 26;
    name = String.fromCharCode(65 + rest) + name;
    n = Math.floor((n - 1) / 26);
  }
  return name;
};
const entityName = (type?: string) => (type ? uiLabel(type) : '민감정보');
// 막힌 요청은 보낸 것이 없으므로 표시한 값은 '찾은 값'이다 (내 요청 기록, 2026-10-09)
const BlockedContext = createContext(false);

// 바꾼 적중인지(2026-10-11): 대체 글자가 있으면 바꿈. 정책 값만 있으면(allow 등) 찾았지만 그대로 보냄. 둘 다 없는 옛 기록은 가린 값
const replaced = (span: Span) => span.replacement !== undefined || span.policy_action === undefined;

// HWP는 같은 길이(UTF-16 단위 수)로 덮어 보낸다(Gateway hwp_mask, 2026-10-12 표시 통일).
//  - 부분 가림(대체 글자가 값과 글자 수가 같음): 그 글자. 4바이트 글자(서로게이트 쌍)·쓸 수 없는 글자는 단위마다 '*'
//  - 그 밖([KR_RRN] 같은 표시): 표시가 값의 단위 수 이하면 표시 + 남는 자리 빈칸, 길면(또는 쓸 수 없는 글자) 단위마다 '*'
const writable = (char: string) => {
  const code = char.codePointAt(0) ?? 0;
  return code >= 0x20 && code <= 0xffff && !(code >= 0xd800 && code <= 0xdfff);
};
function hwpSent(value: string[], replacement?: string) {
  const units = value.join('').length;
  const swap = replacement === undefined ? undefined : Array.from(replacement);
  if (swap && swap.length === value.length)
    return value.map((char, index) => {
      const wide = (char.codePointAt(0) ?? 0) > 0xffff;
      return (wide || !writable(swap[index]) ? '*' : swap[index]).repeat(wide ? 2 : 1);
    }).join('');
  if (replacement !== undefined && replacement.length <= units && swap!.every(writable))
    return replacement + ' '.repeat(units - replacement.length);
  return '*'.repeat(units);
}

// 가린 뒤 보낸 표시(2026-10-12 통일): 모든 형식이 [유형] 표시. DOCX·XLSX·HWPX는 대체 글자, HWP는 같은 길이 규칙(hwpSent),
// PDF는 값을 지운 검은 상자 위에 흰 글자로 [유형](부분 가림 정책도 값 전체)
function SentValue({ format, value, span }: { format: Format; value: string[]; span: Span }) {
  const label = entityName(span.entity_type);
  if (format === 'pdf')
    return <span className="dops-file-rep box" role="img" aria-label={`${label} · 표시로 바꿈`} title={`${label} · 표시로 바꿈`}>
      {span.entity_type ? `[${span.entity_type}]` : span.replacement ?? '[마스킹]'}</span>;
  if (format === 'hwp') return <span className="dops-file-rep pad" title={`${label} · 같은 길이로 덮어씀`}>{hwpSent(value, span.replacement)}</span>;
  return <span className="dops-file-rep" title={label}>{span.replacement ?? '[마스킹]'}</span>;
}

function SegmentText({ segment, side }: { segment: Segment; side: Side }) {
  const blocked = useContext(BlockedContext);
  const chars = Array.from(segment.before);
  const spans = segment.spans.filter(span => span.end <= chars.length).sort((a, b) => a.start - b.start);
  if (!spans.length) return <>{side === 'after' && segment.after !== undefined ? segment.after : segment.before}</>;
  const parts: ReactNode[] = [];
  let at = 0;
  spans.forEach((span, index) => {
    if (span.start < at) return;
    parts.push(chars.slice(at, span.start).join(''));
    const label = entityName(span.entity_type);
    const value = chars.slice(span.start, span.end);
    if (!replaced(span))   // 정책상 그대로 보낸 값: 전·후 모두 원문, 점선 테두리로만 알린다
      parts.push(<span key={index} className="dops-file-flagged" title={blocked ? `${label} · 탐지(허용 정책)` : `${label} · 탐지(정책상 그대로 보냄)`}>{value.join('')}</span>);
    else parts.push(side === 'before'
      ? <mark key={index} className="dops-file-hl" title={blocked ? `${label} · 탐지` : `${label} · 마스킹`}>{value.join('')}</mark>
      : <SentValue key={index} format={segment.format} value={value} span={span} />);
    at = span.end;
  });
  parts.push(chars.slice(at).join(''));
  return <>{parts}</>;
}

// 위치를 남기지 못한 탐지 칸(10/9 이전 기록 등)은 칸 테두리로만 알린다
const flagged = (segment: Segment) => segment.decided_by === 'signature' && !segment.spans.length;

function SegmentBlock({ segment, side, as = 'span' }: { segment: Segment; side: Side; as?: 'span' | 'p' }) {
  const Tag = as;
  return <Tag className={flagged(segment) ? 'dops-file-flagged' : undefined} data-seg={segment.id}
    title={flagged(segment) ? `${segment.id} · 이 칸에서 탐지됨(위치 기록 없음)` : segment.id}>
    <SegmentText segment={segment} side={side} />
  </Tag>;
}

interface TableBlock { kind: 'table'; index: number; order?: number; rows: Map<number, Map<number, Segment[]>> }
interface ParagraphBlock { kind: 'paragraph'; index: number; order?: number; segment: Segment }
type Block = TableBlock | ParagraphBlock;

function docxAreas(segments: Segment[]) {
  const areas = new Map<string, { paragraphs: ParagraphBlock[]; tables: Map<number, TableBlock> }>();
  for (const segment of segments) {
    if (!areas.has(segment.area)) areas.set(segment.area, { paragraphs: [], tables: new Map() });
    const area = areas.get(segment.area)!;
    if (segment.table === undefined) {
      area.paragraphs.push({ kind: 'paragraph', index: segment.para ?? 0, order: segment.block_order, segment });
      continue;
    }
    if (!area.tables.has(segment.table)) area.tables.set(segment.table, { kind: 'table', index: segment.table, rows: new Map() });
    const table = area.tables.get(segment.table)!;
    if (segment.block_order !== undefined) table.order = Math.min(table.order ?? segment.block_order, segment.block_order);
    const row = segment.row ?? 0;
    if (!table.rows.has(row)) table.rows.set(row, new Map());
    const cells = table.rows.get(row)!;
    const col = segment.col ?? 0;
    cells.set(col, [...(cells.get(col) ?? []), segment]);
  }
  return areas;
}

function orderedBlocks(area: { paragraphs: ParagraphBlock[]; tables: Map<number, TableBlock> }): { blocks: Block[]; byOrder: boolean } {
  const blocks: Block[] = [...area.paragraphs, ...area.tables.values()];
  if (blocks.length && blocks.every(block => block.order !== undefined))
    return { blocks: blocks.sort((a, b) => a.order! - b.order! || a.index - b.index), byOrder: true };
  return { blocks: [...area.paragraphs.sort((a, b) => a.index - b.index), ...[...area.tables.values()].sort((a, b) => a.index - b.index)], byOrder: false };
}

function DocxTable({ table, side }: { table: TableBlock; side: Side }) {
  const rows = [...table.rows.keys()].sort((a, b) => a - b);
  const width = Math.max(...[...table.rows.values()].flatMap(cells => [...cells.keys()].map(col => col + 1)));
  return <div className="table-scroll"><table className="dops-file-table"><tbody>{rows.map(row => <tr key={row}>
    {Array.from({ length: width }, (_, col) => {
      const parts = (table.rows.get(row)?.get(col) ?? []).sort((a, b) => (a.para ?? 0) - (b.para ?? 0) || a.id.localeCompare(b.id));
      return <td key={col}>{parts.map(part => <SegmentBlock key={part.id} segment={part} side={side} as="p" />)}</td>;
    })}
  </tr>)}</tbody></table></div>;
}

function DocxPaper({ segments, side }: { segments: Segment[]; side: Side }) {
  const areas = docxAreas(segments);
  const names = [...areas.keys()];
  const headers = names.filter(name => name.startsWith('header')).sort();
  const footers = names.filter(name => name.startsWith('footer')).sort();
  const body = areas.get('body');
  const ordered = body ? orderedBlocks(body) : { blocks: [], byOrder: true };
  const plain = (name: string) => orderedBlocks(areas.get(name)!).blocks.map(block => block.kind === 'paragraph'
    ? <SegmentBlock key={block.segment.id} segment={block.segment} side={side} />
    : <DocxTable key={`t${block.index}`} table={block} side={side} />);
  return <>
    {headers.length > 0 && <div className="dops-file-hf head">{headers.map(name => <div key={name}>{plain(name)}</div>)}</div>}
    {!ordered.byOrder && ordered.blocks.some(block => block.kind === 'table') && ordered.blocks.some(block => block.kind === 'paragraph')
      && <p className="dops-file-note">문단·표 순서 기록이 없어 표를 문단 뒤에 표시합니다.</p>}
    {ordered.blocks.map(block => block.kind === 'paragraph'
      ? <SegmentBlock key={block.segment.id} segment={block.segment} side={side} as="p" />
      : <DocxTable key={`t${block.index}`} table={block} side={side} />)}
    {footers.length > 0 && <div className="dops-file-hf foot">{footers.map(name => <div key={name}>{plain(name)}</div>)}</div>}
  </>;
}

function XlsxPaper({ segments, side }: { segments: Segment[]; side: Side }) {
  const sheets = new Map<number, Segment[]>();
  for (const segment of segments) sheets.set(segment.sheet ?? 0, [...(sheets.get(segment.sheet ?? 0) ?? []), segment]);
  return <>{[...sheets.entries()].sort(([a], [b]) => a - b).map(([sheet, cells]) => {
    const rows = [...new Set(cells.map(cell => cell.row ?? 0))].sort((a, b) => a - b);
    const width = Math.max(...cells.map(cell => (cell.col ?? 0) + 1));
    const at = new Map(cells.map(cell => [`${cell.row ?? 0}:${cell.col ?? 0}`, cell]));
    return <section key={sheet} className="dops-file-sheet"><p className="dops-file-sheet-name">시트 {sheet + 1}</p>
      <div className="table-scroll"><table className="dops-file-grid"><thead><tr><th aria-label="행 번호" />
        {Array.from({ length: width }, (_, col) => <th key={col} scope="col">{columnName(col)}</th>)}</tr></thead>
        <tbody>{rows.map(row => <tr key={row}><th scope="row">{row + 1}</th>{Array.from({ length: width }, (_, col) => {
          const cell = at.get(`${row}:${col}`);
          return <td key={col}>{cell && <SegmentBlock segment={cell} side={side} />}</td>;
        })}</tr>)}</tbody></table></div></section>;
  })}</>;
}

// PDF(2026-10-11): Detection이 남긴 쪽 기록(body:p{쪽 번호}, 0부터). 글자 없는 쪽은 기록이 없어 건너뛴다
function PdfPaper({ segments, side }: { segments: Segment[]; side: Side }) {
  const pages = [...segments].sort((a, b) => (a.para ?? 0) - (b.para ?? 0));
  return <>{pages.map(page => <section key={page.id} className="dops-file-sheet" aria-label={`${(page.para ?? 0) + 1}쪽`}>
    <p className="dops-file-sheet-name">{(page.para ?? 0) + 1}쪽</p>
    <SegmentBlock segment={page} side={side} as="p" />
  </section>)}</>;
}

const paperFor = (format?: Format) => (format === 'xlsx' ? XlsxPaper : format === 'pdf' ? PdfPaper : DocxPaper);

// Claude 여러 파일(2026-10-11): 파일 번호마다 종이 하나(그 파일 형식으로). 번호가 없으면(ChatGPT·옛 기록) 지금처럼 한 장
interface FileGroup { key: string; title?: string; format?: Format; segments: Segment[] }
function fileGroups(comparison: FileComparison): FileGroup[] {
  if (!comparison.segments.some(segment => segment.file !== undefined)) return [{ key: 'all', format: comparison.format, segments: comparison.segments }];
  const byFile = new Map<number, Segment[]>();
  const loose: Segment[] = [];
  for (const segment of comparison.segments) {
    if (segment.file === undefined) loose.push(segment);
    else byFile.set(segment.file, [...(byFile.get(segment.file) ?? []), segment]);
  }
  const named = new Map((comparison.files ?? []).map(file => [file.file, file]));
  const groups: FileGroup[] = [...byFile.entries()].sort(([a], [b]) => a - b).map(([file, segments]) => {
    const format = named.get(file)?.format ?? segments[0].format;
    const filename = named.get(file)?.filename;
    return { key: `file${file}`, title: `파일 ${file + 1} · ${filename || format.toUpperCase()}`, format, segments };
  });
  if (loose.length) groups.unshift({ key: 'loose', format: loose[0].format, segments: loose });
  return groups;
}

// 나란히 보기 배치 (2026-10-12): 전·후 두 표의 열 폭을 같게 맞춰 같은 번호 행이 같은 높이에 오게 하고,
// 표가 반쪽 종이에 가로 스크롤 없이 들어가지 않을 때만 전·후를 위아래로 쌓는다(쌓은 두 표도 열 폭은 같게).
// 칸의 최소·최대 폭은 브라우저 표 배치(table-layout:auto + width:min-content / max-content)로 잰다.
const sum = (values: number[]) => values.reduce((total, value) => total + value, 0);
function columnRange(table: HTMLTableElement) {
  const cells = [...(table.rows[0]?.cells ?? [])];
  if (!cells.length) return null;
  // 소수점 폭을 %로 바꿀 때 반올림으로 칸이 1px 모자라 한 낱말이 접히지 않도록 올림 + 1px
  const measure = (cell: HTMLTableCellElement) => Math.ceil(cell.getBoundingClientRect().width) + 1;
  table.style.tableLayout = 'auto';
  table.style.width = 'min-content';
  const min = cells.map(measure);
  table.style.width = 'max-content';
  const max = cells.map((cell, index) => Math.max(min[index], measure(cell)));
  table.style.width = '';
  table.style.tableLayout = '';
  return { min, max };
}
// 브라우저 표 배치와 같은 방식: 최소 폭을 먼저 주고 남는 폭은 (최대 - 최소)에 비례해 나눈다
function distribute(min: number[], max: number[], room: number) {
  const low = sum(min);
  const high = sum(max);
  if (room <= low) return min;
  if (room >= high) return max.map(value => value * room / high);
  return min.map((value, index) => value + (max[index] - value) * (room - low) / (high - low));
}
function clearLayout(papers: HTMLElement[]) {
  for (const paper of papers) {
    for (const child of paper.children) (child as HTMLElement).style.minHeight = '';
    for (const table of paper.querySelectorAll('table')) {
      table.style.width = '';
      table.style.tableLayout = '';
      for (const cell of table.rows[0]?.cells ?? []) cell.style.width = '';
      for (const row of table.rows) row.style.height = '';
    }
  }
}
// stacked: 표가 반쪽에 안 들어가 이 화면이 쌓은 경우 / forced: 좁은 화면 규칙(CSS)이 쌓은 경우
function useAlignedPapers(ref: RefObject<HTMLDivElement | null>, deps: unknown[]) {
  const [stacked, setStacked] = useState(false);
  const [forced, setForced] = useState(false);
  useLayoutEffect(() => {
    const root = ref.current;
    if (!root) return;
    let lastWidth = -1;
    const run = () => {
      const papers = [...root.children].filter((el): el is HTMLElement => el instanceof HTMLElement && el.classList.contains('dops-file-paper'));
      clearLayout(papers);
      const width = root.clientWidth;
      lastWidth = width;
      const tables = papers.map(paper => [...paper.querySelectorAll('table')]);
      if (!width || papers.length !== 2 || tables[0].length !== tables[1].length) { setStacked(false); setForced(false); return; }
      const ranges = tables[0].map((table, index) => {
        const a = columnRange(table);
        const b = columnRange(tables[1][index]);
        if (!a || !b || a.min.length !== b.min.length) return null;
        return { min: a.min.map((value, i) => Math.max(value, b.min[i])), max: a.max.map((value, i) => Math.max(value, b.max[i])) };
      });
      // 종이 테두리·안쪽 여백은 배치와 상관없이 같으므로, 반쪽·전체 종이에서 표가 쓸 수 있는 폭을 지금 배치에서 계산한다
      const gap = parseFloat(getComputedStyle(root).columnGap) || 0;
      const roomFor = (table: HTMLTableElement, columns: number) => {
        const paper = table.closest('.dops-file-paper') as HTMLElement;
        const chrome = paper.getBoundingClientRect().width - (table.parentElement?.clientWidth ?? 0);
        return (columns === 2 ? (width - gap) / 2 : width) - chrome;
      };
      const applyWidths = (columns: number) => ranges.forEach((range, index) => {
        if (!range) return;
        for (const table of [tables[0][index], tables[1][index]]) {
          const room = roomFor(table, columns);
          const widths = distribute(range.min, range.max, room);
          const overflow = sum(range.min) > room;
          table.style.tableLayout = 'fixed';
          table.style.width = overflow ? `${sum(range.min)}px` : '100%';
          [...table.rows[0].cells].forEach((cell, i) => { cell.style.width = overflow ? `${widths[i]}px` : `${(widths[i] / room * 100).toFixed(3)}%`; });
        }
      });
      // 나란히일 때 같은 번호 행·문단의 높이를 큰 쪽에 맞춘다(모두 읽은 뒤 쓴다)
      const alignHeights = () => {
        // 두 행에 같은 값을 주어야 칸 테두리 계산까지 같아진다
        const rowWrites: Array<[HTMLTableRowElement, HTMLTableRowElement, number]> = [];
        tables[0].forEach((a, index) => {
          const b = tables[1][index];
          for (let i = 0; i < Math.min(a.rows.length, b.rows.length); i++) {
            const ha = a.rows[i].getBoundingClientRect().height;
            const hb = b.rows[i].getBoundingClientRect().height;
            if (Math.abs(ha - hb) > 0.01) rowWrites.push([a.rows[i], b.rows[i], Math.max(ha, hb)]);
          }
        });
        for (const [a, b, height] of rowWrites) { a.style.height = `${height}px`; b.style.height = `${height}px`; }
        const [left, right] = papers.map(paper => [...paper.children] as HTMLElement[]);
        if (left.length !== right.length) return;
        const blockWrites: Array<[HTMLElement, number]> = [];
        left.forEach((a, i) => {
          const ha = a.getBoundingClientRect().height;
          const hb = right[i].getBoundingClientRect().height;
          if (Math.abs(ha - hb) > 0.01) blockWrites.push(ha < hb ? [a, hb] : [right[i], ha]);
        });
        for (const [block, height] of blockWrites) block.style.minHeight = `${height}px`;
      };
      // 쌓을지: 좁은 화면 규칙(CSS)이 이미 한 줄이면 그대로. 아니면 표가 반쪽에 가로 스크롤 없이 안 들어가거나,
      // 나란히 놓아도 위아래로 쌓은 것보다 길어질 때(칸이 너무 좁아 줄이 많이 접힐 때) 쌓는다
      const hadClass = root.classList.contains('stacked');
      if (hadClass) root.classList.remove('stacked');
      const single = getComputedStyle(root).gridTemplateColumns.trim().split(/\s+/).length < 2;
      let stack = false;
      if (!single && ranges.some(Boolean)) {
        stack = ranges.some((range, index) => range !== null && sum(range.min) > roomFor(tables[0][index], 2) + 1);
        if (!stack) {
          applyWidths(2);
          alignHeights();
          const sideHeight = root.getBoundingClientRect().height;
          clearLayout(papers);
          root.classList.add('stacked');
          applyWidths(1);
          const stackedHeight = root.getBoundingClientRect().height;
          root.classList.remove('stacked');
          clearLayout(papers);
          stack = stackedHeight < sideHeight;
        }
      }
      if (hadClass) root.classList.add('stacked');
      if (stack !== hadClass) { setStacked(stack); return; }
      setForced(single);
      applyWidths(stack || single ? 1 : 2);
      if (!stack && !single) alignHeights();
    };
    run();
    if (typeof ResizeObserver === 'undefined') return;
    let frame = 0;
    const observer = new ResizeObserver(() => {
      if (root.clientWidth === lastWidth) return;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(run);
    });
    observer.observe(root);
    let alive = true;
    void document.fonts?.ready.then(() => { if (alive) run(); });
    return () => { alive = false; observer.disconnect(); cancelAnimationFrame(frame); };
  }, [...deps, stacked]);
  return { stacked, forced };
}

// 전·후 종이 한 쌍(파일 묶음 하나). 나란히 보기 맞춤 훅을 묶음마다 쓴다
function PaperPair({ group, sides, showIds, blocked, text, onStack, page = false }: {
  group: FileGroup; sides: Side[]; showIds: boolean; blocked: boolean; text: boolean; onStack: (key: string, stacked: boolean) => void; page?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const layout = useAlignedPapers(ref, [group, sides.join(','), showIds]);
  const both = sides.length === 2;
  useEffect(() => { onStack(group.key, both && (layout.stacked || layout.forced)); }, [group.key, both, layout.stacked, layout.forced, onStack]);
  const Paper = paperFor(group.format);
  return <div ref={ref} className={`dops-file-papers${both ? ' side' : ''}${both && layout.stacked ? ' stacked' : ''}${showIds ? ' show-seg' : ''}${page && group.format === 'xlsx' ? ' wide' : ''}`}>
    {sides.map(side => <article key={side} className="dops-file-paper" aria-label={side === 'before' ? (text ? '마스킹 전 입력' : '마스킹 전 원문') : '실제로 보낸 내용'}>
      <span className="dops-file-paper-label">{side === 'before'
        ? '전 · 원문' : '후 · 전송 내용'}</span>
      <BlockedContext.Provider value={blocked}><Paper segments={group.segments} side={side} /></BlockedContext.Provider>
    </article>)}
  </div>;
}

/** 항목 종류별 개수(가린 값 · 위치 없는 탐지 칸의 pii_hits) — 이벤트 상세 요약 줄도 쓴다 */
export function fileEntityCounts(segments: Segment[]) {
  const totals = new Map<string, number>();
  for (const segment of segments) {
    if (segment.spans.length) for (const span of segment.spans) totals.set(entityName(span.entity_type), (totals.get(entityName(span.entity_type)) ?? 0) + 1);
    else if (segment.decided_by === 'signature' && segment.pii_hits)
      for (const part of segment.pii_hits.split(',')) {
        const [type, count] = part.split(':');
        if (type && Number(count) > 0) totals.set(entityName(type), (totals.get(entityName(type)) ?? 0) + Number(count));
      }
  }
  return [...totals.entries()];
}

/** 형식별 표시 안내(PDF·HWP·재구성). layout='page'에서는 화면 맨 아래 '세부 정보'로 옮겨 보인다 */
export function fileComparisonNotes(comparison: FileComparison, { blocked = false, text = false }: { blocked?: boolean; text?: boolean } = {}) {
  const formats = new Set(comparison.segments.map(segment => segment.format));
  const notes: string[] = [];
  if (formats.has('pdf')) notes.push(blocked ? 'PDF는 쪽 단위로 재구성한 화면입니다.'
    : 'PDF는 값을 지우고 같은 자리에 [유형] 표시를 넣어 보냈습니다(부분 마스킹 정책도 값 전체). 쪽 단위로 재구성한 화면입니다.');
  if (formats.has('hwp') && !blocked) notes.push('HWP는 값을 같은 길이로 덮어 보냈습니다([유형] 표시 뒤는 빈칸, 표시가 값보다 길면 *, 부분 마스킹은 그 글자).');
  if (!text) notes.push('판정 기록의 칸 정보로 재구성한 화면입니다. 원본 파일은 저장하지 않으므로 글꼴·병합 셀·그림은 표시되지 않습니다.');
  return notes;
}

// variant='text': 질문처럼 칸 구조가 없는 글 한 덩어리(내 요청 기록). blocked: 막혀서 보내지 않은 요청이라 '후'가 없다
// '전'은 원문 그대로, 가린 값은 하이라이트로만 표시한다(서버가 원문을 보냄, 2026-10-09)
// layout='page'(2026-10-16 이벤트 상세 파일 마스킹 전·후): 보기 전환·범례·칸 번호를 한 줄로, 종이를 회색 책상 위 한 장으로(길면 그 안에서 스크롤).
//   항목별 개수는 화면 요약 줄, 형식 안내는 '세부 정보'(fileComparisonNotes)로 옮긴다. 내 요청 기록은 지금 모양('card') 그대로
export function FileComparisonView({ comparison, variant = 'file', blocked = false, layout = 'card' }:
  { comparison: FileComparison; variant?: 'file' | 'text'; blocked?: boolean; layout?: 'card' | 'page' }) {
  const text = variant === 'text';
  const afterRecorded = comparison.after_recorded === true && !blocked;
  const [mode, setMode] = useState<Mode>(afterRecorded ? 'side' : 'before');
  const [showIds, setShowIds] = useState(false);
  // 파일 묶음마다 나란히 맞춤을 따로 한다(Claude 여러 파일). 하나라도 위아래로 쌓였으면 보기 단추를 '위아래'로
  const groups = useMemo(() => (comparison.status === 'AVAILABLE' ? fileGroups(comparison) : []), [comparison]);
  const [stackedKeys, setStackedKeys] = useState<Record<string, boolean>>({});
  const reportStack = useCallback((key: string, value: boolean) =>
    setStackedKeys(prev => (prev[key] === value ? prev : { ...prev, [key]: value })), []);
  if (comparison.status !== 'AVAILABLE')
    return <p className="evidence-notice">{comparison.status === 'TOO_LARGE'
      ? (text ? '내용이 길어 비교를 표시하지 않습니다.' : '칸 수가 많아 파일 구조 비교를 표시하지 않습니다.')
      : (text ? '검사 기록이 없습니다.' : '칸별 검사 기록이 없습니다.')}</p>;
  const sides: Side[] = mode === 'side' ? ['before', 'after'] : [mode];
  const totals = fileEntityCounts(comparison.segments);
  const formats = new Set(comparison.segments.map(segment => segment.format));
  const sideStacked = sides.length === 2 && Object.values(stackedKeys).some(Boolean);
  const modes: Array<[Mode, string]> = [['side', sideStacked ? '위아래' : '나란히'], ['before', '전'], ['after', '후']];
  const papers = (group: FileGroup) =>
    <PaperPair key={group.key} group={group} sides={sides} showIds={showIds} blocked={blocked} text={text} onStack={reportStack} page={layout === 'page'} />;
  if (layout === 'page') return <div className="pg-evp-file">
    <div className="pg-evp-bar">
      <div className="pg-evp-seg" role="group" aria-label="보기 방식">{modes.map(([value, label]) =>
        <button key={value} type="button" aria-pressed={mode === value} disabled={value !== 'before' && !afterRecorded} onClick={() => setMode(value)}
          title={value === 'side' && sideStacked ? '폭이 좁아 전·후를 위아래로 놓았습니다' : undefined}>{label}</button>)}</div>
      <p className="pg-evp-legend">
        <span className="pg-evp-legend-item"><i className="pg-evp-swatch" aria-hidden="true" />{blocked ? '탐지 값' : '마스킹 값'}</span>
        {!blocked && [...formats].some(format => format !== 'pdf') && <span className="pg-evp-legend-item"><i className="pg-evp-swatch rep" aria-hidden="true" />대체 표시</span>}
        {!blocked && formats.has('pdf') && <span className="pg-evp-legend-item"><i className="pg-evp-swatch box" aria-hidden="true" />대체 표시(PDF)</span>}
        {!text && <label><input type="checkbox" checked={showIds} onChange={event => setShowIds(event.target.checked)} /> 칸 번호 표시</label>}
      </p>
    </div>
    {blocked && <p className="pg-evp-note" role="note">차단되어 전송되지 않은 요청입니다.</p>}
    {!afterRecorded && !blocked && <p className="pg-evp-note" role="note">{text ? '전송 내용(후)이 기록되지 않았습니다.'
      : '2026-10-09 이전 기록으로 전송 내용(후)이 없습니다. 탐지된 칸은 테두리로 표시됩니다.'}</p>}
    <div className="pg-evp-desk"><div className="pg-evp-scroll" role="region" tabIndex={0} aria-label={text ? '입력 내용' : '파일 내용'}>
      {groups.length === 1 && !groups[0].title ? papers(groups[0]) : groups.map(group =>
        <section key={group.key} className="dops-file-sheet-group" aria-label={group.title ?? '파일 번호 없는 칸'}>
          {group.title && <p className="dops-file-sheet-name">{group.title}</p>}
          {papers(group)}
        </section>)}
    </div></div>
  </div>;
  return <div className="dops-file-compare">
    <div className="dops-file-toolbar">
      <div className="dops-file-seg" role="group" aria-label="보기 방식">{modes.map(([value, label]) =>
        <button key={value} type="button" aria-pressed={mode === value} disabled={value !== 'before' && !afterRecorded} onClick={() => setMode(value)}
          title={value === 'side' && sideStacked ? '폭이 좁아 전·후를 위아래로 놓았습니다' : undefined}>{label}</button>)}</div>
      <div className="dops-file-legend">
        <span><i className="dops-file-swatch hl" />{blocked ? '탐지 값' : '마스킹 값'}</span>
        {!blocked && [...formats].some(format => format !== 'pdf') && <span><i className="dops-file-swatch rep" />대체 표시</span>}
        {!blocked && formats.has('pdf') && <span><i className="dops-file-swatch box" />대체 표시(PDF)</span>}
        {!text && <label><input type="checkbox" checked={showIds} onChange={event => setShowIds(event.target.checked)} /> 칸 번호 표시</label>}
      </div>
    </div>
    {totals.length > 0 && <p className="dops-file-totals">{totals.map(([name, count]) => <span key={name} className="dops-chip">{name} {count}</span>)}</p>}
    {blocked && <p className="dops-file-note" role="note">차단되어 전송되지 않은 요청입니다.</p>}
    {!afterRecorded && !blocked && <p className="dops-file-note" role="note">{text ? '전송 내용(후)이 기록되지 않았습니다.'
      : '2026-10-09 이전 기록으로 전송 내용(후)이 없습니다. 탐지된 칸은 테두리로 표시됩니다.'}</p>}
    {groups.length === 1 && !groups[0].title ? papers(groups[0]) : groups.map(group =>
      <section key={group.key} className="dops-file-sheet" aria-label={group.title ?? '파일 번호 없는 칸'}>
        {group.title && <p className="dops-file-sheet-name">{group.title}</p>}
        {papers(group)}
      </section>)}
    {formats.has('pdf') && <p className="dops-file-note">{blocked ? 'PDF는 쪽 단위로 재구성한 화면입니다.'
      : 'PDF는 값을 지우고 같은 자리에 [유형] 표시를 넣어 보냈습니다(부분 마스킹 정책도 값 전체). 쪽 단위로 재구성한 화면입니다.'}</p>}
    {formats.has('hwp') && !blocked && <p className="dops-file-note">HWP는 값을 같은 길이로 덮어 보냈습니다([유형] 표시 뒤는 빈칸, 표시가 값보다 길면 *, 부분 마스킹은 그 글자).</p>}
    {!text && <p className="dops-file-note">판정 기록의 칸 정보로 재구성한 화면입니다. 원본 파일은 저장하지 않으므로 글꼴·병합 셀·그림은 표시되지 않습니다.</p>}
  </div>;
}
