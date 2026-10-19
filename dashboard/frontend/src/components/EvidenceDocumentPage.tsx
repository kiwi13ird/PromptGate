import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronUp, FileText } from 'lucide-react';
import { Link } from 'react-router-dom';
import { evidenceService, type EventEvidence } from '@/src/services/evidenceService';
import { ApiError } from '@/src/api/errors';
import type { EnforcementResult } from '@/src/types/event';
import { formatDateTime, formatProcessingTime } from '@/src/utils/format';
import { uiLabel } from '@/src/utils/labels';
import { collapseRedactions, joinSegments, type CollapsedText, type TextUnit } from '@/src/utils/redactedText';
import { anchorOn, renderedRanges, structureUnits, type TextBlock } from '@/src/utils/textStructure';
import { type DiffRange } from '@/src/utils/textDiff';
import { SAME_RATIO_NAME, computeMatchRatio, formatSameRatio, type MatchRatio } from '@/src/utils/matchRatio';
import '@/src/styles/evidence-page.css';

// 이벤트 상세 '보호 문서 일치 구간'(2026-10-16 사용자 피드백 2차 "디자인은 그대로, 입력 좌측·원문 우측, 미일치 구간만 하이라이트").
// 원래(10/15 이전) 배치 그대로 왼쪽 '보낸 입력' · 오른쪽 '보호 문서 원문' 두 칸(좁은 화면은 위아래). 각 칸은 종이처럼 본문 전체, 길면 칸 안에서 스크롤.
// 군더더기(일치 구간 칩·초록 확인 박스·반복 설명·여러 접기)는 없애고 요약 한 줄 + 맨 아래 '세부 정보' 하나(EvidenceDetails).
// 강조는 미일치만: 왼쪽 = 보호 문서에 없는 입력 부분, 오른쪽 = 입력에 대응하는 범위 안에서 입력과 다른 부분(그 밖의 문서 나머지는 흐린 평문).
// 본문은 기존 쪽 API(1,800자씩)를 끝까지 이어 받는다. 대조는 화면에서 공백·줄바꿈을 빼고(utils/textDiff), 가림(█) 덩어리는 짧은 표시 하나로 접고
// 대조 때도 같은 토큰으로 본다(utils/redactedText). 서버 확인과 어긋나면 강조 없이 '원문 대조 불가' 한 줄(diffDistrust).

const PAGE_SIZE = 1800;
const PARALLEL = 4;
type Comparison = EventEvidence['comparisons'][number];
type Metadata = NonNullable<EventEvidence['metadata']>;
type Side = 'input' | 'document';
type FullText = { status: 'AVAILABLE'; text: string; runs: DiffRange[]; total: number; source?: string } | { status: 'NOT_RECORDED' | 'MISMATCH' | 'TOO_LARGE' | 'INVALID_RANGE' };

const percent = (value: number) => `${(value * 100).toLocaleString('ko-KR', { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;
// 서버 비율의 정확한 이름·뜻(2026-10-16 확인: Detection windowhash engine.py). 30자 창 해시가 이 문서에서만 나온 창(2개 이상 문서에 있는 창 제외)의
// 입력 구간 합집합 ÷ 입력 글자 수. 긴 입력은 앞 2,000개 창 뒤로 50개마다 1개만 조회(표본)해, 전문을 그대로 붙여 넣어도 낮게 나온다
// (11_AI기술기획서 19,373자 전문: 모든 조회 창이 일치해도 최대 65.6% → 기록 65.5%). '얼마나 같은가'가 아니다
export const serverCoverageName = (comparison: Comparison) => comparison.coverage_basis === 'CONFIRMED_WINDOW_INTERVALS' ? '해시 근거 비율' : '해시 근거 비율(이전 방식)';
export function serverCoverageNote(comparison: Comparison) {
  if (comparison.coverage_basis !== 'CONFIRMED_WINDOW_INTERVALS') return '이전 계산 방식의 탐지 범위 비율입니다. 범위 안의 수정·삽입 문장이 포함될 수 있어 전체 문서 유사도로 해석하면 안 됩니다.';
  return `30자 창 해시가 이 문서에서만 나온 곳(여러 문서에 공통인 문구 제외)만 센 입력 비율입니다.${comparison.coverage_sampled ? ' 긴 입력이라 앞 2,000개 창 뒤로는 50개마다 하나만 조회한 표본 기록이어서, 전문을 그대로 붙여 넣어도 낮게 나옵니다.' : ''} 탐지 근거의 양이지 입력이 문서와 얼마나 같은지가 아닙니다.`;
}

/** 한 쪽(입력·문서) 본문 전체: 첫 쪽으로 길이를 알고 나머지 쪽을 몇 개씩 나눠 받는다(가림 조각 위치도 같이) */
async function loadFullText(eventId: string, side: Side, documentId: string, signal: AbortSignal | undefined, onProgress: (done: number, total: number) => void): Promise<FullText> {
  const first = await evidenceService.getPage(eventId, side, 0, documentId, signal);
  if (first.status !== 'AVAILABLE') return { status: first.status };
  const firstText = first.segments?.map((part) => part.text).join('') ?? '';
  const total = first.total_chars ?? Array.from(firstText).length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const parts: Array<Array<{ text: string; redacted?: boolean }>> = Array.from({ length: pages }, () => []);
  parts[0] = first.segments ?? [];
  let next = 1;
  let done = 1;
  onProgress(done, pages);
  const worker = async () => {
    while (next < pages) {
      const index = next++;
      const page = await evidenceService.getPage(eventId, side, index * PAGE_SIZE, documentId, signal);
      if (page.status !== 'AVAILABLE') throw new ApiError('본문 일부를 불러오지 못했습니다.', 'INVALID_RESPONSE');
      parts[index] = page.segments ?? [];
      done++;
      onProgress(done, pages);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL, pages - 1) }, worker));
  const { text, runs } = joinSegments(parts);
  return { status: 'AVAILABLE', text, runs, total, source: first.content_source };
}

function useFullText(eventId: string, side: Side, documentId: string) {
  const [progress, setProgress] = useState<{ done: number; total: number }>();
  const query = useQuery({
    // 'evidence-page' 접두어: 상세 화면 [새로고침]이 같이 다시 받는다. 본문은 바뀌지 않으므로 자동 갱신은 하지 않는다
    queryKey: ['evidence-page', eventId, 'full', side, documentId],
    queryFn: ({ signal }) => loadFullText(eventId, side, documentId, signal, (done, total) => setProgress({ done, total })),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  return { query, progress };
}

const clip = (range: DiffRange, span?: DiffRange): DiffRange | undefined => {
  if (!span) return undefined;
  const start = Math.max(range.start, span.start);
  const end = Math.min(range.end, span.end);
  return end > start ? { start, end } : undefined;
};
const overlaps = (a: DiffRange, b?: DiffRange) => Boolean(b && a.start < b.end && b.start < a.end);

interface RenderContext { marks: DiffRange[]; current?: DiffRange; faintOutside?: DiffRange; anchors: Set<number> }

/** 단위 [start, end) → 화면 조각. marks = 강조(미일치), faint = 이 범위 밖은 흐리게, anchors = 이동용 빈 표시 */
function renderSlice(units: TextUnit[], start: number, end: number, { marks, current, faintOutside, anchors }: RenderContext): ReactNode[] {
  const edges = new Set<number>([start, end]);
  // 이 구간과 겹치는 강조만(정렬돼 있으므로 이분 탐색으로 시작점)
  let lo = 0, hi = marks.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (marks[mid].end > start) hi = mid; else lo = mid + 1; }
  const local = [];
  for (let index = lo; index < marks.length && marks[index].start < end; index++) local.push(marks[index]);
  for (const range of local) { edges.add(Math.max(start, range.start)); edges.add(Math.min(end, range.end)); }
  if (faintOutside) for (const at of [faintOutside.start, faintOutside.end]) if (at > start && at < end) edges.add(at);
  for (const at of anchors) if (at >= start && at < end) edges.add(at);
  const points = [...edges].sort((a, b) => a - b);
  const out: ReactNode[] = [];
  let markIndex = 0;
  const content = (from: number, to: number) => {
    const parts: ReactNode[] = [];
    let buffer = '';
    for (let at = from; at < to; at++) {
      const unit = units[at];
      if (typeof unit === 'string') { buffer += unit; continue; }
      if (buffer) { parts.push(buffer); buffer = ''; }
      parts.push(<span key={`r${at}`} className="pg-evp-redact" title={`개인정보·자격증명 가림 표시 · 원래 ${unit.redacted.toLocaleString('ko-KR')}자`}>가림</span>);
    }
    if (buffer) parts.push(buffer);
    return parts;
  };
  for (let index = 0; index < points.length - 1; index++) {
    const from = points[index];
    const to = points[index + 1];
    if (anchors.has(from)) out.push(<span key={`a${from}`} className="pg-evp-anchor" data-at={from} />);
    if (to <= from) continue;
    while (markIndex < local.length && local[markIndex].end <= from) markIndex++;
    const mark = local[markIndex];
    const inMark = Boolean(mark && mark.start <= from && mark.end >= to);
    const faint = Boolean(faintOutside && (to <= faintOutside.start || from >= faintOutside.end));
    const body = content(from, to);
    if (inMark) out.push(<mark key={`m${from}`} className={overlaps({ start: from, end: to }, current) ? 'pg-evp-diff is-current' : 'pg-evp-diff'} data-start={from}>{body}</mark>);
    else if (faint) out.push(<span key={`f${from}`} className="pg-evp-faint">{body}</span>);
    else out.push(...body.map((part, i) => (typeof part === 'string' ? <span key={`t${from}-${i}`}>{part}</span> : part)));
  }
  return out;
}

/** 글 구조(문단·제목·표)대로 그린다(utils/textStructure). 표 칸 안에서도 강조·가림·이동 표시가 같은 규칙 */
function renderDocument(units: TextUnit[], blocks: TextBlock[], context: RenderContext): ReactNode[] {
  return blocks.map((block) => {
    if (block.kind === 'blank') return <div key={`b${block.start}`} className="pg-evp-gap" aria-hidden="true" />;
    if (block.kind === 'table') {
      const width = Math.max(...block.rows.map((row) => row.cells.length));
      const faint = Boolean(context.faintOutside && (block.end <= context.faintOutside.start || block.start >= context.faintOutside.end));
      return <div key={`t${block.start}`} className={faint ? 'pg-evp-table-wrap is-faint' : 'pg-evp-table-wrap'}><table className="pg-evp-table"><tbody>
        {block.rows.map((row, rowIndex) => {
          const Cell = rowIndex === 0 ? 'th' : 'td';
          return <tr key={row.start}>{row.cells.map((cell, cellIndex) => <Cell key={cell.start} colSpan={cellIndex === row.cells.length - 1 && row.cells.length < width ? width - row.cells.length + 1 : undefined} scope={rowIndex === 0 ? 'col' : undefined}>
            {renderSlice(units, cell.start, cell.end, context)}</Cell>)}</tr>;
        })}
      </tbody></table></div>;
    }
    const Tag = block.kind === 'heading' ? 'h5' : 'p';
    return <Tag key={`${block.kind}${block.start}`} className={block.kind === 'heading' ? 'pg-evp-h' : 'pg-evp-p'}>{renderSlice(units, block.start, block.end, context)}</Tag>;
  });
}

// 대조를 믿지 않을 이유(diffDistrust)·같은 글자 비율은 utils/matchRatio.ts(서버와 같은 원본)

function scrollToAnchor(container: HTMLElement | null, at: number | undefined) {
  if (!container || at === undefined) return;
  const target = container.querySelector<HTMLElement>(`[data-at="${at}"]`);
  if (!target) return;
  container.scrollTop = Math.max(0, container.scrollTop + target.getBoundingClientRect().top - container.getBoundingClientRect().top - 48);
  // 좁은 폭에서 가로로 넘치는 표: 그 칸이 보이게 표만 가로로 옮긴다
  const wrap = target.closest<HTMLElement>('.pg-evp-table-wrap');
  if (wrap) wrap.scrollLeft = Math.max(0, wrap.scrollLeft + target.getBoundingClientRect().left - wrap.getBoundingClientRect().left - 24);
}

export function EvidenceDocumentPage({ eventId, comparison, metadata }: {
  eventId: string; comparison: Comparison; metadata?: Metadata;
}) {
  const [cursor, setCursor] = useState(-1);
  const leftRef = useRef<HTMLDivElement>(null);
  const rightRef = useRef<HTMLDivElement>(null);
  const input = useFullText(eventId, 'input', comparison.document_id);
  const documentText = useFullText(eventId, 'document', comparison.document_id);
  const inputData = input.query.data;
  const documentData = documentText.query.data;
  // 같은 글자 비율·대조 결과: 서버(목록 응답)와 같은 원본 utils/matchRatio. 서버 기록과 어긋나면 강조하지 않고 '원문 대조 불가' 한 줄
  const result: MatchRatio | undefined = useMemo(() => (inputData?.status === 'AVAILABLE' && documentData?.status === 'AVAILABLE'
    ? computeMatchRatio(inputData, documentData, comparison) : undefined), [inputData, documentData, comparison]);
  const left: CollapsedText | undefined = useMemo(() => result?.left ?? (inputData?.status === 'AVAILABLE' ? collapseRedactions(inputData.text, inputData.runs) : undefined), [result, inputData]);
  const right: CollapsedText | undefined = useMemo(() => result?.right ?? (documentData?.status === 'AVAILABLE' ? collapseRedactions(documentData.text, documentData.runs) : undefined), [result, documentData]);
  const distrust = result?.state === 'UNAVAILABLE' ? result.reason : undefined;
  const diff = result?.state === 'READY' ? result.diff : undefined;
  // 오른쪽: 입력에 대응하는 범위(같은 글자가 처음~마지막으로 나오는 곳) 안의 미일치만. 그 밖은 흐린 평문
  const span = diff?.bSpan;
  const rightMarks = useMemo(() => (diff ? diff.b.map((range) => clip(range, span)).filter((range): range is DiffRange => Boolean(range)) : []), [diff, span]);
  const hunks = useMemo(() => (diff ? diff.hunks.map((hunk) => ({ ...hunk, b: hunk.b ? clip(hunk.b, span) : undefined }))
    .filter((hunk) => hunk.a || hunk.b) : []), [diff, span]);
  const current = cursor >= 0 ? hunks[cursor] : undefined;
  // 글 구조(문단·제목·표). 이동 표시는 그려지는 글자 위로 옮겨 둔다(줄바꿈·칸 구분 자리에는 그릴 곳이 없음)
  const leftBlocks = useMemo(() => (left ? structureUnits(left.units) : []), [left]);
  const rightBlocks = useMemo(() => (right ? structureUnits(right.units) : []), [right]);
  const leftDrawn = useMemo(() => renderedRanges(leftBlocks), [leftBlocks]);
  const rightDrawn = useMemo(() => renderedRanges(rightBlocks), [rightBlocks]);
  const leftAt = (hunk: (typeof hunks)[number]) => anchorOn(leftDrawn, hunk.a?.start ?? hunk.aAt);
  const rightAt = (hunk: (typeof hunks)[number]) => anchorOn(rightDrawn, hunk.b?.start ?? Math.min(Math.max(hunk.bAt, span?.start ?? 0), span?.end ?? hunk.bAt));
  const spanAt = span ? anchorOn(rightDrawn, span.start) : undefined;
  const leftAnchors = new Set(hunks.map(leftAt));
  const rightAnchors = new Set([...hunks.map(rightAt), ...(spanAt !== undefined ? [spanAt] : [])]);
  // 처음: 오른쪽을 입력에 대응하는 범위로
  useEffect(() => { if (spanAt !== undefined) scrollToAnchor(rightRef.current, spanAt); }, [spanAt]);
  const jump = (step: 1 | -1) => {
    if (!hunks.length) return;
    const next = cursor < 0 ? (step > 0 ? 0 : hunks.length - 1) : (cursor + step + hunks.length) % hunks.length;
    setCursor(next);
    const hunk = hunks[next];
    scrollToAnchor(leftRef.current, leftAt(hunk));
    scrollToAnchor(rightRef.current, rightAt(hunk));
  };
  const name = comparison.document_name ?? comparison.document_id;
  const compareFailed = [input, documentText].some((side) => side.query.isError || (side.query.data !== undefined && side.query.data.status !== 'AVAILABLE'));
  const legend = distrust ? `원문 대조 불가 · ${distrust} 다른 부분을 강조하지 않음`
    : !diff ? (compareFailed ? '본문을 불러오지 못해 다른 부분을 표시하지 않습니다' : '다른 부분 계산 중…')
    : hunks.length ? '강조 = 서로 다른 부분' : '서로 다른 부분 없음(공백·줄바꿈 제외)';
  const pane = (side: Side) => {
    const state = side === 'input' ? input : documentText;
    const data = state.query.data;
    const collapsed = side === 'input' ? left : right;
    const total = data?.status === 'AVAILABLE' ? data.total : undefined;
    const body = state.query.isLoading
      ? <p className="pg-evp-state" role="status">본문을 불러오는 중{state.progress && state.progress.total > 1 ? ` · ${state.progress.done} / ${state.progress.total}` : ''}…</p>
      : state.query.isError
        ? <p className="pg-evp-state" role="status">본문을 불러오지 못했습니다. <button type="button" className="pg-evp-link" onClick={() => state.query.refetch()}>다시 시도</button></p>
        : !collapsed ? <p className="pg-evp-state">이 기록은 안전하게 연결할 비교 텍스트가 없습니다.</p>
        : collapsed.units.length === 0 ? <p className="pg-evp-state">본문 내용 없음 · 빈 문자열이 기록되었습니다.</p>
        : <div className="pg-evp-text">{renderDocument(collapsed.units, side === 'input' ? leftBlocks : rightBlocks, side === 'input'
          ? { marks: diff?.a ?? [], current: current?.a, anchors: leftAnchors }
          : { marks: rightMarks, current: current?.b, faintOutside: span, anchors: rightAnchors })}</div>;
    const source = side === 'input' ? '당시 입력' : comparison.document_source === 'EVENT_DOCUMENT_VERSION' ? `사건 당시 보존본${comparison.recorded_document_version ? ` v${comparison.recorded_document_version}` : ''}` : '현재 저장본';
    return <section className="pg-evp-pane">
      <header className="pg-evp-pane-head">
        <h4>{side === 'input' ? '보낸 입력' : '보호 문서 원문'}</h4>
        <span>{source}{total !== undefined ? ` · ${total.toLocaleString('ko-KR')}자` : ''}</span>
      </header>
      <div className="pg-evp-desk">
        <div ref={side === 'input' ? leftRef : rightRef} className="pg-evp-scroll" role="region" tabIndex={0} aria-label={side === 'input' ? '보낸 입력 문서' : '보호 문서 원문'}>
          <div className="pg-evp-paper">{body}</div>
        </div>
      </div>
    </section>;
  };
  const anyRedaction = Boolean(left?.redactions || right?.redactions);
  return <article className="pg-evp" aria-label={`${name} 비교`}>
    <p className="pg-evp-summary">
      <FileText aria-hidden="true" className="pg-evp-icon" />
      <Link className="pg-evp-doc" to={`/documents/${encodeURIComponent(comparison.document_id)}`} title={name}>{name}</Link>
      {diff
        ? <span title="공백·줄바꿈을 빼고 보낸 입력의 글자 중 보호 문서와 같은 글자의 비율(화면 대조). 서버의 해시 근거 비율은 세부 정보"><span className="pg-evp-key">{SAME_RATIO_NAME}</span> <b>{result?.state === 'READY' ? formatSameRatio(result.ratio) : ''}</b></span>
        : <span title={serverCoverageNote(comparison)}><span className="pg-evp-key">{serverCoverageName(comparison)}</span> <b>{percent(comparison.coverage)}</b></span>}
      {metadata?.input_chars !== undefined && <span><span className="pg-evp-key">입력</span> <b>{metadata.input_chars.toLocaleString('ko-KR')}자</b></span>}
      {metadata?.detection_ms !== undefined && <span><span className="pg-evp-key">보안 검사</span> <b>{formatProcessingTime(metadata.detection_ms)}</b></span>}
    </p>
    <div className="pg-evp-bar">
      <p className="pg-evp-legend" role="status">
        {diff && hunks.length > 0 && <i className="pg-evp-swatch" aria-hidden="true" />}
        <span>{legend}</span>
        {diff && span && <span className="pg-evp-legend-item"><i className="pg-evp-swatch faint" aria-hidden="true" />흐린 글 = 입력에 쓰이지 않은 문서 부분</span>}
        {anyRedaction && <span className="pg-evp-legend-item"><span className="pg-evp-redact">가림</span> = 개인정보·자격증명 가림 표시</span>}
      </p>
      {diff && hunks.length > 0 && <p className="pg-evp-nav-group">
        <span className="pg-evp-count">{cursor >= 0 ? `${cursor + 1} / ` : ''}{hunks.length.toLocaleString('ko-KR')}곳</span>
        <button type="button" className="pg-evp-nav" aria-label="이전 다른 부분" title="이전 다른 부분(양쪽 함께 이동)" onClick={() => jump(-1)}><ChevronUp aria-hidden="true" /></button>
        <button type="button" className="pg-evp-nav" aria-label="다음 다른 부분" title="다음 다른 부분(양쪽 함께 이동)" onClick={() => jump(1)}><ChevronDown aria-hidden="true" /></button>
      </p>}
    </div>
    <div className="pg-evp-pair">{pane('input')}{pane('document')}</div>
  </article>;
}

const statusLabels: Record<string, string> = { ok: '정상', error: '오류', skipped: '미실행' };

/** 맨 아래 '세부 정보' 하나: 문서마다 산정 기준·위치·보존 버전·집행, 그리고 당시 탐지 기록 */
export function EvidenceDetails({ comparisons = [], metadata, finalAction, enforcement, raw = false, notes = [] }: {
  comparisons?: Comparison[]; metadata?: Metadata; finalAction?: string; enforcement?: EnforcementResult; raw?: boolean; notes?: string[];
}) {
  const many = comparisons.length > 1;
  const row = (term: string, value: ReactNode) => <div><dt>{term}</dt><dd>{value}</dd></div>;
  return <details className="pg-evp-details">
    <summary>세부 정보</summary>
    {comparisons.map((comparison, index) => {
      const name = comparison.document_name ?? comparison.document_id;
      const event = comparison.document_source === 'EVENT_DOCUMENT_VERSION';
      const current = [comparison.current_document_version && `버전 ${comparison.current_document_version}`, comparison.current_classification,
        comparison.current_index_status && `색인 ${uiLabel(comparison.current_index_status)}`,
        comparison.document_chars !== undefined && `정규화 텍스트 ${comparison.document_chars.toLocaleString('ko-KR')}자`].filter(Boolean).join(' · ');
      const where = (location: { char_start: number; char_end: number } | undefined, total?: number) => location
        ? `${location.char_start.toLocaleString('ko-KR')}–${location.char_end.toLocaleString('ko-KR')}자${total !== undefined ? ` / 전체 ${total.toLocaleString('ko-KR')}자` : ''}` : '당시 미기록';
      return <section key={`${comparison.document_id}-${index}`} className="pg-evp-details-group" aria-label={`${name} 세부 정보`}>
        {many && <h4>{name}</h4>}
        <dl>
          {row('탐지', `${finalAction === 'BLOCK' ? (enforcement?.applied ? '보호 문서 내용 탐지 · 게이트웨이 차단 집행 확인' : '보호 문서 내용 탐지 · 최종 조치 차단 · 집행 여부는 별도 확인') : '보호 문서와 겹치는 내용 탐지'} · 문서 구간 해시 일치`)}
          {row(`${serverCoverageName(comparison)}${comparison.coverage_basis === 'CONFIRMED_WINDOW_INTERVALS' ? '(여러 문서 공통 문구 제외)' : ''}`, `${percent(comparison.coverage)} · ${serverCoverageNote(comparison)}`)}
          {row('강조 기준', `공백·줄바꿈을 빼고 낱말·글자 단위로 ${event ? '사건 당시 문서 보존본' : '현재 저장본'}과 대조한 결과입니다. 당시 해시 창별 기록의 재현은 아닙니다. 서버가 같은 글로 확인한 문장과 어긋나면(본문 일부만 저장·판 차이 등) 강조하지 않고 '원문 대조 불가'로 알립니다.${raw ? '' : ' 가린 값(가림 표시)은 양쪽이 같은 자리를 가렸으면 같은 것으로 봅니다(값끼리 같은지는 알 수 없음).'} 원본 서식은 재현하지 않고(입력 파일 원본은 보관하지 않음), 추출 텍스트의 문단·번호 제목·표(칸을 ' | '로 이은 줄)만 문서처럼 그립니다.`)}
          {(comparison.current_text_equal_ignoring_whitespace !== undefined || !!comparison.matching_passages?.length) && row('본문 대조', comparison.current_text_equal_ignoring_whitespace
            ? '공백·줄바꿈 제외 본문 동일'
            : `${comparison.current_text_equal_ignoring_whitespace === false ? '일부 내용은 다르지만 ' : ''}같은 문장 확인${comparison.matching_passages?.length ? ` ${comparison.matching_passages.length}곳` : ''}(서버 대조)`)}
          {row('탐지 구간', <>입력 {where(comparison.input_location, metadata?.input_chars)}<br />보호 문서 {where(comparison.document_location, comparison.document_chars)} · 끝 좌표 미포함</>)}
          {row('보호 문서', <><Link to={`/documents/${encodeURIComponent(comparison.document_id)}`}>{name}</Link> · {event
            ? `사건 당시 색인된 보호 문서 버전 ${comparison.recorded_document_version ?? '미기록'}의 보존본입니다. 이후 원본이 바뀌어도 이 비교 근거는 유지됩니다.`
            : '현재 RDS 저장본으로, 당시 원문 스냅샷은 아닙니다.'}{current ? <><br />{event ? '보존 문서 정보' : '현재 문서 정보'}: {current}</> : null}</>)}
        </dl>
      </section>;
    })}
    {notes.length > 0 && <section className="pg-evp-details-group" aria-label="표시 안내">{notes.map(note => <p key={note}>{note}</p>)}</section>}
    {metadata && <section className="pg-evp-details-group" aria-label="당시 탐지 기록">
      <h4>당시 탐지 기록</h4>
      <dl>
        {metadata.detection_reason && <div className="pg-evp-wide"><dt>당시 탐지 사유</dt><dd>{metadata.detection_reason}</dd></div>}
        {metadata.detection_ms !== undefined && row('탐지 처리시간', formatProcessingTime(metadata.detection_ms))}
        {metadata.input_chars !== undefined && row('검사한 입력 글자 수', `${metadata.input_chars.toLocaleString()}자`)}
        {metadata.hash_status && row('해시 검사 상태', statusLabels[metadata.hash_status] ?? metadata.hash_status)}
        {metadata.signature_status && row('시그니처 검사 상태', statusLabels[metadata.signature_status] ?? metadata.signature_status)}
        {metadata.input_filename && row('검사한 파일명', metadata.input_filename)}
        {metadata.decision_at && row('탐지 기록 시각', formatDateTime(metadata.decision_at))}
      </dl>
    </section>}
  </details>;
}
