import type { OverviewPeriod, SecurityEvent, DashboardStats } from '@/src/types/event';

export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;
const KST_OFFSET = 9 * HOUR_MS;
export const periodMilliseconds = (period: OverviewPeriod) => period === '24H' ? DAY_MS : period === '7D' ? 7 * DAY_MS : 30 * DAY_MS;
export const kstDayKey = (timestamp: number) => new Date(timestamp + KST_OFFSET).toISOString().slice(0, 10);
const floorBucket = (timestamp: number, step: number) => Math.floor((timestamp + KST_OFFSET) / step) * step - KST_OFFSET;

export interface EventTimeBucket {
  bucket: string;
  timestamp: string;
  start: number;
  end: number;
  partial: boolean;
  total: number;
  block: number;
  mask: number;
  allow: number;
  averageLatencyMs?: number;
  p95LatencyMs?: number;
}
export interface EventSeries {
  buckets: EventTimeBucket[];
  issues: string[];
  asOf: number;
  from: number;
  boundaryBucket: boolean;
}

/** Only real API rows create nonzero values. Zeroes denote no row in a time bucket.
 * The API uses a rolling interval, not calendar days. Retain an occupied partial
 * start bucket rather than discard it to force exactly 24/7/30 calendar buckets.
 */
/** 행의 조치: 요청 단위 묶음이면 묶음 조치(질문·첨부 파일 중 가장 강한 것, 보안 이벤트 목록과 같음), 아니면 그 기록의 조치 */
export const rowAction = (event: SecurityEvent) => event.groupFinalAction ?? event.finalAction;

export function normalizeEventSeries(events: SecurityEvent[], period: OverviewPeriod, asOf: number): EventSeries {
  const step = period === '24H' ? HOUR_MS : DAY_MS;
  const count = period === '24H' ? 24 : period === '7D' ? 7 : 30;
  const from = asOf - periodMilliseconds(period);
  const endStart = floorBucket(asOf, step);
  const firstBase = endStart - (count - 1) * step;
  const earliest = floorBucket(from, step);
  const issues: string[] = [];
  const rows = new Map<number, SecurityEvent[]>();
  const seen = new Set<string>();
  for (const event of events) {
    const t = Date.parse(event.occurredAt);
    if (!Number.isFinite(t)) { issues.push('발생 시각이 올바르지 않은 기록이 있습니다.'); continue; }
    if (t > asOf) { issues.push('조회 기준 시각보다 미래인 기록이 있습니다.'); continue; }
    if (t < from) { issues.push('선택 기간 밖의 기록이 응답에 포함돼 있습니다.'); continue; }
    if (seen.has(event.eventId)) { issues.push('중복 이벤트 ID가 응답에 포함돼 있습니다.'); continue; }
    seen.add(event.eventId);
    const key = floorBucket(t, step);
    const group = rows.get(key);
    if (group) group.push(event);
    else rows.set(key, [event]);
  }
  const boundaryBucket = earliest < firstBase && rows.has(earliest);
  const first = boundaryBucket ? earliest : firstBase;
  const buckets: EventTimeBucket[] = [];
  for (let start = first; start <= endStart; start += step) {
    const bucketRows = rows.get(start) ?? [];
    const processing = bucketRows.map(e => e.processingMs).filter((v): v is number => v !== undefined && Number.isFinite(v) && v >= 0).sort((a, b) => a - b);
    const block = bucketRows.filter(e => rowAction(e) === 'BLOCK').length;
    const mask = bucketRows.filter(e => rowAction(e) === 'MASK').length;
    const allow = bucketRows.filter(e => rowAction(e) === 'ALLOW').length;
    if (block + mask + allow !== bucketRows.length) issues.push('최종 조치별 건수와 구간 전체 건수가 일치하지 않습니다.');
    buckets.push({bucket: period === '24H' ? new Date(start).toISOString() : kstDayKey(start), timestamp: new Date(start).toISOString(), start, end: start + step, partial: start < from || start + step > asOf, total: bucketRows.length, block, mask, allow,
      ...(processing.length ? {averageLatencyMs: processing.reduce((a, b) => a + b, 0) / processing.length, p95LatencyMs: processing[Math.ceil(processing.length * .95) - 1]} : {})});
  }
  return {buckets, issues: [...new Set(issues)], asOf, from, boundaryBucket};
}

export function overviewIntegrityIssues(stats: DashboardStats, events: SecurityEvent[], series: EventSeries) {
  const issues = [...series.issues];
  const count = (action: string) => events.filter(e => rowAction(e) === action).length;
  if (stats.allow === undefined) issues.push('허용 건수가 API에 제공되지 않았습니다.');
  else if (stats.total !== stats.block + stats.mask + stats.allow) issues.push('전체 건수와 최종 조치별 합계가 일치하지 않습니다.');
  if (stats.total !== events.length || stats.block !== count('BLOCK') || stats.mask !== count('MASK') || (stats.allow !== undefined && stats.allow !== count('ALLOW'))) issues.push('집계 API와 사건 목록의 조회 결과가 달라졌습니다. 새로고침해 확인하세요.');
  if (stats.newEvents !== events.filter(e => e.status === 'NEW').length) issues.push('신규 상태 집계와 사건 목록이 일치하지 않습니다.');
  if (series.buckets.reduce((n, b) => n + b.total, 0) !== stats.total) issues.push('시간 구간 합계와 전체 이벤트 건수가 일치하지 않습니다.');
  const ordered = [...events].sort((a, b) => Date.parse(b.occurredAt) - Date.parse(a.occurredAt));
  if (stats.lastSuccessAt && ordered[0] && Date.parse(stats.lastSuccessAt) !== Date.parse(ordered[0].occurredAt)) issues.push('최신 기록 시각과 최근 사건이 일치하지 않습니다.');
  const eventIds = new Set(events.map(event => event.eventId));
  if (stats.recent.some((event, index) => !eventIds.has(event.eventId) || Date.parse(event.occurredAt) !== Date.parse(ordered[index]?.occurredAt ?? ''))) issues.push('최근 사건이 선택 기간의 최신 사건 순서와 일치하지 않습니다.');
  if (events.length && !stats.recent.length) issues.push('집계에 사건이 있으나 최근 사건 목록이 비어 있습니다.');
  if (stats.recent.some(e => Date.parse(e.occurredAt) < series.from || Date.parse(e.occurredAt) > series.asOf)) issues.push('최근 사건 목록에 조회 기간 밖의 기록이 있습니다.');
  return [...new Set(issues)];
}

export function integerCountAxis(maximum: number) {
  const maximumValue = Math.max(0, Math.ceil(maximum));
  const raw = Math.max(1, maximumValue / 4);
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = maximumValue <= 3 ? 1 : Math.max(1, Math.ceil(([1, 2, 5, 10].find(n => n * magnitude >= raw) ?? 10) * magnitude));
  const upper = maximumValue <= 3 ? Math.max(1, maximumValue + 1) : Math.ceil(maximumValue / step) * step;
  return {domain: [0, upper] as [number, number], ticks: Array.from({length: Math.round(upper / step) + 1}, (_, i) => i * step)};
}

export function bucketLabel(timestamp: number, period: OverviewPeriod, detailed = false) {
  return new Intl.DateTimeFormat('ko-KR', {timeZone:'Asia/Seoul', ...(detailed ? {year:'numeric',month:'2-digit',day:'2-digit'} as const : {month:'2-digit',day:'2-digit'} as const), ...(period === '24H' ? {hour:'2-digit',minute:'2-digit',hourCycle:'h23'} as const : {})}).format(new Date(timestamp));
}
