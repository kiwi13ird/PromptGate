// 숫자 산정 수정(2026-10-15 감사 docs/audit-2026-10-15): 보안 현황 요청 단위·접속 차단 분리·민감정보 검출 수, 트래픽 표본 수·검사 요청 분모·
// 연결 오류 기준, 연결 IP (IP, 확장 ID) 줄, 키워드 추출 실패·건너뜀, 새로 고침 알림. 옛 서버·옛 Gateway(새 칸 없음)에서도 깨지지 않는지
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OverviewPage } from './OverviewPage';
import { TrafficPerformancePage } from './TrafficPerformancePage';
import { DocumentKeywordsPage } from './DocumentKeywordsPage';
import { RecordStatusBar, overviewLevel } from '@/src/components/OverviewPanels';
import { TrafficClientsPanel } from '@/src/components/TrafficClientsPanel';
import { PgRefresh } from '@/src/components/pg';
import { dashboardService } from '@/src/services/dashboardService';
import { documentService } from '@/src/services/documentService';
import { detectionOpsService, type KeywordJob } from '@/src/services/detectionOpsService';
import { gatewaySettingsService } from '@/src/services/gatewaySettingsService';
import { trafficService } from '@/src/services/trafficService';
import type { GatewaySettingsResponse } from '@/src/api/gatewaySettingsSchemas';
import type { DashboardStats, SecurityEvent } from '@/src/types/event';
import type { TrafficSnapshot } from '@/src/types/traffic';
import type { ConfidentialDocument } from '@/src/types/policy';
import { actionReasons, failedExtractionDocuments, inspectableCount, uninspectedRequests } from '@/src/utils/overviewMetrics';
import { normalizeEventSeries, overviewIntegrityIssues } from '@/src/utils/eventSeries';
import { mapDashboardStatsDto, mapTrafficClientsDto, mapTrafficSnapshotDto } from '@/src/api/mappers';
import { dashboardStatsSchema, trafficClientsSchema, trafficSummarySchema } from '@/src/api/schemas';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('recharts', () => ({ BarChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>, Bar: () => null, CartesianGrid: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));

const event = (id: string, extra: Partial<SecurityEvent> = {}): SecurityEvent => ({ eventId: id, clientId: 'chrome-1', occurredAt: '2026-10-15T01:00:00Z', targetLlm: 'ChatGPT', detectionOutcome: 'MATCH', finalAction: 'BLOCK', status: 'NEW', detections: [], adminNotes: [], timeline: [], ...extra });
const pii = { detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', entityCounts: [{ entityType: 'KR_RRN', count: 1 }] } as const;
const client = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });
const values = { timeout: { prompt: { action: 'forward' as const, seconds: 3 }, file: { action: 'block' as const, seconds: 10 } }, uninspectable: { image: 'allow' as const, scanned_pdf: 'block' as const, other: 'block' as const }, notify_on_allow: true };
const settings = { settings: { ...values, version: 0, revision: null, updated_at: null, updated_by: null, source: 'DEFAULT' }, defaults: values, gateway: { state: 'APPLIED' } } as GatewaySettingsResponse;

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(settings);
  vi.spyOn(documentService, 'getDocuments').mockResolvedValue([]);
  vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue([]);
  vi.spyOn(detectionOpsService, 'getKeywordJobs').mockResolvedValue({ jobs: [], counts: { queued: 0, running: 0, done: 0, failed: 0 } });
});

describe('overview metrics on request rows (list grouping)', () => {
  const grouped = event('q1', { finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', groupFinalAction: 'MASK',
    attachedFiles: [{ eventId: 'f1', occurredAt: '2026-10-15T01:00:01Z', finalAction: 'MASK', contentType: 'file', detectionOutcome: 'MATCH', detections: [{ ...pii, entityCounts: [{ entityType: 'KR_RRN', count: 2 }] }] }] });
  const uninspectedFile = event('q2', { finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', groupFinalAction: 'ALLOW',
    attachedFiles: [{ eventId: 'f2', occurredAt: '2026-10-15T01:00:01Z', finalAction: 'ALLOW', contentType: 'file', detectionOutcome: 'UNAVAILABLE', detections: [], reasonCode: 'file_uninspectable_image' }] });

  it('takes the reason from the member that set the request action and counts one per request', () => {
    expect(actionReasons([grouped, uninspectedFile, event('b1', { detections: [], reasonCode: 'doc_excerpt' })])).toEqual([
      { key: 'document', label: '보호 문서 일치', to: '/documents', block: 1, mask: 0 },   // 검출이 비어도 사유 코드 doc_excerpt(감사 11번)
      { key: 'pii', label: '개인정보', to: '/policies', block: 0, mask: 1 },               // 질문은 허용, 첨부 파일의 개인정보 때문에 마스킹
    ]);
  });
  it('finds an uninspected attached file and divides by rows without access blocks', () => {
    const result = uninspectedRequests([grouped, uninspectedFile]);
    expect([result.allow, result.block]).toEqual([1, 0]);
    expect(result.rows.find(row => row.key === 'uninspectable')).toMatchObject({ allow: 1, block: 0 });
    expect(inspectableCount([grouped, event('x', { reasonCode: 'client_id_missing' }), event('y', { reasonCode: 'client_blocked' })])).toBe(1);
  });
  it('draws the trend and checks integrity with the request action', () => {
    const now = Date.parse('2026-10-15T02:00:00Z');
    const series = normalizeEventSeries([grouped, uninspectedFile], '24H', now);
    expect(series.buckets.reduce((sum, bucket) => sum + bucket.mask, 0)).toBe(1);
    const stats = { total: 2, block: 0, mask: 1, allow: 1, newEvents: 2, averageProcessingMs: 0, gatewayStatus: 'HEALTHY', detectionStatus: 'HEALTHY', trend: [], recent: [grouped, uninspectedFile], lastSuccessAt: '2026-10-15T01:00:00Z' } as DashboardStats;
    expect(overviewIntegrityIssues(stats, [grouped, uninspectedFile], series)).toEqual([]);
  });
  it('counts a failed extraction only for registered documents whose latest job failed', () => {
    const job = (id: number, docId: string, status: KeywordJob['status']) => ({ id, doc_id: docId, doc_version: 1, status, attempts: 0, error: null, created_at: null, finished_at: null }) as KeywordJob;
    const documents = [{ documentId: 'd1' }, { documentId: 'd2' }];
    expect(failedExtractionDocuments(documents, [job(1, 'd1', 'failed'), job(2, 'd1', 'done'), job(3, 'd2', 'failed'), job(4, 'gone', 'failed')])).toEqual(['d2']);
  });
});

const counting = { unit: 'REQUEST' as const, records: 24, listTotal: 50, accessBlocked: 26, resendFolded: 0, sensitive: 15 };
const overviewStats = (extra: Partial<DashboardStats> = {}): DashboardStats => ({ total: 24, block: 4, mask: 13, allow: 7, degraded: 0, newEvents: 24, averageProcessingMs: 5,
  gatewayStatus: 'HEALTHY', gatewayMetricsStatus: 'FRESH', gatewayCompletedRequests: 5, detectionStatus: 'HEALTHY', lastSuccessAt: '2026-10-15T01:00:00Z', trend: [], recent: [], counting, ...extra });
const viewOverview = () => render(<QueryClientProvider client={client()}><MemoryRouter initialEntries={['/overview?period=24H']}><OverviewPage /></MemoryRouter></QueryClientProvider>);

describe('overview cards with the new server (counting)', () => {
  it('shows detected sensitive requests, access blocks apart and the card unit against the list', async () => {
    vi.spyOn(dashboardService, 'getStats').mockResolvedValue(overviewStats());
    viewOverview();
    const total = await screen.findByRole('link', { name: '전체 이벤트 목록 보기' });
    expect(total).toHaveTextContent('민감정보·기밀 검출 15건 · 63%');   // 감사 실데이터 24시간: 차단+마스킹 43건(86%) → 검출 15건
    expect(total.getAttribute('title')).toContain('요청 단위(첨부 파일은 프롬프트에 묶음, 보안 이벤트 목록과 같음) · 접속 차단 제외');
    expect(screen.getByRole('link', { name: '전송 차단 목록 보기' })).toHaveTextContent('전체의 17% · 접속 차단 26건 별도');
    const note = document.querySelector('.pg-ov-unit-note') as HTMLElement;
    // 2026-10-16: 목록 기본 보기가 카드와 같은 기록이 되어 '목록은 이들을 포함해' 문장을 없애고, 접속 차단 수는 목록의 '접속 차단 기록' 보기로 연결
    expect(note).toHaveTextContent(/^카드 단위 = 요청\(첨부 파일은 프롬프트에 묶어 1건, 보안 이벤트 목록과 같음\) · 접속 차단 26건은 따로 셈$/);
    expect(within(note).getByRole('link', { name: '26건' })).toHaveAttribute('href', expect.stringMatching(/^\/events\?period=24H&view=access$/));
  });
  it('mentions folded resends only when there were some', async () => {
    vi.spyOn(dashboardService, 'getStats').mockResolvedValue(overviewStats({ total: 410, counting: { ...counting, listTotal: 458, accessBlocked: 28, resendFolded: 20 } }));
    viewOverview();
    await screen.findByRole('link', { name: '전체 이벤트 목록 보기' });
    expect(document.querySelector('.pg-ov-unit-note')).toHaveTextContent(/10\/11 전 파일 재전송 20건은 앞 기록 1건으로 접음$/);   // 옛 서버 모양(파일만)
  });
  it('keeps the old server working: no unit line and an honest "차단·마스킹" label', async () => {
    vi.spyOn(dashboardService, 'getStats').mockResolvedValue(overviewStats({ counting: undefined, total: 50, block: 30 }));
    viewOverview();
    const total = await screen.findByRole('link', { name: '전체 이벤트 목록 보기' });
    expect(total).toHaveTextContent('차단·마스킹 43건 · 86%');
    expect(document.querySelector('.pg-ov-unit-note')).toBeNull();
  });
  it('parses counting from the server and leaves it out for an old server', () => {
    const raw = { total: 1, block: 1, mask: 0, allow: 0, new_events: 1, average_processing_ms: 0, trend: [], recent: [],
      counting: { unit: 'REQUEST', records: 1, list_total: 3, access_blocked: 2, resend_folded: 0, sensitive: 1, last_degraded_at: '2026-10-01T08:36:15.232Z' } };
    expect(mapDashboardStatsDto(dashboardStatsSchema.parse(raw)).counting).toEqual({ unit: 'REQUEST', records: 1, listTotal: 3, accessBlocked: 2, resendFolded: 0, sensitive: 1, lastDegradedAt: '2026-10-01T08:36:15.232Z' });
    expect(mapDashboardStatsDto(dashboardStatsSchema.parse({ ...raw, counting: undefined })).counting).toBeUndefined();
  });
  it('reads an old Detection error as a period record, not as a current warning', () => {
    const old = overviewStats({ detectionStatus: 'DEGRADED', degraded: 7, counting: { ...counting, lastDegradedAt: new Date(Date.now() - 14 * 86_400_000).toISOString() } });
    expect(overviewLevel(old, false).level).toBe('ok');
    render(<MemoryRouter><RecordStatusBar stats={old} stale={false} /></MemoryRouter>);
    expect(screen.getByText(/^기간 중 오류 7건 · 마지막 /)).toBeInTheDocument();
    const recent = overviewStats({ detectionStatus: 'DEGRADED', degraded: 1, counting: { ...counting, lastDegradedAt: new Date(Date.now() - 3_600_000).toISOString() } });
    expect(overviewLevel(recent, false).level).toBe('warn');
  });
});

describe('refresh notice counts new records, not the total difference', () => {
  it('announces a new record when an old one left the rolling window at the same time', () => {
    const view = (recentAt: string[]) => <PgRefresh updatedAt={1} fetching={false} onRefresh={() => {}} total={10} scope="24H" recentAt={recentAt} />;
    const { rerender } = render(view(['2026-10-15T01:00:00Z', '2026-10-15T00:00:00Z']));
    expect(screen.queryByRole('button', { name: /건 증가/ })).toBeNull();
    act(() => rerender(view(['2026-10-15T01:05:00Z', '2026-10-15T01:00:00Z'])));   // 전체 10건 그대로, 새 기록 1건
    expect(screen.getByRole('button', { name: /현재 조건에서 이벤트 1건 증가/ })).toBeInTheDocument();
  });
});

const liveSnapshot = (summary: Partial<TrafficSnapshot['summary']>): TrafficSnapshot => ({ period: '24H', timeSeries: [], summary: {
  metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY', gatewayTotalRequests: 2888, gatewayCompletedRequests: 2880, gatewayErrorRequests: 1,
  gatewayWindowSeconds: 60, activeClients: 1, concurrentRequests: 2, requestsPerSec: 0.5, averageLatencyMs: 360, p95LatencyMs: 1543, timeoutRate: 0, degradedRate: 1 / 11, ...summary } });
const viewTraffic = () => render(<QueryClientProvider client={client()}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);

describe('traffic with the extended Gateway metrics', () => {
  beforeEach(() => vi.spyOn(trafficService, 'getClients').mockResolvedValue({ receivedAt: undefined, stale: false, windowSeconds: 300, clients: [] }));
  it('uses sample counts, the inspected denominator and errors without browser cancels', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(liveSnapshot({ latencySampleCount: 11, gatewayInspectedRequests: 11, gatewayErrorBasis: 'GATEWAY_ERRORS', gatewayClientCancelledRequests: 6,
      gatewayStatus: 'DEGRADED', gatewayStatusReason: 'Gateway 오류 1건(브라우저 취소 제외) · 보안 검사 응답 없음 1건' }));
    viewTraffic();
    const strip = await screen.findByRole('status', { name: 'Gateway 상태' });
    expect(strip).toHaveTextContent('시작 이후 LLM 사이트 요청 2,888건(화면 로딩 포함) · 완료 2,880건 · 검사 요청 11건 · Gateway 오류 1건(브라우저 취소 제외) · 브라우저 취소 6건');
    expect(strip).toHaveTextContent('오류 기록 있음');
    const kpis = screen.getByRole('region', { name: 'Gateway 지표' });
    const p95 = within(kpis).getByText('느린 5% 요청의 처리 시간 (P95)').closest('article') as HTMLElement;
    expect(p95).toHaveTextContent('평균 0.36초 · 표본 11건(Gateway가 검사한 요청) · 20건 미만');
    const degraded = within(kpis).getByText('보안 검사 응답 없음').closest('article') as HTMLElement;
    expect(degraded).toHaveTextContent('9.1%');                                  // 검사 요청 11건 중 1건(전체 HTTP 기준이면 0.03%)
    expect(degraded).toHaveTextContent('시작 이후 검사한 요청 11건 중');
  });
  it('says "기록 없음" for zero samples and "검사 요청 없음" for a zero denominator, never 0초·0%', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(liveSnapshot({ latencySampleCount: 0, averageLatencyMs: undefined, p95LatencyMs: undefined, gatewayInspectedRequests: 0, degradedRate: 0, gatewayErrorBasis: 'GATEWAY_ERRORS' }));
    viewTraffic();
    const kpis = await screen.findByRole('region', { name: 'Gateway 지표' });
    expect(within(within(kpis).getByText('느린 5% 요청의 처리 시간 (P95)').closest('article') as HTMLElement).getAllByText('기록 없음')).toHaveLength(2);
    expect(within(kpis).getAllByText('검사 요청 없음')).toHaveLength(2);
    expect(kpis).not.toHaveTextContent(/(^|[^0-9])0초|0\.0%/);
  });
  it('maps the new summary fields and leaves them out for an old Gateway', () => {
    const raw = { metric_source: 'GATEWAY_LIVE', gateway_status: 'HEALTHY', access_blocked: 26, gateway_inspected_requests: 11, gateway_error_basis: 'GATEWAY_ERRORS', gateway_client_cancelled_requests: 6, gateway_status_reason: 'x' };
    const summary = mapTrafficSnapshotDto({ summary: trafficSummarySchema.parse(raw), time_series: [] }, '24H').summary;
    expect(summary).toMatchObject({ accessBlocked: 26, gatewayInspectedRequests: 11, gatewayErrorBasis: 'GATEWAY_ERRORS', gatewayClientCancelledRequests: 6, gatewayStatusReason: 'x' });
    const old = mapTrafficSnapshotDto({ summary: trafficSummarySchema.parse({ metric_source: 'GATEWAY_LIVE' }), time_series: [] }, '24H').summary;
    expect('gatewayInspectedRequests' in old || 'accessBlocked' in old || 'gatewayErrorBasis' in old).toBe(false);
  });
  it('shows the stored records without access blocks', async () => {
    const stored = event('p1', { finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', processingMs: 12, contentType: 'prompt', occurredAt: new Date(Date.now() - 3_600_000).toISOString() });
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue({ ...liveSnapshot({ metricSource: 'STORED_EVENTS', eventCount: 1, accessBlocked: 26, latencySampleCount: 1 }), timeSeries: [{ timestamp: stored.occurredAt, requestCount: 1, allowCount: 1, maskCount: 0, blockCount: 0 }], periodEvents: [stored] });
    viewTraffic();
    const group = await screen.findByRole('region', { name: '24시간 저장 기록' });
    expect(group).toHaveTextContent('질문·파일 검사 기록(보안 이벤트) 1건 (접속 차단 26건 제외)');
    const kpis = screen.getByRole('region', { name: 'Gateway 지표' });
    expect(within(kpis).getByText('보안 검사 응답 없음').closest('article')).toHaveTextContent('24시간 보안 이벤트 1건 중 · 접속 차단 제외');
  });
});

describe('connected IP rows split by extension (Gateway by_client)', () => {
  it('counts extensions per IP without the no-ID row and counts IPs in the header', () => {
    const row = (ip: string, clientId: string | null, connections: number) => ({ ip, client_id: clientId, connections, inflight: 0, waiting: 0, requests_5m: 1, targets: { ChatGPT: 1 }, first_seen_at: '2026-10-15T01:00:00Z', last_seen_at: '2026-10-15T01:04:00Z' });
    const data = mapTrafficClientsDto(trafficClientsSchema.parse({ received_at: '2026-10-15T01:04:10Z', stale: false, window_seconds: 300,
      clients: [row('203.0.113.10', 'chrome-a', 1), row('203.0.113.10', 'chrome-b', 1), row('203.0.113.10', null, 1), row('203.0.113.11', 'chrome-c', 0)] }));
    render(<TrafficClientsPanel data={data} loading={false} onRetry={() => {}} now={Date.parse('2026-10-15T01:05:00Z')} />);
    expect(screen.getByText(/연결 중 IP 1 · 최근 활동 IP 1/)).toBeInTheDocument();
    expect(screen.getAllByText('이 IP 확장 2개')).toHaveLength(2);       // 확장 ID 없는 줄은 세지 않고 그 줄에는 표시 없음
    expect(screen.getByText('확장 ID 없음')).toBeInTheDocument();
  });
});

describe('keyword extraction status', () => {
  const doc = (id: string): ConfidentialDocument => ({ documentId: id, documentName: `${id}.docx`, registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'DOCX',
    exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 3, activeDetectors: ['WINDOW_HASH'] });
  const job = (id: number, docId: string, status: KeywordJob['status'], error: string | null = null): KeywordJob => ({ id, doc_id: docId, doc_version: 1, status, attempts: 0, error, created_at: '2026-10-14T05:00:00Z', finished_at: '2026-10-14T05:01:00Z' });
  it('counts failed documents like the list and the overview, and shows skipped jobs as skipped', async () => {
    vi.mocked(documentService.getDocuments).mockResolvedValue([doc('d1'), doc('d2'), doc('d3')]);
    vi.mocked(detectionOpsService.getKeywordJobs).mockResolvedValue({ jobs: [job(1, 'd1', 'failed'), job(2, 'd1', 'done'), job(3, 'd2', 'failed'), job(4, 'removed', 'failed'), job(5, 'd3', 'done', 'superseded: document changed')], counts: { queued: 0, running: 0, done: 2, failed: 3 } });
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue({ connected: true, models: [], latency_ms: 1, error: null, checked_at: '2026-10-15T00:00:00Z' });
    render(<QueryClientProvider client={client()}><MemoryRouter initialEntries={['/policies/keywords']}><DocumentKeywordsPage /></MemoryRouter></QueryClientProvider>);
    const failed = await screen.findByText(/추출 실패 문서/, { selector: 'label, label *' });
    await waitFor(() => expect(failed.closest('label')).toHaveTextContent('추출 실패 문서 1'));   // 작업 행 3건이 아니라 마지막 추출이 실패한 등록 문서 1개
    await act(async () => { (screen.getByRole('radio', { name: /전체 문서/ }) as HTMLInputElement).click(); });
    expect(await screen.findByText('추출 건너뜀')).toBeInTheDocument();
    expect(screen.getAllByText('추출 완료')).toHaveLength(1);                  // d1(다시 추출해 성공)만 완료
  });
});
