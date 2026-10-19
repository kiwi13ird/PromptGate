// 남은 로직·문구 정리(2026-10-16): 보안 이벤트 목록 보기(보안 이벤트 = 카드와 같은 기록 · 접속 차단 기록 · 전체 기록), 천 단위 쉼표,
// 탐지 값 단위 '개', 목록 새 기록 알림(굴러가는 기간), 내 요청 기록 100건 상한 안내, Detection 5xx 문구, 키워드 '문서 n개에 나옴'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { SecurityEventsPage } from './SecurityEventsPage';
import { MyRequestsPage } from './MyRequestsPage';
import { OverviewPage } from './OverviewPage';
import { Pagination } from '@/src/components/common';
import { EventsTable } from '@/src/components/EventsTable';
import { AutoRefreshBar } from '@/src/components/AutoRefreshBar';
import { eventService } from '@/src/services/eventService';
import { dashboardService } from '@/src/services/dashboardService';
import { documentService } from '@/src/services/documentService';
import { gatewaySettingsService } from '@/src/services/gatewaySettingsService';
import { detectionOpsService, keywordGenerality, keywordGeneralityText, type DocumentKeyword } from '@/src/services/detectionOpsService';
import { ownRequestListSchema } from '@/src/services/myRequestsService';
import { mapPageDto } from '@/src/api/mappers';
import { pageSchema } from '@/src/api/schemas';
import { policyErrorInfo, POLICY_ERROR_MESSAGES } from '@/src/utils/policyErrors';
import { serverError } from '@/src/test/policyFixtures';
import { filterAndPaginateEventDtos } from '@/src/mocks/eventQuery';
import type { SecurityEventDto } from '@/src/api/dto';
import type { DashboardStats, EventFilters, SecurityEvent } from '@/src/types/event';
import type { GatewaySettingsResponse } from '@/src/api/gatewaySettingsSchemas';
import { isDemoDocument } from '@/src/utils/demoDocuments';
import { protectionCoverage } from '@/src/utils/overviewMetrics';
import { sparseLabels } from '@/src/utils/trafficMetrics';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('recharts', () => ({ BarChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>, Bar: () => null, CartesianGrid: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));

const event = (id: string, extra: Partial<SecurityEvent> = {}): SecurityEvent => ({ eventId: id, clientId: 'chrome-1', occurredAt: '2026-10-16T01:00:00Z', targetLlm: 'ChatGPT',
  detectionOutcome: 'MATCH', finalAction: 'BLOCK', status: 'NEW', contentType: 'prompt', detections: [], adminNotes: [], timeline: [], ...extra });
const client = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });
const page = (items: SecurityEvent[], extra: Record<string, unknown> = {}) => ({ items, total: items.length, page: 1, totalPages: 1, pageSize: 20, ...extra });
function view(node: React.ReactNode, initial: string) {
  return render(<QueryClientProvider client={client()}><MemoryRouter initialEntries={[initial]}>{node}</MemoryRouter></QueryClientProvider>);
}
const lastFilters = () => vi.mocked(eventService.getEvents).mock.lastCall![0] as EventFilters;

beforeEach(() => { vi.restoreAllMocks(); });
afterEach(() => { delete (globalThis as { chrome?: unknown }).chrome; });

describe('security event list views', () => {
  it('opens on security events (the records the overview cards count) and shows each view total', async () => {
    vi.spyOn(eventService, 'getEvents').mockResolvedValue(page([event('q1')], { total: 1234, totalPages: 62, viewTotals: { counted: 1234, access: 56, all: 1312 } }));
    view(<SecurityEventsPage />, '/events?period=7D');
    const tabs = await screen.findByRole('navigation', { name: '목록 보기' });
    expect(lastFilters()).toMatchObject({ scope: 'counted', group: 'request', period: '7D' });
    await waitFor(() => expect(within(tabs).getByRole('link', { name: /보안 이벤트/ })).toHaveTextContent('보안 이벤트1,234'));
    expect(within(tabs).getByRole('link', { name: /보안 이벤트/ })).toHaveAttribute('aria-current', 'page');
    expect(within(tabs).getByRole('link', { name: /접속 차단 기록/ })).toHaveTextContent('56');
    expect(within(tabs).getByRole('link', { name: /접속 차단 기록/ })).toHaveAttribute('href', '/events?period=7D&view=access');
    expect(within(tabs).getByRole('link', { name: /전체 기록/ })).toHaveTextContent('1,312');
    expect(screen.getByText((_, node) => node?.className === 'console-list-count' && /^보안 이벤트 1,234건/.test(node.textContent ?? ''))).toBeInTheDocument();
    expect(screen.getByText(/총 1,234건 · 1 \/ 62쪽/)).toBeInTheDocument();   // 쪽 표시도 쉼표
  });
  it('the access view asks only for access blocks and says what they are; all asks without scope', async () => {
    vi.spyOn(eventService, 'getEvents').mockResolvedValue(page([event('x1', { detectionOutcome: 'UNAVAILABLE', reasonCode: 'client_id_missing' })]));
    const { unmount } = view(<SecurityEventsPage />, '/events?view=access');
    await screen.findByRole('table');
    expect(lastFilters().scope).toBe('access');
    expect(screen.getByText(/내용 검사 전에 거부한 기록/)).toBeInTheDocument();
    expect(screen.getByText((_, node) => node?.className === 'console-list-count' && /^접속 차단 기록 1건/.test(node.textContent ?? ''))).toBeInTheDocument();
    unmount();
    view(<SecurityEventsPage />, '/events?view=all');
    await screen.findByRole('table');
    expect(lastFilters().scope).toBeUndefined();
  });
  it('old servers without view totals still show the tabs, only without numbers', async () => {
    vi.spyOn(eventService, 'getEvents').mockResolvedValue(page([event('q1')]));
    view(<SecurityEventsPage />, '/events');
    const tabs = await screen.findByRole('navigation', { name: '목록 보기' });
    await screen.findByRole('table');
    expect(within(tabs).getByRole('link', { name: /보안 이벤트/ }).textContent).toBe('보안 이벤트');
  });
  it('the mock server splits the same way and returns the view totals', () => {
    const dto = (id: string, extra: Partial<SecurityEventDto> = {}) => ({ event_id: id, client_id: 'chrome-1', occurred_at: new Date().toISOString(), target_llm: 'ChatGPT',
      final_action: 'BLOCK', detection_outcome: 'MATCH', status: 'NEW', detections: [], admin_notes: [], timeline: [], ...extra }) as unknown as SecurityEventDto;
    const rows = [dto('q1'), dto('x1', { reason_code: 'client_id_missing', detection_outcome: 'UNAVAILABLE' })];
    const filters = { query: '', period: '24H', finalAction: 'ALL', recommendedAction: 'ALL', detector: 'ALL', matchType: 'ALL', scoreKind: 'ALL', degraded: 'ALL', detectionOutcome: 'ALL',
      degradedReason: 'ALL', failurePolicy: 'ALL', documentId: '', severity: 'ALL', status: 'ALL', targetLlm: 'ALL', sort: 'OCCURRED_AT_DESC', page: 1, pageSize: 20 } as EventFilters;
    const counted = filterAndPaginateEventDtos(rows, { ...filters, scope: 'counted' });
    expect(counted.items.map(item => item.event_id)).toEqual(['q1']);
    expect(counted.view_totals).toEqual({ counted: 1, access: 1, all: 2 });
    expect(filterAndPaginateEventDtos(rows, { ...filters, scope: 'access' }).items.map(item => item.event_id)).toEqual(['x1']);
    const parsed = mapPageDto(pageSchema(z.unknown()).parse(counted) as never, (item: unknown) => item);
    expect(parsed.viewTotals).toEqual({ counted: 1, access: 1, all: 2 });
  });
});

describe('numbers and units', () => {
  it('pagination and detected value counts use thousands separators; values are counted in 개', () => {
    render(<Pagination page={3} totalPages={1200} total={23_999} onPage={() => {}} />);
    expect(screen.getByText('총 23,999건 · 3 / 1,200쪽')).toBeInTheDocument();
    render(<MemoryRouter><EventsTable events={[event('p1', { detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', entityCounts: [{ entityType: 'KR_RRN', count: 1500 }] }] })]} /></MemoryRouter>);
    expect(screen.getByText(/주민등록번호 1,500개/)).toBeInTheDocument();
  });
});

describe('new-record notice on a rolling period', () => {
  it('counts rows newer than the last seen record even when the total does not change', () => {
    const bar = (total: number, recentAt: string[]) => <AutoRefreshBar updatedAt={1} fetching={false} onRefresh={() => {}} total={total} scope="s" recentAt={recentAt} compact />;
    const { rerender } = render(bar(20, ['2026-10-16T01:00:00Z', '2026-10-16T00:59:00Z']));
    expect(screen.queryByText(/증가/)).toBeNull();
    // 굴러가는 24시간: 옛 기록 1건이 빠지고 새 기록 1건이 들어와 전체는 그대로 20
    act(() => rerender(bar(20, ['2026-10-16T01:05:00Z', '2026-10-16T01:00:00Z'])));
    expect(screen.getByText('현재 조건에서 이벤트 1건 증가 · 확인')).toBeInTheDocument();
  });
});

describe('my requests 100-row limit', () => {
  const KEY = 'A'.repeat(43);
  const item = (index: number) => ({ event_id: `evt-${index}`, occurred_at: '2026-10-16T01:00:00Z', target_llm: 'ChatGPT', content_type: 'prompt', final_action: 'MASK',
    protected_document: false, entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] });
  const install = () => {
    const runtime = { sendMessage: (_id: string, _message: unknown, callback: (response: unknown) => void) => queueMicrotask(() => callback({ ok: true, viewerKey: KEY, identityEnabled: true })) };
    (globalThis as { chrome?: unknown }).chrome = { runtime };
  };
  const serve = (body: unknown) => vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  it('always says rows stop at 100, and says older rows were left out when the server cut the list', async () => {
    install();
    serve({ items: Array.from({ length: 100 }, (_, index) => item(index)), window_days: 7, limit: 100, truncated: true });
    render(<QueryClientProvider client={client()}><MyRequestsPage /></QueryClientProvider>);
    expect(screen.getByText(/최근 100건까지 표시합니다/)).toBeInTheDocument();
    expect(await screen.findByText(/최근 100건까지만 표시\(이전 기록 생략\)/)).toBeInTheDocument();
  });
  it('no cut notice when nothing was left out or on an old server', async () => {
    install();
    serve({ items: [item(1)], window_days: 7 });
    render(<QueryClientProvider client={client()}><MyRequestsPage /></QueryClientProvider>);
    expect(await screen.findByText('1건')).toBeInTheDocument();
    expect(screen.queryByText(/이전 기록 생략/)).toBeNull();
    expect(ownRequestListSchema.parse({ items: [], window_days: 7, limit: 100, truncated: false })).toMatchObject({ limit: 100, truncated: false });
  });
});

describe('Detection 5xx on the policy relay', () => {
  it('is a server error message, not an unreadable answer', () => {
    expect(policyErrorInfo(serverError(502, 'POLICY_UPSTREAM_SERVER_ERROR'), 'update')).toEqual({ message: POLICY_ERROR_MESSAGES.upstreamServerError, refetch: 'policies' });
    expect(POLICY_ERROR_MESSAGES.upstreamServerError).toMatch(/^탐지 서버에서 오류가 발생했습니다/);
    expect(policyErrorInfo(serverError(502, 'POLICY_UPSTREAM_INVALID_RESPONSE'), 'update').message).toBe(POLICY_ERROR_MESSAGES.upstreamInvalid);
  });
});

describe('keyword generality from the Detection contract', () => {
  const keyword = (reason_check: DocumentKeyword['reason_check']) => ({ reason_check }) as Pick<DocumentKeyword, 'reason_check'>;
  it('marks keywords found in two or more protected documents and says how many', () => {
    expect(keywordGenerality(keyword({ doc_count: 14, common_in_docs: true, doc_count_at: '2026-10-16T12:00:00Z' }))).toMatchObject({ generic: true, common: true, llm: false, docCount: 14 });
    expect(keywordGeneralityText(keyword({ doc_count: 14, common_in_docs: true }))).toBe('일반 표현일 수 있음 · 문서 14개에 나옴');
    expect(keywordGeneralityText(keyword({ specificity: '일반', kind: '업계 용어', doc_count: 3, common_in_docs: true }))).toBe('일반 표현일 수 있음(업계 용어) · 문서 3개에 나옴');
    expect(keywordGeneralityText(keyword({ specificity: '일반', kind: null }))).toBe('일반 표현일 수 있음');
    expect(keywordGenerality(keyword({ doc_count: 1, common_in_docs: false })).generic).toBe(false);
    expect(keywordGenerality(keyword(null)).generic).toBe(false);          // 셈 전·옛 Detection
    expect(keywordGenerality(keyword(undefined)).generic).toBe(false);
  });
  it('the keyword list keeps the new fields (zod would drop unknown ones)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ keywords: [{ id: 1, keyword: 'NeoBoard', doc_id: 'd1', status: 'approved', source: 'llm',
      reason_check: { doc_count: 14, common_in_docs: true, doc_count_at: '2026-10-16T12:00:00Z' } }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    const [first] = await detectionOpsService.getKeywords();
    expect(first.reason_check).toEqual({ doc_count: 14, common_in_docs: true, doc_count_at: '2026-10-16T12:00:00Z' });
  });
});

describe('overview note matches the new list', () => {
  it('links the access-block count to the access view and no longer says the list includes them', async () => {
    const stats = { total: 10, block: 4, mask: 2, allow: 4, degraded: 0, enforcementRate: 1, actionMismatch: 0, newEvents: 0, averageProcessingMs: 0, detectionStatus: 'HEALTHY',
      trend: [], recent: [], counting: { unit: 'REQUEST', records: 10, listTotal: 15, accessBlocked: 5, resendFolded: 0, sensitive: 3 } } as unknown as DashboardStats;
    vi.spyOn(dashboardService, 'getStats').mockResolvedValue(stats);
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue({ settings: null, gateway: { state: 'UNKNOWN' } } as unknown as GatewaySettingsResponse);
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([]);
    vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue([]);
    vi.spyOn(detectionOpsService, 'getKeywordJobs').mockResolvedValue({ jobs: [], counts: { queued: 0, running: 0, done: 0, failed: 0 } });
    view(<OverviewPage />, '/overview?period=7D');
    const note = (await screen.findByText(/카드 단위 = 요청/)).closest('p')!;
    expect(within(note).getByRole('link', { name: '5건' })).toHaveAttribute('href', expect.stringMatching(/^\/events\?period=(24H|7D|30D)&view=access$/));
    expect(note.textContent).not.toMatch(/포함해/);
    fireEvent.click(within(note).getByRole('link', { name: '5건' }));
  });
});

describe('shared statistics rules (stats-rules SPEC 2026-10-16) on screen', () => {
  const baseStats = (counting: Record<string, unknown>) => ({ total: 10, block: 4, mask: 2, allow: 4, degraded: 0, enforcementRate: 1, actionMismatch: 0, newEvents: 0, averageProcessingMs: 0,
    detectionStatus: 'HEALTHY', trend: [], recent: [], counting: { unit: 'REQUEST', records: 10, listTotal: 15, accessBlocked: 5, resendFolded: 0, sensitive: 3, ...counting } }) as unknown as DashboardStats;
  const mockOverview = (stats: DashboardStats, documents: unknown[] = []) => {
    vi.spyOn(dashboardService, 'getStats').mockResolvedValue(stats);
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue({ settings: null, gateway: { state: 'UNKNOWN' } } as unknown as GatewaySettingsResponse);
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue(documents as never);
    vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue([]);
    vi.spyOn(detectionOpsService, 'getKeywordJobs').mockResolvedValue({ jobs: [], counts: { queued: 0, running: 0, done: 0, failed: 0 } });
  };
  it('the overview note names file resends and prompt retries apart when the new server gives both', async () => {
    mockOverview(baseStats({ resendFolded: 21, resendFile: 20, resendPrompt: 1 }));
    view(<OverviewPage />, '/overview?period=30D');
    const note = (await screen.findByText(/카드 단위 = 요청/)).closest('p')!;
    expect(note.textContent).toMatch(/10\/11 전 파일 재전송 20건 · 같은 질문 재시도 1건은 앞 기록 1건으로 접음$/);
  });
  it('only prompt retries: no file part', async () => {
    mockOverview(baseStats({ resendFolded: 1, resendFile: 0, resendPrompt: 1 }));
    view(<OverviewPage />, '/overview?period=30D');
    const note = (await screen.findByText(/카드 단위 = 요청/)).closest('p')!;
    expect(note.textContent).toMatch(/· 같은 질문 재시도 1건은 앞 기록 1건으로 접음$/);
    expect(note.textContent).not.toMatch(/파일 재전송/);
  });
  it('demo documents (DEMO_) are left out of document counts but stay in the list', () => {
    const doc = (documentId: string) => ({ documentId, documentName: documentId, status: 'ACTIVE', processingStatus: 'READY', activeDetectors: ['WINDOW_HASH'], chunkIndexStatus: 'READY', fileType: 'docx', registeredAt: '2026-10-03T04:32:00Z' }) as never;
    expect(isDemoDocument('DEMO_반도체_공정_시연_20261003')).toBe(true);
    expect(isDemoDocument('01_사업전략')).toBe(false);
    const coverage = protectionCoverage([doc('01_사업전략'), doc('02_인사'), doc('DEMO_반도체_공정_시연_20261003')]);
    expect([coverage.total, coverage.demoExcluded, coverage.counts.protected]).toEqual([2, 1, 2]);
  });
});

describe('screen check fixes (2026-10-16)', () => {
  it('the last axis label does not sit on top of the one before it (30 days on a phone)', () => {
    const days = Array.from({ length: 30 }, (_, index) => `d${index}`);
    const shown = sparseLabels(days, 8).map((label, index) => (label ? index : -1)).filter((index) => index >= 0);
    expect(shown.at(-1)).toBe(29);
    expect(shown.at(-1)! - shown.at(-2)!).toBeGreaterThanOrEqual(2);   // 전: 28·29가 붙어 '10.15''10.16'이 겹침
    expect(sparseLabels(Array.from({ length: 24 }, (_, hour) => `${hour}시`), 8).filter(Boolean)).toEqual(['0시', '3시', '6시', '9시', '12시', '15시', '18시', '21시', '23시']);
  });
});
