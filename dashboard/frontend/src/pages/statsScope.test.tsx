import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpGatewayApi } from '@/src/api/httpAdapter';
import { httpClient } from '@/src/api/httpClient';
import { mapAuditLogDto, mapDashboardStatsDto, mapPageDto, mapSecurityEventDto } from '@/src/api/mappers';
import { readAuditRows } from '@/src/api/schemas';
import { gatewayLiveLabel } from '@/src/components/OverviewPanels';
import { percent } from '@/src/components/OverviewInsights';
import { auditService } from '@/src/services/auditService';
import { eventService } from '@/src/services/eventService';
import type { DashboardStats, EventFilters } from '@/src/types/event';
import { AuditLogsPage } from './AuditLogsPage';
import { PolicyManagementPage } from './PolicyManagementPage';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';
import { dashboardService } from '@/src/services/dashboardService';
import { policyService } from '@/src/services/policyService';
import { documentService } from '@/src/services/documentService';
import { SecurityEventsPage } from './SecurityEventsPage';
import { entityCategory, signatureLabel } from '@/src/utils/entityCategory';
import { InvestigationSummary } from '@/src/components/InvestigationSummary';

// 시험·데모 제외(2번) · 감사 로그 줄 단위 읽기(4번) · Gateway 실시간 상태(5번) — 2026-10-10
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
afterEach(() => vi.restoreAllMocks());

const filters: EventFilters = { query: '', period: '30D', finalAction: 'ALL', recommendedAction: 'ALL', detector: 'ALL', matchType: 'ALL', scoreKind: 'ALL',
  degraded: 'ALL', detectionOutcome: 'ALL', degradedReason: 'ALL', failurePolicy: 'ALL', documentId: '', severity: 'ALL', status: 'ALL', targetLlm: 'ALL',
  sort: 'OCCURRED_AT_DESC', page: 1, pageSize: 20 };
const emptyPage = { items: [], total: 0, page: 1, page_size: 20, total_pages: 1 };
const audit = (over: Record<string, unknown> = {}) => ({ audit_id: 'audit-1', occurred_at: '2026-10-10T01:00:00Z', admin_id: 'local-admin',
  action: 'POLICY_UPDATE', target_type: 'POLICY', target_id: 'POLICY-PII-MASK', result: 'SUCCESS',
  changes: { previous_version: 1, new_version: 2, previous_action: 'MASK_FULL', new_action: 'BLOCK' }, ...over });

describe('test and demo records', () => {
  it('asks for them only when the list includes them', async () => {
    const get = vi.spyOn(httpClient, 'get').mockResolvedValue({ ...emptyPage, excluded_test: 3 });
    await httpGatewayApi.getEvents(filters, undefined);
    expect(String(get.mock.calls[0][0])).not.toContain('include_test');
    await httpGatewayApi.getEvents({ ...filters, includeTest: true }, undefined);
    expect(String(get.mock.calls[1][0])).toContain('include_test=1');
    // 실제 응답 검사(스키마)와 변환을 거쳐 화면 값이 되는지
    expect(mapPageDto(await httpGatewayApi.getEvents(filters, undefined), mapSecurityEventDto).excludedTest).toBe(3);
    get.mockResolvedValue(emptyPage);
    expect(mapPageDto(await httpGatewayApi.getEvents(filters, undefined), mapSecurityEventDto)).not.toHaveProperty('excludedTest');
  });

  it('says how many were left out and can bring them back', async () => {
    const get = vi.spyOn(eventService, 'getEvents').mockImplementation(async (f) => ({ items: [], total: 1, page: 1, pageSize: 20, totalPages: 1,
      ...(f.includeTest ? { excludedTest: 0 } : { excludedTest: 3 }) }));
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/events']}><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText(/시험·데모 3건 제외/)).toBeInTheDocument();
    expect(get).toHaveBeenLastCalledWith(expect.not.objectContaining({ includeTest: true }), expect.any(AbortSignal));
    fireEvent.click(screen.getByRole('button', { name: '포함해서 보기' }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(expect.objectContaining({ includeTest: true }), expect.any(AbortSignal)));
    fireEvent.click(await screen.findByRole('button', { name: '빼고 보기' }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(expect.not.objectContaining({ includeTest: true }), expect.any(AbortSignal)));
  });
});

describe('hit counts on policies and documents', () => {
  const summary = { insights: { entityCounts: [], documents: [], llmActions: [], contentActions: [], heatmap: [],
    categoryCounts: [{ key: 'PII', events: 5, values: 9 }, { key: 'CREDENTIAL', events: 2, values: 2 }, { key: 'KEYWORD', events: 0, values: 0 }],
    entityEventCounts: [{ key: 'KR_RRN', count: 4 }, { key: 'DOC_KEYWORD', count: 3 }] } } as unknown as DashboardStats;
  const policy = (id: string, target: string) => ({ policyId: id, detector: 'SIGNATURE', detectionTarget: target, action: 'MASK', targetLlms: ['ChatGPT'], version: 1, enabled: true });
  const wrap = (node: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>);

  // 2026-10-16 분류별 항목 토글 화면: 분류 머리에 분류 전체 건수, 항목·그 밖의 정책 줄에 유형 건수(0건은 항목 줄에서 생략)
  it('shows recent 30-day hits for each category and type', async () => {
    vi.spyOn(dashboardService, 'getSummary').mockResolvedValue(summary);
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy('POLICY-PII-MASK', 'PII'), policy('POLICY-CREDENTIAL-MASK', 'CREDENTIAL'),
      policy('POLICY-KW', 'DOC_KEYWORD'), policy('POLICY-RRN', 'kr_rrn'), policy('POLICY-NONE', 'PASSPORT')] as never);
    wrap(<PolicyManagementPage />);
    expect(await screen.findByText('최근 30일 탐지 5건')).toHaveAttribute('title', '개인정보 분류 전체 · 탐지된 값 9개 · 최근 30일 대상 탐지(정책별 판정 수 아님)');   // 분류 전체임을 밝힌다
    expect(screen.getByText('최근 30일 탐지 2건')).toHaveAttribute('title', '자격증명 분류 전체 · 탐지된 값 2개 · 최근 30일 대상 탐지(정책별 판정 수 아님)');
    expect(screen.getByText('30일 4건')).toHaveAttribute('title', '주민등록번호 유형 · 최근 30일 대상 탐지(정책별 판정 수 아님)');
    expect(screen.getByText('30일 3건')).toHaveAttribute('title', '기밀 키워드 유형 · 최근 30일 대상 탐지(정책별 판정 수 아님)');   // 그 밖의 정책 줄
    expect(screen.getByText('30일 0건')).toHaveAttribute('title', 'PASSPORT 유형 · 최근 30일 대상 탐지(정책별 판정 수 아님)');
    expect(dashboardService.getSummary).toHaveBeenCalledWith('30D', expect.anything());
  });

  it('tells loading and failure apart from no hits', async () => {
    vi.spyOn(dashboardService, 'getSummary').mockRejectedValue(new Error('offline'));
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy('POLICY-PII-MASK', 'PII')] as never);
    wrap(<PolicyManagementPage />);
    expect(await screen.findAllByText('최근 30일 탐지 확인 불가')).toHaveLength(2);   // 분류 두 묶음 머리
    expect(screen.queryByText('최근 30일 탐지 0건')).toBeNull();
  });

  it('shows how many times each protected document was matched', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([{ documentId: 'doc-13', documentName: '13_파트너사협상자료.docx', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE',
      processingStatus: 'READY', fileType: 'DOCX', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 3,
      activeDetectors: ['WINDOW_HASH'], modifiedPartialDetectionCount: 14, lastDetectedAt: '2026-10-09T08:00:00Z' }] as never);
    wrap(<ProtectedDocumentsPage />);
    expect(await screen.findByRole('columnheader', { name: '누적 탐지 · 최근' })).toBeInTheDocument();
    expect(await screen.findByText('14건')).toBeInTheDocument();
  });
});

describe('confidential keyword detections', () => {
  it('classifies like the server and names keyword hits separately', () => {
    expect(['KR_RRN', 'GITHUB_TOKEN', 'PRIVATE_KEY', 'DOC_KEYWORD', 'NEW_TYPE'].map(entityCategory)).toEqual(['PII', 'CREDENTIAL', 'CREDENTIAL', 'KEYWORD', 'PII']);
    expect(signatureLabel(['DOC_KEYWORD'])).toBe('기밀 키워드');
    expect(signatureLabel(['DOC_KEYWORD', 'KR_RRN'])).toBe('민감정보·기밀 키워드');
    expect(signatureLabel(['KR_RRN'])).toBe('민감정보 패턴');
  });
  it('shows a keyword-only event as a keyword detection on the detail summary', () => {
    render(<MemoryRouter><InvestigationSummary event={{ eventId: 'evt-kw', occurredAt: '2026-10-10T00:00:00Z', clientId: 'c', targetLlm: 'ChatGPT', status: 'NEW', detectionOutcome: 'MATCH',
      finalAction: 'BLOCK', detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', entityCounts: [{ entityType: 'DOC_KEYWORD', count: 2 }] }], adminNotes: [], timeline: [] } as never} /></MemoryRouter>);
    expect(screen.getByRole('heading', { name: '기밀 키워드 탐지' })).toBeInTheDocument();
  });
  it('filters the event list by detected information kind', async () => {
    const get = vi.spyOn(httpClient, 'get').mockResolvedValue(emptyPage);
    await httpGatewayApi.getEvents({ ...filters, entityCategory: 'KEYWORD' }, undefined);
    expect(String(get.mock.calls[0][0])).toContain('entity_category=KEYWORD');
    await httpGatewayApi.getEvents({ ...filters, entityCategory: 'ALL' }, undefined);
    expect(String(get.mock.calls[1][0])).not.toContain('entity_category');
    const list = vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/events']}><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    fireEvent.click(await screen.findByRole('button', { name: '상세 조건' }));
    fireEvent.change(await screen.findByLabelText('탐지 정보 종류'), { target: { value: 'KEYWORD' } });
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ entityCategory: 'KEYWORD' }), expect.any(AbortSignal)));
  });
});

describe('event filters in operation mode', () => {
  it('hides match type and score basis because they mirror the detection method', async () => {
    vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/events']}><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    fireEvent.click(await screen.findByRole('button', { name: '상세 조건' }));
    expect(screen.getByLabelText('탐지 방식')).toBeInTheDocument();
    expect(screen.queryByLabelText('일치 유형')).toBeNull();
    expect(screen.queryByLabelText('점수 기준')).toBeNull();
  });
  it('ignores the hidden filters even when they come in the address', async () => {
    const list = vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/events?matchType=TEXT_FRAGMENT&scoreKind=COVERAGE']}><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ matchType: 'ALL', scoreKind: 'ALL' }), expect.any(AbortSignal)));
  });
});

describe('audit log rows are read one by one', () => {
  it('keeps good rows, drops only unreadable changes, and counts rows it cannot show', () => {
    const page = readAuditRows({ ...emptyPage, total: 3, items: [
      audit(),
      audit({ audit_id: 'audit-2', changes: { previous_action: 'QUARANTINE', new_action: 'BLOCK' } }),   // 화면이 모르는 정책 조치
      audit({ audit_id: 'audit-3', action: 'FUTURE_ACTION' }),                                              // 화면이 모르는 작업
    ] });
    expect(page.items.map((row) => (row as { audit_id: string }).audit_id)).toEqual(['audit-1', 'audit-2']);
    expect((page.items[1] as { changes?: unknown }).changes).toBeUndefined();
    expect(mapAuditLogDto(page.items[1] as never).changesUnreadable).toBe(true);   // 줄마다 표시
    expect(mapAuditLogDto(page.items[0] as never)).not.toHaveProperty('changesUnreadable');
    expect(page).toMatchObject({ skipped: 1, partial: 1, total: 3 });
    expect(readAuditRows({ ...emptyPage, items: [audit()], total: 1 })).not.toHaveProperty('skipped');
  });

  it('loads the page through the adapter even when one row is malformed', async () => {
    vi.spyOn(httpClient, 'get').mockResolvedValue({ ...emptyPage, total: 2, items: [audit(), audit({ audit_id: 'audit-x', result: 'MAYBE' })] });
    // 운영 화면이 쓰는 실제 연결(시험 환경의 auditService는 예시 연결을 씀)
    const page = mapPageDto(await httpGatewayApi.getAuditLogs({ period: '7D', action: 'ALL', result: 'ALL', admin: '', page: 1, pageSize: 20 } as never), mapAuditLogDto);
    expect(page.items.map((row) => row.auditId)).toEqual(['audit-1']);
    expect(page.skipped).toBe(1);
  });

  it('tells the reader what was hidden', async () => {
    vi.spyOn(auditService, 'getLogs').mockResolvedValue({ items: [{ auditId: 'audit-1', occurredAt: '2026-10-10T01:00:00Z', adminId: 'local-admin', action: 'ADMIN_LOGIN',
      targetType: 'ADMIN', targetId: 'local-admin', result: 'SUCCESS' }], total: 3, page: 1, pageSize: 20, totalPages: 1, skipped: 1, partial: 1 });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuditLogsPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText(/이 쪽에서 형식을 읽지 못해 숨긴 기록 1건 · 이 쪽에서 바뀐 값을 읽지 못한 기록 1건/)).toBeInTheDocument();
  });

  it('a row whose changes could not be read does not claim nothing was recorded', async () => {
    vi.spyOn(auditService, 'getLogs').mockResolvedValue({ items: [{ auditId: 'audit-2', occurredAt: '2026-10-10T01:00:00Z', adminId: 'local-admin', action: 'POLICY_UPDATE',
      targetType: 'POLICY', targetId: 'POLICY-PII-MASK', result: 'SUCCESS', changesUnreadable: true }], total: 1, page: 1, pageSize: 20, totalPages: 1, partial: 1 });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuditLogsPage /></MemoryRouter></QueryClientProvider>);
    fireEvent.click(await screen.findByRole('button', { name: 'audit-2 상세 열기' }));
    expect(screen.getByText(/화면이 읽을 수 없는 형식이라 표시하지 않았습니다/)).toBeInTheDocument();
    expect(screen.queryByText(/변경 전·후 값이 기록되지 않았습니다/)).toBeNull();
  });
});

describe('overview gateway status', () => {
  it('reads the live fields from the stats response', async () => {
    const stats = { total: 0, block: 0, mask: 0, allow: 0, new_events: 0, average_processing_ms: 0, trend: [], recent: [] };
    const get = vi.spyOn(httpClient, 'get').mockResolvedValue({ ...stats, gateway_status: 'HEALTHY', gateway_metrics_status: 'FRESH', gateway_completed_requests: 12 });
    const live = mapDashboardStatsDto(await httpGatewayApi.getDashboardStats('24H', undefined));
    expect(live).toMatchObject({ gatewayStatus: 'HEALTHY', gatewayMetricsStatus: 'FRESH', gatewayCompletedRequests: 12 });
    expect(gatewayLiveLabel(live).label).toBe('정상');
    get.mockResolvedValue({ ...stats, gateway_status: 'UNKNOWN', gateway_metrics_status: 'STALE' });
    expect(gatewayLiveLabel(mapDashboardStatsDto(await httpGatewayApi.getDashboardStats('24H', undefined))).label).toBe('연결 확인 안 됨');
  });
  it('reads overview insights from the stats response through the schema and mapper', async () => {
    const heatmap = Array.from({ length: 7 }, (_, day) => Array.from({ length: 24 }, (_, hour) => (day === 2 && hour === 18 ? 4 : 0)));
    vi.spyOn(httpClient, 'get').mockResolvedValue({ total: 5, block: 3, mask: 2, allow: 0, new_events: 0, average_processing_ms: 0, trend: [], recent: [],
      insights: { entity_counts: [{ key: 'KR_RRN', count: 3 }], documents: [{ key: 'doc-13', count: 2, blocked: 2, name: '사업전략.docx' }, { key: 'doc-05', count: 1 }],
        llm_actions: [{ key: 'ChatGPT', block: 3, mask: 2, allow: 0 }], content_actions: [{ key: 'prompt', block: 1, mask: 2, allow: 0 }, { key: 'file', block: 2, mask: 0, allow: 0 }], heatmap,
        category_counts: [{ key: 'PII', events: 3, values: 3 }, { key: 'CREDENTIAL', events: 0, values: 0 }, { key: 'KEYWORD', events: 1, values: 2 }],
        entity_event_counts: [{ key: 'KR_RRN', count: 3 }] } });
    expect(mapDashboardStatsDto(await httpGatewayApi.getDashboardStats('24H', undefined)).insights).toEqual({
      entityCounts: [{ key: 'KR_RRN', count: 3 }],
      documents: [{ key: 'doc-13', count: 2, blocked: 2, name: '사업전략.docx' }, { key: 'doc-05', count: 1 }],
      llmActions: [{ key: 'ChatGPT', block: 3, mask: 2, allow: 0 }],
      contentActions: [{ key: 'prompt', block: 1, mask: 2, allow: 0 }, { key: 'file', block: 2, mask: 0, allow: 0 }],
      heatmap,
      categoryCounts: [{ key: 'PII', events: 3, values: 3 }, { key: 'CREDENTIAL', events: 0, values: 0 }, { key: 'KEYWORD', events: 1, values: 2 }],
      entityEventCounts: [{ key: 'KR_RRN', count: 3 }],
    });
  });
  it('never rounds a partial share to 0% or 100%', () => {
    expect([percent(0, 300), percent(1, 300), percent(199, 200), percent(200, 200), percent(1, 0)]).toEqual(['0%', '1%', '99%', '100%', '—']);
  });
  const base = { gatewayStatus: 'UNKNOWN' } as DashboardStats;
  it.each([
    [{}, '연결 확인 안 됨', 'unknown'],
    [{ gatewayMetricsStatus: 'STALE', gatewayStatus: 'HEALTHY' }, '연결 확인 안 됨', 'unknown'],
    [{ gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY', gatewayCompletedRequests: 12 }, '정상', 'healthy'],
    [{ gatewayMetricsStatus: 'FRESH', gatewayStatus: 'UNKNOWN', gatewayCompletedRequests: 0 }, '요청 대기', 'healthy'],
    [{ gatewayMetricsStatus: 'FRESH', gatewayStatus: 'DEGRADED', gatewayCompletedRequests: 0 }, '오류 기록 있음', 'degraded'],
  ] as const)('%o → %s', (over, label, dot) => {
    expect(gatewayLiveLabel({ ...base, ...over } as DashboardStats)).toEqual({ label, dot });
  });
});
