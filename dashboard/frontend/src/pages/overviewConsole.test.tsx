import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OverviewPage } from './OverviewPage';
import { RecordStatusBar } from '@/src/components/OverviewPanels';
import { dashboardService } from '@/src/services/dashboardService';
import { documentService } from '@/src/services/documentService';
import { detectionOpsService } from '@/src/services/detectionOpsService';
import { gatewaySettingsService } from '@/src/services/gatewaySettingsService';
import type { GatewaySettingsResponse } from '@/src/api/gatewaySettingsSchemas';
import { ApiError } from '@/src/api/errors';
import type { DashboardStats, SecurityEvent } from '@/src/types/event';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('recharts', () => ({ BarChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>, Bar: () => null, CartesianGrid: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));
const stats: DashboardStats = { total: 12, block: 3, mask: 1, allow: 8, degraded: 0, enforcementRate: 1, actionMismatch: 0, newEvents: 2, averageProcessingMs: 5, gatewayStatus: 'HEALTHY', detectionStatus: 'HEALTHY', lastSuccessAt: '2026-10-05T00:00:00Z', trend: [{ bucket: '2026-10-05', total: 12, block: 3, mask: 1, allow: 8 }], recent: [] };
// 보안 현황 그래프(2026-10-10)
Object.assign(stats, { insights: { entityCounts: [{ key: 'KR_PHONE_NUMBER', count: 7 }, { key: 'KR_RRN', count: 2 }], documents: [{ key: 'doc/#mixed', name: '공정 문서', count: 3 }],
  llmActions: [{ key: 'Gemini', block: 3, mask: 1, allow: 8 }], contentActions: [{ key: 'prompt', block: 1, mask: 1, allow: 8 }, { key: 'file', block: 2, mask: 0, allow: 0 }],
  heatmap: Array.from({ length: 7 }, (_, day) => Array.from({ length: 24 }, (_, hour) => (day === 2 && hour === 18 ? 3 : day === 6 && hour === 10 ? 1 : 0))) } });
function view() { return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/overview?period=30D']}><OverviewPage /></MemoryRouter></QueryClientProvider>); }
const values = { timeout: { prompt: { action: 'forward' as const, seconds: 3 }, file: { action: 'block' as const, seconds: 10 } }, uninspectable: { image: 'allow' as const, scanned_pdf: 'block' as const, other: 'block' as const }, notify_on_allow: true };
const settings = { settings: { ...values, version: 0, revision: null, updated_at: null, updated_by: null, source: 'DEFAULT' }, defaults: values, gateway: { state: 'APPLIED' } } as GatewaySettingsResponse;
beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(dashboardService, 'getStats').mockResolvedValue(stats);
  // 재설계 3b: 지표 ②의 지금 설정·③ 보호 범위가 읽는 기존 응답
  vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(settings);
  vi.spyOn(documentService, 'getDocuments').mockResolvedValue([]);
  vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue([]);
  vi.spyOn(detectionOpsService, 'getKeywordJobs').mockResolvedValue({ jobs: [], counts: { queued: 0, running: 0, done: 0, failed: 0 } });
});
describe('Overview presentation-only console refactor', () => {
  it('uses existing counts, keeps five workflow links, and places refresh in the header', async () => {
    const { container } = view();
    await screen.findByRole('link', { name: '전송 차단 목록 보기' });
    // 재설계 2단계: 새 페이지 머리(h1) 안에 새로고침이 있다
    const header = screen.getByRole('heading', { level: 1, name: '보안 현황' }).closest('header') as HTMLElement;
    expect(within(header).getByRole('button', { name: '새로고침' })).toBeInTheDocument();
    expect(container.querySelectorAll('.console-kpi')).toHaveLength(4);
    // 쓰지 않는 조사 상태(신규)는 없음. 재설계 3b(설계 5.1): 요청 처리 흐름 패널 → 전체 카드의 보조 줄·비율 막대(같은 숫자를 한 번만)
    expect(screen.queryByText('신규 상태 이벤트')).toBeNull();
    expect(screen.queryByRole('complementary', { name: '요청 처리 흐름' })).toBeNull();
    const total = screen.getByRole('link', { name: '전체 이벤트 목록 보기' });
    // 2026-10-15 감사 1번: 옛 서버(집계 기준 없음)는 검출 수를 모르므로 '차단·마스킹'으로 적는다(전에는 이 합을 '민감정보·기밀 포함'이라 함)
    expect(total).toHaveTextContent('차단·마스킹 4건 · 33%');
    expect(total).not.toHaveTextContent('민감정보·기밀');
    expect(within(total).getByRole('img', { name: '최종 조치 비율: 차단 3, 마스킹 1, 허용 8' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '전송 차단 목록 보기' })).toHaveAttribute('href', '/events?period=30D&finalAction=BLOCK');
    expect(screen.getByRole('link', { name: '민감정보 마스킹 목록 보기' })).toHaveAttribute('href', '/events?period=30D&finalAction=MASK');
    // 탐지 분석: 정보 유형·보호 문서·서비스·입력 형태·요일·시간대
    const insights = screen.getByRole('region', { name: '탐지 분석' });
    expect(within(insights).getByText('전화번호')).toBeInTheDocument();
    expect(within(insights).getByRole('link', { name: '공정 문서' })).toHaveAttribute('href', '/documents/doc%2F%23mixed');
    expect(within(insights).getByRole('link', { name: 'Gemini' })).toHaveAttribute('href', '/events?period=30D&llm=Gemini');
    expect(within(insights).getByText('파일 업로드의 조치 비율이 프롬프트의 5.0배')).toBeInTheDocument();
    expect(within(insights).getByText(/가장 많은 시간 화요일 18시\(3건\) · 업무 시간 밖\(평일 20시~8시, 주말\) 25%/)).toBeInTheDocument();
    expect(screen.getByText('30일 · 일별 저장 이벤트')).toBeInTheDocument();
    expect(screen.queryByText('Database 정상')).toBeNull(); expect(screen.queryByText('Redis 정상')).toBeNull();
  });
  it('shows a small empty state instead of rendering an empty chart', async () => {
    vi.mocked(dashboardService.getStats).mockResolvedValue({ ...stats, total: 0, block: 0, mask: 0, allow: 0, newEvents: 0, trend: [], lastSuccessAt: undefined, gatewayStatus: 'UNKNOWN', detectionStatus: 'UNKNOWN' });
    const { container } = view(); await screen.findByText('해당 기간에 기록된 이벤트가 없습니다.');
    expect(container.querySelector('.console-trend-chart')).toBeNull();
    expect(screen.getByText('연결 확인 안 됨')).toBeInTheDocument();   // Gateway 실시간 지표 없음
    expect(screen.getAllByText('확인 불가')).toHaveLength(1);              // Detection 저장 기록 없음
    expect(screen.queryByText(/정상/)).toBeNull();
  });
  it('retains the last successful data after network failure but removes it for forbidden access', async () => {
    view(); await screen.findByRole('link', { name: '전체 이벤트 목록 보기' });
    vi.mocked(dashboardService.getStats).mockRejectedValue(new ApiError('offline', 'NETWORK'));
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText(/아래는 마지막 성공 조회 결과/);
    expect(screen.getByRole('link', { name: '전체 이벤트 목록 보기' })).toBeInTheDocument();
    vi.mocked(dashboardService.getStats).mockRejectedValue(new ApiError('denied', 'FORBIDDEN', 403));
    await waitFor(() => expect(screen.getByRole('button', { name: '새로고침' })).not.toBeDisabled());
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText('이 작업을 수행할 권한이 없습니다.');
    expect(screen.queryByRole('link', { name: '전체 이벤트 목록 보기' })).toBeNull();
  });
  // 재설계 3b(설계 5.1 첫눈 ③): 최근 이벤트 8건 → 6건, 짧은 목록(표→카드)
  it('shows only six recent records and preserves URI-encoded evidence/document navigation', async () => {
    const event: SecurityEvent = { eventId: 'evt/#Mixed', clientId: 'client', occurredAt: '2026-10-05T00:00:00Z', targetLlm: 'Gemini', detectionOutcome: 'MATCH', finalAction: 'BLOCK', status: 'NEW', detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', score: 1, scoreKind: 'COVERAGE', matchedDocumentId: 'doc/#Mixed', matchedDocumentName: '공정 문서', documentSpan: { charStart: 0, charEnd: 40, endExclusive: true } }], adminNotes: [], timeline: [] };
    vi.mocked(dashboardService.getStats).mockResolvedValue({ ...stats, recent: Array.from({ length: 10 }, (_, index) => ({ ...event, eventId: index ? `evt-${index}` : event.eventId })) });
    view();
    expect(await screen.findByRole('link', { name: 'evt/#Mixed 상세 보기' })).toHaveAttribute('href', '/events/evt%2F%23Mixed?view=compare');
    expect(screen.getAllByRole('link', { name: '공정 문서' })[0]).toHaveAttribute('href', '/documents/doc%2F%23Mixed');
    expect(within(screen.getByRole('table', { name: '최근 보안 이벤트' })).getAllByRole('row')).toHaveLength(7);
    expect(screen.getByRole('link', { name: '전체 이벤트 보기' })).toHaveAttribute('href', '/events?period=30D');
  });
  it('does not reinterpret stored aggregate errors as a current system outage', () => {
    render(<RecordStatusBar stats={{ ...stats, gatewayStatus: 'DEGRADED', gatewayMetricsStatus: 'FRESH', detectionStatus: 'DEGRADED' }} stale={false} />);
    expect(screen.getAllByText('오류 기록 있음')).toHaveLength(1);   // Gateway(실시간)
    expect(screen.getByText('기간 중 오류 0건')).toBeInTheDocument();   // Detection은 기간 기록이라 기간·건수로(2026-10-15 감사 8번)
    expect(screen.getByText('저장 기록 기준')).toBeInTheDocument();
    expect(screen.queryByText(/현재 장애|서버 정상|DB 정상/)).toBeNull();
  });
  // 재설계 3b(설계 5.1.1 권고 ①②③): 기존 응답으로 계산한 지표 카드 3개
  it('shows block/mask reasons, requests handled without inspection with the current setting, and protection coverage', async () => {
    const event = (id: string, extra: Partial<SecurityEvent>): SecurityEvent => ({ eventId: id, clientId: 'c', occurredAt: '2026-10-05T00:00:00Z', targetLlm: 'ChatGPT', detectionOutcome: 'MATCH', finalAction: 'BLOCK', status: 'NEW', detections: [], adminNotes: [], timeline: [], ...extra });
    vi.mocked(dashboardService.getStats).mockResolvedValue({ ...stats, periodEvents: [
      event('a', { reasonCode: 'client_blocked' }), event('b', { degraded: true, finalAction: 'ALLOW', detectionOutcome: 'UNAVAILABLE' }), event('c', { degraded: true }),
      event('d', { finalAction: 'MASK', detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', entityCounts: [{ entityType: 'EMAIL', count: 1 }] }] }),
    ] });
    vi.mocked(documentService.getDocuments).mockResolvedValue([
      { documentId: 'd1', documentName: '문서 1', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 1, activeDetectors: ['WINDOW_HASH'] },
      { documentId: 'd2', documentName: '문서 2', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'PROCESSING', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'PROCESSING', chunkCount: 0, activeDetectors: ['WINDOW_HASH'] },
    ]);
    vi.mocked(detectionOpsService.getKeywords).mockResolvedValue([{ id: 1, keyword: 'k', doc_id: 'd1', status: 'pending', source: 'llm' }]);
    view();
    const reasons = await screen.findByRole('list', { name: '차단·마스킹 사유별 건수' });
    expect(within(reasons).getByRole('link', { name: /접속 차단/ })).toHaveAttribute('href', '/policies/access');
    expect(within(reasons).getByRole('img', { name: '보안 검사 응답 없음 차단 1건' })).toBeInTheDocument();
    expect(within(reasons).getByRole('img', { name: '개인정보 마스킹 1건' })).toBeInTheDocument();
    expect(reasons.closest('section')).toHaveTextContent('30일 차단·마스킹 3건을 건마다 대표 사유 1개로 셈(합 = 3건)');   // 2026-10-14: 기간·합계를 아래 줄에
    // 2026-10-14: '검사 없이 처리된 요청' → 트래픽 화면과 같은 이름 '검사 못 한 요청', 기간·분모를 적음
    const uninspected = screen.getByRole('region', { name: '검사 못 한 요청' });
    expect(uninspected).toHaveTextContent('30일 · 접속 차단 제외');
    expect(uninspected).toHaveTextContent('1건 검사 없이 허용 · 차단 1건 (접속 차단을 뺀 보안 이벤트 3건 중)');   // 분모도 접속 차단 제외(감사 7번)
    expect(uninspected).toHaveTextContent('지금 설정 · 응답 없음 프롬프트 허용 · 파일 차단');
    expect(within(uninspected).getByRole('link', { name: 'Gateway 처리' })).toHaveAttribute('href', '/policies/gateway');
    const coverage = screen.getByRole('region', { name: '보호 범위' });
    expect(await within(coverage).findByText('/ 2개 문서 보호 중')).toBeInTheDocument();
    expect(coverage).toHaveTextContent('지금 상태 · 기간과 무관');   // 2026-10-14: 기간 선택과 무관함을 머리에
    expect(coverage).toHaveTextContent('등록 문서 2개의 상태(보호 문서 화면 배지와 같은 기준)');
    expect(within(coverage).getByRole('img', { name: '보호 문서 상태: 보호 중 1, 분석 중 1, 분석 실패 0, 보호 중지 0' })).toBeInTheDocument();
    expect(await within(coverage).findByRole('link', { name: '1' })).toHaveAttribute('href', '/policies/keywords');
  });
  it('says the extra metrics could not be computed when the period event list was not read', async () => {
    view();
    await screen.findByRole('link', { name: '전체 이벤트 목록 보기' });
    expect(within(screen.getByRole('region', { name: '검사 못 한 요청' })).getByRole('alert')).toHaveTextContent('기간 이벤트 목록을 읽지 못해 계산하지 못함');
  });
});
