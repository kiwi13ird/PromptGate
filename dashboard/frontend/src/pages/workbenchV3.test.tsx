import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OverviewPage } from './OverviewPage';
import { TrafficPerformancePage } from './TrafficPerformancePage';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';
import { dashboardService } from '@/src/services/dashboardService';
import { trafficService } from '@/src/services/trafficService';
import { documentService } from '@/src/services/documentService';
import type { DashboardStats, SecurityEvent } from '@/src/types/event';
import type { TrafficSnapshot } from '@/src/types/traffic';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('recharts', () => ({ BarChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>, LineChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>, Bar: () => null, Line: () => null, CartesianGrid: () => null, Legend: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));
const event: SecurityEvent = { eventId: 'evt/#Mixed', occurredAt: '2026-10-05T00:00:00Z', clientId: 'client', targetLlm: 'Gemini', detectionOutcome: 'NO_MATCH', finalAction: 'ALLOW', status: 'NEW', detections: [], adminNotes: [], timeline: [] };
const stats: DashboardStats = { total: 1, block: 0, mask: 0, allow: 1, degraded: 0, enforcementRate: 0, actionMismatch: 0, newEvents: 1, averageProcessingMs: 0, gatewayStatus: 'UNKNOWN', detectionStatus: 'UNKNOWN', trend: [], recent: [event] };
const snapshot: TrafficSnapshot = { period: '30D', summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'UNKNOWN', gatewayTotalRequests: 0, gatewayCompletedRequests: 0, gatewayErrorRequests: 0, activeClients: 0, concurrentRequests: 0, requestsPerSec: 0, latencySampleCount: 0 }, timeSeries: [] };
function view(component: React.ReactNode, url: string) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[url]}>{component}</MemoryRouter></QueryClientProvider>);
}
beforeEach(() => vi.restoreAllMocks());
describe('V3 information hierarchy and preserved navigation', () => {
  it('keeps the recent queue before secondary analysis and all original workflow links', async () => {
    vi.spyOn(dashboardService, 'getStats').mockResolvedValue(stats);
    const { container } = view(<OverviewPage />, '/overview?period=30D');
    await screen.findByRole('link', { name: 'evt/#Mixed 상세 보기' });
    expect(container.querySelectorAll('.console-kpi')).toHaveLength(4);
    // 처리 흐름(2026-10-10)은 재설계 3b에서 전체 카드 보조 줄로 합침(설계 5.1)
    expect(screen.getByRole('link', { name: '전체 이벤트 목록 보기' })).toHaveTextContent('차단·마스킹 0건');
    expect(screen.getByRole('link', { name: 'evt/#Mixed 상세 보기' })).toHaveAttribute('href', '/events/evt%2F%23Mixed?view=compare');   // 최근 사건은 아래 최근 보안 이벤트 표에서
    expect(screen.queryByText('요청 ID로 기록 조회')).toBeNull();   // 보안 이벤트 화면에만
    expect(container.querySelector('.console-trend-chart')).toBeNull();
  });
  // 성능 검증 탭은 2026-10-13 뺐다(10/3 시험 측정 기록). 옛 주소 #performance로 와도 요청 모니터링이 보이고 API는 한 번만
  it('opens the old performance deep-link as request monitoring without changing the API', async () => {
    const get = vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    const { container } = view(<TrafficPerformancePage />, '/traffic?period=30D#performance');
    expect(await screen.findByText('요청 대기')).toBeInTheDocument();
    expect(container.querySelector('.traffic-monitor-workspace')).not.toHaveAttribute('hidden');
    expect(container.querySelector('.traffic-performance-workspace')).toBeNull();
    expect(screen.queryByRole('link', { name: '성능 검증' })).toBeNull();
    expect(screen.queryByRole('link', { name: '요청 모니터링' })).toBeNull();   // 탭이 하나만 남아 탭 줄을 그리지 않음
    expect(get).toHaveBeenCalledTimes(1);
    expect(get.mock.calls[0][0]).toBe('30D');
  });
  it('keeps traffic to monitoring and leaves event distribution to the overview', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    const { container } = view(<TrafficPerformancePage />, '/traffic?period=30D');
    expect(await screen.findByRole('heading', { name: '날짜별 처리 시간' })).toBeInTheDocument();   // 2026-10-14: 'Gateway 처리 시간 추이' → 30일은 날짜별
    expect(container.querySelector('.traffic-distribution')).toBeNull();
    expect(screen.queryByText('저장된 이벤트 수')).toBeNull();
    expect(screen.queryByText('측정 기록')).toBeNull();
    expect(container.querySelector('.console-section-nav')).toBeNull();
  });
  it('supports encoded document row keyboard navigation', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([{ documentId: 'doc/#1', documentName: '자산 문서', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 10, activeDetectors: ['WINDOW_HASH'] }]);
    view(<Routes><Route path="/documents" element={<ProtectedDocumentsPage />} /><Route path="/documents/:id" element={<h2>문서 상세 도착</h2>} /></Routes>, '/documents');
    fireEvent.keyDown(await screen.findByRole('row', { name: '자산 문서 문서 상세' }), { key: 'Enter' });
    expect(await screen.findByRole('heading', { name: '문서 상세 도착' })).toBeInTheDocument();
  });
  it('does not trigger row navigation or mutation from a nested protection button', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([{ documentId: 'doc/#1', documentName: '자산 문서', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 10, activeDetectors: ['WINDOW_HASH'] }]);
    const change = vi.spyOn(documentService, 'changeDocumentStatus');
    view(<Routes><Route path="/documents" element={<ProtectedDocumentsPage />} /><Route path="/documents/:id" element={<h2>문서 상세 도착</h2>} /></Routes>, '/documents');
    // 재설계 3e: 보호 중지는 행 ⋯ 메뉴 안 위험 항목, 확인창 제목은 "행동 · 대상"(설계 4.5·4.11)
    fireEvent.click(await screen.findByRole('button', { name: '자산 문서 더보기' }));
    fireEvent.click(await screen.findByRole('menuitem', { name: '보호 중지' }));
    expect(await screen.findByRole('heading', { name: '보호 중지 · 자산 문서' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '문서 상세 도착' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '취소' }));
    expect(change).not.toHaveBeenCalled();
  });
});
