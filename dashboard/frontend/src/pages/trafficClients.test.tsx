// 연결 중인 IP(2026-10-12): 트래픽 화면의 '요청 기록과 탐지 결과' 표를 없애고 그 자리에 Gateway에 연결된 IP를 보여 준다.
// IP는 문서용 대역(203.0.113.x · 198.51.100.x · 2001:db8::)만 쓴다.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TrafficPerformancePage } from './TrafficPerformancePage';
import { TrafficClientsPanel, formatRelativeTime } from '@/src/components/TrafficClientsPanel';
import { trafficService } from '@/src/services/trafficService';
import { mockGatewayApi } from '@/src/api/mockAdapter';
import { parseApiResponse, trafficClientsSchema } from '@/src/api/schemas';
import { ApiError } from '@/src/api/errors';
import { clientAliasService, gatewayAccessService } from '@/src/services/gatewayAccessService';
import type { TrafficClient, TrafficClients, TrafficSnapshot } from '@/src/types/traffic';

vi.mock('recharts', () => ({ LineChart: () => null, Line: () => null, CartesianGrid: () => null, Legend: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));

const NOW = Date.parse('2026-10-12T02:00:00Z');
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();
const client = (over: Partial<TrafficClient> = {}): TrafficClient => ({
  ip: '203.0.113.5', clientId: 'chrome-00000000-0000-4000-8000-000000000001', connections: 2, inflight: 0, waiting: 0, requests5m: 7,
  targets: [{ llm: 'ChatGPT', count: 5 }, { llm: 'Claude', count: 2 }], firstSeenAt: ago(3_600), lastSeenAt: ago(30), ...over,
});
const clients = (over: Partial<TrafficClients> = {}): TrafficClients => ({
  receivedAt: ago(5), stale: false, windowSeconds: 300,
  clients: [client(), client({ ip: '2001:db8::1', clientId: undefined, connections: 0, requests5m: 0, targets: [], firstSeenAt: ago(1_200), lastSeenAt: ago(420) })],
  ...over,
});
const snapshot: TrafficSnapshot = {
  period: '24H',
  summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY', gatewayTotalRequests: 10, gatewayCompletedRequests: 10,
    gatewayErrorRequests: 0, gatewayWindowSeconds: 60, activeClients: 1, concurrentRequests: 0, requestsPerSec: 0.1, latencySampleCount: 10, averageLatencyMs: 30, p95LatencyMs: 60 },
  timeSeries: [],
};
const renderPage = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
const renderPanel = (data: TrafficClients | undefined, extra: Partial<Parameters<typeof TrafficClientsPanel>[0]> = {}) =>
  render(<div className="traffic-console"><TrafficClientsPanel data={data} loading={false} onRetry={() => undefined} now={NOW} {...extra} /></div>);

beforeEach(() => {
  vi.restoreAllMocks();
  // 서버가 아직 접속 차단 API를 모르는 상태(화면 먼저 반영): 연결 IP 표는 '관리' 칸 없이 예전 모양 그대로(접속 차단 관리는 trafficClientsAccess.test.tsx)
  vi.spyOn(gatewayAccessService, 'get').mockRejectedValue(new ApiError('요청을 처리하지 못했습니다.', 'NOT_FOUND', 404));
  vi.spyOn(clientAliasService, 'list').mockRejectedValue(new ApiError('요청을 처리하지 못했습니다.', 'NOT_FOUND', 404));
});

describe('traffic page: connected IPs replace the request record table', () => {
  it('removes the request/detection table and shows the connected IP section with its rows', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    const getClients = vi.spyOn(trafficService, 'getClients').mockResolvedValue(clients({ receivedAt: new Date(Date.now() - 3_000).toISOString() }));
    renderPage();
    const section = (await screen.findByRole('heading', { name: '연결 중인 IP' })).closest('section') as HTMLElement;
    expect(await within(section).findByText('203.0.113.5')).toBeInTheDocument();
    expect(getClients).toHaveBeenCalledTimes(1);
    expect(screen.queryByText('요청 기록과 탐지 결과')).toBeNull();
    expect(screen.queryByText(/저장된 최근 보안 이벤트/)).toBeNull();
    expect(screen.queryByRole('columnheader', { name: '탐지 · 유형' })).toBeNull();
    expect(screen.getByRole('heading', { name: '시간대별 처리 시간' })).toBeInTheDocument();   // 2026-10-14 지표 정리: 'Gateway 처리 시간 추이' → 무엇을 재는지 드러나는 이름
    const headers = within(section).getAllByRole('columnheader').map(cell => cell.textContent);
    // 재설계 3c(설계 4.6·5.9): 9열 → 7열(관리 칸 없으면 6열). IP·확장 ID는 '대상' 한 칸, 처음 확인은 마지막 활동의 title
    // 2026-10-15: '최근 5분 요청' → '최근 5분 검사 요청'(Gateway가 보안 검사를 거친 요청만 셈, 화면 로딩·자산 제외)
    expect(headers).toEqual(['대상', '상태', '최근 5분 검사 요청', '열린 연결', '대상 LLM', '마지막 활동']);
    expect(within(section).getByText(/연결 중 IP 1 · 최근 활동 IP 1/)).toBeInTheDocument();
    expect(within(section).getByText(/^수신 /)).toBeInTheDocument();
    expect(screen.getAllByRole('table')).toHaveLength(1);
  });

  it('shows an error only in the IP section and keeps the rest of the page', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    vi.spyOn(trafficService, 'getClients').mockRejectedValue(new ApiError('요청을 처리하지 못했습니다.', 'NOT_FOUND', 404));
    renderPage();
    expect(await screen.findByText('연결 중인 IP를 불러오지 못했습니다.')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Gateway 지표' })).getByText('느린 5% 요청의 처리 시간 (P95)')).toBeInTheDocument();   // 2026-10-14: 'Gateway 처리 시간 (P95)' → 풀어 쓴 이름
  });

  it('refreshes the IP list with the page refresh button', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    const getClients = vi.spyOn(trafficService, 'getClients').mockResolvedValue(clients());
    renderPage();
    await screen.findByText('203.0.113.5');
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await vi.waitFor(() => expect(getClients).toHaveBeenCalledTimes(2));
  });
});

describe('connected IP panel', () => {
  it('renders each row with status, connection count, requests, targets and times', () => {
    renderPanel(clients({ clients: [client({ inflight: 1 }), client({ ip: '2001:db8::1', clientId: undefined, connections: 0, requests5m: 0, targets: [], firstSeenAt: ago(1_200), lastSeenAt: ago(420) })] }));
    const [, live, idle] = screen.getAllByRole('row');
    const cells = (row: HTMLElement) => within(row).getAllByRole('cell').map(cell => cell.textContent);
    expect(cells(live)).toEqual(['203.0.113.5chrome-00000000-0000-4000-8000-000000000001', '연결 중처리 중 1건', '7', '2', 'ChatGPT 5 · Claude 2', '30초 전']);
    expect(cells(idle)).toEqual(['2001:db8::1확장 ID 없음', '최근 활동', '0', '0', '-', '7분 전']);
    // 상태는 새 배지 1종(옛 .status-badge 클래스는 옛 규칙이 배지 모양을 지워 달지 않음 — stage3/README.md)
    expect(within(live).getByText('연결 중')).toHaveAttribute('data-tone', 'allow');
    expect(within(idle).getByText('최근 활동')).toHaveAttribute('data-tone', 'neutral');
    // 상대 시간 옆에 정확한 시각
    expect(within(live).getByText('30초 전')).toHaveAttribute('title', expect.stringMatching(/2026\. 10\. 12\. 10시 59분 30초/));
    expect(within(live).getByText('30초 전')).toHaveAttribute('dateTime', ago(30));
    expect(within(live).getByText('30초 전')).toHaveAttribute('title', expect.stringContaining('처음 확인 1시간 전'));   // 옛 '처음 확인' 칸
    expect(screen.getByText(/연결 중 IP 1 · 최근 활동 IP 1/)).toBeInTheDocument();
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('says the request column counts only inspected requests (2026-10-15)', () => {
    renderPanel(clients());
    const header = screen.getByRole('columnheader', { name: '최근 5분 검사 요청' });
    // 산정 기준: 질문·파일 업로드처럼 보안 검사를 거친 요청, 자산·페이지 로딩·상태 확인 제외(툴팁 + 표 아래 줄)
    expect(header).toHaveAttribute('title', expect.stringMatching(/^질문\(프롬프트\)·파일 업로드처럼 보안 검사를 거친 요청.*페이지 로딩·이미지 등 자산·상태 확인은 세지 않음$/));
    expect(header.getAttribute('title')).toContain('차단·마스킹·허용, 검사 응답 없음·검사 못 한 파일 포함');
    expect(screen.getByRole('columnheader', { name: '대상 LLM' })).toHaveAttribute('title', '최근 5분 검사 요청의 LLM별 수');
    expect(screen.getByText(/^검사 요청 = 질문\(프롬프트\)·파일 업로드처럼 보안 검사를 거친 요청/)).toHaveTextContent('페이지 로딩·이미지 등 자산·상태 확인은 세지 않음');
    expect(screen.queryByRole('columnheader', { name: '최근 5분 요청' })).toBeNull();
    // 좁은 화면 카드의 칸 이름도 같은 말
    const [, row] = screen.getAllByRole('row');
    expect(within(row).getByText('7')).toHaveAttribute('data-label', '5분 검사 요청');
  });

  it('shows 처리 중 and 대기 연결 under the status only when above zero', () => {
    renderPanel(clients({ clients: [
      client({ ip: '203.0.113.11', inflight: 2 }),
      client({ ip: '203.0.113.12', waiting: 3 }),
      client({ ip: '203.0.113.13', inflight: 1, waiting: 2 }),
      client({ ip: '203.0.113.14' }),
    ] }));
    const [, onlyInflight, onlyWaiting, both, none] = screen.getAllByRole('row');
    const status = (row: HTMLElement) => within(row).getAllByRole('cell')[1].textContent;
    expect(status(onlyInflight)).toBe('연결 중처리 중 2건');
    expect(status(onlyWaiting)).toBe('연결 중대기 연결 3개');
    expect(status(both)).toBe('연결 중처리 중 1건대기 연결 2개');
    expect(status(none)).toBe('연결 중');
    expect(within(onlyInflight).queryByText(/대기 연결/)).toBeNull();
    expect(within(onlyWaiting).queryByText(/처리 중/)).toBeNull();
    expect(within(onlyWaiting).getByText('대기 연결 3개')).toHaveAttribute('title', '응답을 오래 받고 있는 연결(스트리밍 등) — 정상');
    expect(within(both).getByText('대기 연결 2개')).toHaveAttribute('title', '응답을 오래 받고 있는 연결(스트리밍 등) — 정상');
    expect(within(both).getByText('처리 중 1건')).not.toHaveAttribute('title');
    // 상태 배지와 위 요약 숫자는 대기 연결과 상관없이 열린 연결 수로만 정한다
    expect(within(onlyWaiting).getByText('연결 중')).toHaveAttribute('data-tone', 'allow');
    expect(screen.getByText(/연결 중 IP 4 · 최근 활동 IP 0/)).toBeInTheDocument();
  });

  it('warns that the list may be old when metrics are stale', () => {
    renderPanel(clients({ stale: true, receivedAt: ago(95) }));
    expect(screen.getByRole('status')).toHaveTextContent('Gateway 지표가 30초 넘게 들어오지 않아 연결 상태가 오래되었을 수 있습니다.');
    expect(screen.getByText('203.0.113.5')).toBeInTheDocument();
  });

  it('shows the empty state when no IP is connected', () => {
    renderPanel(clients({ clients: [] }));
    expect(screen.getByText('지금 연결된 IP가 없습니다.')).toBeInTheDocument();
    expect(screen.getByText(/연결 중 IP 0 · 최근 활동 IP 0/)).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('does not claim "no IPs" when stale and empty, and says when metrics never arrived', () => {
    const stale = renderPanel(clients({ clients: [], stale: true, receivedAt: ago(120) }));
    expect(screen.getByText('마지막으로 받은 지표에 연결된 IP가 없습니다.')).toBeInTheDocument();
    expect(screen.queryByText('지금 연결된 IP가 없습니다.')).toBeNull();
    stale.unmount();
    renderPanel(clients({ clients: [], stale: true, receivedAt: undefined }));
    expect(screen.getByText('Gateway 지표를 아직 받지 못했습니다.')).toBeInTheDocument();
    expect(screen.getByText(/수신 기록 없음/)).toBeInTheDocument();
    expect(screen.queryByText(/30초 넘게/)).toBeNull();
  });

  it('keeps the last result with a notice when a refresh fails', () => {
    renderPanel(clients(), { error: new ApiError('요청을 처리하지 못했습니다.', 'SERVER', 500) });
    expect(screen.getByText('갱신 실패 · 아래는 마지막으로 받은 연결 상태입니다.')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.5')).toBeInTheDocument();
  });

  it('pages long lists 20 rows at a time', () => {
    renderPanel(clients({ clients: Array.from({ length: 25 }, (_, index) => client({ ip: `198.51.100.${index + 1}` })) }));
    expect(screen.getAllByRole('row')).toHaveLength(21);
    expect(screen.getByText('25건')).toBeInTheDocument();   // 개수는 표 위 왼쪽, 쪽은 아래 오른쪽(설계 4.5)
    expect(screen.getByText('1 / 2쪽')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '다음 페이지' }));
    expect(screen.getAllByRole('row')).toHaveLength(6);
    expect(screen.getByText('198.51.100.25')).toBeInTheDocument();
  });

  it('formats relative times plainly', () => {
    expect(formatRelativeTime(ago(3), NOW)).toBe('방금');
    expect(formatRelativeTime(ago(-20), NOW)).toBe('방금');   // 서버 시계가 조금 빨라도 음수로 쓰지 않는다
    expect(formatRelativeTime(ago(59), NOW)).toBe('59초 전');
    expect(formatRelativeTime(ago(600), NOW)).toBe('10분 전');
    expect(formatRelativeTime(ago(7_200), NOW)).toBe('2시간 전');
    expect(formatRelativeTime(ago(172_800), NOW)).toBe('2일 전');
    expect(formatRelativeTime('not-a-time', NOW)).toBe('시각 미기록');
  });
});

describe('demo adapter', () => {
  it('returns contract-valid clients with documentation-range IPs only', async () => {
    const payload = parseApiResponse(trafficClientsSchema, await mockGatewayApi.getTrafficClients());
    expect(payload.clients.length).toBeGreaterThan(0);
    for (const item of payload.clients) expect(item.ip).toMatch(/^(203\.0\.113\.|198\.51\.100\.|2001:db8:)/);
    expect(payload.clients.some(item => item.connections === 0)).toBe(true);
    expect(payload.clients.some(item => item.waiting > 0)).toBe(true);
    expect(payload.clients.some(item => item.inflight > 0)).toBe(true);
  });
});
