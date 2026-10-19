import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '@/src/App';
import { ApiError } from '@/src/api/errors';
import { AppLayout } from '@/src/components/AppLayout';
import { AuthProvider } from '@/src/hooks/useAuth';
import { fixtureInstances, systemStatusFixture } from '@/src/mocks/systemStatus';
import { systemStatusKeys, systemStatusService } from '@/src/services/systemStatusService';
import { PERMISSION_MISSING_TEXT } from '@/src/utils/systemStatusPresentation';
import { SystemStatusPage } from './SystemStatusPage';

const MOCK_SESSION_KEY = 'llm-security-gateway-demo-session-v3';

function mount(node: React.ReactNode = <SystemStatusPage />, route = '/system') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}>{node}</MemoryRouter></QueryClientProvider>) };
}
function signIn() {
  window.sessionStorage.setItem(MOCK_SESSION_KEY, JSON.stringify({ id: 'admin-001', email: 'admin@securegate.local', displayName: 'Security Admin', role: 'Gateway Administrator' }));
}
const rowOf = (table: HTMLElement, text: string) => {
  const row = within(table).getAllByRole('row').find(candidate => within(candidate).queryByText(text));
  if (!row) throw new Error(`row not found: ${text}`);
  return row;
};
const itemOf = (text: string) => {
  const item = screen.getAllByRole('listitem').find(candidate => within(candidate).queryByText(text, { selector: '.pg-sys-name' }));
  if (!item) throw new Error(`item not found: ${text}`);
  return item;
};
const detailOf = (group: HTMLElement, name: string) => within(group).getByText(name).nextElementSibling as HTMLElement;

beforeEach(() => vi.restoreAllMocks());
afterEach(() => vi.useRealTimers());

describe('permission wording', () => {
  it('uses the agreed Korean sentence', () => {
    expect(PERMISSION_MISSING_TEXT).toBe('권한이 없어 조회하지 못했습니다(IAM 정책 추가 필요)');
  });
});

// 재설계 3d(설계 5.10): 구성 요소 표 → [확인 필요 카드(끊김·느림)] + [나머지 구성 요소 격자(확인 불가 먼저)], 세부는 서랍(4.8),
// 같은 확인 시각은 머리 한 번(상태 띠 '서버 확인'), 개수 요약은 상태 띠
describe('component cards', () => {
  it('puts down/slow components first as big cards, then the rest with unknown first, each with a 정상 / 느림 / 끊김 / 확인 불가 badge and summary', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    const rest = await screen.findByRole('list', { name: '구성 요소 상태' });
    const problems = screen.getByRole('list', { name: '확인 필요 구성 요소' });
    expect(within(problems).getAllByRole('listitem').map(item => item.getAttribute('data-component'))).toEqual(['relay', 'rds']);
    expect(within(rest).getAllByRole('listitem').map(item => item.getAttribute('data-component'))).toEqual(['redis', 'gpu', 'dashboard', 'gateway', 'detection', 'log_shipping', 'keyword_jobs']);
    const expected: [string, string, string, string][] = [
      ['대시보드', '정상', 'ok', '정상 · 가동 3시간'],
      ['RDS', '느림', 'slow', 'DB 응답 420ms'],
      ['Relay', '끊김', 'down', '연결 정보를 받지 못했습니다'],
      ['Redis', '확인 불가', 'unknown', '확인하지 못했습니다'],
    ];
    for (const [label, chip, status, summary] of expected) {
      const item = itemOf(label);
      expect(within(item).getByText(chip)).toHaveAttribute('data-status', status);
      expect(within(item).getByText(summary)).toBeInTheDocument();
      expect(within(item).queryByText('12:00:00')).toBeNull();   // 서버 확인 시각과 같으면 카드에 반복하지 않음
    }
  });

  it('summarises the counts and the problems in the status strip with the server check time once', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    const summary = await screen.findByRole('status', { name: '상태 요약' });
    expect(summary).toHaveAttribute('data-level', 'bad');
    expect(summary).toHaveTextContent('이상 1 · 주의 1');
    expect(summary).toHaveTextContent('Relay 끊김 · RDS 느림');
    expect(summary).toHaveTextContent('정상 5');
    expect(summary).toHaveTextContent('느림 1');
    expect(summary).toHaveTextContent('끊김 1');
    expect(summary).toHaveTextContent('확인 불가 2');
    expect(summary).toHaveTextContent('서버 확인 12:00:00');
    expect(within(summary).getByText('12:00:00')).toHaveAttribute('datetime', '2026-10-12T03:00:00Z');
  });

  it('opens a drawer with the key-value details and keeps it open after a refresh', async () => {
    const getStatus = vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    expect(screen.queryByRole('group', { name: 'Gateway 세부 정보' })).toBeNull();
    fireEvent.click(within(itemOf('Gateway')).getByRole('button', { name: 'Gateway' }));
    const drawer = await screen.findByRole('dialog', { name: 'Gateway' });
    const group = within(drawer).getByRole('group', { name: 'Gateway 세부 정보' });
    expect(detailOf(group, '확인 시각')).toHaveTextContent('12:00:00');
    expect(detailOf(group, '연결된 IP')).toHaveTextContent('3');
    expect(detailOf(group, '설정 반영')).toHaveTextContent('예');
    expect(detailOf(group, '전달 대기')).toHaveTextContent('0');
    // ISO 시각은 한국 시각(UTC+9)으로 바꿔 보인다: 02:59:52Z -> 11:59:52
    expect(detailOf(group, '마지막 보고')).toHaveTextContent('2026-10-12 11:59:52 KST');

    // 서랍이 열린 동안 뒤 화면은 가려져 있어(모달) 새로고침 버튼은 숨김 요소로 찾는다
    fireEvent.click(screen.getByRole('button', { name: '새로고침', hidden: true }));
    await waitFor(() => expect(getStatus).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByRole('button', { name: '새로고침', hidden: true })).toBeEnabled());
    expect(screen.getByRole('group', { name: 'Gateway 세부 정보' })).toBeInTheDocument();

    fireEvent.click(within(drawer).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.queryByRole('group', { name: 'Gateway 세부 정보' })).toBeNull());
  });

  it('gives a component without details no button, and big cards a 세부 정보 link', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    expect(within(itemOf('Redis')).getByText('Redis')).toBeInTheDocument();
    expect(within(itemOf('Redis')).queryByRole('button')).toBeNull();
    fireEvent.click(within(itemOf('Relay')).getByRole('button', { name: 'Relay 세부 정보' }));
    expect(await screen.findByRole('group', { name: 'Relay 세부 정보' })).toBeInTheDocument();
  });

  it('shows an empty notice when the server sends no components', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({ components: [] }));
    mount();
    expect(await screen.findByText('표시할 구성 요소가 없습니다.')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: '구성 요소 상태' })).toBeNull();
  });
});

describe('EC2 instances and RDS', () => {
  it('lists role, name, instance id, state and status checks', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    const table = await screen.findByRole('table', { name: 'EC2 인스턴스' });
    expect(within(table).getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['역할', '상태', '이름', '인스턴스 ID', '상태 점검']);   // 3d: 상태를 역할 다음으로(카드에서 배지)
    expect(within(table).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell')[0].textContent)).toEqual(['Detection', '대시보드', 'GPU', 'Gateway']);   // 이상 → 주의 → 확인 불가 → 정상(설계 5.10 '이상 먼저')
    expect(within(table).getAllByRole('row')).toHaveLength(1 + fixtureInstances.length);

    const gateway = rowOf(table, 'Gateway');
    expect(within(gateway).getByText('sample-gateway')).toBeInTheDocument();
    expect(within(gateway).getByText('i-00000000000000001')).toBeInTheDocument();
    expect(within(gateway).getByText('실행 중')).toHaveAttribute('data-status', 'ok');
    expect(gateway).toHaveTextContent('시스템 정상');
    expect(gateway).toHaveTextContent('인스턴스 정상');

    expect(rowOf(table, 'Detection')).toHaveTextContent('인스턴스 이상');

    const dashboard = rowOf(table, '대시보드');
    expect(within(dashboard).getByText('시작 중')).toHaveAttribute('data-status', 'slow');
    expect(dashboard).toHaveTextContent('시스템 초기화 중');
    expect(dashboard).toHaveTextContent('인스턴스 데이터 부족');
    expect(within(dashboard).getAllByText('–').length).toBeGreaterThan(0);   // 이름 없음

    // GPU는 필요할 때만 켜므로 꺼져 있어도 빨간 '끊김' 색을 쓰지 않는다
    const gpu = rowOf(table, 'GPU');
    expect(within(gpu).getByText('중지됨')).toHaveAttribute('data-status', 'unknown');
    expect(gpu).toHaveTextContent('해당 없음');
  });

  it('colors a stopped non-GPU instance as down', async () => {
    const items = [{ ...fixtureInstances[0], state: 'stopped', system_status: null, instance_status: null }];
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({ instances: { ok: true, error: null, status_checks: 'ok', items } }));
    mount();
    const table = await screen.findByRole('table', { name: 'EC2 인스턴스' });
    expect(within(table).getByText('중지됨')).toHaveAttribute('data-status', 'down');
  });

  it('shows the RDS identifier, engine and state on one line', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    const rds = within(await screen.findByRole('region', { name: 'RDS' })).getByLabelText('RDS 상태');
    expect(within(rds).getByText('사용 가능')).toHaveAttribute('data-status', 'ok');
    expect(rds).toHaveTextContent('sample-db');
    expect(rds).toHaveTextContent('postgres');
  });

  it('keeps the instance list and explains the missing status-check permission', async () => {
    const items = fixtureInstances.map(instance => ({ ...instance, system_status: null, instance_status: null }));
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({ instances: { ok: true, error: null, status_checks: 'permission_missing', items } }));
    mount();
    const region = await screen.findByRole('region', { name: 'EC2 인스턴스' });
    expect(within(region).getByText(PERMISSION_MISSING_TEXT)).toBeInTheDocument();
    const table = within(region).getByRole('table', { name: 'EC2 인스턴스' });
    expect(within(table).getAllByRole('row')).toHaveLength(1 + items.length);
    expect(within(rowOf(table, 'Gateway')).getByText('실행 중')).toBeInTheDocument();
    expect(within(rowOf(table, 'Gateway')).queryByText(/시스템 /)).toBeNull();
    // RDS 쪽은 정상이라 안내가 한 번만 나온다
    expect(screen.getAllByText(PERMISSION_MISSING_TEXT)).toHaveLength(1);
  });

  it('shows only the permission sentence when the instance list itself is not allowed', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({ instances: { ok: false, error: 'permission_missing', status_checks: undefined, items: [] } }));
    mount();
    const region = await screen.findByRole('region', { name: 'EC2 인스턴스' });
    expect(within(region).getByText(PERMISSION_MISSING_TEXT)).toBeInTheDocument();
    expect(within(region).queryByRole('table')).toBeNull();
    expect(within(region).queryByText('표시할 인스턴스가 없습니다.')).toBeNull();
  });

  it('explains a missing RDS permission', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({ rds_instance: { ok: false, error: 'permission_missing', identifier: 'sample-db', status: null, engine: null } }));
    mount();
    const region = await screen.findByRole('region', { name: 'RDS' });
    expect(within(region).getByText(PERMISSION_MISSING_TEXT)).toBeInTheDocument();
    expect(within(region).queryByLabelText('RDS 상태')).toBeNull();
    expect(screen.getAllByText(PERMISSION_MISSING_TEXT)).toHaveLength(1);
  });

  it('shows both permission sentences when neither AWS permission is granted', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({
      instances: { ok: false, error: 'permission_missing', items: [] },
      rds_instance: { ok: false, error: 'permission_missing' },
    }));
    mount();
    await screen.findByRole('region', { name: 'RDS' });
    expect(screen.getAllByText(PERMISSION_MISSING_TEXT)).toHaveLength(2);
  });

  it('falls back to plain wording when Detection could not reach AWS or RDS is not configured', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({
      instances: { ok: false, error: 'unavailable', items: [] },
      rds_instance: { ok: false, error: 'not_configured' },
    }));
    mount();
    expect(await screen.findByText('AWS에서 인스턴스 정보를 받지 못했습니다.')).toBeInTheDocument();
    expect(screen.getByText('RDS 식별자가 설정되지 않아 조회하지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByText(PERMISSION_MISSING_TEXT)).toBeNull();
    expect(screen.queryByRole('table', { name: 'EC2 인스턴스' })).toBeNull();
  });

  it('shows an unavailable RDS fallback from the dashboard backend', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture({ rds_instance: { ok: false, error: 'unavailable' } }));
    mount();
    expect(await screen.findByText('AWS에서 RDS 정보를 받지 못했습니다.')).toBeInTheDocument();
  });
});

describe('loading, refresh and failure', () => {
  it('shows a loading placeholder before the first answer', () => {
    vi.spyOn(systemStatusService, 'getStatus').mockReturnValue(new Promise(() => undefined));
    mount();
    expect(screen.getByRole('status', { name: '데이터를 불러오는 중' })).toBeInTheDocument();
  });

  it('registers a 15 second auto refresh that pauses in background tabs', async () => {
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    const { client } = mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    const options = client.getQueryCache().find({ queryKey: systemStatusKeys.status() })?.observers[0].options;
    expect(options?.refetchInterval).toBe(15_000);
    expect(options?.refetchIntervalInBackground).toBe(false);
  });

  it('asks the server again after 15 seconds', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const getStatus = vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    expect(getStatus).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(14_000); });
    expect(getStatus).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
    await waitFor(() => expect(getStatus).toHaveBeenCalledTimes(2));
  });

  it('refreshes immediately from the refresh button and shows the new state', async () => {
    const getStatus = vi.spyOn(systemStatusService, 'getStatus')
      .mockResolvedValueOnce(systemStatusFixture())
      .mockResolvedValue(systemStatusFixture({ components: [{ ...systemStatusFixture().components[3], status: 'ok', summary: '연결 2건' }] }));
    mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    expect(within(itemOf('Relay')).getByText('끊김')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await waitFor(() => expect(getStatus).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('연결 2건')).toBeInTheDocument();
    await waitFor(() => expect(within(itemOf('Relay')).getByText('정상')).toBeInTheDocument());
  });

  it('shows an error state with a retry button when the first request fails', async () => {
    const getStatus = vi.spyOn(systemStatusService, 'getStatus')
      .mockRejectedValueOnce(new ApiError('x', 'SERVER', 503))
      .mockResolvedValue(systemStatusFixture());
    mount();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('시스템 상태를 불러오지 못했습니다.');
    expect(screen.queryByRole('list', { name: '구성 요소 상태' })).toBeNull();
    fireEvent.click(within(alert).getByRole('button', { name: '다시 시도' }));
    expect(await screen.findByRole('list', { name: '구성 요소 상태' })).toBeInTheDocument();
    expect(getStatus).toHaveBeenCalledTimes(2);
  });

  it('keeps the last result with a notice when a later refresh fails', async () => {
    vi.spyOn(systemStatusService, 'getStatus')
      .mockResolvedValueOnce(systemStatusFixture())
      .mockRejectedValue(new ApiError('x', 'NETWORK'));
    mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    expect(await screen.findByText('갱신 실패 · 아래는 마지막으로 받은 상태입니다.')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: '구성 요소 상태' })).toBeInTheDocument();
  });

  it('drops the last result when the session expired or access was denied', async () => {
    vi.spyOn(systemStatusService, 'getStatus')
      .mockResolvedValueOnce(systemStatusFixture())
      .mockRejectedValue(new ApiError('x', 'FORBIDDEN', 403));
    mount();
    await screen.findByRole('list', { name: '구성 요소 상태' });
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('시스템 상태를 불러오지 못했습니다.');
    expect(screen.queryByRole('list', { name: '구성 요소 상태' })).toBeNull();
  });
});

describe('route and navigation', () => {
  // 재설계 2단계: 데스크톱 상단 띠(h1 경로)가 없어지고 본문 제목이 h1. 메뉴 묶음 '보고' → '운영 상태'(설계 2.1). 현재 항목은 aria-current로 확인
  it('serves /system inside the admin layout with a 운영 상태 menu entry', async () => {
    signIn();
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/system']}><AuthProvider><App /></AuthProvider></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('list', { name: '구성 요소 상태' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: '시스템 상태' })).toBeInTheDocument();   // 본문 제목
    expect(screen.getAllByRole('heading', { name: '시스템 상태' })).toHaveLength(1);   // 화면 이름이 두 번 나오지 않음
    expect(document.title).toBe('시스템 상태 · PromptGate');
    const menu = screen.getByRole('navigation', { name: '주요 메뉴' });
    const link = within(menu).getByRole('link', { name: '시스템 상태' });
    expect(link).toHaveAttribute('href', '/system');
    expect(link).toHaveAttribute('aria-current', 'page');
    const group = within(menu).getByRole('group', { name: '운영 상태' });
    expect(within(group).getByRole('link', { name: '시스템 상태' })).toBe(link);
    expect(within(group).getByRole('link', { name: '트래픽 및 성능' })).not.toHaveAttribute('aria-current');
    expect(within(menu).getByRole('link', { name: '리포트' })).not.toHaveAttribute('aria-current');
  });

  it('opens the page from the menu', async () => {
    signIn();
    vi.spyOn(systemStatusService, 'getStatus').mockResolvedValue(systemStatusFixture());
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/reports']}>
          <AuthProvider>
            <Routes>
              <Route element={<AppLayout />}>
                <Route path="/reports" element={<p>리포트 화면</p>} />
                <Route path="/system" element={<SystemStatusPage />} />
              </Route>
            </Routes>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText('리포트 화면')).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('navigation', { name: '주요 메뉴' })).getByRole('link', { name: '시스템 상태' }));
    expect(await screen.findByRole('list', { name: '구성 요소 상태' })).toBeInTheDocument();
    expect(screen.queryByText('리포트 화면')).toBeNull();
  });
});
