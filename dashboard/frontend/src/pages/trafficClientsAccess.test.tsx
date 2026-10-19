// 연결 중인 IP 표의 접속 차단 관리(2026-10-12): 별칭, 차단·해제 버튼, 차단 중 배지, 반영 대기 → 반영됨. 확장 ID·IP는 모두 가짜.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { TrafficClientsManager } from '@/src/components/TrafficClientsManager';
import { TrafficClientsPanel, type TrafficClientsManage } from '@/src/components/TrafficClientsPanel';
import { clientAliasService, gatewayAccessService, type AccessRule, type GatewayAccessResponse } from '@/src/services/gatewayAccessService';
import { trafficService } from '@/src/services/trafficService';
import type { TrafficClient, TrafficClients, TrafficSnapshot } from '@/src/types/traffic';
import { TrafficPerformancePage } from './TrafficPerformancePage';

vi.mock('recharts', () => ({ LineChart: () => null, Line: () => null, CartesianGrid: () => null, Legend: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));
const mode = vi.hoisted(() => ({ canManagePolicies: true }));
vi.mock('@runtime/ui-mode', async () => {
  const real = await import('@/src/config/uiMode.real');
  return { uiMode: new Proxy(real.uiMode, { get: (target, key) => (key === 'canManagePolicies' ? mode.canManagePolicies : Reflect.get(target, key)) }) };
});
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const NOW = Date.parse('2026-10-12T05:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const REV2 = '0b7d3c55-1e2f-4a6b-8c9d-aa11bb22cc33';
const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';
const ID_B = 'chrome-9b1e4d7c-2a6f-4c3b-8e05-7f2d9a6c4b18';
const RULE_B = '1a2b3c4d-0000-4000-8000-0000000000b1';

const client = (over: Partial<TrafficClient> = {}): TrafficClient => ({
  ip: '203.0.113.24', clientId: ID_A, connections: 2, inflight: 0, waiting: 0, requests5m: 7, targets: [{ llm: 'ChatGPT', count: 5 }],
  firstSeenAt: iso(NOW - 3_600_000), lastSeenAt: iso(NOW - 30_000), ...over,
});
const clients: TrafficClients = {
  receivedAt: iso(NOW - 5_000), stale: false, windowSeconds: 300,
  clients: [
    client(),
    client({ ip: '203.0.113.88', clientId: ID_B, connections: 1 }),
    client({ ip: '198.51.100.17', clientId: undefined, connections: 0, requests5m: 0, targets: [] }),
  ],
};
const ruleB: AccessRule = {
  id: RULE_B, client_id: ID_B, reasons: ['LEAVE'], memo: null, expires_at: iso(NOW + 2 * 3_600_000 + 5 * 60_000),
  created_by: 'local-admin', created_at: iso(NOW - 60_000), removed_by: null, removed_at: null, active: true,
};
const appliedOf = (over: Record<string, unknown> = {}) => ({
  version: 5, revision: REV, source: 'DASHBOARD' as const, applied_at: iso(NOW - 3_000), rejected: null, active_rules: 1,
  require_client_id: false, denied_5m: 0, received_at: iso(NOW - 4_000), ...over,
});
const docOf = (over: Partial<GatewayAccessResponse> = {}): GatewayAccessResponse => ({
  version: 5, revision: REV, require_client_id: false, rules: [ruleB], applied: appliedOf(), ...over,
});

const cellsOf = (row: HTMLElement) => within(row).getAllByRole('cell');
const rowOf = (ip: string) => screen.getByText(ip).closest('tr') as HTMLElement;

beforeEach(() => {
  mode.canManagePolicies = true;
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe('connected IP panel with access management', () => {
  const manage = (over: Partial<TrafficClientsManage> = {}): TrafficClientsManage => ({
    canManage: true, aliases: new Map([[ID_A, '홍길동 PC']]),
    activeRuleOf: id => (id === ID_B ? ruleB : undefined),
    onBlock: vi.fn(), onUnblock: vi.fn(), onEditAlias: vi.fn(), ...over,
  });
  const renderPanel = (props: Partial<Parameters<typeof TrafficClientsPanel>[0]> = {}) =>
    render(<div className="traffic-console"><TrafficClientsPanel data={clients} loading={false} onRetry={() => undefined} now={NOW} {...props} /></div>);

  it('adds a 관리 column only when management is available', () => {
    const plain = renderPanel();
    expect(within(screen.getAllByRole('row')[0]).getAllByRole('columnheader').map(cell => cell.textContent)).not.toContain('관리');
    expect(screen.queryByRole('button', { name: /차단|별칭/ })).toBeNull();
    plain.unmount();
    renderPanel({ manage: manage() });
    expect(within(screen.getAllByRole('row')[0]).getAllByRole('columnheader').map(cell => cell.textContent).at(-1)).toBe('관리');
  });

  // 2026-10-13 피드백: 카드 이름이 '연결 중인 IP'라 IP가 첫 줄(주 표시), 둘째 줄이 별칭 · 확장 ID(전에는 별칭·ID 아래 IP)
  it('shows the IP first and the alias with the id on the second line, with a pencil to edit the alias', () => {
    const m = manage();
    renderPanel({ manage: m });
    const idCell = cellsOf(rowOf('203.0.113.24'))[0];
    expect(idCell.textContent).toBe(`203.0.113.24홍길동 PC${ID_A}`);   // IP → 별칭 → ID
    const [main, sub] = Array.from(idCell.querySelector('.pg-tr-ip-who')!.children) as HTMLElement[];
    expect(main.textContent).toBe('203.0.113.24');
    expect(sub.textContent).toBe(`홍길동 PC${ID_A}`);
    expect(within(idCell).getByText(ID_A)).toHaveAttribute('title', ID_A);
    fireEvent.click(within(idCell).getByRole('button', { name: '홍길동 PC 별칭 수정' }));
    expect(m.onEditAlias).toHaveBeenCalledWith(ID_A);
    // 별칭이 없으면 IP 아래 ID만, 그래도 연필은 있다
    const noAlias = cellsOf(rowOf('203.0.113.88'))[0];
    expect(noAlias.textContent).toBe(`203.0.113.88${ID_B}`);
    expect(within(noAlias).getByRole('button', { name: `${ID_B} 별칭 수정` })).toBeInTheDocument();
    // 확장 ID 없는 접속은 둘째 줄에 그렇게 쓰고 연필이 없다
    const noId = cellsOf(rowOf('198.51.100.17'))[0];
    expect(noId.textContent).toBe('198.51.100.17확장 ID 없음');
    expect(within(noId).queryByRole('button')).toBeNull();
  });

  it('keeps several extensions behind one IP next to each other and says how many', () => {
    const ID_C = 'chrome-0c1d2e3f-4a5b-4c6d-8e7f-a0b1c2d3e4f5';
    renderPanel({ manage: manage(), data: { ...clients, clients: [client(), client({ ip: '203.0.113.88', clientId: ID_B }), client({ clientId: ID_C, connections: 0 })] } });
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows.map(row => cellsOf(row)[0].querySelector('.pg-tr-ip-addr')?.textContent)).toEqual(['203.0.113.24', '203.0.113.24', '203.0.113.88']);
    expect(within(rows[0]).getByText('이 IP 확장 2개')).toBeInTheDocument();
    expect(within(rows[1]).getByText(ID_C)).toBeInTheDocument();
    expect(within(rows[1]).getByText('이 IP 확장 2개')).toBeInTheDocument();
    expect(within(rows[2]).queryByText(/이 IP 확장/)).toBeNull();
  });

  it('offers 차단 for an unblocked id, and the 차단 중 badge with remaining time and 해제 for a blocked one', () => {
    const m = manage();
    renderPanel({ manage: m });
    const free = cellsOf(rowOf('203.0.113.24'));
    fireEvent.click(within(free[6]).getByRole('button', { name: '홍길동 PC 차단' }));   // 관리 = 7번째 칸(3c)
    expect(m.onBlock).toHaveBeenCalledWith(ID_A);
    // 차단 중·남은 시간은 상태 칸의 차단 계열 배지(설계 4.6), 관리 칸에는 해제만
    expect(within(cellsOf(rowOf('203.0.113.88'))[1]).getByText('차단 중 · 남은 시간 2시간 5분')).toHaveAttribute('data-tone', 'block');
    const blocked = cellsOf(rowOf('203.0.113.88'))[6];
    expect(within(blocked).queryByRole('button', { name: /^.* 차단$/ })).toBeNull();
    fireEvent.click(within(blocked).getByRole('button', { name: `${ID_B} 차단 해제` }));
    expect(m.onUnblock).toHaveBeenCalledWith(ruleB);
  });

  it('shows 영구 for a permanent rule', () => {
    renderPanel({ manage: manage({ activeRuleOf: id => (id === ID_B ? { ...ruleB, expires_at: null } : undefined) }) });
    expect(within(cellsOf(rowOf('203.0.113.88'))[1]).getByText('차단 중 · 영구')).toBeInTheDocument();
  });

  it('leaves 관리 empty for a row without an extension id', () => {
    renderPanel({ manage: manage() });
    const noId = cellsOf(rowOf('198.51.100.17'));
    expect(noId[0].textContent).toBe('198.51.100.17확장 ID 없음');
    expect(noId[6].textContent).toBe('ID 없음');
    expect(within(noId[6]).queryByRole('button')).toBeNull();
  });

  it('does not offer 차단 for placeholder ids', () => {
    renderPanel({ data: { ...clients, clients: [client({ clientId: 'unknown-client' }), client({ ip: '203.0.113.50', clientId: 'legacy-gateway' })] }, manage: manage() });
    for (const row of screen.getAllByRole('row').slice(1)) expect(within(row).queryByRole('button')).toBeNull();
  });

  it('shows aliases and the badge but no buttons when the admin cannot manage', () => {
    renderPanel({ manage: manage({ canManage: false }) });
    expect(screen.getByText('홍길동 PC')).toBeInTheDocument();
    expect(screen.getByText('차단 중 · 남은 시간 2시간 5분')).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('connected IP manager (block, unblock, alias against the access api)', () => {
  let current: GatewayAccessResponse;
  let aliases: Array<{ client_id: string; alias: string }>;
  beforeEach(() => {
    current = docOf();
    aliases = [{ client_id: ID_A, alias: '홍길동 PC' }];
    vi.spyOn(gatewayAccessService, 'get').mockImplementation(async () => structuredClone(current));
    vi.spyOn(clientAliasService, 'list').mockImplementation(async () => ({ items: structuredClone(aliases) }));
  });
  const mount = () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    return render(<QueryClientProvider client={queryClient}><MemoryRouter><div className="traffic-console"><TrafficClientsManager data={clients} loading={false} onRetry={() => undefined} now={NOW} /></div></MemoryRouter></QueryClientProvider>);
  };

  it('blocks a user from the row: preset target, required reason, then 반영 대기 → 반영됨 and a 차단 중 badge', async () => {
    const add = vi.spyOn(gatewayAccessService, 'addRule').mockImplementation(async (input, expected) => {
      current = docOf({ version: expected + 1, revision: REV2, applied: appliedOf({ version: expected }), rules: [ruleB, { ...ruleB, id: '2b3c4d5e-0000-4000-8000-0000000000a1', client_id: input.clientId, reasons: input.reasons }] });
      return { version: expected + 1 };
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: '홍길동 PC 차단' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('홍길동 PC')).toBeInTheDocument();   // 대상: 별칭 + ID
    expect(within(dialog).getByText(ID_A)).toBeInTheDocument();
    expect(within(dialog).queryByLabelText('차단할 확장 프로그램 ID')).toBeNull();   // 대상은 바꿀 수 없다
    const confirm = within(dialog).getByRole('button', { name: '차단' });
    expect(confirm).toBeDisabled();
    expect(within(dialog).getByText('사유를 하나 이상 선택하세요.')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByLabelText('개인정보 반복 입력'));
    expect(confirm).toBeEnabled();
    fireEvent.click(within(dialog).getByLabelText('1시간'));
    fireEvent.click(confirm);
    await waitFor(() => expect(add).toHaveBeenCalledWith({ clientId: ID_A, reasons: ['PII_REPEAT'], memo: '', duration: '1h' }, 5));
    expect(await within(dialog).findByText('차단 등록 완료 · v6')).toBeInTheDocument();
    expect(within(dialog).getByText('반영 대기')).toBeInTheDocument();
    current = docOf({ ...current, applied: appliedOf({ version: 6, revision: REV2 }) });   // Gateway가 v6을 보고
    expect(await within(dialog).findByText('반영됨', {}, { timeout: 5000 })).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(await within(rowOf('203.0.113.24')).findByText(/^차단 중 · /)).toBeInTheDocument();
  }, 15_000);

  it('unblocks from the row after a confirmation', async () => {
    const remove = vi.spyOn(gatewayAccessService, 'removeRule').mockImplementation(async (_id, expected) => {
      current = docOf({ version: expected + 1, revision: REV2, rules: [{ ...ruleB, removed_by: 'local-admin', removed_at: iso(NOW), active: false }] });
      return { version: expected + 1 };
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: `${ID_B} 차단 해제` }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('퇴사·휴직 예정')).toBeInTheDocument();
    expect(remove).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: '해제' }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith(RULE_B, 5));
    expect(await within(dialog).findByText('차단 해제 완료 · v6')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    expect(await within(rowOf('203.0.113.88')).findByRole('button', { name: `${ID_B} 차단` })).toBeInTheDocument();   // 다시 차단할 수 있는 상태
    expect(screen.queryByText(/^차단 중 · /)).toBeNull();
  });

  it('edits the alias with the pencil and the new alias shows in the row', async () => {
    const set = vi.spyOn(clientAliasService, 'set').mockImplementation(async (clientId, alias) => {
      aliases = [...aliases.filter(item => item.client_id !== clientId), { client_id: clientId, alias: alias.trim() }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: `${ID_B} 별칭 수정` }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('별칭'), { target: { value: '회의실 노트북' } });
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(set).toHaveBeenCalledWith(ID_B, '회의실 노트북'));
    expect(await within(rowOf('203.0.113.88')).findByText('회의실 노트북')).toBeInTheDocument();
  });

  it('keeps the old table (no 관리 column, no aliases) while the server does not know the access api', async () => {
    vi.spyOn(gatewayAccessService, 'get').mockRejectedValue(new ApiError('x', 'NOT_FOUND', 404));
    vi.spyOn(clientAliasService, 'list').mockRejectedValue(new ApiError('x', 'NOT_FOUND', 404));
    mount();
    await screen.findByText('203.0.113.24');
    await waitFor(() => expect(gatewayAccessService.get).toHaveBeenCalled());
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(screen.getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['대상', '상태', '최근 5분 검사 요청', '열린 연결', '대상 LLM', '마지막 활동']);   // 3c 7열(관리 칸 없음). 10/15 '검사 요청'
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.queryByText('홍길동 PC')).toBeNull();
  });

  it('hides block, unblock and pencil buttons without policy management rights', async () => {
    mode.canManagePolicies = false;
    mount();
    expect(await screen.findByText('차단 중 · 남은 시간 2시간 5분')).toBeInTheDocument();
    await screen.findByText('홍길동 PC');
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('traffic page', () => {
  const snapshot: TrafficSnapshot = {
    period: '24H',
    summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY', gatewayTotalRequests: 10, gatewayCompletedRequests: 10,
      gatewayErrorRequests: 0, gatewayWindowSeconds: 60, activeClients: 1, concurrentRequests: 0, requestsPerSec: 0.1, latencySampleCount: 10, averageLatencyMs: 30, p95LatencyMs: 60 },
    timeSeries: [],
  };

  it('shows the 관리 column and aliases in the connected IP section once the server answers', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    vi.spyOn(trafficService, 'getClients').mockResolvedValue(clients);
    vi.spyOn(gatewayAccessService, 'get').mockResolvedValue(docOf());
    vi.spyOn(clientAliasService, 'list').mockResolvedValue({ items: [{ client_id: ID_A, alias: '홍길동 PC' }] });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    const section = (await screen.findByRole('heading', { name: '연결 중인 IP' })).closest('section') as HTMLElement;
    expect(await within(section).findByRole('columnheader', { name: '관리' })).toBeInTheDocument();
    expect(await within(section).findByText('홍길동 PC')).toBeInTheDocument();
    expect(within(section).getByText('차단 중 · 남은 시간 2시간 5분')).toBeInTheDocument();
  });
});
