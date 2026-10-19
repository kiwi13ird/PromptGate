import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import {
  clientAliasService,
  gatewayAccessService,
  type AccessRule,
  type GatewayAccessResponse,
} from '@/src/services/gatewayAccessService';
import { trafficService } from '@/src/services/trafficService';
import type { TrafficClient, TrafficClients } from '@/src/types/traffic';
import { GatewayAccessPage } from './GatewayAccessPage';

// 접속 차단 탭(2026-10-12). 확장 ID·IP·시각은 모두 가짜. 시계는 Date만 고정한다(타이머는 실제).
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
const ID_C = 'chrome-6c2d8e1f-4b7a-4d9e-a3c6-1e8f5b2d7a04';
const RULE_A = '1a2b3c4d-0000-4000-8000-000000000001';
const RULE_OLD = '2b3c4d5e-0000-4000-8000-000000000002';
const RULE_GONE = '3c4d5e6f-0000-4000-8000-000000000003';

const rule = (over: Partial<AccessRule> = {}): AccessRule => ({
  id: RULE_A, client_id: ID_A, reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], memo: '조사 협조 요청',
  expires_at: iso(NOW + 2 * 3_600_000 + 5 * 60_000), created_by: 'local-admin', created_at: iso(NOW - 600_000),
  removed_by: null, removed_at: null, active: true, ...over,
});
const expiredRule = rule({ id: RULE_OLD, client_id: ID_B, reasons: ['LEAVE'], memo: null, expires_at: iso(NOW - 3_600_000), created_at: iso(NOW - 7_200_000), active: false });
const removedRule = rule({ id: RULE_GONE, client_id: ID_C, reasons: ['OTHER'], memo: '기타 사유', expires_at: null, created_at: iso(NOW - 86_400_000), removed_by: 'second-admin', removed_at: iso(NOW - 43_200_000), active: false });
const appliedOf = (over: Record<string, unknown> = {}) => ({
  version: 5, revision: REV, source: 'DASHBOARD' as const, applied_at: iso(NOW - 3_000), rejected: null, active_rules: 1,
  require_client_id: false, denied_5m: 3, received_at: iso(NOW - 4_000), ...over,
});
const docOf = (over: Partial<GatewayAccessResponse> = {}): GatewayAccessResponse => ({
  version: 5, revision: REV, require_client_id: false, rules: [rule(), expiredRule, removedRule],
  applied: appliedOf(), updated_at: iso(NOW - 600_000), updated_by: 'local-admin', ...over,
});
const client = (over: Partial<TrafficClient> = {}): TrafficClient => ({
  ip: '203.0.113.24', clientId: ID_A, connections: 2, inflight: 0, waiting: 0, requests5m: 7, targets: [],
  firstSeenAt: iso(NOW - 3_600_000), lastSeenAt: iso(NOW - 6_000), ...over,
});
const clients: TrafficClients = {
  receivedAt: iso(NOW - 4_000), stale: false, windowSeconds: 300,
  clients: [
    client(),
    client({ ip: '198.51.100.17', clientId: undefined, connections: 1 }),
    client({ ip: '198.51.100.18', clientId: undefined, connections: 0 }),
    client({ ip: '203.0.113.88', clientId: ID_B, connections: 1 }),
    client({ ip: '203.0.113.99', clientId: 'unknown-client', connections: 1 }),
  ],
};

let current: GatewayAccessResponse;
let aliases: Array<{ client_id: string; alias: string }>;
function stubServer() {
  current = docOf();
  aliases = [];
  vi.spyOn(gatewayAccessService, 'get').mockImplementation(async () => structuredClone(current));
  vi.spyOn(clientAliasService, 'list').mockImplementation(async () => ({ items: structuredClone(aliases) }));
  vi.spyOn(trafficService, 'getClients').mockResolvedValue(clients);
}
function mount() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/policies/access']}><GatewayAccessPage /></MemoryRouter></QueryClientProvider>);
  return queryClient;
}
// 화면 시계만 앞으로 돌린다
const setClock = (ms: number) => vi.setSystemTime(ms);
const rulesTable = async () => within(await screen.findByRole('table'));
const bodyRows = async () => (await rulesTable()).getAllByRole('row').slice(1);

beforeEach(() => {
  mode.canManagePolicies = true;
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  stubServer();
});
afterEach(() => vi.useRealTimers());

describe('access tab: list and status', () => {
  it('lists the active rules with target, reasons, memo, remaining time and who registered', async () => {
    mount();
    const rows = await bodyRows();
    expect(rows).toHaveLength(1);
    const cells = within(rows[0]).getAllByRole('cell');
    expect(cells[0]).toHaveTextContent(ID_A);
    expect(cells[0]).toHaveTextContent('차단 번호 1a2b3c4d');
    expect(cells[1]).toHaveTextContent('보안 조사 중');
    expect(cells[1]).toHaveTextContent('관리자 요청');
    expect(cells[2]).toHaveTextContent('조사 협조 요청');
    expect(cells[3]).toHaveTextContent('남은 시간 2시간 5분');
    expect(cells[4]).toHaveTextContent('local-admin');
    expect(cells[4]).toHaveTextContent('2026-10-12 13:50');
    expect(within(rows[0]).getByRole('button', { name: `${ID_A} 차단 해제` })).toBeInTheDocument();
    expect(screen.getByText('저장 v5 · 2026-10-12 13:50 · local-admin · 적용 중 차단 1개 · 확장 ID 없는 접속 차단 꺼짐')).toBeInTheDocument();
    expect(screen.getByText('Gateway 반영 v5 · 적용 중 차단 1개 · 최근 5분 막은 요청 3건(화면 로딩 포함) · 확인 13:59:56')).toBeInTheDocument();
    // 재설계 2단계: 정책 탭 줄 대신 왼쪽 메뉴(경로는 appLayout.test.tsx가 확인). 본문 제목 = 메뉴 이름
    expect(screen.getByRole('heading', { level: 1, name: '접속 차단' })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: '탐지 정책 보기' })).toBeNull();
  });

  it('shows expired and removed rules only with 만료·해제 포함', async () => {
    mount();
    await bodyRows();
    expect(screen.queryByText('만료됨 · 2026-10-12 13:00')).toBeNull();
    fireEvent.click(screen.getByLabelText('만료·해제 포함(최근 200개)'));
    const rows = await bodyRows();
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent(ID_A);   // 적용 중이 먼저
    expect(rows[1]).toHaveTextContent('만료됨 · 2026-10-12 13:00');
    expect(rows[2]).toHaveTextContent('해제됨 · 2026-10-12 02:00');
    expect(rows[2]).toHaveTextContent('해제 second-admin');
    expect(rows[2]).toHaveTextContent('기타 사유');
    expect(within(rows[1]).queryByRole('button', { name: /차단 해제/ })).toBeNull();
    expect(within(rows[2]).queryByRole('button', { name: /차단 해제/ })).toBeNull();
    fireEvent.click(screen.getByLabelText('만료·해제 포함(최근 200개)'));
    expect(await bodyRows()).toHaveLength(1);
  });

  it('follows the screen clock: a rule that expired since the last fetch is no longer listed as active', async () => {
    mount();
    expect(await bodyRows()).toHaveLength(1);
    setClock(NOW + 3 * 3_600_000);
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await waitFor(() => expect(screen.getByText('적용 중인 차단이 없습니다.')).toBeInTheDocument());
  });

  it('says there is no active rule and explains the filter when the list is empty', async () => {
    current = docOf({ rules: [expiredRule], version: 6 });
    mount();
    expect(await screen.findByText('적용 중인 차단이 없습니다.')).toBeInTheDocument();
    expect(screen.getByText('만료·해제된 차단은 ‘만료·해제 포함’을 켜면 보입니다.')).toBeInTheDocument();
  });

  it.each([
    ['반영됨', {}, 'Gateway 반영 v5 · 적용 중 차단 1개'],
    ['반영 대기', { applied: appliedOf({ version: 4, revision: REV2 }) }, 'Gateway 반영 대기 중 · Gateway 현재 v4'],
    ['거부됨', { applied: appliedOf({ version: 4, revision: REV2, rejected: 'rules.0.client_id' }) }, 'Gateway가 이 목록을 거부함 · 거부한 칸 차단 목록 1번째 확장 프로그램 ID'],
    ['보고 없음', { applied: null }, 'Gateway 보고 없음 · 접속 차단을 지원하지 않는 판이거나 첫 보고 전(최대 10초)'],
  ] as const)('shows the gateway state %s', async (_state, over, text) => {
    current = docOf(over as Partial<GatewayAccessResponse>);
    mount();
    expect(await screen.findByText(new RegExp(`^${text.replace(/[()]/g, '\\$&')}`))).toBeInTheDocument();
  });

  it('says 서버 반영 전 when the server does not know the api yet, without polling again', async () => {
    const get = vi.spyOn(gatewayAccessService, 'get').mockRejectedValue(new ApiError('x', 'NOT_FOUND', 404));
    mount();
    expect(await screen.findByText('서버 반영 전')).toBeInTheDocument();
    expect(screen.getByText('대시보드 서버가 아직 접속 차단을 지원하지 않습니다(서버 반영 전).')).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('shows a retry for other load failures and recovers', async () => {
    const get = vi.spyOn(gatewayAccessService, 'get').mockRejectedValue(new ApiError('x', 'SERVER', 503));
    mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('접속 차단 목록을 불러오지 못했습니다. 접속 차단 목록을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.');
    get.mockImplementation(async () => structuredClone(current));
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    expect(await bodyRows()).toHaveLength(1);
  });

  it('shows the alias first with the id below, using the alias list', async () => {
    aliases = [{ client_id: ID_A, alias: '홍길동 PC' }];
    mount();
    const rows = await bodyRows();
    const target = within(rows[0]).getAllByRole('cell')[0];
    await waitFor(() => expect(within(target).getByText('홍길동 PC')).toBeInTheDocument());
    expect(within(target).getByText(ID_A)).toBeInTheDocument();
    expect(within(rows[0]).getByRole('button', { name: '홍길동 PC 차단 해제' })).toBeInTheDocument();
  });
});

describe('access tab: block dialog', () => {
  const openAdd = async () => {
    mount();
    await bodyRows();
    fireEvent.click(screen.getByRole('button', { name: '차단 추가' }));   // 재설계 3f: 머리의 주 행동 [차단 추가](설계 5.8)
    return screen.findByRole('dialog');
  };
  const confirmButton = (dialog: HTMLElement) => within(dialog).getByRole('button', { name: '차단' });

  it('guides step by step: id, reasons, 기타 needs a memo', async () => {
    const dialog = await openAdd();
    expect(within(dialog).getByText('차단할 확장 프로그램 ID를 입력하세요.')).toBeInTheDocument();
    expect(confirmButton(dialog)).toBeDisabled();
    const input = within(dialog).getByLabelText('차단할 확장 프로그램 ID');
    fireEvent.change(input, { target: { value: 'unknown-client' } });
    expect(within(dialog).getByText('사용자를 구분할 수 없는 ID(unknown-·legacy-)는 차단할 수 없습니다.')).toBeInTheDocument();
    fireEvent.change(input, { target: { value: 'bad id' } });
    expect(within(dialog).getByText('확장 프로그램 ID 형식이 올바르지 않습니다.')).toBeInTheDocument();
    fireEvent.change(input, { target: { value: ID_A } });
    expect(within(dialog).getByText('이미 차단 중인 확장 프로그램 ID입니다.')).toBeInTheDocument();   // 이미 규칙이 걸려 있다
    fireEvent.change(input, { target: { value: ID_B } });
    expect(within(dialog).getByText('사유를 하나 이상 선택하세요.')).toBeInTheDocument();
    expect(confirmButton(dialog)).toBeDisabled();
    fireEvent.click(within(dialog).getByLabelText('기타'));
    expect(within(dialog).getByText('사유 ‘기타’를 고르면 메모를 입력해야 합니다.')).toBeInTheDocument();
    expect(within(dialog).getByText(/\(기타는 필수\)/)).toBeInTheDocument();
    expect(confirmButton(dialog)).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '   ' } });
    expect(confirmButton(dialog)).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '조사 중' } });
    expect(within(dialog).queryByText(/기타’를 고르면/)).toBeNull();
    expect(confirmButton(dialog)).toBeEnabled();
    fireEvent.click(within(dialog).getByLabelText('기타'));   // 기타를 빼면 메모는 선택이지만 사유가 0개
    expect(within(dialog).getByText('사유를 하나 이상 선택하세요.')).toBeInTheDocument();
    expect(confirmButton(dialog)).toBeDisabled();
  });

  it('offers the six preset reasons as multi-select chips and 1시간 · 1일 · 영구, defaulting to 1일', async () => {
    const dialog = await openAdd();
    const reasons = within(within(dialog).getByRole('group', { name: /사유/ })).getAllByRole('checkbox').map(box => (box.closest('label') as HTMLElement).textContent);
    expect(reasons).toEqual(['기밀 문서 반복 유출 시도', '개인정보 반복 입력', '보안 조사 중', '퇴사·휴직 예정', '관리자 요청', '기타']);
    const durations = within(within(dialog).getByRole('group', { name: '기간' })).getAllByRole('radio');
    expect(durations.map(radio => (radio.closest('label') as HTMLElement).textContent)).toEqual(['1시간', '1일', '영구']);
    expect(durations.map(radio => (radio as HTMLInputElement).checked)).toEqual([false, true, false]);
    fireEvent.click(within(dialog).getByLabelText('영구'));
    expect(within(dialog).getByLabelText('영구')).toBeChecked();
    expect(within(dialog).getByLabelText('1일')).not.toBeChecked();
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));
    fireEvent.click(within(dialog).getByLabelText('퇴사·휴직 예정'));
    expect(within(dialog).getByLabelText('보안 조사 중')).toBeChecked();
    expect(within(dialog).getByLabelText('퇴사·휴직 예정')).toBeChecked();
    expect(within(dialog).getByText('0 / 200자')).toBeInTheDocument();
  });

  it('suggests connected extension ids that are not blocked yet (no placeholder ids, no duplicates)', async () => {
    aliases = [{ client_id: ID_B, alias: '회의실 노트북' }];
    const dialog = await openAdd();
    await waitFor(() => expect(dialog.querySelectorAll('datalist option').length).toBeGreaterThan(0));
    await waitFor(() => expect([...dialog.querySelectorAll('datalist option')].map(option => option.textContent)).toEqual(['회의실 노트북 · 203.0.113.88']));
    expect([...dialog.querySelectorAll('datalist option')].map(option => option.getAttribute('value'))).toEqual([ID_B]);
  });

  it('sends the chosen id, reasons in fixed order, memo and duration with the current version, then shows 반영 대기 → 반영됨', async () => {
    const add = vi.spyOn(gatewayAccessService, 'addRule').mockImplementation(async (input, expected) => {
      current = docOf({ version: expected + 1, revision: REV2, applied: appliedOf({ version: expected, revision: REV }), rules: [...current.rules, rule({ id: '4d5e6f70-0000-4000-8000-000000000004', client_id: input.clientId })] });
      return { version: expected + 1 };
    });
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('차단할 확장 프로그램 ID'), { target: { value: `  ${ID_B}  ` } });
    fireEvent.click(within(dialog).getByLabelText('관리자 요청'));   // 클릭 순서와 전송 순서가 달라야 한다
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));
    fireEvent.click(within(dialog).getByLabelText('영구'));
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '  현장 확인  ' } });
    fireEvent.click(confirmButton(dialog));
    await waitFor(() => expect(add).toHaveBeenCalledTimes(1));
    expect(add).toHaveBeenCalledWith({ clientId: ID_B, reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], memo: '  현장 확인  ', duration: 'permanent' }, 5);
    expect(await within(dialog).findByText('차단 등록 완료 · v6')).toBeInTheDocument();
    expect(within(dialog).getByText('반영 대기')).toBeInTheDocument();
    expect(within(dialog).queryByText('반영됨')).toBeNull();
    // Gateway가 v6을 보고하면 반영됨(저장 직후에는 2초마다 확인한다)
    current = docOf({ ...current, applied: appliedOf({ version: 6, revision: REV2 }) });
    expect(await within(dialog).findByText('반영됨', {}, { timeout: 5000 })).toBeInTheDocument();
    expect(within(dialog).getByText('Gateway v6')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(await bodyRows()).toHaveLength(2);
  }, 15_000);

  it('keeps the dialog on a version conflict and says why: someone else changed the list, or the id is already blocked', async () => {
    const add = vi.spyOn(gatewayAccessService, 'addRule').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('차단할 확장 프로그램 ID'), { target: { value: ID_B } });
    fireEvent.click(within(dialog).getByLabelText('개인정보 반복 입력'));
    fireEvent.click(confirmButton(dialog));
    expect(await within(dialog).findByText('차단 실패 · 다른 관리자가 먼저 바꿨습니다. 최신 목록을 확인하세요.')).toBeInTheDocument();
    expect(add).toHaveBeenCalledTimes(1);
    expect(confirmButton(dialog)).toBeEnabled();   // 그대로 다시 시도할 수 있다
    // 그사이 다른 관리자가 같은 ID를 이미 차단함
    current = docOf({ version: 6, rules: [...current.rules, rule({ id: '5e6f7081-0000-4000-8000-000000000005', client_id: ID_B })] });
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));   // 입력을 바꾸면 이전 오류는 지워진다
    expect(within(dialog).queryByText(/다른 관리자가 먼저/)).toBeNull();
    fireEvent.click(confirmButton(dialog));
    expect(await within(dialog).findByText('차단 실패 · 이미 차단 중인 확장 프로그램 ID입니다.')).toBeInTheDocument();
    expect(add).toHaveBeenCalledTimes(2);
  });

  it('shows a plain failure message without server codes', async () => {
    vi.spyOn(gatewayAccessService, 'addRule').mockRejectedValue(new ApiError('x', 'VALIDATION', 422));
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('차단할 확장 프로그램 ID'), { target: { value: ID_B } });
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));
    fireEvent.click(confirmButton(dialog));
    expect(await within(dialog).findByText('차단 실패 · 저장할 수 없는 값입니다. 입력 값을 확인하세요.')).toBeInTheDocument();
  });
});

describe('access tab: unblock', () => {
  it('asks first, sends the rule id with the current version, and shows 반영 대기', async () => {
    const remove = vi.spyOn(gatewayAccessService, 'removeRule').mockImplementation(async (_id, expected) => {
      current = docOf({ version: expected + 1, revision: REV2, rules: [rule({ removed_by: 'local-admin', removed_at: iso(NOW), active: false }), expiredRule, removedRule] });
      return { version: expected + 1 };
    });
    mount();
    const rows = await bodyRows();
    fireEvent.click(within(rows[0]).getByRole('button', { name: `${ID_A} 차단 해제` }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('LLM 사용 차단 해제')).toBeInTheDocument();
    expect(within(dialog).getByText(ID_A)).toBeInTheDocument();
    expect(within(dialog).getByText('보안 조사 중 · 관리자 요청')).toBeInTheDocument();
    expect(remove).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: '해제' }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith(RULE_A, 5));
    expect(await within(dialog).findByText('차단 해제 완료 · v6')).toBeInTheDocument();
    expect(within(dialog).getByText('반영 대기')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.getByText('적용 중인 차단이 없습니다.')).toBeInTheDocument());
  });

  it('does nothing when cancelled', async () => {
    const remove = vi.spyOn(gatewayAccessService, 'removeRule');
    mount();
    fireEvent.click(within((await bodyRows())[0]).getByRole('button', { name: `${ID_A} 차단 해제` }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '취소' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(remove).not.toHaveBeenCalled();
  });

  it('refreshes the list and says so when someone else changed it first', async () => {
    vi.spyOn(gatewayAccessService, 'removeRule').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    mount();
    fireEvent.click(within((await bodyRows())[0]).getByRole('button', { name: `${ID_A} 차단 해제` }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: '해제' }));
    expect(await within(dialog).findByText('해제 실패 · 다른 관리자가 먼저 바꿨습니다. 최신 목록을 확인하세요.')).toBeInTheDocument();
  });
});

describe('access tab: 확장 ID 없는 접속 차단', () => {
  // 대화상자가 열려 있으면 바깥은 접근성 트리에서 숨겨지므로 hidden까지 찾는다
  const toggle = () => screen.getByRole('switch', { name: '확장 ID 없는 접속 차단', hidden: true });

  it('is off by default and says what it does', async () => {
    mount();
    await bodyRows();
    expect(toggle()).not.toBeChecked();
    expect(screen.getByText('꺼짐')).toBeInTheDocument();
    expect(screen.getByText(/llm-gateway\.local/)).toBeInTheDocument();
  });

  it('asks before turning on and shows how many connected IPs have no extension id', async () => {
    const setMode = vi.spyOn(gatewayAccessService, 'setMode').mockImplementation(async (on, expected) => {
      current = docOf({ ...current, version: expected + 1, revision: REV2, require_client_id: on });
      return { version: expected + 1 };
    });
    mount();
    await bodyRows();
    await waitFor(() => expect(trafficService.getClients).toHaveBeenCalled());
    fireEvent.click(toggle());
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('확장 ID 없는 접속 차단 켜기')).toBeInTheDocument();
    // 연결 중 4개(확장 ID 있음 2 · 없음 1 · 자리표시 ID 1) 중 ID 없는 접속은 1개. 연결이 끊긴 ID 없는 IP는 세지 않는다
    await waitFor(() => expect(within(dialog).getByText('지금 연결 중인 IP 4개 중 1개가 확장 프로그램 ID 없이 접속 중입니다. 켜면 이 접속이 막힙니다.')).toBeInTheDocument());
    expect(setMode).not.toHaveBeenCalled();
    expect(toggle()).not.toBeChecked();   // 확인 전에는 바뀌지 않는다
    fireEvent.click(within(dialog).getByRole('button', { name: '켜기' }));
    await waitFor(() => expect(setMode).toHaveBeenCalledWith(true, 5));
    expect(await within(dialog).findByText('설정 저장 완료 · v6')).toBeInTheDocument();
    expect(within(dialog).getByText('반영 대기')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(toggle()).toBeChecked());
    expect(screen.getByText('켜짐')).toBeInTheDocument();
  });

  it('asks before turning off too, without the count', async () => {
    current = docOf({ require_client_id: true });
    const setMode = vi.spyOn(gatewayAccessService, 'setMode').mockResolvedValue({ version: 6 });
    mount();
    await bodyRows();
    expect(toggle()).toBeChecked();
    fireEvent.click(toggle());
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('확장 ID 없는 접속 차단 끄기')).toBeInTheDocument();
    expect(within(dialog).getByText('끄면 확장 프로그램 ID가 없는 접속도 다시 허용됩니다.')).toBeInTheDocument();
    expect(within(dialog).queryByText(/지금 연결 중인 IP/)).toBeNull();
    fireEvent.click(within(dialog).getByRole('button', { name: '끄기' }));
    await waitFor(() => expect(setMode).toHaveBeenCalledWith(false, 5));
  });

  it('keeps going when the connected IP list cannot be read, and says so', async () => {
    vi.spyOn(trafficService, 'getClients').mockRejectedValue(new ApiError('x', 'NOT_FOUND', 404));
    mount();
    await bodyRows();
    fireEvent.click(toggle());
    const dialog = await screen.findByRole('dialog');
    await waitFor(() => expect(within(dialog).getByText('연결 중인 IP 수를 불러오지 못했습니다.')).toBeInTheDocument());
    expect(within(dialog).getByRole('button', { name: '켜기' })).toBeEnabled();
  });

  it('warns that the count may be old when the gateway metrics are stale', async () => {
    vi.spyOn(trafficService, 'getClients').mockResolvedValue({ ...clients, stale: true });
    mount();
    await bodyRows();
    await waitFor(() => expect(trafficService.getClients).toHaveBeenCalled());
    fireEvent.click(toggle());
    const dialog = await screen.findByRole('dialog');
    await waitFor(() => expect(within(dialog).getByText(/Gateway 지표가 오래되어/)).toBeInTheDocument());
  });

  it('shows the conflict and refreshes when someone else saved first', async () => {
    vi.spyOn(gatewayAccessService, 'setMode').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    mount();
    await bodyRows();
    fireEvent.click(toggle());
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: '켜기' }));
    expect(await within(dialog).findByText('저장 실패 · 다른 관리자가 먼저 바꿨습니다. 최신 목록을 확인하세요.')).toBeInTheDocument();
  });
});

describe('access tab: aliases', () => {
  it('edits an alias with the pencil, saves it trimmed, and shows it right away', async () => {
    const set = vi.spyOn(clientAliasService, 'set').mockImplementation(async (clientId, alias) => { aliases = [{ client_id: clientId, alias: alias.trim() }]; });
    mount();
    const rows = await bodyRows();
    fireEvent.click(within(rows[0]).getByRole('button', { name: `${ID_A} 별칭 수정` }));
    const dialog = await screen.findByRole('dialog');
    const input = within(dialog).getByLabelText('별칭');
    expect(input).toHaveValue('');
    expect(within(dialog).getByRole('button', { name: '저장' })).toBeDisabled();   // 바뀐 값이 없다
    fireEvent.change(input, { target: { value: '  홍길동 PC ' } });
    expect(within(dialog).getByText('9 / 40자')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(set).toHaveBeenCalledWith(ID_A, '  홍길동 PC '));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(await screen.findByText('홍길동 PC')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '홍길동 PC 별칭 수정' })).toBeInTheDocument();
  });

  it('clears an alias by saving an empty value', async () => {
    aliases = [{ client_id: ID_A, alias: '홍길동 PC' }];
    const set = vi.spyOn(clientAliasService, 'set').mockImplementation(async () => { aliases = []; });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: '홍길동 PC 별칭 수정' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText('별칭')).toHaveValue('홍길동 PC');
    fireEvent.change(within(dialog).getByLabelText('별칭'), { target: { value: '' } });
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(set).toHaveBeenCalledWith(ID_A, ''));
    await waitFor(() => expect(screen.queryByText('홍길동 PC')).toBeNull());
    expect(screen.getByRole('button', { name: `${ID_A} 별칭 수정` })).toBeInTheDocument();
  });

  it('limits the alias to 40 characters', async () => {
    mount();
    const rows = await bodyRows();
    fireEvent.click(within(rows[0]).getByRole('button', { name: `${ID_A} 별칭 수정` }));
    const input = within(await screen.findByRole('dialog')).getByLabelText('별칭');
    expect(input).toHaveAttribute('maxlength', '40');
  });
});

describe('access tab: read-only', () => {
  it('hides every change control without policy management rights', async () => {
    mode.canManagePolicies = false;
    mount();
    const rows = await bodyRows();
    expect(screen.getByText('읽기 전용')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '차단 추가' })).toBeNull();   // 3f: 머리의 [차단 추가]
    expect(within(rows[0]).queryByRole('button')).toBeNull();
    expect(screen.getByRole('switch', { name: '확장 ID 없는 접속 차단' })).toBeDisabled();
    expect(rows[0]).toHaveTextContent(ID_A);
  });
});

