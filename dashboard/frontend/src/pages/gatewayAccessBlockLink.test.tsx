import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { gatewayApi } from '@/src/api';
import {
  clientAliasService,
  gatewayAccessService,
  type AccessRule,
  type GatewayAccessResponse,
} from '@/src/services/gatewayAccessService';
import { trafficService } from '@/src/services/trafficService';
import type { TrafficClients } from '@/src/types/traffic';
import { GatewayAccessPage } from './GatewayAccessPage';

// 보고서의 '이 사용자 차단' 링크(2026-10-12 설계 v2 4.6-d·4.11): /policies/access?block=<확장 ID>&reason=<사유>
// 대화상자를 대상·사유를 채워 열기만 하고, 저장은 관리자가 ‘차단’을 누를 때만 한다. 확장 ID·시각은 모두 가짜.
const mode = vi.hoisted(() => ({ canManagePolicies: true }));
vi.mock('@runtime/ui-mode', async () => {
  const real = await import('@/src/config/uiMode.real');
  return { uiMode: new Proxy(real.uiMode, { get: (target, key) => (key === 'canManagePolicies' ? mode.canManagePolicies : Reflect.get(target, key)) }) };
});
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const NOW = Date.parse('2026-10-12T05:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';   // 이미 차단 중
const ID_B = 'chrome-9b1e4d7c-2a6f-4c3b-8e05-7f2d9a6c4b18';   // 차단 대상
const rule = (over: Partial<AccessRule> = {}): AccessRule => ({
  id: '1a2b3c4d-0000-4000-8000-000000000001', client_id: ID_A, reasons: ['INVESTIGATION'], memo: null,
  expires_at: iso(NOW + 2 * 3_600_000), created_by: 'local-admin', created_at: iso(NOW - 600_000), removed_by: null, removed_at: null, active: true, ...over,
});
const docOf = (rules: AccessRule[]): GatewayAccessResponse => ({
  version: 5, revision: REV, require_client_id: false, rules,
  applied: { version: 5, revision: REV, source: 'DASHBOARD', applied_at: iso(NOW - 3_000), rejected: null, active_rules: rules.length, require_client_id: false, denied_5m: 0, received_at: iso(NOW - 4_000) },
  updated_at: iso(NOW - 600_000), updated_by: 'local-admin',
});
const noClients: TrafficClients = { receivedAt: iso(NOW - 4_000), stale: false, windowSeconds: 300, clients: [] };

let current: GatewayAccessResponse;
function Where() {
  const location = useLocation();
  return <div data-testid="where">{location.pathname}{location.search}</div>;
}
function mount(search: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/policies/access${search}`]}><GatewayAccessPage /><Where /></MemoryRouter>
    </QueryClientProvider>,
  );
}
const address = () => screen.getByTestId('where').textContent;
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
// 주소 정리는 라우터가 낮은 우선순위로 반영하므로 대화상자보다 조금 늦을 수 있다
const addressIs = (expected: string) => waitFor(() => expect(address()).toBe(expected));
const chip = (dialog: HTMLElement, label: string) => within(dialog).getByLabelText(label) as HTMLInputElement;

beforeEach(() => {
  mode.canManagePolicies = true;
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  current = docOf([rule()]);
  vi.spyOn(gatewayAccessService, 'get').mockImplementation(async () => structuredClone(current));
  vi.spyOn(clientAliasService, 'list').mockResolvedValue({ items: [] });
  vi.spyOn(trafficService, 'getClients').mockResolvedValue(noClients);
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('access tab opened from a report link', () => {
  it('opens the block dialog for the user with the reason already chosen, and clears the link from the address', async () => {
    const add = vi.spyOn(gatewayApi, 'addAccessRule');
    mount(`?block=${ID_B}&reason=LEAK_DOC_REPEAT`);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('LLM 사용 차단')).toBeInTheDocument();
    expect(within(dialog).getByText(ID_B)).toBeInTheDocument();
    expect(chip(dialog, '기밀 문서 반복 유출 시도')).toBeChecked();
    for (const other of ['개인정보 반복 입력', '보안 조사 중', '퇴사·휴직 예정', '관리자 요청', '기타']) expect(chip(dialog, other)).not.toBeChecked();
    expect(within(dialog).getByLabelText('1일')).toBeChecked();   // 기간은 기본 1일
    expect(within(dialog).getByRole('region', { name: '사용자에게 보이는 내용' })).toHaveTextContent('사유: 기밀 문서 반복 유출 시도');
    expect(within(dialog).getByRole('button', { name: '차단' })).toBeEnabled();
    await addressIs('/policies/access');
    expect(add).not.toHaveBeenCalled();   // 열기만 한다 - 저장은 관리자가 누를 때만
  });

  it('saves only when the admin presses 차단, with the chosen target and reason', async () => {
    const add = vi.spyOn(gatewayApi, 'addAccessRule').mockImplementation(async () => {
      current = docOf([rule(), rule({ id: '1a2b3c4d-0000-4000-8000-000000000002', client_id: ID_B, reasons: ['PII_REPEAT'] })]);
      return { version: 6 };
    });
    mount(`?block=${ID_B}&reason=PII_REPEAT`);
    const dialog = await screen.findByRole('dialog');
    expect(add).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: '차단' }));
    await waitFor(() => expect(add).toHaveBeenCalledTimes(1));
    expect(add.mock.calls[0][0]).toEqual({ client_id: ID_B, reasons: ['PII_REPEAT'], duration: '1d', expected_version: 5 });
    // 저장으로 규칙이 생겨 ‘이미 차단 중’이 돼도 완료 화면은 남아 있어야 한다
    expect(await within(dialog).findByText('차단 등록 완료 · v6')).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBe(dialog);
  });

  it('lets the admin change the preselected reason before saving', async () => {
    const add = vi.spyOn(gatewayApi, 'addAccessRule').mockResolvedValue({ version: 6 });
    mount(`?block=${ID_B}&reason=LEAK_DOC_REPEAT`);
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(chip(dialog, '기밀 문서 반복 유출 시도'));
    fireEvent.click(chip(dialog, '보안 조사 중'));
    fireEvent.click(within(dialog).getByRole('button', { name: '차단' }));
    await waitFor(() => expect(add).toHaveBeenCalledTimes(1));
    expect(add.mock.calls[0][0]).toMatchObject({ client_id: ID_B, reasons: ['INVESTIGATION'] });
  });

  it('opens with nothing chosen when the link has no reason, and the 차단 button stays disabled until one is chosen', async () => {
    mount(`?block=${ID_B}`);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(ID_B)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: '차단' })).toBeDisabled();
    expect(within(dialog).getByText('사유를 하나 이상 선택하세요.')).toBeInTheDocument();
  });

  it('chooses several reasons from a comma list and ignores unknown codes', async () => {
    mount(`?block=${ID_B}&reason=${encodeURIComponent('PII_REPEAT,LEAK_DOC_REPEAT,DROP_TABLE,leak_doc_repeat')}`);
    const dialog = await screen.findByRole('dialog');
    expect(chip(dialog, '기밀 문서 반복 유출 시도')).toBeChecked();
    expect(chip(dialog, '개인정보 반복 입력')).toBeChecked();
    expect(within(dialog).getByRole('region', { name: '사용자에게 보이는 내용' })).toHaveTextContent('사유: 기밀 문서 반복 유출 시도 · 개인정보 반복 입력');
    for (const other of ['보안 조사 중', '퇴사·휴직 예정', '관리자 요청', '기타']) expect(chip(dialog, other)).not.toBeChecked();
  });

  it('waits for the rule list before opening, so it can tell an already blocked user', async () => {
    let release: (doc: GatewayAccessResponse) => void = () => {};
    vi.spyOn(gatewayAccessService, 'get').mockReturnValue(new Promise<GatewayAccessResponse>(resolve => { release = resolve; }));
    mount(`?block=${ID_B}&reason=LEAK_DOC_REPEAT`);
    await settle();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(address()).toBe(`/policies/access?block=${ID_B}&reason=LEAK_DOC_REPEAT`);   // 아직 처리 전이라 주소가 그대로
    await act(async () => { release(current); });
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    await addressIs('/policies/access');
  });

  it('does not reopen after cancel', async () => {
    mount(`?block=${ID_B}&reason=LEAK_DOC_REPEAT`);
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: '취소' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await settle();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('shows a notice instead of the dialog when that user is already blocked, using the alias if there is one', async () => {
    vi.spyOn(clientAliasService, 'list').mockResolvedValue({ items: [{ client_id: ID_A, alias: '영업지원-2' }] });
    mount(`?block=${ID_A}&reason=LEAK_DOC_REPEAT`);
    expect(await screen.findByText('영업지원-2은(는) 이미 차단 중입니다.')).toHaveAttribute('role', 'status');
    expect(screen.queryByRole('dialog')).toBeNull();
    await addressIs('/policies/access');
  });

  it('opens for a user whose earlier block expired or was removed', async () => {
    current = docOf([rule({ client_id: ID_B, expires_at: iso(NOW - 1000), active: false }), rule({ id: '1a2b3c4d-0000-4000-8000-000000000003', client_id: ID_B, removed_at: iso(NOW - 5000), removed_by: 'x' })]);
    mount(`?block=${ID_B}&reason=PII_REPEAT`);
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });

  it.each([
    ['unknown-client', 'unknown-'],
    ['legacy-gateway', 'legacy-'],
    ['chrome 1', '공백 포함'],
    ['', '비어 있음'],
    ['x'.repeat(81), '너무 김'],
    ['<script>alert(1)</script>', '태그'],
  ])('does not open for the id %j (%s) and says why', async id => {
    mount(`?block=${encodeURIComponent(id)}&reason=LEAK_DOC_REPEAT`);
    expect(await screen.findByText(/올바르지 않거나 사용자를 구분할 수 없는 ID/)).toHaveAttribute('role', 'status');
    expect(screen.queryByRole('dialog')).toBeNull();
    await addressIs('/policies/access');
  });

  it('does not open in read-only mode', async () => {
    mode.canManagePolicies = false;
    mount(`?block=${ID_B}&reason=LEAK_DOC_REPEAT`);
    expect(await screen.findByText('읽기 전용이라 차단할 수 없습니다.')).toHaveAttribute('role', 'status');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('leaves the page as before when the link has no block value, keeping other query values', async () => {
    mount('?foo=1&reason=LEAK_DOC_REPEAT');
    await screen.findByRole('table');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText(/이미 차단 중입니다|올바르지 않거나|읽기 전용이라/)).toBeNull();
    expect(address()).toBe('/policies/access?foo=1&reason=LEAK_DOC_REPEAT');
  });

  it('keeps other query values when it clears block and reason', async () => {
    mount(`?foo=1&block=${ID_B}&reason=PII_REPEAT`);
    await screen.findByRole('dialog');
    await addressIs('/policies/access?foo=1');
  });

  it('shows 서버 반영 전 and opens nothing when the server does not know the access api yet', async () => {
    vi.spyOn(gatewayAccessService, 'get').mockRejectedValue(new ApiError('x', 'NOT_FOUND', 404));
    mount(`?block=${ID_B}&reason=LEAK_DOC_REPEAT`);
    expect(await screen.findByText('서버 반영 전')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
