import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

// 접속 차단 사유·메모 공개(2026-10-12): 차단 대화상자의 '사용자에게 메모도 보이기' · 미리보기, 규칙 표의 '메모 공개' 표시. 확장 ID·시각은 모두 가짜.
const mode = vi.hoisted(() => ({ canManagePolicies: true }));
vi.mock('@runtime/ui-mode', async () => {
  const real = await import('@/src/config/uiMode.real');
  return { uiMode: new Proxy(real.uiMode, { get: (target, key) => (key === 'canManagePolicies' ? mode.canManagePolicies : Reflect.get(target, key)) }) };
});
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const NOW = Date.parse('2026-10-12T05:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';
const ID_B = 'chrome-9b1e4d7c-2a6f-4c3b-8e05-7f2d9a6c4b18';
const ID_C = 'chrome-6c2d8e1f-4b7a-4d9e-a3c6-1e8f5b2d7a04';
const rule = (over: Partial<AccessRule> = {}): AccessRule => ({
  id: '1a2b3c4d-0000-4000-8000-000000000001', client_id: ID_A, reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], memo: '조사 협조 요청',
  expires_at: iso(NOW + 2 * 3_600_000), created_by: 'local-admin', created_at: iso(NOW - 600_000), removed_by: null, removed_at: null, active: true, ...over,
});
const docOf = (rules: AccessRule[]): GatewayAccessResponse => ({
  version: 5, revision: REV, require_client_id: false, rules,
  applied: { version: 5, revision: REV, source: 'DASHBOARD', applied_at: iso(NOW - 3_000), rejected: null, active_rules: rules.length, require_client_id: false, denied_5m: 0, received_at: iso(NOW - 4_000) },
  updated_at: iso(NOW - 600_000), updated_by: 'local-admin',
});
const noClients: TrafficClients = { receivedAt: iso(NOW - 4_000), stale: false, windowSeconds: 300, clients: [] };

let current: GatewayAccessResponse;
function mount() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/policies/access']}><GatewayAccessPage /></MemoryRouter></QueryClientProvider>);
}
const bodyRows = async () => within(await screen.findByRole('table')).getAllByRole('row').slice(1);
const openAdd = async () => {
  mount();
  await bodyRows();
  fireEvent.click(screen.getByRole('button', { name: '차단 추가' }));
  return screen.findByRole('dialog');
};
const confirmButton = (dialog: HTMLElement) => within(dialog).getByRole('button', { name: '차단' });
const preview = (dialog: HTMLElement) => within(dialog).getByRole('region', { name: '사용자에게 보이는 내용' });

beforeEach(() => {
  mode.canManagePolicies = true;
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  current = docOf([rule()]);
  vi.spyOn(gatewayAccessService, 'get').mockImplementation(async () => structuredClone(current));
  vi.spyOn(clientAliasService, 'list').mockResolvedValue({ items: [] });
  vi.spyOn(trafficService, 'getClients').mockResolvedValue(noClients);
});
afterEach(() => vi.useRealTimers());

describe('access tab: what the blocked user sees', () => {
  it('tells the admin that reasons are shown to the blocked user and the memo only when chosen', async () => {
    const dialog = await openAdd();
    expect(within(dialog).getByText(/차단된 사용자에게는 선택한 사유가 보입니다\. 메모는 공개를 고른 경우에만 보입니다\./)).toBeInTheDocument();
    expect(within(dialog).queryByText(/사유가 보이지 않습니다/)).toBeNull();
    expect(screen.getByText(/차단된 사용자에게는 사유가 보이고, 메모는 공개를 고른 경우에만 보입니다\./)).toBeInTheDocument();
  });

  it('disables 사용자에게 메모도 보이기 until a memo is typed, and unchecks it when the memo is emptied', async () => {
    const dialog = await openAdd();
    const box = within(dialog).getByLabelText('사용자에게 메모도 보이기', { exact: false });
    expect(box).toBeDisabled();
    expect(box).not.toBeChecked();
    expect(within(dialog).getByText('메모를 입력하면 고를 수 있습니다')).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '   ' } });
    expect(box).toBeDisabled();   // 공백만으로는 못 고른다
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '현장 확인' } });
    expect(box).toBeEnabled();
    expect(within(dialog).queryByText('메모를 입력하면 고를 수 있습니다')).toBeNull();
    fireEvent.click(box);
    expect(box).toBeChecked();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '' } });
    expect(box).toBeDisabled();
    expect(box).not.toBeChecked();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '다시 입력' } });
    expect(box).not.toBeChecked();   // 다시 입력해도 저절로 켜지지 않는다
  });

  it('previews what the user will see: the chosen reasons in fixed order, and the memo only when shown', async () => {
    const dialog = await openAdd();
    expect(preview(dialog)).toHaveTextContent('사용자에게 보이는 내용');
    expect(within(preview(dialog)).getByText('사유: 선택 전')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByLabelText('관리자 요청'));   // 클릭 순서와 보이는 순서가 달라야 한다
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));
    expect(within(preview(dialog)).getByText('사유: 보안 조사 중 · 관리자 요청')).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '  현장 확인  ' } });
    expect(within(preview(dialog)).queryByText(/관리자 안내/)).toBeNull();   // 기본은 관리자만
    expect(preview(dialog)).not.toHaveTextContent('현장 확인');
    fireEvent.click(within(dialog).getByLabelText('사용자에게 메모도 보이기', { exact: false }));
    expect(within(preview(dialog)).getByText('관리자 안내: 현장 확인')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByLabelText('사용자에게 메모도 보이기', { exact: false }));
    expect(within(preview(dialog)).queryByText(/관리자 안내/)).toBeNull();
  });

  it('shows the memo text as plain text in the preview (no HTML)', async () => {
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '<b>굵게</b><img src=x onerror=alert(1)>' } });
    fireEvent.click(within(dialog).getByLabelText('사용자에게 메모도 보이기', { exact: false }));
    expect(within(preview(dialog)).getByText('관리자 안내: <b>굵게</b><img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(preview(dialog).querySelector('b, img')).toBeNull();
  });

  it('sends show_memo_to_user: true with the memo only when chosen, and omits it otherwise', async () => {
    const add = vi.spyOn(gatewayApi, 'addAccessRule').mockResolvedValue({ version: 6 });
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('차단할 확장 프로그램 ID'), { target: { value: ID_B } });
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '  현장 확인  ' } });
    fireEvent.click(within(dialog).getByLabelText('사용자에게 메모도 보이기', { exact: false }));
    fireEvent.click(confirmButton(dialog));
    await waitFor(() => expect(add).toHaveBeenCalledTimes(1));
    expect(add.mock.calls[0][0]).toEqual({ client_id: ID_B, reasons: ['INVESTIGATION'], memo: '현장 확인', show_memo_to_user: true, duration: '1d', expected_version: 5 });
    expect(await within(dialog).findByText('차단 등록 완료 · v6')).toBeInTheDocument();
  });

  it('keeps the memo admin-only (no show_memo_to_user key) when the box is left unchecked or the memo is empty', async () => {
    const add = vi.spyOn(gatewayApi, 'addAccessRule').mockResolvedValue({ version: 6 });
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('차단할 확장 프로그램 ID'), { target: { value: ID_B } });
    fireEvent.click(within(dialog).getByLabelText('개인정보 반복 입력'));
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '관리자 전용 메모' } });
    fireEvent.click(confirmButton(dialog));
    await waitFor(() => expect(add).toHaveBeenCalledTimes(1));
    expect(add.mock.calls[0][0]).toEqual({ client_id: ID_B, reasons: ['PII_REPEAT'], memo: '관리자 전용 메모', duration: '1d', expected_version: 5 });
    expect(Object.keys(add.mock.calls[0][0])).not.toContain('show_memo_to_user');
  });

  it('does not send show_memo_to_user when the box was checked and the memo was then emptied', async () => {
    const add = vi.spyOn(gatewayApi, 'addAccessRule').mockResolvedValue({ version: 6 });
    const dialog = await openAdd();
    fireEvent.change(within(dialog).getByLabelText('차단할 확장 프로그램 ID'), { target: { value: ID_B } });
    fireEvent.click(within(dialog).getByLabelText('보안 조사 중'));
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '메모' } });
    fireEvent.click(within(dialog).getByLabelText('사용자에게 메모도 보이기', { exact: false }));
    fireEvent.change(within(dialog).getByLabelText('메모'), { target: { value: '' } });
    fireEvent.click(confirmButton(dialog));
    await waitFor(() => expect(add).toHaveBeenCalledTimes(1));
    expect(add.mock.calls[0][0]).toEqual({ client_id: ID_B, reasons: ['INVESTIGATION'], duration: '1d', expected_version: 5 });
  });
});

describe('access tab: 메모 공개 marker', () => {
  it('marks only rules whose memo is shown to the user', async () => {
    current = docOf([
      rule(),
      rule({ id: '2b3c4d5e-0000-4000-8000-000000000002', client_id: ID_B, memo: '사용자에게 보이는 메모', show_memo_to_user: true, created_at: iso(NOW - 300_000) }),
      rule({ id: '3c4d5e6f-0000-4000-8000-000000000003', client_id: ID_C, memo: null, show_memo_to_user: true, created_at: iso(NOW - 900_000) }),
    ]);
    mount();
    const rows = await bodyRows();
    expect(rows).toHaveLength(3);
    const byTarget = (id: string) => rows.find(row => row.textContent?.includes(id))!;
    expect(within(byTarget(ID_B)).getByText('메모 공개')).toBeInTheDocument();
    expect(within(byTarget(ID_B)).getAllByRole('cell')[2]).toHaveTextContent('사용자에게 보이는 메모');
    expect(within(byTarget(ID_A)).queryByText('메모 공개')).toBeNull();   // 필드가 없는 옛 규칙
    expect(within(byTarget(ID_C)).queryByText('메모 공개')).toBeNull();   // 보일 메모가 없으면 표시도 없다
  });
});
