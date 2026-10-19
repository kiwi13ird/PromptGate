import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { GatewaySettingsResponse, GatewaySettingsValues } from '@/src/api/gatewaySettingsSchemas';
import { GatewaySettingsPage } from './GatewaySettingsPage';

// 운영 빌드와 같은 조합(HTTP 어댑터 + 운영 화면 설정)으로 Gateway 처리 설정 화면을 연다. 값은 모두 가짜.
vi.mock('@runtime/gateway-api', async () => import('@/src/api/httpAdapter'));
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const REV3 = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const REV4 = '0b7d3c55-1e2f-4a6b-8c9d-aa11bb22cc33';
const values: GatewaySettingsValues = {
  timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'block', seconds: 2 } },
  uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
  notify_on_allow: false,
};
const reply = (version: number, revision: string, settings: GatewaySettingsValues, state: 'APPLIED' | 'PENDING'): GatewaySettingsResponse => ({
  settings: { ...settings, version, revision, updated_at: '2026-10-10T05:12:00.000Z', updated_by: 'local-admin', source: 'STORED' },
  defaults: values,
  gateway: {
    state, metrics_status: 'FRESH', reported_at: '2026-10-10T05:12:08.120Z', applied_version: 3, applied_revision: REV3, applied_source: 'DASHBOARD',
    applied_at: '2026-10-10T05:12:07.900Z', first_seen_at: '2026-10-10T05:12:08.120Z', rejected: null, effective: values,
  },
});
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(() => vi.unstubAllGlobals());

describe('gateway settings page with the real HTTP adapter', () => {
  it('loads over GET and saves with PUT and the version it started from', async () => {
    const changed: GatewaySettingsValues = { ...values, timeout: { ...values.timeout, file: { action: 'forward', seconds: 0.125 } } };
    const fetchMock = vi.fn(async (_url: URL, init?: RequestInit) =>
      init?.method === 'PUT' ? json(reply(4, REV4, changed, 'PENDING')) : json(reply(3, REV3, values, 'APPLIED')));
    vi.stubGlobal('fetch', fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><GatewaySettingsPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('Gateway 반영 v3 · Gateway 시각 14:12:07 · 확인 14:12:08')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('파일 지연 시 처리'), { target: { value: 'forward' } });
    fireEvent.change(screen.getByLabelText('파일 대기 시간(초)'), { target: { value: '0.125' } });
    fireEvent.click(screen.getByRole('button', { name: '저장' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/약 5,040자보다 긴 파일은 Gateway가 탐지 서버에 보내지 않아 검사되지 않습니다/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    expect(await screen.findByText('Gateway 반영 대기 중 · Gateway 현재 v3')).toBeInTheDocument();
    const put = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT');
    expect(put).toBeDefined();
    expect(new URL(String(put?.[0])).pathname).toBe('/api/gateway-settings');
    expect(JSON.parse(String(put?.[1]?.body))).toEqual({ expected_version: 3, ...changed });
    await waitFor(() => expect(screen.getByText('저장 v4 · 2026-10-10 14:12 · local-admin')).toBeInTheDocument());
  });

  it('shows the 503 wording when the backend has not read the settings', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: { code: 'SETTINGS_UNAVAILABLE' } }, 503)));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><GatewaySettingsPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('alert')).toHaveTextContent('설정을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.');
    expect(screen.queryByText(/SETTINGS_UNAVAILABLE/)).not.toBeInTheDocument();
  });
});
