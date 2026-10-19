import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { mockGatewayApi, MOCK_GATEWAY_APPLY_MS } from '@/src/api/mockAdapter';
import { maxCharsForWait, WORST_MS_PER_1K_CHARS } from '@/src/constants/detectionSpeed';
import {
  gatewaySettingsResponseSchema,
  gatewaySettingsService,
  type GatewayApplyStatus,
  type GatewaySettingsDocument,
  type GatewaySettingsResponse,
  type GatewaySettingsValues,
} from '@/src/services/gatewaySettingsService';
import { notifySuccess } from '@/src/utils/feedback';
import { GatewaySettingsPage } from './GatewaySettingsPage';

// Gateway 처리 설정 화면(2026-10-10, 명세 §10 · §11.3). 값은 모두 가짜.
const mode = vi.hoisted(() => ({ canManagePolicies: true }));
vi.mock('@runtime/ui-mode', async () => {
  const real = await import('@/src/config/uiMode.real');
  return { uiMode: new Proxy(real.uiMode, { get: (target, key) => (key === 'canManagePolicies' ? mode.canManagePolicies : Reflect.get(target, key)) }) };
});
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const REV3 = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const REV4 = '0b7d3c55-1e2f-4a6b-8c9d-aa11bb22cc33';
const REV4B = 'f00dbabe-0000-4000-8000-000000000004';
const defaults: GatewaySettingsValues = {
  timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'block', seconds: 2 } },
  uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
  notify_on_allow: false,
};
const stored = (version: number, revision: string, values: GatewaySettingsValues = defaults): GatewaySettingsDocument => ({
  ...structuredClone(values), version, revision, updated_at: '2026-10-10T05:12:00.000Z', updated_by: 'local-admin', source: 'STORED',
});
const unsaved: GatewaySettingsDocument = { ...structuredClone(defaults), version: 0, revision: null, updated_at: null, updated_by: null, source: 'DEFAULT' };
const response = (settings: GatewaySettingsDocument, gateway: Partial<GatewayApplyStatus> = {}): GatewaySettingsResponse => ({
  settings,
  defaults: structuredClone(defaults),
  gateway: {
    state: 'APPLIED', metrics_status: 'FRESH', reported_at: '2026-10-10T05:12:08.120Z',
    applied_version: settings.version, applied_revision: settings.revision, applied_source: settings.revision ? 'DASHBOARD' : 'ENV_DEFAULT',
    applied_at: '2026-10-10T05:12:07.900Z', first_seen_at: '2026-10-10T05:12:08.120Z', rejected: null, effective: structuredClone(defaults),
    ...gateway,
  },
});
const v3 = response(stored(3, REV3));

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/policies/gateway']}><GatewaySettingsPage /></MemoryRouter></QueryClientProvider>);
  return client;
}
const saveButton = () => screen.getByRole('button', { name: '저장' });
async function openConfirm() {
  fireEvent.click(saveButton());
  return screen.findByRole('dialog');
}

beforeEach(() => {
  vi.restoreAllMocks();
  mode.canManagePolicies = true;
});
afterEach(() => vi.useRealTimers());

describe('gateway settings contract fixtures', () => {
  it('match the settings document shape in the spec', () => {
    for (const fixture of [v3, response(unsaved), response(stored(4, REV4), { state: 'NOT_REPORTING', reported_at: null, applied_version: null, applied_revision: null, applied_source: null, applied_at: null, first_seen_at: null, effective: null })])
      expect(gatewaySettingsResponseSchema.safeParse(fixture).success).toBe(true);
  });
  it('rejects unknown or missing setting fields, out-of-range waits and a non-UUID revision', () => {
    const bad = (mutate: (value: Record<string, unknown>) => void) => {
      const copy = structuredClone(v3) as unknown as { settings: Record<string, unknown> };
      mutate(copy.settings);
      return gatewaySettingsResponseSchema.safeParse(copy).success;
    };
    expect(bad(settings => { settings.extra = true; })).toBe(false);
    expect(bad(settings => { delete settings.notify_on_allow; })).toBe(false);
    expect(bad(settings => { (settings.timeout as GatewaySettingsValues['timeout']).file.seconds = 0.04; })).toBe(false);
    expect(bad(settings => { (settings.timeout as GatewaySettingsValues['timeout']).file.seconds = 30.01; })).toBe(false);
    expect(bad(settings => { (settings.timeout as GatewaySettingsValues['timeout']).file.seconds = 0.125; })).toBe(true);
    expect(bad(settings => { settings.revision = REV3.toUpperCase(); })).toBe(false);
  });
});

describe('detection speed constant', () => {
  it('is pinned to the gateway value and gives the same character limits', () => {
    expect(WORST_MS_PER_1K_CHARS).toBe(24.8);
    expect([0.5, 1, 2, 5, 10, 30].map(maxCharsForWait)).toEqual([20161, 40322, 80645, 201612, 403225, 1209677]);
  });
});

describe('gateway settings page', () => {
  it('loads the saved settings and the gateway apply line', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    mount();
    expect(await screen.findByText('저장 v3 · 2026-10-10 14:12 · local-admin')).toBeInTheDocument();
    expect(screen.getByText('Gateway 반영 v3 · Gateway 시각 14:12:07 · 확인 14:12:08')).toBeInTheDocument();
    expect(screen.getByLabelText('질문 지연 시 처리')).toHaveValue('forward');
    expect(screen.getByLabelText('질문 대기 시간(초)')).toHaveValue(0.5);
    expect(screen.getByLabelText('파일 지연 시 처리')).toHaveValue('block');
    expect(screen.getByLabelText('파일 대기 시간(초)')).toHaveValue(2);
    expect(screen.getByLabelText('이미지 처리')).toHaveValue('allow');
    expect(screen.getByLabelText('스캔 PDF 처리')).toHaveValue('block');
    expect(screen.getByLabelText('기타 형식 처리')).toHaveValue('block');
    expect(screen.getByLabelText('검사 없이 전송된 경우에도 알림')).not.toBeChecked();
    expect(screen.getByText('대기하는 동안 Gateway를 지나는 다른 요청도 함께 기다립니다.')).toBeInTheDocument();
    // 2026-10-13 피드백: Gateway는 HWP·HWPX·PDF를 검사한다 - 기타 형식은 운영 Gateway 분류(gateway_file_classes.py other)대로 못 읽는 경우만
    const other = screen.getByText(/^PPT·옛 DOC·XLS·RTF·압축 파일, 암호·배포용·손상 문서\(HWP·PDF 포함\)/);
    expect(other.textContent).not.toMatch(/^HWP|HWP·HWPX·PPT/);
    expect(screen.getByText('PDF·DOCX·XLSX·HWP·HWPX·텍스트 파일은 내용을 검사합니다.')).toBeInTheDocument();
    // 재설계 2단계: 정책 탭 줄 대신 왼쪽 메뉴(경로는 appLayout.test.tsx가 확인). 본문 제목 = 메뉴 이름 'Gateway 처리'
    expect(screen.getByRole('heading', { level: 1, name: 'Gateway 처리' })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: '탐지 정책 보기' })).toBeNull();
    expect(saveButton()).toBeDisabled();
    expect(screen.getByText('바뀐 값 없음')).toBeInTheDocument();
  });

  it('shows the defaults when nothing has been saved', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(response(unsaved));
    mount();
    expect(await screen.findByText('저장된 설정 없음 · 기본값으로 동작')).toBeInTheDocument();
    expect(screen.getByText('Gateway 반영 · 기본값 · 확인 14:12:08')).toBeInTheDocument();
  });

  it('says the server has not read the settings yet on 503', async () => {
    const get = vi.spyOn(gatewaySettingsService, 'get').mockRejectedValue(new ApiError('x', 'SERVER', 503));
    mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('설정을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.');
    get.mockResolvedValue(v3);
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    expect(await screen.findByText('저장 v3 · 2026-10-10 14:12 · local-admin')).toBeInTheDocument();
  });

  it('shows a load failure without codes', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockRejectedValue(new ApiError('x', 'SERVER', 500));
    mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('설정을 불러오지 못했습니다. 잠시 후 다시 시도해주세요.');
  });

  it('is read-only without policy management rights', async () => {
    mode.canManagePolicies = false;
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    mount();
    expect(await screen.findByText('저장 v3 · 2026-10-10 14:12 · local-admin')).toBeInTheDocument();
    expect(screen.getByText('읽기 전용')).toBeInTheDocument();
    for (const label of ['질문 지연 시 처리', '질문 대기 시간(초)', '파일 지연 시 처리', '파일 대기 시간(초)', '이미지 처리', '스캔 PDF 처리', '기타 형식 처리', '검사 없이 전송된 경우에도 알림'])
      expect(screen.getByLabelText(label)).toBeDisabled();
    expect(screen.queryByRole('button', { name: '저장' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '기본값 채우기' })).not.toBeInTheDocument();
  });

  it('checks the wait range (0.05 to 30, any decimals) and recomputes the character limit', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    mount();
    const file = await screen.findByLabelText('파일 대기 시간(초)');
    expect(screen.getByText('20,161')).toBeInTheDocument();   // 질문 0.5초
    expect(screen.getByText('80,645')).toBeInTheDocument();   // 파일 2초
    expect(screen.getByText('이보다 긴 파일은 Detection에 보내지 않고 차단')).toBeInTheDocument();
    for (const value of ['0.04', '30.01', '']) {
      fireEvent.change(file, { target: { value } });
      expect(screen.getByRole('alert')).toHaveTextContent('대기 시간은 0.05~30초 사이로 입력하세요.');
      expect(saveButton()).toBeDisabled();
      expect(screen.getByText('대기 시간을 확인하세요.')).toBeInTheDocument();
    }
    fireEvent.change(file, { target: { value: '30' } });
    expect(screen.getByText('1,209,677')).toBeInTheDocument();
    fireEvent.change(file, { target: { value: '0.125' } });
    expect(screen.getByText('5,040')).toBeInTheDocument();
    expect(screen.queryByText('대기 시간은 0.05~30초 사이로 입력하세요.')).not.toBeInTheDocument();
    expect(saveButton()).toBeEnabled();
    fireEvent.change(screen.getByLabelText('파일 지연 시 처리'), { target: { value: 'forward' } });
    expect(screen.getByText('이보다 긴 파일은 Detection에 보내지 않고 검사 없이 전송')).toBeInTheDocument();
  });

  it('confirms the before and after and warns for each side that sends without inspection', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    mount();
    fireEvent.change(await screen.findByLabelText('파일 지연 시 처리'), { target: { value: 'forward' } });
    fireEvent.change(screen.getByLabelText('파일 대기 시간(초)'), { target: { value: '5' } });
    const dialog = await openConfirm();
    expect(within(dialog).getByText('Gateway 처리 설정 저장')).toBeInTheDocument();
    expect(within(dialog).getByText(/v3 → v4/)).toBeInTheDocument();
    const changes = within(dialog).getByLabelText('변경 전·후');
    expect(within(changes).getByText('파일 지연 시 처리')).toBeInTheDocument();
    expect(within(changes).getByText('차단 → 원본 전송')).toBeInTheDocument();
    expect(within(changes).getByText('2초 → 5초')).toBeInTheDocument();
    expect(within(changes).queryByText('질문 지연 시 처리')).not.toBeInTheDocument();
    expect(within(dialog).getByText('대기 시간을 넘긴 파일은 검사 없이 전송됩니다. 지금 값으로는 약 201,612자보다 긴 파일은 Gateway가 탐지 서버에 보내지 않아 검사되지 않습니다.')).toBeInTheDocument();
    expect(within(dialog).getByText('대기 시간을 넘긴 질문은 검사 없이 전송됩니다. 지금 값으로는 약 20,161자보다 긴 질문은 검사되지 않을 수 있습니다(탐지 서버 처리 시간 기준 · 네트워크·Gateway 추출 시간은 빠짐).')).toBeInTheDocument();
  });

  it('has no warning when both sides block', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    mount();
    fireEvent.change(await screen.findByLabelText('질문 지연 시 처리'), { target: { value: 'block' } });
    const dialog = await openConfirm();
    expect(within(dialog).getByText('원본 전송 → 차단')).toBeInTheDocument();
    expect(within(dialog).queryByText(/검사 없이 전송됩니다/)).not.toBeInTheDocument();
  });

  it('saves with the version the edit started from and records the new version', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    const saved = response(stored(4, REV4, { ...defaults, uninspectable: { ...defaults.uninspectable, image: 'block' }, notify_on_allow: true }), { state: 'PENDING', applied_version: 3, applied_revision: REV3 });
    const save = vi.spyOn(gatewaySettingsService, 'save').mockResolvedValue(saved);
    mount();
    fireEvent.change(await screen.findByLabelText('이미지 처리'), { target: { value: 'block' } });
    fireEvent.click(screen.getByLabelText('검사 없이 전송된 경우에도 알림'));
    const dialog = await openConfirm();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith({ ...defaults, uninspectable: { image: 'block', scanned_pdf: 'block', other: 'block' }, notify_on_allow: true }, 3);
    expect(await screen.findByText('저장 v4 · 2026-10-10 14:12 · local-admin')).toBeInTheDocument();
    expect(screen.getByText('Gateway 반영 대기 중 · Gateway 현재 v3')).toBeInTheDocument();
    expect(notifySuccess).toHaveBeenCalledWith('Gateway 처리 설정을 저장했습니다.', expect.stringContaining('v4'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(saveButton()).toBeDisabled();
  });

  it('fills the defaults without saving', async () => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(response(stored(3, REV3, { ...defaults, timeout: { prompt: { action: 'block', seconds: 1 }, file: { action: 'forward', seconds: 5 } } })));
    const save = vi.spyOn(gatewaySettingsService, 'save');
    mount();
    expect(await screen.findByLabelText('파일 대기 시간(초)')).toHaveValue(5);
    fireEvent.click(screen.getByRole('button', { name: '기본값 채우기' }));
    expect(screen.getByLabelText('파일 대기 시간(초)')).toHaveValue(2);
    expect(screen.getByLabelText('질문 지연 시 처리')).toHaveValue('forward');
    expect(screen.getByText(/바뀐 칸 4개/)).toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
  });

  it('reloads and says another admin saved first on 409', async () => {
    const newer = response(stored(4, REV4, { ...defaults, timeout: { ...defaults.timeout, file: { action: 'block', seconds: 3 } } }));
    const get = vi.spyOn(gatewaySettingsService, 'get').mockResolvedValueOnce(v3).mockResolvedValue(newer);
    vi.spyOn(gatewaySettingsService, 'save').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    mount();
    fireEvent.change(await screen.findByLabelText('파일 대기 시간(초)'), { target: { value: '7' } });
    const dialog = await openConfirm();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    expect(await screen.findByText('다른 관리자가 먼저 바꿨습니다. 최신 값을 확인하세요.')).toBeInTheDocument();
    expect(get).toHaveBeenCalledTimes(2);
    expect(screen.getByText('저장 v4 · 2026-10-10 14:12 · local-admin')).toBeInTheDocument();
    expect(screen.getByLabelText('파일 대기 시간(초)')).toHaveValue(3);   // 입력은 최신 값으로
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('keeps the unsaved input when another admin saves meanwhile and blocks saving until reloaded', async () => {
    const newer = response(stored(4, REV4));
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValueOnce(v3).mockResolvedValue(newer);
    const client = mount();
    fireEvent.change(await screen.findByLabelText('파일 대기 시간(초)'), { target: { value: '7' } });
    await act(() => client.refetchQueries({ queryKey: ['gateway-settings'] }));
    expect(await screen.findByText('다른 관리자가 먼저 바꿨습니다. 최신 값을 확인하세요.')).toBeInTheDocument();
    expect(screen.getByLabelText('파일 대기 시간(초)')).toHaveValue(7);
    expect(saveButton()).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: '최신 값 불러오기' }));
    expect(screen.getByLabelText('파일 대기 시간(초)')).toHaveValue(2);
    expect(screen.queryByText('다른 관리자가 먼저 바꿨습니다. 최신 값을 확인하세요.')).not.toBeInTheDocument();
  });

  it.each([
    ['503', new ApiError('x', 'SERVER', 503), '저장 실패 · 설정을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.'],
    ['422', new ApiError('x', 'VALIDATION', 422), '저장 실패 · 저장할 수 없는 값입니다. 입력 값을 확인하세요.'],
  ])('explains a %s save failure in the dialog', async (_status, error, text) => {
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(v3);
    vi.spyOn(gatewaySettingsService, 'save').mockRejectedValue(error);
    mount();
    fireEvent.change(await screen.findByLabelText('파일 대기 시간(초)'), { target: { value: '3' } });
    const dialog = await openConfirm();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    expect(await within(dialog).findByText(text)).toBeInTheDocument();
  });

  it.each<[string, Partial<GatewayApplyStatus>, string]>([
    ['APPLIED', {}, 'Gateway 반영 v3 · Gateway 시각 14:12:07 · 확인 14:12:08'],
    ['APPLIED without a gateway clock', { applied_source: 'CACHE', applied_at: null }, 'Gateway 반영 v3 · 확인 14:12:08'],
    ['PENDING', { state: 'PENDING', applied_version: 2, applied_revision: REV4B }, 'Gateway 반영 대기 중 · Gateway 현재 v2'],
    ['REJECTED', { state: 'REJECTED', applied_version: 2, applied_revision: REV4B, rejected: { version: 3, revision: REV3, field: 'timeout.file.seconds' } }, 'Gateway가 이 설정을 거부함 · 거부한 칸 파일 대기 시간'],
    // 백엔드는 거부 문서 번호가 없는 보고(rejected.version null)도 받아 그대로 돌려준다
    ['REJECTED without a version', { state: 'REJECTED', applied_version: 0, applied_revision: null, applied_source: 'ENV_DEFAULT', rejected: { version: null, revision: REV3, field: 'timeout.file.seconds' } }, 'Gateway가 이 설정을 거부함 · 거부한 칸 파일 대기 시간'],
    ['NOT_REPORTING', { state: 'NOT_REPORTING', metrics_status: 'STALE', reported_at: null, applied_version: null, applied_revision: null, applied_source: null, applied_at: null, first_seen_at: null, effective: null }, 'Gateway 응답 없음 · 마지막으로 받은 설정으로 동작 중'],
    ['LEGACY_GATEWAY', { state: 'LEGACY_GATEWAY', applied_version: null, applied_revision: null, applied_source: null, applied_at: null, first_seen_at: null, effective: null }, 'Gateway가 설정 반영을 지원하지 않는 판(또는 첫 응답 전, 최대 10초)'],
    ['REPORT_INVALID', { state: 'REPORT_INVALID', applied_version: null, applied_revision: null, applied_source: null, applied_at: null, first_seen_at: null, effective: null }, 'Gateway 보고 형식 오류 · 반영 여부 확인 불가'],
  ])('shows the %s state', async (_state, gateway, text) => {
    const fixture = response(stored(3, REV3), gateway);
    expect(gatewaySettingsResponseSchema.safeParse(fixture).success).toBe(true);
    vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(fixture);
    mount();
    expect(await screen.findByText(text)).toBeInTheDocument();
  });

  it('polls every 2 seconds after saving and stops once the gateway applied it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const pending = response(stored(4, REV4), { state: 'PENDING', applied_version: 3, applied_revision: REV3 });
    const applied = response(stored(4, REV4));
    const get = vi.spyOn(gatewaySettingsService, 'get')
      .mockResolvedValueOnce(v3)
      .mockResolvedValueOnce(pending)
      .mockResolvedValue(applied);
    vi.spyOn(gatewaySettingsService, 'save').mockResolvedValue(pending);
    mount();
    fireEvent.change(await screen.findByLabelText('파일 대기 시간(초)'), { target: { value: '3' } });
    const dialog = await openConfirm();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    expect(await screen.findByText('Gateway 반영 대기 중 · Gateway 현재 v3')).toBeInTheDocument();
    expect(get).toHaveBeenCalledTimes(1);
    await act(() => vi.advanceTimersByTimeAsync(2_000));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await act(() => vi.advanceTimersByTimeAsync(2_000));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(3));
    expect(await screen.findByText('Gateway 반영 v4 · Gateway 시각 14:12:07 · 확인 14:12:08')).toBeInTheDocument();
    await act(() => vi.advanceTimersByTimeAsync(6_000));   // 반영된 뒤에는 2초마다 다시 읽지 않는다
    expect(get).toHaveBeenCalledTimes(3);
    await act(() => vi.advanceTimersByTimeAsync(4_500));   // 평소 10초 주기로 돌아감
    await waitFor(() => expect(get).toHaveBeenCalledTimes(4));
  });

  it('stops fast polling after 30 seconds even when the gateway never applies it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const pending = response(stored(4, REV4), { state: 'PENDING', applied_version: 3, applied_revision: REV3 });
    const get = vi.spyOn(gatewaySettingsService, 'get').mockResolvedValueOnce(v3).mockResolvedValue(pending);
    vi.spyOn(gatewaySettingsService, 'save').mockResolvedValue(pending);
    mount();
    fireEvent.change(await screen.findByLabelText('파일 대기 시간(초)'), { target: { value: '3' } });
    const dialog = await openConfirm();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    expect(await screen.findByText('Gateway 반영 대기 중 · Gateway 현재 v3')).toBeInTheDocument();
    await act(() => vi.advanceTimersByTimeAsync(30_500));
    const afterWindow = get.mock.calls.length;
    expect(afterWindow).toBeGreaterThanOrEqual(13);   // 30초 동안 2초마다
    await act(() => vi.advanceTimersByTimeAsync(8_000));
    expect(get.mock.calls.length).toBe(afterWindow);   // 그 뒤로는 10초 주기
  });
});

describe('gateway settings in mock mode', () => {
  it('works end to end against the mock adapter with an audit row', async () => {
    mount();
    expect(await screen.findByText('저장된 설정 없음 · 기본값으로 동작')).toBeInTheDocument();
    expect(screen.getByText(/^Gateway 반영 · 기본값/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('스캔 PDF 처리'), { target: { value: 'allow' } });
    const dialog = await openConfirm();
    fireEvent.click(within(dialog).getByRole('button', { name: '저장' }));
    expect(await screen.findByText(/^저장 v1 · /)).toBeInTheDocument();
    expect(screen.getByText('Gateway 반영 대기 중 · Gateway 현재 기본값')).toBeInTheDocument();
    const logs = await mockGatewayApi.getAuditLogs({ period: '24H', action: 'GATEWAY_SETTINGS_UPDATE', result: 'ALL', admin: '', page: 1, pageSize: 10 });
    expect(logs.items).toHaveLength(1);
    expect(logs.items[0]).toMatchObject({ target_type: 'GATEWAY', target_id: 'gateway-settings', result: 'SUCCESS' });
    expect(logs.items[0].changes).toEqual({
      new_version: 1,
      previous_value: '기본값 · 질문 지연 시 원본 전송(0.5초) · 파일 지연 시 차단(2초) · 이미지 허용 · 스캔 PDF 차단 · 기타 형식 차단 · 허용 알림 끔',
      new_value: '질문 지연 시 원본 전송(0.5초) · 파일 지연 시 차단(2초) · 이미지 허용 · 스캔 PDF 허용 · 기타 형식 차단 · 허용 알림 끔',
    });
  });

  it('mock adapter follows the contract: version check, field check and apply delay', async () => {
    const first = await mockGatewayApi.getGatewaySettings();
    expect(gatewaySettingsResponseSchema.safeParse(first).success).toBe(true);
    expect(first.settings).toMatchObject({ version: 0, source: 'DEFAULT', revision: null });
    expect(first.gateway).toMatchObject({ state: 'APPLIED', applied_source: 'ENV_DEFAULT' });
    const saved = await mockGatewayApi.saveGatewaySettings({ expected_version: 0, ...defaults });
    expect(gatewaySettingsResponseSchema.safeParse(saved).success).toBe(true);
    expect(saved.settings).toMatchObject({ version: 1, source: 'STORED' });
    expect(saved.gateway.state).toBe('PENDING');
    await expect(mockGatewayApi.saveGatewaySettings({ expected_version: 0, ...defaults })).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });
    await expect(mockGatewayApi.saveGatewaySettings({ expected_version: 1, ...defaults, extra: 1 } as never)).rejects.toMatchObject({ code: 'VALIDATION', status: 400 });
    await expect(mockGatewayApi.saveGatewaySettings({ expected_version: 1, ...defaults, timeout: { ...defaults.timeout, file: { action: 'block', seconds: 31 } } })).rejects.toMatchObject({ code: 'VALIDATION', status: 422 });
    const later = Date.now() + MOCK_GATEWAY_APPLY_MS + 10;
    vi.spyOn(Date, 'now').mockReturnValue(later);
    const applied = await mockGatewayApi.getGatewaySettings();
    expect(applied.gateway).toMatchObject({ state: 'APPLIED', applied_version: 1, applied_revision: saved.settings.revision, applied_source: 'DASHBOARD' });
    const logs = await mockGatewayApi.getAuditLogs({ period: '24H', action: 'GATEWAY_SETTINGS_UPDATE', result: 'ALL', admin: '', page: 1, pageSize: 10 });
    expect(logs.items).toHaveLength(1);   // 실패한 저장은 기록하지 않는다
  });
});
