import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { toast } from '@/components/ui/toast';
import { ApiError } from '@/src/api/errors';
import { mapAuditLogDto } from '@/src/api/mappers';
import { auditLogSchema, pageSchema, parseApiResponse } from '@/src/api/schemas';
import { detectionOpsService, type GpuStatus } from '@/src/services/detectionOpsService';
import { notifySuccess } from '@/src/utils/feedback';
import { uiLabel } from '@/src/utils/labels';
import { AuditChangeDetails } from './AuditChangeDetails';
import { GpuStatusBadge } from './GpuStatusBadge';

const mode = vi.hoisted(() => ({ canManagePolicies: true }));
vi.mock('@runtime/ui-mode', async () => {
  const real = await import('@/src/config/uiMode.real');
  return { uiMode: new Proxy(real.uiMode, { get: (target, key) => (key === 'canManagePolicies' ? mode.canManagePolicies : Reflect.get(target, key)) }) };
});
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const at = '2026-10-07T12:00:00+00:00';
const gpu = (instance_state: string | null, connected = false, controllable = true): GpuStatus => ({
  connected, models: connected ? ['qwen3-8b'] : [], latency_ms: connected ? 8 : null, error: null, checked_at: at, instance_state, controllable,
});

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><GpuStatusBadge /></QueryClientProvider>);
  return client;
}

beforeEach(() => {
  vi.restoreAllMocks();
  mode.canManagePolicies = true;
});

describe('gpu phases', () => {
  it.each([
    [gpu('stopped'), 'GPU 꺼짐', 'GPU 켜기'],
    [gpu('pending'), 'GPU 켜는 중', null],
    [gpu('running'), 'GPU 모델 준비 중', 'GPU 끄기'],
    [gpu('running', true), 'GPU 연결됨', 'GPU 끄기'],
    [gpu('stopping'), 'GPU 끄는 중', null],
    [gpu(null), 'GPU 응답 없음', null],
  ])('%#: %j', async (status, label, button) => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(status);
    mount();
    expect(await screen.findByText(label)).toBeInTheDocument();
    if (button) expect(screen.getByRole('button', { name: button })).toBeInTheDocument();
    else expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
  it('hides the buttons when Detection cannot control the GPU or is an older version', async () => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValueOnce(gpu('stopped', false, false));
    mount();
    expect(await screen.findByText('GPU 꺼짐')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
  it('keeps the earlier answer for a Detection without instance state', async () => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue({ connected: false, models: [], latency_ms: null, error: 'URLError', checked_at: at });
    mount();
    expect(await screen.findByText('GPU 응답 없음')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
  it('hides the buttons from a read-only administrator', async () => {
    mode.canManagePolicies = false;
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpu('running', true));
    mount();
    expect(await screen.findByText('GPU 연결됨')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});

describe('gpu start and stop', () => {
  it('starts only after confirmation and shows the new state', async () => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValueOnce(gpu('stopped')).mockResolvedValue(gpu('pending'));
    const control = vi.spyOn(detectionOpsService, 'controlGpu').mockResolvedValue({ instance_id: 'i-0gpu', previous_state: 'stopped', instance_state: 'pending' });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'GPU 켜기' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('GPU를 켜시겠습니까?')).toBeInTheDocument();
    expect(control).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: '켜기' }));
    await waitFor(() => expect(control).toHaveBeenCalledWith('start'));
    expect(await screen.findByText('GPU 켜는 중')).toBeInTheDocument();
    expect(notifySuccess).toHaveBeenCalledWith('GPU를 켜고 있습니다.', expect.stringContaining('2~3분'));
    expect(screen.queryByRole('button', { name: 'GPU 켜기' })).not.toBeInTheDocument();
  });
  it('does nothing when cancelled', async () => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpu('running', true));
    const control = vi.spyOn(detectionOpsService, 'controlGpu');
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'GPU 끄기' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '취소' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(control).not.toHaveBeenCalled();
  });
  it.each([
    [new ApiError('x', 'CONFLICT', 409), /리포트 생성이나 키워드 추출이 GPU를 쓰는 중/],
    [new ApiError('x', 'FORBIDDEN', 403), /GPU 켜기·끄기 권한이 없습니다/],
    [new ApiError('x', 'SERVER', 502), /AWS에 GPU 켜기·끄기를 요청하지 못했습니다/],
    [new ApiError('x', 'SERVER', 503), /탐지 서버에 연결할 수 없습니다/],
  ])('explains a refused stop: %s', async (error, message) => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpu('running', true));
    vi.spyOn(detectionOpsService, 'controlGpu').mockRejectedValue(error);
    const notice = vi.spyOn(toast, 'add');
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'GPU 끄기' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '끄기' }));
    await waitFor(() => expect(notice).toHaveBeenCalledWith(expect.objectContaining({ title: 'GPU를 끄지 못했습니다.', description: expect.stringMatching(message), type: 'error' })));
    expect(screen.getByText('GPU 연결됨')).toBeInTheDocument();
  });
  it('says a start conflict means it is already on or changing', async () => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpu('stopped'));
    vi.spyOn(detectionOpsService, 'controlGpu').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    const notice = vi.spyOn(toast, 'add');
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'GPU 켜기' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '켜기' }));
    await waitFor(() => expect(notice).toHaveBeenCalledWith(expect.objectContaining({ title: 'GPU를 켜지 못했습니다.', description: expect.stringMatching(/이미 켜져 있거나/) })));
  });
});

describe('gpu audit rows', () => {
  const row = (action: string) => ({
    audit_id: `A-${action}`, occurred_at: '2026-10-07T01:00:00.000Z', admin_id: 'local-admin', result: 'SUCCESS', action, target_type: 'GPU', target_id: 'i-094b015caf120ab1e',
    changes: action === 'GPU_START' ? { previous_instance_state: 'stopped', new_instance_state: 'pending' } : { previous_instance_state: 'running', new_instance_state: 'stopping' },
  });
  it('parses GPU_START and GPU_STOP with the state change', () => {
    const page = parseApiResponse(pageSchema(auditLogSchema), { items: [row('GPU_START'), row('GPU_STOP')], page: 1, page_size: 20, total: 2, total_pages: 1 });
    const logs = page.items.map(mapAuditLogDto);
    expect(logs.map(log => [log.action, log.targetType])).toEqual([['GPU_START', 'GPU'], ['GPU_STOP', 'GPU']]);
    expect(logs[0].changes).toMatchObject({ previousGpuState: 'stopped', newGpuState: 'pending' });
    expect([uiLabel('GPU_START'), uiLabel('GPU_STOP'), uiLabel('GPU')]).toEqual(['GPU 켜기', 'GPU 끄기', 'GPU']);
  });
  it('shows the state change in Korean', () => {
    render(<AuditChangeDetails changes={{ previousGpuState: 'running', newGpuState: 'stopping' }} />);
    expect(screen.getByText('GPU 상태')).toBeInTheDocument();
    expect(screen.getByText('변경 전: 켜짐')).toBeInTheDocument();
    expect(screen.getByText('변경 후: 끄는 중')).toBeInTheDocument();
  });
});
