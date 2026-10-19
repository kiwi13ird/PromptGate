// 보안 이벤트의 접속 차단(2026-10-12): '이 사용자 차단' 버튼, 별칭, 접속 차단(관리자) 이벤트 표시, 내 요청 기록 문구. 확장 ID·시각은 모두 가짜.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { EventsTable } from '@/src/components/EventsTable';
import { clientAliasService, gatewayAccessService, type AccessRule, type GatewayAccessResponse } from '@/src/services/gatewayAccessService';
import { eventService } from '@/src/services/eventService';
import { EXTENSION_ID } from '@/src/services/myRequestsService';
import type { SecurityEvent } from '@/src/types/event';
import { EventDetailPage } from './EventDetailPage';
import { MyRequestsPage } from './MyRequestsPage';

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
const RULE = '1a2b3c4d-0000-4000-8000-000000000001';
const rule: AccessRule = {
  id: RULE, client_id: ID_A, reasons: ['INVESTIGATION'], memo: null, expires_at: iso(NOW + 3_600_000 + 30 * 60_000),
  created_by: 'local-admin', created_at: iso(NOW - 60_000), removed_by: null, removed_at: null, active: true,
};
const docOf = (rules: AccessRule[] = []): GatewayAccessResponse => ({
  version: 5, revision: REV, require_client_id: false, rules,
  applied: { version: 5, revision: REV, source: 'DASHBOARD', applied_at: iso(NOW - 3_000), rejected: null, active_rules: rules.length, require_client_id: false, denied_5m: 0, received_at: iso(NOW - 4_000) },
});
const base: SecurityEvent = {
  eventId: 'evt-access', requestId: 'req-access', occurredAt: '2026-10-12T04:50:00Z', clientId: ID_A, targetLlm: 'ChatGPT',
  detectionOutcome: 'NO_MATCH', finalAction: 'ALLOW', status: 'NEW', adminNotes: [], timeline: [], detections: [], degraded: false,
};

function openEvent(event: SecurityEvent) {
  vi.spyOn(eventService, 'getEventById').mockResolvedValue(event);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/events/evt-access']}><Routes><Route path="/events/:eventId" element={<EventDetailPage />} /></Routes></MemoryRouter></QueryClientProvider>);
}
const summary = async () => within(await screen.findByLabelText('요청 정보'));

beforeEach(() => {
  mode.canManagePolicies = true;
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  vi.spyOn(gatewayAccessService, 'get').mockResolvedValue(docOf());
  vi.spyOn(clientAliasService, 'list').mockResolvedValue({ items: [] });
});
afterEach(() => vi.useRealTimers());

describe('event detail: 이 사용자 차단', () => {
  it('shows the button for a real extension client id and opens the dialog with that id as the target', async () => {
    openEvent(base);
    fireEvent.click(await (await summary()).findByRole('button', { name: '이 사용자 차단' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('LLM 사용 차단')).toBeInTheDocument();
    expect(within(dialog).getByText(ID_A)).toBeInTheDocument();
    expect(within(dialog).queryByLabelText('차단할 확장 프로그램 ID')).toBeNull();
    expect(within(dialog).getByRole('button', { name: '차단' })).toBeDisabled();   // 사유를 고르기 전에는 못 보낸다
  });

  it('sends the block for this client id with the chosen reason', async () => {
    const add = vi.spyOn(gatewayAccessService, 'addRule').mockResolvedValue({ version: 6 });
    openEvent(base);
    fireEvent.click(await (await summary()).findByRole('button', { name: '이 사용자 차단' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByLabelText('기밀 문서 반복 유출 시도'));
    fireEvent.click(within(dialog).getByRole('button', { name: '차단' }));
    await waitFor(() => expect(add).toHaveBeenCalledWith({ clientId: ID_A, reasons: ['LEAK_DOC_REPEAT'], memo: '', duration: '1d' }, 5));
    expect(await within(dialog).findByText('차단 등록 완료 · v6')).toBeInTheDocument();
  });

  it.each(['unknown-client', 'legacy-gateway', 'Unknown-Client'])('hides the button for the placeholder id %s', async clientId => {
    openEvent({ ...base, clientId });
    const request = await summary();
    expect(request.getByText(clientId)).toBeInTheDocument();
    await waitFor(() => expect(gatewayAccessService.get).toHaveBeenCalled());
    await new Promise(resolve => setTimeout(resolve, 30));
    expect(screen.queryByRole('button', { name: '이 사용자 차단' })).toBeNull();
    expect(screen.queryByText('접속 차단')).toBeNull();
  });

  it('hides the button while the server does not know the access api', async () => {
    vi.spyOn(gatewayAccessService, 'get').mockRejectedValue(new ApiError('x', 'NOT_FOUND', 404));
    openEvent(base);
    await summary();
    await waitFor(() => expect(gatewayAccessService.get).toHaveBeenCalled());
    await new Promise(resolve => setTimeout(resolve, 30));
    expect(screen.queryByRole('button', { name: '이 사용자 차단' })).toBeNull();
  });

  it('hides the button without policy management rights', async () => {
    mode.canManagePolicies = false;
    openEvent(base);
    await summary();
    await waitFor(() => expect(gatewayAccessService.get).toHaveBeenCalled());
    await new Promise(resolve => setTimeout(resolve, 30));
    expect(screen.queryByRole('button', { name: '이 사용자 차단' })).toBeNull();
  });

  it('shows 차단 중 with the remaining time and a link instead of the button when the id is already blocked', async () => {
    vi.spyOn(gatewayAccessService, 'get').mockResolvedValue(docOf([rule]));
    openEvent(base);
    const request = await summary();
    expect(await request.findByText('차단 중 · 남은 시간 1시간 30분')).toBeInTheDocument();
    expect(request.getByRole('link', { name: '접속 차단 보기' })).toHaveAttribute('href', '/policies/access');
    expect(screen.queryByRole('button', { name: '이 사용자 차단' })).toBeNull();
  });

  it('still shows the blocked state to a read-only admin, without the button', async () => {
    mode.canManagePolicies = false;
    vi.spyOn(gatewayAccessService, 'get').mockResolvedValue(docOf([rule]));
    openEvent(base);
    expect(await (await summary()).findByText(/^차단 중 · /)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '이 사용자 차단' })).toBeNull();
  });

  it('shows the alias in front of the client id', async () => {
    vi.spyOn(clientAliasService, 'list').mockResolvedValue({ items: [{ client_id: ID_A, alias: '홍길동 PC' }] });
    openEvent(base);
    const request = await summary();
    expect(await request.findByText('홍길동 PC')).toBeInTheDocument();
    expect(request.getByText(ID_A)).toBeInTheDocument();
  });
});

describe('event shown for an access block (관리자 차단 · 확장 ID 없음)', () => {
  const blocked: SecurityEvent = {
    ...base, detectionOutcome: 'UNAVAILABLE', finalAction: 'BLOCK', contentType: 'prompt', reasonCode: 'client_blocked', accessRuleId: RULE,
    enforcement: { applied: true, httpStatus: 403 },
  };

  it('names it 접속 차단 instead of a detection failure, with the block number', async () => {
    openEvent(blocked);
    const request = await summary();
    expect(request.getByText('차단 번호').nextElementSibling).toHaveTextContent('1a2b3c4d');
    expect(screen.getByRole('heading', { name: '접속 차단' })).toBeInTheDocument();   // 요약 제목
    expect(screen.getAllByText('관리자 설정에 따라 접속 단계에서 차단했습니다. 내용은 검사하지 않았습니다.').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('접속 차단(관리자)', { selector: 'dd' })).toBeInTheDocument();   // 판정 사유 코드
    expect(screen.queryByText('입력 검사 결과 확인 불가')).toBeNull();
    expect(screen.queryByText(/최종 조치가 허용이어도 안전하다고/)).toBeNull();
    expect(screen.queryByText('검사 장애 원인')).toBeNull();
  });

  it('uses the other label when the id was missing', async () => {
    openEvent({ ...blocked, clientId: 'unknown-client', reasonCode: 'client_id_missing', accessRuleId: undefined });
    await summary();
    expect(await screen.findByText('접속 차단(확장 ID 없음)', { selector: 'dd' })).toBeInTheDocument();
    expect(screen.queryByText('차단 번호')).toBeNull();
  });

  it('shows 접속 차단 in the event list instead of 탐지 결과 확인 불가', () => {
    render(<MemoryRouter><EventsTable events={[blocked]} aliases={new Map([[ID_A, '홍길동 PC']])} /></MemoryRouter>);
    const row = screen.getByText('evt-access').closest('tr') as HTMLElement;
    expect(within(row).getByText('검사 안 함 · 접속 차단')).toBeInTheDocument();
    expect(within(row).getByText('접속 차단', { selector: '.inspection-failure' })).toHaveAttribute('title', '접속 차단(관리자)');
    expect(within(row).queryByText('탐지 결과 확인 불가')).toBeNull();
    // 운영 정보 보기에서 별칭이 클라이언트 ID 앞에 나온다
    fireEvent.click(screen.getByRole('button', { name: '운영 정보 보기' }));
    expect(screen.getByText('홍길동 PC')).toBeInTheDocument();
    expect(screen.getByText(ID_A)).toBeInTheDocument();
  });

  it('keeps the plain client id in the list when there is no alias', () => {
    render(<MemoryRouter><EventsTable events={[{ ...base, eventId: 'evt-plain' }]} /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: '운영 정보 보기' }));
    expect(screen.getByText(ID_A)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /별칭/ })).toBeNull();
  });
});

describe('my requests page: access block', () => {
  const KEY = 'A'.repeat(20) + 'b-_' + '9'.repeat(20);
  afterEach(() => { delete (globalThis as { chrome?: unknown }).chrome; });

  it('says the admin limited the use with only the category label when the response carries no reasons', async () => {
    const runtime = { sendMessage: vi.fn((_id: string, _message: unknown, callback: (response: unknown) => void) => queueMicrotask(() => callback({ ok: true, viewerKey: KEY, identityEnabled: true }))) };
    (globalThis as { chrome?: unknown }).chrome = { runtime };
    expect(EXTENSION_ID).toBeTruthy();
    const item = { event_id: 'evt-blocked', occurred_at: '2026-10-12T04:50:00.000Z', target_llm: 'ChatGPT', content_type: 'prompt', final_action: 'BLOCK', protected_document: false, entity_counts: [], reason_code: 'client_blocked' };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = new URL(String(input));
      const body = /evidence$/.test(url.pathname)
        ? { event_id: 'evt-blocked', status: 'NOT_RECORDED', redaction: 'OFF', content_type: 'prompt', final_action: 'BLOCK', reason_code: 'client_blocked' }
        : { items: [item], window_days: 7 };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MyRequestsPage /></QueryClientProvider>);
    expect(await screen.findByText('접속 차단(관리자)')).toBeInTheDocument();   // 사유 이름표(범주)만
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('관리자에 의해 LLM 사용이 제한되어 내용을 검사하지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByText(/검사 기록이 아직 반영되지 않았습니다/)).toBeNull();
    expect(screen.queryByText(/조사|퇴사|기밀 문서 반복/)).toBeNull();
  });
});
