import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import './zodCsp';
import { ApiError } from '@/src/api/errors';
import { ExtensionMyRequestsApp } from './ExtensionMyRequestsApp';
import { PROTECTION_REQUIRED_MESSAGE, getBlockedStatus, readViewerGate, setBlockedStatus, viewerGate } from './extensionGate';
import { shouldRetryQuery } from './extensionQueryClient';
import { GATEWAY_MY_BASE, askViewerKey, isGatewayRelayUrl, myRequestsService } from './myRequestsService.extension';

// 확장 프로그램 안 '내 요청 기록'(1.4.3): 보호 상태 확인(GET_MODEL) → llm-gateway.local(Gateway 중계). 가짜 값만 쓴다.
const KEY = 'A'.repeat(20) + 'b-_' + '9'.repeat(20);
const OTHER_KEY = 'Z'.repeat(43);
const OWNED_PAC = { levelOfControl: 'controlled_by_this_extension', mode: 'pac_script', matchesSettings: true };
const at = '2026-10-09T07:50:00.000Z';
const item = { event_id: 'evt-file', occurred_at: at, target_llm: 'ChatGPT', content_type: 'file', final_action: 'MASK',
  protected_document: false, entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] };
const evidence = { event_id: 'evt-file', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'file', final_action: 'MASK', filename: '요청서.docx',
  file_comparison: { status: 'AVAILABLE', format: 'docx', after_recorded: true, ordered: true, segments: [
    { id: 'body:p0', format: 'docx', area: 'body', para: 0, block_order: 0, before: '주민번호 900101-1234567', after: '주민번호 [KR_RRN]',
      spans: [{ start: 5, end: 19, entity_type: 'KR_RRN', replacement: '[KR_RRN]' }], decided_by: 'signature' }] } };

function model({ protection = true as unknown, host = '203.0.113.10', key = KEY, identity = true } = {}) {
  return { settings: { gateway: { host, port: 8081 }, identity: { enabled: identity } }, identity: { clientId: 'chrome-test', viewerKey: key },
    runtimeState: { desiredProtection: protection } };
}
const ready = (overrides: Parameters<typeof model>[0] = {}) => ({ ok: true, model: model(overrides), proxy: OWNED_PAC });

type StorageListener = (changes: Record<string, unknown>, areaName: string) => void;
// 서비스 워커 대역: GET_MODEL 응답을 바꿔 가며 쓴다. 호출 순서는 log에 남긴다(fetch와 섞어서 본다)
function installExtension(initial: unknown) {
  const log: string[] = [];
  const state = { reply: initial as unknown, fail: null as Error | null };
  const listeners = new Set<StorageListener>();
  const sendMessage = vi.fn(async (message: unknown) => {
    log.push(`message:${(message as { type?: string }).type}`);
    if (state.fail) throw state.fail;
    return structuredClone(state.reply);
  });
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { id: 'mdeejegfkckeeolcgbkkblnccealmgan', sendMessage },
    storage: { onChanged: { addListener: (listener: StorageListener) => listeners.add(listener), removeListener: (listener: StorageListener) => listeners.delete(listener) } },
  };
  const emitChange = (changes: Record<string, unknown>, areaName = 'local') => { for (const listener of Array.from(listeners)) listener(changes, areaName); };
  return { log, state, sendMessage, listeners, emitChange };
}

function mockGateway(log: string[], status = 200) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = new URL(String(input));
    log.push(`fetch:${url.pathname}`);
    const body = status !== 200 ? { error: { code: 'VIEWER_KEY_REQUIRED' } }
      : url.pathname === '/__llmsgw/my/requests/evt-file/evidence' ? evidence : { items: [item], window_days: 7 };
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  });
}

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ExtensionMyRequestsApp /></QueryClientProvider>);
}

async function expectProtectionNotice(status: string) {
  const notice = await screen.findByText(PROTECTION_REQUIRED_MESSAGE);
  expect(notice.closest('[role="alert"]')).toHaveAttribute('data-gate', status);
  expect(document.body.innerHTML).not.toContain(KEY);
}

// 화면을 먼저 내리고, 남은 GET_MODEL 응답이 다 끝난 뒤 공유 상태(안내 화면 전환)를 되돌린다 - 다음 시험으로 새지 않게
afterEach(async () => {
  vi.useRealTimers();
  cleanup();
  await new Promise(resolve => setTimeout(resolve, 0));
  vi.restoreAllMocks();
  setBlockedStatus(null);
  delete (globalThis as { chrome?: unknown }).chrome;
});

describe('보호 상태 판정(GET_MODEL 응답)', () => {
  it('보호 켜짐 + 이 확장 프로그램의 PAC가 설정과 같을 때만 READY', () => {
    expect(viewerGate(model(), OWNED_PAC)).toEqual({ status: 'READY', viewerKey: KEY, identityEnabled: true });
    expect(viewerGate(model({ identity: false }), OWNED_PAC)).toEqual({ status: 'READY', viewerKey: KEY, identityEnabled: false });
  });

  it('보호 꺼짐·Gateway 미설정·PAC 불일치·키 없음을 구분한다', () => {
    expect(viewerGate(model({ protection: false }), OWNED_PAC).status).toBe('PROTECTION_OFF');
    expect(viewerGate(model({ protection: 'true' }), OWNED_PAC).status).toBe('PROTECTION_OFF');
    expect(viewerGate(model({ host: '  ' }), OWNED_PAC).status).toBe('NOT_CONFIGURED');
    // PAC가 llm-gateway.local을 설정된 Gateway가 아닌 곳으로 보냄(원문 불일치)
    expect(viewerGate(model(), { ...OWNED_PAC, matchesSettings: false }).status).toBe('PROXY_CONFLICT');
    expect(viewerGate(model(), { ...OWNED_PAC, levelOfControl: 'controlled_by_other_extensions' }).status).toBe('PROXY_CONFLICT');
    expect(viewerGate(model(), { ...OWNED_PAC, mode: 'fixed_servers' }).status).toBe('PROXY_CONFLICT');
    expect(viewerGate(model(), undefined).status).toBe('PROXY_CONFLICT');
    expect(viewerGate(model({ key: 'short' }), OWNED_PAC).status).toBe('NOT_READY');
    expect(viewerGate(model({ key: `${KEY}x` }), OWNED_PAC).status).toBe('NOT_READY');
    for (const garbage of [null, undefined, [], 'model', 1]) expect(viewerGate(garbage, OWNED_PAC).status).toBe('PROTECTION_OFF');
  });
});

describe('서비스 워커 확인(readViewerGate)', () => {
  it('chrome.runtime.sendMessage로 GET_MODEL 하나만 보낸다', async () => {
    const extension = installExtension(ready());
    expect(await readViewerGate()).toEqual({ status: 'READY', viewerKey: KEY, identityEnabled: true });
    expect(extension.sendMessage).toHaveBeenCalledTimes(1);
    expect(extension.sendMessage).toHaveBeenCalledWith({ type: 'GET_MODEL' });
  });

  it('확장 프로그램 밖·응답 실패·형식 오류·무응답이면 UNAVAILABLE', async () => {
    expect(await readViewerGate()).toEqual({ status: 'UNAVAILABLE' });
    (globalThis as { chrome?: unknown }).chrome = { runtime: { sendMessage: vi.fn(async () => ready()) } };   // runtime.id 없음 = 확장 페이지 아님
    expect(await readViewerGate()).toEqual({ status: 'UNAVAILABLE' });
    const extension = installExtension(ready());
    extension.state.fail = new Error('Extension context invalidated.');
    expect(await readViewerGate()).toEqual({ status: 'UNAVAILABLE' });
    extension.state.fail = null;
    for (const reply of [{ ok: false, errorCode: 'UNKNOWN_MESSAGE' }, undefined, null, 'ok', { model: model(), proxy: OWNED_PAC }]) {
      extension.state.reply = reply;
      expect(await readViewerGate()).toEqual({ status: 'UNAVAILABLE' });
    }
    extension.sendMessage.mockImplementation(() => new Promise(() => undefined));
    expect(await readViewerGate(20)).toEqual({ status: 'UNAVAILABLE' });
  });
});

describe('보호 상태 확인 실패 시 열람 키를 보내지 않는다', () => {
  it('보호 꺼짐: 안내만 보이고 Gateway 요청이 없다', async () => {
    const extension = installExtension(ready({ protection: false }));
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    await expectProtectionNotice('PROTECTION_OFF');
    expect(screen.getByText(/PromptGate 창에서 보호를 켠 뒤/)).toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(extension.log).toEqual(['message:GET_MODEL']);
  });

  it('PAC가 llm-gateway.local을 설정된 Gateway로 보내지 않으면(불일치·다른 확장 프로그램) 요청하지 않는다', async () => {
    const extension = installExtension({ ok: true, model: model(), proxy: { ...OWNED_PAC, matchesSettings: false } });
    const fetchSpy = mockGateway(extension.log);
    const first = renderApp();
    await expectProtectionNotice('PROXY_CONFLICT');
    first.unmount();
    setBlockedStatus(null);
    extension.state.reply = { ok: true, model: model(), proxy: { levelOfControl: 'controlled_by_other_extensions', mode: 'fixed_servers', matchesSettings: false } };
    renderApp();
    await expectProtectionNotice('PROXY_CONFLICT');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('상태 확인 자체가 실패하면(서비스 워커 오류·ok:false) 요청하지 않는다', async () => {
    const extension = installExtension(ready());
    extension.state.fail = new Error('Could not establish connection. Receiving end does not exist.');
    const fetchSpy = mockGateway(extension.log);
    const first = renderApp();
    await expectProtectionNotice('UNAVAILABLE');
    first.unmount();
    setBlockedStatus(null);
    extension.state.fail = null;
    extension.state.reply = { ok: false, errorCode: 'OPERATION_FAILED' };
    renderApp();
    await expectProtectionNotice('UNAVAILABLE');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('Gateway 미설정이면 요청하지 않는다', async () => {
    const extension = installExtension(ready({ host: '' }));
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    await expectProtectionNotice('NOT_CONFIGURED');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('목록을 본 뒤 보호를 끄면 상세 보기 요청을 보내지 않고 안내로 바뀐다', async () => {
    const extension = installExtension(ready());
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    const row = (await screen.findByText('주민등록번호 1')).closest('tr')!;
    extension.state.reply = ready({ protection: false });
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    await expectProtectionNotice('PROTECTION_OFF');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(extension.log).not.toContain('fetch:/__llmsgw/my/requests/evt-file/evidence');
  });

  it('열린 화면에서 보호를 끄면 저장소 변경으로 바로 안내, 다시 켜면 기록 화면으로 돌아온다', async () => {
    const extension = installExtension(ready());
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    await screen.findByText('주민등록번호 1');
    extension.state.reply = ready({ protection: false });
    act(() => extension.emitChange({ runtimeState: { oldValue: { desiredProtection: true }, newValue: { desiredProtection: false } } }));
    await expectProtectionNotice('PROTECTION_OFF');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    // 다른 저장 영역·관계없는 키는 무시
    extension.state.reply = ready();
    const messages = extension.sendMessage.mock.calls.length;
    act(() => { extension.emitChange({ runtimeState: {} }, 'managed'); extension.emitChange({ events: {} }); });
    expect(extension.sendMessage.mock.calls.length).toBe(messages);
    act(() => extension.emitChange({ runtimeState: { oldValue: { desiredProtection: false }, newValue: { desiredProtection: true } } }));
    expect(await screen.findByText('주민등록번호 1')).toBeInTheDocument();
    expect(screen.queryByText(PROTECTION_REQUIRED_MESSAGE)).not.toBeInTheDocument();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("안내 화면의 '다시 확인'은 보호가 켜졌을 때만 기록 화면을 다시 연다", async () => {
    const extension = installExtension(ready({ protection: false }));
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    await expectProtectionNotice('PROTECTION_OFF');
    fireEvent.click(screen.getByRole('button', { name: '다시 확인' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '다시 확인' })).toBeEnabled());
    await expectProtectionNotice('PROTECTION_OFF');
    expect(fetchSpy).not.toHaveBeenCalled();
    extension.state.reply = ready();
    fireEvent.click(screen.getByRole('button', { name: '다시 확인' }));
    expect(await screen.findByText('주민등록번호 1')).toBeInTheDocument();
    expect(getBlockedStatus()).toBeNull();
  });

  it('보호는 켜졌지만 키가 아직 없으면 기존 준비 중 안내(요청 없음)', async () => {
    const extension = installExtension(ready({ key: '' }));
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    expect(await screen.findByText('확장 프로그램 준비 중입니다. 잠시 후 다시 확인하십시오.')).toBeInTheDocument();
    expect(screen.queryByText(PROTECTION_REQUIRED_MESSAGE)).not.toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('확장 프로그램이 가진 키와 다른 키는 보내지 않는다', async () => {
    const extension = installExtension(ready({ key: OTHER_KEY }));
    const fetchSpy = mockGateway(extension.log);
    await expect(myRequestsService.list(KEY)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    extension.state.reply = ready({ protection: false });
    await expect(myRequestsService.evidence(KEY, 'evt-file')).rejects.toMatchObject({ code: 'FORBIDDEN', message: PROTECTION_REQUIRED_MESSAGE });
    expect(getBlockedStatus()).toBe('PROTECTION_OFF');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('확인 중에 호출이 취소되면 요청하지 않는다', async () => {
    const extension = installExtension(ready());
    const fetchSpy = mockGateway(extension.log);
    const controller = new AbortController();
    const pending = myRequestsService.list(KEY, controller.signal);
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(ApiError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('요청 약속(llm-gateway.local 중계)', () => {
  it('목록·상세는 확인 직후 GET, 키는 X-Viewer-Key 머리 하나로만, 쿠키·리디렉트·리퍼러 없이', async () => {
    const extension = installExtension(ready());
    const fetchSpy = mockGateway(extension.log);
    renderApp();
    const row = (await screen.findByText('주민등록번호 1')).closest('tr')!;
    expect(within(row).getByText('마스킹')).toBeInTheDocument();
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('· 요청서.docx')).toBeInTheDocument();
    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      'http://llm-gateway.local/__llmsgw/my/requests',
      'http://llm-gateway.local/__llmsgw/my/requests/evt-file/evidence',
    ]);
    for (const [url, init] of fetchSpy.mock.calls) {
      expect(String(url)).not.toContain(KEY);
      expect(init).toMatchObject({ method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' });
      expect(init?.headers).toEqual({ 'X-Viewer-Key': KEY });
      expect(init?.body).toBeUndefined();
      expect(init?.signal).toBeInstanceOf(AbortSignal);
    }
    // 처음 키 확인 1번 + 요청마다 직전 확인 1번
    expect(extension.log).toEqual(['message:GET_MODEL', 'message:GET_MODEL', 'fetch:/__llmsgw/my/requests', 'message:GET_MODEL', 'fetch:/__llmsgw/my/requests/evt-file/evidence']);
    expect(screen.queryByText(/클라이언트 식별 헤더/)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(KEY);
  });

  it('형식에 맞는 기록 번호만 경로 한 칸으로 보낸다(Gateway 중계 규칙과 같음)', async () => {
    installExtension(ready());
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    for (const id of ['evt-11111111-2222-3333-4444-555555555555', 'evt_a.b-1', 'a..b', '-', 'A'.repeat(128)]) {
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ ...evidence, event_id: id }), { status: 200 }));
      await myRequestsService.evidence(KEY, id);
      expect(String(fetchSpy.mock.lastCall?.[0])).toBe(`${GATEWAY_MY_BASE}requests/${id}/evidence`);
    }
    expect(fetchSpy).toHaveBeenCalledTimes(5);
  });

  it('형식이 틀린 기록 번호는 상태 확인·요청 없이 거절한다(".."이면 중계 경로 밖 /__llmsgw/my/evidence가 되므로)', async () => {
    const extension = installExtension(ready());
    const fetchSpy = mockGateway(extension.log);
    const invalid = ['..', '.', '%2e%2e', '.%2e', 'a/../..', '../a/b?c#d', '', '.hidden', 'A'.repeat(129), 'a b', '기록',
      'a%2Fb', 'evt-1/evidence', 'evt-1?x', 'evt-1#x', 'evt-1\n'];
    for (const id of invalid)
      await expect(myRequestsService.evidence(KEY, id), JSON.stringify(id)).rejects.toMatchObject({ code: 'VALIDATION', message: '기록 번호가 올바르지 않습니다.' });
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(extension.log).toEqual([]);
  });

  it('목록에 형식이 틀린 기록 번호가 오면 상세 보기는 요청하지 않고 기존 오류 문구만', async () => {
    const extension = installExtension(ready());
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      extension.log.push(`fetch:${new URL(String(input)).pathname}`);
      return new Response(JSON.stringify({ items: [{ ...item, event_id: '..' }], window_days: 7 }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    renderApp();
    const row = (await screen.findByText('주민등록번호 1')).closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('파일 기록을 불러올 수 없습니다.')).toBeInTheDocument();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(extension.log.filter(entry => entry.startsWith('fetch:'))).toEqual(['fetch:/__llmsgw/my/requests']);
  });

  it('Gateway 중계 경로(목록·근거 두 가지)가 아닌 주소는 부르지 않는다', () => {
    const list = `${GATEWAY_MY_BASE}requests`;
    expect(isGatewayRelayUrl(list)).toBe(true);
    expect(isGatewayRelayUrl(`${list}/evt-1/evidence`)).toBe(true);
    expect(isGatewayRelayUrl(`${list}/${'a'.repeat(128)}/evidence`)).toBe(true);
    for (const href of ['http://llm-gateway.local/__llmsgw/my/evidence', 'http://llm-gateway.local/__llmsgw/my/', `${list}X`, `${list}/`,
      `${list}/evt-1`, `${list}/evt-1/evidence/x`, `${list}/.x/evidence`, `${list}/a%2Fb/evidence`, `${list}/${'a'.repeat(129)}/evidence`,
      `${list}?x=1`, `${list}#x`, 'http://llm-gateway.local/__llmsgw/health', 'http://llm-gateway.local/__llmsgw/review/x',
      'https://llm-gateway.local/__llmsgw/my/requests', 'http://llm-gateway.local:8080/__llmsgw/my/requests', 'http://evil.example/__llmsgw/my/requests'])
      expect(isGatewayRelayUrl(href), href).toBe(false);
  });

  it('10초 안에 답이 없으면 끊고 시간 초과로 알린다', async () => {
    installExtension(ready());
    vi.useFakeTimers();
    let signal: AbortSignal | undefined;
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      signal = init?.signal ?? undefined;
      signal?.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')));
    }));
    const pending = myRequestsService.list(KEY);
    const outcome = pending.catch((error: unknown) => error);
    for (let turn = 0; turn < 50 && !signal; turn += 1) await Promise.resolve();   // 상태 확인(GET_MODEL) 뒤 fetch까지
    expect(signal).toBeDefined();
    await vi.advanceTimersByTimeAsync(9_999);
    expect(signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await outcome).toMatchObject({ code: 'TIMEOUT' });
  });

  it('너무 큰 응답·JSON이 아닌 응답은 표시하지 않는다', async () => {
    installExtension(ready());
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('{}', { status: 200, headers: { 'Content-Length': String(17 * 1024 * 1024) } }));
    await expect(myRequestsService.list(KEY)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('<html>502</html>', { status: 200 }));
    await expect(myRequestsService.list(KEY)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });

  it('키 거부(401)와 Gateway 연결 실패는 기존 문구로 보인다', async () => {
    const extension = installExtension(ready({ identity: false }));
    mockGateway(extension.log, 401);
    const first = renderApp();
    expect(await screen.findByText(/클라이언트 식별 헤더 전송/)).toBeInTheDocument();
    expect(await screen.findByText(/열람 키를 확인할 수 없습니다/)).toBeInTheDocument();
    first.unmount();
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));
    renderApp();
    expect(await screen.findByText(/기록을 불러올 수 없습니다/)).toBeInTheDocument();
  });

  it('처음 키 확인도 보호 상태를 거친다', async () => {
    installExtension(ready());
    expect(await askViewerKey()).toEqual({ status: 'READY', viewerKey: KEY, identityEnabled: true });
    installExtension(ready({ protection: false }));
    expect(await askViewerKey()).toEqual({ status: 'NOT_READY' });
    expect(getBlockedStatus()).toBe('PROTECTION_OFF');
  });

  it('시간 초과·보호 상태 확인 실패·키 문제는 다시 보내지 않고, 일시 오류만 한 번 더', () => {
    for (const code of ['TIMEOUT', 'FORBIDDEN', 'UNAUTHORIZED', 'VALIDATION'] as const) expect(shouldRetryQuery(0, new ApiError('x', code))).toBe(false);
    for (const code of ['NETWORK', 'SERVER'] as const) {
      expect(shouldRetryQuery(0, new ApiError('x', code))).toBe(true);
      expect(shouldRetryQuery(1, new ApiError('x', code))).toBe(false);
    }
  });

  it('zod JIT를 꺼서 확장 프로그램 CSP 아래에서 eval 확인을 하지 않는다', () => {
    expect(z.config().jitless).toBe(true);
  });
});
