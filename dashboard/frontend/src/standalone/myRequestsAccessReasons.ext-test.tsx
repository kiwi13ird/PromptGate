import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import './zodCsp';
import { ExtensionMyRequestsApp } from './ExtensionMyRequestsApp';
import { setBlockedStatus } from './extensionGate';
import { myRequestsService } from './myRequestsService.extension';

// 확장 프로그램 안 '내 요청 기록'의 접속 차단 안내(1.4.5): llm-gateway.local 중계로 받은 사유·관리자 안내를 그대로 보인다. 값은 모두 가짜.
const KEY = 'A'.repeat(20) + 'b-_' + '9'.repeat(20);
const OWNED_PAC = { levelOfControl: 'controlled_by_this_extension', mode: 'pac_script', matchesSettings: true };
const base = { occurred_at: '2026-10-12T04:50:00.000Z', target_llm: 'ChatGPT', content_type: 'prompt', final_action: 'BLOCK', protected_document: false, entity_counts: [] };
const items = [
  { ...base, event_id: 'evt-a', reason_code: 'client_blocked', reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], user_memo: '보안팀 내선으로 문의', request_id: 'req-ext-a' },
  { ...base, event_id: 'evt-b', reason_code: 'client_id_missing' },
];
const evidence: Record<string, unknown> = {
  'evt-a': { event_id: 'evt-a', status: 'NOT_RECORDED', redaction: 'OFF', content_type: 'prompt', final_action: 'BLOCK', reason_code: 'client_blocked', reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], user_memo: '보안팀 내선으로 문의', request_id: 'req-ext-a' },
  'evt-b': { event_id: 'evt-b', status: 'NOT_RECORDED', redaction: 'OFF', content_type: 'prompt', final_action: 'BLOCK', reason_code: 'client_id_missing' },
};

function install() {
  const sendMessage = vi.fn(async () => ({
    ok: true,
    model: { settings: { gateway: { host: '203.0.113.10', port: 8081 }, identity: { enabled: true } }, identity: { clientId: 'chrome-test', viewerKey: KEY }, runtimeState: { desiredProtection: true } },
    proxy: OWNED_PAC,
  }));
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { id: 'mdeejegfkckeeolcgbkkblnccealmgan', sendMessage },
    storage: { onChanged: { addListener: vi.fn(), removeListener: vi.fn() } },
  };
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = new URL(String(input));
    const match = /^\/__llmsgw\/my\/requests\/([^/]+)\/evidence$/.exec(url.pathname);
    const body = match ? evidence[decodeURIComponent(match[1])] : { items, window_days: 7 };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
}

afterEach(async () => {
  cleanup();
  await new Promise(resolve => setTimeout(resolve, 0));
  vi.restoreAllMocks();
  setBlockedStatus(null);
  delete (globalThis as { chrome?: unknown }).chrome;
});

describe('내 기록: 접속 차단 안내', () => {
  it('목록에 "접속 차단 · 사유: …"와 관리자 안내를, 확장 ID 없음은 고정 사유로 보인다', async () => {
    install();
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ExtensionMyRequestsApp /></QueryClientProvider>);
    const rowA = (await screen.findByText('접속 차단 · 사유: 보안 조사 중 · 관리자 요청')).closest('tr')!;
    expect(within(rowA).getByText('차단')).toBeInTheDocument();
    expect(within(rowA).getByText('관리자 안내: 보안팀 내선으로 문의')).toBeInTheDocument();
    const rowB = screen.getByText('접속 차단 · 사유: 확장 프로그램 식별 정보 없음').closest('tr')!;
    expect(within(rowB).queryByText(/관리자 안내/)).toBeNull();
    expect(document.body.innerHTML).not.toContain(KEY);
  });

  it('상세 보기에도 사유와 관리자 안내가 나온다', async () => {
    const fetchSpy = install();
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ExtensionMyRequestsApp /></QueryClientProvider>);
    const rowA = (await screen.findByText('접속 차단 · 사유: 보안 조사 중 · 관리자 요청')).closest('tr')!;
    fireEvent.click(within(rowA).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('관리자에 의해 LLM 사용이 제한되어 내용을 검사하지 않았습니다.')).toBeInTheDocument();
    expect(screen.getByText('접속 차단 · 사유: 보안 조사 중 · 관리자 요청', { selector: '.dops-my-evidence p' })).toBeInTheDocument();
    expect(screen.getByText('관리자 안내: 보안팀 내선으로 문의', { selector: '.dops-my-evidence p' })).toBeInTheDocument();
    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      'http://llm-gateway.local/__llmsgw/my/requests',
      'http://llm-gateway.local/__llmsgw/my/requests/evt-a/evidence',
    ]);
  });

  it('중계 응답 스키마는 reasons·user_memo를 그대로 통과시킨다', async () => {
    install();
    const list = await myRequestsService.list(KEY);
    expect(list.items[0]).toMatchObject({ reason_code: 'client_blocked', reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], user_memo: '보안팀 내선으로 문의' });
    expect(list.items[1].reasons).toBeUndefined();
    const detail = await myRequestsService.evidence(KEY, 'evt-a');
    expect(detail).toMatchObject({ reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], user_memo: '보안팀 내선으로 문의' });
    // 요청 ID(1.4.7): 중계 응답의 request_id도 그대로 통과, 옛 서버처럼 없으면 undefined
    expect(list.items[0].request_id).toBe('req-ext-a');
    expect(list.items[1].request_id).toBeUndefined();
    expect(detail.request_id).toBe('req-ext-a');
  });

  it('상세 보기 맨 위에 요청 ID와 복사 버튼, 요청 ID가 없는 기록은 줄을 숨긴다', async () => {
    install();
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ExtensionMyRequestsApp /></QueryClientProvider>);
    const rowA = (await screen.findByText('접속 차단 · 사유: 보안 조사 중 · 관리자 요청')).closest('tr')!;
    expect(within(rowA).queryByText(/요청 ID/)).toBeNull();   // 닫힌 줄에는 없다
    fireEvent.click(within(rowA).getByRole('button', { name: '상세 보기' }));
    const value = await screen.findByText('req-ext-a');
    expect(value.closest('.dops-my-reqid')).toHaveTextContent('요청 ID');
    expect(screen.getByRole('button', { name: '요청 ID 복사' })).toBeInTheDocument();
    const rowB = screen.getByText('접속 차단 · 사유: 확장 프로그램 식별 정보 없음').closest('tr')!;
    fireEvent.click(within(rowB).getByRole('button', { name: '상세 보기' }));
    await waitFor(() => expect(screen.getAllByText('관리자에 의해 LLM 사용이 제한되어 내용을 검사하지 않았습니다.')).toHaveLength(2));
    expect(screen.getAllByRole('button', { name: '요청 ID 복사' })).toHaveLength(1);   // 요청 ID가 없는 evt-b는 줄 없음
    expect(document.body.innerHTML).not.toContain(KEY);
  });
});
