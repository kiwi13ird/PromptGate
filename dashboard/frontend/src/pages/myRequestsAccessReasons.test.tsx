import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ownEvidenceSchema, ownRequestListSchema } from '@/src/services/myRequestsService';
import { MyRequestsPage } from './MyRequestsPage';

// 내 요청 기록: 접속 차단 안내(2026-10-12) - 사유(고정 이름표)와 관리자가 공개를 고른 메모. 값은 모두 가짜.
const KEY = 'A'.repeat(20) + 'b-_' + '9'.repeat(20);
const base = { occurred_at: '2026-10-12T04:50:00.000Z', target_llm: 'ChatGPT', content_type: 'prompt', final_action: 'BLOCK', protected_document: false, entity_counts: [] };
const blocked = (id: string, over: Record<string, unknown> = {}) => ({ ...base, event_id: id, reason_code: 'client_blocked', ...over });
const evidenceOf = (id: string, over: Record<string, unknown> = {}) =>
  ({ event_id: id, status: 'NOT_RECORDED', redaction: 'OFF', content_type: 'prompt', final_action: 'BLOCK', reason_code: 'client_blocked', ...over });

function serve(items: unknown[], evidence: Record<string, unknown>) {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { sendMessage: vi.fn((_id: string, _message: unknown, callback: (response: unknown) => void) => queueMicrotask(() => callback({ ok: true, viewerKey: KEY, identityEnabled: true }))) },
  };
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = new URL(String(input));
    const match = /^\/api\/my\/requests\/([^/]+)\/evidence$/.exec(url.pathname);
    const body = match ? evidence[decodeURIComponent(match[1])] : { items, window_days: 7 };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
}
const renderPage = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MyRequestsPage /></QueryClientProvider>);
afterEach(() => { delete (globalThis as { chrome?: unknown }).chrome; });

describe('my requests: schema', () => {
  it('accepts blocked entries with and without reasons and user_memo, in the list and the evidence', () => {
    const list = ownRequestListSchema.parse({ items: [
      blocked('a', { reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], user_memo: '담당자에게 문의' }),
      blocked('b', { reasons: ['LEAVE'], user_memo: null }),
      blocked('c'),
    ], window_days: 7 });
    expect(list.items.map(item => [item.reasons, item.user_memo])).toEqual([[['INVESTIGATION', 'ADMIN_REQUEST'], '담당자에게 문의'], [['LEAVE'], null], [undefined, undefined]]);
    expect(ownEvidenceSchema.parse(evidenceOf('a', { reasons: ['OTHER'], user_memo: '메모' }))).toMatchObject({ reasons: ['OTHER'], user_memo: '메모' });
    expect(ownEvidenceSchema.safeParse(evidenceOf('a', { reasons: 'OTHER' })).success).toBe(false);
  });
});

describe('my requests: 접속 차단 · 사유', () => {
  it('shows the rule reasons in the list and the detail, without any memo that was not shared', async () => {
    serve([blocked('evt-1', { reasons: ['INVESTIGATION', 'ADMIN_REQUEST'] })], { 'evt-1': evidenceOf('evt-1', { reasons: ['INVESTIGATION', 'ADMIN_REQUEST'] }) });
    renderPage();
    const row = (await screen.findByText('접속 차단 · 사유: 보안 조사 중 · 관리자 요청')).closest('tr')!;
    expect(within(row).getByText('차단')).toBeInTheDocument();
    expect(screen.queryByText('접속 차단(관리자)')).toBeNull();   // 사유가 있으면 기본 이름표 대신
    expect(screen.queryByText(/관리자 안내/)).toBeNull();
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('관리자에 의해 LLM 사용이 제한되어 내용을 검사하지 않았습니다.')).toBeInTheDocument();
    expect(screen.getByText('접속 차단 · 사유: 보안 조사 중 · 관리자 요청', { selector: '.dops-my-evidence p' })).toBeInTheDocument();
    expect(screen.queryByText(/관리자 안내/)).toBeNull();
  });

  it('shows 관리자 안내 in the list and the detail when the memo was shared, as plain text', async () => {
    const memo = '<b>담당자</b>에게 문의하세요';
    serve([blocked('evt-1', { reasons: ['OTHER'], user_memo: memo })], { 'evt-1': evidenceOf('evt-1', { reasons: ['OTHER'], user_memo: memo }) });
    renderPage();
    const row = (await screen.findByText('접속 차단 · 사유: 기타')).closest('tr')!;
    expect(within(row).getByText(`관리자 안내: ${memo}`)).toBeInTheDocument();
    expect(row.querySelector('b')).toBeNull();
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText(`관리자 안내: ${memo}`, { selector: '.dops-my-evidence p' })).toBeInTheDocument();
    expect(document.querySelector('.dops-my-evidence b')).toBeNull();
  });

  it('falls back to the list entry when the evidence response carries no reasons', async () => {
    serve([blocked('evt-1', { reasons: ['LEAVE'], user_memo: '인사팀 문의' })], { 'evt-1': evidenceOf('evt-1') });
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('접속 차단 · 사유: 퇴사·휴직 예정', { selector: '.dops-my-evidence p' })).toBeInTheDocument();
    expect(screen.getByText('관리자 안내: 인사팀 문의', { selector: '.dops-my-evidence p' })).toBeInTheDocument();
  });

  it('keeps the old label with no reason line when the rule has no reasons (old server)', async () => {
    serve([blocked('evt-1')], { 'evt-1': evidenceOf('evt-1') });
    renderPage();
    expect(await screen.findByText('접속 차단(관리자)')).toBeInTheDocument();
    expect(screen.queryByText(/사유:/)).toBeNull();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('관리자에 의해 LLM 사용이 제한되어 내용을 검사하지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByText(/사유:|관리자 안내/)).toBeNull();
  });

  it('shows the fixed reason for a request without an extension id, ignoring any reasons sent', async () => {
    serve([blocked('evt-2', { reason_code: 'client_id_missing', reasons: ['INVESTIGATION'], user_memo: '보이면 안 됨' })],
      { 'evt-2': evidenceOf('evt-2', { reason_code: 'client_id_missing' }) });
    renderPage();
    const row = (await screen.findByText('접속 차단 · 사유: 확장 프로그램 식별 정보 없음')).closest('tr')!;
    expect(within(row).queryByText(/보안 조사 중|보이면 안 됨|관리자 안내/)).toBeNull();
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('접속 차단 · 사유: 확장 프로그램 식별 정보 없음', { selector: '.dops-my-evidence p' })).toBeInTheDocument();
  });

  it('does not attach reasons or a memo to other kinds of entries', async () => {
    serve([{ ...base, event_id: 'evt-3', reason_code: 'file_too_large', reasons: ['INVESTIGATION'], user_memo: '다른 건' }], {});
    renderPage();
    expect(await screen.findByText('파일이 커서 검사하지 못함')).toBeInTheDocument();
    expect(screen.queryByText(/보안 조사 중|다른 건|접속 차단/)).toBeNull();
  });

  it('shows the reasons of an attached blocked file too', async () => {
    serve([{ ...base, event_id: 'evt-4', final_action: 'ALLOW', group_final_action: 'BLOCK',
      attached_files: [blocked('evt-5', { content_type: 'file', reasons: ['PII_REPEAT'], user_memo: '파일 안내' })] }], {});
    renderPage();
    const row = (await screen.findByText('접속 차단 · 사유: 개인정보 반복 입력')).closest('tr')!;
    expect(within(row).getByText('관리자 안내: 파일 안내')).toBeInTheDocument();
  });
});
