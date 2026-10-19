import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { askViewerKey, EXTENSION_ID, ownEvidenceSchema, ownRequestListSchema } from '@/src/services/myRequestsService';
import { MyRequestsPage } from './MyRequestsPage';

// 내 요청 기록 (2026-10-09): 확장 프로그램 열람 키로 본인 요청만, 관리자 로그인 없이
const KEY = 'A'.repeat(20) + 'b-_' + '9'.repeat(20);
const at = '2026-10-09T07:50:00.000Z';
const RRN = '900101-1234567';   // 전 화면은 원문 그대로
const promptItem = { event_id: 'evt-prompt', occurred_at: at, target_llm: 'ChatGPT', content_type: 'prompt', final_action: 'ALLOW',
  group_final_action: 'MASK', protected_document: false, entity_counts: [],
  attached_files: [{ event_id: 'evt-file', occurred_at: at, target_llm: 'ChatGPT', content_type: 'file', final_action: 'MASK',
    protected_document: false, entity_counts: [{ entity_type: 'KR_BANK_ACCOUNT', count: 4 }] }] };
const blockedItem = { event_id: 'evt-doc', occurred_at: '2026-10-09T07:40:00.000Z', target_llm: 'ChatGPT', content_type: 'prompt',
  final_action: 'BLOCK', protected_document: true, entity_counts: [] };
const text = (before: string, after: string, start: number, end: number) => ({ status: 'AVAILABLE', format: 'docx', after_recorded: true, ordered: true,
  segments: [{ id: 'prompt', format: 'docx', area: 'body', para: 0, before, after, spans: [{ start, end, entity_type: 'KR_RRN', replacement: '[KR_RRN]' }] }] });
const evidence: Record<string, unknown> = {
  'evt-prompt': { event_id: 'evt-prompt', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'ALLOW',
    // 운영 판정 기록: 허용된 질문은 가린 결과를 남기지 않는다(after 없음)
    prompt_comparison: { status: 'AVAILABLE', format: 'docx', after_recorded: false, ordered: true,
      segments: [{ id: 'prompt', format: 'docx', area: 'body', para: 0, before: '요약해줘', spans: [] }] } },
  'evt-file': { event_id: 'evt-file', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'file', final_action: 'MASK', filename: '요청서.docx',
    file_comparison: { status: 'AVAILABLE', format: 'docx', after_recorded: true, ordered: true, segments: [
      { id: 'body:p0', format: 'docx', area: 'body', para: 0, block_order: 0, before: `주민번호 ${RRN}`, after: '주민번호 [KR_RRN]',
        spans: [{ start: 5, end: 19, entity_type: 'KR_RRN', replacement: '[KR_RRN]' }], decided_by: 'signature' }] } },
  'evt-doc': { event_id: 'evt-doc', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'BLOCK', protected_document: true },
  'evt-sig-block': { event_id: 'evt-sig-block', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'BLOCK',
    prompt_comparison: text(`번호 ${RRN}`, '번호 [KR_RRN]', 3, 17) },
};

type Reply = { ok?: boolean; viewerKey?: string; identityEnabled?: boolean } | undefined;
function installExtension(reply: Reply, lastError?: unknown) {
  const sendMessage = vi.fn((id: string, message: unknown, callback: (response: unknown) => void) => {
    void id; void message;
    queueMicrotask(() => { runtime.lastError = lastError; callback(reply); runtime.lastError = undefined; });
  });
  const runtime: { sendMessage: typeof sendMessage; lastError?: unknown } = { sendMessage };
  (globalThis as { chrome?: unknown }).chrome = { runtime };
  return sendMessage;
}

function mockServer(items: unknown[], status = 200) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = new URL(String(input));
    const evidenceMatch = /^\/api\/my\/requests\/([^/]+)\/evidence$/.exec(url.pathname);
    const body = status !== 200 ? { error: { code: 'VIEWER_KEY_REQUIRED' } }
      : evidenceMatch ? evidence[decodeURIComponent(evidenceMatch[1])] : { items, window_days: 7 };
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MyRequestsPage /></QueryClientProvider>);
}

afterEach(() => {
  vi.restoreAllMocks();
  delete (globalThis as { chrome?: unknown }).chrome;
});

describe('my requests page', () => {
  it('asks only this extension for the key and sends it as a header, never in the address', async () => {
    const sendMessage = installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    const fetchSpy = mockServer([promptItem]);
    renderPage();
    expect(await screen.findByText('프롬프트 + 파일 1')).toBeInTheDocument();
    expect(sendMessage).toHaveBeenCalledWith(EXTENSION_ID, { type: 'GET_VIEWER_KEY' }, expect.any(Function));
    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toMatch(/\/api\/my\/requests$/);
    expect(String(url)).not.toContain(KEY);
    expect(init).toMatchObject({ credentials: 'omit', cache: 'no-store', headers: { 'X-Viewer-Key': KEY } });
    const row = screen.getByText('프롬프트 + 파일 1').closest('tr')!;
    expect(within(row).getByText('마스킹')).toBeInTheDocument();   // 질문은 허용이지만 파일이 가려짐 → 묶음 결과
    expect(within(row).getByText('계좌번호 4')).toBeInTheDocument();
    expect(screen.queryByText(/클라이언트 식별 헤더/)).not.toBeInTheDocument();
  });

  it('opens the question and the attached file before and after', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    const fetchSpy = mockServer([promptItem]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('첨부 파일 1')).toBeInTheDocument();
    expect(await screen.findByText('· 요청서.docx')).toBeInTheDocument();
    expect(within(screen.getByLabelText('마스킹 전 원문')).getByText(RRN).tagName).toBe('MARK');
    expect(within(screen.getByLabelText('실제로 보낸 내용')).getByText('[KR_RRN]')).toBeInTheDocument();   // 파일만 전·후
    expect(screen.getByLabelText('전송 내용')).toHaveTextContent('요약해줘');   // 허용된 질문은 그대로 보낸 글만
    expect(screen.getByText('정상 처리되었습니다.')).toBeInTheDocument();
    expect(screen.queryByText(/기록되지 않았습니다/)).not.toBeInTheDocument();
    expect(screen.getAllByText('칸 번호 표시')).toHaveLength(1);                   // 칸 번호는 파일에만
    const evidenceCalls = fetchSpy.mock.calls.filter(([url]) => String(url).includes('/evidence'));
    expect(evidenceCalls.map(([url]) => new URL(String(url)).pathname).sort())
      .toEqual(['/api/my/requests/evt-file/evidence', '/api/my/requests/evt-prompt/evidence']);
    for (const [, init] of evidenceCalls) expect(init).toMatchObject({ headers: { 'X-Viewer-Key': KEY } });
  });

  it('a masked question shows its before and after as one block', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    mockServer([{ ...blockedItem, event_id: 'evt-sig-mask', final_action: 'MASK', protected_document: false, entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }]);
    evidence['evt-sig-mask'] = { event_id: 'evt-sig-mask', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'MASK',
      prompt_comparison: text(`번호 ${RRN}`, '번호 [KR_RRN]', 3, 17) };
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(within(await screen.findByLabelText('마스킹 전 입력')).getByText(RRN).tagName).toBe('MARK');
    expect(within(screen.getByLabelText('실제로 보낸 내용')).getByText('[KR_RRN]')).toBeInTheDocument();
    expect(screen.getByText('전 · 원문')).toBeInTheDocument();
    expect(screen.queryByText(/개인정보 보호 표시/)).not.toBeInTheDocument();
    expect(screen.queryByText('칸 번호 표시')).not.toBeInTheDocument();
  });

  it('a protected-document block says only that it was blocked', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    mockServer([blockedItem]);
    renderPage();
    const row = (await screen.findByText('차단')).closest('tr')!;
    expect(within(row).getByText('보호 문서')).toBeInTheDocument();
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText(/관리자만 확인할 수 있습니다/)).toBeInTheDocument();
    expect(screen.queryByLabelText('마스킹 전 입력')).not.toBeInTheDocument();
  });

  it('a pattern block shows what was found, with no after side', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    mockServer([{ ...blockedItem, event_id: 'evt-sig-block', protected_document: false, entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText(/차단되어 전송되지 않은 요청/)).toBeInTheDocument();
    expect(screen.queryByLabelText('실제로 보낸 내용')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '후' })).toBeDisabled();
    expect(screen.getByText(RRN)).toHaveAttribute('title', '주민등록번호 · 탐지');
  });

  it('without the extension it explains how to open the page and sends nothing', async () => {
    const fetchSpy = mockServer([]);
    renderPage();
    expect(await screen.findByText('확장 프로그램을 찾을 수 없습니다.')).toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalled();
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    fireEvent.click(screen.getByRole('button', { name: '다시 확인' }));
    expect(await screen.findByText(/마스킹·차단된 요청이 없습니다/)).toBeInTheDocument();
  });

  it('warns when identity headers are off and handles a rejected key', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: false });
    mockServer([], 401);
    renderPage();
    expect(await screen.findByText(/클라이언트 식별 헤더 전송/)).toBeInTheDocument();
    expect(await screen.findByText(/열람 키를 확인할 수 없습니다/)).toBeInTheDocument();
  });
});

// 차단·가림 사유(2026-10-10, 명세 §8.2): 차단·마스킹된 요청·파일에 사유를 보인다(백엔드 ownReasonCode와 같은 규칙).
// 검사 없이 전송된(허용) 파일은 사유를 보이지 않는다
describe('block reasons', () => {
  const file = (event_id: string, final_action: string, reason_code?: string) => ({ event_id, occurred_at: at, target_llm: 'Claude', content_type: 'file',
    final_action, protected_document: false, entity_counts: [], ...(reason_code ? { reason_code } : {}) });
  const notRecorded = (event_id: string, final_action: string, reason_code?: string) => ({ event_id, status: 'NOT_RECORDED', redaction: 'APPLIED',
    content_type: 'file', final_action, ...(reason_code ? { reason_code } : {}) });

  it('shows a reason chip for each blocked request, file_too_large included', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    mockServer([
      file('evt-big', 'BLOCK', 'file_too_large'),
      { ...file('evt-q', 'BLOCK', 'detection_timeout'), content_type: 'prompt' },
      { ...file('evt-scan-group', 'ALLOW'), content_type: 'prompt', group_final_action: 'BLOCK',
        attached_files: [file('evt-scan', 'BLOCK', 'file_uninspectable_scanned_pdf'), file('evt-hwp', 'BLOCK', 'file_uninspectable_other')] },
      { ...file('evt-mask-group', 'MASK'), content_type: 'prompt', entity_counts: [{ entity_type: 'KR_RRN', count: 1 }],
        attached_files: [file('evt-png', 'ALLOW', 'file_uninspectable_image')] },
      file('evt-mask-fail', 'BLOCK', 'mask_application_failed'),
      file('evt-unknown', 'BLOCK', 'some_new_code'),
    ]);
    renderPage();
    expect(await screen.findByText('파일이 커서 검사하지 못함')).toBeInTheDocument();
    expect(screen.getByText('보안 검사 응답 없음')).toBeInTheDocument();
    const groupRow = screen.getByText('검사할 수 없는 파일(스캔 PDF)').closest('tr')!;
    expect(within(groupRow).getByText('검사할 수 없는 파일 형식')).toBeInTheDocument();   // 묶음 안 차단 파일마다
    expect(within(groupRow).getByText('차단')).toBeInTheDocument();
    expect(screen.getByText('마스킹할 수 없음')).toBeInTheDocument();
    const maskRow = screen.getByText('주민등록번호 1').closest('tr')!;
    expect(within(maskRow).queryByText(/검사할 수 없는/)).not.toBeInTheDocument();   // 허용된 이미지는 사유를 보이지 않는다
    expect(screen.queryByText('검사할 수 없는 파일(이미지)')).not.toBeInTheDocument();
    expect(screen.queryByText('some_new_code')).not.toBeInTheDocument();
    expect(screen.queryByText(/file_too_large|detection_timeout|uninspectable/)).not.toBeInTheDocument();
  });

  it('explains why a blocked file was not inspected instead of saying the record is not in yet', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    evidence['evt-big'] = notRecorded('evt-big', 'BLOCK', 'file_too_large');
    evidence['evt-scan'] = notRecorded('evt-scan', 'BLOCK', 'file_uninspectable_scanned_pdf');
    evidence['evt-q'] = { ...notRecorded('evt-q', 'BLOCK', 'detection_unreachable'), content_type: 'prompt' };
    mockServer([file('evt-big', 'BLOCK', 'file_too_large'), file('evt-scan', 'BLOCK', 'file_uninspectable_scanned_pdf'),
      { ...file('evt-q', 'BLOCK', 'detection_unreachable'), content_type: 'prompt' }]);
    renderPage();
    for (const button of await screen.findAllByRole('button', { name: '상세 보기' })) fireEvent.click(button);
    await waitFor(() => expect(screen.getAllByText('검사할 수 없는 파일이라 내용을 검사하지 않았습니다.')).toHaveLength(2));
    expect(await screen.findByText('보안 검사가 제때 끝나지 않아 내용을 검사하지 못했습니다.')).toBeInTheDocument();
    expect(screen.queryByText(/검사 기록이 아직 반영되지 않았습니다/)).not.toBeInTheDocument();
  });

  it('shows the reason of a masked file whose remaining cells went out uninspected', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    // 실제 대시보드 백엔드(dash-work ownRequests·buildOwnEvidence, 가짜 값)가 돌려준 본문 그대로:
    // 칸 일부를 가린 뒤 Detection이 응답하지 않아 나머지는 원본 전송(MASK · UNAVAILABLE · detection_timeout)
    const captured = {"items":[{"event_id":"evt-mask-degraded","occurred_at":"2026-10-10T06:24:01.925Z","target_llm":"ChatGPT","content_type":"file","final_action":"MASK","protected_document":false,"entity_counts":[],"reason_code":"detection_timeout"}],"window_days":7};
    evidence['evt-mask-degraded'] = {"event_id":"evt-mask-degraded","status":"NOT_RECORDED","redaction":"OFF","content_type":"file","final_action":"MASK","reason_code":"detection_timeout"};
    mockServer(captured.items);
    renderPage();
    const row = (await screen.findByText('보안 검사 응답 없음')).closest('tr')!;
    expect(within(row).getByText('마스킹')).toBeInTheDocument();
    fireEvent.click(within(row).getByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('보안 검사가 제때 끝나지 않아 내용을 검사하지 못했습니다.')).toBeInTheDocument();
    expect(screen.queryByText(/검사 기록이 아직 반영되지 않았습니다/)).not.toBeInTheDocument();
  });

  it('keeps the earlier wording for an attached file that was sent without inspection', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    evidence['evt-mask-only'] = { event_id: 'evt-mask-only', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'MASK',
      prompt_comparison: text(`번호 ${RRN}`, '번호 [KR_RRN]', 3, 17) };
    evidence['evt-png'] = notRecorded('evt-png', 'ALLOW', 'file_uninspectable_image');
    mockServer([{ ...file('evt-mask-only', 'MASK'), content_type: 'prompt', entity_counts: [{ entity_type: 'KR_RRN', count: 1 }],
      attached_files: [file('evt-png', 'ALLOW', 'file_uninspectable_image')] }]);
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('첨부 파일 1')).toBeInTheDocument();
    expect(await screen.findByText(/검사 기록이 아직 반영되지 않았습니다/)).toBeInTheDocument();
    expect(screen.queryByText('검사할 수 없는 파일이라 내용을 검사하지 않았습니다.')).not.toBeInTheDocument();
  });
});

// 요청 ID(2026-10-12): 펼친 상세 맨 위에 한 줄 + 복사 버튼. 옛 서버(값 없음)·null·빈 값이면 줄을 숨긴다. 값은 모두 가짜
function stubClipboard(writeText: (text: string) => Promise<void>) {
  const previous = Object.getOwnPropertyDescriptor(window.navigator, 'clipboard');
  Object.defineProperty(window.navigator, 'clipboard', { value: { writeText }, configurable: true });
  return () => {
    if (previous) Object.defineProperty(window.navigator, 'clipboard', previous);
    else delete (window.navigator as { clipboard?: unknown }).clipboard;
  };
}
const protectedEvidence = (event_id: string) => ({ event_id, status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'BLOCK', protected_document: true });

describe('request id', () => {
  it('keeps request_id in the list, the attached files and the evidence; answers without it still parse', () => {
    const list = ownRequestListSchema.parse({ items: [
      { ...promptItem, request_id: 'req-1', attached_files: [{ ...promptItem.attached_files[0], request_id: 'req-1-f' }] },
      blockedItem,
      { ...blockedItem, event_id: 'evt-null', request_id: null },
    ], window_days: 7 });
    expect(list.items.map(item => item.request_id)).toEqual(['req-1', undefined, null]);
    expect(list.items[0].attached_files?.[0].request_id).toBe('req-1-f');
    expect(ownEvidenceSchema.parse({ ...protectedEvidence('evt-doc'), request_id: 'req-doc' }).request_id).toBe('req-doc');
    expect(ownEvidenceSchema.parse(protectedEvidence('evt-doc')).request_id).toBeUndefined();
  });

  it('shows one request ID line at the top of the opened detail and copies it with the keyboard', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    const restore = stubClipboard(writeText);
    try {
      installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
      mockServer([{ ...blockedItem, event_id: 'evt-id-1', request_id: 'req-20261012-a1', final_action: 'MASK', protected_document: false,
        entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }]);
      evidence['evt-id-1'] = { event_id: 'evt-id-1', status: 'AVAILABLE', redaction: 'APPLIED', content_type: 'prompt', final_action: 'MASK',
        request_id: 'req-20261012-a1', prompt_comparison: text(`번호 ${RRN}`, '번호 [KR_RRN]', 3, 17) };
      renderPage();
      const toggle = await screen.findByRole('button', { name: '상세 보기' });
      expect(screen.queryByText('req-20261012-a1')).toBeNull();   // 닫힌 줄에는 보이지 않는다
      await user.click(toggle);
      const value = await screen.findByText('req-20261012-a1');
      const line = value.closest('.dops-my-reqid')!;
      expect(within(line as HTMLElement).getByText('요청 ID')).toBeInTheDocument();
      expect(line.parentElement!.firstElementChild).toBe(line);   // 상세 맨 위
      expect(screen.getByText('관리자에게 문의할 때 이 요청 ID를 알려 주십시오.')).toBeInTheDocument();
      await user.tab();   // 상세 보기 버튼 다음 차례가 복사 버튼
      const copy = screen.getByRole('button', { name: '요청 ID 복사' });
      expect(copy).toHaveFocus();
      await user.keyboard('{Enter}');
      await waitFor(() => expect(writeText).toHaveBeenCalledWith('req-20261012-a1'));
      expect(await screen.findByRole('button', { name: '복사됨' })).toHaveFocus();
      expect(screen.getByText('요청 ID를 복사했습니다.')).toHaveAttribute('role', 'status');
      expect(document.body.innerHTML).not.toContain(KEY);
    } finally { restore(); }
  });

  it('hides the line when the server sends no request ID (old server), null or blank', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    mockServer([{ ...blockedItem, event_id: 'evt-old' }, { ...blockedItem, event_id: 'evt-nullid', request_id: null },
      { ...blockedItem, event_id: 'evt-blankid', request_id: '   ' }]);
    for (const id of ['evt-old', 'evt-nullid', 'evt-blankid']) evidence[id] = protectedEvidence(id);
    renderPage();
    for (const button of await screen.findAllByRole('button', { name: '상세 보기' })) fireEvent.click(button);
    await waitFor(() => expect(screen.getAllByText(/관리자만 확인할 수 있습니다/)).toHaveLength(3));
    expect(screen.queryByText(/요청 ID/)).toBeNull();
    expect(screen.queryByRole('button', { name: '요청 ID 복사' })).toBeNull();
  });

  it('a question with attached files has one line; a file with its own ID shows it small next to its name', async () => {
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    const file = promptItem.attached_files[0];
    mockServer([{ ...promptItem, event_id: 'evt-grp', request_id: 'req-grp-1', attached_files: [
      { ...file, event_id: 'evt-grp-f1', request_id: 'req-grp-1' },    // 대표와 같으면 다시 적지 않는다
      { ...file, event_id: 'evt-grp-f2' },                             // 목록에 없으면 근거 응답의 값을 쓴다
    ] }]);
    const fileEvidence = evidence['evt-file'] as Record<string, unknown>;
    evidence['evt-grp'] = { ...(evidence['evt-prompt'] as Record<string, unknown>), event_id: 'evt-grp', request_id: 'req-grp-1' };
    evidence['evt-grp-f1'] = { ...fileEvidence, event_id: 'evt-grp-f1', request_id: 'req-grp-1' };
    evidence['evt-grp-f2'] = { ...fileEvidence, event_id: 'evt-grp-f2', filename: '명단.docx', request_id: 'req-grp-1-file-2' };
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByText('· 명단.docx')).toBeInTheDocument();
    expect(await screen.findByText('첨부 파일 1')).toBeInTheDocument();
    expect(await screen.findByText('정상 처리되었습니다.')).toBeInTheDocument();   // 질문(대표) 근거도 다 불러온 뒤
    expect(screen.getAllByRole('button', { name: '요청 ID 복사' })).toHaveLength(1);
    expect(screen.getAllByText('req-grp-1')).toHaveLength(1);
    const second = screen.getByText('첨부 파일 2').closest('h3')!;
    expect(within(second).getByText('req-grp-1-file-2')).toBeInTheDocument();
    expect(second.querySelector('.dops-my-reqid-inline')).toHaveTextContent('요청 ID req-grp-1-file-2');
    expect(within(screen.getByText('첨부 파일 1').closest('h3')!).queryByText(/요청 ID/)).toBeNull();
    expect(within(screen.getByText('프롬프트').closest('h3')!).queryByText(/요청 ID/)).toBeNull();
  });

  it('offers a field to copy by hand instead of claiming success when the browser refuses', async () => {
    const restore = stubClipboard(vi.fn().mockRejectedValue(Error('denied')));
    const previous = document.execCommand;
    document.execCommand = vi.fn().mockReturnValue(false);
    try {
      installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
      mockServer([{ ...blockedItem, event_id: 'evt-manual', request_id: 'req-manual-1' }]);
      evidence['evt-manual'] = protectedEvidence('evt-manual');
      renderPage();
      fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
      fireEvent.click(await screen.findByRole('button', { name: '요청 ID 복사' }));
      const field = await screen.findByLabelText('자동 복사가 되지 않았습니다. 아래 칸의 요청 ID를 직접 복사하십시오.');
      expect(field).toHaveValue('req-manual-1');
      expect(field).toHaveAttribute('readonly');
      await waitFor(() => expect(field).toHaveFocus());
      expect(screen.queryByRole('button', { name: '복사됨' })).toBeNull();
      expect(screen.queryByText('요청 ID를 복사했습니다.')).toBeNull();
      expect(screen.queryByText('denied')).toBeNull();
    } finally { document.execCommand = previous; restore(); }
  });
});

describe('asking the extension for the key', () => {
  it('treats errors, malformed keys and silence as unavailable', async () => {
    expect(await askViewerKey()).toEqual({ status: 'NO_EXTENSION' });
    installExtension({ ok: true, viewerKey: KEY }, { message: 'Could not establish connection.' });
    expect(await askViewerKey()).toEqual({ status: 'NO_EXTENSION' });
    installExtension({ ok: true, viewerKey: 'short' });
    expect(await askViewerKey()).toEqual({ status: 'NOT_READY' });
    installExtension({ ok: false, errorCode: 'NOT_ALLOWED' } as Reply);
    expect(await askViewerKey()).toEqual({ status: 'NOT_READY' });
    (globalThis as { chrome?: unknown }).chrome = { runtime: { sendMessage: vi.fn() } };   // 응답 없음
    expect(await askViewerKey(20)).toEqual({ status: 'NO_EXTENSION' });
    (globalThis as { chrome?: unknown }).chrome = { runtime: { sendMessage: () => { throw new Error('Invalid extension id'); } } };
    expect(await askViewerKey()).toEqual({ status: 'NO_EXTENSION' });
    installExtension({ ok: true, viewerKey: KEY, identityEnabled: true });
    await waitFor(async () => expect(await askViewerKey()).toEqual({ status: 'READY', viewerKey: KEY, identityEnabled: true }));
  });
});
