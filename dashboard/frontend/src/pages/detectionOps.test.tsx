import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { toast } from '@/components/ui/toast';
import { ApiError } from '@/src/api/errors';
import { httpClient } from '@/src/api/httpClient';
import { AppLayout } from '@/src/components/AppLayout';
import { GpuStatusBadge } from '@/src/components/GpuStatusBadge';
import { AuthProvider } from '@/src/hooks/useAuth';
import { documentService } from '@/src/services/documentService';
import { detectionOpsService, type DocumentKeyword, type KeywordJob, type Report } from '@/src/services/detectionOpsService';
import { policyService } from '@/src/services/policyService';
import { notifySuccess } from '@/src/utils/feedback';
import type { ConfidentialDocument } from '@/src/types/policy';
import { DocumentKeywordsPage } from './DocumentKeywordsPage';
import { PolicyManagementPage } from './PolicyManagementPage';
import { ReportsPage } from './ReportsPage';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const doc = (id: string, name: string, extra: Partial<ConfidentialDocument> = {}): ConfidentialDocument => ({
  documentId: id, documentName: name, registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'DOCX',
  exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 3, activeDetectors: ['WINDOW_HASH'], ...extra,
});
const kw = (id: number, keyword: string, docId: string, status: 'pending' | 'approved'): DocumentKeyword => ({
  id, keyword, doc_id: docId, status, source: 'llm', reason: '프로젝트 코드', doc_hits: 1, neg_hits: 0,
  created_at: '2026-10-04T05:00:00Z', created_by: null, decided_at: status === 'approved' ? '2026-10-04T06:00:00Z' : null, decided_by: status === 'approved' ? 'admin-1' : null,
});
const job = (id: number, docId: string, status: KeywordJob['status']): KeywordJob => ({ id, doc_id: docId, doc_version: 1, status, attempts: 0, error: status === 'failed' ? 'LLM 응답 오류' : null, created_at: '2026-10-04T05:00:00Z', finished_at: null });
const gpuUp = { connected: true, models: ['qwen3-8b'], latency_ms: 6, error: null, checked_at: '2026-10-06T12:00:00+00:00' };
const gpuDown = { connected: false, models: [], latency_ms: null, error: 'URLError', checked_at: '2026-10-06T12:00:00+00:00' };

function mount(node: React.ReactNode, route: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}>{node}</MemoryRouter></QueryClientProvider>) };
}

function mockKeywordPage({ keywords, jobs = [], gpu = gpuUp, counts }: { keywords: DocumentKeyword[]; jobs?: KeywordJob[]; gpu?: typeof gpuUp | typeof gpuDown; counts?: Partial<Record<KeywordJob['status'], number>> }) {
  vi.spyOn(documentService, 'getDocuments').mockResolvedValue([
    doc('13_파트너사협상자료', '파트너사 협상자료.docx'),
    doc('01_사업전략', '사업전략 보고서.docx'),
    doc('99_색인중', '색인 중 문서.pdf', { chunkIndexStatus: 'PROCESSING' }),
  ]);
  vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue(keywords);
  vi.spyOn(detectionOpsService, 'getKeywordJobs').mockResolvedValue({ jobs, counts: { queued: 0, running: 0, done: 0, failed: 0, ...counts } });
  vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpu);
}

beforeEach(() => vi.restoreAllMocks());

describe('gpu connection status', () => {
  it.each([
    [gpuUp, 'GPU 연결됨'],
    [gpuDown, 'GPU 응답 없음'],
  ])('shows %j', async (status, label) => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(status);
    mount(<GpuStatusBadge />, '/reports');
    expect(await screen.findByText(label)).toBeInTheDocument();
  });
  it('says the status could not be checked when Detection does not answer', async () => {
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockRejectedValue(new ApiError('x', 'SERVER', 503));
    mount(<GpuStatusBadge />, '/reports');
    expect(await screen.findByText('GPU 상태 확인 실패')).toBeInTheDocument();
  });
});

// 재설계 2단계: 정책 탭 줄(PolicyViewTabs)을 없애고 왼쪽 메뉴가 대신한다(설계 2.1). 같은 두 보기로 가는 링크가 메뉴에 있는지 본다
describe('policy views from the main menu', () => {
  it('links the existing policy list and the keyword view from the menu without adding tables to the policy page', async () => {
    window.sessionStorage.setItem('llm-security-gateway-demo-session-v3', JSON.stringify({ id: 'admin-001', email: 'admin@securegate.local', displayName: 'Security Admin', role: 'Gateway Administrator' }));
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([]);
    mount(<AuthProvider><Routes><Route element={<AppLayout />}><Route path="/policies" element={<PolicyManagementPage />} /></Route></Routes></AuthProvider>, '/policies');
    expect(await screen.findByRole('heading', { level: 1, name: '탐지 정책' })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: '탐지 정책 보기' })).toBeNull();
    const menu = screen.getByRole('navigation', { name: '주요 메뉴' });
    expect(within(menu).getByRole('link', { name: '탐지 정책' })).toHaveAttribute('href', '/policies');
    expect(within(menu).getByRole('link', { name: '탐지 정책' })).toHaveAttribute('aria-current', 'page');
    expect(within(menu).getByRole('link', { name: '문서별 키워드' })).toHaveAttribute('href', '/policies/keywords');
    expect(screen.queryByRole('table')).toBeNull();
  });
});

describe('document keywords (HITL)', () => {
  it('shows pending keywords in a review queue and each document with its approved and pending keywords', async () => {
    mockKeywordPage({
      keywords: [kw(1, 'PRJ-2026-07', '13_파트너사협상자료', 'pending'), kw(2, 'TBS', '13_파트너사협상자료', 'pending'), kw(3, '네오보드 3.0', '01_사업전략', 'approved')],
      jobs: [job(4, '01_사업전략', 'done')],
      counts: { done: 1 },
    });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    // 재설계 3a: 승인 대기 후보는 문서 카드마다 표 1개(이름 "승인 대기 키워드 · 문서명"), 대기 없는 문서는 아래 표 1개
    const queue = await screen.findByRole('table', { name: '승인 대기 키워드 · 파트너사 협상자료.docx' });
    const queueRows = within(queue).getAllByRole('row').slice(1);
    expect(queueRows).toHaveLength(2);
    expect(queueRows[0]).toHaveTextContent('PRJ-2026-07');
    expect(queueRows[1]).toHaveTextContent('TBS');
    expect(screen.getByRole('heading', { name: '승인 대기 키워드 2개' })).toBeInTheDocument();
    const card = screen.getByRole('article', { name: '파트너사 협상자료.docx' });
    expect(card).toHaveTextContent('대기 2');
    expect(within(card).getByRole('table', { name: '승인 대기 키워드 · 파트너사 협상자료.docx' })).toBe(queue);
    const rows = within(screen.getByRole('table', { name: '대기 없는 문서' })).getAllByRole('row');
    expect(rows[1]).toHaveTextContent('사업전략 보고서.docx');
    expect(rows[1]).toHaveTextContent('승인 1');
    expect(rows[1]).toHaveTextContent('네오보드 3.0');
    expect(rows[1]).toHaveTextContent('추출 완료');
    const summary = screen.getByRole('group', { name: '키워드 현황' });
    expect(summary).toHaveTextContent('승인 대기 2');
    expect(summary).toHaveTextContent('승인됨 1');
  });
  it('approves from the review queue and flags a detection reload failure for retry', async () => {
    mockKeywordPage({ keywords: [kw(1, 'PRJ-2026-07', '13_파트너사협상자료', 'pending')] });
    const approve = vi.spyOn(detectionOpsService, 'approveKeyword').mockResolvedValue({ ...kw(1, 'PRJ-2026-07', '13_파트너사협상자료', 'approved'), applied: false, apply_error: 'reload failed' });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const queue = await screen.findByRole('table', { name: /^승인 대기 키워드 · / });
    fireEvent.click(within(queue).getByRole('button', { name: '승인' }));
    await waitFor(() => expect(approve).toHaveBeenCalledWith(1));
    expect(await screen.findByText('탐지 반영 실패')).toBeInTheDocument();   // 후보 행의 주의 배지(3a)
  });
  it('rejects a pending keyword after confirmation', async () => {
    mockKeywordPage({ keywords: [kw(2, 'TBS', '13_파트너사협상자료', 'pending')] });
    const reject = vi.spyOn(detectionOpsService, 'rejectKeyword').mockResolvedValue({ applied: false });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    fireEvent.click(within(await screen.findByRole('table', { name: /^승인 대기 키워드 · / })).getByRole('button', { name: '반려' }));
    const dialog = await screen.findByRole('dialog', { name: '반려 · TBS' });   // 확인창 제목 "행동 · 대상"(설계 4.11)
    fireEvent.click(within(dialog).getByRole('button', { name: '반려' }));
    await waitFor(() => expect(reject).toHaveBeenCalledWith(2));
  });
  it('deletes an approved keyword from the document keyword management after confirmation', async () => {
    mockKeywordPage({ keywords: [kw(3, '네오보드 3.0', '01_사업전략', 'approved')] });
    const reject = vi.spyOn(detectionOpsService, 'rejectKeyword').mockResolvedValue({ applied: true });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    expect(await screen.findByText(/승인 대기 중인 키워드가 없습니다/)).toBeInTheDocument();
    const row = screen.getByText('사업전략 보고서.docx').closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: '키워드 관리' }));
    const detail = screen.getByRole('table', { name: '사업전략 보고서.docx 키워드' });
    fireEvent.click(within(detail).getByRole('button', { name: '삭제' }));
    const dialog = await screen.findByRole('dialog', { name: '삭제 · 네오보드 3.0' });
    expect(dialog).toHaveTextContent('탐지에서도 바로 빠집니다');
    expect(reject).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: '삭제' }));
    await waitFor(() => expect(reject).toHaveBeenCalledWith(3));
  });
  it('adds a keyword to the opened document, optionally approved', async () => {
    mockKeywordPage({ keywords: [] });
    const add = vi.spyOn(detectionOpsService, 'addKeyword').mockResolvedValue({ ...kw(9, 'TBS 수수료', '13_파트너사협상자료', 'approved'), source: 'manual', applied: true });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const row = (await screen.findByText('파트너사 협상자료.docx')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: '키워드 관리' }));
    fireEvent.change(screen.getByLabelText('추가할 키워드'), { target: { value: '  TBS 수수료 ' } });
    fireEvent.click(screen.getByLabelText('바로 승인'));
    fireEvent.click(screen.getByRole('button', { name: '키워드 추가' }));
    await waitFor(() => expect(add).toHaveBeenCalledWith('TBS 수수료', '13_파트너사협상자료', true));
  });
  it('requests extraction only for indexed documents without a running job, and retries failed jobs', async () => {
    mockKeywordPage({ keywords: [], jobs: [job(6, '13_파트너사협상자료', 'running'), job(7, '01_사업전략', 'failed')], counts: { running: 1, failed: 1 } });
    const extract = vi.spyOn(detectionOpsService, 'requestExtraction');
    const retry = vi.spyOn(detectionOpsService, 'retryJob').mockResolvedValue(job(7, '01_사업전략', 'queued'));
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const rowOf = async (name: string) => (await screen.findByText(name)).closest('tr') as HTMLElement;
    expect(within(await rowOf('파트너사 협상자료.docx')).getByRole('button', { name: '추출 요청' })).toBeDisabled();
    expect(within(await rowOf('색인 중 문서.pdf')).getByRole('button', { name: '추출 요청' })).toBeDisabled();
    fireEvent.click(within(await rowOf('사업전략 보고서.docx')).getByRole('button', { name: '추출 재시도' }));
    await waitFor(() => expect(retry).toHaveBeenCalledWith(7));
    expect(extract).not.toHaveBeenCalled();
  });
  it('announces when a requested extraction finishes and shows the new candidates for review', async () => {
    mockKeywordPage({ keywords: [], jobs: [job(8, '13_파트너사협상자료', 'running')], counts: { running: 1 } });
    const { client } = mount(<DocumentKeywordsPage />, '/policies/keywords');
    expect(await screen.findByText(/추출 중입니다/)).toBeInTheDocument();
    vi.mocked(detectionOpsService.getKeywordJobs).mockResolvedValue({ jobs: [{ ...job(8, '13_파트너사협상자료', 'done'), finished_at: '2026-10-07T00:00:00Z' }], counts: { queued: 0, running: 0, done: 1, failed: 0 } });
    vi.mocked(detectionOpsService.getKeywords).mockResolvedValue([kw(20, '간사이 파일럿', '13_파트너사협상자료', 'pending')]);
    await client.invalidateQueries({ queryKey: ['detection-ops'] });
    await waitFor(() => expect(notifySuccess).toHaveBeenCalledWith('키워드 추출 완료 · 파트너사 협상자료.docx', expect.any(String)));
    expect(await screen.findByRole('table', { name: /^승인 대기 키워드 · / })).toHaveTextContent('간사이 파일럿');
  });
  it('edits a pending keyword in place and keeps it pending', async () => {
    mockKeywordPage({ keywords: [kw(1, '총 투자 규모: 약 24억원', '13_파트너사협상자료', 'pending')] });
    const update = vi.spyOn(detectionOpsService, 'updateKeyword').mockResolvedValue({ ...kw(1, '24억원', '13_파트너사협상자료', 'pending'), doc_hits: null, neg_hits: null });
    const approve = vi.spyOn(detectionOpsService, 'approveKeyword');
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const queue = await screen.findByRole('table', { name: /^승인 대기 키워드 · / });
    fireEvent.click(within(queue).getByRole('button', { name: '수정' }));
    const input = within(queue).getByLabelText('총 투자 규모: 약 24억원 수정');
    expect(within(queue).getByRole('button', { name: '저장' })).toBeDisabled(); // 바뀐 것이 없으면 저장할 수 없다
    fireEvent.change(input, { target: { value: ' 24억원 ' } });
    fireEvent.click(within(queue).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(update).toHaveBeenCalledWith(1, '24억원'));
    expect(approve).not.toHaveBeenCalled();
    await waitFor(() => expect(within(queue).queryByLabelText('총 투자 규모: 약 24억원 수정')).not.toBeInTheDocument());
  });
  it('saves and approves an edited keyword in one step', async () => {
    mockKeywordPage({ keywords: [kw(1, '총 투자 규모: 약 24억원', '13_파트너사협상자료', 'pending')] });
    const update = vi.spyOn(detectionOpsService, 'updateKeyword').mockResolvedValue(kw(1, '24억원', '13_파트너사협상자료', 'pending'));
    const approve = vi.spyOn(detectionOpsService, 'approveKeyword').mockResolvedValue({ ...kw(1, '24억원', '13_파트너사협상자료', 'approved'), applied: true });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const queue = await screen.findByRole('table', { name: /^승인 대기 키워드 · / });
    fireEvent.click(within(queue).getByRole('button', { name: '수정' }));
    fireEvent.change(within(queue).getByLabelText('총 투자 규모: 약 24억원 수정'), { target: { value: '24억원' } });
    fireEvent.click(within(queue).getByRole('button', { name: '저장 후 승인' }));
    await waitFor(() => expect(approve).toHaveBeenCalledWith(1));
    expect(update.mock.invocationCallOrder[0]).toBeLessThan(approve.mock.invocationCallOrder[0]);
  });
  it('keeps the editor open and explains a conflict when the edit is rejected', async () => {
    mockKeywordPage({ keywords: [kw(1, 'TBS', '13_파트너사협상자료', 'pending')] });
    vi.spyOn(detectionOpsService, 'updateKeyword').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    const notice = vi.spyOn(toast, 'add');
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const queue = await screen.findByRole('table', { name: /^승인 대기 키워드 · / });
    fireEvent.click(within(queue).getByRole('button', { name: '수정' }));
    fireEvent.change(within(queue).getByLabelText('TBS 수정'), { target: { value: 'SPK' } });
    fireEvent.click(within(queue).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(notice).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining('그사이 승인된 키워드') })));
    expect(within(queue).getByLabelText('TBS 수정')).toHaveValue('SPK');
  });
  it('shows the selection reason with evidence sentences, a generic-expression badge and the automatic check result', async () => {
    const withReason: DocumentKeyword = {
      ...kw(1, 'PRJ-2026-07', '13_파트너사협상자료', 'pending'),
      reason: '일본 진출 프로젝트 코드명이라 외부에 알려지면 사업 계획이 노출될 수 있다.',
      evidence: 'prj-2026-07 일본 진출 계획은 이사회 승인 안건이다.\n두 번째 용례 PRJ-2026-07 입니다.',
      reason_check: { ok: true, source: 'llm', foreign_tokens: [], specificity: '일반', kind: '표제·항목명' },
    };
    const shortFallback: DocumentKeyword = {
      ...kw(2, 'TBS', '13_파트너사협상자료', 'pending'), reason: '협상 상대', evidence: 'TBS 담당자와 미팅',
      reason_check: { ok: false, source: 'short', foreign_tokens: ['Samsung'] },
    };
    mockKeywordPage({ keywords: [withReason, shortFallback, kw(3, '네오보드 3.0', '01_사업전략', 'pending')] });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const queue = await screen.findByRole('region', { name: '승인 대기 키워드 3개' });   // 3a: 두 문서 카드의 후보를 함께 본다
    expect(within(queue).getByText('일본 진출 프로젝트 코드명이라 외부에 알려지면 사업 계획이 노출될 수 있다.')).toBeInTheDocument();
    expect(within(queue).getAllByText(/일반적인 표현일 수 있습니다/)).toHaveLength(1);          // '일반'으로 판정된 행에만
    expect(within(queue).getByText(/일반적인 표현일 수 있습니다\(표제·항목명\)/)).toBeInTheDocument();   // 표현 종류를 같이 보여 줌
    const evidence = within(queue).getAllByText('근거 문장');
    expect(evidence).toHaveLength(2);                                            // 근거가 있는 두 행에만
    const marks = Array.from(queue.querySelectorAll('.dops-evidence mark')).map(node => node.textContent);
    expect(marks).toEqual(['prj-2026-07', 'PRJ-2026-07', 'TBS']);                // 키워드를 대소문자 무시로 굵게, 본문 글자 그대로
    expect(within(queue).getAllByText(/자동 설명 검사를 통과하지 못해/)).toHaveLength(1);   // 검사 미통과 행에만
    expect(within(queue).getByText('프로젝트 코드')).toBeInTheDocument();           // 옛 행(필드 없음)도 그대로 보임
  });
  it('offers editing only for pending keywords', async () => {
    mockKeywordPage({ keywords: [kw(3, '네오보드 3.0', '01_사업전략', 'approved')] });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const row = (await screen.findByText('사업전략 보고서.docx')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: '키워드 관리' }));
    const detail = screen.getByRole('table', { name: '사업전략 보고서.docx 키워드' });
    expect(within(detail).queryByRole('button', { name: '수정' })).not.toBeInTheDocument();
    expect(within(detail).getByRole('button', { name: '삭제' })).toBeInTheDocument();
  });
  // 재설계 3a(설계 5.5): 보기 세그먼트·근거 기본 펼침(4개 이상이면 3개 + 더보기)·무관 문장 주의 바탕·카드 칸 역할
  it('switches the document view with the segment and keeps every action reachable', async () => {
    mockKeywordPage({
      keywords: [kw(1, 'PRJ-2026-07', '13_파트너사협상자료', 'pending'), kw(3, '네오보드 3.0', '01_사업전략', 'approved')],
      jobs: [job(7, '01_사업전략', 'failed')], counts: { failed: 1 },
    });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    await screen.findByRole('table', { name: '승인 대기 키워드 · 파트너사 협상자료.docx' });
    const view = screen.getByRole('group', { name: '키워드 현황' });
    expect(within(view).getByRole('radio', { name: /승인 대기/ })).toBeChecked();
    expect(screen.getAllByRole('article').map(card => card.getAttribute('aria-labelledby') && within(card).getByRole('heading').textContent)).toEqual(['파트너사 협상자료.docx']);
    fireEvent.click(within(view).getByRole('radio', { name: /승인됨/ }));
    expect(screen.getAllByRole('article').map(card => within(card).getByRole('heading').textContent)).toEqual(['사업전략 보고서.docx']);
    expect(screen.queryByRole('table', { name: '대기 없는 문서' })).toBeNull();
    fireEvent.click(within(view).getByRole('radio', { name: /추출 실패/ }));
    const failedCard = screen.getByRole('article', { name: '사업전략 보고서.docx' });
    expect(failedCard).toHaveTextContent('추출 실패');
    expect(within(failedCard).getByRole('button', { name: '추출 재시도' })).toBeEnabled();
    fireEvent.click(within(view).getByRole('radio', { name: /전체 문서/ }));
    expect(screen.getAllByRole('article')).toHaveLength(3);
  });
  it('opens evidence by default, folds more than three sentences and marks unrelated hits', async () => {
    const many: DocumentKeyword = { ...kw(1, 'SPK', '13_파트너사협상자료', 'pending'), neg_hits: 14, evidence: ['SPK 1', 'SPK 2', 'SPK 3', 'SPK 4', 'SPK 5'].join(String.fromCharCode(10)) };
    mockKeywordPage({ keywords: [many] });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    const table = await screen.findByRole('table', { name: '승인 대기 키워드 · 파트너사 협상자료.docx' });
    expect(table.querySelectorAll('.dops-evidence p')).toHaveLength(3);
    fireEvent.click(within(table).getByRole('button', { name: '더보기 2' }));
    expect(table.querySelectorAll('.dops-evidence p')).toHaveLength(5);
    expect(within(table).getByText('무관 문장 포함', { selector: '.pg-kw-count span' }).closest('.pg-kw-count')).toHaveClass('is-warn');
    expect(within(table).getByText('보호 문서 포함', { selector: '.pg-kw-count span' }).closest('.pg-kw-count')).not.toHaveClass('is-warn');
    const [row] = within(table).getAllByRole('row').slice(1);
    expect([...row.querySelectorAll('td')].map(cell => cell.getAttribute('data-card'))).toEqual(['title', 'body', null, null, 'actions']);
    expect(within(row.querySelector('[data-card="actions"]') as HTMLElement).getAllByRole('button').map(button => button.textContent)).toEqual(['승인', '수정', '반려']);
  });
  it('explains queued extraction while the gpu does not answer', async () => {
    mockKeywordPage({ keywords: [], jobs: [job(8, '13_파트너사협상자료', 'queued')], gpu: gpuDown, counts: { queued: 1 } });
    mount(<DocumentKeywordsPage />, '/policies/keywords');
    expect(await screen.findByText(/GPU가 응답하지 않아 추출 요청 1건이 대기 중/)).toBeInTheDocument();
  });
});

describe('reports', () => {
  // 2026-10-12 이전 방식 보고서(10/1~10/11 생성): 새 상태 칸이 없다
  const done: Report = { report_id: 'report_2026-09-15_2026-09-30_20261004T000000', status: 'done', from: '2026-09-15', to: '2026-09-30', generated_at: '2026-10-04T00:00:30Z', rows: 1234 };
  // 설계 v2 방식 보고서(값은 가짜)
  const fresh: Report = {
    report_id: 'report_2026-10-01_2026-10-12_20261012T060000', status: 'done', from: '2026-10-01', to: '2026-10-12', compare_from: '2026-09-19', compare_to: '2026-09-30',
    generated_at: '2026-10-12T06:03:00Z', items: 242, rows: 25241,
    incidents: { total: 62, by_grade: { '1': 11, '2': 5, '3': 7, '4': 4, '5': 35 } }, users_high: 2,
  };
  const list = (reports: Report[], contentTrendEnabled: boolean | null = true) => ({ reports, contentTrendEnabled });
  const cells = (table: HTMLElement, row: number) => within(within(table).getAllByRole('row')[row]).getAllByRole('cell');
  const started = { report_id: 'report_2026-09-01_2026-09-30_20261006T000000', status: 'running' as const, from: '2026-09-01', to: '2026-09-30' };
  const pickPeriod = (from: string, to: string) => {
    fireEvent.change(screen.getByLabelText('시작일'), { target: { value: from } });
    fireEvent.change(screen.getByLabelText('종료일'), { target: { value: to } });
  };

  it('lists finished reports with new-tab and download links and the checked count', async () => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([done], null));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    mount(<ReportsPage />, '/reports');
    const table = await screen.findByRole('table', { name: '생성한 리포트' });
    // 재설계 3g(설계 5.11): [열기](새 탭) + ⋯ 메뉴 안 내려받기
    expect(within(table).getByRole('link', { name: '열기' })).toHaveAttribute('href', expect.stringMatching(/\/api\/reports\/report_2026-09-15_2026-09-30_20261004T000000\/file$/));
    expect(within(table).getByRole('link', { name: '열기' })).toHaveAttribute('target', '_blank');
    expect(within(table).getByRole('link', { name: '열기' })).toHaveAttribute('title', '새 탭에서 보기');
    fireEvent.click(within(table).getByRole('button', { name: '2026-09-15 ~ 2026-09-30 더보기' }));
    expect(screen.getByRole('menuitem', { name: '내려받기' })).toHaveAttribute('href', expect.stringMatching(/file\?download=1$/));
    // 옛 보고서: 판정 기록 행 수는 '분석 N건'(설계 2.2), 비교 기간 없음. 사건·높음 사용자는 모든 행이 비어 열을 숨김(설계 4.5)
    expect(within(table).getAllByRole('columnheader').map(header => header.textContent)).toEqual(['기간', '상태', '생성 시각', '분석', '보기']);
    const [period, , , checked] = cells(table, 1);
    expect(checked).toHaveTextContent('분석 1,234건');
    expect(period).not.toHaveTextContent('비교');
  });
  it('shows period with compare period, status, generated time, checked, incidents, high users, and the view links', async () => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([fresh]));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    mount(<ReportsPage />, '/reports');
    const table = await screen.findByRole('table', { name: '생성한 리포트' });
    expect(within(table).getAllByRole('columnheader').map(header => header.textContent)).toEqual(['기간', '상태', '생성 시각', '분석', '사건', '높음 사용자', '보기']);
    const [period, status, , checked, incidents, high, actions] = cells(table, 1);
    expect(period).toHaveTextContent('2026-10-01 ~ 2026-10-12');
    expect(period).toHaveTextContent('비교: 9/19~9/30');
    expect(status).toHaveTextContent('완료');
    expect(checked).toHaveTextContent('242건');
    expect(incidents.textContent).toBe('62건');
    expect(incidents).toHaveAttribute('title', '사건 등급별 · 기밀 차단 11 · 인증정보 5 · 검사 없이 통과 7 · 그 밖 차단 4 · 마스킹만 35');
    expect(high).toHaveTextContent('2명');
    expect(within(actions).getByRole('link', { name: '열기' })).toBeInTheDocument();
    fireEvent.click(within(actions).getByRole('button', { name: '2026-10-01 ~ 2026-10-12 더보기' }));   // 행 조치 2개 + ⋯(설계 4.5)
    expect(within(actions).getByRole('menuitem', { name: '내려받기' })).toBeInTheDocument();
    expect(within(actions).getByRole('menuitem', { name: '다시 만들기' })).toBeInTheDocument();
  });
  it('shows nothing about how a report was written, even if the server still sends those fields', async () => {
    const written = {
      use_llm: true, llm_used: true, mode: 'partial', writer: 'qwen3-8b · LLM 41문장 · 버림 3 · 일부 집계 문장', llm_lines: 41, llm_dropped: 3, llm_error: 'URLError',
      llm_ms: 96_000, agg_ms: 900, gpu_waited_s: 152.5, content_trend: true, content_trend_state: 'on',
    };
    const llmDone = { ...fresh, ...written, incidents: { total: 62, narrated: 12, by_grade: { '1': 11 } } };
    const sqlDone = { ...fresh, ...written, report_id: 'report_2026-09-01_2026-09-14_20261012T060000', mode: 'sql', use_llm: false, llm_lines: 0, content_trend_state: 'no_llm' };
    const running = { report_id: 'report_2026-10-07_2026-10-12_20261012T070000', status: 'running', stage: 'llm', llm_progress: '5/15', from: '2026-10-07', to: '2026-10-12', use_llm: true, content_trend: true, elapsed_seconds: 41 };
    vi.spyOn(httpClient, 'get').mockResolvedValue({ reports: [running, llmDone, sqlDone], content_trend_enabled: true });
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    mount(<ReportsPage />, '/reports');
    const table = await screen.findByRole('table', { name: '생성한 리포트' });
    expect(within(cells(table, 1)[1]).getByText('분석 중 · 41초')).toBeInTheDocument();
    expect(table.textContent).not.toMatch(/LLM|GPU|qwen|버림|집계 문장|일부 집계|\d+문장|5\/15|내용 경향|작성|소요/);
    expect(cells(table, 2)[4].textContent).toBe('62건');   // 서술한 사건 수(narrated)는 보이지 않는다
    expect(document.querySelector('.dops-report-form')?.textContent).not.toMatch(/LLM/);
  });
  it('says 비교 불가 for a new report that has no compare period', async () => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([{ ...fresh, compare_from: null, compare_to: null }]));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    mount(<ReportsPage />, '/reports');
    const table = await screen.findByRole('table', { name: '생성한 리포트' });
    expect(cells(table, 1)[0]).toHaveTextContent('비교 불가');
  });
  it('shows the running stage and blocks a second request', async () => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([{ report_id: 'report_2026-10-01_2026-10-06_20261006T000000', status: 'running', stage: 'writing', from: '2026-10-01', to: '2026-10-06', elapsed_seconds: 12 }]));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    mount(<ReportsPage />, '/reports');
    expect(await screen.findByText(/생성 중 · 2026-10-01 ~ 2026-10-06/)).toHaveTextContent('분석 중 · 12초');
    expect(screen.getByRole('button', { name: '리포트 생성' })).toBeDisabled();
  });
  it.each([
    [{ stage: 'aggregating' }, '집계 중 · 41초'],
    [{ stage: 'incidents' }, '집계 중 · 41초'],
    [{ stage: 'gpu_stopping' }, '분석 준비 중 · 41초'],
    [{ stage: 'gpu_starting' }, '분석 준비 중 · 41초'],
    [{ stage: 'gpu_booting' }, '분석 준비 중 · 41초'],
    [{ stage: 'llm' }, '분석 중 · 41초'],
    [{ stage: 'writing' }, '분석 중 · 41초'],
    [{ stage: 'rendering' }, '파일 만드는 중 · 41초'],
    [{ stage: 'gpu_stopping_after' }, '마무리 중 · 41초'],
    [{ stage: null }, '준비 중 · 41초'],
    [{ stage: 'a_stage_added_later' }, '준비 중 · 41초'],
  ] as const)('labels a running report %j as %s', async (extra, label) => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([{ report_id: 'report_2026-10-01_2026-10-06_20261006T000000', status: 'running', from: '2026-10-01', to: '2026-10-06', elapsed_seconds: 41, ...extra }]));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    mount(<ReportsPage />, '/reports');
    expect(await screen.findByText(/생성 중 · 2026-10-01 ~ 2026-10-06/)).toHaveTextContent(label);
    expect(within(cells(screen.getByRole('table', { name: '생성한 리포트' }), 1)[1]).getByText(label)).toBeInTheDocument();
    expect(label).not.toMatch(/LLM|GPU/);
  });
  it('validates the period before calling the API and sends the chosen dates', async () => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], null));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuDown);
    const create = vi.spyOn(detectionOpsService, 'createReport').mockResolvedValue(started);
    mount(<ReportsPage />, '/reports');
    await screen.findByText('아직 만든 리포트가 없습니다.');
    expect(screen.getByText(/GPU 꺼짐 · 켜지 못하면 분석 문장 없이 작성/)).toBeInTheDocument();
    pickPeriod('2026-09-30', '2026-09-01');
    fireEvent.click(screen.getByRole('button', { name: '리포트 생성' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('종료일은 시작일과 같거나 뒤여야 합니다');
    expect(create).not.toHaveBeenCalled();
    pickPeriod('2026-09-01', '2026-09-30');
    fireEvent.click(screen.getByRole('button', { name: '리포트 생성' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith('2026-09-01', '2026-09-30', true));
  });
  it('explains a conflict when another report is already being made', async () => {
    vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([]));
    vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    vi.spyOn(detectionOpsService, 'createReport').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
    mount(<ReportsPage />, '/reports');
    await screen.findByText('아직 만든 리포트가 없습니다.');
    pickPeriod('2026-09-01', '2026-09-30');
    fireEvent.click(screen.getByRole('button', { name: '리포트 생성' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('이미 만들고 있는 리포트가 있습니다');
  });

  describe('period presets and compare period', () => {
    beforeEach(() => {
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(Date.parse('2026-10-12T00:30:00Z'));   // 한국 시각 10/12 09:30
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], null));
      vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    });
    afterEach(() => vi.useRealTimers());
    // 재설계 3g: 바로 고르기는 기간 세그먼트(속은 라디오) — 눌린 것 = 선택된 라디오
    const pressed = () => screen.getAllByRole<HTMLInputElement>('radio').filter(radio => radio.checked).map(radio => radio.closest('label')?.textContent);
    // 2026-10-15 감사 9·10번: 비교 가능 여부(그 기간 기록)와 끝날이 오늘이면 이번 기간이 짧다는 것을 같은 줄에 적는다
    const compareLine = (range: string, endsToday: boolean) => `비교 기간 · ${range} (직전 같은 길이 · 그 기간에 기록이 없으면 '비교 불가')${endsToday ? ' · 끝날이 오늘이라 이번 기간은 지금 시각까지만 셈(비교 기간보다 짧음)' : ''}`;

    it('starts with the last 7 days and shows the previous period of the same length', async () => {
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      expect(screen.getByLabelText('시작일')).toHaveValue('2026-10-06');
      expect(screen.getByLabelText('종료일')).toHaveValue('2026-10-12');
      expect(pressed()).toEqual(['지난 7일']);
      expect(screen.getByText(compareLine('9/29~10/5', true))).toBeInTheDocument();
    });
    it.each([
      ['지난 30일', '2026-09-13', '2026-10-12', '8/14~9/12', true],
      ['이번 달', '2026-10-01', '2026-10-12', '9/19~9/30', true],
      ['지난달', '2026-09-01', '2026-09-30', '8/2~8/31', false],
      ['지난 7일', '2026-10-06', '2026-10-12', '9/29~10/5', true],
    ])('%s fills %s ~ %s and compares with %s', async (label, from, to, compare, endsToday) => {
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      fireEvent.click(screen.getByRole('radio', { name: label }));
      expect(screen.getByLabelText('시작일')).toHaveValue(from);
      expect(screen.getByLabelText('종료일')).toHaveValue(to);
      expect(pressed()).toEqual([label]);
      expect(screen.getByText(compareLine(compare, endsToday))).toBeInTheDocument();
    });
    it('keeps the preset that was pressed even when another preset covers the same days', async () => {
      vi.setSystemTime(Date.parse('2026-10-30T03:00:00Z'));   // 이 날은 지난 30일과 이번 달이 같은 기간(10/1~10/30)
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      fireEvent.click(screen.getByRole('radio', { name: '지난 30일' }));
      expect(pressed()).toEqual(['지난 30일']);
      fireEvent.click(screen.getByRole('radio', { name: '이번 달' }));
      expect(screen.getByLabelText('시작일')).toHaveValue('2026-10-01');
      expect(pressed()).toEqual(['이번 달']);
    });
    it('unpresses every preset after typing a custom date and hides the compare line for a broken period', async () => {
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      pickPeriod('2026-09-03', '2026-09-20');
      expect(pressed()).toHaveLength(0);
      expect(screen.getByText(compareLine('8/16~9/2', false))).toBeInTheDocument();
      pickPeriod('2026-09-20', '2026-09-03');
      expect(screen.queryByText(/비교 기간/)).toBeNull();
    });
  });

  describe('generation options', () => {
    beforeEach(() => {
      vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
    });
    it('names the options by what the report contains, not by the model', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], true));
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      expect(screen.getByLabelText('분석 문장 포함')).toBeChecked();
      expect(screen.getByLabelText('내용 경향 포함')).toBeChecked();
      expect(screen.queryByLabelText('LLM 사용')).toBeNull();
      expect(screen.getByText('기간별 판정 현황 · 사건 · 사용자 위험 · 권고')).toBeInTheDocument();
      expect(document.querySelector('.dops-page')?.textContent).not.toContain('LLM');
    });
    const spyCreate = () => vi.spyOn(detectionOpsService, 'createReport').mockResolvedValue(started);
    const submitPeriod = () => {
      pickPeriod('2026-09-01', '2026-09-30');
      fireEvent.click(screen.getByRole('button', { name: '리포트 생성' }));
    };

    it('is on by default when the server allows it, and sends the choice with the request', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], true));
      const create = spyCreate();
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      const box = screen.getByLabelText('내용 경향 포함');
      expect(box).toBeEnabled();
      expect(box).toBeChecked();
      expect(screen.getByText('예상 시간 · GPU 켜짐 약 2분 · 꺼짐 약 5분')).toBeInTheDocument();
      submitPeriod();
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-09-01', '2026-09-30', true, { contentTrend: true }));
    });
    it('sends false when unchecked and shortens the time estimate', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], true));
      const create = spyCreate();
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      fireEvent.click(screen.getByLabelText('내용 경향 포함'));
      expect(screen.getByLabelText('내용 경향 포함')).not.toBeChecked();
      expect(screen.getByText('예상 시간 · GPU 켜짐 약 1.5분 · 꺼짐 약 5분')).toBeInTheDocument();
      submitPeriod();
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-09-01', '2026-09-30', true, { contentTrend: false }));
    });
    it('is disabled without analysis sentences, remembers the choice, and sends no content_trend then', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], true));
      const create = spyCreate();
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      fireEvent.click(screen.getByLabelText('분석 문장 포함'));
      expect(screen.getByLabelText('내용 경향 포함')).toBeDisabled();
      expect(screen.getByLabelText('내용 경향 포함')).not.toBeChecked();
      expect(screen.getByText('내용 경향 · 분석 문장 포함일 때만')).toBeInTheDocument();
      expect(screen.getByText('예상 시간 · 집계만 1초 이내')).toBeInTheDocument();
      submitPeriod();
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-09-01', '2026-09-30', false));
      fireEvent.click(screen.getByLabelText('분석 문장 포함'));
      expect(screen.getByLabelText('내용 경향 포함')).toBeChecked();
    });
    // 2026-10-13 피드백: 전역 스위치가 꺼져 있으면 체크·안내 줄을 아예 보이지 않는다(전에는 비활성 + '관리자 설정으로 꺼짐')
    it('is hidden when the server switch is off, and sends no content_trend', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], false));
      const create = spyCreate();
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      expect(screen.queryByLabelText('내용 경향 포함')).toBeNull();
      expect(screen.queryByText(/내용 경향/)).toBeNull();
      expect(screen.getByText('예상 시간 · GPU 켜짐 약 1.5분 · 꺼짐 약 5분')).toBeInTheDocument();   // 내용 경향 없이 만드는 시간
      submitPeriod();
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-09-01', '2026-09-30', true));
    });
    it('hides it for an older detection server (no switch in the list)', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list([], null));
      mount(<ReportsPage />, '/reports');
      await screen.findByText('아직 만든 리포트가 없습니다.');
      expect(screen.queryByLabelText('내용 경향 포함')).toBeNull();
      expect(screen.queryByText(/내용 경향/)).toBeNull();
    });
    it('stays hidden while the list is still loading', async () => {
      vi.spyOn(detectionOpsService, 'getReports').mockReturnValue(new Promise(() => {}));
      mount(<ReportsPage />, '/reports');
      expect(screen.queryByLabelText('내용 경향 포함')).toBeNull();
      expect(screen.queryByText(/내용 경향/)).toBeNull();
    });
  });

  describe('regenerate', () => {
    beforeEach(() => vi.mocked(notifySuccess).mockClear());
    const open = async (reports: Report[], contentTrendEnabled: boolean | null = true) => {
      vi.spyOn(detectionOpsService, 'getReports').mockResolvedValue(list(reports, contentTrendEnabled));
      vi.spyOn(detectionOpsService, 'getGpuStatus').mockResolvedValue(gpuUp);
      mount(<ReportsPage />, '/reports');
      const table = await screen.findByRole('table', { name: '생성한 리포트' });
      fireEvent.click(within(table).getByRole('button', { name: '2026-10-01 ~ 2026-10-12 더보기' }));   // 3g: ⋯ 메뉴 → 다시 만들기
      fireEvent.click(screen.getByRole('menuitem', { name: '다시 만들기' }));
      return screen.getByRole('group', { name: '2026-10-01 ~ 2026-10-12 다시 만들기 방식' });
    };

    it('starts a new report for the same period with analysis sentences and content trend', async () => {
      const create = vi.spyOn(detectionOpsService, 'createReport').mockResolvedValue(started);
      const menu = await open([fresh]);
      expect(within(menu).getAllByRole('button').map(button => button.textContent)).toEqual(['분석 문장 포함', '분석 문장 빼고', '내용 경향 빼고']);
      fireEvent.click(within(menu).getByRole('button', { name: '분석 문장 포함' }));
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-10-01', '2026-10-12', true, { contentTrend: true }));
      await waitFor(() => expect(screen.queryByRole('group', { name: /다시 만들기 방식/ })).toBeNull());   // 메뉴가 닫힘
      expect(notifySuccess).toHaveBeenCalledWith('리포트 생성을 시작했습니다.', '예상 시간 · GPU 켜짐 약 2분 · 꺼짐 약 5분');
    });
    it('can leave the content trend out or the analysis sentences out', async () => {
      const create = vi.spyOn(detectionOpsService, 'createReport').mockResolvedValue(started);
      const menu = await open([fresh]);
      fireEvent.click(within(menu).getByRole('button', { name: '내용 경향 빼고' }));
      await waitFor(() => expect(create).toHaveBeenLastCalledWith('2026-10-01', '2026-10-12', true, { contentTrend: false }));
      await waitFor(() => expect(notifySuccess).toHaveBeenLastCalledWith('리포트 생성을 시작했습니다.', '예상 시간 · GPU 켜짐 약 1.5분 · 꺼짐 약 5분'));
      await waitFor(() => expect(screen.queryByRole('group', { name: /다시 만들기 방식/ })).toBeNull());
      fireEvent.click(screen.getByRole('button', { name: '2026-10-01 ~ 2026-10-12 더보기' }));
      fireEvent.click(screen.getByRole('menuitem', { name: '다시 만들기' }));
      fireEvent.click(within(screen.getByRole('group', { name: /다시 만들기 방식/ })).getByRole('button', { name: '분석 문장 빼고' }));
      await waitFor(() => expect(create).toHaveBeenLastCalledWith('2026-10-01', '2026-10-12', false));
      await waitFor(() => expect(notifySuccess).toHaveBeenLastCalledWith('리포트 생성을 시작했습니다.', '예상 시간 · 집계만 1초 이내'));
    });
    it('sends no content_trend and hides 내용 경향 빼고 when the server switch is off or unknown', async () => {
      const create = vi.spyOn(detectionOpsService, 'createReport').mockResolvedValue(started);
      const menu = await open([fresh], false);
      expect(within(menu).getAllByRole('button').map(button => button.textContent)).toEqual(['분석 문장 포함', '분석 문장 빼고']);
      fireEvent.click(within(menu).getByRole('button', { name: '분석 문장 포함' }));
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-10-01', '2026-10-12', true));
    });
    it('explains a conflict in the list and keeps the menu open', async () => {
      vi.spyOn(detectionOpsService, 'createReport').mockRejectedValue(new ApiError('x', 'CONFLICT', 409));
      const menu = await open([fresh]);
      fireEvent.click(within(menu).getByRole('button', { name: '분석 문장 빼고' }));
      expect(await screen.findByRole('alert')).toHaveTextContent('이미 만들고 있는 리포트가 있습니다');
      expect(screen.getByRole('group', { name: /다시 만들기 방식/ })).toBeInTheDocument();
    });
    it('is blocked while another report is running', async () => {
      const running: Report = { report_id: 'report_2026-10-07_2026-10-12_20261012T070000', status: 'running', stage: 'llm', from: '2026-10-07', to: '2026-10-12', elapsed_seconds: 30 };
      const create = vi.spyOn(detectionOpsService, 'createReport');
      const menu = await open([running, fresh]);
      for (const name of ['분석 문장 포함', '분석 문장 빼고', '내용 경향 빼고']) {
        expect(within(menu).getByRole('button', { name })).toBeDisabled();
      }
      expect(within(menu).getByRole('button', { name: '분석 문장 포함' })).toHaveAttribute('title', '생성 중인 리포트가 있습니다');
      expect(create).not.toHaveBeenCalled();
      // 진행 중인 행에는 다시 만들기가 없다
      expect(screen.queryByRole('button', { name: '2026-10-07 ~ 2026-10-12 더보기' })).toBeNull();
    });
    it('offers regenerate for a failed report using the period in its id, with no view links', async () => {
      const failedReport: Report = { report_id: 'report_2026-10-01_2026-10-12_20261012T080000', status: 'failed', error: '합계 불일치' };
      const create = vi.spyOn(detectionOpsService, 'createReport').mockResolvedValue(started);
      const menu = await open([failedReport]);
      const table = screen.getByRole('table', { name: '생성한 리포트' });
      expect(cells(table, 1)[0]).toHaveTextContent('2026-10-01 ~ 2026-10-12');
      expect(cells(table, 1)[1]).toHaveTextContent('실패');
      expect(within(table).queryByRole('link', { name: '열기' })).toBeNull();
      fireEvent.click(within(menu).getByRole('button', { name: '분석 문장 포함' }));
      await waitFor(() => expect(create).toHaveBeenCalledWith('2026-10-01', '2026-10-12', true, { contentTrend: true }));
    });
  });
});
