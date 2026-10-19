import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';
import { PolicyManagementPage } from './PolicyManagementPage';
import { documentService } from '@/src/services/documentService';
import { policyService } from '@/src/services/policyService';
import type { ConfidentialDocument, DetectionPolicy } from '@/src/types/policy';
import { ApiError } from '@/src/api/errors';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
const document: ConfidentialDocument = { documentId: 'doc/#1', documentName: '첫 문서', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 10, activeDetectors: ['WINDOW_HASH'] };
const policy: DetectionPolicy = { policyId: 'policy-1', detector: 'SIGNATURE', detectionTarget: 'KR_PHONE_NUMBER', action: 'MASK', policyAction: 'MASK_FULL', finalPolicyAction: 'MASK_FULL', targetLlms: [], version: 1, enabled: true, versions: [] };
// 재설계 3e: 보호 중지는 행 ⋯ 메뉴 안 위험 항목(설계 4.5)
async function openStop(name: string) {
  fireEvent.click(await screen.findByRole('button', { name: `${name} 더보기` }));
  fireEvent.click(await screen.findByRole('menuitem', { name: '보호 중지' }));
}
function open(page: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter>{page}</MemoryRouter></QueryClientProvider>);
  return client;
}

describe('document management safeguards', () => {
  it('searches all documents across pages and URI-encodes IDs', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue(Array.from({ length: 12 }, (_, index) => ({ ...document, documentId: index ? `doc-${index}` : document.documentId, documentName: index ? `보고서 ${index}` : document.documentName })));
    open(<ProtectedDocumentsPage />);
    expect(await screen.findByRole('link', { name: '첫 문서' })).toHaveAttribute('href', '/documents/doc%2F%231');
    expect(screen.getAllByRole('row')).toHaveLength(11);
    fireEvent.click(screen.getByRole('button', { name: '다음 페이지' }));
    await screen.findByRole('link', { name: '보고서 11' });
    fireEvent.change(screen.getByLabelText('문서명 · ID · 소유자 검색'), { target: { value: '첫 문서' } });
    expect(screen.getByRole('link', { name: '첫 문서' })).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(2);
    fireEvent.click(screen.getByRole('radio', { name: /^보호 중지/ }));   // 재설계 3e: 상태는 세그먼트(설계 4.7)
    expect(screen.getByText('검색 조건에 맞는 문서가 없습니다.')).toBeInTheDocument();
  });
  it('requires confirmation and does not mutate when canceled', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([document]);
    const change = vi.spyOn(documentService, 'changeDocumentStatus');
    open(<ProtectedDocumentsPage />);
    await openStop('첫 문서');
    await screen.findByRole('heading', { name: '보호 중지 · 첫 문서' });
    expect(change).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: '취소' }));
    expect(change).not.toHaveBeenCalled();
  });
  it('keeps the confirmation after failure and never exposes raw server errors', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([document]);
    const change = vi.spyOn(documentService, 'changeDocumentStatus').mockRejectedValue(new ApiError('private server detail', 'NETWORK'));
    open(<ProtectedDocumentsPage />);
    await openStop('첫 문서');
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '보호 중지' }));
    await screen.findByText(/상태 변경 실패/);
    expect(change).toHaveBeenCalledWith('doc/#1', 'INACTIVE');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.queryByText('private server detail')).not.toBeInTheDocument();
  });
  it('prevents stale writes after a failed refresh', async () => {
    const get = vi.spyOn(documentService, 'getDocuments').mockResolvedValue([document]);
    open(<ProtectedDocumentsPage />);
    await screen.findByRole('link', { name: '첫 문서' });
    get.mockRejectedValue(new ApiError('offline', 'NETWORK'));
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText(/아래는 마지막 성공 조회 결과/);
    fireEvent.click(screen.getByRole('button', { name: '첫 문서 더보기' }));
    expect(screen.getByRole('menuitem', { name: '보호 중지' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '문서 등록' })).toBeDisabled();
  });
  it('hides a cached document confirmation when permissions are revoked', async () => {
    const get = vi.spyOn(documentService, 'getDocuments').mockResolvedValue([document]);
    const client = open(<ProtectedDocumentsPage />);
    await openStop('첫 문서');
    await screen.findByRole('dialog');
    get.mockRejectedValue(new ApiError('denied', 'FORBIDDEN', 403));
    await client.invalidateQueries({ queryKey: ['documents'] });
    await screen.findByText('이 작업을 수행할 권한이 없습니다.');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: '첫 문서' })).not.toBeInTheDocument();
  });
});

describe('policy management safeguards', () => {
  // 2026-10-16: 탐지 정책은 분류별 항목 토글 화면(생성·수정 대화상자 없음). 같은 보호 장치를 토글·처리 방식 선택에서 확인
  it('blocks duplicate requests while saving and never exposes raw server errors', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    let reject!: (error: Error) => void;
    const save = vi.spyOn(policyService, 'createPolicy').mockReturnValue(new Promise((_, fail) => { reject = fail; }));
    open(<PolicyManagementPage />);
    const email = await screen.findByRole('switch', { name: '이메일 따로 처리' });
    await waitFor(() => expect(email).toBeEnabled());
    fireEvent.click(email);
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(within(email.closest('li')!).getByRole('status')).toHaveTextContent('저장 중…');
    for (const item of screen.getAllByRole('switch')) expect(item).toBeDisabled();   // 저장 중에는 다른 변경도 막음
    expect(screen.getByRole('combobox', { name: '전화번호 처리 방식' })).toBeDisabled();
    fireEvent.click(email);
    expect(save).toHaveBeenCalledTimes(1);
    reject(new ApiError('private detail', 'NETWORK'));
    expect(await within(email.closest('li')!).findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByText('private detail')).not.toBeInTheDocument();
    await waitFor(() => expect(email).toBeEnabled());
  });
  it('prevents unchanged action submissions', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    const save = vi.spyOn(policyService, 'updatePolicy');
    open(<PolicyManagementPage />);
    const select = await screen.findByRole('combobox', { name: '전화번호 처리 방식' });
    await waitFor(() => expect(select).toBeEnabled());
    fireEvent.change(select, { target: { value: 'MASK_FULL' } });   // 지금 값과 같음
    expect(save).not.toHaveBeenCalled();
  });
  it('blocks outdated versions instead of silently overwriting another admin change', async () => {
    const get = vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    const save = vi.spyOn(policyService, 'updatePolicy');
    const client = open(<PolicyManagementPage />);
    const select = await screen.findByRole('combobox', { name: '전화번호 처리 방식' });
    await waitFor(() => expect(select).toBeEnabled());
    fireEvent.change(select, { target: { value: 'ALLOW' } });
    const confirm = await screen.findByRole('dialog', { name: '허용 · 전화번호' });
    get.mockResolvedValue([{ ...policy, version: 2 }]);
    await client.invalidateQueries({ queryKey: ['policies'] });
    expect(await within(confirm).findByText(/정책 버전이 변경됐습니다/)).toBeInTheDocument();
    expect(within(confirm).getByRole('button', { name: '허용' })).toBeDisabled();
    fireEvent.click(within(confirm).getByRole('button', { name: '허용' }));
    expect(save).not.toHaveBeenCalled();
  });
  it('keeps policy data but disables writes on refresh failure', async () => {
    const get = vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    open(<PolicyManagementPage />);
    const phone = await screen.findByRole('switch', { name: '전화번호 따로 처리' });
    await waitFor(() => expect(phone).toBeEnabled());
    get.mockRejectedValue(new ApiError('offline', 'NETWORK'));
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText(/아래는 마지막 성공 조회 결과/);
    expect(phone).toHaveAttribute('aria-checked', 'true');
    expect(phone).toBeDisabled();
    expect(phone).toHaveAttribute('title', '최신 정책 조회가 회복되면 변경할 수 있습니다.');
    expect(screen.getByRole('combobox', { name: '전화번호 처리 방식' })).toBeDisabled();
  });
});
