import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { documentService } from '@/src/services/documentService';
import type { ConfidentialDocument } from '@/src/types/policy';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';

// 보호 문서 등록 업로드 중 표시(2026-10-10, 명세 §6). 20MB 안내·브라우저 검사는 그대로. 값은 모두 가짜.
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const doc: ConfidentialDocument = { documentId: 'doc-1', documentName: '가짜 문서.pdf', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 5, activeDetectors: ['WINDOW_HASH'] };

async function openUpload() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/documents']}><ProtectedDocumentsPage /></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('link', { name: doc.documentName });
  fireEvent.click(screen.getByRole('button', { name: '문서 등록' }));
  return screen.findByRole('dialog');
}

beforeEach(() => vi.restoreAllMocks());

describe('protected document upload progress', () => {
  it('locks the dialog and says it is uploading until the server answers', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([doc]);
    let finish: (value: ConfidentialDocument) => void = () => undefined;
    vi.spyOn(documentService, 'registerDocument').mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const dialog = await openUpload();
    expect(within(dialog).getByText('최대 20MB · PDF, DOCX, XLSX, HWP, HWPX')).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('등록할 문서 파일'), { target: { files: [new File(['%PDF fake'], 'fake.pdf', { type: 'application/pdf' })] } });
    fireEvent.click(within(dialog).getByRole('button', { name: '등록' }));
    expect(await within(dialog).findByRole('status')).toHaveTextContent('업로드 중 · 파일 크기와 네트워크에 따라 최대 2분 걸립니다.');
    expect(within(dialog).getByRole('button', { name: '업로드 중…' })).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: '취소' })).toBeDisabled();
    expect(within(dialog).getByLabelText('등록할 문서 파일')).toBeDisabled();
    finish(doc);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('still rejects a file over 20 MiB in the browser', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([doc]);
    const register = vi.spyOn(documentService, 'registerDocument');
    const dialog = await openUpload();
    const big = new File(['x'], 'big.pdf', { type: 'application/pdf' });
    Object.defineProperty(big, 'size', { value: 20 * 1024 * 1024 + 1 });
    fireEvent.change(within(dialog).getByLabelText('등록할 문서 파일'), { target: { files: [big] } });
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('파일 크기는 20MB 이하여야 합니다.');
    expect(within(dialog).getByRole('button', { name: '등록' })).toBeDisabled();
    expect(register).not.toHaveBeenCalled();
  });
});
