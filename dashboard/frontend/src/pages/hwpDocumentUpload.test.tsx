import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { documentService } from '@/src/services/documentService';
import { eventService } from '@/src/services/eventService';
import type { ConfidentialDocument } from '@/src/types/policy';
import { ProtectedDocumentDetailPage } from './ProtectedDocumentDetailPage';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';

// HWP·HWPX 보호 문서 등록(2026-10-11, PDF·HWP 마스킹 명세 1단계 §2.4). 파일 구조 확인은 서버 몫이라 화면은 확장자·크기만 본다. 값은 모두 가짜.
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));

const pdf: ConfidentialDocument = { documentId: 'doc-pdf', documentName: '가짜 문서.pdf', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'pdf', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 5, activeDetectors: ['WINDOW_HASH'] };
const hwp: ConfidentialDocument = { ...pdf, documentId: 'doc-hwp', documentName: '가짜 보고서.hwp', fileType: 'hwp' };
const hwpx: ConfidentialDocument = { ...pdf, documentId: 'doc-hwpx', documentName: '가짜 양식.hwpx', fileType: 'hwpx', processingStatus: 'PROCESSING', chunkIndexStatus: 'PROCESSING', chunkCount: 0 };

function mount(node: React.ReactNode, route = '/documents') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}>{node}</MemoryRouter></QueryClientProvider>);
}

async function openUpload() {
  mount(<ProtectedDocumentsPage />);
  await screen.findByRole('link', { name: pdf.documentName });
  fireEvent.click(screen.getByRole('button', { name: '문서 등록' }));
  return screen.findByRole('dialog');
}

beforeEach(() => vi.restoreAllMocks());

describe('HWP and HWPX protected document upload', () => {
  it('offers .hwp and .hwpx in the picker and the size hint', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([pdf]);
    const dialog = await openUpload();
    expect(within(dialog).getByLabelText('등록할 문서 파일')).toHaveAttribute('accept', '.pdf,.docx,.xlsx,.hwp,.hwpx');
    expect(within(dialog).getByText('최대 20MB · PDF, DOCX, XLSX, HWP, HWPX')).toBeInTheDocument();
  });

  it.each([
    ['가짜 보고서.hwp', 'application/x-hwp'],
    ['가짜 보고서.HWP', 'application/haansofthwp'],
    ['가짜 양식.hwpx', ''],
    ['가짜 양식.hwpx', 'application/octet-stream'],
  ])('sends %s (MIME "%s") unchanged to the registration service', async (name, type) => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([pdf]);
    const register = vi.spyOn(documentService, 'registerDocument').mockResolvedValue(hwp);
    const dialog = await openUpload();
    const file = new File(['가짜 내용'], name, { type });
    fireEvent.change(within(dialog).getByLabelText('등록할 문서 파일'), { target: { files: [file] } });
    expect(within(dialog).queryByRole('alert')).toBeNull();
    fireEvent.click(within(dialog).getByRole('button', { name: '등록' }));
    await waitFor(() => expect(register).toHaveBeenCalledWith(file));
  });

  it.each([
    ['가짜.hwt', 'application/x-hwp', 'PDF, DOCX, XLSX, HWP, HWPX 파일만'],
    ['빈 문서.hwp', 'application/x-hwp', '내용이 없는 파일'],
    ['가짜.pdf', 'application/x-hwp', 'MIME 유형'],
  ])('still blocks %s in the browser', async (name, type, message) => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([pdf]);
    const register = vi.spyOn(documentService, 'registerDocument');
    const dialog = await openUpload();
    const file = new File(name.startsWith('빈') ? [] : ['x'], name, { type });
    fireEvent.change(within(dialog).getByLabelText('등록할 문서 파일'), { target: { files: [file] } });
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(message);
    expect(within(dialog).getByRole('button', { name: '등록' })).toBeDisabled();
    expect(register).not.toHaveBeenCalled();
  });

  it('rejects an HWP over 20 MiB before uploading', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([pdf]);
    const register = vi.spyOn(documentService, 'registerDocument');
    const dialog = await openUpload();
    const big = new File(['x'], '큰 문서.hwp', { type: 'application/x-hwp' });
    Object.defineProperty(big, 'size', { value: 20 * 1024 * 1024 + 1 });
    fireEvent.change(within(dialog).getByLabelText('등록할 문서 파일'), { target: { files: [big] } });
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('파일 크기는 20MB 이하여야 합니다.');
    expect(register).not.toHaveBeenCalled();
  });

  it('shows the hwp and hwpx format in the list, the format filter and the detail page', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([pdf, hwp, hwpx]);
    vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [], total: 0, page: 1, totalPages: 1, pageSize: 20 });
    const { unmount } = mount(<ProtectedDocumentsPage />);
    const row = (await screen.findByRole('link', { name: hwp.documentName })).closest('tr') as HTMLElement;
    expect(within(row).getByText('hwp')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '필터 더보기' }));   // 재설계 3e: 파일 형식은 필터 더보기 안(설계 4.7)
    const filter = screen.getByLabelText('파일 형식');
    expect([...filter.querySelectorAll('option')].map(option => option.getAttribute('value'))).toEqual(['ALL', 'hwp', 'hwpx', 'pdf']);
    fireEvent.change(filter, { target: { value: 'hwpx' } });
    expect(screen.getByRole('link', { name: hwpx.documentName })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: hwp.documentName })).toBeNull();
    expect(screen.queryByRole('link', { name: pdf.documentName })).toBeNull();
    unmount();
    mount(<Routes><Route path="/documents/:documentId" element={<ProtectedDocumentDetailPage />} /></Routes>, '/documents/doc-hwp');
    const format = await screen.findByText('파일 형식');
    expect(format.nextElementSibling).toHaveTextContent('hwp');
  });
});
