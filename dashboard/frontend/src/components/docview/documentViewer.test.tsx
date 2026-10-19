import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DocumentViewer } from './DocumentViewer';
import { DocumentViewError, documentViewService, type DocumentView, type DocumentViewMode } from '@/src/services/documentViewService';
import { detectionOpsService } from '@/src/services/detectionOpsService';
import type { ConfidentialDocument } from '@/src/types/policy';
import type { RendererProps } from './types';

// 재설계 3h 뷰어(설계 6.4·6.5·6.6). 형식별 그리기 부품은 가짜로 바꾸고(실제 그리기는 stage3e/viewer-check.mjs가 브라우저로 확인) 열람·실패·보안 흐름만 본다. 값은 모두 가짜.
const rendered = vi.hoisted(() => ({ props: null as null | RendererProps, fail: '' }));
vi.mock('./PdfPages', async () => {
  const { useEffect } = await import('react');
  return {
    default: (props: RendererProps) => {
      rendered.props = props;
      // 실제 부품처럼 열 때 한 번만 알린다
      useEffect(() => { if (rendered.fail) props.onFailure(rendered.fail); else props.onInfo({ pages: 12, firstPaintMs: 5 }); }, []);   // eslint-disable-line react-hooks/exhaustive-deps
      return <div data-testid="pdf-pages">PDF {props.data.byteLength}B</div>;
    },
  };
});

const doc: ConfidentialDocument = { documentId: '13_파트너사협상자료', documentName: '13_파트너사협상자료.pdf', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'pdf', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 1284, activeDetectors: ['WINDOW_HASH'], version: '2', owner: 'local-admin', modifiedPartialDetectionCount: 9, lastDetectedAt: '2026-10-12T23:49:00Z' };
const view = (overrides: Partial<DocumentView> = {}): DocumentView => ({ view_id: 'Qm9yZWQ0Ny1leGFtcGxlMQ', view_ref: '7F3A2C1B', document_id: doc.documentId, document_name: doc.documentName, version: '2', format: 'pdf', size: 2_400_000, status: 'ACTIVE', index_status: 'READY', mode: 'original', issued_at: '2026-10-13T00:31:00.000Z', expires_at: '2026-10-13T08:31:00.000Z', ...overrides });
const textPage = (overrides: Record<string, unknown> = {}) => ({ document_id: doc.documentId, version: '2', index_status: 'READY' as const, coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS' as const, redaction: 'APPLIED' as const,
  page: { status: 'AVAILABLE' as const, side: 'document' as const, document_id: doc.documentId, char_start: 0, char_end: 12, total_chars: 12, page_size: 1800 as const, segments: [{ text: '협상 목표 ', matched: false, redacted: false }, { text: '██████', matched: false, redacted: true }], content_source: 'CURRENT_PROTECTED_DOCUMENT' as const }, ...overrides });

function Harness({ initial = 'original', document = doc, onMode }: { initial?: DocumentViewMode; document?: ConfidentialDocument; onMode?: (mode: DocumentViewMode, options?: { replace?: boolean }) => void }) {
  const [mode, setMode] = useState<DocumentViewMode>(initial);
  return <DocumentViewer documentId={document.documentId} document={document} mode={mode} onClose={() => undefined} onModeChange={(next, options) => { onMode?.(next, options); setMode(next); }} />;
}
function mount(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>) };
}

beforeEach(() => {
  rendered.props = null;
  rendered.fail = '';
  vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue([
    { id: 1, keyword: '가나다전자 단가', doc_id: doc.documentId, status: 'approved', source: 'llm' },
    { id: 2, keyword: 'MOU-24', doc_id: doc.documentId, status: 'approved', source: 'llm' },
    { id: 3, keyword: '보류 후보', doc_id: doc.documentId, status: 'pending', source: 'llm' },
    { id: 4, keyword: '다른 문서', doc_id: 'other', status: 'approved', source: 'llm' },
  ]);
});

describe('document viewer', () => {
  it('opens once (one audit record), shows the view number and watermark, and keeps the same view when switching to text', async () => {
    const start = vi.spyOn(documentViewService, 'startView').mockResolvedValue(view());
    const original = vi.spyOn(documentViewService, 'getOriginal').mockResolvedValue({ data: new ArrayBuffer(64), version: '2' });
    const text = vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue(textPage());
    const { client } = mount(<Harness />);
    expect(await screen.findByTestId('pdf-pages')).toHaveTextContent('PDF 64B');
    expect(start).toHaveBeenCalledTimes(1);
    expect(start).toHaveBeenCalledWith(doc.documentId, 'original', expect.anything());
    expect(original).toHaveBeenCalledWith(doc.documentId, 'Qm9yZWQ0Ny1leGFtcGxlMQ', expect.anything());
    const toolbar = screen.getByRole('toolbar', { name: '보기 도구' });
    expect(toolbar).toHaveTextContent('열람 기록됨 · 열람 7F3A2C1B');
    expect(await within(toolbar).findByText('1 / 12쪽')).toBeInTheDocument();
    expect(document.querySelector('.pg-dv-wm')?.getAttribute('data-watermark')).toBe('관리자 · 10.13 09:31 · 열람 7F3A2C1B');
    expect(screen.getByText(/2\.3 MB · 12쪽 · 판 2/)).toBeInTheDocument();
    expect(screen.getByText('가나다전자 단가')).toBeInTheDocument();
    expect(screen.queryByText('다른 문서')).toBeNull();
    expect(screen.getByRole('link', { name: '승인 대기 1' })).toHaveAttribute('href', '/policies/keywords');
    expect(screen.getByRole('link', { name: '이벤트' })).toHaveAttribute('href', `/events?documentId=${encodeURIComponent(doc.documentId)}&period=30D`);
    // 자동 갱신·창 포커스로 다시 열지 않는다
    await act(async () => { window.dispatchEvent(new Event('visibilitychange')); window.dispatchEvent(new Event('focus')); await new Promise((resolve) => setTimeout(resolve, 50)); });
    fireEvent.click(screen.getByRole('radio', { name: '텍스트' }));
    expect(await screen.findByText(/협상 목표/)).toBeInTheDocument();
    expect(screen.getByText('탐지 기준 텍스트 · 개인정보 가림')).toBeInTheDocument();
    expect(text).toHaveBeenCalledWith(doc.documentId, 'Qm9yZWQ0Ny1leGFtcGxlMQ', 0, expect.anything());
    expect(start).toHaveBeenCalledTimes(1);
    // 원본 바이트는 react-query 캐시에 넣지 않는다
    expect(client.getQueryCache().getAll().some((query) => query.state.data instanceof ArrayBuffer || (query.state.data as { data?: unknown })?.data instanceof ArrayBuffer)).toBe(false);
  });

  it('switches to text with a reason band when the original cannot be drawn', async () => {
    rendered.fail = '깨진 PDF 파일';
    vi.spyOn(documentViewService, 'startView').mockResolvedValue(view());
    vi.spyOn(documentViewService, 'getOriginal').mockResolvedValue({ data: new ArrayBuffer(8), version: '2' });
    vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue(textPage());
    const onMode = vi.fn();
    mount(<Harness onMode={onMode} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('원본 모양으로 그리지 못함 · 깨진 PDF 파일 · 텍스트로 표시');
    expect(onMode).toHaveBeenCalledWith('text', { replace: true });
    expect(await screen.findByText(/협상 목표/)).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: '텍스트' })).toBeChecked();
  });

  it('shows nothing of the document when the view could not be recorded, and retries as a new view', async () => {
    const start = vi.spyOn(documentViewService, 'startView').mockRejectedValueOnce(new DocumentViewError('FORBIDDEN', 403, 'AUDIT_REQUIRED')).mockResolvedValue(view());
    const original = vi.spyOn(documentViewService, 'getOriginal').mockResolvedValue({ data: new ArrayBuffer(8), version: '2' });
    mount(<Harness />);
    expect(await screen.findByText('본문을 열지 못함 · 열람 기록을 남기지 못해 열 수 없음')).toBeInTheDocument();
    expect(original).not.toHaveBeenCalled();
    expect(document.querySelector('.pg-dv-wm')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    await screen.findByTestId('pdf-pages');
    expect(start).toHaveBeenCalledTimes(2);
  });

  it('never asks for an original over 20 MiB or of an unknown format', async () => {
    vi.spyOn(documentViewService, 'startView').mockResolvedValue(view({ size: 20 * 1024 * 1024 + 1 }));
    const original = vi.spyOn(documentViewService, 'getOriginal');
    vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue(textPage());
    const { unmount } = mount(<Harness />);
    expect(await screen.findByText('원본이 20MB를 넘어 텍스트로만 표시')).toBeInTheDocument();
    expect(await screen.findByText(/협상 목표/)).toBeInTheDocument();
    unmount();
    vi.spyOn(documentViewService, 'startView').mockResolvedValue(view({ format: null }));
    mount(<Harness />);
    expect(await screen.findByText('이 형식(알 수 없음)은 원본 모양 보기를 지원하지 않음 · 텍스트로 표시')).toBeInTheDocument();
    expect(original).not.toHaveBeenCalled();
  });

  // '원본 내려받기'는 2026-10-13 뺐다(머리 버튼·⋯ 메뉴·그리기 실패 띠). 새 판 등록(409) 뒤 다시 열기는 원본 받기에서 확인
  it('offers no download anywhere and offers reopening when a new version was registered', async () => {
    const start = vi.spyOn(documentViewService, 'startView').mockResolvedValue(view());
    vi.spyOn(documentViewService, 'getOriginal').mockRejectedValueOnce(new DocumentViewError('CONFLICT', 409, 'DOCUMENT_VERSION_CHANGED')).mockResolvedValue({ data: new ArrayBuffer(8), version: '3' });
    vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue(textPage());
    mount(<Harness />);
    expect(await screen.findByText('새 판이 등록됨 · 다시 열기')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /내려받기/ })).toBeNull();
    expect(screen.queryByRole('button', { name: `${doc.documentName} 더보기` })).toBeNull();   // 좁은 화면 ⋯ 메뉴도 없음('정보 더보기'는 별개)
    expect(screen.queryByText(/내려받기/)).toBeNull();
    expect(screen.getByRole('link', { name: /상세/ })).toHaveAttribute('href', `/documents/${encodeURIComponent(doc.documentId)}`);
    expect('download' in documentViewService).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: '다시 열기' }));
    await waitFor(() => expect(start).toHaveBeenCalledTimes(2));
    await screen.findByTestId('pdf-pages');
  });

  it('marks retired documents and text that is still being indexed', async () => {
    vi.spyOn(documentViewService, 'startView').mockResolvedValue(view({ status: 'INACTIVE', index_status: 'PROCESSING' }));
    vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue(textPage({ index_status: 'PROCESSING' }));
    mount(<Harness initial="text" document={{ ...doc, status: 'INACTIVE', activeDetectors: [] }} />);
    expect(await screen.findByText('보호 중지됨 · 탐지에 쓰지 않음 · 다시 켜기 전 내용 확인용')).toBeInTheDocument();
    expect(await screen.findByText('색인 중 · 텍스트는 이전 판일 수 있음')).toBeInTheDocument();
  });

  it('says when there is no detection text yet', async () => {
    vi.spyOn(documentViewService, 'startView').mockResolvedValue(view({ index_status: 'PROCESSING' }));
    vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue(textPage({ index_status: 'PROCESSING', page: { status: 'NOT_RECORDED', side: 'document', document_id: doc.documentId } }));
    mount(<Harness initial="text" />);
    expect(await screen.findByText('색인이 끝나면 표시(지금은 탐지 기준 텍스트가 없음)')).toBeInTheDocument();
  });
});
