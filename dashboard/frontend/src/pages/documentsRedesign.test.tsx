import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';
import { ProtectedDocumentDetailPage } from './ProtectedDocumentDetailPage';
import { documentService } from '@/src/services/documentService';
import { documentViewService } from '@/src/services/documentViewService';
import { detectionOpsService } from '@/src/services/detectionOpsService';
import { eventService } from '@/src/services/eventService';
import { AuditChangeDetails } from '@/src/components/AuditChangeDetails';
import { readAuditRows } from '@/src/api/schemas';
import { mapAuditLogDto } from '@/src/api/mappers';
import { uiLabel } from '@/src/utils/labels';
import type { ConfidentialDocument } from '@/src/types/policy';

// 재설계 3e(보호 문서 목록·상세, 설계 5.4) + 3h 들어가는 곳(6.5)·감사 이름(6.4). 값은 모두 가짜.
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
const base: ConfidentialDocument = { documentId: '13_파트너사협상자료', documentName: '13_파트너사협상자료.pdf', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'pdf', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 1284, activeDetectors: ['WINDOW_HASH'], version: '2', owner: 'local-admin' };
const docs: ConfidentialDocument[] = [
  base,
  { ...base, documentId: '05_투자유치_자료', documentName: '05_투자유치_자료.xlsx', fileType: 'xlsx' },
  { ...base, documentId: '20_장애대응보고서', documentName: '20_장애대응보고서.hwpx', fileType: 'hwpx', processingStatus: 'PROCESSING', chunkIndexStatus: 'PROCESSING', chunkCount: 0, activeDetectors: [] },
  { ...base, documentId: '09_아키텍처_설계서', documentName: '09_아키텍처_설계서.hwp', fileType: 'hwp', status: 'INACTIVE', activeDetectors: [] },
  // 문서 상태는 보호 중인데 색인이 실패 → 배지 1개로 합치면 '분석 실패'(지금 화면은 '보호 중' 숫자에 세던 경우, 설계 3.5)
  { ...base, documentId: 'doc-x', documentName: '기획.docx', fileType: 'docx', chunkIndexStatus: 'FAILED' },
];
function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.pathname}{location.search}</output>;
}
function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/documents" element={<><ProtectedDocumentsPage /><Where /></>} />
    <Route path="/documents/:documentId" element={<><ProtectedDocumentDetailPage /><Where /></>} />
  </Routes></MemoryRouter></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(documentService, 'getDocuments').mockResolvedValue(docs);
  vi.spyOn(detectionOpsService, 'getKeywords').mockResolvedValue([
    { id: 1, keyword: '가나다전자 단가', doc_id: base.documentId, status: 'approved', source: 'llm' },
    { id: 2, keyword: 'TBS 수수료', doc_id: base.documentId, status: 'pending', source: 'llm' },
  ]);
});

describe('protected documents list (3e)', () => {
  it('merges document and index status into one badge and counts the strip and segment with the same rule', async () => {
    mount('/documents');
    const strip = await screen.findByRole('status', { name: '보호 문서 상태' });
    expect(strip).toHaveTextContent('5개 중 2개 보호 중');
    expect(strip).toHaveTextContent('분석 중 1 · 분석 실패 1 · 보호 중지 1');   // 2026-10-16 행 배지와 같은 말
    expect(strip).toHaveAttribute('data-level', 'bad');
    expect(strip).toHaveTextContent('본문 보기는 열람 기록이 남음');
    expect(screen.getAllByRole('radio').map((radio) => radio.closest('label')?.textContent)).toEqual(['전체 5', '보호 중 2', '분석 중 1', '분석 실패 1', '보호 중지 1']);
    const failedRow = screen.getByRole('row', { name: '기획.docx 문서 상세' });
    expect(within(failedRow).getByText('분석 실패')).toHaveAttribute('data-tone', 'block');
    expect(failedRow).toHaveAttribute('data-tone', 'block');
    fireEvent.click(screen.getByRole('radio', { name: '분석 실패 1' }));
    expect(screen.getAllByRole('row')).toHaveLength(2);
    expect(screen.getByRole('button', { name: '상태: 분석 실패 지우기' })).toBeInTheDocument();
  });

  it('hides the detection column when no row on the page has a detection, and shows it otherwise', async () => {
    mount('/documents');
    await screen.findByRole('row', { name: '기획.docx 문서 상세' });
    expect(screen.queryByRole('columnheader', { name: '누적 탐지 · 최근' })).toBeNull();
    expect(screen.getAllByRole('columnheader').map((head) => head.textContent)).toEqual(['문서', '상태', '소유자', '등록', '조치']);
  });

  it('keeps row actions to [보기] + ⋯ and opens the split viewer through the address (?view=&mode=)', async () => {
    const start = vi.spyOn(documentViewService, 'startView').mockResolvedValue({ view_id: 'Qm9yZWQ0Ny1leGFtcGxlMQ', view_ref: '3F9A2C1B', document_id: base.documentId, document_name: base.documentName, version: '2', format: 'pdf', size: 1000, status: 'ACTIVE', index_status: 'READY', mode: 'text', issued_at: '2026-10-13T00:31:00.000Z', expires_at: '2026-10-13T08:31:00.000Z' });
    vi.spyOn(documentViewService, 'getTextPage').mockResolvedValue({ document_id: base.documentId, version: '2', index_status: 'READY', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', redaction: 'APPLIED', page: { status: 'NOT_RECORDED', side: 'document', document_id: base.documentId } });
    mount('/documents');
    const row = await screen.findByRole('row', { name: '13_파트너사협상자료.pdf 문서 상세' });
    expect(within(row).getAllByRole('button').map((button) => button.getAttribute('aria-label'))).toEqual(['13_파트너사협상자료.pdf 본문 보기', '13_파트너사협상자료.pdf 더보기']);
    fireEvent.click(within(row).getByRole('button', { name: '13_파트너사협상자료.pdf 더보기' }));
    expect(screen.getAllByRole('menuitem').map((item) => [item.textContent, item.className.includes('danger')])).toEqual([['상세 보기', false], ['보호 중지', true]]);
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Escape' });
    fireEvent.click(within(row).getByRole('button', { name: '13_파트너사협상자료.pdf 본문 보기' }));
    expect(screen.getByTestId('where')).toHaveTextContent(`/documents?view=${encodeURIComponent(base.documentId)}&mode=original`);
    const viewer = await screen.findByRole('region', { name: '문서 본문 보기' });
    expect(within(viewer).getByRole('heading', { name: base.documentName })).toBeInTheDocument();
    const side = screen.getByRole('complementary', { name: '보호 문서 목록' });
    expect(within(side).getByRole('button', { name: /^13_파트너사협상자료\.pdf/ })).toHaveAttribute('aria-current', 'true');
    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    fireEvent.click(within(viewer).getByRole('radio', { name: '텍스트' }));
    expect(screen.getByTestId('where')).toHaveTextContent('mode=text');
    expect(start).toHaveBeenCalledTimes(1);
    fireEvent.click(within(side).getByRole('button', { name: '표로 보기' }));
    expect(screen.getByTestId('where')).toHaveTextContent(/^\/documents$/);
    expect(await screen.findByRole('table', { name: '보호 문서' })).toBeInTheDocument();
  });

  it('replaces the old "metadata only" principle with the recorded-view wording', async () => {
    mount('/documents');
    await screen.findByRole('row', { name: '기획.docx 문서 상세' });
    expect(screen.queryByText(/메타데이터만 표시/)).toBeNull();
    expect(screen.getByText('본문 보기 원칙')).toBeInTheDocument();
    expect(screen.getByText(/열 때마다 감사 로그에 남고/)).toBeInTheDocument();
  });
});

describe('protected document detail (3e)', () => {
  beforeEach(() => vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [], total: 0, page: 1, totalPages: 1, pageSize: 20 }));
  it('puts [본문 보기] in the header, keeps registration and keyword facts, and drops "원문 비노출"', async () => {
    mount(`/documents/${encodeURIComponent(base.documentId)}`);
    expect(await screen.findByRole('heading', { level: 1, name: base.documentName })).toBeInTheDocument();
    expect(screen.queryByText('문서 ID')).toBeNull();   // ID가 파일 이름과 같으면 숨김
    expect(screen.getByText('판').nextElementSibling).toHaveTextContent('2');   // 2026-10-16 목록·본문 보기와 같은 말('판')
    expect(await screen.findByText('가나다전자 단가')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '승인 대기 1' })).toHaveAttribute('href', '/policies/keywords');
    expect(screen.queryByText('원문 비노출')).toBeNull();
    expect(screen.getByText(/열 때마다 감사 로그에 남고/)).toBeInTheDocument();
    expect(screen.queryByText(/내려받을 때마다/)).toBeNull();   // 내려받기는 10/13에 없앴다(2026-10-15 감사 15번)
    expect(screen.getByText('최근 30일 동안 이 문서와 일치한 보안 이벤트가 없습니다.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '본문 보기' }));
    expect(screen.getByTestId('where')).toHaveTextContent(`/documents?view=${encodeURIComponent(base.documentId)}&mode=original`);
  });
  it('shows the document ID when it differs from the file name, and a neutral strip for retired documents', async () => {
    mount('/documents/doc-x');
    expect(await screen.findByText('문서 ID')).toBeInTheDocument();
    cleanup();
    mount('/documents/09_%EC%95%84%ED%82%A4%ED%85%8D%EC%B2%98_%EC%84%A4%EA%B3%84%EC%84%9C');
    expect(await screen.findByRole('status', { name: '보호 상태' })).toHaveTextContent('보호 중지됨구간 일치·승인 키워드 모두 탐지에 쓰지 않음 · 등록 기록·원본은 그대로');   // 2026-10-16 Detection이 중지 문서 키워드도 뺌
  });
});

describe('document view audit rows (3h)', () => {
  it('reads DOCUMENT_VIEW and DOCUMENT_DOWNLOAD with version, format, mode and view number', () => {
    const page = readAuditRows<never>({ page: 1, page_size: 20, total: 3, total_pages: 1, items: [
      { audit_id: 'a1', occurred_at: '2026-10-13T00:31:00Z', admin_id: 'local-admin', action: 'DOCUMENT_VIEW', target_type: 'DOCUMENT', target_id: base.documentId, result: 'SUCCESS', changes: { version: '2', format: 'pdf', mode: 'original', view_ref: '3F9A2C1B' } },
      { audit_id: 'a2', occurred_at: '2026-10-13T00:32:00Z', admin_id: 'local-admin', action: 'DOCUMENT_DOWNLOAD', target_type: 'DOCUMENT', target_id: base.documentId, result: 'SUCCESS', changes: { version: '2', format: 'pdf', mode: 'download', view_ref: '3F9A2C1B' } },
      // 옛 문서 등록 기록: 판이 숫자여도 읽고, 모르는 보기 방식은 그 칸만 버린다(줄 전체를 버리지 않음)
      { audit_id: 'a3', occurred_at: '2026-10-01T00:00:00Z', admin_id: 'local-admin', action: 'DOCUMENT_REGISTER', target_type: 'DOCUMENT', target_id: base.documentId, result: 'SUCCESS', changes: { version: 1, mode: 'peek' } },
    ] });
    expect(page.items).toHaveLength(3);
    expect(page).not.toHaveProperty('skipped');
    expect(page).not.toHaveProperty('partial');
    const [viewRow, downloadRow, registerRow] = page.items.map((row) => mapAuditLogDto(row));
    expect([uiLabel(viewRow.action), uiLabel(downloadRow.action)]).toEqual(['문서 열람', '문서 내려받기']);
    expect(registerRow.changes).toMatchObject({ documentVersion: '1' });
    expect(registerRow.changes?.viewMode).toBeUndefined();
    render(<AuditChangeDetails changes={downloadRow.changes} action={downloadRow.action} />);
    const details = document.querySelector('.audit-change-details') as HTMLElement;
    expect([...details.querySelectorAll('dt')].map((node) => `${node.textContent}=${node.nextElementSibling?.textContent}`)).toEqual(['판=2', '형식=PDF', '보기 방식=내려받기', '열람 번호=3F9A2C1B']);
  });
});
