import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ProtectedDocumentsPage } from './ProtectedDocumentsPage';
import { PolicyManagementPage } from './PolicyManagementPage';
import { AuditLogsPage } from './AuditLogsPage';
import { documentService } from '@/src/services/documentService';
import { policyService } from '@/src/services/policyService';
import { auditService } from '@/src/services/auditService';
import type { ConfidentialDocument, DetectionPolicy } from '@/src/types/policy';
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
const doc: ConfidentialDocument = { documentId: 'doc/#1', documentName: '공정 문서.pdf', registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'PDF', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 5, activeDetectors: ['WINDOW_HASH'] };
const policy: DetectionPolicy = { policyId: 'POL/#1', detector: 'SIGNATURE', detectionTarget: 'KR_PHONE_NUMBER', action: 'MASK', policyAction: 'MASK_FULL', finalPolicyAction: 'MASK_FULL', targetLlms: ['Gemini'], priority: 100, updatedBy: 'admin-1', version: 2, enabled: true, versions: [] };
function mount(node: React.ReactNode, route = '/documents') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}>{node}</MemoryRouter></QueryClientProvider>) };
}
beforeEach(() => vi.restoreAllMocks());
describe('full console presentation preserves management behavior', () => {
  it('derives document counts from real fields and filters formats without adding API parameters', async () => {
    const get = vi.spyOn(documentService, 'getDocuments').mockResolvedValue([doc, { ...doc, documentId: 'doc-2', documentName: '기획.docx', fileType: 'DOCX', status: 'INACTIVE', processingStatus: 'FAILED', chunkIndexStatus: 'FAILED' }]);
    const { container } = mount(<ProtectedDocumentsPage/>);
    await screen.findByRole('link', { name: doc.documentName });
    // 재설계 3e: 집계 4칸 → 상태 띠 + 세그먼트 숫자(문서 상태·색인 상태를 배지 1개로 합친 같은 규칙, 설계 5.4). 표 7열 → 5열(탐지 기록이 없으면 그 열 숨김, 4.5)
    expect(container.querySelector('.console-metrics')).toBeNull();
    expect(screen.getByRole('status', { name: '보호 문서 상태' })).toHaveTextContent('2개 중 1개 보호 중');
    expect(screen.getAllByRole('radio').map(radio => radio.closest('label')?.textContent)).toEqual(['전체 2', '보호 중 1', '분석 중 0', '분석 실패 0', '보호 중지 1']);
    expect(screen.getAllByRole('columnheader').map(head => head.textContent)).toEqual(['문서', '상태', '소유자', '등록', '조치']);
    fireEvent.click(screen.getByRole('button', { name: '필터 더보기' }));
    fireEvent.change(screen.getByLabelText('파일 형식'), { target: { value: 'DOCX' } });
    expect(screen.queryByRole('link', { name: doc.documentName })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: '기획.docx' })).toBeInTheDocument();
    expect(get).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: '초기화' }));
    expect(screen.getByRole('link', { name: doc.documentName })).toBeInTheDocument();
  });
  it.each([
    ['bad.exe','application/octet-stream','x','PDF, DOCX, XLSX, HWP, HWPX 파일만'],
    ['bad.pdf','image/png','x','MIME 유형'],
    ['empty.pdf','application/pdf','','내용이 없는 파일'],
  ])('blocks invalid upload %s without a registration request', async (name, mime, content, error) => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([doc]);
    const register = vi.spyOn(documentService, 'registerDocument');
    mount(<ProtectedDocumentsPage/>);
    await screen.findByRole('link', { name: doc.documentName });
    fireEvent.click(screen.getByRole('button', { name: '문서 등록' }));
    fireEvent.change(screen.getByLabelText('등록할 문서 파일'), { target: { files: [new File([content], name, { type: mime })] } });
    expect(await screen.findByRole('alert')).toHaveTextContent(error);
    expect(screen.getByRole('button', { name: '등록' })).toBeDisabled();
    expect(register).not.toHaveBeenCalled();
  });
  it('passes the selected File unchanged to the existing registration service and refreshes', async () => {
    const get = vi.spyOn(documentService, 'getDocuments').mockResolvedValue([doc]);
    const register = vi.spyOn(documentService, 'registerDocument').mockResolvedValue(doc);
    mount(<ProtectedDocumentsPage/>); await screen.findByRole('link', { name: doc.documentName });
    fireEvent.click(screen.getByRole('button', { name: '문서 등록' }));
    const file = new File(['%PDF QA fixture'], 'qa.pdf', { type: 'application/pdf' });
    fireEvent.change(screen.getByLabelText('등록할 문서 파일'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: '등록' }));
    await waitFor(() => expect(register).toHaveBeenCalledWith(file));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(get.mock.calls.length).toBeGreaterThan(1);
  });
  it('keeps status confirmation and sends the same id and desired status', async () => {
    vi.spyOn(documentService, 'getDocuments').mockResolvedValue([doc]);
    const change = vi.spyOn(documentService, 'changeDocumentStatus').mockResolvedValue({ ...doc, status: 'INACTIVE' });
    mount(<ProtectedDocumentsPage/>);
    fireEvent.click(await screen.findByRole('button', { name: doc.documentName + ' 더보기' }));
    fireEvent.click(await screen.findByRole('menuitem', { name: '보호 중지' }));
    expect(change).not.toHaveBeenCalled();
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '보호 중지' }));
    await waitFor(() => expect(change).toHaveBeenCalledWith(doc.documentId, 'INACTIVE'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
  // 2026-10-16: 정책 생성 2단계·수정 대화상자 → 분류별 항목 토글(켬 = 생성/활성, 끔 = 비활성, 처리 방식 선택 = 수정). 보내는 값은 그대로
  it('creates an item policy from its toggle with only the target code and action', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    const create = vi.spyOn(policyService, 'createPolicy').mockResolvedValue(policy);
    mount(<PolicyManagementPage/>, '/policies'); await screen.findByRole('list', { name: '개인정보 항목' });
    const email = screen.getByRole('switch', { name: '이메일 따로 처리' });
    await waitFor(() => expect(email).toBeEnabled());
    expect(create).not.toHaveBeenCalled();
    fireEvent.click(email);   // 개인정보 분류 정책이 없으므로 지금 받는 처리(기본 차단)로 만든다
    await waitFor(() => expect(create).toHaveBeenCalledWith('EMAIL_ADDRESS','BLOCK'));
  });
  it('sends an action change with the optimistic version guard', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    const update = vi.spyOn(policyService, 'updatePolicy').mockResolvedValue({ ...policy, action: 'BLOCK', version: 3 });
    mount(<PolicyManagementPage/>, '/policies');
    const select = await screen.findByRole('combobox', { name: '전화번호 처리 방식' });
    await waitFor(() => expect(select).toBeEnabled());
    expect(select).toHaveValue('MASK_FULL');
    expect(screen.queryByRole('textbox')).toBeNull();   // 대상은 고르기만(입력 칸 없음)
    fireEvent.change(select, { target: { value: 'BLOCK' } });
    await waitFor(() => expect(update).toHaveBeenCalledWith(policy.policyId, 'BLOCK', 2));
  });
  it('keeps the status mutation and expected version', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    const toggle = vi.spyOn(policyService, 'changePolicyStatus').mockResolvedValue({ ...policy, enabled: false, version: 3 });
    mount(<PolicyManagementPage/>, '/policies');
    const phone = await screen.findByRole('switch', { name: '전화번호 따로 처리' });
    await waitFor(() => expect(phone).toBeEnabled());   // 2026-10-15: 처리 방식 목록을 받은 뒤에만 활성 변경
    expect(phone).toHaveAttribute('aria-checked', 'true');
    fireEvent.click(phone);
    await waitFor(() => expect(toggle).toHaveBeenCalledWith(policy.policyId, false, 2));
  });
  it('shows history previous values only when the preceding version is retained', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    vi.spyOn(policyService, 'getPolicyHistory').mockResolvedValue([{ version: 1, action: 'MASK', actionVariant: undefined, policyAction: 'MASK_FULL', createdAt: '2026-10-01T00:00:00Z', changedBy: 'admin-1', enabled: true }, { version: 2, action: 'BLOCK', actionVariant: undefined, policyAction: 'BLOCK', createdAt: '2026-10-02T00:00:00Z', changedBy: 'admin-2', enabled: true }, { version: 4, action: 'BLOCK', actionVariant: undefined, policyAction: 'BLOCK', createdAt: '2026-10-04T00:00:00Z', changedBy: 'admin-3', enabled: false }]);
    mount(<PolicyManagementPage/>, '/policies'); fireEvent.click(await screen.findByRole('button', { name: /더보기$/ })); fireEvent.click(await screen.findByRole('menuitem', { name: '변경 이력' }));   // 3f: ⋯ 메뉴 · 이력은 서랍(dialog 역할)
    const dialog = await screen.findByRole('dialog'); await within(dialog).findByText('admin-2');
    const rows = within(dialog).getAllByRole('row');
    // 2026-10-15: '이전 조치' 열 → '변경 내용'(앞 버전과 비교). v3이 없는 v4는 이전 버전 미기록, v1은 최초 생성
    expect(rows[1]).toHaveTextContent('v4'); expect(rows[1]).toHaveTextContent('이전 버전 미기록');
    expect(rows[2]).toHaveTextContent('처리 방식 전체 마스킹 → 차단'); expect(rows[2]).toHaveTextContent('차단');
    expect(rows[3]).toHaveTextContent('최초 생성'); expect(rows[3]).toHaveTextContent('전체 마스킹');
  });
  it('opens recorded-policy navigation using only the existing policies route', async () => {
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy]);
    mount(<PolicyManagementPage/>, '/policies?policyId=POL%2F%231');
    const phone = await screen.findByRole('switch', { name: '전화번호 따로 처리' });
    expect(phone.closest('li')).toHaveAttribute('aria-current', 'true');   // 2026-10-16: 그 정책의 항목 줄을 강조
    expect(screen.getByRole('switch', { name: '이메일 따로 처리' }).closest('li')).not.toHaveAttribute('aria-current');
  });
  it('keeps audit filtering, pagination and selected row details without changing enum values', async () => {
    const get = vi.spyOn(auditService, 'getLogs').mockResolvedValue({ items: [{ auditId: 'audit-1', occurredAt: '2026-10-01T00:00:00Z', adminId: 'admin-1', action: 'POLICY_UPDATE', targetType: 'POLICY', targetId: 'POL/#1', result: 'SUCCESS', changes: { previousVersion: 1, newVersion: 2 } }], page: 1, pageSize: 9, total: 20, totalPages: 3 });
    const { container } = mount(<AuditLogsPage/>, '/audit-logs');
    expect(await screen.findByRole('link', { name: 'POL/#1' })).toHaveAttribute('href', '/policies?policyId=POL%2F%231');
    fireEvent.click(screen.getByRole('button', { name: 'audit-1 상세 열기' }));
    expect(container.querySelector('.console-selected-row')).not.toBeNull();
    expect(screen.getByText('변경 후: v2')).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '닫기' }));   // 재설계 3g: 변경 내용은 서랍 — 닫고 쪽 이동
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    fireEvent.click(screen.getByRole('button', { name: '다음 페이지' }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 }), expect.anything()));
    fireEvent.change(screen.getByLabelText('작업 유형'), { target: { value: 'POLICY_CREATE' } });
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, action: 'POLICY_CREATE' }), expect.anything()));
  });
});
