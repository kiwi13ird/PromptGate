import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { auditLogSchema, pageSchema, parseApiResponse } from '@/src/api/schemas';
import { mapAuditLogDto } from '@/src/api/mappers';
import { AuditLogsPage } from '@/src/pages/AuditLogsPage';
import { auditService } from '@/src/services/auditService';
import { uiLabel } from '@/src/utils/labels';
import { AuditChangeDetails } from './AuditChangeDetails';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));

// 백엔드 detectionOps 블록이 실제로 남기는 행 모양(app.mjs recordAuditSafely 호출 그대로)
const rows = [
  { audit_id: 'A1', action: 'REPORT_CREATE', target_type: 'REPORT', target_id: 'report_2026-10-01_2026-10-07_20261007T000000', changes: { from: '2026-10-01', to: '2026-10-07', use_llm: true } },
  { audit_id: 'A2', action: 'KEYWORD_APPROVE', target_type: 'KEYWORD', target_id: '7', changes: { keyword: 'PRJ-2026-07', doc_id: '13_파트너사협상자료', applied: false } },
  { audit_id: 'A3', action: 'KEYWORD_CREATE', target_type: 'KEYWORD', target_id: '8', changes: { keyword: 'TBS 수수료', doc_id: '13_파트너사협상자료', status: 'approved', applied: true } },
  { audit_id: 'A4', action: 'KEYWORD_REJECT', target_type: 'KEYWORD', target_id: '9', changes: { applied: true } },
  { audit_id: 'A5', action: 'KEYWORD_UPDATE', target_type: 'KEYWORD', target_id: '10', changes: { keyword: '24억원', doc_id: '05_투자유치_자료' } },
  { audit_id: 'A6', action: 'KEYWORD_EXTRACT_REQUEST', target_type: 'DOCUMENT', target_id: '13_파트너사협상자료', changes: { job_id: 5, status: 'queued' } },
].map(row => ({ occurred_at: '2026-10-07T01:00:00.000Z', admin_id: 'local-admin', result: 'SUCCESS', ...row }));

beforeEach(() => vi.restoreAllMocks());

describe('audit log accepts report and keyword actions', () => {
  it('parses the new actions and targets instead of failing the whole page', () => {
    const page = parseApiResponse(pageSchema(auditLogSchema), { items: rows, page: 1, page_size: 20, total: rows.length, total_pages: 1 });
    const logs = page.items.map(mapAuditLogDto);
    expect(logs.map(log => log.action)).toEqual(['REPORT_CREATE', 'KEYWORD_APPROVE', 'KEYWORD_CREATE', 'KEYWORD_REJECT', 'KEYWORD_UPDATE', 'KEYWORD_EXTRACT_REQUEST']);
    expect(logs[0].changes).toMatchObject({ reportFrom: '2026-10-01', reportTo: '2026-10-07', useLlm: true });
    expect(logs[1].changes).toMatchObject({ keyword: 'PRJ-2026-07', documentId: '13_파트너사협상자료', detectionApplied: false });
    expect(logs[5].changes).toMatchObject({ jobId: 5, recordedStatus: 'queued' });
  });
  it('still rejects an action the backend never records', () => {
    expect(() => parseApiResponse(pageSchema(auditLogSchema), { items: [{ ...rows[0], action: 'GPU_REBOOT' }], page: 1, page_size: 20, total: 1, total_pages: 1 })).toThrow();
  });
  it('shows Korean names and links report and keyword targets', async () => {
    const page = parseApiResponse(pageSchema(auditLogSchema), { items: rows, page: 1, page_size: 20, total: rows.length, total_pages: 1 });
    vi.spyOn(auditService, 'getLogs').mockResolvedValue({ ...page, items: page.items.map(mapAuditLogDto) } as never);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/audit-logs']}><AuditLogsPage /></MemoryRouter></QueryClientProvider>);
    const table = await screen.findByRole('table');
    for (const name of ['리포트 생성', '키워드 승인', '키워드 추가', '키워드 반려·삭제', '키워드 수정', '키워드 추출 요청'])
      expect(within(table).getByText(name)).toBeInTheDocument();
    expect(within(table).getByRole('link', { name: 'report_2026-10-01_2026-10-07_20261007T000000' })).toHaveAttribute('href', '/reports');
    expect(within(table).getByRole('link', { name: '7' })).toHaveAttribute('href', '/policies/keywords');
    expect(screen.getByRole('option', { name: '키워드 승인' })).toBeInTheDocument();
  });
});

describe('recorded values of report and keyword actions', () => {
  it('lists what was recorded at that moment', () => {
    render(<AuditChangeDetails changes={{ keyword: 'PRJ-2026-07', documentId: '13_파트너사협상자료', detectionApplied: false }} />);
    expect(screen.getByText('PRJ-2026-07')).toBeInTheDocument();
    expect(screen.getByText('13_파트너사협상자료')).toBeInTheDocument();
    expect(screen.getByText('반영 실패')).toBeInTheDocument();
    expect(screen.queryByText(/변경 전·후 값이 기록되지 않았습니다/)).not.toBeInTheDocument();
  });
  it('shows the report period and the analysis sentence choice under the same name as the generate option', () => {
    const { rerender } = render(<AuditChangeDetails changes={{ reportFrom: '2026-10-01', reportTo: '2026-10-07', useLlm: false }} />);
    expect(screen.getByText('2026-10-01 ~ 2026-10-07')).toBeInTheDocument();
    expect(screen.getByText('분석 문장')).toBeInTheDocument();
    expect(screen.getByText('포함 안 함')).toBeInTheDocument();
    expect(screen.queryByText(/LLM/)).toBeNull();
    rerender(<AuditChangeDetails changes={{ reportFrom: '2026-10-01', reportTo: '2026-10-07', useLlm: true }} />);
    expect(screen.getByText('포함')).toBeInTheDocument();
  });
});

describe('detection type names', () => {
  it.each([
    ['KR_BANK_ACCOUNT', '계좌번호'], ['KR_DATE_OF_BIRTH', '생년월일'], ['KR_FOREIGN_REGISTRATION_NUMBER', '외국인등록번호'],
    ['PASSWORD', '비밀번호'], ['GITHUB_TOKEN', 'GitHub 토큰'], ['DOC_KEYWORD', '기밀 키워드'],
  ])('%s → %s', (code, name) => {
    expect(uiLabel(code)).toBe(name);
  });
});
