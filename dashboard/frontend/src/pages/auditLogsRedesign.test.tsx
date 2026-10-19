// 재설계 3g(설계 5.12·4.7·4.8): 감사 로그 필터 바(핵심 2개 + 더보기·칩·초기화), 5열 + 행 누르면 서랍, 같은 ID는 '본인'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditLogsPage } from './AuditLogsPage';
import { auditService } from '@/src/services/auditService';

const page = (items: Parameters<typeof auditService.getLogs> extends never ? never : Awaited<ReturnType<typeof auditService.getLogs>>['items']) => ({ items, total: items.length, page: 1, pageSize: 9, totalPages: 1 });
const login = { auditId: 'audit-1', occurredAt: '2026-10-10T01:00:00Z', adminId: 'local-admin', action: 'ADMIN_LOGIN' as const, targetType: 'ADMIN' as const, targetId: 'local-admin', result: 'SUCCESS' as const };
const failed = { auditId: 'audit-2', occurredAt: '2026-10-10T02:00:00Z', adminId: 'local-admin', action: 'POLICY_UPDATE' as const, targetType: 'POLICY' as const, targetId: 'POLICY-PII-MASK', result: 'FAILURE' as const, changes: { previousVersion: 1, newVersion: 2 } };
const mount = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuditLogsPage /></MemoryRouter></QueryClientProvider>);

beforeEach(() => vi.restoreAllMocks());

describe('audit logs (3g)', () => {
  it('shows five columns with the action as the title, 본인 for self targets and a result badge', async () => {
    vi.spyOn(auditService, 'getLogs').mockResolvedValue(page([login, failed]));
    mount();
    const table = await screen.findByRole('table', { name: '감사 로그' });
    expect(within(table).getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['발생 시각', '관리자', '작업', '대상', '결과', '상세']);
    const [, selfRow, failRow] = within(table).getAllByRole('row');
    expect(within(selfRow).getByText('본인')).toHaveAttribute('title', 'local-admin');
    expect(within(selfRow).queryByRole('link')).toBeNull();
    expect(within(failRow).getByText('실패')).toHaveAttribute('data-tone', 'block');
    expect(failRow).toHaveAttribute('data-tone', 'block');
    expect(within(failRow).getByRole('link', { name: 'POLICY-PII-MASK' })).toHaveAttribute('href', '/policies?policyId=POLICY-PII-MASK');
  });
  it('opens the change drawer by clicking the row (not the target link) and closes it', async () => {
    vi.spyOn(auditService, 'getLogs').mockResolvedValue(page([failed]));
    mount();
    const table = await screen.findByRole('table', { name: '감사 로그' });
    fireEvent.click(within(table).getByText('정책 수정'));
    const drawer = await screen.findByRole('dialog', { name: '정책 수정 · 변경 내용' });
    expect(within(drawer).getByRole('region', { name: '기록된 변경 전후' })).toHaveTextContent('변경 후: v2');
    fireEvent.click(within(drawer).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });
  it('keeps period and action in the bar, result and admin under 더보기, and shows chips for non-default filters', async () => {
    const get = vi.spyOn(auditService, 'getLogs').mockResolvedValue(page([login]));
    mount();
    await screen.findByRole('table', { name: '감사 로그' });
    const bar = screen.getByRole('search', { name: '감사 로그 필터' });
    expect(within(bar).getByLabelText('기간')).toBeInTheDocument();
    expect(within(bar).getByLabelText('작업 유형')).toBeInTheDocument();
    expect(within(bar).queryByLabelText('결과')).toBeNull();
    fireEvent.click(within(bar).getByRole('button', { name: /필터 더보기/ }));
    fireEvent.change(within(bar).getByLabelText('결과'), { target: { value: 'FAILURE' } });
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(expect.objectContaining({ result: 'FAILURE', page: 1 }), expect.anything()));
    fireEvent.change(within(bar).getByLabelText('기간'), { target: { value: '7D' } });
    const chips = within(bar).getByLabelText('적용한 필터');
    expect(within(chips).getByText('결과: 실패')).toBeInTheDocument();
    expect(within(chips).getByText('기간: 최근 7일')).toBeInTheDocument();
    fireEvent.click(within(chips).getByRole('button', { name: '초기화' }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(expect.objectContaining({ period: '24H', result: 'ALL' }), expect.anything()));
    expect(within(bar).queryByLabelText('적용한 필터')).toBeNull();
  });
});
