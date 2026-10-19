import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { SecurityEventsPage } from './SecurityEventsPage';
import { AuditLogsPage } from './AuditLogsPage';
import { eventService } from '@/src/services/eventService';
import { auditService } from '@/src/services/auditService';
import { ApiError } from '@/src/api/errors';

describe('failed refresh keeps successful list data', () => {
  it('keeps event rows and shows a stale-data notice', async () => {
    const get = vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [{ eventId: 'evt-retained', occurredAt: '2026-10-02T00:00:00Z', clientId: 'test', targetLlm: 'ChatGPT', finalAction: 'ALLOW', detectionOutcome: 'UNAVAILABLE', status: 'NEW', detections: [], adminNotes: [], timeline: [] }], total: 1, page: 1, pageSize: 8, totalPages: 1 });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    await screen.findByRole('link', { name: 'evt-retained 상세 보기' });
    expect(screen.getByText('탐지 결과 확인 불가')).toBeInTheDocument();
    get.mockRejectedValue(new ApiError('offline', 'NETWORK'));
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText(/아래는 마지막 성공 조회 결과/);
    expect(screen.getByRole('link', { name: 'evt-retained 상세 보기' })).toBeInTheDocument();
    expect(screen.queryByText('이벤트를 불러오지 못했습니다.')).not.toBeInTheDocument();
  });
  it('keeps an expanded audit change and URI-encodes target IDs', async () => {
    const get = vi.spyOn(auditService, 'getLogs').mockResolvedValue({ items: [{ auditId: 'audit-1', occurredAt: '2026-10-02T00:00:00Z', adminId: 'admin-1', action: 'DOCUMENT_DISABLE', targetType: 'DOCUMENT', targetId: 'doc/#1', result: 'SUCCESS', changes: { previousStatus: 'ACTIVE', newStatus: 'INACTIVE' } }], total: 1, page: 1, pageSize: 9, totalPages: 1 });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><AuditLogsPage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('link', { name: 'doc/#1' })).toHaveAttribute('href', '/documents/doc%2F%231');
    fireEvent.click(screen.getByRole('button', { name: 'audit-1 상세 열기' }));
    expect(screen.getByText('변경 전: 활성')).toBeInTheDocument();
    get.mockRejectedValue(new ApiError('offline', 'NETWORK'));
    fireEvent.click(screen.getByRole('button', { name: '새로고침', hidden: true }));   // 재설계 3g: 서랍(모달)이 열린 동안 뒤 화면은 숨김 요소
    await screen.findByText(/아래는 마지막 성공 조회 결과/);
    expect(screen.getByText('변경 후: 비활성')).toBeInTheDocument();
  });
  it('does not keep showing rows when permissions are denied', async () => {
    const get = vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [{ eventId: 'evt-permission', occurredAt: '2026-10-02T00:00:00Z', clientId: 'test', targetLlm: 'ChatGPT', finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', status: 'NEW', detections: [], adminNotes: [], timeline: [] }], total: 1, page: 1, pageSize: 8, totalPages: 1 });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    await screen.findByRole('link', { name: 'evt-permission 상세 보기' });
    get.mockRejectedValue(new ApiError('denied', 'FORBIDDEN', 403));
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText('이 작업을 수행할 권한이 없습니다.');
    expect(screen.queryByRole('link', { name: 'evt-permission 상세 보기' })).not.toBeInTheDocument();
  });
});
