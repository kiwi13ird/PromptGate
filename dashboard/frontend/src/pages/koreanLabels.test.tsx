import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { SecurityEventsPage } from './SecurityEventsPage';
import { eventService } from '@/src/services/eventService';
import { uiLabel } from '@/src/utils/labels';

describe('Korean display labels', () => {
  it('translates display detector labels while leaving unknown identifiers unchanged', () => {
    expect(uiLabel('ALL')).toBe('전체');
    expect(uiLabel('NO_MATCH')).toBe('일치 없음');
    expect(uiLabel('COVERAGE')).toBe('해시 근거 비율');   // 2026-10-16 '일치 비율' 통일: 화면의 일치 비율은 같은 글자 비율 하나
    expect(uiLabel('WINDOW_HASH')).toBe('문서 구간 검사');
    expect(uiLabel('evt-abc')).toBe('evt-abc');
    expect(uiLabel(undefined)).toBe('당시 미기록');
  });

  it('sends the original enum values when Korean filter options are selected', async () => {
    const getEvents = vi.spyOn(eventService, 'getEvents').mockResolvedValue({
      items: [], total: 0, page: 1, pageSize: 8, totalPages: 1,
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><SecurityEventsPage /></MemoryRouter></QueryClientProvider>);
    fireEvent.click(screen.getByRole('button', { name: '상세 조건' }));
    const match = await screen.findByLabelText('일치 유형');
    expect(screen.getByRole('option', { name: '문서 구간 일치' })).toHaveValue('TEXT_FRAGMENT');
    fireEvent.change(match, { target: { value: 'TEXT_FRAGMENT' } });
    fireEvent.change(screen.getByLabelText('조사 상태'), { target: { value: 'INVESTIGATING' } });
    await waitFor(() => expect(getEvents).toHaveBeenLastCalledWith(expect.objectContaining({
      matchType: 'TEXT_FRAGMENT', status: 'INVESTIGATING', severity: 'ALL',
    }), expect.anything()));
    fireEvent.change(screen.getByLabelText('일치 유형'), { target: { value: 'ALL' } });
    await waitFor(() => expect(getEvents).toHaveBeenLastCalledWith(expect.objectContaining({ matchType: 'ALL' }), expect.anything()));
  });
});
