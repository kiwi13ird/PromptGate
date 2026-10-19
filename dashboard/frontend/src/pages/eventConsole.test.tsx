import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SecurityEventsPage } from './SecurityEventsPage';
import { EventDetailPage } from './EventDetailPage';
import { eventService } from '@/src/services/eventService';
import { evidenceService } from '@/src/services/evidenceService';
import type { SecurityEvent } from '@/src/types/event';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
const event: SecurityEvent = { eventId: 'evt/#Case', requestId: 'req-MixedCase', clientId: 'client-MixedCase', occurredAt: '2026-10-05T00:00:00Z', targetLlm: 'Gemini', finalAction: 'BLOCK', recommendedAction: 'BLOCK', detectionOutcome: 'MATCH', status: 'NEW', processingMs: 2974.1, contentType: 'prompt', enforcement: { applied: true, httpStatus: 403 }, detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', score: 0.999, scoreKind: 'COVERAGE', matchedDocumentId: 'doc/#Case', matchedDocumentName: '공정 원본', documentSpan: { charStart: 0, charEnd: 100, endExclusive: true } }], adminNotes: [], timeline: [] };
function view(node: React.ReactNode, initial = '/events?period=30D&page=2') {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><MemoryRouter initialEntries={[initial]}>{node}</MemoryRouter></QueryClientProvider>);
}
beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [event], total: 21, page: 2, totalPages: 3, pageSize: 8 });
  vi.spyOn(eventService, 'getEventById').mockResolvedValue(event);
  vi.spyOn(evidenceService, 'getEventEvidence').mockResolvedValue({ status: 'NOT_RECORDED', event_id: event.eventId, source: 'RDS_DECISION_LOG', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', comparisons: [] });
});
describe('Security Events and detail console presentation', () => {
  it('uses a five-column table and puts operational fields beneath the rows, not in a wide table', async () => {
    const { container } = view(<SecurityEventsPage />);
    await screen.findByRole('link', { name: `${event.eventId} 상세 보기` });
    const table = screen.getByRole('table');
    expect(within(table).getAllByRole('columnheader')).toHaveLength(5);
    expect(screen.queryByText('근거 보기 →')).toBeNull();
    expect(screen.getByRole('link', { name: `${event.eventId} 상세 보기` })).toHaveTextContent(event.eventId);
    expect(container.querySelector('.console-page-header .console-refresh')).not.toBeNull();
    const get = vi.mocked(eventService.getEvents), calls = get.mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: '운영 정보 보기' }));
    expect(within(table).getAllByRole('columnheader')).toHaveLength(5);
    expect(screen.getByText(event.clientId)).toBeInTheDocument();
    expect(screen.getByText(event.requestId!)).toBeInTheDocument();
    expect(get.mock.calls).toHaveLength(calls);
    expect(screen.getByText(/같은 글자/)).toBeInTheDocument();   // 2026-10-16: 목록 비율 = 같은 글자 비율
  });
  it('keeps original search/filter enum values and resets only pagination when a condition changes', async () => {
    view(<SecurityEventsPage />);
    await screen.findByRole('table');
    fireEvent.change(screen.getByLabelText('탐지 방식'), { target: { value: 'WINDOW_HASH' } });
    await waitFor(() => expect(eventService.getEvents).toHaveBeenLastCalledWith(expect.objectContaining({ detector: 'WINDOW_HASH', period: '30D', page: 1, pageSize: 20, group: 'request' }), expect.any(AbortSignal)));
    fireEvent.change(screen.getByLabelText('문서명 / 이벤트·요청·클라이언트 ID 검색'), { target: { value: ' req-MixedCase ' } });
    fireEvent.click(screen.getByRole('button', { name: '검색' }));
    await waitFor(() => expect(eventService.getEvents).toHaveBeenLastCalledWith(expect.objectContaining({ query: 'req-MixedCase', detector: 'WINDOW_HASH', period: '30D', page: 1 }), expect.any(AbortSignal)));
  });
  it('preserves filtered-list return state when a whole row is opened with the keyboard', async () => {
    const initial = '/events?period=30D&finalAction=BLOCK&page=2&llm=Gemini';
    view(<Routes><Route path="/events" element={<SecurityEventsPage />} /><Route path="/events/:eventId" element={<EventDetailPage />} /></Routes>, initial);
    fireEvent.keyDown(await screen.findByRole('row', { name: `${event.eventId} 상세 보기` }), { key: 'Enter' });
    expect(await screen.findByRole('link', { name: '보안 이벤트로 돌아가기' })).toHaveAttribute('href', initial);
  });
  it('keeps request information visible and technical/workflow details initially collapsed', async () => {
    const { container } = view(<Routes><Route path="/events/:eventId" element={<EventDetailPage />} /></Routes>, '/events/evt%2F%23Case?view=operations');
    await screen.findByText(event.eventId);
    expect(container.querySelector('.console-request-summary')).toHaveAttribute('aria-label', '요청 정보');
    expect(screen.getByText(event.clientId)).toHaveClass('mono');
    expect(within(container.querySelector('.console-request-summary') as HTMLElement).getByText('2.97초')).toBeInTheDocument();
    expect(container.querySelector('.technical-disclosure')).not.toHaveAttribute('open');
    expect(container.querySelector('.admin-disclosure')).not.toHaveAttribute('open');
    expect(container.querySelector('.event-detail-toolbar .console-refresh')).not.toBeNull();
    expect(screen.queryByText(/^(DB 정상|Redis 정상|현재 정책)$/)).toBeNull();
  });
});
