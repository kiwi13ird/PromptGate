import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { EventsTable } from '@/src/components/EventsTable';
import { EventDetailPage } from './EventDetailPage';
import { SecurityEventsPage } from './SecurityEventsPage';
import { eventService } from '@/src/services/eventService';
import type { SecurityEvent } from '@/src/types/event';
const event: SecurityEvent = { eventId: 'evt-back', occurredAt: '2026-10-04T00:00:00Z', clientId: 'client-a', targetLlm: 'ChatGPT', finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', status: 'NEW', adminNotes: [], timeline: [], detections: [] };
const original = '/events?period=30D&finalAction=BLOCK&page=2&llm=Gemini';
function List() { const location = useLocation(); return <><p>{location.pathname + location.search}</p><EventsTable events={[event]}/></>; }
function view(node: React.ReactNode) { return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{node}</QueryClientProvider>); }
describe('review navigation continuity', () => {
  it.each(['link', 'keyboard'] as const)('preserves list filters and page after opening by %s and toggling view', async method => {
    vi.spyOn(eventService, 'getEventById').mockResolvedValue(event);
    view(<MemoryRouter initialEntries={[original]}><Routes><Route path="/events" element={<List/>}/><Route path="/events/:eventId" element={<EventDetailPage/>}/></Routes></MemoryRouter>);
    if (method === 'link') fireEvent.click(screen.getByRole('link', { name: 'evt-back 상세 보기' }));
    else fireEvent.keyDown(screen.getByRole('row', { name: 'evt-back 상세 보기' }), { key: 'Enter' });
    fireEvent.click(await screen.findByRole('button', { name: '운영 화면으로' }));
    expect(screen.getByRole('link', { name: '보안 이벤트로 돌아가기' })).toHaveAttribute('href', original);
    fireEvent.click(screen.getByRole('link', { name: '보안 이벤트로 돌아가기' }));
    expect(await screen.findByText(original)).toBeInTheDocument();
  });
  it('opens the request finder for the documented anchor URL', async () => {
    vi.spyOn(eventService, 'getEvents').mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 8, totalPages: 0 });
    view(<MemoryRouter initialEntries={['/events#request-finder']}><SecurityEventsPage/></MemoryRouter>);
    expect(screen.getByText('요청 ID로 기록 조회').closest('details')).toHaveAttribute('open');
  });
});
