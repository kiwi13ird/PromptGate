import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { EventDetailPage } from './EventDetailPage';
import { eventService } from '@/src/services/eventService';
import type { SecurityEvent } from '@/src/types/event';
import { ApiError } from '@/src/api/errors';

vi.mock('@/src/utils/feedback', async importOriginal => ({ ...await importOriginal<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
const fixture: SecurityEvent = { eventId: 'evt-a', occurredAt: '2026-10-02T00:00:00Z', clientId: 'test-client', targetLlm: 'ChatGPT', detectionOutcome: 'NO_MATCH', finalAction: 'ALLOW', status: 'NEW', adminNotes: [], timeline: [], detections: [] };
function NextEvent() { const navigate = useNavigate(); return <button onClick={() => navigate('/events/evt-b')}>다른 이벤트 열기</button>; }
function open(value = fixture) {
  const get = vi.spyOn(eventService, 'getEventById').mockImplementation(async id => ({ ...value, eventId: id }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/events/evt-a']}><NextEvent /><Routes><Route path="/events/:eventId" element={<EventDetailPage />} /></Routes></MemoryRouter></QueryClientProvider>);
  return { client, get };
}
describe('incident workflow safety', () => {
  it('does not describe unavailable detection as no match or low severity', async () => {
    open({ ...fixture, detectionOutcome: 'UNAVAILABLE' });
    const title = await screen.findByRole('heading', { name: '탐지 결과 확인 불가' });
    expect(title.closest('section')).toHaveClass('hero-unknown');
    expect(screen.getByText(/안전하다고 확인된 요청은 아닙니다/)).toBeInTheDocument();
  });
  it('keeps note input after failure and blocks other writes while saving', async () => {
    let reject!: (error: Error) => void;
    const save = vi.spyOn(eventService, 'addNote').mockReturnValue(new Promise((_, fail) => { reject = fail; }));
    open();
    fireEvent.click(await screen.findByText('관리자 조사 · 담당자 · 메모 · 처리 이력'));
    const note = await screen.findByLabelText('메모');
    fireEvent.change(note, { target: { value: '  확인한 내용  ' } });
    fireEvent.click(screen.getByRole('button', { name: '메모 추가' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith('evt-a', '확인한 내용'));
    expect(screen.getByLabelText('상태')).toBeDisabled();
    expect(screen.getByLabelText('담당자')).toBeDisabled();
    expect(note).toBeDisabled();
    reject(new ApiError('private error detail', 'NETWORK'));
    expect(await screen.findByRole('alert')).toHaveTextContent('입력 내용은 유지됩니다');
    expect(screen.queryByText('private error detail')).not.toBeInTheDocument();
    expect(note).toHaveValue('  확인한 내용  ');
    expect(note).not.toBeDisabled();
    expect(note).toHaveAttribute('maxlength', '2000');
    expect(screen.getByLabelText('담당자')).toHaveAttribute('maxlength', '200');
  });
  it('does not carry an unsaved note or assignee into another event', async () => {
    open();
    fireEvent.click(await screen.findByText('관리자 조사 · 담당자 · 메모 · 처리 이력'));
    fireEvent.change(await screen.findByLabelText('메모'), { target: { value: 'evt-a draft' } });
    fireEvent.change(screen.getByLabelText('담당자'), { target: { value: 'reviewer-a' } });
    fireEvent.click(screen.getByRole('button', { name: '다른 이벤트 열기' }));
    await screen.findByText('evt-b');
    expect(screen.getByLabelText('메모')).toHaveValue('');
    expect(screen.getByLabelText('담당자')).toHaveValue('');
  });
  it('keeps the last event and draft after refresh failure while preventing stale writes', async () => {
    const { get } = open();
    fireEvent.click(await screen.findByText('관리자 조사 · 담당자 · 메모 · 처리 이력'));
    fireEvent.change(await screen.findByLabelText('메모'), { target: { value: 'keep this draft' } });
    get.mockRejectedValue(new ApiError('offline', 'NETWORK'));
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await screen.findByText(/아래는 마지막 성공 조회 결과/);
    expect(screen.getByText('evt-a')).toBeInTheDocument();
    expect(screen.getByLabelText('메모')).toHaveValue('keep this draft');
    expect(screen.getByRole('button', { name: '메모 추가' })).toBeDisabled();
    get.mockResolvedValue(fixture);
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '메모 추가' })).not.toBeDisabled());
    expect(screen.getByLabelText('메모')).toHaveValue('keep this draft');
  });
});
