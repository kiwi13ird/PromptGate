import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { evidenceService, type EventEvidence } from '@/src/services/evidenceService';
import type { SecurityEvent } from '@/src/types/event';
import { EventEvidencePanel } from './EventEvidencePanel';
import { EventsTable } from './EventsTable';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));

const base: SecurityEvent = { eventId: 'evt-block', requestId: 'req-block', occurredAt: '2026-10-07T01:00:00Z', clientId: 'chrome-1', targetLlm: 'ChatGPT', finalAction: 'BLOCK', detectionOutcome: 'MATCH', degraded: false, status: 'NEW', adminNotes: [], timeline: [],
  detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', score: 0.9, scoreKind: 'COVERAGE', matchedDocumentId: 'doc-13', matchedDocumentName: '파트너사 협상자료', documentSpan: { charStart: 0, charEnd: 100, endExclusive: true } }] };
const mask: SecurityEvent = { ...base, eventId: 'evt-mask', finalAction: 'MASK', detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', entityCounts: [{ entityType: 'KR_PHONE_NUMBER', count: 1 }] }] };
const allow: SecurityEvent = { ...base, eventId: 'evt-allow', finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [] };
const notRecorded = (id: string): EventEvidence => ({ event_id: id, source: 'RDS_DECISION_LOG', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', status: 'NOT_RECORDED', comparisons: [] });

function view(events: SecurityEvent[], evidenceToggle = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/events']}><Routes>
    <Route path="/events" element={<EventsTable events={events} evidenceToggle={evidenceToggle} />} />
    <Route path="/events/:id" element={<p>상세 화면</p>} />
  </Routes></MemoryRouter></QueryClientProvider>);
}

beforeEach(() => vi.restoreAllMocks());

describe('원문 보기 toggle in the security event list', () => {
  it('appears only for blocked or masked matches', () => {
    vi.spyOn(evidenceService, 'getEventEvidence').mockImplementation(async id => notRecorded(id));
    view([base, mask, allow]);
    expect(screen.getByRole('button', { name: 'evt-block 원문 보기' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'evt-mask 원문 보기' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'evt-allow 원문 보기' })).not.toBeInTheDocument();
  });
  it('expands the evidence under the row without opening the detail page, and collapses again', async () => {
    const evidence = vi.spyOn(evidenceService, 'getEventEvidence').mockImplementation(async id => notRecorded(id));
    view([base, mask]);
    const toggle = screen.getByRole('button', { name: 'evt-block 원문 보기' });
    fireEvent.click(toggle);
    expect(screen.queryByText('상세 화면')).not.toBeInTheDocument();
    expect(await screen.findByText('연결할 수 있는 당시 기록 또는 비교용 텍스트가 없습니다.')).toBeInTheDocument();
    expect(evidence).toHaveBeenCalledWith('evt-block', expect.anything());
    expect(evidence).not.toHaveBeenCalledWith('evt-mask', expect.anything());
    const close = screen.getByRole('button', { name: 'evt-block 원문 닫기' });
    expect(close).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(close);
    expect(screen.queryByText('연결할 수 있는 당시 기록 또는 비교용 텍스트가 없습니다.')).not.toBeInTheDocument();
  });
  it('is not shown where the list is used without the toggle', () => {
    view([base], false);
    expect(screen.queryByRole('button', { name: 'evt-block 원문 보기' })).not.toBeInTheDocument();
  });
});

describe('evidence captions follow the redaction setting', () => {
  const maskEvidence = (redaction: 'APPLIED' | 'OFF'): EventEvidence => ({ ...notRecorded('evt-mask'), status: 'AVAILABLE', redaction,
    mask_comparison: { status: 'REQUEST_REWRITTEN', entity_counts: [{ entity_type: 'KR_PHONE_NUMBER', count: 1 }],
      before_preview: redaction === 'OFF' ? '문의 010-1234-5678 입니다' : '문의 █████████████ 입니다', after_preview: '문의 [KR_PHONE_NUMBER] 입니다',
      before_chars: 20, after_chars: 24, preview_truncated: false, spans: [{ start: 3, end: 16, entityType: 'KR_PHONE_NUMBER' }], outbound_text_sha256: 'a'.repeat(64) } });
  function panel(value: EventEvidence) {
    vi.spyOn(evidenceService, 'getEventEvidence').mockResolvedValue(value);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-mask" /></MemoryRouter></QueryClientProvider>);
  }
  it('says the original is shown when redaction is off', async () => {
    panel(maskEvidence('OFF'));
    expect(await screen.findByText('RDS 기록 기반 · 원문 그대로 표시')).toBeInTheDocument();
    expect(screen.getByText('치환 전 입력 · 원문')).toBeInTheDocument();
    const before = screen.getByText('치환 전 입력 · 원문').closest('section') as HTMLElement;
    expect(within(before).getByText('010-1234-5678')).toBeInTheDocument();
    expect(screen.queryByText(/민감 값은 █로 보호/)).not.toBeInTheDocument();
  });
  it('shows the original request with highlights when the server restored the same input (before_raw), whatever the redaction setting', async () => {
    const value=maskEvidence('APPLIED');
    value.mask_comparison={...value.mask_comparison!,before_preview:'문의 010-1234-5678 입니다',before_raw:true};
    panel(value);
    expect(await screen.findByText('치환 전 입력 · 원문')).toBeInTheDocument();
    const before = screen.getByText('치환 전 입력 · 원문').closest('section') as HTMLElement;
    expect(within(before).getByText('010-1234-5678')).toBeInTheDocument();
    expect(within(before).getByText('010-1234-5678').tagName).toBe('MARK');
    expect(screen.getByText('RDS 기록 기반 · 원문 그대로 표시')).toBeInTheDocument();
    expect(screen.queryByText(/민감 값은 █로 보호/)).not.toBeInTheDocument();
  });
  it('keeps the protection captions when redaction is applied', async () => {
    panel(maskEvidence('APPLIED'));
    expect(await screen.findByText('치환 전 입력 · 민감 값 보호')).toBeInTheDocument();
    expect(screen.getByText('RDS 기록 기반 · 민감정보 보호 표시')).toBeInTheDocument();
    expect(screen.getByText(/민감 값은 █로 보호/)).toBeInTheDocument();
  });
});
