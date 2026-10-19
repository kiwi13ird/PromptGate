import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { httpGatewayApi } from '@/src/api/httpAdapter';
import { httpClient } from '@/src/api/httpClient';
import { mapSecurityEventDto } from '@/src/api/mappers';
import { pageSchema, parseApiResponse, securityEventSchema } from '@/src/api/schemas';
import { evidenceService, type EventEvidence } from '@/src/services/evidenceService';
import type { SecurityEvent } from '@/src/types/event';
import { EventsTable } from './EventsTable';
import { FileComparisonView, type FileComparison } from './FileComparisonView';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));

const RRN = '900101-1234567';
const at = '2026-10-09T06:30:41.000Z';
const signature = { detector: 'SIGNATURE', match_type: 'SIGNATURE_RULE', action: 'MASK', entity_counts: [{ entity_type: 'KR_RRN', count: 3 }] };
const eventDto = (over: Record<string, unknown>) => ({
  event_id: 'evt-prompt', request_id: 'req-prompt', occurred_at: at, client_id: 'chrome-a', action: 'ALLOW', final_action: 'ALLOW',
  detection_outcome: 'NO_MATCH', status: 'NEW', admin_notes: [], timeline: [], detections: [], target_llm: 'ChatGPT', content_type: 'prompt', ...over,
});
const fileDto = eventDto({ event_id: 'evt-file', request_id: 'req-file', action: 'MASK', final_action: 'MASK', detection_outcome: 'MATCH',
  content_type: 'file', detections: [signature], file_id: 'f1', enforcement: { applied: true } });

beforeEach(() => vi.restoreAllMocks());

describe('question and attached file arrive together', () => {
  it('parses and maps a grouped list item and a detail summary', () => {
    const page = parseApiResponse(pageSchema(securityEventSchema), { items: [eventDto({ attached_file_ids: ['f1'], group_final_action: 'MASK', attached_files: [fileDto] })],
      total: 1, page: 1, page_size: 20, total_pages: 1 });
    const event = mapSecurityEventDto(page.items[0]);
    expect(event.groupFinalAction).toBe('MASK');
    expect(event.attachedFileIds).toEqual(['f1']);
    expect(event.attachedFiles?.[0]).toMatchObject({ eventId: 'evt-file', finalAction: 'MASK', contentType: 'file', detectionOutcome: 'MATCH',
      enforcement: { applied: true } });
    expect(event.attachedFiles?.[0].detections[0]).toMatchObject({ detector: 'SIGNATURE', entityCounts: [{ entityType: 'KR_RRN', count: 3 }] });

    const detail = mapSecurityEventDto(parseApiResponse(securityEventSchema, eventDto({ event_id: 'evt-file', content_type: 'file', file_id: 'f1',
      attached_to: [{ event_id: 'evt-prompt', request_id: 'req-prompt', occurred_at: at, final_action: 'ALLOW', content_type: 'prompt' }] })));
    expect(detail.fileId).toBe('f1');
    expect(detail.attachedTo).toEqual([{ eventId: 'evt-prompt', requestId: 'req-prompt', occurredAt: at, finalAction: 'ALLOW', contentType: 'prompt',
      detectionOutcome: undefined, detections: [], enforcement: undefined }]);
  });

  it('groups only when the list screen asks for it', async () => {
    const get = vi.spyOn(httpClient, 'get').mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, total_pages: 1 });
    const filters = { query: '', period: '30D', finalAction: 'ALL', recommendedAction: 'ALL', detector: 'ALL', matchType: 'ALL', scoreKind: 'ALL',
      degraded: 'ALL', detectionOutcome: 'ALL', degradedReason: 'ALL', failurePolicy: 'ALL', documentId: '', severity: 'ALL', status: 'ALL', targetLlm: 'ALL',
      sort: 'OCCURRED_AT_DESC', page: 1, pageSize: 20 } as const;
    await httpGatewayApi.getEvents({ ...filters, group: 'request' } as never);
    expect(String(get.mock.calls[0][0])).toContain('group=request');
    await httpGatewayApi.getEvents(filters as never);   // 차트·집계용 조회는 이벤트 단위
    expect(String(get.mock.calls[1][0])).not.toContain('group=');
  });

  function table(events: SecurityEvent[]) {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/events']}><Routes>
      <Route path="/events" element={<EventsTable events={events} evidenceToggle />} />
    </Routes></MemoryRouter></QueryClientProvider>);
  }
  const grouped = mapSecurityEventDto(parseApiResponse(securityEventSchema, eventDto({ attached_file_ids: ['f1'], group_final_action: 'MASK', attached_files: [fileDto] })));

  it('shows one row with the strongest action and the file detections', () => {
    table([grouped]);
    const row = screen.getByRole('row', { name: 'evt-prompt 상세 보기' });
    expect(within(row).getByText('프롬프트 + 파일 1')).toBeInTheDocument();
    expect(within(row).getByText('마스킹')).toBeInTheDocument();
    expect(within(row).getByText('문서 비교 대상 아님')).toBeInTheDocument();       // 파일의 민감정보 탐지가 질문 줄에 보인다
    expect(row).toHaveAttribute('data-action', 'mask');
  });

  it('opens the attached file evidence under the question row', async () => {
    const evidence = vi.spyOn(evidenceService, 'getEventEvidence').mockImplementation(async id => ({ event_id: id, source: 'RDS_DECISION_LOG',
      coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', status: 'NOT_RECORDED', comparisons: [] }));
    table([grouped]);
    fireEvent.click(screen.getByRole('button', { name: 'evt-prompt 원문 보기' }));
    expect(await screen.findByText(/첨부 파일 ·/)).toBeInTheDocument();
    expect(evidence).toHaveBeenCalledWith('evt-file', expect.anything());
    expect(evidence).not.toHaveBeenCalledWith('evt-prompt', expect.anything());   // 질문 자체는 허용 · 탐지 없음
    expect(screen.getByRole('link', { name: '파일 이벤트 보기' })).toHaveAttribute('href', '/events/evt-file?view=compare');
  });

  it('keeps an ungrouped event unchanged', () => {
    table([mapSecurityEventDto(parseApiResponse(securityEventSchema, fileDto))]);
    const row = screen.getByRole('row', { name: 'evt-file 상세 보기' });
    expect(within(row).queryByText(/프롬프트 \+ 파일/)).not.toBeInTheDocument();
    expect(within(row).getByText('마스킹')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------- 파일 칸별 전·후

const seg = (over: Partial<FileComparison['segments'][number]>) => ({ id: 'body:p0', format: 'docx' as const, area: 'body', para: 0, before: '', spans: [], ...over });
const maskedCell = seg({ id: 'body:t0:r0:c1:p0', table: 0, row: 0, col: 1, block_order: 1, before: `번호 ${RRN}`, after: '번호 [KR_RRN]', decided_by: 'signature',
  spans: [{ start: 3, end: 3 + RRN.length, entity_type: 'KR_RRN', replacement: '[KR_RRN]' }] });
const docx: FileComparison = { status: 'AVAILABLE', format: 'docx', after_recorded: true, ordered: true, segments: [
  seg({ id: 'header0:p0', area: 'header0', before: '경영지원실 대외비' }),
  seg({ id: 'body:p0', block_order: 0, before: '신규 입사자 등록 요청서' }),
  seg({ id: 'body:t0:r0:c0:p0', table: 0, row: 0, col: 0, block_order: 1, before: '주민등록번호' }),
  maskedCell,
  seg({ id: 'body:p1', para: 1, block_order: 2, before: '표 다음 문단' }),
  seg({ id: 'footer0:p0', area: 'footer0', before: '가상 테스트 문서' }),
] };

describe('file comparison view', () => {
  it('shows original and sent text side by side with highlights in document order', () => {
    const { container } = render(<FileComparisonView comparison={docx} />);
    const [before, after] = screen.getAllByRole('article');
    expect(within(before).getByText(RRN).tagName).toBe('MARK');
    expect(within(before).getByText(RRN)).toHaveAttribute('title', '주민등록번호 · 마스킹');
    expect(within(after).getByText('[KR_RRN]')).toHaveClass('dops-file-rep');
    expect(within(after).queryByText(RRN)).not.toBeInTheDocument();
    const text = before.textContent ?? '';
    expect(text.indexOf('신규 입사자')).toBeLessThan(text.indexOf('주민등록번호'));
    expect(text.indexOf('주민등록번호')).toBeLessThan(text.indexOf('표 다음 문단'));     // 본문 순번대로: 문단 → 표 → 문단
    expect(text.indexOf('경영지원실')).toBe(text.search(/\S/) + text.slice(text.search(/\S/)).indexOf('경영지원실'));
    expect(screen.getByText('주민등록번호 1')).toBeInTheDocument();
    expect(container.querySelector('.dops-file-papers.show-seg')).toBeNull();
    fireEvent.click(screen.getByLabelText('칸 번호 표시'));
    expect(container.querySelector('.dops-file-papers.show-seg')).not.toBeNull();
  });

  it('switches between before and after', () => {
    render(<FileComparisonView comparison={docx} />);
    fireEvent.click(screen.getByRole('button', { name: '후' }));
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(screen.queryByText(RRN)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '전' }));
    expect(screen.getByText(RRN)).toBeInTheDocument();
  });

  it('collects tables after paragraphs when the order was not recorded', () => {
    const unordered: FileComparison = { ...docx, ordered: false, segments: docx.segments.map(({ block_order: _, ...rest }) => rest) };
    render(<FileComparisonView comparison={unordered} />);
    expect(screen.getAllByText('문단·표 순서 기록이 없어 표를 문단 뒤에 표시합니다.').length).toBeGreaterThan(0);
    const text = screen.getAllByRole('article')[0].textContent ?? '';
    expect(text.indexOf('표 다음 문단')).toBeLessThan(text.indexOf('주민등록번호'));
  });

  it('marks detected cells of older records and offers only the original', () => {
    const old: FileComparison = { status: 'AVAILABLE', format: 'docx', after_recorded: false, ordered: false,
      segments: [seg({ id: 'body:p0', before: `번호 ${RRN}`, decided_by: 'signature', pii_hits: 'KR_RRN:1' })] };
    const { container } = render(<FileComparisonView comparison={old} />);
    expect(screen.getByRole('button', { name: '후' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '나란히' })).toBeDisabled();
    expect(screen.getByRole('note')).toHaveTextContent('2026-10-09 이전 기록');
    expect(container.querySelector('.dops-file-flagged')).not.toBeNull();
    expect(screen.getByText('주민등록번호 1')).toBeInTheDocument();
  });

  it('draws spreadsheets as a lettered grid', () => {
    const sheet: FileComparison = { status: 'AVAILABLE', format: 'xlsx', after_recorded: true, ordered: false, segments: [
      { id: 's0:r0:c0', format: 'xlsx', area: 'sheet', sheet: 0, row: 0, col: 0, before: '이름', spans: [] },
      { id: 's0:r0:c1', format: 'xlsx', area: 'sheet', sheet: 0, row: 0, col: 1, before: '주민등록번호', spans: [] },
      { id: 's0:r1:c1', format: 'xlsx', area: 'sheet', sheet: 0, row: 1, col: 1, before: RRN, after: '[KR_RRN]', decided_by: 'signature',
        spans: [{ start: 0, end: RRN.length, entity_type: 'KR_RRN', replacement: '[KR_RRN]' }] },
    ] };
    render(<FileComparisonView comparison={sheet} />);
    const [before] = screen.getAllByRole('article');
    expect(within(before).getByRole('columnheader', { name: 'A' })).toBeInTheDocument();
    expect(within(before).getByRole('columnheader', { name: 'B' })).toBeInTheDocument();
    expect(within(before).getByRole('rowheader', { name: '2' })).toBeInTheDocument();
    expect(within(before).getByText(RRN).tagName).toBe('MARK');
    expect(within(before).getByText('시트 1')).toBeInTheDocument();
  });

  it('says when the file is too large or not recorded', () => {
    const { rerender } = render(<FileComparisonView comparison={{ status: 'TOO_LARGE', segments: [] }} />);
    expect(screen.getByText('칸 수가 많아 파일 구조 비교를 표시하지 않습니다.')).toBeInTheDocument();
    rerender(<FileComparisonView comparison={{ status: 'NOT_RECORDED', segments: [] }} />);
    expect(screen.getByText('칸별 검사 기록이 없습니다.')).toBeInTheDocument();
  });
});

describe('evidence panel uses the file view for files', () => {
  it('replaces the prompt preview with the document view', async () => {
    const { EventEvidencePanel } = await import('./EventEvidencePanel');
    const evidence: EventEvidence = { event_id: 'evt-file', source: 'RDS_DECISION_LOG', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', status: 'AVAILABLE',
      redaction: 'APPLIED', comparisons: [], mask_comparison: { status: 'NOT_RECORDED', entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }, file_comparison: docx };
    vi.spyOn(evidenceService, 'getEventEvidence').mockResolvedValue(evidence);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-file" /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('파일 마스킹 전·후')).toBeInTheDocument();
    expect(screen.getByText('전 · 원문')).toBeInTheDocument();   // 파일 칸 비교는 원문 그대로(하이라이트만)
    expect(screen.getByText('RDS 기록 기반 · 원문 그대로 표시')).toBeInTheDocument();
    expect(screen.queryByText(/개인정보 보호 표시/)).not.toBeInTheDocument();
    expect(screen.queryByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).not.toBeInTheDocument();
  });
});
