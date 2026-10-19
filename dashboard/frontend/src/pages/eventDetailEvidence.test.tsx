import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { EventDetailPage } from './EventDetailPage';
import { eventService } from '@/src/services/eventService';
import type { SecurityEvent } from '@/src/types/event';

const event: SecurityEvent = {
  eventId: 'evt-layout', occurredAt: '2026-10-01T13:40:00Z',
  clientId: 'unknown-client', targetLlm: 'Gemini', detectionOutcome: 'NO_MATCH',
  finalAction: 'ALLOW', status: 'NEW', adminNotes: [], timeline: [], detections: [],
  requestId: '42241f8b-de8a-4f23-bcab-95555d58920c', host: 'gemini.google.com',
  endpoint: '/a/long/endpoint?' + 'query=value&'.repeat(30),
};
function openEvent(value: SecurityEvent, url = '/events/evt-layout') {
  vi.spyOn(eventService, 'getEventById').mockResolvedValue(value);
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}});
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[url]}><Routes><Route path="/events/:eventId" element={<EventDetailPage />} /></Routes></MemoryRouter></QueryClientProvider>);
}
describe('event detail evidence and long metadata', () => {
  it('names a keyword-only detection as a confidential keyword everywhere on the page', async () => {
    openEvent({ ...event, detectionOutcome: 'MATCH', finalAction: 'BLOCK', detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', entityCounts: [{ entityType: 'DOC_KEYWORD', count: 1 }] }] });
    expect((await screen.findAllByRole('heading', { name: '기밀 키워드 탐지' })).length).toBeGreaterThanOrEqual(2);   // 요약 제목과 화면 읽기용 제목
    fireEvent.click(screen.getByText('탐지 기술 · 요청 상세 · 기록 누락 확인'));
    expect(screen.getByRole('heading', { name: '기밀 키워드 일치' })).toBeInTheDocument();
    expect(screen.queryByText(/민감정보 패턴/)).toBeNull();
  });
  it('opens a shareable comparison view and returns to normal view without changing event data', async () => {
    openEvent(event, '/events/evt-layout?view=compare');
    const button = await screen.findByRole('button', { name: '운영 화면으로' });
    expect(button).toHaveAttribute('aria-pressed', 'true');
    expect(document.querySelector('.event-investigation')).toHaveClass('presentation-focused');
    const investigation=document.querySelector('.event-investigation')!;
    expect(investigation.querySelector('.event-brief')).toBeInTheDocument();
    // 같은 판정을 여러 번 보여 주던 영역은 없앴다(2026-10-10). 판정은 맨 위 요약 한 곳에만
    for (const removed of ['처리 과정 · 계산 기준 자세히 보기', '기록된 탐지 근거 · 정책 판단 상세', '탐지 결과부터 게이트웨이 조치까지']) expect(screen.queryByText(removed)).toBeNull();
    expect(investigation.querySelector('.investigation-processing')).toBeNull();
    expect(document.querySelector('.decision-flow')).toBeNull();
    expect(document.querySelectorAll('.investigation-result')).toHaveLength(1);
    // 다른 곳에 없던 '기록되지 않은 정보 확인'은 기술 상세에 남는다
    expect(screen.getByText('기록되지 않은 정보 확인').closest('.technical-disclosure')).not.toBeNull();
    fireEvent.click(button);
    expect(screen.getByRole('button', { name: '비교 집중 화면' })).toHaveAttribute('aria-pressed', 'false');
    expect(document.querySelector('.event-investigation')).not.toHaveClass('presentation-focused');
  });
  it('shows the endpoint path without session query values and gives it a wrapping field', async () => {
    openEvent(event);
    const endpoint = await screen.findByText(event.host! + '/a/long/endpoint');
    fireEvent.click(screen.getByText('탐지 기술 · 요청 상세 · 기록 누락 확인'));
    fireEvent.click(screen.getByText('관리자 조사 · 담당자 · 메모 · 처리 이력'));
    expect(endpoint.closest('div')).toHaveClass('metadata-endpoint');
    expect(screen.queryByText(/query=value/)).not.toBeInTheDocument();
    expect(screen.getByText(event.requestId!)).toHaveClass('mono');
    expect(screen.getAllByText('일치한 보호 문서나 민감정보가 없습니다.').length).toBeGreaterThan(0);
    expect(screen.queryByText(/NO_MATCH/)).toBeNull();
    expect(screen.getByText('아직 작성된 관리자 메모가 없습니다.')).toBeInTheDocument();
    expect(screen.getByText('아직 담당자 지정·상태 변경·메모 추가 이력이 없습니다.')).toBeInTheDocument();
    expect(screen.getByText('이벤트 발생')).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'메모 추가'})).toBeDisabled();
    expect(screen.getByRole('button',{name:'지정'})).toBeDisabled();
  });
  it('shows the actual matched document and distinguishes coverage from similarity', async () => {
    const documentId = '01_사업전략_방향_보고서';
    openEvent({...event,detectionOutcome:'MATCH',finalAction:'BLOCK',detections:[{
      detector:'WINDOW_HASH',matchType:'TEXT_FRAGMENT',score:1,scoreKind:'COVERAGE',
      matchedDocumentId:documentId,inputSpan:{charStart:0,charEnd:21394,endExclusive:true},
      documentSpan:{charStart:49,charEnd:21414,endExclusive:true},
    }]});
    const links = await screen.findAllByRole('link',{name:documentId});
    fireEvent.click(screen.getByText('탐지 기술 · 요청 상세 · 기록 누락 확인'));
    for (const link of links) expect(link).toHaveAttribute('href',`/documents/${encodeURIComponent(documentId)}`);
    expect(screen.getByText('해시 근거 비율 100%')).toBeInTheDocument();   // 2026-10-16: Detection 값은 '해시 근거 비율'로 구분
    expect(screen.getByText(/30자 창 해시로 이 문서에서만 나온 곳을 센 비율/)).toHaveTextContent("'문서와 같은 글자'(확인 불가)");
  });
});
