import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { EventsTable } from './EventsTable';
import type { SecurityEvent } from '@/src/types/event';

const event: SecurityEvent = { eventId:'evt-test',requestId:'request-test',occurredAt:'2026-10-03T01:00:00Z',clientId:'test-client',targetLlm:'ChatGPT',finalAction:'BLOCK',detectionOutcome:'MATCH',degraded:false,status:'NEW',adminNotes:[],timeline:[],detections:[{detector:'WINDOW_HASH',matchType:'TEXT_FRAGMENT',score:0.748,scoreKind:'COVERAGE',matchedDocumentId:'doc/1',matchedDocumentName:'반도체 공정 원본',documentSpan:{charStart:0,charEnd:100,endExclusive:true},sameText:{state:'READY',sameChars:9999,inputChars:10000,differences:1}}] };
function view(value = event) { return render(<MemoryRouter><EventsTable events={[value]} /></MemoryRouter>); }
describe('result-first event list', () => {
  it('says computing, unavailable or unknown instead of falling back to the hash ratio', () => {
    const states: Array<[NonNullable<Extract<SecurityEvent['detections'][number], { detector: 'WINDOW_HASH' }>['sameText']> | undefined, string]> = [
      [{ state: 'PENDING' }, '같은 글자 계산 중'],
      [{ state: 'UNAVAILABLE', reason: '서버가 같은 글로 확인한 문장과 대조 결과가 맞지 않아' }, '같은 글자 대조 불가'],
      [undefined, '같은 글자 확인 불가'],
    ];
    for (const [sameText, text] of states) {
      const { unmount } = view({ ...event, detections: [{ ...event.detections[0], sameText } as SecurityEvent['detections'][number]] });
      expect(screen.getByText(text)).toBeInTheDocument();
      expect(screen.queryByText(/74\.8%/)).toBeNull();
      unmount();
    }
  });
  // 2026-10-16 '일치 비율' 통일: 목록 = 입력 중 문서와 같은 글자 비율(서버 same_text, 상세 대조와 같은 계산). Detection 해시 근거 비율(score 0.748)은 보이지 않음
  it('shows document and the same-character ratio (one decimal, never rounded up to 100%)', () => {
    view(); expect(screen.getByText('문서와 같은 글자 99.9%')).toBeInTheDocument();
    expect(screen.getByText('문서와 같은 글자 99.9%')).toHaveAttribute('title', '보낸 입력의 공백 뺀 10,000자 중 보호 문서와 같은 글자 9,999자 · 다른 곳 1곳 (이벤트 상세 대조와 같은 계산)');
    expect(screen.queryByText(/74\.8%/)).toBeNull();
    expect(screen.queryByText(/입력 일치 비율/)).toBeNull();
    expect(screen.getByRole('link',{name:'반도체 공정 원본'})).toHaveAttribute('href','/documents/doc%2F1');
    expect(screen.queryByRole('columnheader',{name:'심각도'})).toBeNull();
    expect(screen.queryByRole('columnheader',{name:'클라이언트 ID'})).toBeNull();
    expect(screen.getByRole('link',{name:'evt-test 상세 보기'})).toHaveAttribute('href','/events/evt-test?view=compare');
    expect(screen.getByRole('link',{name:'evt-test 상세 보기'})).toHaveTextContent('evt-test');
    expect(screen.queryByText('당시 미기록')).toBeNull();
  });
  it('omits severity and the routine inspection-status column even in operations', () => {
    view({...event,severity:'HIGH'});fireEvent.click(screen.getByText('운영 정보 보기'));
    expect(screen.queryByRole('columnheader',{name:'심각도'})).toBeNull();
    expect(screen.queryByRole('columnheader',{name:'보안 검사 상태'})).toBeNull();
    expect(screen.queryByText('검사 장애 없음')).toBeNull();
    expect(screen.queryByText('높음')).toBeNull();expect(screen.getByText('test-client')).toBeInTheDocument();
  });
  it('does not add an entirely empty severity column even in operations', () => {
    view();fireEvent.click(screen.getByText('운영 정보 보기'));expect(screen.queryByRole('columnheader',{name:'심각도'})).toBeNull();
  });
  it('never presents an unavailable fail-open inspection as a normal green allow', () => {
    const {container}=view({...event,detections:[],degraded:true,degradedReason:'TIMEOUT',failurePolicy:'FAIL_OPEN',detectionOutcome:'UNAVAILABLE',finalAction:'ALLOW'});
    expect(screen.getByText('검사 불가 · 허용')).toHaveAttribute('title','시간 초과 · 장애 시 허용');
    expect(container.querySelector('.badge-allow')).toBeNull();
  });
  it('keeps failure visible even when operational information is hidden', () => {
    view({...event,detections:[],degraded:true,degradedReason:'PARSE_ERROR',failurePolicy:'FAIL_CLOSED',detectionOutcome:'UNAVAILABLE'});
    expect(screen.getByText('검사 불가 · 차단')).toBeInTheDocument();
  });
  it('does not invent a document match for sensitive-information patterns', () => {
    view({...event,finalAction:'MASK',detections:[{detector:'SIGNATURE',matchType:'SIGNATURE_RULE',scoreKind:'CONFIDENCE',entityCounts:[{entityType:'KR_PHONE_NUMBER',count:1}]}]});
    expect(screen.getByText('문서 비교 대상 아님')).toBeInTheDocument();expect(screen.getByText('전화번호 1개')).toBeInTheDocument();   // 2026-10-16 탐지 값은 '개'
  });
});
