import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {MemoryRouter,useLocation} from 'react-router-dom';
import {describe,it,expect,vi,beforeEach} from 'vitest';
import {SecurityEventsPage} from './SecurityEventsPage';
import {eventService} from '@/src/services/eventService';
import {evidenceService} from '@/src/services/evidenceService';
import {demoToolsService} from '@/src/services/demoToolsService';
import type {SecurityEvent} from '@/src/types/event';
vi.mock('@runtime/ui-mode',async()=>import('@/src/config/uiMode.real'));
const event:SecurityEvent={eventId:'evt-operating',requestId:'req-MixedCase',occurredAt:'2026-10-05T00:00:00Z',clientId:'known-client',targetLlm:'Gemini',finalAction:'BLOCK',detectionOutcome:'MATCH',status:'NEW',detections:[{detector:'WINDOW_HASH',matchType:'TEXT_FRAGMENT',matchedDocumentId:'doc-current',matchedDocumentName:'공정 문서',score:.882,scoreKind:'COVERAGE',documentSpan:{charStart:0,charEnd:40,endExclusive:true}}],timeline:[],adminNotes:[]};
function CurrentLocation(){const l=useLocation();return <output data-testid='location'>{l.pathname+l.search+l.hash}</output>;}
function view(initial='/events?period=30D&finalAction=BLOCK&page=2'){
  return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><MemoryRouter initialEntries={[initial]}><CurrentLocation/><SecurityEventsPage/></MemoryRouter></QueryClientProvider>);
}
beforeEach(()=>{vi.restoreAllMocks();vi.spyOn(eventService,'getEvents').mockResolvedValue({items:[event],total:21,page:2,totalPages:3,pageSize:8});});
describe('operational dashboard has no presentation-only tools',()=>{
  it('keeps filters and page and loads no curated records',async()=>{
    const detail=vi.spyOn(eventService,'getEventById'),evidence=vi.spyOn(evidenceService,'getEventEvidence');
    const {container}=view();await screen.findByText('공정 문서');
    await waitFor(()=>expect(screen.getByTestId('location')).toHaveTextContent('/events?period=30D&finalAction=BLOCK&page=2'));
    expect(container.querySelector('#showcase,.showcase-cases,.demo-readiness')).toBeNull();
    expect(screen.queryByText(/시연|촬영|리허설/)).toBeNull();
    expect(detail).not.toHaveBeenCalled();expect(evidence).not.toHaveBeenCalled();
    expect(screen.getByRole('link',{name:'evt-operating 상세 보기'})).toHaveAttribute('href','/events/evt-operating?view=compare');
  });
  it('keeps explicit request lookup as a collapsed operational tool',async()=>{
    const lookup=vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'FOUND',count:1,checked_at:'2026-10-05T00:00:00Z',items:[{event_id:event.eventId,request_id:event.requestId,client_id:event.clientId,occurred_at:event.occurredAt,final_action:'BLOCK',target_llm:'Gemini'}]});
    const {container}=view('/events?period=30D');await screen.findByText('공정 문서');
    expect(container.querySelector('.request-finder-disclosure')).not.toHaveAttribute('open');expect(lookup).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('요청 ID로 기록 조회'));
    fireEvent.change(screen.getByLabelText('내 요청 식별자'),{target:{value:'req-MixedCase'}});fireEvent.click(screen.getByRole('button',{name:'이 요청 확인'}));
    expect(await screen.findByText('해당 식별자 사건 1건 확인')).toBeInTheDocument();
    expect(lookup).toHaveBeenCalledWith('request','req-MixedCase',undefined,expect.any(AbortSignal));
    expect(screen.getByRole('link',{name:/차단 · Gemini/})).toHaveAttribute('href','/events/evt-operating?view=compare');
  });
});
