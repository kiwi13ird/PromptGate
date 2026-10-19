import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {MemoryRouter,Route,Routes} from 'react-router-dom';
import {describe,it,expect,vi} from 'vitest';
import {EventDetailPage} from './EventDetailPage';
import {eventService} from '@/src/services/eventService';
import {evidenceService,type EventEvidence,type EvidencePage} from '@/src/services/evidenceService';
import type {SecurityEvent} from '@/src/types/event';
vi.mock('@runtime/ui-mode',()=>({uiMode:{isDemo:false,supportedActions:['ALLOW','BLOCK','MASK']}}));
const event:SecurityEvent={eventId:'evt-refresh',occurredAt:'2026-10-03T10:00:00Z',clientId:'client',targetLlm:'ChatGPT',detectionOutcome:'MATCH',finalAction:'BLOCK',status:'NEW',adminNotes:[],timeline:[],enforcement:{applied:true,httpStatus:403},detections:[{detector:'WINDOW_HASH',matchType:'TEXT_FRAGMENT',score:.8,scoreKind:'COVERAGE',matchedDocumentId:'doc-1',documentSpan:{charStart:0,charEnd:20,endExclusive:true}}]};
const evidence:EventEvidence={event_id:event.eventId,source:'RDS_DECISION_LOG',coordinate_system:'NORMALIZED_UNICODE_CODE_POINTS',status:'AVAILABLE',comparisons:[{document_id:'doc-1',coverage:.8,status:'AVAILABLE',input_location:{char_start:0,char_end:20},document_location:{char_start:0,char_end:20},input_previews:[],document_previews:[],matching_passages:[{id:'first',match_basis:'SAME_TEXT_IGNORING_WHITESPACE',input_location:{char_start:0,char_end:20},document_location:{char_start:0,char_end:20},input_text:'실제 대응 문장',document_text:'실제 대응 문장',nonspace_chars:6}]}]};
const page=(side:'input'|'document'):EvidencePage=>({status:'AVAILABLE',side,char_start:0,char_end:100,total_chars:100,segments:[{text:'실제 대응 문장'.repeat(10),matched:true,redacted:false}]});
describe('one refresh for the entire review',()=>{
  it('refreshes event, evidence and both body pages and waits for the slowest page',async()=>{
    const getEvent=vi.spyOn(eventService,'getEventById').mockResolvedValue(event);
    const getEvidence=vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue(evidence);
    const getPage=vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side)=>page(side));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/events/evt-refresh?view=compare']}><Routes><Route path="/events/:eventId" element={<EventDetailPage/>}/></Routes></MemoryRouter></QueryClientProvider>);
    await screen.findByRole('region',{name:'보낸 입력 문서'});
    await waitFor(()=>expect(getPage.mock.calls.length).toBe(2));   // 입력·문서 본문 전체(각 한 쪽)
    const eventBefore=getEvent.mock.calls.length,evidenceBefore=getEvidence.mock.calls.length,pagesBefore=getPage.mock.calls.length;
    let finish!:()=>void;
    getPage.mockImplementation(async(_id,side)=>side==='input'?new Promise(resolve=>{finish=()=>resolve(page(side));}):page(side));
    fireEvent.click(screen.getByRole('button',{name:'새로고침'}));
    await waitFor(()=>expect(getPage.mock.calls.length).toBe(pagesBefore+2));
    expect(getEvent.mock.calls.length).toBe(eventBefore+1);
    expect(getEvidence.mock.calls.length).toBe(evidenceBefore+1);
    expect(screen.getByRole('button',{name:'새로고침'})).toBeDisabled();
    await act(async()=>{finish();});
    await waitFor(()=>expect(screen.getByRole('button',{name:'새로고침'})).toBeEnabled());
    getEvidence.mockRejectedValue(new Error('browser-like failure'));
    fireEvent.click(screen.getByRole('button',{name:'새로고침'}));
    await screen.findByText(/최신 비교 근거를 확인하지 못해/);
    expect(screen.queryByRole('region',{name:'보낸 입력 문서'})).toBeNull();
  });
});
