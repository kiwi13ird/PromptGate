import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {MemoryRouter,Route,Routes,useLocation} from 'react-router-dom';
import {describe,it,expect,vi} from 'vitest';
import {SecurityEventsPage} from './SecurityEventsPage';
import {EventDetailPage} from './EventDetailPage';
import {eventService} from '@/src/services/eventService';
import {evidenceService} from '@/src/services/evidenceService';
import type {SecurityEvent} from '@/src/types/event';

const event:SecurityEvent={eventId:'evt-fields',occurredAt:'2026-10-04T00:00:00Z',clientId:'test-client',targetLlm:'ChatGPT',detectionOutcome:'NO_MATCH',finalAction:'ALLOW',degraded:false,severity:'HIGH',status:'NEW',adminNotes:[],timeline:[],detections:[]};
function LocationDisplay(){const location=useLocation();return <output data-testid="location">{location.pathname+location.search+location.hash}</output>;}
function view(path:string){return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><MemoryRouter initialEntries={[path]}><LocationDisplay/><Routes><Route path="/events" element={<SecurityEventsPage/>}/><Route path="/events/:eventId" element={<EventDetailPage/>}/></Routes></MemoryRouter></QueryClientProvider>);}
function mockDetail(value:SecurityEvent){
  vi.spyOn(eventService,'getEventById').mockResolvedValue(value);
  vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue({event_id:event.eventId,source:'RDS_DECISION_LOG',coordinate_system:'NORMALIZED_UNICODE_CODE_POINTS',status:'NOT_RECORDED',comparisons:[]});
}
describe('remove empty event fields without hiding real failures',()=>{
  it('removes retired filters and normalizes old links without losing period, action, query or anchor',async()=>{
    const get=vi.spyOn(eventService,'getEvents').mockResolvedValue({items:[],total:0,page:1,pageSize:8,totalPages:1});
    view('/events?period=30D&finalAction=BLOCK&q=sample&severity=HIGH&degraded=NO&degradedReason=TIMEOUT&sort=SEVERITY_DESC&page=9#request-finder');
    await waitFor(()=>expect(screen.getByTestId('location')).toHaveTextContent('/events?period=30D&finalAction=BLOCK&q=sample#request-finder'));
    fireEvent.click(screen.getByRole('button',{name:'상세 조건'}));
    for(const label of ['심각도','보안 검사 장애','장애 원인'])expect(screen.queryByLabelText(label)).toBeNull();
    expect(screen.queryByRole('option',{name:'심각도 높은 순'})).toBeNull();
    expect(get).toHaveBeenCalled();
    for(const [filters] of get.mock.calls)expect(filters).toMatchObject({period:'30D',finalAction:'BLOCK',query:'sample',severity:'ALL',degraded:'ALL',degradedReason:'ALL',sort:'OCCURRED_AT_DESC',page:1});
  });
  it.each([false,undefined])('hides normal or unrecorded inspection state and severity in detail (%s)',async degraded=>{
    mockDetail({...event,degraded});view('/events/evt-fields?view=operations');
    await screen.findByRole('button',{name:'비교 집중 화면'});
    fireEvent.click(screen.getByText('탐지 기술 · 요청 상세 · 기록 누락 확인'));
    expect(screen.queryByText('심각도',{exact:false})).toBeNull();
    expect(screen.queryByText('높음')).toBeNull();
    expect(screen.queryByText('보안 검사 장애')).toBeNull();
    expect(screen.queryByText('장애 상태 미기록')).toBeNull();
    expect(screen.queryByText('검사 장애 원인')).toBeNull();
  });
  it('keeps actual inspection failure prominent and its cause available',async()=>{
    mockDetail({...event,degraded:true,detectionOutcome:'UNAVAILABLE',degradedReason:'TIMEOUT',failurePolicy:'FAIL_OPEN'});
    const {container}=view('/events/evt-fields?view=operations');
    await screen.findByRole('button',{name:'비교 집중 화면'});
    expect(container.querySelector('.partial-data-warning')).toHaveAttribute('role','status');
    expect(container.querySelector('.partial-data-warning')).toHaveTextContent('최종 조치가 허용이어도 안전하다고 확인된 요청은 아닙니다');
    expect(container.querySelector('.inspection-failure')).toHaveTextContent('검사 불가 · 허용');
    fireEvent.click(screen.getByText('탐지 기술 · 요청 상세 · 기록 누락 확인'));
    expect(screen.getByText('검사 장애 원인')).toBeInTheDocument();
    expect(screen.getByText('시간 초과 · 장애 시 허용')).toBeInTheDocument();
    expect(container.querySelector('.badge-allow')).toBeNull();
  });
});
