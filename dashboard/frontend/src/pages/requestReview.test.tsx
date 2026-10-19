import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { RequestReviewPage } from './RequestReviewPage';
import { demoToolsService } from '@/src/services/demoToolsService';

function Destination() { const location=useLocation();return <p>{location.pathname+location.search}</p>; }
function view(){const client=new QueryClient({defaultOptions:{queries:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/requests/my-request']}><Routes><Route path="/requests/:requestId" element={<RequestReviewPage/>}/><Route path="/events/:eventId" element={<Destination/>}/></Routes></MemoryRouter></QueryClientProvider>);}
const item={event_id:'evt-mine',request_id:'my-request',client_id:'client-mine',occurred_at:'2026-10-03T00:00:00Z',final_action:'BLOCK' as const,target_llm:'ChatGPT'};
describe('request-number direct review',()=>{
  it('opens only the exact resolved event in comparison view',async()=>{const lookup=vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'FOUND',count:1,checked_at:new Date().toISOString(),items:[item]});view();expect(await screen.findByText('/events/evt-mine?view=compare')).toBeInTheDocument();expect(lookup).toHaveBeenCalledWith('request','my-request',undefined,expect.any(AbortSignal));});
  it('waits rather than opening the newest unrelated event',async()=>{vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'WAITING',count:0,checked_at:new Date().toISOString(),items:[]});view();await waitFor(()=>expect(screen.getByRole('status')).toHaveTextContent('사건 저장을 기다리고'));expect(screen.queryByText('/events/evt-mine?view=compare')).toBeNull();});
  it('requires an explicit selection when a request maps to multiple events',async()=>{vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'AMBIGUOUS',count:2,checked_at:new Date().toISOString(),items:[item,{...item,event_id:'evt-second'}]});view();expect(await screen.findByText(/같은 요청 번호로 여러 사건/)).toHaveTextContent('자동으로 선택하지');expect(screen.getAllByRole('link').length).toBe(3);expect(screen.queryByText('/events/evt-mine?view=compare')).toBeNull();});
  it('does not redirect using stale lookup data after failure',async()=>{vi.spyOn(demoToolsService,'lookup').mockRejectedValue(Error('private detail'));view();expect(await screen.findByText(/사건 조회에 실패/)).toBeInTheDocument();expect(screen.queryByText('private detail')).toBeNull();});
  it('does not open an event when the response names another request',async()=>{vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'FOUND',count:1,checked_at:new Date().toISOString(),items:[{...item,request_id:'someone-else'}]});view();expect(await screen.findByRole('alert')).toHaveTextContent('요청 번호가 일치하지');expect(screen.queryByText('/events/evt-mine?view=compare')).toBeNull();});
  it('does not render another request in an ambiguous response',async()=>{vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'AMBIGUOUS',count:2,checked_at:new Date().toISOString(),items:[item,{...item,event_id:'other',request_id:'someone-else'}]});view();expect(await screen.findByRole('alert')).toBeInTheDocument();expect(screen.getAllByRole('link')).toHaveLength(1);});
  it('restarts a bounded wait after expiry without choosing an unrelated event',async()=>{
    vi.spyOn(demoToolsService,'lookup').mockResolvedValue({status:'WAITING',count:0,checked_at:new Date().toISOString(),items:[]});
    const timer=vi.spyOn(window,'setTimeout');view();await waitFor(()=>expect(screen.getByRole('status')).toHaveTextContent('사건 저장을 기다리고'));
    const expire=timer.mock.calls.find(call=>call[1]===120000)?.[0];expect(expire).toBeTypeOf('function');
    act(()=>{if(typeof expire==='function')expire();});
    fireEvent.click(screen.getByRole('button',{name:'다시 2분 기다리기'}));
    await waitFor(()=>expect(screen.getByRole('status')).toHaveTextContent('사건 저장을 기다리고'));
    expect(screen.queryByText('/events/evt-mine?view=compare')).toBeNull();
  });
});
