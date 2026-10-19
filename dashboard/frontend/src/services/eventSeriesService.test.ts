import {describe,it,expect,vi,afterEach} from 'vitest';
import {gatewayApi} from '@/src/api';
import {readPeriodEvents} from './eventSeriesService';
const row=(id:number)=>({event_id:`isolated-${id}`,occurred_at:'2026-10-03T03:00:00Z',client_id:'contract',action:'ALLOW' as const,status:'NEW' as const,target_llm:'Gemini' as const,admin_notes:[],timeline:[],detections:[]});
afterEach(()=>vi.restoreAllMocks());
describe('Complete existing API pagination for charts',()=>{
 it('fetches 1000 real-shaped API rows using existing GET pages, not recent-ten fallback',async()=>{const spy=vi.spyOn(gatewayApi,'getEvents').mockImplementation(async f=>({items:Array.from({length:100},(_,i)=>row((f.page-1)*100+i)),total:1000,page:f.page,page_size:100,total_pages:10}));expect(await readPeriodEvents('30D')).toHaveLength(1000);expect(spy).toHaveBeenCalledTimes(10);expect(spy.mock.calls.every(([f])=>f.period==='30D'&&f.pageSize===100)).toBe(true);expect(spy.mock.calls.every(([f])=>f.group===undefined)).toBe(true);/* 차트는 묶지 않은 이벤트 단위(첨부 파일도 1건) */});
 it('rejects duplicate/truncated pagination rather than drawing an inaccurate chart',async()=>{vi.spyOn(gatewayApi,'getEvents').mockResolvedValue({items:[row(1)],total:2,page:1,page_size:100,total_pages:1});await expect(readPeriodEvents('7D')).rejects.toMatchObject({code:'INVALID_RESPONSE'});});
 it('bounds frontend work without presenting a partial large set as complete',async()=>{vi.spyOn(gatewayApi,'getEvents').mockResolvedValue({items:[],total:10001,page:1,page_size:100,total_pages:101});await expect(readPeriodEvents('30D')).rejects.toMatchObject({code:'INVALID_RESPONSE'});});
 it('propagates failures without fixtures',async()=>{vi.spyOn(gatewayApi,'getEvents').mockRejectedValue(new Error('network'));await expect(readPeriodEvents('24H')).rejects.toThrow('network');});
});
