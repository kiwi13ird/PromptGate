import {cloneElement,type ReactElement,type ReactNode} from 'react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {render,screen,waitFor,within} from '@testing-library/react';
import {MemoryRouter} from 'react-router-dom';
import {describe,it,expect,vi} from 'vitest';
import {TrafficPerformancePage} from './TrafficPerformancePage';
import {trafficService} from '@/src/services/trafficService';
import type {TrafficSnapshot} from '@/src/types/traffic';
import type {EventTimeBucket} from '@/src/utils/eventSeries';

// 2026-10-14 지표 정리: 처리 시간 추이는 점 몇 개뿐인 선(LineChart) 대신 구간마다 막대(BarChart), 툴팁은 값·요청 수를 함께 보이는 content 부품
const captured=vi.hoisted(()=>({series:[] as Array<Array<Record<string,unknown>>>,units:[] as Array<string|undefined>,tooltips:[] as ReactElement[]}));
vi.mock('recharts',()=>({
  BarChart:({data,children}:{data:Array<Record<string,unknown>>;children:ReactNode})=>{captured.series.push(data);return <div>{children}</div>;},
  YAxis:({unit}:{unit?:string})=>{captured.units.push(unit);return null;},
  Tooltip:({content}:{content?:ReactElement})=>{if(content)captured.tooltips.push(content);return null;},
  LineChart:({children}:{children:ReactNode})=><div>{children}</div>,
  Bar:()=>null,CartesianGrid:()=>null,Legend:()=>null,Line:()=>null,XAxis:()=>null,
}));
const snapshot:TrafficSnapshot={period:'24H',summary:{metricSource:'STORED_EVENTS',eventCount:1,gatewayStatus:'UNKNOWN',averageLatencyMs:2974.1,p95LatencyMs:4000},
  timeSeries:[{timestamp:'2026-10-05T06:00:00Z',requestCount:1,allowCount:0,maskCount:0,blockCount:1,averageLatencyMs:2974.1,p95LatencyMs:4000},{timestamp:'2026-10-05T07:00:00Z',requestCount:0,allowCount:0,maskCount:0,blockCount:0}],
  visualization:{asOf:Date.parse('2026-10-05T08:00:00Z'),from:Date.parse('2026-10-04T08:00:00Z'),boundaryBucket:false,issues:[],buckets:[
    {bucket:'2026-10-05T06:00:00Z',timestamp:'2026-10-05T06:00:00Z',start:Date.parse('2026-10-05T06:00:00Z'),end:Date.parse('2026-10-05T07:00:00Z'),partial:false,total:1,block:1,mask:0,allow:0,averageLatencyMs:2974.1,p95LatencyMs:4000},
    {bucket:'2026-10-05T07:00:00Z',timestamp:'2026-10-05T07:00:00Z',start:Date.parse('2026-10-05T07:00:00Z'),end:Date.parse('2026-10-05T08:00:00Z'),partial:false,total:0,block:0,mask:0,allow:0},
  ] satisfies EventTimeBucket[]}};
describe('judge-readable measurements',()=>{
  it('uses seconds in cards, chart values, axis and tooltip without rounding the stored data',async()=>{
    vi.spyOn(trafficService,'getSnapshot').mockResolvedValue(snapshot);
    render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><MemoryRouter><TrafficPerformancePage/></MemoryRouter></QueryClientProvider>);
    const card=(await within(await screen.findByRole('region',{name:'Gateway 지표'})).findByText('느린 5% 요청의 처리 시간 (P95)')).closest('article') as HTMLElement;   // 2026-10-14: 풀어 쓴 이름, 평균은 보조 줄
    expect(within(card).getByText('2.97초')).toBeInTheDocument();
    expect(within(card).getByText('4초')).toBeInTheDocument();
    expect(card).toHaveAttribute('title',expect.stringMatching(/^요청 95%가 이 시간 안에 처리됨/));   // 옛 '측정값의 95%가 이 시간 이하'
    expect(card).toHaveTextContent('처리 시간 기록 건수 미확인');   // 옛 '측정 건수 미확인'
    expect(screen.queryByText(/0건 평균/)).toBeNull();
    // 차트 값 칸 이름 average·p95 그대로(1초 미만이면 ms 눈금, 이 기록은 1초 넘어 초 그대로). 막대는 p95, 평균은 툴팁
    await waitFor(()=>expect(captured.series.some(series=>series.length>0&&'average' in series[0])).toBe(true));
    const series=captured.series.find(series=>series.length>0&&'average' in series[0])!;
    expect(series[0].average).toBe(2.9741);expect(series[0].p95).toBe(4);
    expect(series[1].average).toBeUndefined();expect(series[1].p95).toBeUndefined();
    expect(captured.units).toContain('초');expect(captured.units).not.toContain('ms');
    // 툴팁(옛 formatter 2.97초): 저장 값 그대로 초로, 요청 수(옛 요청 수 띠)와 처리 시간 기록 수를 함께
    const tooltip=render(cloneElement(captured.tooltips.at(-1)!,{active:true,payload:[{payload:series[0]}]} as Record<string,unknown>));
    expect(tooltip.container).toHaveTextContent('느린 5% (P95) 4초 · 평균 2.97초');
    expect(tooltip.container).toHaveTextContent('요청 1건');
    expect(tooltip.container).not.toHaveTextContent('처리 시간 기록');   // 이 시험 고정값은 기간 이벤트 목록이 없어 기록 수를 모름 → 0건이라고 쓰지 않음
    expect(snapshot.timeSeries[0].averageLatencyMs).toBe(2974.1);
  });
});
