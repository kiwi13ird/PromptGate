import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {render,screen,fireEvent,waitFor,within} from '@testing-library/react';
import {MemoryRouter,Routes,Route} from 'react-router-dom';
import {describe,it,expect,vi,beforeEach} from 'vitest';
import {OverviewPage} from './OverviewPage';
import {ProtectedDocumentDetailPage} from './ProtectedDocumentDetailPage';
import {dashboardService} from '@/src/services/dashboardService';
import {documentService} from '@/src/services/documentService';
import {eventService} from '@/src/services/eventService';
import type {ConfidentialDocument} from '@/src/types/policy';
vi.mock('@runtime/ui-mode',async()=>import('@/src/config/uiMode.real'));
vi.mock('recharts',()=>({BarChart:({children}:{children:React.ReactNode})=><div>{children}</div>,LineChart:({children}:{children:React.ReactNode})=><div>{children}</div>,Bar:()=>null,Line:()=>null,Legend:()=>null,CartesianGrid:()=>null,Tooltip:()=>null,XAxis:()=>null,YAxis:()=>null}));
function view(node:React.ReactNode,initial='/overview?period=30D'){
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
  const rendered=render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[initial]}>{node}</MemoryRouter></QueryClientProvider>);
  return {...rendered,client};
}
beforeEach(()=>{
  vi.restoreAllMocks();
  vi.spyOn(dashboardService,'getStats').mockResolvedValue({total:1234,block:2,mask:1,allow:1231,degraded:0,enforcementRate:1,actionMismatch:0,newEvents:3,averageProcessingMs:10,detectionStatus:'HEALTHY',gatewayStatus:'HEALTHY',trend:[],recent:[]});
});
describe('operational navigation polish',()=>{
  it('keeps the selected period and action/status on all five Korean cards',async()=>{
    view(<OverviewPage/>);
    await screen.findByRole('link',{name:'전체 이벤트 목록 보기'});
    for(const [name,suffix] of [['전체 이벤트',''],['전송 차단','&finalAction=BLOCK'],['민감정보 마스킹','&finalAction=MASK'],['전송 허용','&finalAction=ALLOW']]) expect(screen.getByRole('link',{name:`${name} 목록 보기`})).toHaveAttribute('href',`/events?period=30D${suffix}`);
    expect(within(screen.getByRole('link',{name:'전체 이벤트 목록 보기'})).getByText('1,234')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('radio',{name:'7일'}));   // 재설계 3b: 기간 선택은 세그먼트(속은 라디오)
    await waitFor(()=>expect(screen.getByRole('link',{name:'전송 차단 목록 보기'})).toHaveAttribute('href','/events?period=7D&finalAction=BLOCK'));
  });
  it('keeps presentation-only panels out of the operational overview',async()=>{
    const {container}=view(<OverviewPage/>);
    await screen.findByRole('link',{name:'전체 이벤트 목록 보기'});
    expect(container.querySelector('.demo-readiness')).toBeNull();
    expect(container.querySelector('#showcase')).toBeNull();
    expect(screen.queryByText(/시연|촬영|리허설/)).toBeNull();
    expect(container.querySelector('.request-finder-disclosure')).toBeNull();   // 요청 조회는 보안 이벤트 화면에만(2026-10-10)
  });
  it('omits unavailable optional document fields but preserves measured zero counts',async()=>{
    const doc:ConfidentialDocument={documentId:'doc-1',documentName:'공정 문서',registeredAt:'2026-10-05T00:00:00Z',status:'ACTIVE',processingStatus:'READY',fileType:'TXT',exactFingerprintStatus:'NOT_AVAILABLE',similarityFingerprintStatus:'NOT_AVAILABLE',chunkIndexStatus:'READY',chunkCount:1,activeDetectors:['WINDOW_HASH'],exactDetectionCount:0,modifiedPartialDetectionCount:2};
    vi.spyOn(documentService,'getDocuments').mockResolvedValue([doc]);
    vi.spyOn(eventService,'getEvents').mockResolvedValue({items:[],total:0,page:1,totalPages:1,pageSize:20});
    view(<Routes><Route path='/documents/:documentId' element={<ProtectedDocumentDetailPage/>}/></Routes>,'/documents/doc-1');
    expect(await screen.findByText('보호 중')).toBeInTheDocument();
    for(const absent of ['버전','소유자','문서 분류','변형 / 부분 일치','최근 탐지 시각']) expect(screen.queryByText(absent)).toBeNull();
    expect(screen.getAllByText('0건').length).toBeGreaterThan(0);
    expect(screen.queryByText('WINDOW_HASH')).toBeNull();
    expect(within(screen.getByLabelText('연결된 탐지 기록 집계')).getByText('누적 문서 구간 일치 탐지')).toBeInTheDocument();
    for(const removed of ['기록된 전체 일치 탐지','기록된 변형·부분 일치 탐지','전체 일치 지문','유사도 지문']) expect(screen.queryByText(removed)).toBeNull();   // 항상 0·해당 없음이던 항목
  });
});
