import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {MemoryRouter} from 'react-router-dom';
import {describe,it,expect,vi,beforeEach} from 'vitest';
import {RequestFinder} from './RequestFinder';
import {PageText} from './EvidenceDocumentViewer';
import {demoToolsService} from '@/src/services/demoToolsService';
vi.mock('@runtime/ui-mode',()=>({uiMode:{isDemo:false}}));
vi.mock('@/src/services/demoToolsService',()=>({demoToolsService:{lookup:vi.fn()}}));
function view(node:React.ReactNode){const client=new QueryClient({defaultOptions:{queries:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>);}
beforeEach(()=>vi.clearAllMocks());
describe('operational request lookup',()=>{
  it('requires a real client identifier and does not look up unknown-client',()=>{view(<RequestFinder/>);fireEvent.change(screen.getByLabelText('내 요청 조회 기준'),{target:{value:'client'}});fireEvent.change(screen.getByLabelText('내 요청 식별자'),{target:{value:'unknown-client'}});fireEvent.click(screen.getByText('지금부터 요청 기다리기'));expect(screen.getByRole('alert')).toHaveTextContent('사람을 구분');expect(demoToolsService.lookup).not.toHaveBeenCalled();});
  it('looks up the exact submitted ID without navigating to someone else',async()=>{vi.mocked(demoToolsService.lookup).mockResolvedValue({status:'WAITING',count:0,items:[],checked_at:new Date().toISOString()});view(<RequestFinder/>);fireEvent.change(screen.getByLabelText('내 요청 식별자'),{target:{value:'req-mine'}});fireEvent.click(screen.getByText('이 요청 확인'));await waitFor(()=>expect(demoToolsService.lookup).toHaveBeenCalledWith('request','req-mine',undefined,expect.any(AbortSignal)));expect(await screen.findByText(/아직 해당 식별자/)).toBeInTheDocument();});
  it('hides records that do not match the submitted request ID',async()=>{vi.mocked(demoToolsService.lookup).mockResolvedValue({status:'FOUND',count:1,checked_at:new Date().toISOString(),items:[{event_id:'other-event',request_id:'other-request',client_id:'other-client',occurred_at:new Date().toISOString(),target_llm:'ChatGPT',final_action:'ALLOW'}]});view(<RequestFinder/>);fireEvent.change(screen.getByLabelText('내 요청 식별자'),{target:{value:'req-mine'}});fireEvent.click(screen.getByText('이 요청 확인'));expect(await screen.findByRole('alert')).toHaveTextContent('다른 결과');expect(screen.queryByRole('link')).toBeNull();});
  it('renders same and changed Unicode spans together without interpreting markup',()=>{const {container}=render(<PageText page={{status:'AVAILABLE',side:'input',char_start:10,segments:[{text:'가😀나<script>█',matched:false,redacted:false}]}} focus={{char_start:10,char_end:12}} matches={[{char_start:13,char_end:21}]} changes={[{char_start:12,char_end:13}]}/>);expect(container.querySelector('.evidence-same')).toHaveTextContent('가😀');expect(container.querySelectorAll('.evidence-same').length).toBe(2);expect(container.querySelector('.evidence-change')).toHaveTextContent('나');expect(container.querySelector('script')).toBeNull();expect(container).toHaveTextContent('█');});
});
