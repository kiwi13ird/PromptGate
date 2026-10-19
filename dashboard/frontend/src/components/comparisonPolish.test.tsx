import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {describe,it,expect,vi,afterEach} from 'vitest';
import {SignatureInputComparison} from './EvidenceDocumentViewer';
import {evidenceService,type EventEvidence} from '@/src/services/evidenceService';
afterEach(()=>vi.restoreAllMocks());
describe('comparison-first behavior',()=>{
  it('makes long retained requests keyboard-readable without adding focus stops to short requests',()=>{
    const text='긴 보관 본문\n'.repeat(100);
    const {rerender}=render(<SignatureInputComparison eventId="long-proof" entities={[]} proof={{status:'REQUEST_REWRITTEN',entity_counts:[],before_preview:text,after_preview:text}}/>);
    expect(screen.getByRole('region',{name:'치환 전 보관 본문'})).toHaveAttribute('tabindex','0');
    expect(screen.getByRole('region',{name:'치환 후 보관 본문'})).toHaveAttribute('tabindex','0');
    rerender(<SignatureInputComparison eventId="short-proof" entities={[]} proof={{status:'REQUEST_REWRITTEN',entity_counts:[],before_preview:'짧은 본문',after_preview:'짧은 본문'}}/>);
    expect(screen.queryByRole('region',{name:'치환 전 보관 본문'})).toBeNull();
  });
  it('distinguishes retained empty text from an unrecorded preview and character count',()=>{
    const {rerender}=render(<SignatureInputComparison eventId="empty-proof" entities={[]} proof={{status:'REQUEST_REWRITTEN',entity_counts:[],before_preview:'',after_preview:'',before_chars:0,after_chars:0}}/>);
    expect(screen.getAllByText('본문 내용 없음 · 빈 문자열이 기록되었습니다.')).toHaveLength(2);
    expect(screen.queryByText('치환 전 본문이 기록되지 않았습니다.')).toBeNull();
    rerender(<SignatureInputComparison eventId="missing-proof" entities={[]} proof={{status:'REQUEST_REWRITTEN',entity_counts:[]}}/>);
    expect(screen.getByText('치환 전 본문이 기록되지 않았습니다.')).toBeInTheDocument();
    expect(screen.getByText('치환 후 본문이 기록되지 않았습니다.')).toBeInTheDocument();
    expect(screen.getAllByText(/글자 수 미기록/)).toHaveLength(2);
    expect(screen.queryByText(/본문 치환 확인/)).toBeNull();
    expect(document.querySelector('.mask-change-after')).toBeNull();
  });
  it('shows only verified rewritten highlights and safely renders markup as text',()=>{
    const proof:NonNullable<EventEvidence['mask_comparison']>={status:'REQUEST_REWRITTEN',entity_counts:[],before_preview:'A██Z',after_preview:'A<script>Z',before_chars:4,after_chars:10,preview_truncated:false,spans:[{start:1,end:3,entityType:'PHONE'}]};
    const {container,rerender}=render(<SignatureInputComparison eventId="evt-mask" entities={[]} proof={proof}/>);
    expect(container.querySelector('.mask-change-before')).toHaveTextContent('██');
    expect(container.querySelector('.mask-change-after')).toHaveTextContent('<script>');
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByLabelText('저장된 요청 마스킹 전후 관계')).toHaveTextContent('원래 요청→ Gateway 마스킹 →전달 요청');
    rerender(<SignatureInputComparison eventId="evt-mask" entities={[]} proof={{...proof,preview_truncated:true}}/>);
    expect(container.querySelector('.mask-change-after')).toBeNull();
    expect(screen.getByText(/범위 강조는 하지 않습니다/)).toBeInTheDocument();
  });
  it('does not show a transformation indicator when a retained rewrite is missing',async()=>{
    vi.spyOn(evidenceService,'getPage').mockResolvedValue({status:'AVAILABLE',side:'input',char_start:0,char_end:4,total_chars:4,segments:[{text:'A██Z',matched:false,redacted:true}]});
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><SignatureInputComparison eventId="evt-unrecorded" entities={[{entity_type:'KR_PHONE_NUMBER',count:1}]} proof={{status:'NOT_RECORDED',entity_counts:[]}}/></QueryClientProvider>);
    expect(await screen.findByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByLabelText('저장된 요청 마스킹 전후 관계')).toBeNull();
  });
});
