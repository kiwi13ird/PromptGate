import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { evidenceService, evidenceSchema, type EventEvidence } from '@/src/services/evidenceService';
import { EventEvidencePanel } from './EventEvidencePanel';
vi.mock('@runtime/ui-mode',()=>({uiMode:{isDemo:false}}));
const fixture:EventEvidence={event_id:'evt-test',source:'RDS_DECISION_LOG',coordinate_system:'NORMALIZED_UNICODE_CODE_POINTS',status:'AVAILABLE',metadata:{detection_ms:270.1,input_chars:21398,detection_reason:'문서 구간 일치',hash_status:'ok'},comparisons:[{
  document_id:'doc-1',document_name:'사업전략.docx',coverage:0.8,status:'AVAILABLE',
  input_location:{char_start:0,char_end:100},document_location:{char_start:49,char_end:149},
  input_previews:[{char_start:0,char_end:100,segments:[{text:'<script>not executable</script>',matched:true}],omitted_before:false,omitted_after:true}],
  document_previews:[{char_start:49,char_end:149,segments:[{text:'동일 문서 구간',matched:true}],omitted_before:true,omitted_after:true}],
  matching_passages:[{id:'passage-1',match_basis:'SAME_TEXT_IGNORING_WHITESPACE',input_location:{char_start:0,char_end:29},document_location:{char_start:49,char_end:78},input_text:'<script>not executable</script>',document_text:'<script>not executable</script>',nonspace_chars:29}],
}]};
// Claude 새 화면 질문 마스킹: Gateway 본문은 없고 Detection 판정 기록(원문·대체본·적중 위치)만 있다. 값은 가짜
const PHONE='010-9876-5432';
const promptComparison:NonNullable<EventEvidence['prompt_comparison']>={status:'AVAILABLE',format:'docx',after_recorded:true,ordered:true,segments:[{
  id:'prompt',format:'docx',area:'body',para:0,before:`고객 연락처 ${PHONE}로 안내해줘`,after:'고객 연락처 [KR_PHONE_NUMBER]로 안내해줘',
  spans:[{start:7,end:20,entity_type:'KR_PHONE_NUMBER',replacement:'[KR_PHONE_NUMBER]'}],decided_by:'signature'}]};
const claudeMask:EventEvidence={...fixture,comparisons:[],metadata:{...fixture.metadata,gateway_final:'MASK'},
  mask_comparison:{status:'NOT_RECORDED',entity_counts:[{entity_type:'KR_PHONE_NUMBER',count:1}]},prompt_comparison:promptComparison};
function open(value:EventEvidence){
  vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue(value);
  vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side,offset)=>({status:'AVAILABLE',side,
    char_start:offset,char_end:offset+100,total_chars:3600,page_size:1800,content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',
    segments:[{text:side==='input'?'<script>not executable</script>':'동일 문서 구간',matched:true,redacted:false}]}));
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
  return render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
}
describe('real evidence comparison',()=>{
  it('shows recorded rewrite previews without claiming LLM delivery completion',async()=>{
    open({...fixture,comparisons:[],mask_comparison:{status:'REQUEST_REWRITTEN',entity_counts:[{entity_type:'KR_PHONE_NUMBER',count:1}],
      before_preview:'문의 █████████████ 입니다',after_preview:'문의 010-****-5678 입니다',before_chars:20,after_chars:20,preview_truncated:false,spans:[],outbound_text_sha256:'a'.repeat(64)}});
    expect(await screen.findByText('게이트웨이가 실제로 치환한 요청 본문')).toBeInTheDocument();
    expect(screen.getByRole('heading',{name:'민감정보 마스킹 전·후'})).toBeInTheDocument();
    expect(screen.getByText('문의 010-****-5678 입니다')).toBeInTheDocument();
    expect(screen.getByText(/외부 LLM의 수신·답변 완료를 뜻하지 않습니다/)).toBeInTheDocument();
    expect(screen.queryByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).not.toBeInTheDocument();
  });
  it('distinguishes an immutable event-time version from current stored text',async()=>{
    open({...fixture,comparisons:[{...fixture.comparisons[0],document_source:'EVENT_DOCUMENT_VERSION',recorded_document_version:'2'}]});
    expect(await screen.findByText(/사건 당시 색인된 보호 문서 버전 2/)).toBeInTheDocument();
    expect(screen.queryByText(/현재 RDS 저장본으로/)).not.toBeInTheDocument();
  });
  it('shows the whole sent input as one page, loading every stored page, and highlights only what differs from the protected document',async()=>{
    // 입력 3,600자(두 쪽) 전체를 이어 받아 한 장으로 붙인다. 문서와 다른 부분만 <mark>
    vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue(fixture);
    const getPage=vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side,offset)=>({status:'AVAILABLE',side,char_start:offset,char_end:offset+20,total_chars:3600,page_size:1800,
      content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',
      segments:[{text:offset===0?'공정 조건 문서 앞부분.\n':(side==='input'?'입력에만 있는 문장.':'문서에만 있는 문장.'),matched:true,redacted:false}]}));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
    const page=await screen.findByRole('region',{name:'보낸 입력 문서'});
    await waitFor(()=>expect(page.querySelectorAll('mark')).toHaveLength(1));
    expect(page).toHaveTextContent('공정 조건 문서 앞부분.입력에만 있는 문장.');   // 줄 = 문단(글 구조)
    expect(page.querySelectorAll('p.pg-evp-p')).toHaveLength(2);
    expect(page.querySelector('mark')?.textContent).toBe('입력');   // '에만 있는 문장.'은 문서와 같아 평문
    for(const side of ['input','document'] as const)for(const offset of [0,1800])expect(getPage).toHaveBeenCalledWith('evt-test',side,offset,'doc-1',expect.anything());
    expect(screen.getByText('강조 = 서로 다른 부분')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:/일치 구간 1/})).toBeNull();   // 옛 칩·나란히 쪽 보기 없음
    // 2차(10/16): 왼쪽 보낸 입력 · 오른쪽 보호 문서 원문이 함께 보인다(전환 단추 없음)
    expect(screen.queryByRole('button',{name:'보호 문서 원문'})).toBeNull();
    const doc=screen.getByRole('region',{name:'보호 문서 원문'});
    expect(page.closest('.pg-evp-pair')).toBe(doc.closest('.pg-evp-pair'));
    expect(doc.querySelector('mark')?.textContent).toBe('문서');
    expect(screen.getAllByText('1곳')).toHaveLength(1);   // 양쪽이 대응하는 한 곳
  });
  it('never paints the whole page when the comparison contradicts what the server confirmed: says the original could not be compared',async()=>{
    // 서버가 '같은 글'로 확인한 문장이 화면 대조에서 통째로 '다름'이 되는 경우(본문이 일부만 오거나 판이 다를 때) → 강조 없이 한 줄
    const sentence='당사 초기 제시안: 수수료율 20%, 최소보장금액 연 JPY 60,000,000, 계약기간 2년.';
    const passage={id:'p1',match_basis:'SAME_TEXT_IGNORING_WHITESPACE' as const,input_location:{char_start:0,char_end:Array.from(sentence).length},document_location:{char_start:0,char_end:Array.from(sentence).length},input_text:sentence,document_text:sentence,nonspace_chars:40};
    vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue({...fixture,comparisons:[{...fixture.comparisons[0],coverage:.94,coverage_basis:'CONFIRMED_WINDOW_INTERVALS',matching_passages:[passage]}]});
    vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side)=>({status:'AVAILABLE',side,char_start:0,char_end:10,total_chars:10,page_size:1800,
      content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',segments:[{text:side==='input'?sentence:'다른 판의 문서 본문만 저장되어 있음',matched:true,redacted:false}]}));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('원문 대조 불가 · 서버가 같은 글로 확인한 문장과 대조 결과가 맞지 않아 다른 부분을 강조하지 않음')).toBeInTheDocument();
    const page=screen.getByRole('region',{name:'보낸 입력 문서'});
    expect(page).toHaveTextContent(sentence);
    expect(page.querySelector('mark')).toBeNull();
    expect(screen.queryByRole('button',{name:'다음 다른 부분'})).toBeNull();
  });
  it('highlights on the right only inside the range the input corresponds to; the rest of the document is plain and faint, and opens there',async()=>{
    const doc=['문서 앞부분 머리말은 입력에 쓰이지 않았다.','당사 초기 제시안은 수수료율 20%이다.','계약 기간은 2년으로 한다.','문서 뒷부분 부록도 입력에 없다.'].join('\n');
    const input=['이걸 메일로 바꿔줘.','당사 초기 제시안은 수수료율 18%이다.','계약 기간은 2년으로 한다.'].join('\n');
    vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue({...fixture,comparisons:[{...fixture.comparisons[0],matching_passages:[]}]});
    vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side)=>({status:'AVAILABLE',side,char_start:0,char_end:10,total_chars:10,page_size:1800,
      content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',segments:[{text:side==='input'?input:doc,matched:true,redacted:false}]}));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
    const right=await screen.findByRole('region',{name:'보호 문서 원문'});
    await waitFor(()=>expect(right.querySelectorAll('mark')).toHaveLength(1));
    expect(right.querySelector('mark')?.textContent).toBe('20');
    expect([...right.querySelectorAll('.pg-evp-faint')].map(node=>node.textContent).join('|')).toContain('머리말은 입력에 쓰이지 않았다');
    expect([...right.querySelectorAll('.pg-evp-faint')].map(node=>node.textContent).join('|')).toContain('부록도 입력에 없다');
    const left=screen.getByRole('region',{name:'보낸 입력 문서'});
    expect([...left.querySelectorAll('mark')].map(node=>node.textContent)).toEqual(['이걸 메일로 바꿔줘','18']);
    expect(screen.getByText('2곳')).toBeInTheDocument();
    // 주 숫자 = 화면 대조의 같은 글자 비율, 서버 해시 근거 비율은 세부 정보로(2026-10-16 3차)
    const summary=screen.getAllByRole('link',{name:'사업전략.docx'})[0].closest('p')!;
    expect(summary).toHaveTextContent(/문서와 같은 글자 \d+\.\d%/);
    expect(summary).not.toHaveTextContent('80.0%');
    expect(screen.getByText('세부 정보').closest('details')).toHaveTextContent('해시 근거 비율(이전 방식)80.0%');   // 이 예시는 이전 방식 기록
  });
  it('draws the extracted text as a document: numbered headings, and " | " rows as a table whose cells keep highlights',async()=>{
    const doc=['14. 상세 로드맵 (스프린트/월 단위)','일정은 표7과 같다.','시기 | 마일스톤 | 게이트/승인','2026-08 (Sprint 1-2) | 모델 후보 비교 완료 | AI팀 승인'].join('\n');
    const input=doc.replace('AI팀 승인','CTO 승인');
    vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue({...fixture,comparisons:[{...fixture.comparisons[0],matching_passages:[]}]});
    vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side)=>({status:'AVAILABLE',side,char_start:0,char_end:10,total_chars:10,page_size:1800,
      content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',segments:[{text:side==='input'?input:doc,matched:true,redacted:false}]}));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
    const left=await screen.findByRole('region',{name:'보낸 입력 문서'});
    await waitFor(()=>expect(left.querySelector('mark')).not.toBeNull());
    expect(within(left).getByRole('heading',{name:'14. 상세 로드맵 (스프린트/월 단위)'})).toBeInTheDocument();
    const table=within(left).getByRole('table');
    expect(within(table).getAllByRole('columnheader').map(cell=>cell.textContent)).toEqual(['시기','마일스톤','게이트/승인']);
    expect(within(table).getAllByRole('cell').at(-1)?.querySelector('mark')?.textContent).toBe('CTO');
    expect(table.textContent).not.toContain('|');
  });
  it('folds masked values (█ runs) into one short tag and treats both sides masking the same place as the same',async()=>{
    // 서버 가림: 값 글자 수만큼 █ + redacted 조각. 입력·문서의 가린 값 길이가 달라도 같은 자리면 '다름'이 아니다
    vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue({...fixture,comparisons:[{...fixture.comparisons[0],matching_passages:[]}]});
    vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side)=>({status:'AVAILABLE',side,char_start:0,char_end:10,total_chars:10,page_size:1800,
      content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',segments:[
        {text:'접속 정보 db_connection: postgres://svc@10.0.31.21/neoboard ',matched:true,redacted:false},
        {text:'█'.repeat(side==='input'?40:24),matched:true,redacted:true},
        {text:' (더미, AWS Access Key 형식) ssh_port: 22',matched:true,redacted:false}]}));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    const {container}=render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('서로 다른 부분 없음(공백·줄바꿈 제외)')).toBeInTheDocument();
    const left=screen.getByRole('region',{name:'보낸 입력 문서'});
    expect(left.textContent).not.toContain('█');
    expect(left.querySelector('.pg-evp-redact')).toHaveTextContent('가림');
    expect(left.querySelector('.pg-evp-redact')).toHaveAttribute('title','개인정보·자격증명 가림 표시 · 원래 40자');
    expect(container.querySelectorAll('mark')).toHaveLength(0);
    expect(screen.getByText('= 개인정보·자격증명 가림 표시',{exact:false})).toBeInTheDocument();
  });
  it('says there is no difference when the texts match ignoring whitespace',async()=>{
    vi.spyOn(evidenceService,'getEventEvidence').mockResolvedValue({...fixture,comparisons:[{...fixture.comparisons[0],coverage:1,current_text_equal_ignoring_whitespace:true}]});
    vi.spyOn(evidenceService,'getPage').mockImplementation(async(_id,side)=>({status:'AVAILABLE',side,char_start:0,char_end:10,total_chars:10,page_size:1800,
      content_source:side==='input'?'RETAINED_INPUT':'CURRENT_PROTECTED_DOCUMENT',segments:[{text:side==='input'?'같은 본문 문장':'같은  본문\n문장',matched:true,redacted:false}]}));
    const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-test" /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('서로 다른 부분 없음(공백·줄바꿈 제외)')).toBeInTheDocument();
    expect(screen.getByRole('region',{name:'보낸 입력 문서'}).querySelector('mark')).toBeNull();
    expect(screen.getByText('100.0%')).toBeInTheDocument();
  });
  it('puts one summary line on top and collects basis, version, location and record details in one fold',async()=>{
    open({...fixture,comparisons:[{...fixture.comparisons[0],coverage_basis:'CONFIRMED_WINDOW_INTERVALS',coverage_sampled:true,current_text_equal_ignoring_whitespace:false}]});
    expect((await screen.findAllByRole('link',{name:'사업전략.docx'}))[0]).toHaveAttribute('href','/documents/doc-1');
    expect(screen.getByRole('heading',{name:'보호 문서 일치 구간'})).toBeInTheDocument();
    const summary=screen.getAllByRole('link',{name:'사업전략.docx'})[0].closest('p')!;
    expect(summary).toHaveTextContent('해시 근거 비율 80.0%');   // 화면 대조를 믿을 수 없는 본문(전혀 다른 글)이라 서버 값이 주 숫자
    expect(summary).toHaveTextContent('입력 21,398자');
    expect(summary).toHaveTextContent('보안 검사 0.27초');
    expect(document.querySelectorAll('details')).toHaveLength(1);   // 접기는 맨 아래 '세부 정보' 하나
    expect(document.querySelector('.evidence-match-banner')).toBeNull();
    const details=screen.getByText('세부 정보').closest('details')!;
    expect(details).toHaveTextContent('해시 근거 비율(여러 문서 공통 문구 제외)80.0%');
    expect(details).toHaveTextContent('전문을 그대로 붙여 넣어도 낮게 나옵니다');
    expect(details).toHaveTextContent('입력 0–100자 / 전체 21,398자');
    expect(details).toHaveTextContent('현재 RDS 저장본으로, 당시 원문 스냅샷은 아닙니다.');
    expect(details).toHaveTextContent('일부 내용은 다르지만 같은 문장 확인 1곳(서버 대조)');
    expect(details).toHaveTextContent('당시 탐지 사유문서 구간 일치');
    expect(details).toHaveTextContent('해시 검사 상태정상');
  });
  it('does not invent a total length when the record has none, and names legacy ratios',async()=>{
    open({...fixture,metadata:undefined,comparisons:[{...fixture.comparisons[0],coverage_basis:'LEGACY_BOUNDING_RANGE'}]});
    const details=(await screen.findByText('세부 정보')).closest('details')!;
    expect(details).toHaveTextContent('입력 0–100자보호 문서 49–149자 · 끝 좌표 미포함');
    expect(details).not.toHaveTextContent('/ 전체');
    expect(screen.getAllByRole('link',{name:'사업전략.docx'})[0].closest('p')).toHaveTextContent('해시 근거 비율(이전 방식) 80.0%');
    expect(details).toHaveTextContent('이전 계산 방식의 탐지 범위 비율입니다');
  });
  it('renders stored strings as text, never as HTML',async()=>{
    const {container}=open(fixture);
    const page=await screen.findByRole('region',{name:'보낸 입력 문서'});
    await waitFor(()=>expect(page).toHaveTextContent('<script>not executable</script>'));
    expect(container.querySelector('script')).toBeNull();
  });
  it('does not show excerpts for an ambiguous request ID',async()=>{
    open({...fixture,status:'AMBIGUOUS',comparisons:[],metadata:undefined});
    expect(await screen.findByText('같은 요청 ID의 기록이 여러 건이라 잘못된 내용을 연결하지 않습니다.')).toBeInTheDocument();
    expect(screen.queryByText('보낸 입력')).not.toBeInTheDocument();
  });
  it('accepts the additional evidence DTO but rejects guessed coverage above one',()=>{
    expect(evidenceSchema.safeParse(fixture).success).toBe(true);
    expect(evidenceSchema.safeParse({...fixture,comparisons:[{...fixture.comparisons[0],coverage:2}]}).success).toBe(false);
  });
  it('a blocked keyword event reads as blocked, not as masking',async()=>{
    open({...fixture,comparisons:[],metadata:{...fixture.metadata,gateway_final:'BLOCK'},mask_comparison:{status:'NOT_RECORDED',entity_counts:[{entity_type:'DOC_KEYWORD',count:2}]}});
    expect(await screen.findByRole('heading',{name:'차단된 입력'})).toBeInTheDocument();
    expect(screen.getByText('기밀 키워드 탐지 · 전송 차단')).toBeInTheDocument();
    expect(screen.getByText('문서 일치가 아닌 기밀 키워드 탐지입니다')).toBeInTheDocument();
    expect(screen.getByText('이 요청은 차단되어 LLM으로 전송되지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading',{name:/마스킹 전·후/})).not.toBeInTheDocument();
  });
  it('does not fabricate a protected document or a Gateway mask result for a signature event',async()=>{
    open({...fixture,comparisons:[],mask_comparison:{status:'NOT_RECORDED',entity_counts:[{entity_type:'KR_PHONE_NUMBER',count:1}]}});
    expect(await screen.findByText('문서 일치가 아닌 민감정보 패턴 탐지입니다')).toBeInTheDocument();
    expect(screen.getByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByRole('link',{name:'사업전략.docx'})).not.toBeInTheDocument();
  });
});
describe('prompt masking without a Gateway body',()=>{
  it('shows the same before/after as the own-request page, with the original and no black blocks',async()=>{
    const {container}=open(claudeMask);
    expect(await screen.findByRole('heading',{name:'민감정보 마스킹 전·후'})).toBeInTheDocument();
    expect(screen.getByText('민감정보 탐지 · 요청 치환')).toBeInTheDocument();
    expect(screen.getByText('RDS 기록 기반 · 원문 그대로 표시')).toBeInTheDocument();
    expect(within(screen.getByLabelText('마스킹 전 입력')).getByText(PHONE).tagName).toBe('MARK');
    expect(within(screen.getByLabelText('실제로 보낸 내용')).getByText('[KR_PHONE_NUMBER]')).toBeInTheDocument();
    expect(screen.getByText('전 · 원문')).toBeInTheDocument();
    expect(container.textContent).not.toContain('█');
    expect(screen.queryByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).not.toBeInTheDocument();
    expect(screen.queryByText('칸 번호 표시')).not.toBeInTheDocument();
    expect(evidenceService.getPage).not.toHaveBeenCalled();
  });
  it('keeps the Gateway body view when the Gateway sent one',async()=>{
    open({...claudeMask,mask_comparison:{status:'REQUEST_REWRITTEN',entity_counts:[{entity_type:'KR_PHONE_NUMBER',count:1}],
      before_preview:'고객 연락처 █████████████로 안내해줘',after_preview:'고객 연락처 [KR_PHONE_NUMBER]로 안내해줘',before_chars:24,after_chars:28,preview_truncated:false,spans:[],outbound_text_sha256:'a'.repeat(64)}});
    expect(await screen.findByText('게이트웨이가 실제로 치환한 요청 본문')).toBeInTheDocument();
    expect(screen.queryByLabelText('마스킹 전 입력')).not.toBeInTheDocument();
    expect(screen.queryByText('RDS 기록 기반 · 원문 그대로 표시')).not.toBeInTheDocument();
  });
  it('keeps the earlier notice when no masked text was recorded, and the blocked view for a block',async()=>{
    const {unmount}=open({...claudeMask,prompt_comparison:undefined});
    expect(await screen.findByText('당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByLabelText('마스킹 전 입력')).not.toBeInTheDocument();
    unmount();
    open({...claudeMask,metadata:{...fixture.metadata,gateway_final:'BLOCK'}});
    expect(await screen.findByRole('heading',{name:'차단된 입력'})).toBeInTheDocument();
    expect(screen.getByText('이 요청은 차단되어 LLM으로 전송되지 않았습니다.')).toBeInTheDocument();
    expect(screen.queryByLabelText('마스킹 전 입력')).not.toBeInTheDocument();
  });
  it('keeps the response field through validation and rejects a malformed one',()=>{
    expect(evidenceSchema.parse(claudeMask).prompt_comparison).toEqual(promptComparison);
    expect(evidenceSchema.safeParse({...claudeMask,prompt_comparison:{status:'AVAILABLE',segments:[{id:'prompt'}]}}).success).toBe(false);
  });
});
