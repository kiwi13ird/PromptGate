import {useEffect,useRef,useState} from 'react';
import {useQuery} from '@tanstack/react-query';
import {ChevronLeft,ChevronRight,FileText,ShieldCheck} from 'lucide-react';
import {evidenceService,type EventEvidence,type EvidencePage} from '@/src/services/evidenceService';
import { liveQueryOptions } from './AutoRefreshBar';
import { maskHighlights, splitHighlightedText } from '@/src/utils/maskHighlight';
import { uiLabel } from '@/src/utils/labels';
import { signatureLabel } from '@/src/utils/entityCategory';
import { formatCount } from '@/src/utils/format';

const PAGE_SIZE=1800;
type Location={char_start:number;char_end:number};
type SyncAnchor={id:string;location:Location};
type SyncTarget={id:string;progress:number;offset:number;sequence:number};
export function PageText({page,focus,matches=[],changes=[],anchors=[],selectedAnchor,onSelectAnchor,sideLabel='본문'}:{page:EvidencePage;focus?:Location;matches?:Location[];changes?:Location[];anchors?:SyncAnchor[];selectedAnchor?:string;onSelectAnchor?:(id:string)=>void;sideLabel?:string}) {
  const text=Array.from(page.segments?.map(part=>part.text).join('')??'');
  const offset=page.char_start??0;
  const ranges=[...(focus?[{...focus,kind:'same'}]:[]),...matches.map(range=>({...range,kind:'same'})),...changes.map(range=>({...range,kind:'changed'}))].map(range=>({...range,start:Math.max(0,Math.min(text.length,range.char_start-offset)),end:Math.max(0,Math.min(text.length,range.char_end-offset))})).filter(range=>range.end>range.start);
  const edges=[...new Set([0,text.length,...ranges.flatMap(range=>[range.start,range.end])])].sort((a,b)=>a-b);
  return <>{edges.slice(0,-1).map((start,index)=>{const end=edges[index+1],range=ranges.find(range=>range.kind==='changed'&&range.start<=start&&range.end>=end)??ranges.find(range=>range.start<=start&&range.end>=end);const anchor=range?.kind==='same'?anchors.find(a=>a.location.char_start<=offset+start&&a.location.char_end>=offset+end):undefined;const content=text.slice(start,end).join('');const interactive=anchor&&onSelectAnchor;return range?<mark key={start} data-sync-anchor={anchor?.id} data-char-start={offset+start} data-char-end={offset+end} role={interactive?'button':undefined} tabIndex={interactive?0:undefined} aria-label={interactive?`일치 구간 ${Number(anchor.id.replace('match-',''))+1} 선택 · ${sideLabel}`:undefined} aria-pressed={interactive?selectedAnchor===anchor.id:undefined} onClick={interactive?()=>onSelectAnchor(anchor.id):undefined} onKeyDown={interactive?e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onSelectAnchor(anchor.id);}}:undefined} className={`${range.kind==='changed'?'evidence-change':'evidence-same'}${interactive?' evidence-selectable':''}${interactive&&selectedAnchor===anchor.id?' evidence-selected':''}`}>{content}</mark>:<span key={start}>{content}</span>;})}</>;
}
function DocumentSheet({eventId,side,documentId,title,location,focus,matches,changes,changedFocus,offset,onOffset,anchors=[],syncTarget,onAnchorScroll,jumpRevision=0,onSelectAnchor,selectedAnchor}:{eventId:string;side:'input'|'document';documentId?:string;title:string;location?:Location;focus?:Location;matches?:Location[];changes?:Location[];changedFocus?:Location;offset:number;onOffset:(offset:number)=>void;anchors?:SyncAnchor[];syncTarget?:SyncTarget;onAnchorScroll?:(id:string,progress:number)=>void;jumpRevision?:number;onSelectAnchor?:(id:string)=>void;selectedAnchor?:string}) {
  const query=useQuery({...liveQueryOptions,queryKey:['evidence-page',eventId,side,documentId,offset],queryFn:({signal})=>evidenceService.getPage(eventId,side,offset,documentId,signal)});
  const page=query.data;
  const scrollRef=useRef<HTMLDivElement>(null);
  const jumped=useRef('');
  const ignoreTop=useRef<number|undefined>(undefined);
  const synced=useRef(0);
  useEffect(()=>{
    const key=`${offset}:${focus?.char_start}:${focus?.char_end}:${changedFocus?.char_start}:${jumpRevision}`;
    if(page?.status!=='AVAILABLE'||jumped.current===key)return;
    jumped.current=key;
    const container=scrollRef.current;
    const target=changedFocus??focus;
    const mark=target?Array.from(container?.querySelectorAll(changedFocus?'.evidence-change':'.evidence-same')??[]).find(mark=>Number(mark.getAttribute('data-char-start'))<=target.char_start&&Number(mark.getAttribute('data-char-end'))>target.char_start):null;
    if(container&&mark){container.scrollTop=Math.max(0,container.scrollTop+mark.getBoundingClientRect().top-container.getBoundingClientRect().top-64);ignoreTop.current=container.scrollTop;}
  },[page,offset,focus?.char_start,focus?.char_end,changedFocus?.char_start,jumpRevision]);
  useEffect(()=>{
    if(!syncTarget||syncTarget.offset!==offset||page?.status!=='AVAILABLE'||synced.current===syncTarget.sequence)return;
    const anchor=anchors.find(a=>a.id===syncTarget.id),container=scrollRef.current;
    if(!anchor||!container)return;
    const point=anchor.location.char_start+Math.min(.999999,Math.max(0,syncTarget.progress))*(anchor.location.char_end-anchor.location.char_start);
    const mark=Array.from(container.querySelectorAll<HTMLElement>('[data-sync-anchor]')).find(m=>m.dataset.syncAnchor===syncTarget.id&&Number(m.dataset.charStart)<=point&&Number(m.dataset.charEnd)>point);
    if(!mark)return;
    const progress=(point-Number(mark.dataset.charStart))/Math.max(1,Number(mark.dataset.charEnd)-Number(mark.dataset.charStart));
    container.scrollTop=Math.max(0,container.scrollTop+mark.getBoundingClientRect().top-container.getBoundingClientRect().top-64+progress*mark.getBoundingClientRect().height);
    ignoreTop.current=container.scrollTop;synced.current=syncTarget.sequence;
  },[syncTarget,page,offset,anchors]);
  const total=page?.total_chars??0;
  const start=page?.char_start??offset;
  const count=Math.max(1,Math.ceil(total/PAGE_SIZE));
  return <section className="evidence-document-sheet">
    <header><span className="evidence-source-tag">{side==='input'?'입력 기록':'보호 문서'}</span><h4 title={title}><FileText size={17} aria-hidden="true" />{title}</h4><p>{side==='input'?'요청 ID와 연결된 당시 입력':page?.content_source==='EVENT_DOCUMENT_VERSION'?'사건 당시 문서 버전의 보존 본문':'현재 RDS에 저장된 문서 텍스트'}</p></header>
    {count>1&&<div className="evidence-sheet-controls"><button type="button" aria-label={`${side==='input'?'입력':'문서'} 이전 보기`} disabled={query.isFetching||start===0} onClick={()=>onOffset(Math.max(0,start-PAGE_SIZE))}><ChevronLeft size={16}/></button><span>{Math.floor(start/PAGE_SIZE)+1} / {count} 보기</span><button type="button" aria-label={`${side==='input'?'입력':'문서'} 다음 보기`} disabled={query.isFetching||start+PAGE_SIZE>=total} onClick={()=>onOffset(start+PAGE_SIZE)}><ChevronRight size={16}/></button>{location&&<button type="button" className="evidence-jump" onClick={()=>onOffset(Math.floor((changedFocus??focus??location).char_start/PAGE_SIZE)*PAGE_SIZE)}>선택 구간으로</button>}</div>}
    <div className="evidence-paper-scroll" ref={scrollRef} aria-label={side==='input'?'입력 문서 내용':'보호 문서 내용'} tabIndex={0} key={offset} onScroll={()=>{
      const container=scrollRef.current;if(!onAnchorScroll||!container||query.isError||page?.status!=='AVAILABLE'||(ignoreTop.current!==undefined&&Math.abs(container.scrollTop-ignoreTop.current)<1))return;
      const line=container.getBoundingClientRect().top+64;
      const mark=Array.from(container.querySelectorAll<HTMLElement>('[data-sync-anchor]')).find(m=>m.getBoundingClientRect().top<=line&&m.getBoundingClientRect().bottom>line);
      const anchor=anchors.find(a=>a.id===mark?.dataset.syncAnchor);if(!mark||!anchor)return;
      const progress=(Number(mark.dataset.charStart)-anchor.location.char_start+(line-mark.getBoundingClientRect().top)/Math.max(1,mark.getBoundingClientRect().height)*(Number(mark.dataset.charEnd)-Number(mark.dataset.charStart)))/Math.max(1,anchor.location.char_end-anchor.location.char_start);
      onAnchorScroll(anchor.id,Math.max(0,Math.min(1,progress)));
    }}>
      {query.isLoading?<p className="evidence-empty">실제 텍스트를 불러오는 중…</p>:query.isError?<p className="evidence-empty">텍스트를 불러오지 못했습니다. <button type="button" onClick={()=>query.refetch()}>다시 시도</button></p>:page?.status!=='AVAILABLE'?<p className="evidence-empty">이 기록은 안전하게 연결할 비교 텍스트가 없습니다.</p>:<article className="evidence-paper"><div className="evidence-paper-label">{side==='input'?'검사한 입력':'원본 문서 저장본'} · {onSelectAnchor?'강조 문장을 누르면 양쪽 구간 선택':'텍스트 보기'}</div><div className="evidence-document-text"><PageText page={page} focus={focus} matches={matches} changes={changes} anchors={anchors} onSelectAnchor={onSelectAnchor} selectedAnchor={selectedAnchor} sideLabel={side==='input'?'입력 본문':'보호 문서'}/></div><footer>문자 {start.toLocaleString()}–{page.char_end?.toLocaleString()} / {total.toLocaleString()}</footer></article>}
    </div>
  </section>;
}
// 보호 문서 비교(옛 EvidenceDocumentComparison: 일치 구간 칩·나란히 쪽 보기)는 2026-10-16 문서 한 페이지 보기(EvidenceDocumentPage.tsx)로 바뀜
export function SignatureInputComparison({eventId,entities,proof,raw=false,blocked=false}:{eventId:string;entities:Array<{entity_type:string;count:number}>;proof?:EventEvidence['mask_comparison'];raw?:boolean;blocked?:boolean}) {
  const [offset,setOffset]=useState(0);
  const highlights=proof?maskHighlights(proof):undefined;
  const marked=(text:string|undefined,ranges:Array<{start:number;end:number}>,side:string)=>text===undefined?<span className="evidence-empty-body">{side==='before'?'치환 전':'치환 후'} 본문이 기록되지 않았습니다.</span>:text===''?<span className="evidence-empty-body">본문 내용 없음 · 빈 문자열이 기록되었습니다.</span>:splitHighlightedText(text,ranges).map((part,index)=>part.highlighted?<mark key={index} className={`mask-change mask-change-${side}`}>{part.text}</mark>:<span key={index}>{part.text}</span>);
  // 2026-10-17: 서버가 같은 입력의 원문으로 되돌렸으면(before_raw) 설정과 무관하게 원문 그대로 + 위치 하이라이트
  const beforeRaw=raw||proof?.before_raw===true;
  const characters=(count:number|undefined)=>count===undefined?'글자 수 미기록':`${count.toLocaleString()}자`;
  const requestBody=(text:string|undefined,ranges:Array<{start:number;end:number}>,side:string)=>{
    const scrollable=Boolean(text&&(text.length>500||text.split('\n').length>10));
    return <p className="evidence-document-text" tabIndex={scrollable?0:undefined} role={scrollable?'region':undefined} aria-label={scrollable?side==='before'?'치환 전 보관 본문':'치환 후 보관 본문':undefined}>{marked(text,ranges,side)}</p>;
  };
  const labels:Record<string,string>={KR_PHONE_NUMBER:'전화번호',KR_RRN:'주민등록번호',EMAIL_ADDRESS:'이메일',GENERIC_API_KEY:'API 키'};
  return <article className="match-comparison signature-input-comparison"><div className="evidence-match-banner"><ShieldCheck size={20}/><div><strong>문서 일치가 아닌 {signatureLabel(entities.map(entity=>entity.entity_type))} 탐지입니다</strong><p>이 이벤트는 보호 문서와 비교하지 않습니다.</p></div></div><div className="evidence-entity-tags">{entities.map(entity=><span key={entity.entity_type}>{labels[entity.entity_type]??uiLabel(entity.entity_type)} <b>{formatCount(entity.count)}개</b></span>)}</div>{proof?.status==='REQUEST_REWRITTEN'&&<p className="evidence-transformation" aria-label="저장된 요청 마스킹 전후 관계"><span>원래 요청</span><strong>→ Gateway 마스킹 →</strong><span>전달 요청</span></p>}<div className="evidence-document-pair">
    {proof?.status==='REQUEST_REWRITTEN'?<><section className="evidence-paper"><header className="mask-request-heading"><span>Original Request</span><h4>원래 요청</h4></header><div className="evidence-paper-label">{beforeRaw?'치환 전 입력 · 원문':'치환 전 입력 · 민감 값 보호'}</div>{requestBody(proof.before_preview,highlights?.before??[],'before')}<footer>{characters(proof.before_chars)} · 강조는 기록된 탐지 위치{beforeRaw?'':' · 민감 값은 █로 보호'}</footer></section><section className="evidence-paper"><header className="mask-request-heading"><span>Forwarded / Masked Request</span><h4>전달 요청 · 마스킹 적용</h4></header><div className="evidence-paper-label">게이트웨이가 실제로 치환한 요청 본문</div>{requestBody(proof.after_preview,highlights?.after??[],'after')}<footer>{characters(proof.after_chars)} · {proof.after_preview===undefined?'본문 기록 없음':proof.preview_truncated?'일부 미리보기':'본문 치환 확인'}</footer><p className="match-caption mask-comparison-proof-caption">{highlights?.mapped?'강조된 부분은 전후 본문 대조로 확인한 치환 범위입니다.':'치환 후 위치를 확실히 대응할 수 없어 범위 강조는 하지 않습니다.'} 요청 변경 기록이며 외부 LLM의 수신·답변 완료를 뜻하지 않습니다.</p><details className="comparison-explanation"><summary>처리 근거</summary><p>탐지 구간 {proof.spans?.map(s=>`${s.start}–${s.end} (${labels[s.entityType]??s.entityType})`).join(' · ')||'구간 당시 미기록'}</p>{proof.outbound_text_sha256&&<p className="match-caption">치환 본문 SHA-256: {proof.outbound_text_sha256}</p>}</details></section></>:<><DocumentSheet eventId={eventId} side="input" title="검사된 입력" offset={offset} onOffset={setOffset}/>{blocked?<section className="evidence-mask-unavailable"><h4>전송 차단</h4><p>이 요청은 차단되어 LLM으로 전송되지 않았습니다.</p></section>:<section className="evidence-mask-unavailable"><h4>게이트웨이 최종 마스킹 결과</h4><p>당시 전송된 마스킹 본문은 RDS에 저장되지 않았습니다.</p>{!raw&&<p>입력의 █ 표시는 대시보드의 개인정보 보호 처리이며, 게이트웨이가 실제로 바꾼 문자열이나 탐지 위치의 증거가 아닙니다.</p>}<p>실제 전·후 비교에는 게이트웨이가 적용한 마스킹 구간과 처리 결과 기록이 필요합니다.</p></section>}</>}
  </div></article>;
}
