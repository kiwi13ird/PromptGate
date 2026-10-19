import {useEffect,useState,type SyntheticEvent} from 'react';
import {useQuery} from '@tanstack/react-query';
import {Link} from 'react-router-dom';
import {uiMode} from '@runtime/ui-mode';
import {demoToolsService,type LookupKind} from '@/src/services/demoToolsService';
import {formatDateTime} from '@/src/utils/format';
import {lookupMatches} from '@/src/utils/requestLookup';
const labels={request:'요청 ID',client:'클라이언트 ID',event:'이벤트 ID'};
export function RequestFinder(){
  const [kind,setKind]=useState<LookupKind>('request'),[value,setValue]=useState(''),[error,setError]=useState('');
  const [search,setSearch]=useState<{kind:LookupKind;value:string;since?:string;started:number}>();
  const [expired,setExpired]=useState(false);
  useEffect(()=>{if(!search)return;const timer=window.setTimeout(()=>setExpired(true),Math.max(0,120000-(Date.now()-search.started)));return()=>window.clearTimeout(timer);},[search]);
  const query=useQuery({queryKey:['request-finder',search],queryFn:({signal})=>demoToolsService.lookup(search!.kind,search!.value,search!.since,signal),enabled:!!search&&!uiMode.isDemo,retry:false,refetchInterval:q=>!expired&&q.state.data?.status==='WAITING'?1500:false,refetchIntervalInBackground:false});
  function submit(event:SyntheticEvent){event.preventDefault();const id=value.trim();setError('');if(!id||id.length>200||(kind==='client'&&id.toLowerCase()==='unknown-client')){setError('프록시가 보낸 실제 식별자를 입력하세요. unknown-client로는 사람을 구분할 수 없습니다.');return;}setExpired(false);setSearch({kind,value:id,started:Date.now(),...(kind==='client'?{since:new Date().toISOString()}: {})});}
  function resume(){if(!search)return;setExpired(false);setSearch({...search,started:Date.now()});}
  const mismatch=search&&query.data&&!lookupMatches(query.data,search.kind,search.value,search.since);
  if(uiMode.isDemo)return null;
  return <section id="request-finder" className="panel request-finder"><div className="panel-heading"><div><h3>내 요청 찾기</h3><span>식별자가 정확히 같은 기록만 표시합니다.</span></div></div><form onSubmit={submit} className="request-finder-form"><label>조회 기준<select aria-label="내 요청 조회 기준" value={kind} onChange={e=>setKind(e.target.value as LookupKind)}>{Object.entries(labels).map(([id,label])=><option key={id} value={id}>{label}</option>)}</select></label><label>{labels[kind]}<input aria-label="내 요청 식별자" value={value} maxLength={200} onChange={e=>setValue(e.target.value)} placeholder="프록시·확장 프로그램이 전달한 ID"/></label><button type="submit">{kind==='client'?'지금부터 요청 기다리기':'이 요청 확인'}</button></form>
    <p className="request-finder-help">{kind==='client'?'조회 시작 이후 같은 클라이언트 ID의 기록을 기다립니다.':'프록시·확장 프로그램 또는 사건 상세의 ID를 그대로 입력하세요. 대소문자를 구분해 조회합니다.'} 입력한 식별자와 정확히 일치하는 사건만 표시합니다.</p>
    {error&&<p role="alert" className="evidence-notice">{error}</p>}{search&&(query.isError?<p role="status" className="evidence-notice">조회에 실패했습니다. <button type="button" onClick={resume}>다시 확인</button></p>:!query.data?<p role="status" className="evidence-notice">해당 요청 조회 중…</p>:mismatch?<p role="alert" className="evidence-notice">입력한 식별자·조회 시작 시각과 다른 결과여서 표시하지 않았습니다. <button type="button" onClick={resume}>다시 확인</button></p>:<div aria-live="polite" className="request-finder-results"><p>{query.data.status==='WAITING'?(expired?'2분 동안 해당 식별자의 사건이 확인되지 않았습니다. 프록시 경로와 ID를 확인하세요.':'아직 해당 식별자의 사건이 없습니다. 최대 2분 동안 자동 확인합니다.'):query.data.status==='AMBIGUOUS'?'같은 ID로 여러 사건이 있어 자동으로 선택하지 않습니다. 아래 기록을 비교하세요.':`해당 식별자 사건 ${query.data.count}건 확인`}</p>{expired&&query.data.status==='WAITING'&&<button type="button" onClick={resume}>다시 2분 기다리기</button>}{query.data.items.map(item=><Link key={item.event_id} to={`/events/${encodeURIComponent(item.event_id)}?view=compare`}><strong>{item.final_action==='BLOCK'?'차단':item.final_action==='MASK'?'마스킹':'허용'} · {item.target_llm}</strong><span>{formatDateTime(item.occurred_at)}</span><code>{item.event_id}</code><small>{item.request_id??'요청 ID 미기록'} · {item.client_id}</small></Link>)}{query.data.count>5&&<small>최근 5건을 표시합니다. 전체 내역은 아래 검색에서 확인하세요.</small>}</div>)}
  </section>;
}
