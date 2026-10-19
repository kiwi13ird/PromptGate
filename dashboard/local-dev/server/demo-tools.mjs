// All answers derive from current observations, not historical success badges.
export function lookupRequest(events,params,now=Date.now()) {
  const kind=params.get('kind'), value=(params.get('value')??'').trim();
  const since=params.get('since'), sinceMs=since?Date.parse(since):null;
  if(!['request','client','event'].includes(kind)||!value||value.length>200
    ||[...params.keys()].some(k=>!['kind','value','since'].includes(k))
    ||(since!==null&&(!Number.isFinite(sinceMs)||sinceMs>now+5000))
    ||(kind==='client'&&(!since||value.toLowerCase()==='unknown-client'))){
    const error=new Error('A known identifier and valid observation time are required.');error.statusCode=400;throw error;
  }
  const field={request:'request_id',client:'client_id',event:'event_id'}[kind];
  const items=events.filter(e=>e[field]===value&&(sinceMs===null||Date.parse(e.occurred_at)>=sinceMs))
    .sort((a,b)=>Date.parse(b.occurred_at)-Date.parse(a.occurred_at));
  return {status:!items.length?'WAITING':kind!=='client'&&items.length>1?'AMBIGUOUS':'FOUND',
    count:items.length,items:items.slice(0,5).map(e=>({event_id:e.event_id,request_id:e.request_id,client_id:e.client_id,
      occurred_at:e.occurred_at,final_action:e.final_action??e.action,target_llm:e.target_llm,content_type:e.content_type})),
    checked_at:new Date(now).toISOString()};
}
