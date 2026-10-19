import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { evidenceService, type EventEvidence } from '@/src/services/evidenceService';
import { formatDateTime, formatProcessingTime } from '@/src/utils/format';
import { uiMode } from '@runtime/ui-mode';
import {SignatureInputComparison} from './EvidenceDocumentViewer';
import {EvidenceDetails,EvidenceDocumentPage} from './EvidenceDocumentPage';
import {FileComparisonView,fileComparisonNotes,fileEntityCounts} from './FileComparisonView';
import {FileText} from 'lucide-react';
import { liveQueryOptions } from './AutoRefreshBar';
import type { EnforcementResult, SecurityAction } from '@/src/types/event';
import { signatureLabel } from '@/src/utils/entityCategory';

const unavailable = {
  PENDING:'사건은 저장됐으며 탐지 근거를 연결하고 있습니다. 잠시 후 자동으로 다시 확인합니다.',
  NOT_RECORDED:'연결할 수 있는 당시 기록 또는 비교용 텍스트가 없습니다.',
  AMBIGUOUS:'같은 요청 ID의 기록이 여러 건이라 잘못된 내용을 연결하지 않습니다.',
  MISMATCH:'이벤트와 탐지 기록의 문서·구간이 달라 비교를 표시하지 않습니다.',
  TOO_LARGE:'안전한 비교 처리 한도를 초과했습니다.',
  INVALID_RANGE:'저장된 텍스트에 기록된 문자 구간을 적용할 수 없습니다.',
};
const statusLabels:Record<string,string>={ok:'정상',error:'오류',skipped:'미실행'};
// expanded: 비교 집중 화면 여부(2026-10-16부터 보호 문서 비교는 두 화면이 같은 문서 한 페이지 보기라 쓰지 않음, 호출 호환용)
export function EventEvidencePanel({eventId,enforcement,finalAction}:{eventId:string;enforcement?:EnforcementResult;expanded?:boolean;finalAction?:SecurityAction}) {
  const query=useQuery<EventEvidence>({...liveQueryOptions,refetchInterval:q=>q.state.data?.status==='PENDING'?1500:10000,queryKey:['event-evidence',eventId],queryFn:({signal})=>evidenceService.getEventEvidence(eventId,signal),enabled:!uiMode.isDemo});
  if (uiMode.isDemo) return null;
  const maskOnly=!query.isError&&query.data?.status==='AVAILABLE'&&!!query.data.mask_comparison&&!query.data.comparisons.length;
  const documentComparison=!query.isError&&query.data?.status==='AVAILABLE'&&!!query.data.comparisons.length;
  const raw=query.data?.redaction==='OFF';
  const fileView=maskOnly&&!!query.data?.file_comparison;
  // 차단된 요청은 보낸 것이 없으므로 '마스킹 전·후'가 아니다(2026-10-10). 키워드만 걸린 건은 '기밀 키워드'로
  const blocked=(finalAction??query.data?.metadata?.gateway_final)==='BLOCK';
  // Gateway 마스킹 본문이 없는 질문 마스킹은 Detection 판정 기록의 전·후를 내 요청 기록과 같은 화면으로 보인다(2026-10-12). Gateway 본문이 있으면 지금 화면
  const promptView=maskOnly&&!fileView&&!blocked&&query.data?.mask_comparison?.status!=='REQUEST_REWRITTEN'&&query.data?.prompt_comparison?.status==='AVAILABLE';
  const kind=signatureLabel(query.data?.mask_comparison?.entity_counts.map(entity=>entity.entity_type)??[]);
  const kindShort=kind==='기밀 키워드'?'기밀 키워드':'민감정보';
  const pageView=documentComparison||(fileView&&!!query.data?.file_comparison);
  const fileTotals=fileView&&query.data?.file_comparison?fileEntityCounts(query.data.file_comparison.segments):[];
  return <section className="panel rds-evidence-panel">
    <div className="panel-heading"><div><p className="eyebrow">{maskOnly?`${kindShort} 탐지 · ${blocked?'전송 차단':fileView?'마스킹 후 전송':'요청 치환'}`:'실제 입력 · 보호 문서'}</p><h3>{fileView?(blocked?'차단된 파일':'파일 마스킹 전·후'):maskOnly?(blocked?'차단된 입력':`${kindShort} 마스킹 전·후`):documentComparison?'보호 문서 일치 구간':'탐지 구간 비교'}</h3></div><span>{raw||fileView||promptView||query.data?.mask_comparison?.before_raw?'RDS 기록 기반 · 원문 그대로 표시':'RDS 기록 기반 · 민감정보 보호 표시'}</span></div>
    {query.isLoading?<p className="evidence-notice">탐지 근거를 불러오는 중입니다.</p>:query.isError?<p className="evidence-notice" role="status">최신 비교 근거를 확인하지 못해 문서 비교를 잠시 숨겼습니다. <button type="button" onClick={()=>query.refetch()}>근거 다시 시도</button></p>:!query.data?null:query.data.status!=='AVAILABLE'?<p className="evidence-notice">{unavailable[query.data.status]}</p>:<>
      {/* 2026-10-16: 보호 문서 일치·파일 전·후는 요약 한 줄 + 문서 한 페이지 + 맨 아래 '세부 정보' 하나. 나머지(패턴 마스킹 전·후 등)는 그대로 */}
      {query.data.metadata&&!pageView&&<div className="evidence-timing-strip">{query.data.metadata.detection_ms!==undefined&&<span>보안 검사 <strong>{formatProcessingTime(query.data.metadata.detection_ms)}</strong></span>}{query.data.metadata.input_chars!==undefined&&<span>검사한 입력 <strong>{query.data.metadata.input_chars.toLocaleString()}자</strong></span>}{query.data.metadata.input_filename&&<span>전송 파일 <strong>{query.data.metadata.input_filename}</strong></span>}</div>}
      {fileView&&query.data.file_comparison?<>
        <p className="pg-evp-summary pg-evp-file-summary"><FileText aria-hidden="true" className="pg-evp-icon"/><span className="pg-evp-name" title={query.data.metadata?.input_filename}>{query.data.metadata?.input_filename??'전송 파일'}</span>
          {fileTotals.length>0&&<span><span className="pg-evp-key">{blocked?'탐지':'가린 항목'}</span> {fileTotals.map(([name,count],index)=><span key={name}>{index>0&&' · '}{name} <b>{count}</b></span>)}</span>}
          {query.data.metadata?.detection_ms!==undefined&&<span><span className="pg-evp-key">보안 검사</span> <b>{formatProcessingTime(query.data.metadata.detection_ms)}</b></span>}</p>
        <FileComparisonView comparison={query.data.file_comparison} blocked={blocked} layout="page"/></>
      :promptView&&query.data.prompt_comparison?<FileComparisonView comparison={query.data.prompt_comparison} variant="text" blocked={blocked}/>:query.data.mask_comparison&&<SignatureInputComparison eventId={eventId} entities={query.data.mask_comparison.entity_counts} proof={query.data.mask_comparison} raw={raw} blocked={blocked}/>}
      {query.data.comparisons.map((comparison,index)=>comparison.status==='AVAILABLE'&&comparison.input_location
        ?<EvidenceDocumentPage key={`${eventId}-${comparison.document_id}-${index}`} eventId={eventId} comparison={comparison} metadata={query.data?.metadata}/>
        :<article className="pg-evp" key={`${eventId}-${comparison.document_id}-${index}`}><p className="pg-evp-summary"><FileText aria-hidden="true" className="pg-evp-icon"/><Link className="pg-evp-doc" to={`/documents/${encodeURIComponent(comparison.document_id)}`}>{comparison.document_name??comparison.document_id}</Link></p><p className="evidence-notice">{comparison.status==='AVAILABLE'?unavailable.INVALID_RANGE:unavailable[comparison.status]}</p></article>)}
      {pageView?<EvidenceDetails comparisons={query.data.comparisons} metadata={query.data.metadata} finalAction={finalAction??query.data.metadata?.gateway_final} enforcement={enforcement} raw={raw}
        notes={fileView&&query.data.file_comparison?[`검사한 입력 ${query.data.metadata?.input_chars!==undefined?`${query.data.metadata.input_chars.toLocaleString()}자`:'글자 수 미기록'}`,...fileComparisonNotes(query.data.file_comparison,{blocked})]:[]}/>
      :query.data.metadata&&<details className="evidence-record-details"><summary>당시 탐지 기록 세부정보</summary><dl className="rds-metadata-grid">
        {query.data.metadata.detection_reason&&<div className="rds-reason"><dt>당시 탐지 사유</dt><dd>{query.data.metadata.detection_reason}</dd></div>}
        {query.data.metadata.detection_ms!==undefined&&<div><dt>탐지 처리시간</dt><dd>{formatProcessingTime(query.data.metadata.detection_ms)}</dd></div>}
        {query.data.metadata.input_chars!==undefined&&<div><dt>검사한 입력 글자 수</dt><dd>{query.data.metadata.input_chars.toLocaleString()}자</dd></div>}
        {query.data.metadata.hash_status&&<div><dt>해시 검사 상태</dt><dd>{statusLabels[query.data.metadata.hash_status]??query.data.metadata.hash_status}</dd></div>}
        {query.data.metadata.signature_status&&<div><dt>시그니처 검사 상태</dt><dd>{statusLabels[query.data.metadata.signature_status]??query.data.metadata.signature_status}</dd></div>}
        {query.data.metadata.input_filename&&<div><dt>검사한 파일명</dt><dd>{query.data.metadata.input_filename}</dd></div>}
        {query.data.metadata.decision_at&&<div><dt>탐지 기록 시각</dt><dd>{formatDateTime(query.data.metadata.decision_at)}</dd></div>}
      </dl></details>}
    </>}
  </section>;
}
