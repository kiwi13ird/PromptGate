import { uiLabel } from '@/src/utils/labels';
import { useState, type SyntheticEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, MessageSquarePlus } from 'lucide-react';
import { Link, useLocation, useParams, useSearchParams } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ActionBadge, DetectorBadge, EmptyState, ErrorState, IncidentStatusBadge, LoadingSkeleton } from '@/src/components/common';
import { ApiError } from '@/src/api/errors';
import { eventKeys, auditKeys, dashboardKeys, trafficKeys } from '@/src/queries/keys';
import { eventService } from '@/src/services/eventService';
import type { Detection, IncidentStatus, SecurityEvent } from '@/src/types/event';
import { formatDateTime, formatProcessingTime, formatCount } from '@/src/utils/format';
import { notifyError, notifySuccess, safeMessage } from '@/src/utils/feedback';
import { uiMode } from '@runtime/ui-mode';
import { EventEvidencePanel } from '@/src/components/EventEvidencePanel';
import { InvestigationSummary } from '@/src/components/InvestigationSummary';
import { AutoRefreshBar, liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { missingDetectionTitle, displayRequestPath, inspectionFailure } from '@/src/utils/eventPresentation';
import { hasReasonLabel, reasonLabel } from '@/src/utils/reasonLabels';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { GATEWAY_PROCESSING_LABEL, GATEWAY_PROCESSING_SCOPE } from '@/src/utils/trafficPresentation';
import { storyPercent } from '@/src/utils/eventStory';
import { eventListReturnPath } from '@/src/utils/requestLookup';
import { ClientIdentity } from '@/src/components/ClientAlias';
import { EventAccessControl } from '@/src/components/EventAccessControl';
import { useClientAliases } from '@/src/hooks/useGatewayAccess';
import { blockNumber } from '@/src/services/gatewayAccessService';

const attachedActionText: Record<SecurityEvent['finalAction'], string> = { ALLOW: '허용', MASK: '마스킹', BLOCK: '차단' };
import { ReviewLinkCopy } from '@/src/components/ReviewLinkCopy';
import { signatureLabel } from '@/src/utils/entityCategory';
import { HASH_RATIO_NAME, sameTextLabel } from '@/src/utils/sameTextLabel';
import { SAME_RATIO_NAME } from '@/src/utils/matchRatio';

const labels: Record<Detection['matchType'], string> = {
  EXACT_DOCUMENT: '문서 전체 일치',
  SIMILAR_DOCUMENT: '유사 문서 일치',
  TEXT_FRAGMENT: '문서 구간 일치',
  SIGNATURE_RULE: '민감정보 패턴 일치',
};
const percent = storyPercent;

function scoreLabel(detection: Detection) {
  if (detection.detector === 'SHA256') return '완전 일치';
  if (detection.detector === 'MINHASH') return `유사도 ${percent(detection.similarity)}`;
  if (detection.detector === 'WINDOW_HASH') return `${HASH_RATIO_NAME} ${percent(detection.score)}`;   // Detection 값(같은 글자 비율과 다른 값이라 이름을 구분)
  return detection.confidence === undefined ? `${signatureLabel(detection.entityCounts?.map(item => item.entityType) ?? [])} 일치` : `신뢰도 ${percent(detection.confidence)}`;
}

function eventTitle(detections: Detection[], outcome: SecurityEvent['detectionOutcome']) {
  if (detections.length > 1) return `${formatCount(detections.length)}건 탐지 확인`;
  const detection = detections[0];
  if (!detection) return missingDetectionTitle(outcome);
  if (detection.detector === 'WINDOW_HASH') return `보호 문서 구간 탐지 · ${sameTextLabel(detection).text}`;
  if (detection.detector === 'MINHASH') return `보호 문서 유사도 ${percent(detection.similarity)}`;
  if (detection.detector === 'SHA256') return '동일 보호 문서 탐지';
  return `${signatureLabel(detection.entityCounts?.map(item => item.entityType) ?? [])} 탐지`;
}

function DetectionFinding({ detection, index }: { detection: Detection; index: number }) {
  return <article className="detection-finding">
    <div className="finding-heading"><span>탐지 근거 {String(index + 1).padStart(2, '0')}</span>{uiMode.showRecommendedAction ? detection.recommendedAction ? <ActionBadge action={detection.recommendedAction} /> : <small>권장 조치 당시 미기록</small> : null}</div>
    <h4>{detection.detector === 'SIGNATURE' ? `${signatureLabel(detection.entityCounts?.map(item => item.entityType) ?? [])} 일치` : labels[detection.matchType]}</h4>
    <dl>
      <div><dt>탐지 방식</dt><dd><DetectorBadge detector={detection.detector} /></dd></div>
      <div><dt>탐지 점수</dt><dd>{scoreLabel(detection)}</dd>{detection.detector === 'WINDOW_HASH' && <small className="score-explanation">Detection이 30자 창 해시로 이 문서에서만 나온 곳을 센 비율(긴 입력은 표본)입니다. 입력이 문서와 얼마나 같은지는 '{SAME_RATIO_NAME}'({sameTextLabel(detection).value ?? '확인 불가'})로 봅니다.</small>}</div>
      {'matchedDocumentId' in detection && <div className="finding-wide"><dt>일치한 보호 문서</dt><dd><Link className="matched-document-link" to={`/documents/${encodeURIComponent(detection.matchedDocumentId)}`}>{detection.matchedDocumentName ?? detection.matchedDocumentId}</Link>{detection.matchedDocumentName && <small className="matched-document-id">{detection.matchedDocumentId}</small>}</dd></div>}
      {detection.detector === 'MINHASH' && <><div><dt>외부 전송 문서</dt><dd>{detection.outboundDocumentName}</dd></div><div><dt>탐지 기준값</dt><dd>{percent(detection.threshold)}</dd></div></>}
      {detection.detector === 'WINDOW_HASH' && <><div><dt>입력 탐지 구간</dt><dd>{detection.inputSpan ? `${detection.inputSpan.charStart}-${detection.inputSpan.charEnd} · 끝 좌표 미포함` : '당시 미기록'}</dd></div><div><dt>문서 탐지 구간</dt><dd>{`${detection.documentSpan.charStart}-${detection.documentSpan.charEnd} · 끝 좌표 미포함`}</dd></div>{detection.threshold!==undefined&&<div><dt>당시 탐지 기준값</dt><dd>{percent(detection.threshold)}</dd></div>}</>}
      {detection.detector === 'SIGNATURE' && <>{detection.ruleId&&<div><dt>규칙 ID</dt><dd className="mono">{detection.ruleId}</dd></div>}{detection.policyId&&<div><dt>기록된 정책 ID</dt><dd className="mono"><Link to={`/policies?policyId=${encodeURIComponent(detection.policyId)}`} title="현재 정책과 버전 이력 확인 · 당시 적용 내용은 사건 기록 기준">{detection.policyId}</Link></dd></div>}{detection.category&&<div><dt>탐지 분류</dt><dd>{detection.category}</dd></div>}{detection.entityCounts?.length ? <div><dt>탐지한 유형·개수</dt><dd>{detection.entityCounts.map((item) => `${uiLabel(item.entityType)} ${formatCount(item.count)}개`).join(' · ')}</dd></div> : null}</>}
    </dl>
  </article>;
}

export function EventDetailPage() {
  const { eventId = '' } = useParams();
  return <EventDetailContent key={eventId} eventId={eventId} />;
}

function EventDetailContent({ eventId }: { eventId: string }) {
  const queryClient = useQueryClient();
  const { aliases } = useClientAliases();   // 확장 프로그램 ID 별칭(서버가 모르면 빈 목록)
  const [assignee, setAssignee] = useState('');
  const [note, setNote] = useState('');
  const [refreshingEvidence,setRefreshingEvidence]=useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const view = searchParams.get('view');
  const setPresentation = (enabled: boolean) => {
    const next = new URLSearchParams(searchParams);
    next.set('view', enabled ? 'compare' : 'operations');
    setSearchParams(next, { replace: true, state: location.state });
  };
  const query = useQuery({ ...liveQueryOptions, queryKey: eventKeys.detail(eventId), queryFn: ({ signal }) => eventService.getEventById(eventId, signal) });
  const refreshReview = async () => {
    setRefreshingEvidence(true);
    try {
      await Promise.all([
        query.refetch(),
        queryClient.invalidateQueries({queryKey:['event-evidence',eventId]}),
        queryClient.invalidateQueries({queryKey:['evidence-page',eventId]}),
      ]);
    } finally { setRefreshingEvidence(false); }
  };
  const refresh = async () => Promise.all([
    queryClient.invalidateQueries({ queryKey: eventKeys.all }),
    queryClient.invalidateQueries({ queryKey: auditKeys.all }),
    queryClient.invalidateQueries({ queryKey: dashboardKeys.all }),
    queryClient.invalidateQueries({ queryKey: trafficKeys.all }),
  ]);
  const statusMutation = useMutation({ mutationFn: (status: IncidentStatus) => eventService.updateStatus(eventId, status), onSuccess: async () => { await refresh(); notifySuccess('상태를 변경했습니다.'); }, onError: notifyError });
  const assignMutation = useMutation({ mutationFn: () => eventService.assign(eventId, assignee.trim()), onSuccess: async () => { setAssignee(''); await refresh(); notifySuccess('담당자를 지정했습니다.'); }, onError: notifyError });
  const noteMutation = useMutation({ mutationFn: () => eventService.addNote(eventId, note.trim()), onSuccess: async () => { setNote(''); await refresh(); notifySuccess('메모를 추가했습니다.'); }, onError: notifyError });
  const saving = statusMutation.isPending || assignMutation.isPending || noteMutation.isPending;
  const readOnly = saving || query.isError;
  if (query.isLoading) return <div className="event-detail-console" data-ui="legacy"><LoadingSkeleton /></div>;
  const backLink = <Link className="back-link" to={eventListReturnPath(location.state)}><ArrowLeft /> 보안 이벤트로 돌아가기</Link>;
  const notFound = <div className="event-detail-console" data-ui="legacy"><div className="event-detail-toolbar">{backLink}</div><EmptyState title="이벤트를 찾을 수 없습니다." description="삭제됐거나 주소가 잘못됐습니다." /></div>;
  if (query.isError && (!query.data || !canRetainQueryData(query.error))) return query.error instanceof ApiError && query.error.status === 404 ? notFound
    : <div className="event-detail-console" data-ui="legacy"><div className="event-detail-toolbar">{backLink}</div><ErrorState message="이벤트를 불러오지 못했습니다." error={query.error} onRetry={() => query.refetch()} /></div>;
  const event = query.data;
  if (!event) return notFound;
  const presentation = view === 'compare' || (view !== 'operations' && (event.detectionOutcome === 'MATCH' || event.finalAction === 'MASK'));
  const failure = inspectionFailure(event);
  return <div className="event-detail-console" data-ui="legacy">
    <div className="event-detail-toolbar">{backLink}<div className="event-detail-actions"><ReviewLinkCopy key={event.eventId} eventId={event.eventId}/><Button variant="outline" aria-pressed={presentation} onClick={() => setPresentation(!presentation)}>{presentation ? '운영 화면으로' : '비교 집중 화면'}</Button><AutoRefreshBar compact updatedAt={query.dataUpdatedAt} fetching={query.isFetching||refreshingEvidence} failed={query.isError} onRefresh={refreshReview} /></div></div>
    {query.isError && <p role="status" className="console-stale-notice">갱신 실패 · 아래는 마지막 성공 조회 결과입니다.</p>}
    <div className={presentation ? 'event-investigation presentation-focused' : 'event-investigation'}>
    <InvestigationSummary event={event} />
    <section className="event-hero hero-unknown console-event-header investigation-identifiers"><div><p className="console-event-id">{event.eventId}</p><h2 className="sr-only">{eventTitle(event.detections, event.detectionOutcome)}</h2><p><time dateTime={event.occurredAt}>{formatDateTime(event.occurredAt)}</time></p></div><div className="event-hero-badges"><IncidentStatusBadge status={event.status} /></div></section>
    <dl className="console-request-summary" aria-label="요청 정보">
      <div><dt>클라이언트 ID</dt><dd className="mono" title={event.clientId}>{aliases.get(event.clientId) ? <ClientIdentity clientId={event.clientId} alias={aliases.get(event.clientId)} /> : event.clientId}</dd></div>
      <EventAccessControl clientId={event.clientId} aliases={aliases} />
      {event.accessRuleId && <div><dt>차단 번호</dt><dd className="mono" title="차단된 사용자에게 보인 번호(규칙 번호 앞 8자)">{blockNumber(event.accessRuleId)}</dd></div>}
      {event.userId && <div><dt>사용자 ID</dt><dd className="mono" title={event.userId}>{event.userId}</dd></div>}
      <div><dt>대상 LLM</dt><dd>{event.targetLlm}</dd></div>
      {event.contentType && <div><dt>입력 유형</dt><dd>{uiLabel(event.contentType)}</dd></div>}
      {event.attachedFiles?.length ? <div><dt>첨부 파일</dt><dd className="dops-attach-links">{event.attachedFiles.map(file =>
        <Link key={file.eventId} to={`/events/${encodeURIComponent(file.eventId)}?view=compare`}>{formatDateTime(file.occurredAt)} · {attachedActionText[file.finalAction]}</Link>)}</dd></div> : null}
      {event.attachedTo?.length ? <div><dt>이 파일이 첨부된 프롬프트</dt><dd className="dops-attach-links">{event.attachedTo.map(prompt =>
        <Link key={prompt.eventId} to={`/events/${encodeURIComponent(prompt.eventId)}?view=compare`}>{formatDateTime(prompt.occurredAt)} · {attachedActionText[prompt.finalAction]}</Link>)}</dd></div> : null}
      {event.processingMs !== undefined && <div><dt>{GATEWAY_PROCESSING_LABEL}</dt><dd title={GATEWAY_PROCESSING_SCOPE}>{formatProcessingTime(event.processingMs)}</dd></div>}
    </dl>
    {failure && <p className="partial-data-warning" role="status"><strong>{failure.action} · {failure.detail}</strong><br />{'accessBlock' in failure ? '관리자 설정에 따라 접속 단계에서 차단했습니다. 내용은 검사하지 않았습니다.' : '탐지 결과를 확인할 수 없습니다. 최종 조치가 허용이어도 안전하다고 확인된 요청은 아닙니다.'}</p>}
    <EventEvidencePanel eventId={event.eventId} enforcement={event.enforcement} expanded={presentation} finalAction={event.finalAction} />
    {event.attachedFiles?.filter(file => file.finalAction !== 'ALLOW').map(file => <div key={file.eventId} className="dops-attached-evidence">
      <p className="dops-attached-heading">첨부 파일 · {formatDateTime(file.occurredAt)} · {attachedActionText[file.finalAction]}</p>
      <EventEvidencePanel eventId={file.eventId} enforcement={file.enforcement} finalAction={file.finalAction} />
    </div>)}
    </div>
    <details className="event-detail-disclosure technical-disclosure"><summary>탐지 기술 · 요청 상세 · 기록 누락 확인</summary>
    <section className="panel evidence-panel">
      <div className="panel-heading"><div><p className="eyebrow">탐지·요청 정보</p><h3>탐지 결과와 요청 정보</h3></div><span>원문 전체는 표시하지 않습니다.</span></div>
      <div className="findings-layout">
        <div className="findings-list">{event.detections.length ? event.detections.map((detection, index) => <DetectionFinding key={`${detection.detector}-${index}`} detection={detection} index={index} />) : <p className="empty-copy">{event.detectionOutcome === 'NO_MATCH' ? '일치한 보호 문서나 민감정보가 없습니다.' : '탐지 상세 정보가 제공되지 않았습니다.'}</p>}</div>
        <dl className="detail-grid compact-detail-grid">
          <div className="metadata-wide"><dt>요청 ID</dt><dd className="mono">{event.requestId ?? '—'}</dd></div>
          <div className="metadata-endpoint"><dt>요청 경로</dt><dd>{displayRequestPath(event.host, event.endpoint)}</dd>{/[?#]/.test(event.endpoint ?? '') && <small>세션·인증정보 보호를 위해 URL 매개변수는 표시하지 않습니다.</small>}</div>
          {event.reasonCode&&<div><dt>판정 사유 코드</dt><dd title={hasReasonLabel(event.reasonCode)?event.reasonCode:undefined}>{reasonLabel(event.reasonCode)}</dd></div>}
          {uiMode.showRecommendedAction && event.recommendedAction && <div><dt>탐지 권고 조치</dt><dd>{uiLabel(event.recommendedAction)}</dd></div>}
          {event.policyVersion&&<div><dt>당시 정책 버전</dt><dd>{event.policyVersion}</dd></div>}
          {failure && !('accessBlock' in failure) && <div><dt>검사 장애 원인</dt><dd>{failure.detail}</dd></div>}
          {uiMode.showFailurePolicy && <div><dt>장애 처리 정책</dt><dd>{uiLabel(event.failurePolicy)}</dd></div>}
        </dl>
      </div>
    </section>
    <details className="missing-evidence-fields"><summary>기록되지 않은 정보 확인</summary><p>{[!event.reasonCode&&'판정 사유 코드',!event.policyVersion&&'당시 정책 버전',!event.enforcement&&'집행 확인값',event.detections.some(d=>d.detector==='WINDOW_HASH'&&d.threshold===undefined)&&'당시 탐지 기준값',event.detections.some(d=>d.detector==='SIGNATURE'&&!d.ruleId)&&'규칙 ID'].filter(Boolean).join(' · ')||'표시 대상 정보가 기록되어 있습니다.'}</p><small>없는 값은 추정하지 않습니다. 현재 정책을 과거 이벤트의 정책으로 표시하지 않습니다.</small></details>
    </details>
    <details className="event-detail-disclosure admin-disclosure"><summary>관리자 조사 · 담당자 · 메모 · 처리 이력</summary>
    {query.isError && <p className="workflow-empty" role="status">최신 상태를 불러오면 담당자·상태·메모 변경을 다시 사용할 수 있습니다. 작성 중인 내용은 유지됩니다.</p>}
    <section className="incident-grid" aria-busy={saving}>
      <article className="panel incident-controls">
        <div className="panel-heading"><h3>조사 상태 · 담당자</h3></div>
        <div className="incident-form">
          <label htmlFor="incident-status">상태</label>
          <select id="incident-status" disabled={readOnly} value={event.status} onChange={(change) => statusMutation.mutate(change.target.value as IncidentStatus)}>
            <option value="NEW">신규 (NEW)</option><option value="INVESTIGATING">조사 중 (INVESTIGATING)</option><option value="RESOLVED">처리 완료 (RESOLVED)</option>
          </select>
          {statusMutation.isError && <p className="workflow-error" role="alert">상태 변경 실패 · {safeMessage(statusMutation.error)}</p>}
          <form onSubmit={(submit: SyntheticEvent) => { submit.preventDefault(); if (!readOnly && assignee.trim() && assignee.length <= 200) assignMutation.mutate(); }}>
            <label htmlFor="incident-assignee">담당자</label>
            <div className="incident-input-row">
              <Input id="incident-assignee" maxLength={200} disabled={readOnly} placeholder="담당자 이름 또는 ID" value={assignee} onChange={(change) => { setAssignee(change.target.value); assignMutation.reset(); }} />
              <Button type="submit" disabled={!assignee.trim() || assignee.length > 200 || readOnly}>{assignMutation.isPending ? '저장 중…' : '지정'}</Button>
            </div>
            {assignMutation.isError && <p className="workflow-error" role="alert">담당자 지정 실패 · {safeMessage(assignMutation.error)}</p>}
          </form>
          <p>현재 담당자: {event.assignee || '미지정'}</p>
        </div>
      </article>
      <article className="panel incident-notes">
        <div className="panel-heading"><div className="incident-note-heading"><MessageSquarePlus /><h3>관리자 메모</h3></div></div>
        <form onSubmit={(submit: SyntheticEvent) => { submit.preventDefault(); if (!readOnly && note.trim() && note.length <= 2000) noteMutation.mutate(); }}>
          <label htmlFor="incident-note">메모</label>
          <textarea id="incident-note" maxLength={2000} disabled={readOnly} placeholder="확인 내용이나 조치 사항을 입력하세요." value={note} onChange={(change) => { setNote(change.target.value); noteMutation.reset(); }} />
          <small className="note-character-count">{note.length.toLocaleString()} / 2,000자</small>
          <Button type="submit" disabled={!note.trim() || note.length > 2000 || readOnly}>{noteMutation.isPending ? '저장 중…' : '메모 추가'}</Button>
          {noteMutation.isError && <p className="workflow-error" role="alert">메모 저장 실패 · {safeMessage(noteMutation.error)} 입력 내용은 유지됩니다.</p>}
        </form>
        <div className="note-list">{event.adminNotes.length ? event.adminNotes.map((item) => <article key={item.noteId}><p>{item.content}</p><small>{item.author} · {formatDateTime(item.createdAt)}</small></article>) : <p className="workflow-empty">아직 작성된 관리자 메모가 없습니다.</p>}</div>
      </article>
    </section>
    <section className="panel timeline-panel"><div className="panel-heading"><h3>처리 이력</h3></div><ol>{event.timeline.length?event.timeline.map((item) => <li key={item.timelineId}><i /><div><strong>{item.summary}</strong><span>{item.actor} · {formatDateTime(item.occurredAt)}</span></div></li>):<li><i/><div><strong>이벤트 발생</strong><span>기록된 발생 시각 · {formatDateTime(event.occurredAt)}</span></div></li>}</ol>{!event.timeline.some(item=>item.type!=='DETECTED')&&<p className="workflow-empty timeline-empty">아직 담당자 지정·상태 변경·메모 추가 이력이 없습니다.</p>}</section>
    </details>
  </div>;
}
