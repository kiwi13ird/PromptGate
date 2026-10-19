import { Fragment, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ActionBadge, IncidentStatusBadge, LlmBadge } from './common';
import type { AttachedEvent, Detection, SecurityEvent } from '@/src/types/event';
import { formatDateTime, formatCount } from '@/src/utils/format';
import { storyPercent } from '@/src/utils/eventStory';
import { sameTextLabel } from '@/src/utils/sameTextLabel';
import { signatureLabel } from '@/src/utils/entityCategory';
import { uiLabel } from '@/src/utils/labels';
import { uiMode } from '@runtime/ui-mode';
import { inspectionFailure, missingDetectionTitle } from '@/src/utils/eventPresentation';
import { EventEvidencePanel } from './EventEvidencePanel';
import { ClientIdentity } from './ClientAlias';
import '@/src/detection-ops.css';

// 질문 + 첨부 파일 묶음(2026-10-09): 조치는 묶음에서 가장 강한 것, 탐지는 질문·파일 모두
const groupAction = (event: SecurityEvent) => event.groupFinalAction ?? event.finalAction;
const withAttachments = (event: SecurityEvent): SecurityEvent => event.attachedFiles?.length ? {
  ...event,
  detections: [...event.detections, ...event.attachedFiles.flatMap(file => file.detections)],
  detectionOutcome: event.detectionOutcome === 'MATCH' || event.attachedFiles.some(file => file.detectionOutcome === 'MATCH') ? 'MATCH' : event.detectionOutcome,
} : event;
const actionText: Record<SecurityEvent['finalAction'], string> = { ALLOW: '허용', MASK: '마스킹', BLOCK: '차단' };
const matched = (item: SecurityEvent | AttachedEvent) => (item.finalAction === 'BLOCK' || item.finalAction === 'MASK') && item.detectionOutcome === 'MATCH';

// 원문 보기: 차단·마스킹으로 판정된(탐지 일치) 행만. 상세 화면과 같은 비교를 행 아래에 펼친다
const hasEvidence = (event: SecurityEvent) => matched(event) || !!event.attachedFiles?.some(matched);

const matchLabels: Record<Detection['matchType'], string> = {
  EXACT_DOCUMENT: '문서 전체 일치', SIMILAR_DOCUMENT: '유사 문서',
  TEXT_FRAGMENT: '문서 구간 일치', SIGNATURE_RULE: '민감정보 패턴',
};

function MatchSummary({ event }: { event: SecurityEvent }) {
  if (!event.detections.length) return <span className="match-summary"><strong>{missingDetectionTitle(event.detectionOutcome, event.reasonCode)}</strong></span>;
  if (event.detections.length > 1) return <span className="match-summary"><strong>{formatCount(event.detections.length)}건 탐지</strong><small>상세에서 각각의 근거 확인</small></span>;
  const detection = event.detections[0];
  const score = detection.detector === 'SIGNATURE'
    ? detection.confidence === undefined
      ? detection.entityCounts?.map(item => `${uiLabel(item.entityType)} ${formatCount(item.count)}개`).join(' · ') || '민감정보 패턴 일치'
      : `${storyPercent(detection.confidence)} 신뢰도`
    : detection.detector === 'WINDOW_HASH' ? sameTextLabel(detection).text   // 2026-10-16 '일치 비율' 통일: 상세 대조와 같은 값
    : detection.detector === 'MINHASH' ? `${storyPercent(detection.similarity)} 문서 유사도` : '동일 문서 판정';
  const label = detection.detector === 'SIGNATURE' ? signatureLabel(detection.entityCounts?.map(item => item.entityType) ?? []) : matchLabels[detection.matchType];
  return <span className="match-summary"><strong>{label}</strong><small title={detection.detector === 'WINDOW_HASH' ? sameTextLabel(detection).title : undefined}>{score}</small></span>;
}

function MatchedDocuments({ event }: { event: SecurityEvent }) {
  const documents = [...new Map(event.detections.flatMap(item => 'matchedDocumentId' in item
    ? [[item.matchedDocumentId, item.matchedDocumentName ?? item.matchedDocumentId] as const] : [])).entries()];
  if (!documents.length) return <span className="table-document-empty">{event.detections.some(item => item.detector === 'SIGNATURE') ? '문서 비교 대상 아님' : event.detectionOutcome === 'NO_MATCH' ? '일치 문서 없음' : '연결 문서 없음'}</span>;
  return <div className="table-matched-documents">{documents.map(([id, name]) => <Link key={id} to={`/documents/${encodeURIComponent(id)}`} title={name}
    onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>{name}</Link>)}</div>;
}

// aliases: 확장 프로그램 ID별 별칭(2026-10-12). 있으면 클라이언트 ID 옆에 별칭을 먼저 보인다
export function EventsTable({ events, evidenceToggle = false, aliases }: { events: SecurityEvent[]; evidenceToggle?: boolean; aliases?: ReadonlyMap<string, string> }) {
  const navigate = useNavigate();
  const location = useLocation();
  const returnState = location.pathname === '/events' ? { eventListReturn: location.pathname + location.search } : undefined;
  const [operational, setOperational] = useState(false);
  const [openEvidence, setOpenEvidence] = useState<ReadonlySet<string>>(new Set());
  const toggleEvidence = (eventId: string) => setOpenEvidence(current => {
    const next = new Set(current);
    if (next.has(eventId)) next.delete(eventId); else next.add(eventId);
    return next;
  });
  return <div className="events-table-view console-events-table">
    <div className="event-table-controls"><span>행 또는 이벤트 ID를 선택하면 탐지 근거를 확인합니다.</span><button type="button" aria-pressed={operational} onClick={() => setOperational(!operational)}>{operational ? '핵심 정보만 보기' : '운영 정보 보기'}</button></div>
    <div className="table-scroll events-table-scroll"><Table><TableHeader><TableRow>
      <TableHead>발생 시각 · 이벤트 ID</TableHead><TableHead>대상 LLM</TableHead><TableHead>일치한 보호 문서</TableHead><TableHead>탐지 결과 · 비율</TableHead><TableHead>최종 조치</TableHead>
    </TableRow></TableHeader><TableBody>{events.map(event => {
      const destination = `/events/${encodeURIComponent(event.eventId)}?view=compare`;
      const failure = inspectionFailure(event);
      const evidenceOpen = evidenceToggle && openEvidence.has(event.eventId);
      const shown = withAttachments(event);
      const files = event.attachedFiles ?? [];
      return <Fragment key={event.eventId}><TableRow className="clickable-row" data-action={groupAction(event).toLowerCase()} tabIndex={0} aria-label={`${event.eventId} 상세 보기`}
        onClick={() => void navigate(destination, { state: returnState })} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); void navigate(destination, { state: returnState }); } }}>
        <TableCell><time dateTime={event.occurredAt}>{formatDateTime(event.occurredAt)}</time><Link className="event-detail-link" title={event.eventId} aria-label={`${event.eventId} 상세 보기`} to={destination} state={returnState} onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>{event.eventId}</Link></TableCell><TableCell><LlmBadge llm={event.targetLlm} /></TableCell>
        <TableCell><MatchedDocuments event={shown} /></TableCell><TableCell><MatchSummary event={shown} /></TableCell>
        <TableCell><div className="dops-action-cell">{failure && !files.length ? <span className="inspection-failure" title={failure.detail}>{failure.action}</span> : <ActionBadge action={groupAction(event)} />}
          {files.length > 0 && <span className="dops-attach-tag" title="같은 프롬프트에 첨부된 파일을 함께 표시합니다">프롬프트 + 파일 {files.length}</span>}
          {evidenceToggle && hasEvidence(event) && <button type="button" className="dops-evidence-toggle" aria-expanded={evidenceOpen} aria-label={`${event.eventId} ${evidenceOpen ? '원문 닫기' : '원문 보기'}`}
            onClick={e => { e.stopPropagation(); toggleEvidence(event.eventId); }} onKeyDown={e => e.stopPropagation()}>{evidenceOpen ? '원문 닫기' : '원문 보기'}</button>}</div></TableCell>
      </TableRow>{evidenceOpen && <TableRow className="dops-evidence-row"><TableCell colSpan={5}>
        {(!files.length || matched(event)) && <EventEvidencePanel eventId={event.eventId} enforcement={event.enforcement} finalAction={event.finalAction} />}
        {files.filter(matched).map(file => <div key={file.eventId} className="dops-attached-evidence">
          <p className="dops-attached-heading">첨부 파일 · <time dateTime={file.occurredAt}>{formatDateTime(file.occurredAt)}</time> · {actionText[file.finalAction]}
            <Link to={`/events/${encodeURIComponent(file.eventId)}?view=compare`} state={returnState} onClick={e => e.stopPropagation()}>파일 이벤트 보기</Link></p>
          <EventEvidencePanel eventId={file.eventId} enforcement={file.enforcement} finalAction={file.finalAction} />
        </div>)}
      </TableCell></TableRow>}{operational && <TableRow className="console-operational-row"><TableCell colSpan={5}><dl>
        <div className="ops-client"><dt>클라이언트 ID</dt><dd className="mono" title={event.clientId}>{aliases?.get(event.clientId) ? <ClientIdentity clientId={event.clientId} alias={aliases.get(event.clientId)} /> : event.clientId}</dd></div>
        {event.requestId && <div className="ops-request"><dt>요청 ID</dt><dd className="mono" title={event.requestId}>{event.requestId}</dd></div>}
        <div className="ops-detector"><dt>탐지 방식</dt><dd>{[...new Set(event.detections.map(item => item.detector))].map(detector => uiLabel(detector)).join(' · ') || '—'}</dd></div>
        <div className="ops-status"><dt>조사 상태</dt><dd><IncidentStatusBadge status={event.status} /></dd></div>
        {uiMode.showRecommendedAction && <div className="ops-recommended"><dt>권장 조치</dt><dd>{event.recommendedAction ? <ActionBadge action={event.recommendedAction} /> : '—'}</dd></div>}
      </dl></TableCell></TableRow>}</Fragment>;
    })}</TableBody></Table></div>
  </div>;
}
