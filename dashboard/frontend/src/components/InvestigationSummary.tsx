import { Link } from 'react-router-dom';
import type { SecurityEvent } from '@/src/types/event';
import { eventStory } from '@/src/utils/eventStory';
import { signatureLabel } from '@/src/utils/entityCategory';
import { inspectionFailure } from '@/src/utils/eventPresentation';
import { uiLabel } from '@/src/utils/labels';
import { formatCount } from '@/src/utils/format';

/** Visual lead only: a recorded decision is not proof of delivery or execution. */
export function InvestigationSummary({ event }: { event: SecurityEvent }) {
  const failure = inspectionFailure(event);
  const story = eventStory(event);
  const detectors = [...new Set(event.detections.map(item => item.detector))];
  const policies = [...new Set(event.detections.flatMap(item => item.detector === 'SIGNATURE' && item.policyId ? [item.policyId] : []))];
  const entities = event.detections.flatMap(item => item.detector === 'SIGNATURE' ? item.entityCounts?.map(entity => `${uiLabel(entity.entityType)} ${formatCount(entity.count)}개`) ?? [] : []);
  const accessBlock = Boolean(failure && 'accessBlock' in failure);
  const title = accessBlock ? '접속 차단' : failure ? '입력 검사 결과 확인 불가' : event.detections.length > 1 ? `${formatCount(event.detections.length)}개 탐지 근거 확인`
    : detectors.includes('WINDOW_HASH') ? '보호 문서 구간 일치'
    : detectors.includes('SHA256') ? '동일 보호 문서 탐지'
    : detectors.includes('MINHASH') ? '보호 문서 유사성 탐지'
    : detectors.includes('SIGNATURE') ? `${signatureLabel(event.detections.flatMap(item => item.detector === 'SIGNATURE' ? item.entityCounts?.map(entity => entity.entityType) ?? [] : []))} 탐지`
    : event.detectionOutcome === 'NO_MATCH' ? '일치한 문서·민감정보 없음' : '탐지 상세 근거 미기록';
  const reason = accessBlock ? '관리자 설정에 따라 접속 단계에서 차단했습니다. 내용은 검사하지 않았습니다.'
    : failure ? '검사 결과를 확인할 수 없어 안전 여부를 판단할 수 없습니다.'
    : entities.length && !story.documents.length ? `${entities.join(' · ')}가 탐지된 요청입니다.`
    : detectors.includes('WINDOW_HASH') ? '등록된 보호 문서와의 구간 일치가 탐지됐습니다.'
    : story.reason;
  const execution = event.enforcement === undefined ? '집행 확인 기록 없음'
    : !event.enforcement.applied ? event.finalAction === 'ALLOW' ? '추가 차단·치환 없음' : '미집행 기록'
    : event.finalAction === 'BLOCK' ? '전송 차단 집행 확인'
    : event.finalAction === 'MASK' ? '마스킹 집행 확인' : '집행 확인 기록 있음';
  return <section className="event-brief investigation-summary" aria-label="사건 핵심 요약" data-inspection={failure ? 'unavailable' : 'recorded'} data-action={event.finalAction.toLowerCase()} data-enforcement={event.enforcement?.applied === undefined ? 'unknown' : event.enforcement.applied ? 'confirmed' : 'not-applied'}>
    <div className="investigation-result"><span>최종 결정</span><strong>{uiLabel(event.finalAction)}</strong></div>
    <div className="investigation-lead"><h2>{title}</h2><p>{reason}</p>
      <div className="investigation-proof"><strong>{execution}</strong>{event.enforcement?.httpStatus !== undefined && <small>기록된 HTTP {event.enforcement.httpStatus}</small>}{failure && <small className="inspection-failure">{failure.action}</small>}</div>
      <dl className="investigation-context">
        {story.documents.length > 0 && <div className="investigation-document"><dt>연결 문서</dt><dd>{story.documents.map(([id, name]) => <Link key={id} to={`/documents/${encodeURIComponent(id)}`} title={name}>{name}</Link>)}</dd></div>}
        {detectors.length > 0 && <div><dt>탐지 방식</dt><dd>{detectors.map(detector => uiLabel(detector)).join(' · ')}</dd></div>}
        <div><dt>대상</dt><dd>{event.targetLlm}</dd></div>
        {policies.length > 0 && <div className="investigation-policy"><dt>기록 정책</dt><dd>{policies.map(id => <Link key={id} className="mono" to={`/policies?policyId=${encodeURIComponent(id)}`} title="사건에 기록된 정책 ID · 현재 정책과 버전 이력 보기">{id}</Link>)}</dd></div>}
        {event.policyVersion && <div><dt>당시 정책 버전</dt><dd>{event.policyVersion}</dd></div>}
      </dl>
    </div>
  </section>;
}
