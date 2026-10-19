import type { TrafficSummary } from '@/src/types/traffic';
import { formatProcessingTime } from './format';
import { formatCount } from '@/src/utils/format';

/** Include the date at midnight boundaries; labels never imply a continuous day. */
export function trafficTimeLabels(timestamps: string[], period: string) {
  const valid = timestamps.map(value => new Date(value));
  const days = new Set(valid.filter(date => Number.isFinite(date.getTime())).map(date => date.toLocaleDateString('en-CA', { timeZone: 'Asia/Seoul' })));
  const showDate = period !== '24H' || days.size > 1;
  return valid.map(date => Number.isFinite(date.getTime()) ? date.toLocaleString('ko-KR', {
    ...(showDate ? { month: '2-digit', day: '2-digit' } as const : {}),
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'Asia/Seoul',
  }) : '시각 미기록');
}

/** processingMs(2026-10-11 Gateway부터): 요청 수신부터 LLM 전달 또는 Gateway 차단·오류 응답까지. LLM 응답 시간은 넣지 않는다.
 * 그 전 기록(LLM 응답까지)은 백엔드가 processing_ms를 빼고 보낸다(server/processing-time.mjs). */
export const GATEWAY_PROCESSING_LABEL = 'Gateway 처리 시간';
export const GATEWAY_PROCESSING_SCOPE = '요청 수신부터 LLM 전달·차단까지 · LLM 응답 시간 제외';
export const GATEWAY_PROCESSING_HISTORY = 'LLM 응답 시간이 포함된 이전 기록은 처리 시간에서 제외합니다.';
/** 실시간 평균·P95를 백엔드가 뺀 경우(latency_unavailable_reason=LEGACY_GATEWAY)의 설명 */
export const GATEWAY_PROCESSING_UNCONFIRMED = '이전 판 Gateway(또는 첫 응답 전, 최대 10초) · LLM 응답 시간이 섞일 수 있어 표시하지 않음';

export function formatLatency(input?: number) {
  return formatProcessingTime(input);
}

/** 연결 오류 칸 글(2026-10-15 감사 4번): 새 Gateway는 브라우저가 끊은 요청을 빼고 보내므로 'Gateway 오류', 옛 Gateway 값은 브라우저 취소까지 든 '연결 끊김' */
export function gatewayErrorText(summary: TrafficSummary) {
  const count = summary.gatewayErrorRequests === undefined ? '확인 불가' : `${summary.gatewayErrorRequests.toLocaleString('ko-KR')}건`;
  if (summary.gatewayErrorBasis === 'GATEWAY_ERRORS')
    return `Gateway 오류 ${count}(브라우저 취소 제외)${summary.gatewayClientCancelledRequests !== undefined ? ` · 브라우저 취소 ${summary.gatewayClientCancelledRequests.toLocaleString('ko-KR')}건` : ''}`;
  return `연결 끊김 ${count}(브라우저 취소 포함)`;
}

/** Gateway 상태 판정은 서버(liveGatewayState) 한 곳 — 시스템 상태·보안 현황과 같은 규칙. 화면은 그 근거를 적기만 한다 */
export function gatewayHealthExplanation(summary: TrafficSummary) {
  if (summary.metricSource !== 'GATEWAY_LIVE') return {label:'확인 불가', detail:'과거 이벤트로 현재 상태를 추정하지 않습니다.'};
  if (summary.gatewayStatus === 'DEGRADED') {
    const reasons: string[] = [];
    if (summary.gatewayStatusReason) reasons.push(summary.gatewayStatusReason);
    else {
      if (summary.gatewayErrorBasis !== 'ALL_DISCONNECTS' && summary.gatewayErrorRequests !== undefined && summary.gatewayErrorRequests > 0) reasons.push(`Gateway 오류 ${summary.gatewayErrorRequests.toLocaleString('ko-KR')}건`);
      if (summary.degradedRate !== undefined && summary.degradedRate > 0) reasons.push('보안 검사 응답 없음 기록');
    }
    return {label:reasons.length ? '오류 기록 있음' : '상태 확인 필요', detail:reasons.length ? `프로세스 집계에 ${reasons.join(' · ')}이 포함돼 있습니다. 누적 기록이므로 지금도 장애가 지속된다는 뜻은 아닙니다. 개별 오류 원인은 이 집계만으로 확인할 수 없습니다.` : '서버가 기능 저하 상태를 보고했지만 판정 근거는 제공되지 않았습니다. 원인을 정상으로 간주하거나 추측하지 않습니다.'};
  }
  if (summary.gatewayCompletedRequests === 0) return {label:'요청 대기', detail:'지표 연결 정상 · 완료 요청이 없어 처리 상태는 아직 측정되지 않았습니다.'};
  if (summary.gatewayStatus === 'HEALTHY') return {label:'정상', detail:'수신한 집계의 오류·보안 검사 장애 기준입니다. 모든 요청의 성공을 보장하는 표시는 아닙니다.'};
  return {label:'확인 불가', detail:'지표는 수신했지만 서버 상태 판정은 제공되지 않았습니다.'};
}

export function formatTrafficRate(input?: number) {
  if (input === undefined || !Number.isFinite(input) || input < 0 || input > 1) return '미제공';
  if (input > 0 && input < 0.001) return '0.1% 미만';
  if (input < 1 && input > 0.999) return '99.9% 초과';
  return `${(input * 100).toFixed(1)}%`;
}

export function trafficSourceLabel(summary: TrafficSummary) {
  return summary.metricSource === 'GATEWAY_LIVE' ? 'Gateway 실시간 집계' : summary.metricSource === 'STORED_EVENTS' ? '저장 이벤트 집계' : '지표 출처 미확인';
}

export function trafficSourceDescription(summary: TrafficSummary) {
  if (summary.metricSource === 'GATEWAY_LIVE') return '최근 30초 이내 수신된 대상 LLM HTTP 요청 집계입니다. 화면 로딩 등 부가 요청도 포함하며, 질문 수·사용자 수와 같지 않습니다. 추이·분포·최근 내역은 선택 기간 저장 보안 이벤트 기준입니다.';
  if (summary.metricSource === 'STORED_EVENTS') return `${summary.gatewayMetricsStatus === 'STALE' ? '실시간 지표 수신이 30초 이상 지연됐습니다.' : '최근 실시간 지표가 수신되지 않았습니다.'} 선택 기간 저장 이벤트 ${summary.eventCount === undefined ? '건수 미제공' : formatCount(summary.eventCount) + '건'}${summary.accessBlocked !== undefined ? `(접속 차단 ${formatCount(summary.accessBlocked)}건 제외)` : ''}을 집계합니다. 동시 요청·현재 서버 상태는 확인 불가이며, 전체 HTTP 트래픽 통계가 아닙니다.`;
  return '서버가 집계 출처를 제공하지 않았습니다. 이 값을 실시간 지표로 단정하지 않습니다.';
}
