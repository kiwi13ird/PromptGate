import type { SecurityEvent } from '@/src/types/event';
import { uiLabel } from './labels';
import { hasReasonLabel, isAccessBlockReason, isUninspectedReason, reasonLabel } from './reasonLabels';

export function inspectionFailure(event: SecurityEvent) {
  if (!event.degraded && event.detectionOutcome !== 'UNAVAILABLE') return undefined;
  const action = event.finalAction === 'ALLOW' ? '검사 불가 · 허용' : event.finalAction === 'BLOCK' ? '검사 불가 · 차단' : '검사 불가 · 마스킹 결정';
  // 검사할 수 없는 파일·상한 초과(2026-10-10): 장애가 아니라 Gateway가 검사하지 않은 것 - 장애 정책 대신 사유 이름표
  const code = event.reasonCode;
  if (!event.degraded && code && isUninspectedReason(code)) return { action, detail: reasonLabel(code) };
  // 접속 차단(2026-10-12): 검사 장애가 아니라 접속 단계에서 막은 것 - 검사하지 않았다
  if (!event.degraded && code && isAccessBlockReason(code)) return { action: '접속 차단', detail: reasonLabel(code), accessBlock: true as const };
  const policy = event.failurePolicy ? uiLabel(event.failurePolicy) : '장애 정책 미기록';
  const reason = event.degradedReason ? uiLabel(event.degradedReason) : hasReasonLabel(code) ? reasonLabel(code) : '원인 미기록';
  return { action, detail: `${reason} · ${policy}` };
}

export function missingDetectionTitle(outcome: SecurityEvent['detectionOutcome'], reasonCode?: string) {
  if (isAccessBlockReason(reasonCode)) return '검사 안 함 · 접속 차단';
  if (outcome === 'NO_MATCH') return '일치한 문서·민감정보 없음';
  if (outcome === 'UNAVAILABLE') return '탐지 결과 확인 불가';
  return '탐지됨 · 상세 근거 미기록';
}

// Only remove query/fragment values from the displayed path, never alter stored records.
export function displayRequestPath(host?: string, endpoint?: string) {
  if (!host || !endpoint) return '—';
  return `${host.split(/[?#]/, 1)[0]}${endpoint.split(/[?#]/, 1)[0]}`;
}
