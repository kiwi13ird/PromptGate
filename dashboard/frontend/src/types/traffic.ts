import type { OverviewPeriod } from './event';

export type GatewayStatus = 'HEALTHY' | 'DEGRADED' | 'UNKNOWN';

export interface TrafficSummary {
  metricSource?: 'GATEWAY_LIVE' | 'STORED_EVENTS';
  gatewayMetricsStatus?: 'FRESH' | 'STALE' | 'NOT_RECEIVED';
  gatewayMetricsReceivedAt?: string;
  gatewayMetricsAgeSec?: number;
  gatewayTotalRequests?: number;
  gatewayCompletedRequests?: number;
  gatewayErrorRequests?: number;
  gatewayWindowSeconds?: number;
  clientIdentityIncomplete?: boolean;
  eventCount?: number;
  latencySampleCount?: number;
  activeClients?: number;
  concurrentRequests?: number;
  requestsPerSec?: number;
  averageLatencyMs?: number;
  p95LatencyMs?: number;
  /** 실시간 지표를 보낸 Gateway가 settings_applied를 보내지 않아(이전 판 또는 첫 보고 전) 백엔드가 평균·P95를 뺐다 */
  latencyUnavailableReason?: 'LEGACY_GATEWAY';
  timeoutRate?: number;
  degradedRate?: number;
  gatewayStatus: GatewayStatus;
  /** 저장 기록에서 뺀 접속 차단 기록 수(2026-10-15). 옛 서버는 없음(그때는 접속 차단이 건수·분모에 들어 있음) */
  accessBlocked?: number;
  /** 실시간: Gateway 시작 이후 보안 검사를 거친 요청 수(비율의 분모). 옛 Gateway는 없음 → 분모는 LLM 사이트 요청 전체 */
  gatewayInspectedRequests?: number;
  /** 실시간 연결 오류 수의 기준: GATEWAY_ERRORS = 브라우저 취소를 뺀 Gateway 쪽 오류(새 Gateway), ALL_DISCONNECTS = 브라우저 취소 포함(옛 Gateway) */
  gatewayErrorBasis?: 'GATEWAY_ERRORS' | 'ALL_DISCONNECTS';
  /** 실시간: 브라우저가 끊은 요청 수(새 Gateway가 따로 보낼 때만) */
  gatewayClientCancelledRequests?: number;
  /** Gateway 상태가 '오류 기록 있음'인 근거(서버 판정, 시스템 상태와 같은 규칙) */
  gatewayStatusReason?: string;
}

export interface TrafficTimeBucket {
  timestamp: string;
  requestCount: number;
  allowCount: number;
  maskCount: number;
  blockCount: number;
  averageLatencyMs?: number;
  p95LatencyMs?: number;
}

/** 연결 중인 IP(2026-10-12): Gateway가 10초마다 보내는 지표의 clients 한 줄 */
export interface TrafficClient {
  ip: string;
  /** 확장 프로그램 ID(chrome-…). 확장 프로그램 없이 들어온 요청이면 없음 */
  clientId?: string;
  /** 지금 열려 있는 연결 수. 0이면 연결은 끊겼고 10분 안에 요청한 IP */
  connections: number;
  /** 처리 중인 요청 수(30초 미만) */
  inflight: number;
  /** 대기 연결 수: 30초 넘게 응답을 받고 있는 요청(스트리밍 등). 옛 Gateway는 0 */
  waiting: number;
  requests5m: number;
  /** 최근 5분 대상 LLM별 요청 수, 많은 순 */
  targets: Array<{ llm: string; count: number }>;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface TrafficClients {
  /** 백엔드가 마지막으로 지표를 받은 시각. 받은 적 없으면 없음 */
  receivedAt?: string;
  /** 지표가 없거나 30초 넘게 지남 */
  stale: boolean;
  windowSeconds: number;
  clients: TrafficClient[];
}

export interface TrafficSnapshot {
  visualization?: import('@/src/utils/eventSeries').EventSeries;
  /** 추이 검증용으로 읽은 기간 이벤트 목록. 처리 시간 분포·검사 못 한 요청 계산용(재설계 3c). 못 읽으면 없음 */
  periodEvents?: import('./event').SecurityEvent[];
  unavailableSections?: string[];
  period: OverviewPeriod;
  summary: TrafficSummary;
  timeSeries: TrafficTimeBucket[];
}
