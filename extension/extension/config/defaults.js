import { EVENT_CHANNEL_STATES, GATEWAY_PROFILES, GATEWAY_STATES } from "./statuses.js";

export const STORAGE_SCHEMA_VERSION = 5;
export const DNR_IDENTITY_RULE_ID = 20001;
export const EVENT_LIMIT = 100;
export const SECURITY_EVENT_LIMIT = 20;
export const HEALTH_ALARM = "llmsgw-health";
export const EVENT_RECONNECT_ALARM = "llmsgw-event-reconnect";
export const EVENT_RECONNECT_DELAYS_MS = Object.freeze([1000, 2000, 5000, 10000, 30000]);
export const HEALTH_PERIOD_MINUTES = 5;
// 1.4.5: 접속 제한 상태 조회 - 1분마다, 팝업을 열 때는 마지막 시도 후 15초가 지났을 때만
export const ACCESS_STATUS_ALARM = "llmsgw-access-status";
export const ACCESS_STATUS_PERIOD_MINUTES = 1;
export const ACCESS_STATUS_MIN_INTERVAL_MS = 15000;
// 1.4.8: 차단·마스킹 집계. 내 요청 기록(Gateway 중계)을 5분마다·팝업을 열 때 읽어 실시간 알림이 놓친 건을 채운다
export const ACTION_STATS_MIN_INTERVAL_MS = 60000;
export const ACTION_STATS_STALE_MS = 15 * 60 * 1000;
export const MY_REQUESTS_TIMEOUT_MS = 10000;
export const MY_REQUESTS_MAX_BYTES = 2 * 1024 * 1024;
export const HEALTH_TIMEOUT_MS = 3500;
export const DEGRADED_LATENCY_MS = 1000;
export const MAX_CONTROL_RESPONSE_BYTES = 256 * 1024;

export const defaultSettings = () => ({
  schemaVersion: STORAGE_SCHEMA_VERSION,
  gateway: { host: "", port: 8080, profile: GATEWAY_PROFILES.CUSTOM },
  identity: { enabled: false, tenantId: "oide" },
  eventChannel: { enabled: false, url: "" },
  dashboard: { baseUrl: "" },
  developerToolsEnabled: false,
  developmentMode: true
});

export const defaultRuntimeState = () => ({
  desiredProtection: false,
  gatewayState: GATEWAY_STATES.UNKNOWN,
  lastHealthAt: null,
  lastHealthLatencyMs: null,
  lastHealthError: "",
  lastErrorCode: "",
  lastTechnicalDetail: "",
  lastProxyError: "",
  proxyLevelOfControl: "unknown",
  proxyMode: "unknown",
  eventChannelStatus: EVENT_CHANNEL_STATES.DISABLED,
  eventChannelError: "",
  eventReconnectAttempt: 0,
  lastSecurityEventAt: null
});
