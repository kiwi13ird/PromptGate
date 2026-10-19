// Gateway 처리 시간(processing_ms) 기준 변경 — 2026-10-11
// 새 Gateway는 요청 시작부터 Gateway 자체 처리가 끝날 때(LLM으로 넘기기 직전, 또는 Gateway가 직접 차단·오류 응답)까지만 잰다.
// 이전 Gateway는 LLM 답변이 끝날 때까지 쟀다(예: 17초). 두 값이 평균·P95·화면에 섞이지 않도록
// 이 시각보다 먼저 발생한 이벤트의 processing_ms는 읽을 때 뺀다. DB에 저장된 값은 바꾸지 않는다.
//
// 배포: 환경변수 GATEWAY_PROCESSING_MS_SINCE에 새 Gateway 재시작 시각과 같거나 조금 늦은 시각을 넣는다(시간대 포함 ISO 8601).
// 늦게 잡으면 새 기록 몇 건이 빠질 뿐이고, 이르게 잡으면 옛 값이 섞인다. 운영 시작(index.mjs)은 비우면 시작하지 않는다.
// - 백엔드를 Gateway보다 먼저 올릴 때: 예정 재시작 시각보다 늦게 넣고, 재시작이 그보다 늦어지면 실제 시각으로 고친 뒤 백엔드 재시작
// - Gateway만 옛 판으로 되돌릴 때: 먼 미래(예 2099-01-01T00:00:00+09:00)로 바꾸고 백엔드 재시작 → 저장된 처리 시간을 모두 빼고 보낸다.
//   새 Gateway로 다시 올리면 그 재시작 시각으로 다시 맞춘다
// 실시간 평균·P95는 이 시각과 따로, 지표에 settings_applied가 있을 때만 싣는다(app.mjs liveProcessingTimeReported)
// 아래 기본값은 createAppServer를 직접 부르는 시험·로컬 확인용이다(이미 지난 시각이라 운영에 쓰면 옛 값이 섞일 수 있다).
export const DEFAULT_GATEWAY_PROCESSING_MS_SINCE = '2026-10-11T00:00:00+09:00';

const ISO_WITH_ZONE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

// 시각 문자열 → 밀리초. 시간대가 없으면 서버 시간대에 따라 뜻이 달라지므로 받지 않는다.
export function gatewayProcessingCutoff(value) {
  const text = value === undefined || value === null || value === '' ? DEFAULT_GATEWAY_PROCESSING_MS_SINCE : value;
  const milliseconds = typeof text === 'string' && ISO_WITH_ZONE.test(text) ? Date.parse(text) : Number.NaN;
  if (!Number.isFinite(milliseconds))
    throw new Error('GATEWAY_PROCESSING_MS_SINCE must be an ISO 8601 timestamp with a time zone.');
  return milliseconds;
}

// 운영 시작용: 값이 없으면 기본값 대신 오류. 형식은 gatewayProcessingCutoff와 같은 규칙
export function requiredGatewayProcessingSince(value) {
  if (value === undefined || value === null || value === '')
    throw new Error('GATEWAY_PROCESSING_MS_SINCE is required: set it to the new Gateway restart time or later (ISO 8601 with a time zone).');
  gatewayProcessingCutoff(value);
  return value;
}

// 기준 시각 전 이벤트는 processing_ms 칸을 뺀 사본, 나머지는 그대로
export function withGatewayProcessing(event, cutoffMs) {
  if (!event || event.processing_ms === undefined) return event;
  if (Date.parse(event.occurred_at) >= cutoffMs) return event;
  const { processing_ms: _legacyRoundTrip, ...rest } = event;
  return rest;
}
