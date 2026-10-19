// 시험·데모 이벤트 구분 (2026-10-10 결정: 지우지 않고 통계·목록에서만 뺀다)
// 클라이언트 ID 앞부분으로 구분한다. 접두어는 영문·숫자·밑줄만 받는다(SQL 정규식에 그대로 넣기 때문)
// 2026-10-16 공통 규칙(docs/handoff/stats-rules-2026-10-16/SPEC.md 2.1): 기본값에 legacy 추가 — 9/15~9/23 Gateway 서비스 가동 전
// 개발 시험 호출을 판정 기록에서 되살린 'legacy-gateway' 123건. Detection 보고서 REPORT_TEST_CLIENT_PREFIXES와 같은 값
export const TEST_CLIENT_PREFIXES = Object.freeze(
  (process.env.TEST_CLIENT_PREFIXES ?? 'demo,evidence,codex,diag,gateway,legacy')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => /^[A-Za-z0-9_]+$/.test(value)),
);

export function isTestEvent(event) {
  const clientId = String(event?.client_id ?? '');
  return TEST_CLIENT_PREFIXES.some((prefix) => clientId === prefix || clientId.startsWith(`${prefix}-`));
}

// 같은 기준을 SQL(client_id !~ 정규식)에서 쓸 때. 접두어가 없으면 아무것도 맞지 않는 식
export const TEST_CLIENT_PATTERN = TEST_CLIENT_PREFIXES.length ? `^(${TEST_CLIENT_PREFIXES.join('|')})(-|$)` : '$^';

// 시연 문서(SPEC 2.2): 문서 번호가 DEMO_로 시작. 문서 검출(SIGNATURE가 아니고 일치 문서 번호가 있는 탐지)의 문서가
// 하나 이상이고 모두 시연 문서인 이벤트는 통계에서 뺀다(시연 문서 + 다른 문서가 같이 걸리면 남김)
export const DEMO_DOC_PREFIX = 'DEMO_';
export const isDemoDocumentId = (documentId) => String(documentId ?? '').startsWith(DEMO_DOC_PREFIX);

export function isDemoDocumentEvent(event) {
  const documents = (event?.detections ?? [])
    .filter((detection) => detection?.detector && detection.detector !== 'SIGNATURE' && detection.matched_document_id)
    .map((detection) => String(detection.matched_document_id));
  return documents.length > 0 && documents.every(isDemoDocumentId);
}

// 통계·목록에서 빼는 기록 = 시험 접두어 → 시연 문서 순(SPEC 처리 순서 ②). 목록의 '시험·데모 n건 제외'·'포함해서 보기'가 같이 다룬다
export function isExcludedEvent(event) {
  return isTestEvent(event) || isDemoDocumentEvent(event);
}
