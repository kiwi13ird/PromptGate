// 판정 사유 코드(reasonCode·reason_code) 이름표 - 내 요청 기록과 관리자 이벤트 화면이 같이 쓴다(명세 §8.2).
// 개인정보·보호 문서(pii·doc_excerpt)는 탐지 항목 칩으로 이미 보이므로 여기 두지 않는다.
const REASON_TEXT: Record<string, string> = {
  file_uninspectable_image: '검사할 수 없는 파일(이미지)',
  file_uninspectable_scanned_pdf: '검사할 수 없는 파일(스캔 PDF)',
  file_uninspectable_other: '검사할 수 없는 파일 형식',
  file_too_large: '파일이 커서 검사하지 못함',
  // 403: 가림을 적용·확인할 수 없음(PDF 남은 값·지원 안 함·재검사 적중, HWP 크기 못 맞춤 등) / 503: 가림 처리 자체가 실패(응답 없음·시간 초과·오류)
  mask_application_failed: '마스킹할 수 없음',
  file_masking_failed: '마스킹 처리 실패',
  detection_timeout: '보안 검사 응답 없음',
  detection_unreachable: '보안 검사 응답 없음',
  detection_error: '보안 검사 응답 없음',
  detection_parse_error: '보안 검사 응답 없음',
  // 접속 차단(2026-10-12): 관리자 차단 목록에 걸림 / 확장 프로그램 ID 없는 접속 차단. Detection을 부르지 않는다
  client_blocked: '접속 차단(관리자)',
  client_id_missing: '접속 차단(확장 ID 없음)',
};

// 내용을 검사하지 않은 사유(검사 불가 형식·상한 초과) - Detection을 부르지 않았다
const UNINSPECTED = new Set(['file_uninspectable_image', 'file_uninspectable_scanned_pdf', 'file_uninspectable_other', 'file_too_large']);
// Detection이 제때 답하지 않은 사유
const NO_RESPONSE = new Set(['detection_timeout', 'detection_unreachable', 'detection_error', 'detection_parse_error']);

// 접속 단계에서 막아 내용을 검사하지 않은 사유
const ACCESS_BLOCK = new Set(['client_blocked', 'client_id_missing']);

// 차단된 사용자에게 보이는 고정 사유(Gateway 차단 화면 · 확장 프로그램과 같은 문구). 확장 ID가 없는 접속은 규칙이 없어 사유가 하나뿐이다
export const CLIENT_ID_MISSING_USER_REASON = '확장 프로그램 식별 정보 없음';

export function hasReasonLabel(code: string | null | undefined): code is string {
  return typeof code === 'string' && Object.hasOwn(REASON_TEXT, code);
}

/** 사유 코드 이름표. 모르는 코드는 원래 코드 그대로. */
export function reasonLabel(code: string): string {
  return Object.hasOwn(REASON_TEXT, code) ? REASON_TEXT[code] : code;
}

export function isUninspectedReason(code: string | null | undefined): boolean {
  return typeof code === 'string' && UNINSPECTED.has(code);
}

export function isNoResponseReason(code: string | null | undefined): boolean {
  return typeof code === 'string' && NO_RESPONSE.has(code);
}

export function isAccessBlockReason(code: string | null | undefined): boolean {
  return typeof code === 'string' && ACCESS_BLOCK.has(code);
}
