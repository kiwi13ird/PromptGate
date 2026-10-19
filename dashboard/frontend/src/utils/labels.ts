// Display labels only. Keep API values, identifiers and detector codes unchanged.
const labels: Record<string, string> = {
  ALL: '전체', BLOCK: '차단', MASK: '마스킹', ALLOW: '허용',
  MASK_PARTIAL: '부분 마스킹', MASK_FULL: '전체 마스킹',
  NEW: '신규', INVESTIGATING: '조사 중', RESOLVED: '처리 완료',
  CRITICAL: '치명적', HIGH: '높음', MEDIUM: '보통', LOW: '낮음',
  MATCH: '탐지됨', NO_MATCH: '일치 없음', UNAVAILABLE: '확인 불가',
  EXACT_DOCUMENT: '문서 전체 일치', SIMILAR_DOCUMENT: '유사 문서',
  TEXT_FRAGMENT: '문서 구간 일치', SIGNATURE_RULE: '민감정보 패턴',
  COVERAGE: '해시 근거 비율', SIMILARITY: '유사도', CONFIDENCE: '신뢰도', EXACT: '완전 일치',
  SHA256: '동일 문서 검사', MINHASH: '유사 문서 검사', WINDOW_HASH: '문서 구간 검사', SIGNATURE: '민감정보 검사',
  YES: '발생', NO: '없음', TIMEOUT: '시간 초과', UNREACHABLE: '연결 실패',
  PARSE_ERROR: '응답 해석 오류', OTHER: '기타', UNKNOWN: '미확인',
  FAIL_OPEN: '장애 시 허용', FAIL_CLOSED: '장애 시 차단',
  HEALTHY: '정상', DEGRADED: '일부 기능 저하', ACTIVE: '활성', INACTIVE: '비활성',
  ON: '활성', OFF: '비활성', READY: '준비 완료', PROCESSING: '처리 중', NOT_AVAILABLE: '색인 없음',
  PENDING: '대기 중', FAILED: '실패', ERROR: '오류', SUCCESS: '성공', FAILURE: '실패',
  ADMIN_LOGIN: '관리자 로그인', ADMIN_LOGOUT: '관리자 로그아웃',
  POLICY_CREATE: '정책 생성', POLICY_UPDATE: '정책 수정', POLICY_ENABLE: '정책 활성화', POLICY_DISABLE: '정책 비활성화',
  DOCUMENT_REGISTER: '문서 등록', DOCUMENT_DISABLE: '문서 비활성화', DOCUMENT_ENABLE: '문서 활성화',
  EVENT_ASSIGNED: '담당자 지정', EVENT_STATUS_CHANGED: '조사 상태 변경', EVENT_NOTE_ADDED: '관리자 메모 추가',
  ADMIN: '관리자', EVENT: '이벤트', DOCUMENT: '문서', POLICY: '정책',
  PROMPT: '프롬프트', FILE: '파일', prompt: '프롬프트', file: '파일',
  KR_PHONE_NUMBER: '전화번호', KR_RRN: '주민등록번호', EMAIL: '이메일', EMAIL_ADDRESS: '이메일', GENERIC_API_KEY: 'API 키',
  CONFIDENTIAL: '기밀', INTERNAL: '내부용', PUBLIC: '공개', PII: '개인정보', CREDENTIAL: '자격증명',
  '24H': '24시간', '7D': '7일', '30D': '30일',
  REPORT_CREATE: '리포트 생성', KEYWORD_CREATE: '키워드 추가', KEYWORD_APPROVE: '키워드 승인',
  KEYWORD_REJECT: '키워드 반려·삭제', KEYWORD_UPDATE: '키워드 수정', KEYWORD_EXTRACT_REQUEST: '키워드 추출 요청',
  REPORT: '리포트', KEYWORD: '키워드',
  GPU_START: 'GPU 켜기', GPU_STOP: 'GPU 끄기', GPU: 'GPU',
  GATEWAY_SETTINGS_UPDATE: 'Gateway 처리 설정 변경', GATEWAY: 'Gateway',
  ACCESS_RULE_ADD: '접속 차단 등록', ACCESS_RULE_REMOVE: '접속 차단 해제',
  ACCESS_MODE_UPDATE: '확장 ID 없는 접속 차단 변경', CLIENT_ALIAS_UPDATE: '확장 ID 별칭 변경',
  DOCUMENT_VIEW: '문서 열람', DOCUMENT_DOWNLOAD: '문서 내려받기',
  KR_BANK_ACCOUNT: '계좌번호', KR_DATE_OF_BIRTH: '생년월일', KR_FOREIGN_REGISTRATION_NUMBER: '외국인등록번호',
  PASSWORD: '비밀번호', GITHUB_TOKEN: 'GitHub 토큰', DOC_KEYWORD: '기밀 키워드',
  AWS_ACCESS_KEY: 'AWS 액세스 키', PRIVATE_KEY: '개인 키',
  KR_ADDRESS: '주소', KR_POSTAL_CODE: '우편번호',
};

export function uiLabel(value: string | undefined): string {
  if (value === undefined) return '당시 미기록';
  return labels[value] ?? value;
}
