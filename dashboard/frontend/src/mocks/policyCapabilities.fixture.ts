// 정책 선택지 고정 응답(시험·예시 연결용). 운영 대시보드 서버 policy-capabilities.mjs(2026-10-14.2, md5 54269852…)의
// policyCapabilities() 응답을 그대로 옮겼다(대상 13개 = 분류 2 + 항목 11, can_create 11개, 자격증명은 부분 마스킹 없음).
import type { PolicyActionDto, PolicyCapabilitiesDto, PolicyCapabilityTargetDto } from '@/src/api/dto';

const ACTIONS: readonly PolicyActionDto[] = ['ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL'];
const CONTEXT = ['KR_DATE_OF_BIRTH', 'KR_BANK_ACCOUNT', 'KR_ADDRESS', 'KR_POSTAL_CODE', 'GENERIC_API_KEY', 'PASSWORD'];

const rows: Array<[string, string, string, string | null]> = [
  ['PII', '개인정보 전체', 'PII', '항목별 규칙 적용'],
  ['CREDENTIAL', '자격증명 전체', 'CREDENTIAL', null],
  ['KR_RRN', '주민등록번호', 'PII', '앞 6자리 유지'],
  ['KR_FOREIGN_REGISTRATION_NUMBER', '외국인등록번호', 'PII', '앞 6자리 유지'],
  ['KR_PHONE_NUMBER', '휴대전화', 'PII', '마지막 숫자 4자리 가림'],
  ['EMAIL_ADDRESS', '이메일', 'PII', '아이디 일부 가림, 도메인 유지'],
  ['KR_DATE_OF_BIRTH', '생년월일', 'PII', '연도 유지'],
  ['KR_BANK_ACCOUNT', '계좌번호', 'PII', '마지막 숫자 4자리 유지'],
  ['KR_ADDRESS', '주소', 'PII', '공백 외 전체 가림'],
  ['KR_POSTAL_CODE', '우편번호', 'PII', '공백 외 전체 가림'],
  ['GITHUB_TOKEN', 'GitHub 토큰', 'CREDENTIAL', null],
  ['GENERIC_API_KEY', 'API 키', 'CREDENTIAL', null],
  ['PASSWORD', '비밀번호', 'CREDENTIAL', null],
];

export const POLICY_CAPABILITY_TARGETS: readonly (Omit<PolicyCapabilityTargetDto, 'partial_masking'> & { partial_masking: string | null })[] = rows.map(([code, label, category, partial]) => ({
  code,
  label,
  category,
  target_type: code === category ? 'CATEGORY' : 'ENTITY_TYPE',
  can_create: code !== category,
  allowed_actions: ACTIONS.filter((action) => category !== 'CREDENTIAL' || action !== 'MASK_PARTIAL'),
  partial_masking: partial,
  requires_context: CONTEXT.includes(code),
  runtime_availability: 'NOT_VERIFIED',
}));

/** 서버 응답 모양 그대로(partial_masking null 포함). 스키마를 거치지 않는 예시 연결은 policyCapabilitiesDto()를 쓴다 */
export function policyCapabilitiesPayload() {
  return structuredClone({
    catalog_version: '2026-10-14.2',
    catalog_source: 'REVIEWED_CONFIGURATION',
    runtime_verified: false,
    actions: [
      { code: 'ALLOW', label: '허용' },
      { code: 'BLOCK', label: '차단' },
      { code: 'MASK_PARTIAL', label: '부분 비식별화' },
      { code: 'MASK_FULL', label: '전체 비식별화' },
    ],
    targets: POLICY_CAPABILITY_TARGETS,
    full_masking: 'ENTITY_PLACEHOLDER',
    creates_recognizer: false,
    warnings: [
      'Catalog availability is not proof of enabled runtime rules or healthy LLM routing.',
      'Policy creation does not add a recognizer.',
      'Disabling a policy can fall back to another policy or default blocking.',
      'Entity/category precedence is controlled by Detection, not this catalog.',
    ],
  });
}

export function policyCapabilitiesDto(): PolicyCapabilitiesDto {
  const payload = policyCapabilitiesPayload();
  return { ...payload, targets: payload.targets.map(({ partial_masking, ...target }) => ({ ...target, ...(partial_masking ? { partial_masking } : {}) })) };
}
