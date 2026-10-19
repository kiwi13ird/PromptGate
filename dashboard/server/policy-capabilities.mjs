// Reviewed policy configuration catalog, not a runtime recognizer registry.
// Does not create recognizers or claim all LLM adapters are healthy.
export const POLICY_ACTIONS = Object.freeze([
  'ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL',
]);
const labels = {
  ALLOW: '허용', BLOCK: '차단',
  MASK_PARTIAL: '부분 비식별화', MASK_FULL: '전체 비식별화',
};
const entities = [
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
const targets = [
  ['PII', '개인정보 전체', 'PII', '항목별 규칙 적용'],
  ['CREDENTIAL', '자격증명 전체', 'CREDENTIAL', null],
  ...entities,
].map(([code, label, category, partial]) => ({
  code, label, category,
  target_type: code === category ? 'CATEGORY' : 'ENTITY_TYPE',
  // Existing Detection create() creates ENTITY_TYPE rows only.
  can_create: code !== category,
  allowed_actions: POLICY_ACTIONS.filter((a) => category !== 'CREDENTIAL' || a !== 'MASK_PARTIAL'),
  partial_masking: partial,
  requires_context: ['KR_DATE_OF_BIRTH', 'KR_BANK_ACCOUNT', 'KR_ADDRESS', 'KR_POSTAL_CODE', 'GENERIC_API_KEY', 'PASSWORD'].includes(code),
  runtime_availability: 'NOT_VERIFIED',
}));

function fail(code, message) {
  const error = new Error(message);
  error.statusCode = 422;
  error.code = code;
  throw error;
}

export function normalizePolicyResponse(payload) {
  if (Array.isArray(payload)) return payload.map(normalizePolicyResponse);
  if (!payload || typeof payload !== 'object') return payload;
  const result = { ...payload };
  for (const key of ['action', 'recommended_action', 'enforcement_action']) {
    if (typeof result[key] !== 'string') continue;
    const value = result[key].toUpperCase();
    result[key] = ({ MASK: 'MASK_FULL', ALLOW_NOTIFY: 'ALLOW', BLOCK_NOTIFY: 'BLOCK' })[value] ?? value;
  }
  return result;
}

export function policyCapabilities() {
  return structuredClone({
    catalog_version: '2026-10-14.2',
    catalog_source: 'REVIEWED_CONFIGURATION',
    runtime_verified: false,
    actions: POLICY_ACTIONS.map((code) => ({ code, label: labels[code] })),
    targets,
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

export function validatePolicyAction(target, action, { creating = false } = {}) {
  if (typeof target !== 'string') fail('UNSUPPORTED_POLICY_TARGET', 'Select a supported detection target.');
  const selected = targets.find((item) => item.code === target.trim().toUpperCase());
  if (!selected) fail('UNSUPPORTED_POLICY_TARGET', 'Policy target is not in the reviewed configuration catalog.');
  if (creating && !selected.can_create)
    fail('CATEGORY_POLICY_CREATE_UNSUPPORTED', 'Category creation is not supported; edit an existing category policy.');
  if (typeof action !== 'string') fail('UNSUPPORTED_POLICY_ACTION', 'Select a supported policy action.');
  const input = action.trim().toUpperCase();
  // Keep the deployed frontend's legacy values compatible.
  const normalized = ({ MASK: 'MASK_FULL', ALLOW_NOTIFY: 'ALLOW', BLOCK_NOTIFY: 'BLOCK' })[input] ?? input;
  if (!POLICY_ACTIONS.includes(normalized)) fail('UNSUPPORTED_POLICY_ACTION', 'Select one of the four policy actions.');
  if (!selected.allowed_actions.includes(normalized))
    fail('CREDENTIAL_PARTIAL_MASK_FORBIDDEN', 'Credentials require full masking or blocking when masked; partial masking is forbidden.');
  return { detection_target: selected.code, action: normalized };
}

export function validatePolicyVersion(version) {
  if (!Number.isSafeInteger(version) || version < 1)
    fail('INVALID_POLICY_VERSION', 'expected_version must be a positive safe integer.');
}

export function validatePolicyStatus(enabled, version) {
  if (typeof enabled !== 'boolean') fail('INVALID_POLICY_STATUS', 'enabled must be a boolean.');
  validatePolicyVersion(version);
}
