// 탐지 정책이 잡는 항목(정책 목록 펼침 '탐지 항목'). 2026-10-13 운영 Detection(52.78.7.20)을 읽기 전용으로 확인한 목록이다.
// 이 목록을 주는 API가 Detection·대시보드 서버 어디에도 없어 화면에 둔다(근거: docs/design/dashboard-redesign-2026-10-13/feedback-2026-10-13/README.md 6절).
//   - 내장 인식기(분류 PII): /opt/detection/src/signature/recognizers.py PII_RECOGNIZERS 5개
//       KR_RRN · KR_FOREIGN_REGISTRATION_NUMBER · KR_PHONE_NUMBER · EMAIL_ADDRESS · KR_DATE_OF_BIRTH('생년월일' 등 이름표 필요)
//   - 이름표 값 인식기: contextual_pii.py VALUE_ENTITIES — KR_BANK_ACCOUNT · KR_ADDRESS · KR_POSTAL_CODE('주소:'처럼 이름표가 붙은 값만).
//       KR_ADDRESS·KR_POSTAL_CODE는 인식기 목록에 없어 engine.category_for_hit의 기본값 PII로 분류된다
//   - DB 규칙: /var/lib/detection/signature.db signature_rules(enabled=1) 4행
//       SIG-PII-001 PII KR_BANK_ACCOUNT(이름표 필요) · SIG-CRED-001 CREDENTIAL GITHUB_TOKEN · SIG-CRED-002 CREDENTIAL GENERIC_API_KEY(이름표 필요)
//       · SIG-CRED-003 CREDENTIAL PASSWORD(이름표 필요)
//   - 정책: /var/lib/detection-policy/policy.db detection_policies = POLICY-PII-MASK(CATEGORY PII) · POLICY-CREDENTIAL-MASK(CATEGORY CREDENTIAL) 2개
//   - 기밀 키워드(DOC_KEYWORD, keywords.py)는 분류 KEYWORD인데 맞는 정책이 없어 policy_store.resolve의 기본값(차단)으로 처리된다
//   - 문서 일치(창 해시)는 패턴 검사보다 먼저 돌고 정책을 거치지 않고 차단한다(pipeline._decide ①)
// 운영 규칙이 바뀌면(시스템 상태의 '시그니처(내장) 5 · 시그니처(DB) 4'가 달라지면) 이 목록도 다시 확인한다.
import { uiLabel } from './labels';

export const DETECTION_ENTITIES_CHECKED_AT = '2026-10-13';

export interface DetectionEntity {
  type: string;
  /** '주소:'처럼 이름표가 붙은 값만 잡는 항목 */
  needsLabel?: boolean;
}

/** 분류(정책 대상 CATEGORY) → 운영 Detection이 그 분류로 내는 탐지 항목, 화면 순서 */
export const CATEGORY_ENTITIES: Readonly<Record<'PII' | 'CREDENTIAL', readonly DetectionEntity[]>> = {
  PII: [
    { type: 'KR_RRN' },
    { type: 'KR_FOREIGN_REGISTRATION_NUMBER' },
    { type: 'KR_PHONE_NUMBER' },
    { type: 'EMAIL_ADDRESS' },
    { type: 'KR_DATE_OF_BIRTH', needsLabel: true },
    { type: 'KR_BANK_ACCOUNT', needsLabel: true },
    { type: 'KR_ADDRESS', needsLabel: true },
    { type: 'KR_POSTAL_CODE', needsLabel: true },
  ],
  CREDENTIAL: [
    { type: 'PASSWORD', needsLabel: true },
    { type: 'GENERIC_API_KEY', needsLabel: true },
    { type: 'GITHUB_TOKEN' },
  ],
};

const KNOWN = new Map(Object.values(CATEGORY_ENTITIES).flat().map(entity => [entity.type, entity]));

export type PolicyEntities =
  | { kind: 'category'; entities: readonly DetectionEntity[] }
  | { kind: 'entity'; entities: readonly DetectionEntity[] }
  | { kind: 'keyword' }
  | { kind: 'unknown' };

/** 정책의 탐지 대상(분류 이름 또는 유형 이름) → 그 정책이 잡는 항목 */
export function policyEntities(detectionTarget: string): PolicyEntities {
  const target = detectionTarget.trim().toUpperCase();
  if (target === 'PII' || target === 'CREDENTIAL') return { kind: 'category', entities: CATEGORY_ENTITIES[target] };
  if (target === 'KEYWORD' || target === 'DOC_KEYWORD') return { kind: 'keyword' };
  const entity = KNOWN.get(target);
  return entity ? { kind: 'entity', entities: [entity] } : { kind: 'unknown' };
}

export const entityName = (entity: DetectionEntity) => uiLabel(entity.type);
