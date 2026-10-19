// 정책 처리 방식 4종(2026-10-14 정책 API, docs/design/policy-ui-2026-10-15.md 2.1·3.1).
// 이벤트·통계의 SecurityAction(ALLOW/MASK/BLOCK)·uiMode.supportedActions와는 따로 둔다(그쪽은 건드리지 않음).
// 화면 이름은 '부분 마스킹'·'전체 마스킹'(서버 label '비식별화'는 쓰지 않는다, 2026-10-15 결정 1).
import type { BadgeTone } from '@/src/components/pg/badgeTone';
import type { PolicyAction, PolicyCapabilities, PolicyCapabilityTarget } from '@/src/types/policy';
import { categoryTitle } from './entityCategory';
import { uiLabel } from './labels';

/** 화면 순서(서버 POLICY_ACTIONS 순서와 같음) */
export const POLICY_ACTIONS: readonly PolicyAction[] = ['ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL'];

export const POLICY_ACTION_NAME: Readonly<Record<PolicyAction, string>> = {
  ALLOW: '허용',
  BLOCK: '차단',
  MASK_PARTIAL: '부분 마스킹',
  MASK_FULL: '전체 마스킹',
};

/** 옛 값 → 4종(서버 normalizePolicyResponse와 같은 규칙 + ALLOW_DEGRADED). 읽을 때만 쓴다 */
const LEGACY: Readonly<Record<string, PolicyAction>> = {
  MASK: 'MASK_FULL',
  ALLOW_NOTIFY: 'ALLOW',
  ALLOW_DEGRADED: 'ALLOW',
  BLOCK_NOTIFY: 'BLOCK',
};

export function isPolicyAction(value: unknown): value is PolicyAction {
  return typeof value === 'string' && (POLICY_ACTIONS as readonly string[]).includes(value);
}

/** 서버 값(4종 또는 옛 값) → 4종. 모르는 값은 undefined */
export function toPolicyAction(value: string | undefined | null): PolicyAction | undefined {
  if (!value) return undefined;
  const upper = value.trim().toUpperCase();
  if (isPolicyAction(upper)) return upper;
  return LEGACY[upper];
}

/** 배지 색 계열(허용·차단·마스킹 셋) */
export function policyTone(action: PolicyAction): BadgeTone {
  if (action === 'ALLOW') return 'allow';
  if (action === 'BLOCK') return 'block';
  return 'mask';
}

export const policyActionName = (action: PolicyAction) => POLICY_ACTION_NAME[action];

/** 분류 대상(PII·CREDENTIAL)인지 */
export const isCategoryTarget = (target: Pick<PolicyCapabilityTarget, 'targetType' | 'code' | 'category'>) =>
  target.targetType === 'CATEGORY' || target.code === target.category;

/** 탐지 대상 이름: 화면 공통 이름표(uiLabel) → 없으면 서버 이름 → 코드. 분류는 '개인정보 전체'처럼 */
export function policyTargetName(code: string, capabilities?: PolicyCapabilities) {
  const upper = code.trim().toUpperCase();
  const target = capabilities?.targets.find((item) => item.code === upper);
  const label = uiLabel(upper);
  const base = label !== upper ? label : target?.label ?? code;
  if (target && isCategoryTarget(target)) return target.label || `${base} 전체`;
  if (!target && (upper === 'PII' || upper === 'CREDENTIAL')) return `${base} 전체`;
  return base;
}

export function findCapabilityTarget(capabilities: PolicyCapabilities | undefined, code: string) {
  const upper = code.trim().toUpperCase();
  return capabilities?.targets.find((item) => item.code === upper);
}

/** 처리 방식 설명 한 줄(2단계·수정 대화상자) */
export function policyActionDescription(action: PolicyAction, target: PolicyCapabilityTarget, capabilities: PolicyCapabilities) {
  if (action === 'ALLOW') return '탐지해도 원문 그대로 보냅니다.';
  if (action === 'BLOCK') return '요청을 보내지 않고 막습니다.';
  if (action === 'MASK_PARTIAL') return target.partialMasking ? `${target.partialMasking}` : '항목별 규칙으로 일부만 가립니다.';
  if (capabilities.fullMasking !== 'ENTITY_PLACEHOLDER') return '항목 값을 모두 가려 보냅니다.';
  return `[${placeholderCode(target, capabilities)}] 같은 항목 표시로 교체합니다.`;
}

/** 전체 마스킹 예시에 쓰는 항목 코드: 개별 항목은 자기 코드, 분류는 그 분류의 첫 항목 */
function placeholderCode(target: PolicyCapabilityTarget, capabilities: PolicyCapabilities) {
  if (!isCategoryTarget(target)) return target.code;
  const preferred = target.category === 'PII' ? 'EMAIL_ADDRESS' : undefined;
  const members = capabilities.targets.filter((item) => item.category === target.category && !isCategoryTarget(item));
  return members.find((item) => item.code === preferred)?.code ?? members[0]?.code ?? 'EMAIL_ADDRESS';
}

/** 앞 버전과 비교한 변경 내용 한 줄(변경 이력 서랍) */
export function policyChangeText(current: { version: number; policyAction: PolicyAction; enabled: boolean }, previous?: { policyAction: PolicyAction; enabled: boolean }) {
  if (!previous) return current.version === 1 ? '최초 생성' : '이전 버전 미기록';
  const parts: string[] = [];
  if (previous.policyAction !== current.policyAction) parts.push(`처리 방식 ${POLICY_ACTION_NAME[previous.policyAction]} → ${POLICY_ACTION_NAME[current.policyAction]}`);
  if (previous.enabled !== current.enabled) parts.push(current.enabled ? '활성화' : '비활성화');
  return parts.length ? parts.join(' · ') : '처리 방식·활성 상태 변화 없음';
}

/** 허용을 고를 때 확인창에 쓰는 경고 한 줄(분류 기본 처리·항목 공통) */
export function allowWarning(target: PolicyCapabilityTarget) {
  if (isCategoryTarget(target)) {
    const title = categoryTitle[target.category as keyof typeof categoryTitle] ?? target.category;
    return `허용하면 항목별 정책이 없는 ${title} 항목은 마스킹·차단 없이 그대로 전달됩니다.`;
  }
  return '허용하면 이 항목은 마스킹·차단 없이 그대로 전달되고, 분류 전체 정책이 마스킹이어도 이 항목은 예외가 됩니다.';
}
