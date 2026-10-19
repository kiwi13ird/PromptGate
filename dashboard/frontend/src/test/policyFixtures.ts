// 정책 화면 시험용 고정 값(2026-10-15). 운영 서버 응답 모양(설계 docs/design/policy-ui-2026-10-15.md 1절)을 실제 응답 스키마에 통과시켜 만든다.
//   선택지: policy-capabilities.mjs 2026-10-14.2 그대로(대상 13 = 분류 2 + 항목 11)
//   정책: PII·CREDENTIAL 분류(전체 마스킹 v1, bootstrap) + 이메일 항목(부분 마스킹 v2)
//   이력: 생성 → 처리 방식 변경 → 비활성화 3건
//   오류 본문: {"error":{"code","message"}}
import { z } from 'zod';
import { ApiError } from '@/src/api/errors';
import { mapPolicyCapabilitiesDto, mapPolicyDto, mapPolicyVersionDto } from '@/src/api/mappers';
import { parseApiResponse, policyCapabilitiesSchema, policySchema, policyVersionSchema } from '@/src/api/schemas';
import { policyCapabilitiesPayload } from '@/src/mocks/policyCapabilities.fixture';

export const policyDto = (id: string, target: string, action: string, version: number, enabled = true) => ({
  policy_id: id, detector: 'SIGNATURE', detection_target: target,
  action, recommended_action: action, enforcement_action: action,
  target_llms: ['ChatGPT', 'Gemini', 'Claude'], priority: 100, version, enabled,
  updated_by: id.includes('EMAIL') ? 'local-admin' : 'bootstrap', updated_at: '2026-10-14T09:00:00Z',
});

export const capabilitiesFixture = () => mapPolicyCapabilitiesDto(parseApiResponse(policyCapabilitiesSchema, policyCapabilitiesPayload()));

export const policiesFixture = (extra: ReturnType<typeof policyDto>[] = []) => parseApiResponse(z.array(policySchema), [
  policyDto('POLICY-PII-MASK', 'PII', 'MASK_FULL', 1),
  policyDto('POLICY-CREDENTIAL-MASK', 'CREDENTIAL', 'MASK_FULL', 1),
  policyDto('POLICY-EMAIL_ADDRESS-1', 'EMAIL_ADDRESS', 'MASK_PARTIAL', 2),
  ...extra,
]).map(mapPolicyDto);

export const historyFixture = () => parseApiResponse(z.array(policyVersionSchema), [
  { version: 3, action: 'MASK_PARTIAL', enabled: false, created_at: '2026-10-14T09:20:00Z', changed_by: 'local-admin' },
  { version: 2, action: 'MASK_PARTIAL', enabled: true, created_at: '2026-10-14T09:10:00Z', changed_by: 'local-admin' },
  { version: 1, action: 'MASK', enabled: true, created_at: '2026-10-14T09:00:00Z', changed_by: 'bootstrap' },   // 옛 값(MASK) → 전체 마스킹
]).map(mapPolicyVersionDto);

/** 서버 오류 응답을 httpClient가 만든 것과 같은 ApiError로 */
export const serverError = (status: number, serverCode?: string) => {
  const code = status === 401 ? 'UNAUTHORIZED' : status === 404 ? 'NOT_FOUND' : status === 409 ? 'CONFLICT'
    : status === 400 || status === 422 ? 'VALIDATION' : status >= 500 ? 'SERVER' : 'UNKNOWN';
  return new ApiError('요청을 처리하지 못했습니다.', code, status, serverCode);
};
