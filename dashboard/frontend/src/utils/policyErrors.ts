// 탐지 정책 변경 오류 문구(설계 docs/design/policy-ui-2026-10-15.md 3.4 표, 2026-10-15).
// 서버 오류 코드는 ApiError.serverCode(오류 본문 error.code)에서 읽고, 화면에는 코드·서버의 영어 메시지를 보이지 않는다.
// 코드가 없으면(옛 서버·네트워크·시간 초과) 상태 기반 문구(safeMessage)로 둔다.
import { ApiError } from '@/src/api/errors';
import { safeMessage } from './feedback';

/** 오류 뒤에 다시 불러올 것 */
export type PolicyErrorRefetch = 'capabilities' | 'policies' | 'policies-history';
export type PolicyErrorContext = 'create' | 'update' | 'status';

export interface PolicyErrorInfo {
  message: string;
  refetch?: PolicyErrorRefetch;
  /** 버전 충돌: 덮어쓰지 않고 확정 버튼을 끈다 */
  versionConflict?: boolean;
}

const M = {
  unauthorized: '로그인이 만료되었습니다. 다시 로그인해주세요.',
  badRequest: '요청 형식이 올바르지 않습니다. 화면을 새로고침한 뒤 다시 시도하세요.',
  unsupportedTarget: '지원 목록에 없는 탐지 대상입니다. 처리 방식 목록을 다시 불러옵니다.',
  categoryCreate: '분류 전체 정책은 새로 만들 수 없습니다. 목록의 기존 정책을 수정하세요.',
  unsupportedAction: '이 대상에서 쓸 수 없는 처리 방식입니다. 선택지에서 다시 고르세요.',
  credentialPartial: '자격증명은 부분 마스킹을 지원하지 않습니다. 허용·차단·전체 마스킹 중에서 고르세요.',
  invalidVersion: '정책 버전 정보가 올바르지 않습니다. 목록을 새로고침하세요.',
  invalidStatus: '활성 상태 값이 올바르지 않습니다. 새로고침 후 다시 시도하세요.',
  notFound: '정책을 찾을 수 없습니다. 목록을 새로고침하세요.',
  versionConflict: '다른 관리자가 먼저 바꿨습니다. 최신 정책을 다시 불러왔으니 내용을 확인한 뒤 다시 변경하세요.',
  duplicate: '이 탐지 대상에는 이미 정책이 있습니다. 목록에서 수정하세요.',
  upstreamInvalid: '탐지 서버 응답을 해석하지 못했습니다. 잠시 후 다시 시도하고, 반복되면 운영자에게 알려주세요.',
  // 2026-10-16: Detection 5xx(서버 안 오류)는 응답 해석 실패와 따로(대시보드 서버 POLICY_UPSTREAM_SERVER_ERROR)
  upstreamServerError: '탐지 서버에서 오류가 발생했습니다. 변경이 적용됐는지 목록에서 확인한 뒤 다시 시도하고, 반복되면 운영자에게 알려주세요.',
  integrationUnavailable: '정책 서버 연결 설정이 없습니다. 운영자에게 알려주세요.',
  upstreamUnavailable: '탐지 서버에 연결하지 못했습니다(3초 안에 응답 없음 포함). 변경이 적용됐는지 목록에서 확인한 뒤 다시 시도하세요.',
} as const;

export const POLICY_ERROR_MESSAGES = M;

export function policyErrorInfo(error: unknown, context: PolicyErrorContext): PolicyErrorInfo {
  if (!(error instanceof ApiError)) return { message: safeMessage(error) };
  const code = error.serverCode;
  switch (code) {
    case 'UNAUTHORIZED': return { message: M.unauthorized };
    case 'BAD_REQUEST':
    case 'VALIDATION': return { message: M.badRequest };
    case 'UNSUPPORTED_POLICY_TARGET': return { message: M.unsupportedTarget, refetch: 'capabilities' };
    case 'CATEGORY_POLICY_CREATE_UNSUPPORTED': return { message: M.categoryCreate };
    case 'UNSUPPORTED_POLICY_ACTION': return { message: M.unsupportedAction };
    case 'CREDENTIAL_PARTIAL_MASK_FORBIDDEN': return { message: M.credentialPartial };
    case 'INVALID_POLICY_VERSION': return { message: M.invalidVersion, refetch: 'policies' };
    case 'INVALID_POLICY_STATUS': return { message: M.invalidStatus, refetch: 'policies' };
    case 'NOT_FOUND': return { message: M.notFound, refetch: 'policies' };
    case 'VERSION_CONFLICT': return { message: M.versionConflict, refetch: 'policies-history', versionConflict: true };
    case 'CONFLICT': return { message: M.duplicate, refetch: 'policies' };
    case 'POLICY_UPSTREAM_INVALID_RESPONSE': return { message: M.upstreamInvalid };
    case 'POLICY_UPSTREAM_SERVER_ERROR': return { message: M.upstreamServerError, refetch: 'policies' };
    case 'POLICY_INTEGRATION_UNAVAILABLE': return { message: M.integrationUnavailable };
    case 'POLICY_UPSTREAM_UNAVAILABLE':
    case 'POLICY_UNAVAILABLE': return { message: M.upstreamUnavailable, refetch: 'policies' };
    default: break;
  }
  // 서버 코드가 없거나 모르는 코드: 상태로만 판단할 수 있는 것만 정하고 나머지는 기존 문구
  if (error.status === 401) return { message: M.unauthorized };
  if (error.status === 404) return { message: M.notFound, refetch: 'policies' };
  if (error.status === 409) return context === 'create'
    ? { message: M.duplicate, refetch: 'policies' }
    : { message: M.versionConflict, refetch: 'policies-history', versionConflict: true };
  return { message: safeMessage(error) };
}
