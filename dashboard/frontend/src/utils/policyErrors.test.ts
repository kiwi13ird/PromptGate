// 정책 오류 문구표(설계 3.4, 15행)가 서버 코드마다 정확히 나오는지. 서버의 영어 메시지·코드는 화면 글자에 나오지 않는다.
import { describe, expect, it } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { serverError } from '@/src/test/policyFixtures';
import { POLICY_ERROR_MESSAGES as M, policyErrorInfo } from './policyErrors';
import { safeMessage } from './feedback';

describe('policy error messages by server code', () => {
  it.each([
    [401, 'UNAUTHORIZED', 'update', M.unauthorized, undefined],
    [400, 'BAD_REQUEST', 'create', M.badRequest, undefined],
    [400, 'VALIDATION', 'update', M.badRequest, undefined],
    [422, 'UNSUPPORTED_POLICY_TARGET', 'create', M.unsupportedTarget, 'capabilities'],
    [422, 'CATEGORY_POLICY_CREATE_UNSUPPORTED', 'create', M.categoryCreate, undefined],
    [422, 'UNSUPPORTED_POLICY_ACTION', 'update', M.unsupportedAction, undefined],
    [422, 'CREDENTIAL_PARTIAL_MASK_FORBIDDEN', 'create', M.credentialPartial, undefined],
    [422, 'INVALID_POLICY_VERSION', 'status', M.invalidVersion, 'policies'],
    [422, 'INVALID_POLICY_STATUS', 'status', M.invalidStatus, 'policies'],
    [404, 'NOT_FOUND', 'update', M.notFound, 'policies'],
    [409, 'VERSION_CONFLICT', 'update', M.versionConflict, 'policies-history'],
    [409, 'CONFLICT', 'create', M.duplicate, 'policies'],
    [502, 'POLICY_UPSTREAM_INVALID_RESPONSE', 'create', M.upstreamInvalid, undefined],
    [503, 'POLICY_INTEGRATION_UNAVAILABLE', 'create', M.integrationUnavailable, undefined],
    [503, 'POLICY_UPSTREAM_UNAVAILABLE', 'update', M.upstreamUnavailable, 'policies'],
    [503, 'POLICY_UNAVAILABLE', 'status', M.upstreamUnavailable, 'policies'],
  ] as const)('%s %s (%s) → message, refetch %s', (status, code, context, message, refetch) => {
    const info = policyErrorInfo(serverError(status, code), context);
    expect(info.message).toBe(message);
    expect(info.refetch).toBe(refetch);
    expect(info.message).not.toContain(code);
    expect(info.message).not.toMatch(/[A-Za-z]{4,}/);   // 영어 문장·코드 없음
  });
  it('exact wording of the design table', () => {
    expect(M.credentialPartial).toBe('자격증명은 부분 마스킹을 지원하지 않습니다. 허용·차단·전체 마스킹 중에서 고르세요.');
    expect(M.versionConflict).toBe('다른 관리자가 먼저 바꿨습니다. 최신 정책을 다시 불러왔으니 내용을 확인한 뒤 다시 변경하세요.');
    expect(M.duplicate).toBe('이 탐지 대상에는 이미 정책이 있습니다. 목록에서 수정하세요.');
    expect(M.upstreamUnavailable).toBe('탐지 서버에 연결하지 못했습니다(3초 안에 응답 없음 포함). 변경이 적용됐는지 목록에서 확인한 뒤 다시 시도하세요.');
  });
  it('only a version conflict locks the confirm button', () => {
    expect(policyErrorInfo(serverError(409, 'VERSION_CONFLICT'), 'status').versionConflict).toBe(true);
    expect(policyErrorInfo(serverError(409, 'CONFLICT'), 'create').versionConflict).toBeUndefined();
  });
  it('falls back to the status when the server sent no code (older server)', () => {
    expect(policyErrorInfo(serverError(409), 'create').message).toBe(M.duplicate);
    expect(policyErrorInfo(serverError(409), 'update')).toMatchObject({ message: M.versionConflict, versionConflict: true });
    expect(policyErrorInfo(serverError(404), 'status').message).toBe(M.notFound);
  });
  it('unknown codes, network errors and timeouts keep the existing status wording', () => {
    const unknown = serverError(422, 'POLICY_UPSTREAM_ERROR');
    expect(policyErrorInfo(unknown, 'create').message).toBe(safeMessage(unknown));
    const network = new ApiError('네트워크 연결을 확인해주세요.', 'NETWORK');
    expect(policyErrorInfo(network, 'update').message).toBe(safeMessage(network));
    const timeout = new ApiError('x', 'TIMEOUT');
    expect(policyErrorInfo(timeout, 'status').message).toBe(safeMessage(timeout));
    expect(policyErrorInfo(new Error('Credentials require full masking'), 'create').message).toBe(safeMessage());
  });
});
