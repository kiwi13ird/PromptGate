// 정책 API 연결(2026-10-15): 응답 스키마(4종 정규화·선택지), 공용 httpClient의 서버 오류 코드, HTTP 경로·본문, 예시 연결의 서버 규칙.
// 설계 docs/design/policy-ui-2026-10-15.md 5절 시험 1·2·4·5.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ApiError } from './errors';
import { httpClient } from './httpClient';
import { httpGatewayApi } from './httpAdapter';
import { mapAuditLogDto, mapPolicyDto } from './mappers';
import { mockGatewayApi } from './mockAdapter';
import { auditLogSchema, parseApiResponse, policyCapabilitiesSchema, policySchema, policyVersionSchema } from './schemas';
import { policyCapabilitiesPayload } from '@/src/mocks/policyCapabilities.fixture';
import { capabilitiesFixture, policyDto } from '@/src/test/policyFixtures';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
async function failure(promise: Promise<unknown>): Promise<ApiError> {
  try { await promise; } catch (caught) { return caught as ApiError; }
  throw new Error('expected a failure');
}

describe('policy schema: four policy actions, legacy values read only', () => {
  it.each([
    ['ALLOW_NOTIFY', 'ALLOW', 'ALLOW'], ['BLOCK_NOTIFY', 'BLOCK', 'BLOCK'], ['MASK', 'MASK_FULL', 'MASK'], ['ALLOW_DEGRADED', 'ALLOW', 'ALLOW'],
    ['MASK_PARTIAL', 'MASK_PARTIAL', 'MASK'], ['MASK_FULL', 'MASK_FULL', 'MASK'], ['ALLOW', 'ALLOW', 'ALLOW'], ['BLOCK', 'BLOCK', 'BLOCK'],
  ])('%s → %s (color family %s kept)', (raw, four, family) => {
    const policy = mapPolicyDto(parseApiResponse(policySchema, policyDto('POL-1', 'EMAIL_ADDRESS', raw, 1)));
    expect(policy).toMatchObject({ policyAction: four, finalPolicyAction: four, recommendedPolicyAction: four, action: family, actionVariant: raw });
    const [version] = parseApiResponse(z.array(policyVersionSchema), [{ version: 1, action: raw, enabled: true, created_at: '2026-10-14T09:00:00Z', changed_by: 'a' }]);
    expect(version).toMatchObject({ policy_action: four, action: family });
  });
  it('rejects an unknown action instead of treating it as allowed', () => {
    expect(() => parseApiResponse(policySchema, policyDto('POL-1', 'PII', 'QUARANTINE', 1))).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });
  it('keeps the configured action separate from the enforced one', () => {
    const policy = mapPolicyDto(parseApiResponse(policySchema, { ...policyDto('POL-1', 'PASSWORD', 'MASK_PARTIAL', 1), enforcement_action: 'MASK_FULL' }));
    expect(policy.policyAction).toBe('MASK_PARTIAL');
    expect(policy.finalPolicyAction).toBe('MASK_FULL');
  });
});

describe('capabilities schema (server policy-capabilities.mjs shape)', () => {
  it('reads the real response: 13 targets, 11 creatable, credentials without partial masking, extra warnings kept', () => {
    const caps = capabilitiesFixture();
    expect(caps).toMatchObject({ catalogVersion: '2026-10-14.2', runtimeVerified: false, fullMasking: 'ENTITY_PLACEHOLDER', createsRecognizer: false });
    expect(caps.targets).toHaveLength(13);
    expect(caps.targets.filter((target) => target.canCreate)).toHaveLength(11);
    expect(caps.warnings).toHaveLength(4);
    for (const code of ['CREDENTIAL', 'GITHUB_TOKEN', 'GENERIC_API_KEY', 'PASSWORD'])
      expect(caps.targets.find((target) => target.code === code)?.allowedActions).toEqual(['ALLOW', 'BLOCK', 'MASK_FULL']);
    expect(caps.targets.find((target) => target.code === 'EMAIL_ADDRESS')).toMatchObject({ partialMasking: '아이디 일부 가림, 도메인 유지', requiresContext: false, targetType: 'ENTITY_TYPE' });
    expect(caps.targets.find((target) => target.code === 'PASSWORD')).toMatchObject({ partialMasking: undefined, requiresContext: true });
    expect(caps.targets.find((target) => target.code === 'PII')).toMatchObject({ targetType: 'CATEGORY', canCreate: false });
  });
  it('rejects a target without allowed_actions or with an unknown action', () => {
    const missing = policyCapabilitiesPayload() as unknown as { targets: Array<Record<string, unknown>> };
    delete missing.targets[2].allowed_actions;
    expect(() => parseApiResponse(policyCapabilitiesSchema, missing)).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
    const unknown = policyCapabilitiesPayload() as unknown as { targets: Array<Record<string, unknown>> };
    unknown.targets[2].allowed_actions = ['ALLOW', 'QUARANTINE'];
    expect(() => parseApiResponse(policyCapabilitiesSchema, unknown)).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
    const empty = policyCapabilitiesPayload() as unknown as { targets: Array<Record<string, unknown>> };
    empty.targets[2].allowed_actions = [];
    expect(() => parseApiResponse(policyCapabilitiesSchema, empty)).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });
});

describe('audit rows keep partial vs full masking', () => {
  it('keeps the color family and adds the four-way name', () => {
    const row = parseApiResponse(auditLogSchema, { audit_id: 'a-1', occurred_at: '2026-10-15T01:00:00Z', admin_id: 'local-admin', action: 'POLICY_UPDATE', target_type: 'POLICY', target_id: 'POLICY-PII-MASK', result: 'SUCCESS',
      changes: { previous_version: 1, new_version: 2, previous_action: 'MASK_FULL', new_action: 'MASK_PARTIAL' } });
    const mapped = mapAuditLogDto(row as never);
    expect(mapped.changes).toMatchObject({ previousAction: 'MASK', newAction: 'MASK', previousPolicyAction: 'MASK_FULL', newPolicyAction: 'MASK_PARTIAL' });
    const legacy = mapAuditLogDto(parseApiResponse(auditLogSchema, { audit_id: 'a-2', occurred_at: '2026-10-15T01:00:00Z', admin_id: 'x', action: 'POLICY_UPDATE', target_type: 'POLICY', target_id: 'P', result: 'SUCCESS',
      changes: { previous_action: 'MASK', new_action: 'BLOCK_NOTIFY' } }) as never);
    expect(legacy.changes).toMatchObject({ previousAction: 'MASK', newAction: 'BLOCK', previousPolicyAction: 'MASK_FULL', newPolicyAction: 'BLOCK' });
    const none = mapAuditLogDto(parseApiResponse(auditLogSchema, { audit_id: 'a-3', occurred_at: '2026-10-15T01:00:00Z', admin_id: 'x', action: 'POLICY_ENABLE', target_type: 'POLICY', target_id: 'P', result: 'SUCCESS',
      changes: { previous_version: 1, new_version: 2 } }) as never);
    expect(none.changes).not.toHaveProperty('previousPolicyAction', expect.anything());
  });
});

describe('shared httpClient keeps the server error code (backward compatible)', () => {
  it('reads error.code from the body into serverCode, status mapping unchanged', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: { code: 'CREDENTIAL_PARTIAL_MASK_FORBIDDEN', message: 'Credentials require full masking…' } }, 422)));
    const error = await failure(httpClient.post('/api/policies', { detection_target: 'PASSWORD', action: 'MASK_PARTIAL' }));
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ code: 'VALIDATION', status: 422, serverCode: 'CREDENTIAL_PARTIAL_MASK_FORBIDDEN', message: '요청을 처리하지 못했습니다.' });
    expect(String(error.message)).not.toContain('Credentials');   // 서버 영어 메시지는 담지 않음
  });
  it.each([
    [409, { error: { code: 'VERSION_CONFLICT' } }, 'CONFLICT', 'VERSION_CONFLICT'],
    [409, { error: { code: 'CONFLICT' } }, 'CONFLICT', 'CONFLICT'],
    [404, { detail: { code: 'NOT_FOUND' } }, 'NOT_FOUND', 'NOT_FOUND'],
    [503, { error: { code: 'POLICY_UPSTREAM_UNAVAILABLE' } }, 'SERVER', 'POLICY_UPSTREAM_UNAVAILABLE'],
  ])('%s %j → code %s · serverCode %s', async (status, body, code, serverCode) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(body, status)));
    await expect(httpClient.get('/api/policies')).rejects.toMatchObject({ code, status, serverCode });
  });
  it.each([
    ['empty body', () => new Response(null, { status: 500 })],
    ['not JSON', () => new Response('<html>Bad gateway</html>', { status: 502 })],
    ['JSON without code', () => json({ error: 'x' }, 400)],
    ['code of the wrong shape', () => json({ error: { code: 'not a code; drop table' } }, 400)],
    ['code not a string', () => json({ error: { code: 7 } }, 400)],
  ])('%s → no serverCode, same code/status as before', async (_name, response) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response()));
    const error = await failure(httpClient.get('/api/events'));
    expect(error).toBeInstanceOf(ApiError);
    expect(error.serverCode).toBeUndefined();
    expect('serverCode' in error).toBe(false);   // 다른 화면의 오류 객체 모양 불변
    expect([error.code, error.status]).toEqual([(error.status ?? 0) >= 500 ? 'SERVER' : 'VALIDATION', error.status]);
  });
});

describe('policy HTTP paths and bodies', () => {
  it('sends four-way codes, expected_version, and reads capabilities', async () => {
    const policy = policyDto('POLICY-EMAIL_ADDRESS-1', 'EMAIL_ADDRESS', 'MASK_PARTIAL', 1);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(policyCapabilitiesPayload()))
      .mockResolvedValueOnce(json(policy, 201))
      .mockResolvedValueOnce(json({ ...policy, action: 'MASK_FULL', version: 2 }))
      .mockResolvedValueOnce(json({ ...policy, enabled: false, version: 3 }));
    vi.stubGlobal('fetch', fetchMock);
    const caps = await httpGatewayApi.getPolicyCapabilities();
    expect(caps.targets).toHaveLength(13);
    const created = await httpGatewayApi.createPolicy('EMAIL_ADDRESS', 'MASK_PARTIAL');
    expect(created.policy_action).toBe('MASK_PARTIAL');
    await httpGatewayApi.updatePolicy('POLICY-EMAIL_ADDRESS-1', 'MASK_FULL', 1);
    await httpGatewayApi.changePolicyStatus('POLICY-EMAIL_ADDRESS-1', false, 2);
    const calls = fetchMock.mock.calls as Array<[URL, RequestInit]>;
    expect([calls[0][1].method, new URL(calls[0][0]).pathname]).toEqual(['GET', '/api/policies/capabilities']);
    expect([calls[1][1].method, new URL(calls[1][0]).pathname]).toEqual(['POST', '/api/policies']);
    expect(JSON.parse(calls[1][1].body as string)).toEqual({ detection_target: 'EMAIL_ADDRESS', action: 'MASK_PARTIAL' });
    expect([calls[2][1].method, new URL(calls[2][0]).pathname]).toEqual(['PATCH', '/api/policies/POLICY-EMAIL_ADDRESS-1']);
    expect(JSON.parse(calls[2][1].body as string)).toEqual({ action: 'MASK_FULL', expected_version: 1 });
    expect([calls[3][1].method, new URL(calls[3][0]).pathname]).toEqual(['PATCH', '/api/policies/POLICY-EMAIL_ADDRESS-1/status']);
    expect(JSON.parse(calls[3][1].body as string)).toEqual({ enabled: false, expected_version: 2 });
  });
  it('fails the capabilities read on a malformed catalog (so the screen turns writes off)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ catalog_version: 'x', runtime_verified: false, targets: [] })));
    await expect(httpGatewayApi.getPolicyCapabilities()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
});

describe('example adapter follows the server rules', () => {
  beforeEach(() => { vi.spyOn(Math, 'random').mockReturnValue(0); });
  it.each([
    ['PII', 'MASK_FULL', 'CATEGORY_POLICY_CREATE_UNSUPPORTED'],
    ['API_KEY', 'BLOCK', 'UNSUPPORTED_POLICY_TARGET'],
    ['PASSWORD', 'MASK_PARTIAL', 'CREDENTIAL_PARTIAL_MASK_FORBIDDEN'],
    ['KR_RRN', 'QUARANTINE', 'UNSUPPORTED_POLICY_ACTION'],
  ])('create %s %s → 422 %s', async (target, action, serverCode) => {
    await expect(mockGatewayApi.createPolicy(target, action as never)).rejects.toMatchObject({ status: 422, code: 'VALIDATION', serverCode });
  });
  it('creates an item policy with the four-way code and records it in the audit log', async () => {
    const created = await mockGatewayApi.createPolicy('KR_POSTAL_CODE', 'MASK_PARTIAL');
    expect(created).toMatchObject({ detection_target: 'KR_POSTAL_CODE', policy_action: 'MASK_PARTIAL', action: 'MASK', version: 1 });
    const logs = await mockGatewayApi.getAuditLogs({ period: '7D', action: 'POLICY_CREATE', result: 'ALL', admin: '', page: 1, pageSize: 5 } as never);
    expect(logs.items[0].changes).toMatchObject({ new_policy_action: 'MASK_PARTIAL' });
    await expect(mockGatewayApi.createPolicy('kr_postal_code', 'BLOCK')).rejects.toMatchObject({ status: 409, serverCode: 'CONFLICT' });
  });
  it('status change bumps the version like Detection and rejects a stale version', async () => {
    const created = await mockGatewayApi.createPolicy('KR_ADDRESS', 'BLOCK');
    const off = await mockGatewayApi.changePolicyStatus(created.policy_id, false, 1);
    expect(off).toMatchObject({ enabled: false, version: 2 });
    await expect(mockGatewayApi.changePolicyStatus(created.policy_id, true, 1)).rejects.toMatchObject({ status: 409, serverCode: 'VERSION_CONFLICT' });
    const history = await mockGatewayApi.getPolicyHistory(created.policy_id);
    expect(history.map((row) => [row.version, row.policy_action, row.enabled])).toEqual([[1, 'BLOCK', true], [2, 'BLOCK', false]]);
    await expect(mockGatewayApi.updatePolicy('NO-SUCH', 'BLOCK', 1)).rejects.toMatchObject({ status: 404, serverCode: 'NOT_FOUND' });
  });
});
