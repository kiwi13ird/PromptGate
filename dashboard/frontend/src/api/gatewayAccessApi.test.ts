import { afterEach, describe, expect, it, vi } from 'vitest';
import { MOCK_GATEWAY_APPLY_MS, mockGatewayApi } from './mockAdapter';
import { httpGatewayApi } from './httpAdapter';
import { gatewayAccessResponseSchema, clientAliasesResponseSchema } from './gatewayAccessSchemas';
import { readAuditRows } from './schemas';

// 접속 차단 API(2026-10-12): 데모 어댑터와 실제 HTTP 어댑터. 확장 ID·IP·시각은 모두 가짜.
const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';
const ID_B = 'chrome-9b1e4d7c-2a6f-4c3b-8e05-7f2d9a6c4b18';
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const RULE = '1a2b3c4d-0000-4000-8000-000000000001';
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const add = (over: Record<string, unknown> = {}, expected = 0) =>
  mockGatewayApi.addAccessRule({ client_id: ID_A, reasons: ['INVESTIGATION'], duration: '1d', expected_version: expected, ...over } as never);

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('demo adapter: access rules', () => {
  it('starts empty and returns a document the contract accepts', async () => {
    const empty = await mockGatewayApi.getGatewayAccess();
    expect(gatewayAccessResponseSchema.safeParse(empty).success).toBe(true);
    expect(empty).toMatchObject({ version: 0, revision: null, require_client_id: false, rules: [] });
  });

  it('adds a rule as a new version with the requested duration and keeps reasons and memo', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-12T05:00:00.000Z'));
    expect(await add({ duration: '1h', reasons: ['LEAVE', 'OTHER'], memo: '  메모  ' })).toEqual({ version: 1 });
    const saved = await mockGatewayApi.getGatewayAccess();
    expect(saved.version).toBe(1);
    expect(saved.revision).toMatch(/^[0-9a-f-]{36}$/);
    expect(saved.rules).toHaveLength(1);
    expect(saved.rules[0]).toMatchObject({
      client_id: ID_A, reasons: ['LEAVE', 'OTHER'], memo: '메모', expires_at: '2026-10-12T06:00:00.000Z',
      created_by: 'admin-001', removed_at: null, active: true,
    });
    expect(gatewayAccessResponseSchema.safeParse(saved).success).toBe(true);
    await mockGatewayApi.removeAccessRule(saved.rules[0].id, 1);
    expect((await add({ duration: '1d' }, 2)).version).toBe(3);
    expect((await mockGatewayApi.getGatewayAccess()).rules.at(-1)?.expires_at).toBe('2026-10-13T05:00:00.000Z');
    expect((await add({ client_id: ID_B, duration: 'permanent' }, 3)).version).toBe(4);
    expect((await mockGatewayApi.getGatewayAccess()).rules.at(-1)?.expires_at).toBeNull();
  });

  it('rejects an old version (409) and a second active rule for the same id (409)', async () => {
    await add();
    await expect(add({}, 0)).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });   // 번호가 이미 1
    await expect(add({}, 1)).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });   // 같은 ID에 이미 차단 중
    expect((await add({ client_id: ID_B }, 1)).version).toBe(2);
  });

  it('rejects invalid input with 422 before changing anything', async () => {
    for (const bad of [{ reasons: [] }, { reasons: ['OTHER'] }, { client_id: 'unknown-client' }, { duration: '2d' }, { memo: 'a'.repeat(201) }])
      await expect(add(bad)).rejects.toMatchObject({ code: 'VALIDATION', status: 422 });
    expect((await mockGatewayApi.getGatewayAccess()).version).toBe(0);
  });

  it('removes (unblocks) a rule into a new version and keeps the record as removed', async () => {
    await add();
    const before = await mockGatewayApi.getGatewayAccess();
    await expect(mockGatewayApi.removeAccessRule(before.rules[0].id, 0)).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(mockGatewayApi.removeAccessRule(RULE, 1)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(await mockGatewayApi.removeAccessRule(before.rules[0].id, 1)).toEqual({ version: 2 });
    const after = await mockGatewayApi.getGatewayAccess();
    expect(after.rules[0]).toMatchObject({ removed_by: 'admin-001', active: false });
    expect(after.rules[0].removed_at).toMatch(/^2026|^20\d\d-/);
    await expect(mockGatewayApi.removeAccessRule(before.rules[0].id, 2)).rejects.toMatchObject({ code: 'NOT_FOUND' });   // 이미 해제됨
    expect((await add({}, 2)).version).toBe(3);   // 해제한 ID는 다시 차단할 수 있다
  });

  it('marks an expired rule inactive without a new version', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-12T05:00:00.000Z'));
    await add({ duration: '1h' });
    vi.setSystemTime(new Date('2026-10-12T06:00:01.000Z'));
    const later = await mockGatewayApi.getGatewayAccess();
    expect(later.version).toBe(1);
    expect(later.rules[0].active).toBe(false);
    expect(later.rules[0].removed_at).toBeNull();
    expect((await add({}, 1)).version).toBe(2);   // 만료된 규칙이 있어도 다시 차단할 수 있다
  });

  it('changes the no-id mode with a version check and records it', async () => {
    await expect(mockGatewayApi.setAccessMode({ require_client_id: true, expected_version: 3 })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await mockGatewayApi.setAccessMode({ require_client_id: true, expected_version: 0 })).toEqual({ version: 1 });
    expect((await mockGatewayApi.getGatewayAccess()).require_client_id).toBe(true);
    await add({}, 1);   // 방식은 규칙 추가로 바뀌지 않는다
    expect((await mockGatewayApi.getGatewayAccess()).require_client_id).toBe(true);
    await mockGatewayApi.setAccessMode({ require_client_id: false, expected_version: 2 });
    expect((await mockGatewayApi.getGatewayAccess()).require_client_id).toBe(false);
    await expect(mockGatewayApi.setAccessMode({ require_client_id: 'yes', expected_version: 3 } as never)).rejects.toMatchObject({ code: 'VALIDATION' });
  });

  it('reports the gateway as applied only after the demo delay, as pending before', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-12T05:00:00.000Z'));
    expect((await mockGatewayApi.getGatewayAccess()).applied).toMatchObject({ source: 'NONE', version: null });
    await add();
    expect((await mockGatewayApi.getGatewayAccess()).applied).toMatchObject({ source: 'NONE', version: null, active_rules: 0 });
    vi.setSystemTime(new Date(Date.parse('2026-10-12T05:00:00.000Z') + MOCK_GATEWAY_APPLY_MS));
    const applied = (await mockGatewayApi.getGatewayAccess()).applied;
    expect(applied).toMatchObject({ source: 'DASHBOARD', version: 1, active_rules: 1, require_client_id: false, denied_5m: 0, rejected: null });
  });

  it('writes audit rows for add, remove, mode and alias, all with target type GATEWAY', async () => {
    await add();
    const rule = (await mockGatewayApi.getGatewayAccess()).rules[0];
    await mockGatewayApi.removeAccessRule(rule.id, 1);
    await mockGatewayApi.setAccessMode({ require_client_id: true, expected_version: 2 });
    await mockGatewayApi.setClientAlias(ID_A, '홍길동 PC');
    await mockGatewayApi.setClientAlias(ID_A, '');
    const page = await mockGatewayApi.getAuditLogs({ period: '24H', action: 'ALL', result: 'ALL', admin: '', page: 1, pageSize: 50 });
    const access = page.items.filter(row => /^(ACCESS_|CLIENT_ALIAS)/.test(row.action));
    expect(access.map(row => row.action).sort()).toEqual(['ACCESS_MODE_UPDATE', 'ACCESS_RULE_ADD', 'ACCESS_RULE_REMOVE', 'CLIENT_ALIAS_UPDATE', 'CLIENT_ALIAS_UPDATE']);
    for (const row of access) expect(row.target_type).toBe('GATEWAY');
    const added = access.find(row => row.action === 'ACCESS_RULE_ADD');
    expect(added).toMatchObject({ target_id: rule.id, changes: { new_version: 1 } });
    expect(added?.changes?.new_value).toContain(ID_A);
    expect(added?.changes?.new_value).toContain('보안 조사 중');
    // 화면의 감사 로그 읽기가 새 작업 이름을 모두 받는다
    const read = readAuditRows({ items: page.items, total: page.total, page: 1, page_size: 50, total_pages: 1 });
    expect(read.items).toHaveLength(page.items.length);
    expect(read).not.toHaveProperty('skipped');
  });
});

describe('demo adapter: aliases', () => {
  it('sets, lists, overwrites and deletes an alias', async () => {
    expect((await mockGatewayApi.getClientAliases()).items).toEqual([]);
    await mockGatewayApi.setClientAlias(ID_A, ' 홍길동 PC ');
    await mockGatewayApi.setClientAlias(ID_B, '회의실 노트북');
    expect(clientAliasesResponseSchema.parse(await mockGatewayApi.getClientAliases()).items).toEqual([
      { client_id: ID_A, alias: '홍길동 PC' }, { client_id: ID_B, alias: '회의실 노트북' },
    ]);
    await mockGatewayApi.setClientAlias(ID_A, '김철수 PC');
    await mockGatewayApi.setClientAlias(ID_B, '');   // 빈 별칭은 지운다
    expect((await mockGatewayApi.getClientAliases()).items).toEqual([{ client_id: ID_A, alias: '김철수 PC' }]);
    await expect(mockGatewayApi.setClientAlias(ID_A, 'a'.repeat(41))).rejects.toMatchObject({ code: 'VALIDATION' });
  });
});

describe('real http adapter: access', () => {
  it('reads the document and the aliases with the session cookie', async () => {
    const body = { version: 5, revision: REV, require_client_id: false, rules: [], applied: null };
    const fetchMock = vi.fn().mockResolvedValueOnce(json(body)).mockResolvedValueOnce(json({ items: [{ client_id: ID_A, alias: '홍길동 PC' }] }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(httpGatewayApi.getGatewayAccess()).resolves.toMatchObject({ version: 5, applied: null });
    await expect(httpGatewayApi.getClientAliases()).resolves.toEqual({ items: [{ client_id: ID_A, alias: '홍길동 PC' }] });
    const [[first, firstInit], [second]] = fetchMock.mock.calls as Array<[URL, RequestInit]>;
    expect(new URL(String(first)).pathname).toBe('/api/gateway-access');
    expect(firstInit).toMatchObject({ method: 'GET', credentials: 'include' });
    expect(new URL(String(second)).pathname).toBe('/api/client-aliases');
  });

  it('posts exactly the contract fields for a new rule and reads the new version from the reply', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ version: 6 }, 201));
    vi.stubGlobal('fetch', fetchMock);
    await expect(httpGatewayApi.addAccessRule({ client_id: ID_A, reasons: ['LEAVE', 'OTHER'], memo: '메모', duration: 'permanent', expected_version: 5 })).resolves.toEqual({ version: 6 });
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(new URL(String(url)).pathname).toBe('/api/gateway-access/rules');
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({ client_id: ID_A, reasons: ['LEAVE', 'OTHER'], memo: '메모', duration: 'permanent', expected_version: 5 });
  });

  it('does not send a rule that breaks the contract', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const base = { client_id: ID_A, reasons: ['LEAVE'], duration: '1d', expected_version: 5 };
    for (const bad of [{ reasons: [] }, { reasons: ['OTHER'] }, { client_id: 'legacy-gateway' }, { duration: '1w' }, { extra: 1 }])
      await expect(httpGatewayApi.addAccessRule({ ...base, ...bad } as never)).rejects.toMatchObject({ code: 'VALIDATION' });
    await expect(httpGatewayApi.removeAccessRule(RULE, -1)).rejects.toMatchObject({ code: 'VALIDATION' });
    await expect(httpGatewayApi.setAccessMode({ require_client_id: 1, expected_version: 5 } as never)).rejects.toMatchObject({ code: 'VALIDATION' });
    await expect(httpGatewayApi.setClientAlias(ID_A, 'a'.repeat(41))).rejects.toMatchObject({ code: 'VALIDATION' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('deletes a rule with expected_version in the query and reads an empty 204 reply', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(httpGatewayApi.removeAccessRule(RULE, 7)).resolves.toEqual({ version: null });
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(new URL(String(url)).pathname).toBe(`/api/gateway-access/rules/${RULE}`);
    expect(new URL(String(url)).search).toBe('?expected_version=7');
    expect(init.method).toBe('DELETE');
    expect(init.body).toBeUndefined();
  });

  it('puts the mode and the alias; an empty alias is sent to delete it', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => json({}));   // 응답 본문은 한 번만 읽을 수 있어 호출마다 새로 만든다
    vi.stubGlobal('fetch', fetchMock);
    await expect(httpGatewayApi.setAccessMode({ require_client_id: true, expected_version: 5 })).resolves.toEqual({ version: null });
    await httpGatewayApi.setClientAlias(ID_A, '홍길동 PC');
    await httpGatewayApi.setClientAlias('chrome-a/b', '');
    const calls = fetchMock.mock.calls as Array<[URL, RequestInit]>;
    expect(new URL(String(calls[0][0])).pathname).toBe('/api/gateway-access/mode');
    expect(calls[0][1].method).toBe('PUT');
    expect(JSON.parse(String(calls[0][1].body))).toEqual({ require_client_id: true, expected_version: 5 });
    expect(new URL(String(calls[1][0])).pathname).toBe(`/api/client-aliases/${ID_A}`);
    expect(JSON.parse(String(calls[1][1].body))).toEqual({ alias: '홍길동 PC' });
    expect(new URL(String(calls[2][0])).pathname).toBe('/api/client-aliases/chrome-a%2Fb');
    expect(JSON.parse(String(calls[2][1].body))).toEqual({ alias: '' });
  });

  it.each([
    [409, 'CONFLICT'],
    [422, 'VALIDATION'],
    [404, 'NOT_FOUND'],
    [503, 'SERVER'],
  ])('maps %s to %s', async (status, code) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'x' }, status)));
    await expect(httpGatewayApi.addAccessRule({ client_id: ID_A, reasons: ['LEAVE'], duration: '1d', expected_version: 5 })).rejects.toMatchObject({ code, status });
    await expect(httpGatewayApi.getGatewayAccess()).rejects.toMatchObject({ code, status });
  });

  it('rejects a document that does not match the contract', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ version: 5, revision: REV, require_client_id: false })));
    await expect(httpGatewayApi.getGatewayAccess()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ items: [{ client_id: ID_A }] })));
    await expect(httpGatewayApi.getClientAliases()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
});
