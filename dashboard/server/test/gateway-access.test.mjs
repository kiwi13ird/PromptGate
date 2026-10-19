// 접속 차단(2026-10-12): 확장 ID 차단 목록·'확장 ID 없는 접속 차단' 방식·ID 별칭, 지표 응답으로 전달, 적용 보고, 이벤트 accessRuleId
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createAppServer } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import {
  ACCESS_DOCUMENT_MAX_BYTES,
  ACCESS_INACTIVE_KEEP,
  ACCESS_RULE_LIMIT,
  ALIAS_LIMIT,
  BLOCK_REASONS,
  gatewayAccessDocument,
  gatewayAccessState,
  ownAccessReasonCode,
  ownBlockDetails,
  parseAccessApplied,
  parseRuleCreate,
  pruneRules,
  ruleIsActive,
  summarizeRule,
} from '../gateway-access.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';
import { canonicalEventToDto, validateCanonicalEvent } from '../validation.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-access@example.test',
  adminPassword: 'local-password-access-tests',
  ingestToken: 'local-ingest-token-access-tests',
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REV = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const CHROME = (n) => `chrome-00000000-0000-4000-9000-${String(n).padStart(12, '0')}`;
const DOCUMENT_FIELDS = ['version', 'revision', 'updated_at', 'require_client_id', 'rules'];
const RULE_VIEW_FIELDS = ['id', 'client_id', 'reasons', 'memo', 'show_memo_to_user', 'expires_at', 'created_by', 'created_at', 'removed_by', 'removed_at', 'active'];
const metrics = (over = {}) => ({
  active_clients: 1, concurrent_requests: 0, requests_per_sec: 0.2, avg_latency_ms: 30, p95_latency_ms: 80, timeout_rate: 0, degraded_rate: 0,
  total_requests: 5, completed_requests: 5, error_requests: 0, action_distribution: {}, llm_distribution: {}, detector_distribution: {}, window_seconds: 300, ...over,
});
const addBody = (over = {}) => ({ client_id: CHROME(1), reasons: ['INVESTIGATION'], duration: '1h', expected_version: 0, ...over });
const reported = (over = {}) => ({
  version: null, revision: null, source: 'NONE', applied_at: '2026-10-12T05:00:00Z', rejected: null, active_rules: 0, require_client_id: false, denied_5m: 0, ...over,
});

async function withBackend(run, { store, makeStore, retryMs, seed } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-access-'));
  const storePath = path.join(root, 'events.json');
  if (seed) await writeFile(storePath, JSON.stringify({ version: 1, records: [], auditRecords: [], gatewaySettings: [], clientAliases: [], ...seed }));
  const server = createAppServer({
    ...CONFIG,
    ...(store ? { store } : makeStore ? { store: makeStore(storePath) } : { storePath }),
    ...(retryMs ? { gatewaySettingsRetryMs: retryMs } : {}),
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const call = async (method, pathname, payload, { session = true, headers = {}, raw } = {}) => {
      const response = await fetch(`${base}${pathname}`, {
        method,
        headers: { ...(payload !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(session ? { Cookie: cookie } : {}), ...headers },
        body: raw ?? (payload === undefined ? undefined : JSON.stringify(payload)),
      });
      return { status: response.status, headers: response.headers, json: response.status === 204 ? null : await response.json() };
    };
    const state = () => call('GET', '/api/gateway-access');
    const add = (payload) => call('POST', '/api/gateway-access/rules', payload);
    const remove = (id, version) => call('DELETE', `/api/gateway-access/rules/${id}${version === undefined ? '' : `?expected_version=${version}`}`);
    const mode = (payload) => call('PUT', '/api/gateway-access/mode', payload);
    const aliases = () => call('GET', '/api/client-aliases');
    const setAlias = (clientId, alias) => call('PUT', `/api/client-aliases/${encodeURIComponent(clientId)}`, { alias });
    const report = (payload) => call('POST', '/api/traffic/metrics', payload, { session: false, headers: { Authorization: `Bearer ${CONFIG.ingestToken}` } });
    const ingest = (payload) => call('POST', '/api/events/ingest', payload, { session: false, headers: { Authorization: `Bearer ${CONFIG.ingestToken}` } });
    const audits = async (...actions) => (await call('GET', '/api/audit-logs?period=24H&page_size=100')).json.items.filter((item) => actions.includes(item.action));
    await run({ base, storePath, call, state, add, remove, mode, aliases, setAlias, report, ingest, audits });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

const minutes = (n) => n * 60_000;
const seededRow = (rules, over = {}) => ({ version: 1, revision: REV(1), require_client_id: false, rules, updated_by: 'local-admin', updated_at: '2026-10-12T00:00:00.000Z', ...over });
const seededRule = (n, over = {}) => ({
  id: REV(1000 + n), client_id: CHROME(n), reasons: ['OTHER'], memo: '시험', expires_at: null, created_by: 'local-admin',
  created_at: '2026-10-12T00:00:00.000Z', removed_by: null, removed_at: null, ...over,
});

void test('every endpoint needs a session and only accepts its own method', async () => {
  await withBackend(async ({ call }) => {
    const id = REV(9);
    for (const [method, pathname, payload] of [
      ['GET', '/api/gateway-access'],
      ['POST', '/api/gateway-access/rules', addBody()],
      ['DELETE', `/api/gateway-access/rules/${id}?expected_version=0`],
      ['PUT', '/api/gateway-access/mode', { require_client_id: true, expected_version: 0 }],
      ['GET', '/api/client-aliases'],
      ['PUT', `/api/client-aliases/${CHROME(1)}`, { alias: 'x' }],
    ]) {
      assert.equal((await call(method, pathname, payload, { session: false })).status, 401, `${method} ${pathname}`);
    }
    for (const [method, pathname] of [
      ['PUT', '/api/gateway-access'], ['GET', '/api/gateway-access/rules'], ['GET', `/api/gateway-access/rules/${id}`],
      ['POST', `/api/gateway-access/rules/${id}`], ['GET', '/api/gateway-access/mode'], ['POST', '/api/client-aliases'],
      ['GET', `/api/client-aliases/${CHROME(1)}`], ['DELETE', `/api/client-aliases/${CHROME(1)}`],
    ]) {
      assert.equal((await call(method, pathname, method === 'GET' || method === 'DELETE' ? undefined : {})).status, 405, `${method} ${pathname}`);
    }
    assert.equal((await call('GET', '/api/gateway-access/unknown')).status, 404);
  });
});

void test('nothing stored yet: version 0, no rules, no applied report', async () => {
  await withBackend(async ({ state, aliases }) => {
    const first = await state();
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('cache-control'), 'no-store');
    assert.deepEqual(Object.keys(first.json), ['version', 'revision', 'require_client_id', 'rules', 'applied', 'gateway']);
    assert.deepEqual(first.json, {
      version: 0, revision: null, require_client_id: false, rules: [], applied: null,
      gateway: { state: 'NOT_REPORTING', metrics_status: 'NOT_RECEIVED', reported_at: null },
    });
    assert.deepEqual((await aliases()).json, { items: [] });
  });
});

void test('adding a rule rejects bad requests with 415, 400, 422 and 409 and records nothing', async () => {
  await withBackend(async ({ call, add, state, audits }) => {
    assert.equal((await call('POST', '/api/gateway-access/rules', undefined, { headers: { 'Content-Type': 'text/plain' }, raw: JSON.stringify(addBody()) })).status, 415);
    assert.equal((await call('POST', '/api/gateway-access/rules', undefined, { headers: { 'Content-Type': 'application/json' }, raw: '{broken' })).status, 400);
    assert.equal((await call('POST', '/api/gateway-access/rules', undefined, { headers: { 'Content-Type': 'application/json' }, raw: 'x'.repeat(17 * 1024) })).status, 413);
    // 모르는 칸·빠진 칸·객체가 아님 → 400
    for (const payload of [
      [1],
      { ...addBody(), extra: true },
      (({ duration, ...rest }) => rest)(addBody()),
      (({ reasons, ...rest }) => rest)(addBody()),
      (({ client_id, ...rest }) => rest)(addBody()),
      (({ expected_version, ...rest }) => rest)(addBody()),
      { ...addBody(), ip: '203.0.113.7' },
    ]) {
      const result = await add(payload);
      assert.equal(result.status, 400, JSON.stringify(payload));
      assert.equal(result.json.error.code, 'BAD_REQUEST');
    }
    // 값 위반 → 422 + 칸 이름
    const longMemo = '가'.repeat(201);
    for (const [payload, where] of [
      [addBody({ client_id: '' }), 'client_id'],
      [addBody({ client_id: '-abc' }), 'client_id'],
      [addBody({ client_id: 'chrome abc' }), 'client_id'],
      [addBody({ client_id: 'chrome/abc' }), 'client_id'],
      [addBody({ client_id: 'a'.repeat(81) }), 'client_id'],
      [addBody({ client_id: '홍길동' }), 'client_id'],
      [addBody({ client_id: 12 }), 'client_id'],
      [addBody({ client_id: null }), 'client_id'],
      [addBody({ reasons: [] }), 'reasons'],
      [addBody({ reasons: 'INVESTIGATION' }), 'reasons'],
      [addBody({ reasons: ['SPAM'] }), 'reasons'],
      [addBody({ reasons: ['investigation'] }), 'reasons'],
      [addBody({ reasons: [1] }), 'reasons'],
      [addBody({ reasons: Array(7).fill('LEAVE') }), 'reasons'],
      [addBody({ duration: '2h' }), 'duration'],
      [addBody({ duration: 3600 }), 'duration'],
      [addBody({ duration: '__proto__' }), 'duration'],
      [addBody({ memo: longMemo }), 'memo'],
      [addBody({ memo: 5 }), 'memo'],
      [addBody({ memo: 'a\u0000b' }), 'memo'],
      [addBody({ reasons: ['OTHER'] }), 'memo'],
      [addBody({ reasons: ['LEAVE', 'OTHER'], memo: '   ' }), 'memo'],
      // 사용자에게 메모 공개: 불리언만, 켜면 메모 필수
      [addBody({ memo: '안내', show_memo_to_user: 'true' }), 'show_memo_to_user'],
      [addBody({ memo: '안내', show_memo_to_user: 1 }), 'show_memo_to_user'],
      [addBody({ memo: '안내', show_memo_to_user: null }), 'show_memo_to_user'],
      [addBody({ show_memo_to_user: true }), 'memo'],
      [addBody({ memo: null, show_memo_to_user: true }), 'memo'],
      [addBody({ memo: '  \n ', show_memo_to_user: true }), 'memo'],
      [addBody({ expected_version: -1 }), 'expected_version'],
      [addBody({ expected_version: 1.5 }), 'expected_version'],
      [addBody({ expected_version: '0' }), 'expected_version'],
    ]) {
      const result = await add(payload);
      assert.equal(result.status, 422, where);
      assert.equal(result.json.error.code, 'VALIDATION');
      assert.equal(result.json.error.details.path, where);
    }
    const stale = await add(addBody({ expected_version: 3 }));
    assert.equal(stale.status, 409);
    assert.equal(stale.json.error.code, 'ACCESS_VERSION_CONFLICT');
    assert.deepEqual(stale.json.error.details, { current_version: 0 });
    assert.equal((await state()).json.version, 0);
    assert.deepEqual(await audits('ACCESS_RULE_ADD'), []);
  });
});

void test('a rule is stored with its reasons, memo and expiry, and the audit row says what was blocked', async () => {
  await withBackend(async ({ add, state, audits }) => {
    const before = Date.now();
    const first = await add(addBody({ reasons: ['LEAK_DOC_REPEAT', 'PII_REPEAT', 'LEAK_DOC_REPEAT'], memo: '  두 번째 경고 \n 후속 조치  ', duration: '1h' }));
    assert.equal(first.status, 201);
    assert.equal(first.json.version, 1);
    assert.match(first.json.revision, UUID);
    assert.equal(first.json.require_client_id, false);
    assert.deepEqual(Object.keys(first.json.rule), RULE_VIEW_FIELDS);
    const rule = first.json.rule;
    assert.match(rule.id, UUID);
    assert.equal(rule.client_id, CHROME(1));
    assert.deepEqual(rule.reasons, ['LEAK_DOC_REPEAT', 'PII_REPEAT']);   // 중복은 합친다
    assert.equal(rule.memo, '두 번째 경고 후속 조치');   // 한 줄로
    assert.equal(rule.show_memo_to_user, false);   // 켜지 않으면 관리자 전용
    assert.equal(rule.created_by, 'local-admin');
    assert.equal(rule.removed_at, null);
    assert.equal(rule.active, true);
    const lifetime = Date.parse(rule.expires_at) - Date.parse(rule.created_at);
    assert.equal(lifetime, 3_600_000);
    assert.ok(Date.parse(rule.created_at) >= before && Date.parse(rule.created_at) <= Date.now());
    assert.deepEqual(first.json.rules, [rule]);
    assert.deepEqual((await state()).json.rules, [rule]);

    const [row] = await audits('ACCESS_RULE_ADD');
    assert.equal(row.target_type, 'GATEWAY');
    assert.equal(row.target_id, rule.id);
    assert.equal(row.admin_id, 'local-admin');
    assert.equal(row.result, 'SUCCESS');
    assert.deepEqual(Object.keys(row.changes).sort(), ['new_value', 'new_version']);
    assert.equal(row.changes.new_version, 1);
    assert.match(row.changes.new_value, new RegExp(`^확장 ID ${CHROME(1)} · 1시간\\(\\d\\d/\\d\\d \\d\\d:\\d\\d까지\\) · 사유 기밀 문서 반복 유출 시도, 개인정보 반복 입력 · 메모 두 번째 경고 후속 조치$`));

    const day = await add(addBody({ client_id: CHROME(2), duration: '1d', expected_version: 1 }));
    assert.equal(day.status, 201);
    assert.equal(day.json.version, 2);
    assert.equal(Date.parse(day.json.rule.expires_at) - Date.parse(day.json.rule.created_at), 86_400_000);
    assert.equal(day.json.rule.memo, null);
    const forever = await add(addBody({ client_id: CHROME(3), duration: 'permanent', expected_version: 2, reasons: ['OTHER'], memo: '기타 사유' }));
    assert.equal(forever.status, 201);
    assert.equal(forever.json.rule.expires_at, null);
    const rows = await audits('ACCESS_RULE_ADD');
    assert.equal(rows.length, 3);
    const byVersion = (version) => rows.find((item) => item.changes.new_version === version);
    assert.equal(byVersion(2).changes.previous_version, 1);
    assert.match(byVersion(2).changes.new_value, /1일\(\d\d\/\d\d \d\d:\d\d까지\) · 사유 보안 조사 중$/);
    assert.equal(byVersion(3).changes.new_value, `확장 ID ${CHROME(3)} · 영구 · 사유 기타 · 메모 기타 사유`);
    // 목록은 새 규칙이 위
    assert.deepEqual((await state()).json.rules.map((item) => item.client_id), [CHROME(3), CHROME(2), CHROME(1)]);
  });
});

void test('show_memo_to_user: false by default, true is stored on the rule, shown in every GET and noted in the audit row', async () => {
  await withBackend(async ({ add, state, audits }) => {
    const hidden = await add(addBody({ client_id: CHROME(1), memo: '관리자만 보는 메모', show_memo_to_user: false }));
    assert.equal(hidden.status, 201);
    assert.equal(hidden.json.rule.show_memo_to_user, false);
    const shown = await add(addBody({ client_id: CHROME(2), reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], memo: '  담당자에게 \n 문의하세요 ', show_memo_to_user: true, expected_version: 1 }));
    assert.equal(shown.status, 201);
    assert.deepEqual(Object.keys(shown.json.rule), RULE_VIEW_FIELDS);
    assert.equal(shown.json.rule.show_memo_to_user, true);
    assert.equal(shown.json.rule.memo, '담당자에게 문의하세요');
    // 목록 응답(GET·POST 모두)에도 같은 값
    const listed = (await state()).json.rules;
    assert.deepEqual(listed.map((rule) => [rule.client_id, rule.show_memo_to_user]), [[CHROME(2), true], [CHROME(1), false]]);
    assert.deepEqual(shown.json.rules.map((rule) => rule.show_memo_to_user), [true, false]);
    // 메모 없이 생략하면 꺼진 채로 통과
    assert.equal((await add(addBody({ client_id: CHROME(3), expected_version: 2 }))).json.rule.show_memo_to_user, false);
    // 감사 행: 공개한 규칙만 '사용자에게 메모 공개'가 붙는다
    const rows = await audits('ACCESS_RULE_ADD');
    const byTarget = (rule) => rows.find((row) => row.target_id === rule.id).changes.new_value;
    assert.match(byTarget(shown.json.rule), /사유 보안 조사 중, 관리자 요청 · 메모 담당자에게 문의하세요 · 사용자에게 메모 공개$/);
    assert.match(byTarget(hidden.json.rule), /메모 관리자만 보는 메모$/);
    assert.ok(!byTarget(hidden.json.rule).includes('공개'));
  });
});

void test('parseRuleCreate: show_memo_to_user is optional, boolean, and needs a memo when true', () => {
  const body = { client_id: CHROME(1), reasons: ['LEAVE'], duration: '1h', expected_version: 0 };
  assert.equal(parseRuleCreate(body).showMemoToUser, false);
  assert.equal(parseRuleCreate({ ...body, memo: 'a', show_memo_to_user: false }).showMemoToUser, false);
  assert.equal(parseRuleCreate({ ...body, memo: 'a', show_memo_to_user: true }).showMemoToUser, true);
  assert.equal(parseRuleCreate({ ...body, show_memo_to_user: false }).memo, null);   // 메모 없이 false는 통과
  assert.throws(() => parseRuleCreate({ ...body, show_memo_to_user: true }), (error) => error.path === 'memo');
  assert.throws(() => parseRuleCreate({ ...body, memo: 'a', show_memo_to_user: 'yes' }), (error) => error.path === 'show_memo_to_user');
  assert.throws(() => parseRuleCreate({ ...body, show_memo: true }), (error) => error.statusCode === 400);   // 모르는 칸은 그대로 400
});

void test('a second active rule for the same extension id is a 409 and the version does not move', async () => {
  await withBackend(async ({ add, state, remove, audits }) => {
    const first = await add(addBody());
    const again = await add(addBody({ expected_version: 1, duration: '1d' }));
    assert.equal(again.status, 409);
    assert.equal(again.json.error.code, 'ACCESS_RULE_EXISTS');
    assert.deepEqual(again.json.error.details, { rule_id: first.json.rule.id });
    assert.equal((await state()).json.version, 1);
    assert.equal((await audits('ACCESS_RULE_ADD')).length, 1);
    // 해제하면 같은 ID를 다시 막을 수 있다(해제된 규칙은 기록으로 남는다)
    assert.equal((await remove(first.json.rule.id, 1)).status, 200);
    const third = await add(addBody({ expected_version: 2 }));
    assert.equal(third.status, 201);
    const rules = (await state()).json.rules;
    assert.equal(rules.length, 2);
    assert.deepEqual(rules.map((rule) => rule.active), [true, false]);
  });
});

void test('releasing a rule: 404, 422, 409, then the rule is kept as released history', async () => {
  await withBackend(async ({ call, add, remove, state, audits, report }) => {
    const rule = (await add(addBody({ memo: '비밀 메모' }))).json.rule;
    assert.equal((await remove('not-a-uuid', 1)).status, 404);
    assert.equal((await remove(REV(77), 1)).status, 404);
    const missing = await remove(rule.id);
    assert.equal(missing.status, 422);
    assert.equal(missing.json.error.details.path, 'expected_version');
    for (const bad of ['x', '-1', '1.5', '']) {
      assert.equal((await call('DELETE', `/api/gateway-access/rules/${rule.id}?expected_version=${bad}`)).status, 422, bad);
    }
    const stale = await remove(rule.id, 5);
    assert.equal(stale.status, 409);
    assert.equal(stale.json.error.code, 'ACCESS_VERSION_CONFLICT');
    assert.deepEqual(stale.json.error.details, { current_version: 1 });
    assert.equal((await audits('ACCESS_RULE_REMOVE')).length, 0);

    const released = await remove(rule.id, 1);
    assert.equal(released.status, 200);
    assert.equal(released.json.version, 2);
    assert.equal(released.json.rules.length, 1);
    const kept = released.json.rules[0];
    assert.equal(kept.active, false);
    assert.equal(kept.removed_by, 'local-admin');
    assert.ok(Number.isFinite(Date.parse(kept.removed_at)));
    assert.equal(kept.memo, '비밀 메모');   // 기록에는 남는다
    const [row] = await audits('ACCESS_RULE_REMOVE');
    assert.equal(row.target_type, 'GATEWAY');
    assert.equal(row.target_id, rule.id);
    assert.deepEqual(Object.keys(row.changes).sort(), ['new_version', 'previous_value', 'previous_version']);
    assert.equal(row.changes.previous_version, 1);
    assert.equal(row.changes.new_version, 2);
    assert.match(row.changes.previous_value, new RegExp(`^확장 ID ${CHROME(1)} · \\d\\d/\\d\\d \\d\\d:\\d\\d까지 · 사유 보안 조사 중 · 메모 비밀 메모$`));

    // 이미 해제된 규칙
    const second = await remove(rule.id, 2);
    assert.equal(second.status, 409);
    assert.equal(second.json.error.code, 'ACCESS_RULE_INACTIVE');
    assert.equal((await state()).json.version, 2);
    // 해제한 규칙은 Gateway 문서에서 빠진다
    const document = (await report(metrics())).json.gateway_access;
    assert.equal(document.version, 2);
    assert.deepEqual(document.rules, []);
  });
});

void test('the mode switch keeps the rules, and rules keep the mode', async () => {
  await withBackend(async ({ call, add, mode, remove, state, audits, report }) => {
    const bad = (payload) => call('PUT', '/api/gateway-access/mode', payload);
    assert.equal((await bad({ require_client_id: true })).status, 400);
    assert.equal((await bad({ expected_version: 0 })).status, 400);
    assert.equal((await bad({ require_client_id: true, expected_version: 0, extra: 1 })).status, 400);
    for (const value of ['true', 1, null]) {
      const result = await bad({ require_client_id: value, expected_version: 0 });
      assert.equal(result.status, 422);
      assert.equal(result.json.error.details.path, 'require_client_id');
    }
    assert.equal((await bad({ require_client_id: true, expected_version: -1 })).json.error.details.path, 'expected_version');
    const stale = await bad({ require_client_id: true, expected_version: 2 });
    assert.equal(stale.status, 409);
    assert.deepEqual(stale.json.error.details, { current_version: 0 });
    assert.deepEqual(await audits('ACCESS_MODE_UPDATE'), []);

    const on = await mode({ require_client_id: true, expected_version: 0 });
    assert.equal(on.status, 200);
    assert.equal(on.json.version, 1);
    assert.equal(on.json.require_client_id, true);
    assert.deepEqual(on.json.rules, []);
    const rule = (await add(addBody({ expected_version: 1 }))).json.rule;
    assert.equal((await state()).json.require_client_id, true);   // 규칙을 더해도 방식은 그대로
    assert.equal((await remove(rule.id, 2)).json.require_client_id, true);   // 해제해도 그대로
    const off = await mode({ require_client_id: false, expected_version: 3 });
    assert.equal(off.json.version, 4);
    assert.equal(off.json.rules.length, 1);   // 해제된 규칙 기록은 방식을 바꿔도 남는다
    // 같은 값으로 다시 저장해도 새 판(번호·revision)이 된다
    const same = await mode({ require_client_id: false, expected_version: 4 });
    assert.equal(same.json.version, 5);
    assert.notEqual(same.json.revision, off.json.revision);

    const rows = await audits('ACCESS_MODE_UPDATE');
    assert.equal(rows.length, 3);
    const first = rows.find((row) => row.changes.new_version === 1);
    assert.equal(first.target_type, 'GATEWAY');
    assert.equal(first.target_id, 'gateway-access');
    assert.deepEqual(first.changes, { new_version: 1, previous_value: '확장 ID 없는 접속 차단 끔', new_value: '확장 ID 없는 접속 차단 켬' });
    assert.deepEqual(rows.find((row) => row.changes.new_version === 4).changes,
      { previous_version: 3, new_version: 4, previous_value: '확장 ID 없는 접속 차단 켬', new_value: '확장 ID 없는 접속 차단 끔' });
    assert.equal((await report(metrics())).json.gateway_access.require_client_id, false);
  });
});

void test('two administrators saving at once: exactly one wins', async () => {
  await withBackend(async ({ add, state, audits }) => {
    const results = await Promise.all([add(addBody({ client_id: CHROME(1) })), add(addBody({ client_id: CHROME(2) }))]);
    assert.deepEqual(results.map((result) => result.status).sort(), [201, 409]);
    const loser = results.find((result) => result.status === 409);
    assert.equal(loser.json.error.code, 'ACCESS_VERSION_CONFLICT');
    assert.deepEqual(loser.json.error.details, { current_version: 1 });
    const current = (await state()).json;
    assert.equal(current.version, 1);
    assert.equal(current.rules.length, 1);
    assert.equal((await audits('ACCESS_RULE_ADD')).length, 1);
  });
});

void test('metrics responses carry gateway_access: null when empty, the active document after saves (reason codes included), and never an admin-only memo', async () => {
  await withBackend(async ({ add, mode, remove, report, call }) => {
    const empty = await report(metrics());
    assert.equal(empty.status, 202);
    // 2026-10-15: 확장 칸 지원 알림(metrics_ext)이 응답에 더해졌다
    assert.deepEqual(Object.keys(empty.json), ['accepted', 'metrics_ext', 'gateway_settings', 'gateway_access']);
    assert.equal(empty.json.gateway_settings, null);
    assert.equal(empty.json.gateway_access, null);   // 저장된 것이 없다 → Gateway는 비운다
    const a = (await add(addBody({ client_id: CHROME(1), reasons: ['OTHER'], memo: '메모는 Gateway에 가지 않는다', duration: '1h' }))).json.rule;
    const b = (await add(addBody({ client_id: CHROME(2), duration: 'permanent', expected_version: 1 }))).json.rule;
    const c = (await add(addBody({ client_id: CHROME(3), duration: '1d', expected_version: 2 }))).json.rule;
    await mode({ require_client_id: true, expected_version: 3 });
    await remove(c.id, 4);
    const response = await report(metrics());
    const document = response.json.gateway_access;
    assert.deepEqual(Object.keys(document), DOCUMENT_FIELDS);
    assert.equal(document.version, 5);
    assert.match(document.revision, UUID);
    assert.match(document.updated_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.equal(document.require_client_id, true);
    assert.deepEqual(document.rules, [
      { id: a.id, client_id: CHROME(1), expires_at: a.expires_at, reasons: ['OTHER'] },
      { id: b.id, client_id: CHROME(2), expires_at: null, reasons: ['INVESTIGATION'] },
    ]);
    for (const rule of document.rules) assert.deepEqual(Object.keys(rule), ['id', 'client_id', 'expires_at', 'reasons']);
    // 공개를 고르지 않은 메모·등록자·별칭은 가지 않는다
    const text = JSON.stringify(response.json.gateway_access);
    for (const secret of ['메모', 'local-admin', '별칭', 'user_memo', 'show_memo_to_user']) assert.ok(!text.includes(secret), secret);
    // 같은 판은 지표마다 같은 문서
    assert.deepEqual((await report(metrics())).json.gateway_access, document);
    // 지표 본문 검사는 그대로(모르는 칸 400, 토큰 없으면 401)
    assert.equal((await report(metrics({ unknown_metric: 1 }))).status, 400);
    assert.equal((await call('POST', '/api/traffic/metrics', metrics(), { session: false })).status, 401);
  });
});

void test('expired rules are not sent and do not block a new rule for the same id', async () => {
  const now = Date.now();
  const expired = seededRule(1, { expires_at: new Date(now - minutes(5)).toISOString() });
  const live = seededRule(2, { expires_at: new Date(now + minutes(5)).toISOString() });
  const released = seededRule(3, { removed_by: 'local-admin', removed_at: '2026-10-12T00:30:00.000Z' });
  await withBackend(async ({ report, state, add, remove }) => {
    const document = (await report(metrics())).json.gateway_access;
    assert.deepEqual(document.rules.map((rule) => rule.client_id), [CHROME(2)]);
    const rules = (await state()).json.rules;
    assert.equal(rules.length, 3);
    assert.deepEqual(Object.fromEntries(rules.map((rule) => [rule.client_id, rule.active])), { [CHROME(1)]: false, [CHROME(2)]: true, [CHROME(3)]: false });
    // 만료·해제된 ID는 다시 막을 수 있다
    assert.equal((await add(addBody({ client_id: CHROME(1), expected_version: 1 }))).status, 201);
    assert.equal((await add(addBody({ client_id: CHROME(3), expected_version: 2 }))).status, 201);
    // 이미 만료된 규칙의 해제는 409
    assert.equal((await remove(expired.id, 3)).status, 409);
    // 아직 남은 규칙은 해제할 수 있다
    assert.equal((await remove(live.id, 3)).status, 200);
  }, { seed: { gatewayAccess: [seededRow([expired, live, released])] } });
});

void test('a rule that expires between metrics responses disappears from the next document without a new version', async () => {
  const now = Date.now();
  const rule = seededRule(1, { expires_at: new Date(now + 60_000).toISOString() });
  const row = seededRow([rule]);
  assert.equal(gatewayAccessDocument(row, now).rules.length, 1);
  assert.equal(gatewayAccessDocument(row, now + 59_999).rules.length, 1);
  assert.equal(gatewayAccessDocument(row, now + 60_000).rules.length, 0);   // 만료 시각 이후
  assert.equal(ruleIsActive(rule, now + 60_000), false);
  assert.equal(gatewayAccessDocument(row, now + 60_000).version, 1);
  assert.equal(gatewayAccessDocument(null), null);
});

void test('the document carries reasons for every active rule and user_memo only for rules whose memo was made visible', async () => {
  await withBackend(async ({ add, mode, remove, report }) => {
    const plain = (await add(addBody({ client_id: CHROME(1), reasons: ['LEAVE', 'ADMIN_REQUEST'], memo: '관리자 전용 메모' }))).json.rule;
    const shown = (await add(addBody({ client_id: CHROME(2), reasons: ['OTHER'], memo: '  기타   사유\n안내  ', show_memo_to_user: true, duration: 'permanent', expected_version: 1 }))).json.rule;
    const noMemo = (await add(addBody({ client_id: CHROME(3), reasons: ['LEAK_DOC_REPEAT', 'PII_REPEAT', 'INVESTIGATION', 'LEAVE', 'ADMIN_REQUEST', 'OTHER'], memo: '여섯 가지', duration: '1d', expected_version: 2 }))).json.rule;
    const released = (await add(addBody({ client_id: CHROME(4), memo: '해제될 규칙', show_memo_to_user: true, expected_version: 3 }))).json.rule;
    await remove(released.id, 4);
    await mode({ require_client_id: true, expected_version: 5 });
    const document = (await report(metrics())).json.gateway_access;
    assert.deepEqual(Object.keys(document), DOCUMENT_FIELDS);   // 문서 최상위 칸은 그대로
    assert.deepEqual(document.rules, [
      { id: plain.id, client_id: CHROME(1), expires_at: plain.expires_at, reasons: ['LEAVE', 'ADMIN_REQUEST'] },
      { id: shown.id, client_id: CHROME(2), expires_at: null, reasons: ['OTHER'], user_memo: '기타 사유 안내' },
      { id: noMemo.id, client_id: CHROME(3), expires_at: noMemo.expires_at, reasons: ['LEAK_DOC_REPEAT', 'PII_REPEAT', 'INVESTIGATION', 'LEAVE', 'ADMIN_REQUEST', 'OTHER'] },
    ]);   // 해제된 규칙(공개 메모 포함)은 아예 없다
    assert.deepEqual(Object.keys(document.rules[1]), ['id', 'client_id', 'expires_at', 'reasons', 'user_memo']);
    for (const rule of document.rules) {
      assert.ok(rule.reasons.length >= 1 && rule.reasons.length <= 6);
      assert.equal(new Set(rule.reasons).size, rule.reasons.length);
      assert.ok(rule.reasons.every((code) => Object.hasOwn(BLOCK_REASONS, code)));
    }
    const text = JSON.stringify(document);
    assert.ok(!text.includes('관리자 전용 메모') && !text.includes('해제될 규칙') && !text.includes('여섯 가지'));
    assert.ok(!text.includes('local-admin') && !text.includes('created_by') && !text.includes('show_memo_to_user'));
    // 같은 판은 지표마다 같은 문서(키 순서까지)
    assert.equal(JSON.stringify((await report(metrics())).json.gateway_access), JSON.stringify(document));
  });
});

void test('old stored rules (no show_memo_to_user) and hand-edited rows still give a document the Gateway can accept', () => {
  const FAR = '2099-12-31T00:00:00.000Z';
  const doc = (rules) => gatewayAccessDocument(seededRow(rules), Date.now()).rules;
  // 옛 규칙: 메모가 있어도 공개 표시가 없으면 user_memo 없음, 사유 코드는 나간다
  assert.deepEqual(doc([seededRule(1, { reasons: ['LEAVE'], memo: '옛 메모', expires_at: FAR })]), [{ id: REV(1001), client_id: CHROME(1), expires_at: FAR, reasons: ['LEAVE'] }]);
  const odd = (n, over) => doc([seededRule(n, { expires_at: FAR, ...over })])[0];
  // 사유가 없거나 틀리면 reasons 칸을 빼고(선택 칸), 알려진 것만 중복 없이 남긴다
  assert.equal('reasons' in odd(1, { reasons: undefined }), false);
  assert.equal('reasons' in odd(1, { reasons: [] }), false);
  assert.equal('reasons' in odd(1, { reasons: 'LEAVE' }), false);
  assert.equal('reasons' in odd(1, { reasons: ['SPAM', 5, null, '__proto__', 'toString'] }), false);
  assert.deepEqual(odd(1, { reasons: ['SPAM', 'LEAVE', 'LEAVE', 5, 'PII_REPEAT'] }).reasons, ['LEAVE', 'PII_REPEAT']);
  // 공개 메모: 켜 있어도 문자열 1~200자(제어 문자 없음)가 아니면 싣지 않는다
  const flagged = (memo) => odd(1, { show_memo_to_user: true, memo });
  assert.equal(flagged('안내').user_memo, '안내');
  assert.equal(flagged('가'.repeat(200)).user_memo, '가'.repeat(200));
  for (const memo of [null, undefined, '', 5, '가'.repeat(201), 'a\u0000b', ['x']]) assert.equal('user_memo' in flagged(memo), false, String(memo));
  for (const flag of ['true', 1, null, undefined, 'yes']) assert.equal('user_memo' in odd(1, { show_memo_to_user: flag, memo: '안내' }), false, String(flag));
});

void test('document size: a visible 200-character memo counts against the 56,000-byte cap, a hidden one does not', async () => {
  const FAR = '2099-12-31T00:00:00.000Z';
  const ALL = Object.keys(BLOCK_REASONS);
  const memo = '가'.repeat(200);
  const big = (n, over = {}) => seededRule(n, { reasons: ALL, memo, show_memo_to_user: true, expires_at: FAR, ...over });
  const sizeOf = (rules) => Buffer.byteLength(JSON.stringify(gatewayAccessDocument(seededRow(rules), Date.now())));
  // 같은 규칙에서 공개 표시만 다르면: 꺼 둔 메모는 문서에 안 실려 크기가 같고, 켜면 메모 바이트(한글 3바이트 x 200)만큼 커진다
  const plainSize = sizeOf([big(1, { memo: null, show_memo_to_user: false })]);
  assert.equal(sizeOf([big(1, { show_memo_to_user: false })]), plainSize);
  assert.ok(sizeOf([big(1)]) - plainSize >= 600 + '"user_memo":""'.length);
  // 큰 규칙이 몇 개 들어가나: 한도 안에서 가장 많이
  const many = [];
  while (sizeOf([...many, big(many.length)]) <= ACCESS_DOCUMENT_MAX_BYTES) many.push(big(many.length));
  assert.ok(many.length > 30 && many.length < 100, `rules with visible memos until the size limit: ${many.length}`);
  assert.ok(sizeOf(many) <= ACCESS_DOCUMENT_MAX_BYTES);
  await withBackend(async ({ add, state, remove, report }) => {
    // 한도에 닿았다 → 메모를 공개하는 규칙은 422(크기), 저장되지 않는다
    const refused = await add(addBody({ client_id: CHROME(9000), reasons: ALL, memo, show_memo_to_user: true, duration: 'permanent', expected_version: 1 }));
    assert.equal(refused.status, 422);
    assert.equal(refused.json.error.details.path, 'rules');
    assert.match(refused.json.error.message, /response size/);
    assert.equal((await state()).json.version, 1);
    // 한 개 해제하면 같은 크기(영구라 조금 작다)의 규칙이 들어가고, 문서는 한도 안
    assert.equal((await remove(many[0].id, 1)).status, 200);
    const accepted = await add(addBody({ client_id: CHROME(9000), reasons: ALL, memo, show_memo_to_user: true, duration: 'permanent', expected_version: 2 }));
    assert.equal(accepted.status, 201);
    const document = (await report(metrics())).json.gateway_access;
    assert.ok(Buffer.byteLength(JSON.stringify(document)) <= ACCESS_DOCUMENT_MAX_BYTES);
    assert.equal(document.rules.length, many.length);
    assert.equal(document.rules.filter((rule) => rule.user_memo === memo).length, many.length);
  }, { seed: { gatewayAccess: [seededRow(many)] } });
});

void test('rule list limits: 500 active rules, response size, and only the newest released rules are kept', async () => {
  // 500개: 짧은 ID는 크기 상한 안에 들어온다
  const short = Array.from({ length: ACCESS_RULE_LIMIT }, (_, index) => seededRule(index, { client_id: `u${index}` }));
  await withBackend(async ({ add, state }) => {
    const over = await add(addBody({ client_id: 'one-more', expected_version: 1 }));
    assert.equal(over.status, 422);
    assert.equal(over.json.error.details.path, 'rules');
    assert.match(over.json.error.message, /at most 500/);
    assert.equal((await state()).json.version, 1);
  }, { seed: { gatewayAccess: [seededRow(short)] } });

  // 문서가 Gateway 응답 한도(64KiB)에 닿는 쪽: chrome-<uuid> 규칙은 500개 전에 크기 상한이 걸린다(여기서는 한도를 넘지 않는 가장 큰 목록을 미리 넣는다)
  const FAR = '2099-12-31T00:00:00.000Z';
  const sizeOf = (rules) => Buffer.byteLength(JSON.stringify(gatewayAccessDocument(seededRow(rules), Date.now())));
  const many = [];
  while (sizeOf([...many, seededRule(many.length, { expires_at: FAR })]) <= ACCESS_DOCUMENT_MAX_BYTES) many.push(seededRule(many.length, { expires_at: FAR }));
  assert.ok(many.length > 300 && many.length < ACCESS_RULE_LIMIT, `rules until the size limit: ${many.length}`);
  await withBackend(async ({ add, state, report, call }) => {
    const refused = await add(addBody({ client_id: CHROME(9000), expected_version: 1 }));
    assert.equal(refused.status, 422);
    assert.equal(refused.json.error.details.path, 'rules');
    assert.match(refused.json.error.message, /response size/);
    assert.equal((await state()).json.version, 1);
    // 해제하면 한 개 더 들어간다
    const [first] = many;
    assert.equal((await call('DELETE', `/api/gateway-access/rules/${first.id}?expected_version=1`)).status, 200);
    assert.equal((await add(addBody({ client_id: CHROME(9000), expected_version: 2, duration: 'permanent' }))).status, 201);
    const document = (await report(metrics())).json.gateway_access;
    assert.ok(Buffer.byteLength(JSON.stringify(document)) <= ACCESS_DOCUMENT_MAX_BYTES);
    assert.equal(document.rules.length, many.length);
  }, { seed: { gatewayAccess: [seededRow(many)] } });

  // 해제·만료 기록은 최근 200개만(적용 중인 규칙은 모두)
  const now = Date.now();
  const rules = [
    ...Array.from({ length: 5 }, (_, index) => seededRule(index, { expires_at: null })),
    ...Array.from({ length: ACCESS_INACTIVE_KEEP + 30 }, (_, index) => seededRule(100 + index, {
      removed_by: 'local-admin', removed_at: new Date(now - (index + 1) * 1000).toISOString() })),
  ];
  const pruned = pruneRules(rules, now);
  assert.equal(pruned.filter((rule) => ruleIsActive(rule, now)).length, 5);
  assert.equal(pruned.length, 5 + ACCESS_INACTIVE_KEEP);
  assert.ok(pruned.some((rule) => rule.client_id === CHROME(100)));   // 가장 최근에 해제된 것은 남고
  assert.ok(!pruned.some((rule) => rule.client_id === CHROME(100 + ACCESS_INACTIVE_KEEP + 29)));   // 가장 오래된 것은 빠진다
});

void test('a stored row with junk inside still gives a document and a list (the metrics response must not fail)', async () => {
  const good = seededRule(1);
  await withBackend(async ({ report, state, add }) => {
    const response = await report(metrics());
    assert.equal(response.status, 202);
    assert.deepEqual(response.json.gateway_access.rules.map((rule) => rule.client_id), [CHROME(1)]);
    assert.equal((await state()).json.rules.length, 1);
    assert.equal((await add(addBody({ client_id: CHROME(2), expected_version: 1 }))).status, 201);   // 틀린 항목은 다음 저장 때 정리된다
    assert.deepEqual((await state()).json.rules.map((rule) => rule.client_id), [CHROME(2), CHROME(1)]);
  }, { seed: { gatewayAccess: [seededRow([null, 'x', 5, { id: 1 }, { client_id: 'no-id' }, good])] } });
});

void test('rules and the mode survive a restart from the JSON store, and an old file without the fields still opens', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-access-restart-'));
  const storePath = path.join(root, 'events.json');
  try {
    let saved;
    await withBackend(async ({ add, mode, setAlias }) => {
      await add(addBody());
      saved = (await mode({ require_client_id: true, expected_version: 1 })).json;
      await setAlias(CHROME(1), '홍길동 PC');
    }, { store: new JsonEventStore(storePath) });
    await withBackend(async ({ state, aliases }) => {
      const current = (await state()).json;
      assert.equal(current.version, 2);
      assert.equal(current.revision, saved.revision);
      assert.equal(current.require_client_id, true);
      assert.deepEqual(current.rules, saved.rules);
      assert.deepEqual((await aliases()).json.items, [{ client_id: CHROME(1), alias: '홍길동 PC' }]);
    }, { store: new JsonEventStore(storePath) });
    const file = JSON.parse(await readFile(storePath, 'utf8'));
    assert.deepEqual(Object.keys(file.gatewayAccess[0]).sort(), ['require_client_id', 'revision', 'rules', 'updated_at', 'updated_by', 'version']);
    assert.deepEqual(Object.keys(file.gatewayAccess[0].rules[0]), ['id', 'client_id', 'reasons', 'memo', 'show_memo_to_user', 'expires_at', 'created_by', 'created_at', 'removed_by', 'removed_at']);
    assert.deepEqual(Object.keys(file.clientAliases[0]).sort(), ['alias', 'client_id', 'updated_at', 'updated_by']);
    // 옛 파일(접속 차단 칸 없음)
    delete file.gatewayAccess;
    delete file.clientAliases;
    await writeFile(storePath, JSON.stringify(file));
    await withBackend(async ({ state, aliases, report }) => {
      assert.equal((await state()).json.version, 0);
      assert.deepEqual((await aliases()).json, { items: [] });
      assert.equal((await report(metrics())).json.gateway_access, null);
    }, { store: new JsonEventStore(storePath) });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('a failed startup read: 503 for the rule API, no gateway_access field, aliases still work, then the timer reads again', async () => {
  class FlakyStore extends JsonEventStore {
    failing = true;
    reads = 0;
    async getGatewayAccess() {
      this.reads += 1;
      if (this.failing) throw new Error('database unavailable');
      return super.getGatewayAccess();
    }
  }
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-access-flaky-'));
  const store = new FlakyStore(path.join(root, 'events.json'));
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    await withBackend(async ({ state, add, mode, remove, setAlias, report }) => {
      for (const result of [await state(), await add(addBody()), await mode({ require_client_id: true, expected_version: 0 }), await remove(REV(1), 0)]) {
        assert.equal(result.status, 503);
        assert.equal(result.json.error.code, 'ACCESS_UNAVAILABLE');
      }
      assert.equal((await setAlias(CHROME(1), '별칭')).status, 200);
      const accepted = await report(metrics());
      assert.equal(accepted.status, 202);
      assert.equal('gateway_access' in accepted.json, false);   // 칸 없음 → Gateway는 지금 목록 유지
      assert.deepEqual(accepted.json.gateway_settings, null);
      const readsWhileDown = store.reads;
      store.failing = false;
      let response;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        response = await report(metrics());
        if ('gateway_access' in response.json) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(response.json.gateway_access, null);   // 지표가 아니라 타이머가 다시 읽었다
      assert.ok(store.reads > readsWhileDown);
      assert.equal((await state()).status, 200);
      assert.equal((await add(addBody())).status, 201);
    }, { store, retryMs: 10 });
  } finally {
    console.error = originalConsoleError;
    await rm(root, { recursive: true, force: true });
  }
});

void test('metrics processing never reads the store for the access document', async () => {
  const calls = [];
  const makeStore = (file) => new Proxy(new JsonEventStore(file), {
    get(target, property) {
      const value = target[property];
      if (typeof value !== 'function') return value;
      return (...args) => {
        calls.push(String(property));
        return value.apply(target, args);
      };
    },
  });
  await withBackend(async ({ add, report }) => {
    await add(addBody());
    calls.length = 0;
    const response = await report(metrics({ access_applied: reported() }));
    assert.equal(response.status, 202);
    assert.equal(response.json.gateway_access.version, 1);
    assert.deepEqual(calls, []);
  }, { makeStore });
});

void test('access_applied: accepted when exact, otherwise dropped alone, and the state follows the revision', async () => {
  await withBackend(async ({ report, state, add }) => {
    // 목록이 없는 쪽(NONE)이 보고하면 저장된 것이 없으니 반영됨
    assert.equal((await report(metrics({ access_applied: reported() }))).status, 202);
    let current = (await state()).json;
    assert.deepEqual(Object.keys(current.applied), ['version', 'revision', 'source', 'applied_at', 'rejected', 'active_rules', 'require_client_id', 'denied_5m', 'received_at']);
    assert.equal(current.applied.source, 'NONE');
    assert.ok(Number.isFinite(Date.parse(current.applied.received_at)));
    assert.equal(current.gateway.state, 'APPLIED');
    assert.equal(current.gateway.metrics_status, 'FRESH');
    assert.equal(current.gateway.reported_at, current.applied.received_at);

    const saved = (await add(addBody())).json;
    assert.equal((await state()).json.gateway.state, 'PENDING');   // 아직 가져가지 않았다
    await report(metrics({ access_applied: reported({ version: saved.version, revision: saved.revision, source: 'DASHBOARD', active_rules: 1, denied_5m: 7 }) }));
    current = (await state()).json;
    assert.equal(current.gateway.state, 'APPLIED');
    assert.equal(current.applied.version, saved.version);
    assert.equal(current.applied.denied_5m, 7);
    assert.equal(current.applied.active_rules, 1);

    // 다른 revision을 쓰는 중 + 거부 사유 = 거부됨
    await report(metrics({ access_applied: reported({ version: 9, revision: REV(9), source: 'CACHE', rejected: 'rules.3.client_id' }) }));
    current = (await state()).json;
    assert.equal(current.gateway.state, 'REJECTED');
    assert.equal(current.applied.rejected, 'rules.3.client_id');

    // 틀린 보고는 이 칸만 버리고 지표는 받는다
    const originalWarn = console.warn;
    const warnings = [];
    console.warn = (message) => warnings.push(String(message));
    try {
      const bad = await report(metrics({ access_applied: { ...reported(), extra: 1 } }));
      assert.equal(bad.status, 202);
      assert.equal(bad.json.gateway_access.version, 1);
      await report(metrics({ access_applied: 'nope' }));
      await report(metrics({ access_applied: 'nope' }));
    } finally {
      console.warn = originalWarn;
    }
    current = (await state()).json;
    assert.equal(current.applied, null);
    assert.equal(current.gateway.state, 'NOT_REPORTING');
    assert.equal(warnings.length, 2);   // 버린 사유가 바뀔 때만 남긴다(같은 사유가 이어지면 한 번)
  });
});

void test('access_applied is checked completely', () => {
  const ok = reported({ version: 4, revision: REV(4), source: 'DASHBOARD', active_rules: 3, require_client_id: true, denied_5m: 12 });
  assert.deepEqual(parseAccessApplied(ok), ok);
  assert.deepEqual(parseAccessApplied(reported()), reported());
  assert.equal(parseAccessApplied({ ...ok, source: 'CACHE' }).source, 'CACHE');
  assert.equal(parseAccessApplied({ ...ok, applied_at: '2026-10-12T14:00:00+09:00' }).applied_at, '2026-10-12T14:00:00+09:00');
  assert.equal(parseAccessApplied({ ...ok, applied_at: '2026-10-12T14:00:00' }).applied_at, null);   // 표시용이라 이 값만 버린다
  assert.equal(parseAccessApplied({ ...ok, applied_at: null }).applied_at, null);
  assert.equal(parseAccessApplied({ ...reported(), rejected: 'version' }).rejected, 'version');
  const bad = [
    null, [], 'x', 5,
    { ...ok, extra: 1 },
    (({ denied_5m, ...rest }) => rest)(ok),
    { ...ok, source: 'FILE' },
    { ...ok, source: 'NONE' },   // 목록이 있는데 NONE
    { ...ok, version: null },
    { ...ok, revision: null },
    { ...ok, version: 0 },
    { ...ok, version: 1.5 },
    { ...ok, revision: 'not-a-uuid' },
    { ...ok, revision: 'ABCDEF12-0000-4000-8000-000000000ABC' },
    { ...reported(), source: 'DASHBOARD' },   // 목록이 없는데 DASHBOARD
    { ...ok, rejected: '' },
    { ...ok, rejected: 5 },
    { ...ok, rejected: 'x'.repeat(101) },
    { ...ok, rejected: 'a\nb' },
    { ...ok, active_rules: -1 },
    { ...ok, active_rules: 1.5 },
    { ...ok, active_rules: '3' },
    { ...ok, denied_5m: null },
    { ...ok, denied_5m: -1 },
    { ...ok, require_client_id: 1 },
    { ...ok, require_client_id: 'true' },
  ];
  for (const value of bad) assert.throws(() => parseAccessApplied(value), undefined, JSON.stringify(value));
});

void test('the state covers every case', () => {
  const stored = { version: 3, revision: REV(3) };
  const at = '2026-10-12T05:00:00.000Z';
  const metricsWith = (access_applied) => ({ received_at: at, ...(access_applied ? { access_applied } : {}) });
  const same = reported({ version: 3, revision: REV(3), source: 'DASHBOARD' });
  assert.equal(gatewayAccessState(stored, metricsWith(same), 'FRESH').state, 'APPLIED');
  assert.equal(gatewayAccessState(stored, metricsWith(same), 'STALE').state, 'NOT_REPORTING');
  assert.equal(gatewayAccessState(stored, null, 'NOT_RECEIVED').state, 'NOT_REPORTING');
  assert.equal(gatewayAccessState(stored, metricsWith(null), 'FRESH').state, 'NOT_REPORTING');   // 보고 칸이 없다(옛 Gateway·아직 못 읽음)
  assert.equal(gatewayAccessState(stored, metricsWith({ ...same, version: 2, revision: REV(2) }), 'FRESH').state, 'PENDING');
  assert.equal(gatewayAccessState(stored, metricsWith({ ...same, version: 2, revision: REV(2), rejected: 'rules.0.id' }), 'FRESH').state, 'REJECTED');
  assert.equal(gatewayAccessState(stored, metricsWith(reported()), 'FRESH').state, 'PENDING');   // 아무것도 못 받음
  assert.equal(gatewayAccessState(stored, metricsWith(reported({ rejected: 'version' })), 'FRESH').state, 'REJECTED');
  assert.equal(gatewayAccessState(null, metricsWith(reported()), 'FRESH').state, 'APPLIED');   // 저장 없음 + Gateway도 목록 없음
  assert.equal(gatewayAccessState(null, metricsWith(same), 'FRESH').state, 'PENDING');   // 저장 없음인데 Gateway에 옛 목록이 있다 → 곧 비운다
  assert.equal(gatewayAccessState(stored, metricsWith(same), 'FRESH').reported_at, at);
  assert.deepEqual(Object.keys(gatewayAccessState(stored, metricsWith(same), 'FRESH')), ['state', 'metrics_status', 'reported_at']);
});

void test('client aliases: set, change, delete with an audit row for each real change', async () => {
  await withBackend(async ({ call, setAlias, aliases, audits }) => {
    const bad = (clientId, payload, options) => call('PUT', `/api/client-aliases/${encodeURIComponent(clientId)}`, payload, options);
    assert.equal((await bad(CHROME(1), { alias: 'x' }, { headers: { 'Content-Type': 'text/plain' }, raw: '{"alias":"x"}' })).status, 415);
    assert.equal((await bad(CHROME(1), undefined, { headers: { 'Content-Type': 'application/json' }, raw: '{broken' })).status, 400);
    assert.equal((await bad(CHROME(1), { alias: 'x', extra: 1 })).status, 400);
    assert.equal((await bad(CHROME(1), {})).status, 400);
    for (const [clientId, payload, where] of [
      ['-bad', { alias: 'x' }, 'client_id'],
      ['a'.repeat(81), { alias: 'x' }, 'client_id'],
      [CHROME(1), { alias: 5 }, 'alias'],
      [CHROME(1), { alias: null }, 'alias'],
      [CHROME(1), { alias: '가'.repeat(41) }, 'alias'],
      [CHROME(1), { alias: 'a\u0007b' }, 'alias'],
    ]) {
      const result = await bad(clientId, payload);
      assert.equal(result.status, 422, where);
      assert.equal(result.json.error.details.path, where);
    }
    assert.deepEqual(await audits('CLIENT_ALIAS_UPDATE'), []);

    const set = await setAlias(CHROME(1), '  홍길동   PC ');
    assert.equal(set.status, 200);
    assert.deepEqual(set.json, { client_id: CHROME(1), alias: '홍길동 PC' });
    assert.equal((await setAlias(CHROME(2), '가'.repeat(40))).status, 200);   // 40자까지
    await setAlias('legacy.client@1:a', '다른 PC');
    assert.deepEqual((await aliases()).json, { items: [
      { client_id: CHROME(1), alias: '홍길동 PC' },
      { client_id: CHROME(2), alias: '가'.repeat(40) },
      { client_id: 'legacy.client@1:a', alias: '다른 PC' },
    ] });

    let rows = await audits('CLIENT_ALIAS_UPDATE');
    assert.equal(rows.length, 3);
    const first = rows.find((row) => row.target_id === CHROME(1));
    assert.equal(first.target_type, 'GATEWAY');
    assert.deepEqual(first.changes, { previous_value: '(없음)', new_value: '홍길동 PC' });

    // 같은 값은 기록하지 않는다
    assert.equal((await setAlias(CHROME(1), '홍길동 PC')).status, 200);
    assert.equal((await audits('CLIENT_ALIAS_UPDATE')).length, 3);
    // 바꾸기
    assert.equal((await setAlias(CHROME(1), '길동 노트북')).json.alias, '길동 노트북');
    rows = (await audits('CLIENT_ALIAS_UPDATE')).filter((row) => row.target_id === CHROME(1));
    assert.equal(rows.length, 2);
    assert.ok(rows.some((row) => row.changes.previous_value === '홍길동 PC' && row.changes.new_value === '길동 노트북'));
    // 빈 별칭은 삭제
    const removed = await setAlias(CHROME(1), '   ');
    assert.deepEqual(removed.json, { client_id: CHROME(1), alias: null });
    assert.ok((await audits('CLIENT_ALIAS_UPDATE')).some((row) => row.changes.previous_value === '길동 노트북' && row.changes.new_value === '(삭제)'));
    assert.deepEqual((await aliases()).json.items.map((item) => item.client_id), [CHROME(2), 'legacy.client@1:a']);
    // 없는 별칭을 지워도 기록은 없다
    const count = (await audits('CLIENT_ALIAS_UPDATE')).length;
    assert.deepEqual((await setAlias(CHROME(9), '')).json, { client_id: CHROME(9), alias: null });
    assert.equal((await audits('CLIENT_ALIAS_UPDATE')).length, count);
    // 별칭은 Gateway 문서에 가지 않는다
    assert.equal((await call('GET', '/api/gateway-access')).json.version, 0);
  });
});

void test('the alias list is capped at 1000: a new alias is refused, an existing one can change, and deleting makes room', async () => {
  const rows = Array.from({ length: ALIAS_LIMIT }, (_, index) => ({ client_id: `c${index}`, alias: `이름${index}`, updated_by: 'local-admin', updated_at: '2026-10-12T00:00:00.000Z' }));
  await withBackend(async ({ setAlias, aliases }) => {
    const refused = await setAlias('c-new', '새 이름');
    assert.equal(refused.status, 422);
    assert.equal(refused.json.error.details.path, 'alias');
    assert.equal((await setAlias('c5', '바뀐 이름')).status, 200);
    assert.equal((await setAlias('c6', '')).status, 200);
    assert.equal((await setAlias('c-new', '새 이름')).status, 200);
    const items = (await aliases()).json.items;
    assert.equal(items.length, ALIAS_LIMIT);
    assert.equal(items.find((item) => item.client_id === 'c5').alias, '바뀐 이름');
  }, { seed: { clientAliases: rows } });
});

void test('event validation: accessRuleId is a UUID and only for client_blocked; both reason codes are accepted', async () => {
  const event = (over = {}) => ({
    type: 'SECURITY_EVENT', eventId: 'evt-access-1', requestId: 'req-access-1', timestamp: new Date().toISOString(), clientId: CHROME(1),
    targetLlm: 'ChatGPT', contentType: 'prompt', detectionOutcome: 'UNAVAILABLE', finalAction: 'BLOCK', severity: 'LOW',
    enforcement: { applied: true, httpStatus: 403 }, reasonCode: 'client_blocked', detections: [], ...over,
  });
  const ruleId = 'abcdef12-0000-4000-8000-000000000abc';
  const parsed = validateCanonicalEvent(event({ accessRuleId: ruleId }));
  assert.equal(parsed.accessRuleId, ruleId);
  assert.equal(canonicalEventToDto(parsed).access_rule_id, ruleId);
  assert.equal(canonicalEventToDto(parsed).reason_code, 'client_blocked');
  assert.equal('access_rule_id' in canonicalEventToDto(validateCanonicalEvent(event())), false);   // 선택
  assert.equal(validateCanonicalEvent(event({ reasonCode: 'client_id_missing', clientId: 'unknown-1.2.3.4' })).reasonCode, 'client_id_missing');
  for (const [accessRuleId, over, where] of [
    ['not-a-uuid', {}, 'body.accessRuleId'],
    [ruleId.toUpperCase(), {}, 'body.accessRuleId'],
    [5, {}, 'body.accessRuleId'],
    [null, {}, 'body.accessRuleId'],
    [ruleId, { reasonCode: 'client_id_missing' }, 'body.accessRuleId'],
    [ruleId, { reasonCode: undefined }, 'body.accessRuleId'],
  ]) {
    assert.throws(() => validateCanonicalEvent(event({ accessRuleId, ...over })), (error) => error.path === where, `${accessRuleId} ${JSON.stringify(over)}`);
  }
  assert.throws(() => validateCanonicalEvent(event({ ruleId })), (error) => error.path === 'body.ruleId');   // 모르는 칸은 지금처럼 거부

  await withBackend(async ({ call, ingest }) => {
    const stored = await ingest(event({ accessRuleId: ruleId }));
    assert.equal(stored.status, 201);
    assert.equal(stored.json.event.access_rule_id, ruleId);
    assert.equal(stored.json.event.reason_code, 'client_blocked');
    assert.equal(stored.json.event.detection_outcome, 'UNAVAILABLE');
    const missing = await ingest(event({ eventId: 'evt-access-2', requestId: 'req-access-2', clientId: 'unknown-203.0.113.9', reasonCode: 'client_id_missing' }));
    assert.equal(missing.status, 201);
    assert.equal('access_rule_id' in missing.json.event, false);
    const bad = await ingest(event({ eventId: 'evt-access-3', accessRuleId: 'nope' }));
    assert.equal(bad.status, 422);
    assert.equal(bad.json.error.details.path, 'body.accessRuleId');
    const detail = await call('GET', '/api/events/evt-access-1');
    assert.equal(detail.json.access_rule_id, ruleId);
  });
});

void test('own requests: a blocked user gets the reason codes and a visible memo (never the admin-only memo), in the list and in the evidence', async () => {
  const KEY = 'K'.repeat(20) + 'k-_' + '7'.repeat(20);
  const HASH = createHash('sha256').update(KEY).digest('hex');
  const ago = (seconds) => new Date(Date.now() - seconds * 1000).toISOString();
  const blocked = (eventId, clientId, ruleId, over = {}) => ({
    type: 'SECURITY_EVENT', eventId, requestId: `req-${eventId}`, timestamp: ago(60), clientId, targetLlm: 'ChatGPT', contentType: 'prompt',
    detectionOutcome: 'UNAVAILABLE', finalAction: 'BLOCK', severity: 'LOW', enforcement: { applied: true, httpStatus: 403 },
    reasonCode: 'client_blocked', ...(ruleId ? { accessRuleId: ruleId } : {}), detections: [], viewerKeyHash: HASH, ...over,
  });
  await withBackend(async ({ call, add, remove, ingest }) => {
    const shown = (await add(addBody({ client_id: CHROME(1), reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], memo: '보안 관리자에게 문의하세요', show_memo_to_user: true }))).json.rule;
    const hidden = (await add(addBody({ client_id: CHROME(2), reasons: ['LEAVE'], memo: '관리자 전용 메모', expected_version: 1 }))).json.rule;
    const unknownRule = 'abcdef12-0000-4000-8000-000000000abc';
    for (const event of [
      blocked('evt-shown', CHROME(1), shown.id, { timestamp: ago(10) }),
      blocked('evt-hidden', CHROME(2), hidden.id, { timestamp: ago(20) }),
      blocked('evt-missing-id', 'unknown-203.0.113.9', undefined, { timestamp: ago(30), reasonCode: 'client_id_missing' }),
      blocked('evt-pruned', CHROME(3), unknownRule, { timestamp: ago(40) }),                        // 규칙이 목록에서 정리됨
      blocked('evt-wrong-owner', CHROME(2), shown.id, { timestamp: ago(50) }),                       // 확장 ID가 다른 규칙을 가리키는 기록은 그 규칙을 보여 주지 않는다
      blocked('evt-other-viewer', CHROME(1), shown.id, { viewerKeyHash: createHash('sha256').update('x').digest('hex') }),
      blocked('evt-allowed', CHROME(1), shown.id, { finalAction: 'ALLOW', enforcement: undefined }),
    ]) assert.ok([200, 201].includes((await ingest(event)).status), event.eventId);

    const own = (pathname) => call('GET', pathname, undefined, { session: false, headers: { 'X-Viewer-Key': KEY } });
    const list = await own('/api/my/requests');
    assert.equal(list.status, 200);
    const byId = Object.fromEntries(list.json.items.map((item) => [item.event_id, item]));
    assert.deepEqual(list.json.items.map((item) => item.event_id), ['evt-shown', 'evt-hidden', 'evt-missing-id', 'evt-pruned', 'evt-wrong-owner']);
    assert.equal(byId['evt-shown'].final_action, 'BLOCK');
    assert.equal(byId['evt-shown'].reason_code, 'client_blocked');
    assert.deepEqual(byId['evt-shown'].block_reasons, ['INVESTIGATION', 'ADMIN_REQUEST']);   // 코드(이름표는 화면이 붙인다)
    assert.equal(byId['evt-shown'].user_memo, '보안 관리자에게 문의하세요');
    assert.equal(byId['evt-hidden'].reason_code, 'client_blocked');
    assert.deepEqual(byId['evt-hidden'].block_reasons, ['LEAVE']);
    assert.equal('user_memo' in byId['evt-hidden'], false);   // 관리자 전용 메모는 본인에게 가지 않는다
    assert.equal(byId['evt-missing-id'].reason_code, 'client_id_missing');   // 고정 사유: 코드만
    for (const field of ['block_reasons', 'user_memo']) assert.equal(field in byId['evt-missing-id'], false, field);
    for (const id of ['evt-pruned', 'evt-wrong-owner']) {
      assert.equal(byId[id].reason_code, 'client_blocked', id);
      for (const field of ['block_reasons', 'user_memo']) assert.equal(field in byId[id], false, `${id} ${field}`);
    }
    // 규칙의 다른 내용(등록자·관리자 메모·규칙 번호·확장 ID)은 싣지 않는다
    const text = JSON.stringify(list.json);
    for (const secret of ['관리자 전용 메모', 'local-admin', 'created_by', shown.id, hidden.id, CHROME(1), CHROME(2), 'access_rule_id', 'show_memo_to_user']) assert.ok(!text.includes(secret), secret);

    // 근거 응답에도 같은 사유
    const evidence = await own('/api/my/requests/evt-shown/evidence');
    assert.equal(evidence.status, 200);
    assert.equal(evidence.json.final_action, 'BLOCK');
    assert.equal(evidence.json.reason_code, 'client_blocked');
    assert.deepEqual(evidence.json.block_reasons, ['INVESTIGATION', 'ADMIN_REQUEST']);
    assert.equal(evidence.json.user_memo, '보안 관리자에게 문의하세요');
    const hiddenEvidence = (await own('/api/my/requests/evt-hidden/evidence')).json;
    assert.deepEqual([hiddenEvidence.reason_code, hiddenEvidence.block_reasons, 'user_memo' in hiddenEvidence], ['client_blocked', ['LEAVE'], false]);
    const missingEvidence = (await own('/api/my/requests/evt-missing-id/evidence')).json;
    assert.deepEqual([missingEvidence.reason_code, 'block_reasons' in missingEvidence, 'user_memo' in missingEvidence], ['client_id_missing', false, false]);
    assert.equal((await own('/api/my/requests/evt-wrong-owner/evidence')).json.user_memo, undefined);
    assert.equal((await own('/api/my/requests/evt-allowed/evidence')).json.reason_code, undefined);   // 허용 건은 사유를 싣지 않는다
    assert.equal((await call('GET', '/api/my/requests/evt-shown/evidence', undefined, { session: false, headers: { 'X-Viewer-Key': 'Z'.repeat(43) } })).status, 404);

    // 규칙을 해제해도 기록으로 남아 있는 동안은 사유가 그대로 보인다
    assert.equal((await remove(shown.id, 2)).status, 200);
    const after = (await own('/api/my/requests')).json.items.find((item) => item.event_id === 'evt-shown');
    assert.deepEqual([after.block_reasons, after.user_memo], [['INVESTIGATION', 'ADMIN_REQUEST'], '보안 관리자에게 문의하세요']);
  });
});

void test('own-request reason helpers: only a blocked request with an access reason code, and only the listed rule parts', () => {
  assert.equal(ownAccessReasonCode({ final_action: 'BLOCK', reason_code: 'client_blocked' }), 'client_blocked');
  assert.equal(ownAccessReasonCode({ action: 'BLOCK', reason_code: 'client_id_missing' }), 'client_id_missing');
  for (const event of [
    { final_action: 'ALLOW', reason_code: 'client_blocked' }, { final_action: 'MASK', reason_code: 'client_blocked' },
    { final_action: 'BLOCK', reason_code: 'pii' }, { final_action: 'BLOCK' }, { final_action: 'BLOCK', reason_code: '__proto__' },
  ]) assert.equal(ownAccessReasonCode(event), undefined, JSON.stringify(event));
  const rule = { id: REV(1), client_id: CHROME(1), reasons: ['LEAVE', 'SPAM', 'LEAVE'], memo: '메모', show_memo_to_user: true, created_by: 'local-admin', expires_at: null };
  assert.deepEqual(ownBlockDetails(rule), { block_reasons: ['LEAVE'], user_memo: '메모' });
  assert.deepEqual(ownBlockDetails({ ...rule, show_memo_to_user: false }), { block_reasons: ['LEAVE'] });
  assert.deepEqual(ownBlockDetails({ ...rule, reasons: [], memo: null }), {});
  for (const junk of [null, undefined, 'x', 5, []]) assert.deepEqual(ownBlockDetails(junk), {});
});

void test('summaries: reason labels, memo shortening and the Korean time', () => {
  assert.deepEqual(Object.keys(BLOCK_REASONS), ['LEAK_DOC_REPEAT', 'PII_REPEAT', 'INVESTIGATION', 'LEAVE', 'ADMIN_REQUEST', 'OTHER']);
  assert.deepEqual(Object.values(BLOCK_REASONS), ['기밀 문서 반복 유출 시도', '개인정보 반복 입력', '보안 조사 중', '퇴사·휴직 예정', '관리자 요청', '기타']);
  const rule = seededRule(1, { reasons: ['LEAVE', 'ADMIN_REQUEST'], memo: '가'.repeat(60), expires_at: '2026-10-13T05:00:00.000Z' });
  assert.equal(summarizeRule(rule, { durationLabel: '1일' }), `확장 ID ${CHROME(1)} · 1일(10/13 14:00까지) · 사유 퇴사·휴직 예정, 관리자 요청 · 메모 ${'가'.repeat(50)}…`);   // UTC 05:00 = 한국 14:00
  assert.equal(summarizeRule({ ...rule, expires_at: null, memo: null, reasons: ['OTHER'] }), `확장 ID ${CHROME(1)} · 영구 · 사유 기타`);
  // 사용자에게 메모를 공개한 규칙은 끝에 표시(메모가 있을 때만), 칸이 없는 옛 규칙은 표시 없음
  assert.equal(summarizeRule({ ...rule, memo: '안내', show_memo_to_user: true }, { durationLabel: '1일' }), `확장 ID ${CHROME(1)} · 1일(10/13 14:00까지) · 사유 퇴사·휴직 예정, 관리자 요청 · 메모 안내 · 사용자에게 메모 공개`);
  assert.equal(summarizeRule({ ...rule, memo: '안내', show_memo_to_user: false }).includes('공개'), false);
  assert.equal(summarizeRule({ ...rule, memo: '안내' }).includes('공개'), false);
  assert.equal(summarizeRule({ ...rule, memo: null, show_memo_to_user: true }).includes('공개'), false);
});

// PostgreSQL 저장소의 트랜잭션을 흉내 내는 가짜 pool(감사 삽입 실패를 일으킬 수 있다). 진짜 SQL은 gateway-access.pglite.test.mjs가 본다
function fakeAccessPool({ failAudit = false } = {}) {
  const state = { rows: [], aliases: new Map(), audits: [], statements: [] };
  const pool = {
    state,
    async query(sql) {
      if (/INSERT INTO dashboard_admin_activity_history/.test(sql)) return { rows: [], rowCount: 1 };   // 로그인 감사
      if (/FROM dashboard_gateway_access\s+ORDER BY version DESC/.test(sql)) return { rows: state.rows.slice(-1), rowCount: Math.min(1, state.rows.length) };
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      let staged = null;
      return {
        async query(sql, params = []) {
          const statement = sql.trim();
          if (statement === 'BEGIN') { staged = { rows: [...state.rows], audits: [] }; state.statements.push('BEGIN'); return { rows: [], rowCount: 0 }; }
          if (statement === 'COMMIT') { state.rows = staged.rows; state.audits.push(...staged.audits); staged = null; state.statements.push('COMMIT'); return { rows: [], rowCount: 0 }; }
          if (statement === 'ROLLBACK') { staged = null; state.statements.push('ROLLBACK'); return { rows: [], rowCount: 0 }; }
          if (/INSERT INTO dashboard_gateway_access/.test(sql)) {
            state.statements.push('INSERT access');
            const [expected, revision, requireClientId, rules, updatedBy] = params;
            if ((staged.rows.at(-1)?.version ?? 0) !== expected) return { rows: [], rowCount: 0 };
            if (staged.rows.some((row) => row.revision === revision)) throw Object.assign(new Error('duplicate key value'), { code: '23505' });
            const row = { version: expected + 1, revision, require_client_id: requireClientId, rules: JSON.parse(rules), updated_by: updatedBy, updated_at: new Date() };
            staged.rows.push(row);
            return { rows: [row], rowCount: 1 };
          }
          if (/INSERT INTO dashboard_admin_activity_history/.test(sql)) {
            state.statements.push('INSERT audit');
            if (failAudit) throw new Error('new row violates check constraint "dashboard_admin_activity_history_action_check"');
            staged.audits.push(params);
            return { rows: [], rowCount: 1 };
          }
          if (/COALESCE\(max\(version\), 0\) AS version/.test(sql)) return { rows: [{ version: state.rows.at(-1)?.version ?? 0 }], rowCount: 1 };
          return { rows: [], rowCount: 0 };
        },
        release() { state.statements.push('release'); },
      };
    },
  };
  return pool;
}

void test('an audit write failure is a save failure: 500, no version row, and the in-memory copy stays', async () => {
  const pool = fakeAccessPool({ failAudit: true });
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    await withBackend(async ({ add, state, report }) => {
      const result = await add(addBody());
      assert.equal(result.status, 500);
      assert.deepEqual(result.json, { error: { code: 'SERVER', message: 'Internal server error.' } });
      assert.deepEqual(pool.state.rows, []);
      assert.deepEqual(pool.state.audits, []);
      assert.deepEqual(pool.state.statements.slice(-5), ['BEGIN', 'INSERT access', 'INSERT audit', 'ROLLBACK', 'release']);
      assert.equal((await state()).json.version, 0);
      assert.equal((await report(metrics())).json.gateway_access, null);
    }, { store: new PostgresEventStore({ pool }) });
  } finally {
    console.error = originalConsoleError;
  }
});

void test('the PostgreSQL store saves the version row and the audit row together through the API', async () => {
  const pool = fakeAccessPool();
  await withBackend(async ({ add, report }) => {
    const first = await add(addBody());
    assert.equal(first.status, 201);
    assert.equal(pool.state.rows.length, 1);
    assert.equal(pool.state.audits.length, 1);
    const [, , adminId, action, targetType, targetId, result, changes] = pool.state.audits[0];
    assert.deepEqual([adminId, action, targetType, targetId, result], ['local-admin', 'ACCESS_RULE_ADD', 'GATEWAY', first.json.rule.id, 'SUCCESS']);
    assert.equal(JSON.parse(changes).previous_version, undefined);
    assert.deepEqual(pool.state.statements.slice(-5), ['BEGIN', 'INSERT access', 'INSERT audit', 'COMMIT', 'release']);
    assert.deepEqual(Object.keys((await report(metrics())).json.gateway_access), DOCUMENT_FIELDS);
    // 낡은 번호는 409
    const stale = await add(addBody({ client_id: CHROME(2), expected_version: 0 }));
    assert.equal(stale.status, 409);
    assert.equal(pool.state.rows.length, 1);
  }, { store: new PostgresEventStore({ pool }) });
});

// 접속 차단 표가 없는 DB(이관 전·되돌린 뒤): 저장된 목록·별칭이 없는 것으로 읽는다
void test('missing access tables (42P01) read as no stored rules and no aliases', async () => {
  const missing = () => Object.assign(new Error('relation does not exist'), { code: '42P01' });
  const pool = {
    async query(sql) {
      if (/INSERT INTO dashboard_admin_activity_history/.test(sql)) return { rows: [], rowCount: 1 };
      if (/dashboard_gateway_access|dashboard_client_aliases/.test(sql)) throw missing();
      return { rows: [], rowCount: 0 };
    },
    async connect() { throw new Error('not used'); },
  };
  const store = new PostgresEventStore({ pool });
  assert.equal(await store.getGatewayAccess(), null);
  assert.deepEqual(await store.listClientAliases(), []);
  const failing = new PostgresEventStore({ pool: { async query() { throw Object.assign(new Error('boom'), { code: '08006' }); } } });
  await assert.rejects(() => failing.getGatewayAccess(), /boom/);
  await assert.rejects(() => failing.listClientAliases(), /boom/);
  await withBackend(async ({ state, report, aliases }) => {
    assert.equal((await state()).json.version, 0);
    assert.equal((await report(metrics())).json.gateway_access, null);
    assert.deepEqual((await aliases()).json, { items: [] });
  }, { store });
});
