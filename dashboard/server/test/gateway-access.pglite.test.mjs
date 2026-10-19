// 접속 차단의 진짜 SQL을 메모리 PostgreSQL(PGlite)로 확인: 마이그레이션 재적용, 옛 DB에서 올리기, 저장소 질의, 트랜잭션.
// 운영 서버에는 PGlite가 없으므로(개발 PC 전용) 설치되어 있지 않으면 건너뛴다.
// 설치 위치가 다르면 PGLITE_MODULE에 .../@electric-sql/pglite/dist/index.js 의 경로를 준다.
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createAppServer } from '../app.mjs';
import { AccessConflictError } from '../event-store.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

let PGlite = null;
try {
  ({ PGlite } = await import(process.env.PGLITE_MODULE ? pathToFileURL(process.env.PGLITE_MODULE).href : '@electric-sql/pglite'));
} catch {
  PGlite = null;
}
const skip = PGlite ? false : '@electric-sql/pglite is not installed (set PGLITE_MODULE to run)';

const directory = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const migrationFiles = (await readdir(directory)).filter((name) => /^\d+.*\.sql$/.test(name)).sort();
const readMigration = (name) => readFile(path.join(directory, name), 'utf8');
const applyAll = async (db, { replace = {}, only } = {}) => {
  for (const name of migrationFiles) {
    if (only && !only(name)) continue;
    await db.exec(replace[name] ?? (await readMigration(name)));
  }
};
const REV = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const NEW_ACTIONS = ['ACCESS_RULE_ADD', 'ACCESS_RULE_REMOVE', 'ACCESS_MODE_UPDATE', 'CLIENT_ALIAS_UPDATE'];

// pg의 Pool 모양(query·connect). PGlite는 연결이 하나라 트랜잭션이 겹치는 시험은 하지 않는다
function poolFor(db) {
  const run = async (sql, params) => {
    const result = await db.query(sql, params);
    return { rows: result.rows, rowCount: result.rows.length > 0 ? result.rows.length : (result.affectedRows ?? 0) };
  };
  return { query: run, async connect() { return { query: run, release() {} }; } };
}
const one = async (db, sql, params = []) => (await db.query(sql, params)).rows[0];
const audit = (action, targetId = 'x') => ({ adminId: 'local-admin', action, targetType: 'GATEWAY', targetId, result: 'SUCCESS', changes: { new_version: 1 } });
const rule = (n, over = {}) => ({ id: REV(1000 + n), client_id: `chrome-${n}`, reasons: ['OTHER'], memo: '시험', expires_at: null, created_by: 'local-admin', created_at: '2026-10-12T00:00:00.000Z', removed_by: null, removed_at: null, ...over });

void test('migrations apply twice on a new database, the tables and checks exist, and the version table is append-only', { skip }, async () => {
  const db = new PGlite();
  try {
    await applyAll(db);
    await applyAll(db);   // migrate.mjs는 매번 전부 다시 적용한다
    assert.equal((await one(db, "SELECT to_regclass('dashboard_gateway_access') IS NOT NULL AS ok")).ok, true);
    assert.equal((await one(db, "SELECT to_regclass('dashboard_client_aliases') IS NOT NULL AS ok")).ok, true);
    await db.query(`INSERT INTO dashboard_gateway_access (version, revision, require_client_id, rules, updated_by) VALUES (1, $1, true, $2::jsonb, 'a')`, [REV(1), JSON.stringify([rule(1)])]);
    await assert.rejects(() => db.query(`UPDATE dashboard_gateway_access SET require_client_id = false`), /append-only/);
    await assert.rejects(() => db.query(`DELETE FROM dashboard_gateway_access`), /append-only/);
    for (const [label, sql, params] of [
      ['version 0', `INSERT INTO dashboard_gateway_access (version, revision, updated_by) VALUES (0, $1, 'a')`, [REV(2)]],
      ['bad revision', `INSERT INTO dashboard_gateway_access (version, revision, updated_by) VALUES (2, 'x', 'a')`, []],
      ['same revision', `INSERT INTO dashboard_gateway_access (version, revision, updated_by) VALUES (2, $1, 'a')`, [REV(1)]],
      ['rules not an array', `INSERT INTO dashboard_gateway_access (version, revision, rules, updated_by) VALUES (2, $1, '{}'::jsonb, 'a')`, [REV(3)]],
      ['alias empty', `INSERT INTO dashboard_client_aliases (client_id, alias, updated_by) VALUES ('chrome-1', '', 'a')`, []],
      ['alias 41 chars', `INSERT INTO dashboard_client_aliases (client_id, alias, updated_by) VALUES ('chrome-1', $1, 'a')`, ['가'.repeat(41)]],
      ['client id bad', `INSERT INTO dashboard_client_aliases (client_id, alias, updated_by) VALUES ('-bad', 'x', 'a')`, []],
    ]) await assert.rejects(() => db.query(sql, params), undefined, label);
    await db.query(`INSERT INTO dashboard_client_aliases (client_id, alias, updated_by) VALUES ('chrome-1', $1, 'a')`, ['가'.repeat(40)]);   // 40자는 된다
    // 새 감사 action 4개를 받고, 모르는 action은 여전히 막는다
    for (const action of NEW_ACTIONS)
      await db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ($1, now(), 'a', $2, 'GATEWAY', 'chrome-1', 'SUCCESS')`, [`audit-${action}`, action]);
    await assert.rejects(() => db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ('audit-bogus', now(), 'a', 'ACCESS_RULE_BOGUS', 'GATEWAY', 'x', 'SUCCESS')`), /check/i);
  } finally {
    await db.close();
  }
});

void test('upgrading an existing database keeps every audit row, accepts the new actions, and can be applied again', { skip }, async () => {
  const current = await readMigration('002_admin_auth_audit.sql');
  const old = current.replace(/,(\r?\n)\s*-- 2026-10-12 [^\r\n]*(\r?\n)\s*'ACCESS_RULE_ADD',\s*'ACCESS_RULE_REMOVE',\s*'ACCESS_MODE_UPDATE',\s*'CLIENT_ALIAS_UPDATE'/, '');
  assert.ok(old !== current && !old.includes('ACCESS_RULE_ADD') && old.includes("'GATEWAY_SETTINGS_UPDATE'"), 'the old list is rebuilt from the current file');
  const oldActions = [...old.matchAll(/^\s*'([A-Z_]+)',?\s*$/gm)].map((match) => match[1]);
  assert.ok(oldActions.length >= 21 && oldActions.includes('GATEWAY_SETTINGS_UPDATE'));
  const db = new PGlite();
  try {
    // 007 이전 상태: 001~006(옛 002)
    await applyAll(db, { replace: { '002_admin_auth_audit.sql': old }, only: (name) => !name.startsWith('007') });
    assert.equal((await one(db, "SELECT to_regclass('dashboard_gateway_access') IS NULL AS missing")).missing, true);
    await assert.rejects(() => db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ('audit-early', now(), 'a', 'ACCESS_RULE_ADD', 'GATEWAY', 'x', 'SUCCESS')`), /check/i);
    const targetTypes = { ADMIN_LOGIN: 'ADMIN', ADMIN_LOGOUT: 'ADMIN', GPU_START: 'GPU', GPU_STOP: 'GPU', GATEWAY_SETTINGS_UPDATE: 'GATEWAY' };
    for (const action of oldActions)
      await db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result, changes) VALUES ($1, now(), 'a', $2, $3, 'target', 'SUCCESS', '{"new_version":1}'::jsonb)`,
        [`audit-old-${action}`, action, targetTypes[action] ?? 'POLICY']);
    const before = (await one(db, 'SELECT count(*)::int AS n FROM dashboard_admin_activity_history')).n;
    assert.equal(before, oldActions.length);
    // 새 파일 전체 적용(운영에서 migrate.mjs가 하는 일)
    await applyAll(db);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_admin_activity_history')).n, before);
    for (const action of NEW_ACTIONS)
      await db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ($1, now(), 'a', $2, 'GATEWAY', 'x', 'SUCCESS')`, [`audit-new-${action}`, action]);
    // 새 action 기록이 생긴 뒤에도 다시 적용된다
    await applyAll(db);
    await applyAll(db);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_admin_activity_history')).n, before + NEW_ACTIONS.length);
    const definition = (await one(db, "SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'dashboard_admin_activity_history_action_check'")).def;
    for (const action of [...oldActions, ...NEW_ACTIONS]) assert.ok(definition.includes(`'${action}'`), action);   // 목록은 줄지 않았다
  } finally {
    await db.close();
  }
});

void test('the store and the API work on the real tables: versions, audit rows, conflicts, aliases and a restart', { skip }, async () => {
  const db = new PGlite();
  await applyAll(db);
  const pool = poolFor(db);
  const config = { allowedOrigin: 'http://127.0.0.1:4173', adminEmail: 'local-admin-pglite@example.test', adminPassword: 'local-password-pglite-tests', ingestToken: 'local-ingest-token-pglite-tests' };
  const start = async () => {
    const server = createAppServer({ ...config, store: new PostgresEventStore({ pool }) });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identifier: config.adminEmail, password: config.adminPassword }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const call = async (method, pathname, payload, headers = {}) => {
      const response = await fetch(`${base}${pathname}`, { method, headers: { ...(payload ? { 'Content-Type': 'application/json' } : {}), Cookie: cookie, ...headers }, body: payload ? JSON.stringify(payload) : undefined });
      return { status: response.status, json: await response.json() };
    };
    return { server, call };
  };
  let running = await start();
  try {
    const metric = { active_clients: 1, concurrent_requests: 0, requests_per_sec: 0, avg_latency_ms: 1, p95_latency_ms: 1, timeout_rate: 0, degraded_rate: 0, total_requests: 1, completed_requests: 1, error_requests: 0, action_distribution: {}, llm_distribution: {}, detector_distribution: {}, window_seconds: 300 };
    const report = (call) => call('POST', '/api/traffic/metrics', metric, { Authorization: `Bearer ${config.ingestToken}`, Cookie: '' });
    assert.equal((await report(running.call)).json.gateway_access, null);

    const added = await running.call('POST', '/api/gateway-access/rules', { client_id: 'chrome-aaaa', reasons: ['LEAK_DOC_REPEAT', 'OTHER'], memo: '메모', duration: '1d', expected_version: 0 });
    assert.equal(added.status, 201);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_gateway_access')).n, 1);
    const stored = await one(db, 'SELECT version, revision, require_client_id, jsonb_array_length(rules) AS n, rules->0->>\'client_id\' AS client_id, rules->0->>\'memo\' AS memo, rules->0->\'reasons\' AS reasons FROM dashboard_gateway_access');
    assert.deepEqual([stored.version, stored.revision, stored.require_client_id, stored.n, stored.client_id, stored.memo], [1, added.json.revision, false, 1, 'chrome-aaaa', '메모']);
    assert.deepEqual(stored.reasons, ['LEAK_DOC_REPEAT', 'OTHER']);
    const auditAdd = await one(db, "SELECT target_type, target_id, changes FROM dashboard_admin_activity_history WHERE action = 'ACCESS_RULE_ADD'");
    assert.equal(auditAdd.target_type, 'GATEWAY');
    assert.equal(auditAdd.target_id, added.json.rule.id);
    assert.equal(auditAdd.changes.new_version, 1);
    assert.match(auditAdd.changes.new_value, /^확장 ID chrome-aaaa · 1일\(/);

    // 낡은 번호·같은 ID 중복은 행도 감사도 늘지 않는다
    assert.equal((await running.call('POST', '/api/gateway-access/rules', { client_id: 'chrome-bbbb', reasons: ['LEAVE'], duration: '1h', expected_version: 0 })).status, 409);
    assert.equal((await running.call('POST', '/api/gateway-access/rules', { client_id: 'chrome-aaaa', reasons: ['LEAVE'], duration: '1h', expected_version: 1 })).status, 409);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_gateway_access')).n, 1);
    assert.equal((await one(db, "SELECT count(*)::int AS n FROM dashboard_admin_activity_history WHERE action = 'ACCESS_RULE_ADD'")).n, 1);

    const mode = await running.call('PUT', '/api/gateway-access/mode', { require_client_id: true, expected_version: 1 });
    assert.equal(mode.status, 200);
    const released = await running.call('DELETE', `/api/gateway-access/rules/${added.json.rule.id}?expected_version=2`);
    assert.equal(released.status, 200);
    const latest = await one(db, "SELECT version, require_client_id, rules->0->>'removed_by' AS removed_by, rules->0->>'removed_at' AS removed_at FROM dashboard_gateway_access ORDER BY version DESC LIMIT 1");
    assert.deepEqual([latest.version, latest.require_client_id, latest.removed_by], [3, true, 'local-admin']);
    assert.ok(Number.isFinite(Date.parse(latest.removed_at)));
    assert.deepEqual((await db.query("SELECT action FROM dashboard_admin_activity_history WHERE action LIKE 'ACCESS_%' ORDER BY occurred_at, audit_id")).rows.map((row) => row.action).sort(), ['ACCESS_MODE_UPDATE', 'ACCESS_RULE_ADD', 'ACCESS_RULE_REMOVE']);

    // 별칭
    assert.equal((await running.call('PUT', '/api/client-aliases/chrome-aaaa', { alias: '홍길동 PC' })).status, 200);
    assert.equal((await running.call('PUT', '/api/client-aliases/chrome-aaaa', { alias: '홍길동 PC' })).status, 200);   // 같은 값: 기록 없음
    assert.equal((await running.call('PUT', '/api/client-aliases/chrome-cccc', { alias: '다른 PC' })).status, 200);
    assert.deepEqual((await running.call('GET', '/api/client-aliases')).json, { items: [{ client_id: 'chrome-aaaa', alias: '홍길동 PC' }, { client_id: 'chrome-cccc', alias: '다른 PC' }] });
    assert.equal((await running.call('PUT', '/api/client-aliases/chrome-aaaa', { alias: '길동 노트북' })).status, 200);
    assert.equal((await one(db, "SELECT alias FROM dashboard_client_aliases WHERE client_id = 'chrome-aaaa'")).alias, '길동 노트북');
    assert.equal((await running.call('PUT', '/api/client-aliases/chrome-cccc', { alias: '' })).json.alias, null);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_client_aliases')).n, 1);
    const aliasAudits = (await db.query("SELECT target_id, changes FROM dashboard_admin_activity_history WHERE action = 'CLIENT_ALIAS_UPDATE' ORDER BY audit_id")).rows;
    assert.equal(aliasAudits.length, 4);   // 설정 2 + 변경 1 + 삭제 1 (같은 값은 없음)
    assert.ok(aliasAudits.some((row) => row.changes.previous_value === '홍길동 PC' && row.changes.new_value === '길동 노트북'));
    assert.ok(aliasAudits.some((row) => row.target_id === 'chrome-cccc' && row.changes.new_value === '(삭제)'));

    // 다시 시작해도 가장 큰 번호가 현재 판이다
    await new Promise((resolve) => running.server.close(resolve));
    running = await start();
    const state = (await running.call('GET', '/api/gateway-access')).json;
    assert.equal(state.version, 3);
    assert.equal(state.require_client_id, true);
    assert.equal(state.rules.length, 1);
    assert.equal(state.rules[0].active, false);
    const document = (await report(running.call)).json.gateway_access;
    assert.deepEqual(Object.keys(document), ['version', 'revision', 'updated_at', 'require_client_id', 'rules']);
    assert.deepEqual(document.rules, []);
    assert.match(document.updated_at, /Z$/);
  } finally {
    await new Promise((resolve) => running.server.close(resolve));
    await db.close();
  }
});

void test('a failed audit insert rolls back the version row and the alias row; a duplicate revision is a conflict', { skip }, async () => {
  const db = new PGlite();
  await applyAll(db);
  const store = new PostgresEventStore({ pool: poolFor(db) });
  try {
    const save = (over = {}) => store.saveGatewayAccess({ expectedVersion: 0, revision: REV(1), requireClientId: false, rules: [rule(1)], updatedBy: 'local-admin', audit: audit('ACCESS_RULE_ADD'), ...over });
    await assert.rejects(() => save({ audit: audit('NOT_AN_ACTION') }), /check/i);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_gateway_access')).n, 0);   // 감사가 막히면 판도 없다
    assert.equal(await store.getGatewayAccess(), null);
    const first = await save();
    assert.equal(first.version, 1);
    assert.equal(first.updated_at, new Date(first.updated_at).toISOString());
    assert.deepEqual(first.rules, [rule(1)]);
    assert.deepEqual(await store.getGatewayAccess(), first);
    // 번호가 맞아도 같은 revision이면 충돌(동시에 들어온 경우)
    await assert.rejects(() => save({ expectedVersion: 1, revision: REV(1) }), (error) => error instanceof AccessConflictError && error.currentVersion === 1);
    // 낡은 번호
    await assert.rejects(() => save({ expectedVersion: 0, revision: REV(2) }), (error) => error instanceof AccessConflictError && error.currentVersion === 1);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_gateway_access')).n, 1);
    assert.equal((await one(db, "SELECT count(*)::int AS n FROM dashboard_admin_activity_history WHERE action = 'ACCESS_RULE_ADD'")).n, 1);
    const second = await save({ expectedVersion: 1, revision: REV(2), requireClientId: true, rules: [], audit: audit('ACCESS_MODE_UPDATE') });
    assert.equal(second.version, 2);
    assert.equal(second.require_client_id, true);
    assert.deepEqual(await store.getGatewayAccess(), second);

    // 별칭: 감사가 막히면 별칭도 없다
    await assert.rejects(() => store.saveClientAlias({ clientId: 'chrome-1', alias: '이름', updatedBy: 'a', audit: () => audit('NOT_AN_ACTION') }), /check/i);
    assert.deepEqual(await store.listClientAliases(), []);
    const set = await store.saveClientAlias({ clientId: 'chrome-1', alias: '이름', updatedBy: 'a', audit: (previous) => ({ ...audit('CLIENT_ALIAS_UPDATE', 'chrome-1'), changes: { previous_value: String(previous), new_value: '이름' } }) });
    assert.deepEqual(set, { previous: null, alias: '이름', changed: true });
    const same = await store.saveClientAlias({ clientId: 'chrome-1', alias: '이름', updatedBy: 'a', audit: () => { throw new Error('not called'); } });
    assert.equal(same.changed, false);
    const gone = await store.saveClientAlias({ clientId: 'chrome-1', alias: null, updatedBy: 'a', audit: (previous) => ({ ...audit('CLIENT_ALIAS_UPDATE', 'chrome-1'), changes: { previous_value: previous, new_value: '(삭제)' } }) });
    assert.deepEqual(gone, { previous: '이름', alias: null, changed: true });
    assert.deepEqual(await store.listClientAliases(), []);
    assert.equal((await one(db, "SELECT count(*)::int AS n FROM dashboard_admin_activity_history WHERE action = 'CLIENT_ALIAS_UPDATE'")).n, 2);
  } finally {
    await db.close();
  }
});

void test('a database from before 007 (no access tables) reads as no rules and no aliases', { skip }, async () => {
  const db = new PGlite();
  try {
    await applyAll(db, { only: (name) => !name.startsWith('007') });
    const store = new PostgresEventStore({ pool: poolFor(db) });
    assert.equal(await store.getGatewayAccess(), null);
    assert.deepEqual(await store.listClientAliases(), []);
  } finally {
    await db.close();
  }
});
