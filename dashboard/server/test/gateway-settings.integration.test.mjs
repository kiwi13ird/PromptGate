// Gateway 처리 설정(2026-10-10): 관리자 조회·저장, 지표 응답으로 전달, 반영 상태 계산
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createAppServer, gatewaySettingsState } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import {
  defaultGatewaySettings,
  gatewaySettingsDocument,
  parseGatewaySettings,
  parseSettingsApplied,
  summarizeGatewaySettings,
} from '../gateway-settings.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-gateway@example.test',
  adminPassword: 'local-password-gateway-tests',
  ingestToken: 'local-ingest-token-gateway-tests',
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REV = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const DOCUMENT_FIELDS = ['version', 'revision', 'updated_at', 'updated_by', 'timeout', 'uninspectable', 'notify_on_allow'];
const DEFAULT_SUMMARY = '질문 지연 시 원본 전송(0.5초) · 파일 지연 시 차단(2초) · 이미지 허용 · 스캔 PDF 차단 · 기타 형식 차단 · 허용 알림 끔';
const metrics = (over = {}) => ({
  active_clients: 1, concurrent_requests: 0, requests_per_sec: 0.2, avg_latency_ms: 30, p95_latency_ms: 80, timeout_rate: 0, degraded_rate: 0,
  total_requests: 5, completed_requests: 5, error_requests: 0, action_distribution: {}, llm_distribution: {}, detector_distribution: {}, window_seconds: 300, ...over,
});
const body = (over = {}) => ({ expected_version: 0, ...defaultGatewaySettings(), ...over });
const applied = (over = {}) => ({ version: 0, revision: null, source: 'ENV_DEFAULT', applied_at: '2026-10-10T05:12:07.900+09:00', rejected: null,
  effective: defaultGatewaySettings(), ...over });

async function withBackend(run, { store, makeStore, retryMs } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-settings-'));
  const storePath = path.join(root, 'events.json');
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
    const settings = () => call('GET', '/api/gateway-settings');
    const save = (payload) => call('PUT', '/api/gateway-settings', payload);
    const report = (payload) => call('POST', '/api/traffic/metrics', payload, { session: false, headers: { Authorization: `Bearer ${CONFIG.ingestToken}` } });
    const audits = async () => (await call('GET', '/api/audit-logs?period=24H&page_size=100')).json.items.filter((item) => item.action === 'GATEWAY_SETTINGS_UPDATE');
    await run({ base, storePath, call, settings, save, report, audits });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

void test('settings need a session and start at version 0 defaults', async () => {
  await withBackend(async ({ call, settings }) => {
    assert.equal((await call('GET', '/api/gateway-settings', undefined, { session: false })).status, 401);
    assert.equal((await call('PUT', '/api/gateway-settings', body(), { session: false })).status, 401);
    assert.equal((await call('DELETE', '/api/gateway-settings')).status, 405);
    const first = await settings();
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('cache-control'), 'no-store');
    assert.deepEqual(first.json.settings, { version: 0, revision: null, updated_at: null, updated_by: null, ...defaultGatewaySettings(), source: 'DEFAULT' });
    assert.deepEqual(first.json.defaults, defaultGatewaySettings());
    assert.deepEqual(first.json.gateway, {
      state: 'NOT_REPORTING', metrics_status: 'NOT_RECEIVED', reported_at: null, applied_version: null, applied_revision: null,
      applied_source: null, applied_at: null, first_seen_at: null, rejected: null, effective: null,
    });
  });
});

void test('saving rejects bad requests with 415, 400, 422 and 409 and records nothing', async () => {
  await withBackend(async ({ call, save, settings, audits }) => {
    const text = await call('PUT', '/api/gateway-settings', undefined, { headers: { 'Content-Type': 'text/plain' }, raw: JSON.stringify(body()) });
    assert.equal(text.status, 415);
    assert.equal((await call('PUT', '/api/gateway-settings', undefined, { headers: { 'Content-Type': 'application/json' }, raw: '{broken' })).status, 400);
    assert.equal((await call('PUT', '/api/gateway-settings', undefined, { headers: { 'Content-Type': 'application/json' }, raw: 'x'.repeat(17 * 1024) })).status, 413);
    const defaults = defaultGatewaySettings();
    // 모르는 칸·빠진 칸 → 400
    for (const payload of [
      [1, 2],
      { ...body(), extra: true },
      (({ notify_on_allow, ...rest }) => rest)(body()),
      body({ timeout: { ...defaults.timeout, query: { action: 'block', seconds: 1 } } }),
      body({ timeout: { prompt: { action: 'block' }, file: defaults.timeout.file } }),
      body({ timeout: { prompt: { ...defaults.timeout.prompt, retries: 1 }, file: defaults.timeout.file } }),
      body({ uninspectable: { image: 'allow', scanned_pdf: 'block' } }),
      body({ uninspectable: { ...defaults.uninspectable, svg: 'block' } }),
    ]) {
      const result = await save(payload);
      assert.equal(result.status, 400, JSON.stringify(payload));
      assert.equal(result.json.error.code, 'BAD_REQUEST');
    }
    // 값 범위 위반 → 422 + 칸 경로(Gateway가 거부 칸을 부르는 이름과 같음)
    const rule = (kind, value) => body({ timeout: { ...defaults.timeout, [kind]: { ...defaults.timeout[kind], ...value } } });
    for (const [payload, where] of [
      [rule('prompt', { seconds: 0.04 }), 'timeout.prompt.seconds'],
      [rule('file', { seconds: 30.01 }), 'timeout.file.seconds'],
      [rule('file', { seconds: true }), 'timeout.file.seconds'],
      [rule('file', { seconds: '2' }), 'timeout.file.seconds'],
      [rule('file', { seconds: null }), 'timeout.file.seconds'],
      [rule('file', { action: 'allow' }), 'timeout.file.action'],
      [rule('prompt', { action: 'FORWARD' }), 'timeout.prompt.action'],
      [body({ uninspectable: { ...defaults.uninspectable, image: 'forward' } }), 'uninspectable.image'],
      [body({ notify_on_allow: 'false' }), 'notify_on_allow'],
      [body({ timeout: 5 }), 'timeout'],
      [body({ expected_version: -1 }), 'expected_version'],
      [body({ expected_version: 1.5 }), 'expected_version'],
      [body({ expected_version: '0' }), 'expected_version'],
    ]) {
      const result = await save(payload);
      assert.equal(result.status, 422, where);
      assert.equal(result.json.error.code, 'VALIDATION');
      assert.equal(result.json.error.details.path, where);
    }
    const stale = await save(body({ expected_version: 4 }));
    assert.equal(stale.status, 409);
    assert.equal(stale.json.error.code, 'SETTINGS_VERSION_CONFLICT');
    assert.deepEqual(stale.json.error.details, { current_version: 0 });
    assert.equal((await settings()).json.settings.version, 0);
    assert.deepEqual(await audits(), []);   // 실패는 기록하지 않는다
  });
});

void test('saves append versions with one audit row each, and the first omits previous_version', async () => {
  await withBackend(async ({ save, settings, audits }) => {
    const defaults = defaultGatewaySettings();
    const first = await save(body({ timeout: { prompt: { action: 'block', seconds: 0.125 }, file: { action: 'forward', seconds: 30 } } }));
    assert.equal(first.status, 200);
    assert.equal(first.json.settings.version, 1);
    assert.equal(first.json.settings.source, 'STORED');
    assert.match(first.json.settings.revision, UUID);
    assert.equal(first.json.settings.updated_by, 'local-admin');
    assert.ok(Number.isFinite(Date.parse(first.json.settings.updated_at)));
    assert.deepEqual(first.json.settings.timeout, { prompt: { action: 'block', seconds: 0.125 }, file: { action: 'forward', seconds: 30 } });
    assert.deepEqual(first.json.defaults, defaults);
    assert.equal(first.json.gateway.state, 'NOT_REPORTING');
    assert.deepEqual((await settings()).json.settings, first.json.settings);

    let rows = await audits();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].target_type, 'GATEWAY');
    assert.equal(rows[0].target_id, 'gateway-settings');
    assert.equal(rows[0].admin_id, 'local-admin');
    assert.equal(rows[0].result, 'SUCCESS');
    assert.deepEqual(rows[0].changes, {
      new_version: 1,
      previous_value: `기본값 · ${DEFAULT_SUMMARY}`,
      new_value: '질문 지연 시 차단(0.125초) · 파일 지연 시 원본 전송(30초) · 이미지 허용 · 스캔 PDF 차단 · 기타 형식 차단 · 허용 알림 끔',
    });

    const second = await save(body({ expected_version: 1, uninspectable: { image: 'block', scanned_pdf: 'allow', other: 'allow' }, notify_on_allow: true }));
    assert.equal(second.status, 200);
    assert.equal(second.json.settings.version, 2);
    assert.notEqual(second.json.settings.revision, first.json.settings.revision);
    rows = await audits();
    assert.equal(rows.length, 2);
    assert.deepEqual(rows.find((row) => row.changes.new_version === 2).changes, {
      previous_version: 1,
      new_version: 2,
      previous_value: '질문 지연 시 차단(0.125초) · 파일 지연 시 원본 전송(30초) · 이미지 허용 · 스캔 PDF 차단 · 기타 형식 차단 · 허용 알림 끔',
      new_value: `${DEFAULT_SUMMARY.replace('이미지 허용 · 스캔 PDF 차단 · 기타 형식 차단 · 허용 알림 끔', '이미지 차단 · 스캔 PDF 허용 · 기타 형식 허용 · 허용 알림 켬')}`,
    });
    // 같은 내용이라도 저장할 때마다 새 번호·새 revision
    const third = await save(body({ expected_version: 2, uninspectable: { image: 'block', scanned_pdf: 'allow', other: 'allow' }, notify_on_allow: true }));
    assert.equal(third.json.settings.version, 3);
    assert.notEqual(third.json.settings.revision, second.json.settings.revision);
    assert.equal((await save(body({ expected_version: 2 }))).status, 409);
  });
});

void test('two administrators saving at once: exactly one wins', async () => {
  await withBackend(async ({ save, settings, audits }) => {
    const results = await Promise.all([save(body({ notify_on_allow: true })), save(body({ notify_on_allow: false }))]);
    assert.deepEqual(results.map((result) => result.status).sort(), [200, 409]);
    const loser = results.find((result) => result.status === 409);
    assert.equal(loser.json.error.code, 'SETTINGS_VERSION_CONFLICT');
    assert.deepEqual(loser.json.error.details, { current_version: 1 });
    const current = (await settings()).json.settings;
    assert.equal(current.version, 1);
    assert.equal(current.notify_on_allow, results.find((result) => result.status === 200).json.settings.notify_on_allow);
    assert.equal((await audits()).length, 1);
  });
});

void test('settings survive a restart from the JSON store', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-settings-restart-'));
  const storePath = path.join(root, 'events.json');
  try {
    let revision;
    await withBackend(async ({ save }) => {
      revision = (await save(body({ notify_on_allow: true }))).json.settings.revision;
    }, { store: new JsonEventStore(storePath) });
    await withBackend(async ({ settings }) => {
      const current = (await settings()).json.settings;
      assert.equal(current.version, 1);
      assert.equal(current.revision, revision);
      assert.equal(current.notify_on_allow, true);
    }, { store: new JsonEventStore(storePath) });
    const file = JSON.parse(await readFile(storePath, 'utf8'));
    assert.deepEqual(Object.keys(file.gatewaySettings[0]).sort(), ['revision', 'settings', 'updated_at', 'updated_by', 'version']);
    assert.deepEqual(Object.keys(file.gatewaySettings[0].settings), ['timeout', 'uninspectable', 'notify_on_allow']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// PostgreSQL 저장소의 트랜잭션을 흉내 내는 가짜 pool(감사 삽입 실패를 일으킬 수 있다)
function fakeSettingsPool({ failAudit = false } = {}) {
  const state = { rows: [], audits: [], statements: [] };
  const committedQuery = async (sql) => {
    state.statements.push(sql.trim().split(/\s+/).slice(0, 3).join(' '));
    if (/FROM dashboard_gateway_settings\s+ORDER BY version DESC/.test(sql)) return { rows: state.rows.slice(-1), rowCount: Math.min(1, state.rows.length) };
    if (/COALESCE\(max\(version\), 0\) AS version/.test(sql)) return { rows: [{ version: state.rows.at(-1)?.version ?? 0 }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  };
  const pool = {
    state,
    async query(sql) {
      if (/INSERT INTO dashboard_admin_activity_history/.test(sql)) return { rows: [], rowCount: 1 };   // 로그인 감사
      return committedQuery(sql);
    },
    async connect() {
      let staged = null;
      return {
        async query(sql, params = []) {
          const statement = sql.trim();
          if (statement === 'BEGIN') { staged = { rows: [...state.rows], audits: [] }; state.statements.push('BEGIN'); return { rows: [], rowCount: 0 }; }
          if (statement === 'COMMIT') { state.rows = staged.rows; state.audits.push(...staged.audits); staged = null; state.statements.push('COMMIT'); return { rows: [], rowCount: 0 }; }
          if (statement === 'ROLLBACK') { staged = null; state.statements.push('ROLLBACK'); return { rows: [], rowCount: 0 }; }
          if (/INSERT INTO dashboard_gateway_settings/.test(sql)) {
            state.statements.push('INSERT settings');
            const [expected, revision, settings, updatedBy] = params;
            if ((staged.rows.at(-1)?.version ?? 0) !== expected) return { rows: [], rowCount: 0 };
            if (staged.rows.some((row) => row.revision === revision)) throw Object.assign(new Error('duplicate key value'), { code: '23505' });
            const row = { version: expected + 1, revision, settings: JSON.parse(settings), updated_by: updatedBy, updated_at: new Date() };
            staged.rows.push(row);
            return { rows: [row], rowCount: 1 };
          }
          if (/INSERT INTO dashboard_admin_activity_history/.test(sql)) {
            state.statements.push('INSERT audit');
            if (failAudit) throw new Error('new row violates check constraint "dashboard_admin_activity_history_action_check"');
            staged.audits.push(params);
            return { rows: [], rowCount: 1 };
          }
          return committedQuery(sql);
        },
        release() { state.statements.push('release'); },
      };
    },
  };
  return pool;
}

void test('an audit write failure is a save failure: 500 and no settings row', async () => {
  const pool = fakeSettingsPool({ failAudit: true });
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    await withBackend(async ({ save, settings }) => {
      const result = await save(body({ notify_on_allow: true }));
      assert.equal(result.status, 500);
      assert.deepEqual(result.json, { error: { code: 'SERVER', message: 'Internal server error.' } });
      assert.deepEqual(pool.state.rows, []);
      assert.deepEqual(pool.state.audits, []);
      assert.deepEqual(pool.state.statements.slice(-5), ['BEGIN', 'INSERT settings', 'INSERT audit', 'ROLLBACK', 'release']);
      const current = (await settings()).json.settings;
      assert.equal(current.version, 0);
      assert.equal(current.source, 'DEFAULT');
    }, { store: new PostgresEventStore({ pool }) });
  } finally {
    console.error = originalConsoleError;
  }
});

void test('the PostgreSQL store saves settings and audit together through the API', async () => {
  const pool = fakeSettingsPool();
  await withBackend(async ({ save, report }) => {
    const first = await save(body());
    assert.equal(first.status, 200);
    assert.equal(first.json.settings.version, 1);
    assert.equal(pool.state.rows.length, 1);
    assert.equal(pool.state.audits.length, 1);
    const [, , adminId, action, targetType, targetId, result, changes] = pool.state.audits[0];
    assert.deepEqual([adminId, action, targetType, targetId, result], ['local-admin', 'GATEWAY_SETTINGS_UPDATE', 'GATEWAY', 'gateway-settings', 'SUCCESS']);
    assert.equal(JSON.parse(changes).previous_version, undefined);
    assert.deepEqual(Object.keys((await report(metrics())).json.gateway_settings), DOCUMENT_FIELDS);
  }, { store: new PostgresEventStore({ pool }) });
});

void test('a failed startup read gives 503 and no settings field until the timer reads again', async () => {
  class FlakyStore extends JsonEventStore {
    failing = true;
    reads = 0;
    async getGatewaySettings() {
      this.reads += 1;
      if (this.failing) throw new Error('database unavailable');
      return super.getGatewaySettings();
    }
  }
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-settings-flaky-'));
  const store = new FlakyStore(path.join(root, 'events.json'));
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    await withBackend(async ({ settings, save, report }) => {
      const unavailable = await settings();
      assert.equal(unavailable.status, 503);
      assert.equal(unavailable.json.error.code, 'SETTINGS_UNAVAILABLE');
      assert.equal((await save(body())).status, 503);
      const accepted = await report(metrics());
      assert.equal(accepted.status, 202);
      assert.deepEqual(accepted.json, { accepted: true, metrics_ext: 1, gateway_access: null });   // 설정 칸 없음 → Gateway는 지금 값 유지(접속 차단 칸은 따로 읽혀 null)
      const readsWhileDown = store.reads;
      store.failing = false;
      let response;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        response = await report(metrics());
        if ('gateway_settings' in response.json) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.deepEqual(response.json, { accepted: true, metrics_ext: 1, gateway_settings: null, gateway_access: null });   // 지표가 아니라 타이머가 다시 읽었다
      assert.ok(store.reads > readsWhileDown);
      assert.equal((await settings()).status, 200);
      assert.equal((await save(body())).status, 200);
    }, { store, retryMs: 10 });
  } finally {
    console.error = originalConsoleError;
    await rm(root, { recursive: true, force: true });
  }
});

// 되돌리며 DROP TABLE dashboard_gateway_settings 뒤 백엔드를 다시 시작한 경우(42P01): 저장 없음 → 지표 응답 null(Gateway 환경변수 기본값)
void test('a restarted backend reads a dropped settings table as no stored settings and sends null', async () => {
  let reads = 0;
  const missing = () => Object.assign(new Error('relation "dashboard_gateway_settings" does not exist'), { code: '42P01' });
  const pool = {
    async query(sql) {
      if (/INSERT INTO dashboard_admin_activity_history/.test(sql)) return { rows: [], rowCount: 1 };   // 로그인 감사
      if (/FROM dashboard_gateway_settings/.test(sql)) {
        reads += 1;
        throw missing();
      }
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      return {
        async query(sql) {
          if (/dashboard_gateway_settings/.test(sql)) throw missing();
          return { rows: [], rowCount: 0 };
        },
        release() {},
      };
    },
  };
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    await withBackend(async ({ settings, save, report }) => {
      const current = await settings();
      assert.equal(current.status, 200);
      assert.deepEqual(current.json.settings, { version: 0, revision: null, updated_at: null, updated_by: null, ...defaultGatewaySettings(), source: 'DEFAULT' });
      assert.deepEqual((await report(metrics())).json, { accepted: true, metrics_ext: 1, gateway_settings: null, gateway_access: null });   // → Gateway는 환경변수 기본값, 사본 삭제
      assert.equal((await save(body())).status, 500);   // 표가 없으니 저장은 DB 오류(이관을 다시 돌리면 v1부터)
      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.equal(reads, 1);   // 표 없음은 읽기 실패가 아니므로 타이머로 다시 읽지 않는다
    }, { store: new PostgresEventStore({ pool }), retryMs: 10 });
  } finally {
    console.error = originalConsoleError;
  }
});

void test('metrics responses carry the stored document and never read the store', async () => {
  const calls = [];
  const makeStore = (file) => {
    const inner = new JsonEventStore(file);
    return new Proxy(inner, {
      get(target, property) {
        const value = target[property];
        if (typeof value !== 'function') return value;
        return (...args) => {
          calls.push(String(property));
          return value.apply(target, args);
        };
      },
    });
  };
  await withBackend(async ({ save, report, call }) => {
    calls.length = 0;
    const before = await report(metrics());
    assert.equal(before.status, 202);
    assert.deepEqual(before.json, { accepted: true, metrics_ext: 1, gateway_settings: null, gateway_access: null });
    assert.deepEqual(calls, []);

    const saved = (await save(body({ notify_on_allow: true }))).json.settings;
    calls.length = 0;
    const after = await report(metrics({ settings_applied: applied() }));
    assert.deepEqual(calls, []);   // 지표 처리 중 저장소 조회 0회
    assert.equal(after.status, 202);
    assert.equal(after.json.accepted, true);
    assert.deepEqual(Object.keys(after.json.gateway_settings), DOCUMENT_FIELDS);   // §1.1 문서 칸만(source 없음)
    const { source, ...document } = saved;
    assert.equal(source, 'STORED');
    assert.deepEqual(after.json.gateway_settings, document);
    // 칸이 틀린 지표는 지금처럼 거부한다(settings_applied만 관대하게)
    assert.equal((await report(metrics({ unknown_metric: 1 }))).status, 400);
    assert.equal((await call('POST', '/api/traffic/metrics', metrics(), { session: false })).status, 401);
  }, { makeStore });
});

void test('the gateway report drives the applied state end to end', async () => {
  await withBackend(async ({ save, settings, report, call }) => {
    const state = async () => (await settings()).json.gateway;
    assert.equal((await report(metrics())).status, 202);
    assert.equal((await state()).state, 'LEGACY_GATEWAY');
    assert.equal((await state()).metrics_status, 'FRESH');

    assert.equal((await report(metrics({ settings_applied: applied() }))).status, 202);
    let gateway = await state();
    assert.equal(gateway.state, 'APPLIED');   // 저장 없음 + 환경변수 기본값
    assert.equal(gateway.applied_source, 'ENV_DEFAULT');
    assert.equal(gateway.applied_version, 0);
    assert.equal(gateway.first_seen_at, gateway.reported_at);

    const saved = (await save(body({ notify_on_allow: true }))).json;
    assert.equal(saved.gateway.state, 'PENDING');
    const { revision } = saved.settings;
    const appliedNow = applied({ version: 1, revision, source: 'DASHBOARD', effective: { ...defaultGatewaySettings(), notify_on_allow: true } });
    await report(metrics({ settings_applied: appliedNow }));
    gateway = await state();
    assert.equal(gateway.state, 'APPLIED');
    assert.equal(gateway.applied_revision, revision);
    assert.equal(gateway.applied_at, appliedNow.applied_at);
    assert.deepEqual(gateway.effective, appliedNow.effective);
    const firstSeen = gateway.first_seen_at;
    assert.equal(firstSeen, gateway.reported_at);
    await new Promise((resolve) => setTimeout(resolve, 5));
    await report(metrics({ settings_applied: { ...appliedNow, source: 'CACHE' } }));
    gateway = await state();
    assert.equal(gateway.first_seen_at, firstSeen);   // 같은 판을 다시 보고해도 처음 본 시각 그대로
    assert.notEqual(gateway.reported_at, firstSeen);

    // 형식이 틀린 보고: 지표는 받고 칸만 버린다
    const bad = await report(metrics({ settings_applied: { ...appliedNow, effective: { ...appliedNow.effective, notify_on_allow: 'yes' } } }));
    assert.equal(bad.status, 202);
    assert.equal(bad.json.gateway_settings.revision, revision);
    gateway = await state();
    assert.equal(gateway.state, 'REPORT_INVALID');
    assert.equal(gateway.applied_version, null);
    const summary = (await call('GET', '/api/traffic/summary?period=24H')).json;
    assert.equal(summary.gateway_metrics_status, 'FRESH');   // 트래픽 화면은 멈추지 않는다
    assert.equal(summary.gateway_total_requests, 5);
    for (const malformed of [null, 'x', { ...appliedNow, extra: 1 }, { ...appliedNow, revision: revision.toUpperCase() }])
      assert.equal((await report(metrics({ settings_applied: malformed }))).status, 202);

    // Gateway가 거부한 판
    await report(metrics({ settings_applied: applied({ rejected: { version: 1, revision, field: 'timeout.file.seconds' } }) }));
    gateway = await state();
    assert.equal(gateway.state, 'REJECTED');
    assert.deepEqual(gateway.rejected, { version: 1, revision, field: 'timeout.file.seconds' });
  });
});

void test('applied state covers every case, including the same version with another revision', () => {
  const now = Date.parse('2026-10-10T05:12:30Z');
  const at = (seconds) => new Date(now - seconds * 1000).toISOString();
  const stored = { version: 3, revision: REV(3), settings: defaultGatewaySettings(), updated_by: 'local-admin', updated_at: at(60) };
  const fresh = (over) => ({ ...metrics(), received_at: at(10), ...over });
  const report = (over) => applied({ version: 3, revision: REV(3), source: 'DASHBOARD', ...over });
  const state = (row, metricsValue, firstSeen) => gatewaySettingsState(row, metricsValue, firstSeen, now);

  assert.equal(state(stored, null).state, 'NOT_REPORTING');
  const stale = state(stored, { ...fresh({ settings_applied: report() }), received_at: at(121) });
  assert.equal(stale.state, 'NOT_REPORTING');
  assert.equal(stale.metrics_status, 'STALE');
  assert.equal(stale.applied_version, 3);   // 마지막으로 받은 보고는 그대로 보여 준다
  assert.equal(state(stored, fresh()).state, 'LEGACY_GATEWAY');
  assert.equal(state(stored, fresh({ settings_applied_invalid: true })).state, 'REPORT_INVALID');
  assert.equal(state(stored, fresh({ settings_applied: report() })).state, 'APPLIED');
  assert.equal(state(stored, fresh({ settings_applied: report({ source: 'CACHE' }) })).state, 'APPLIED');
  assert.equal(state(null, fresh({ settings_applied: applied() })).state, 'APPLIED');
  assert.equal(state(null, fresh({ settings_applied: report({ source: 'CACHE' }) })).state, 'PENDING');   // DB를 비웠는데 Gateway는 옛 사본
  assert.equal(state(stored, fresh({ settings_applied: report({ version: 2, revision: REV(2),
    rejected: { version: 3, revision: REV(3), field: 'uninspectable.image' } }) })).state, 'REJECTED');
  assert.equal(state(stored, fresh({ settings_applied: report({ version: 2, revision: REV(2) }) })).state, 'PENDING');
  assert.equal(state(stored, fresh({ settings_applied: applied() })).state, 'PENDING');
  // 같은 번호, 다른 revision(DB를 지웠다 다시 만들어 번호가 겹침) → 반영 아님
  assert.equal(state(stored, fresh({ settings_applied: report({ revision: REV(33) }) })).state, 'PENDING');
  assert.equal(state(stored, fresh({ settings_applied: report({ revision: REV(33), rejected: { version: 3, revision: REV(34), field: 'timeout' } }) })).state, 'PENDING');

  const seen = { key: `3\n${REV(3)}`, at: at(20) };
  assert.equal(state(stored, fresh({ settings_applied: report() }), seen).first_seen_at, at(20));
  assert.equal(state(stored, fresh({ settings_applied: report({ revision: REV(33) }) }), seen).first_seen_at, null);
});

void test('the gateway report format is checked leniently but completely', () => {
  const dashboard = applied({ version: 4, revision: REV(4), source: 'DASHBOARD', applied_at: '2026-10-10T05:12:07.900Z' });
  assert.deepEqual(parseSettingsApplied(dashboard), dashboard);
  assert.deepEqual(parseSettingsApplied(applied()), applied());
  assert.deepEqual(parseSettingsApplied(applied({ applied_at: null, rejected: { version: null, revision: null, field: 'version' } })).rejected,
    { version: null, revision: null, field: 'version' });
  const effective = defaultGatewaySettings();
  effective.timeout.file.seconds = 0.125;
  assert.equal(parseSettingsApplied(applied({ effective })).effective.timeout.file.seconds, 0.125);
  for (const bad of [
    applied({ version: 1 }),                                     // 환경변수 기본값은 0
    applied({ revision: REV(1) }),
    applied({ version: 1, revision: REV(1), source: 'DASHBOARD', extra: true }),
    applied({ version: 0, revision: REV(1), source: 'DASHBOARD' }),
    applied({ version: 1, revision: null, source: 'CACHE' }),
    applied({ version: -1 }),
    applied({ version: 1.5, revision: REV(1), source: 'DASHBOARD' }),
    applied({ source: 'FILE' }),
    applied({ rejected: { version: 1, revision: REV(1), field: 'Timeout.File' } }),
    applied({ rejected: { version: 1, revision: REV(1) } }),
    applied({ effective: { ...defaultGatewaySettings(), notify_on_allow: 1 } }),
    applied({ effective: { ...defaultGatewaySettings(), source: 'ENV_DEFAULT' } }),
    (({ effective, ...rest }) => rest)(applied()),
    (({ applied_at, ...rest }) => rest)(applied()),                // 칸이 빠진 것은 여전히 형식 오류
  ]) assert.throws(() => parseSettingsApplied(bad), JSON.stringify(bad));
});

// applied_at은 화면 표시용(Gateway 시계)이라 형식이 틀려도 그 값만 null로 두고 번호·revision·effective는 받는다
// (Python datetime.now().isoformat()의 시간대 없는 값, strftime %z의 +0000 등)
void test('a malformed applied_at becomes null and the rest of the report is kept', async () => {
  const dashboard = applied({ version: 4, revision: REV(4), source: 'DASHBOARD' });
  for (const appliedAt of ['2026-10-10T15:12:00.542771', '2026-10-10T06:12:00+0000', '2026-10-10T05:12:07', 'x'.repeat(51), 'yesterday', 1760073127, {}])
    assert.deepEqual(parseSettingsApplied({ ...dashboard, applied_at: appliedAt }), { ...dashboard, applied_at: null }, JSON.stringify(appliedAt));
  for (const appliedAt of ['2026-10-10T06:12:00+00:00', '2026-10-10T06:12:00Z', '2026-10-10T15:12:00.542771+09:00', null])
    assert.equal(parseSettingsApplied({ ...dashboard, applied_at: appliedAt }).applied_at, appliedAt);

  await withBackend(async ({ save, settings, report }) => {
    const { revision } = (await save(body())).json.settings;
    const naive = applied({ version: 1, revision, source: 'DASHBOARD', applied_at: '2026-10-10T15:12:00.542771' });
    assert.equal((await report(metrics({ settings_applied: naive }))).status, 202);
    const gateway = (await settings()).json.gateway;
    assert.equal(gateway.state, 'APPLIED');
    assert.equal(gateway.applied_version, 1);
    assert.equal(gateway.applied_revision, revision);
    assert.equal(gateway.applied_source, 'DASHBOARD');
    assert.equal(gateway.applied_at, null);
    assert.equal(gateway.first_seen_at, gateway.reported_at);
    assert.deepEqual(gateway.effective, defaultGatewaySettings());
  });
});

void test('settings rules match the gateway: range only, no decimal-place rule', () => {
  const rule = (seconds) => {
    const value = defaultGatewaySettings();
    value.timeout.prompt.seconds = seconds;
    return value;
  };
  for (const seconds of [0.05, 0.125, 1, 2.0, 29.999, 30]) assert.equal(parseGatewaySettings(rule(seconds)).timeout.prompt.seconds, seconds);
  for (const seconds of [0.04, 30.01, Number.NaN, Number.POSITIVE_INFINITY, true, '1', null]) assert.throws(() => parseGatewaySettings(rule(seconds)));
  assert.equal(summarizeGatewaySettings(defaultGatewaySettings()), DEFAULT_SUMMARY);
  assert.equal(summarizeGatewaySettings(defaultGatewaySettings(), { isDefault: true }), `기본값 · ${DEFAULT_SUMMARY}`);
  assert.equal(gatewaySettingsDocument(null), null);
  // 저장된 값은 칸 순서를 맞춰 내보낸다(JSONB는 칸 순서를 바꾼다)
  const reordered = { notify_on_allow: false, uninspectable: { other: 'block', scanned_pdf: 'block', image: 'allow' },
    timeout: { file: { seconds: 2, action: 'block' }, prompt: { seconds: 0.5, action: 'forward' } } };
  const document = gatewaySettingsDocument({ version: 1, revision: REV(1), settings: reordered, updated_by: 'local-admin', updated_at: '2026-10-10T05:12:00.000Z' });
  assert.deepEqual(Object.keys(document), DOCUMENT_FIELDS);
  assert.equal(JSON.stringify(document.timeout), JSON.stringify(defaultGatewaySettings().timeout));
});

// 손으로 넣은 행·앞으로 모양이 바뀐 행처럼 저장된 값이 형식에 맞지 않을 때(PG CHECK는 객체인지만 본다)
void test('a stored row with the wrong shape still loads and can be repaired from the dashboard', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-settings-invalid-row-'));
  const storePath = path.join(root, 'events.json');
  const defaults = defaultGatewaySettings();
  const row = (settings) => ({ version: 1, revision: REV(1), settings, updated_by: 'local-admin', updated_at: '2026-10-10T05:12:00.000Z' });
  const writeStore = (settings) => writeFile(storePath, JSON.stringify({ version: 1, records: [], auditRecords: [], gatewaySettings: [row(settings)] }), 'utf8');
  const shown = { version: 1, revision: REV(1), updated_at: '2026-10-10T05:12:00.000Z', updated_by: 'local-admin', ...defaults, source: 'STORED' };
  try {
    for (const [settings, field] of [
      [{}, 'settings'],
      [{ ...defaults, notify_on_allow: 'no' }, 'notify_on_allow'],
      [{ ...defaults, timeout: { ...defaults.timeout, file: { action: 'block', seconds: 99 } } }, 'timeout.file.seconds'],
      [{ ...defaults, uninspectable: { ...defaults.uninspectable, svg: 'block' } }, 'uninspectable'],
    ]) {
      await writeStore(settings);
      await withBackend(async ({ settings: get }) => {
        const loaded = await get();
        assert.equal(loaded.status, 200, field);
        assert.deepEqual(loaded.json.settings, shown, field);   // 화면의 엄격한 저장 문서 모양: 그 번호에 기본값
        assert.deepEqual(loaded.json.settings_invalid, { field });
      }, { store: new JsonEventStore(storePath) });
    }

    const broken = { timeout: { prompt: { action: 'forward', seconds: 0.5 } }, uninspectable: { ...defaults.uninspectable }, notify_on_allow: false };
    await writeStore(broken);
    await withBackend(async ({ settings: get, save, report, audits }) => {
      const loaded = await get();
      assert.equal(loaded.status, 200);
      assert.deepEqual(loaded.json.settings, shown);
      assert.deepEqual(loaded.json.settings_invalid, { field: 'timeout' });
      // Gateway에는 저장된 그대로 보낸다 → Gateway가 거부하고 마지막 값을 유지(REJECTED), 기본값을 몰래 적용하지 않는다
      const { source, ...document } = shown;
      assert.deepEqual((await report(metrics())).json.gateway_settings, { ...document, ...broken });
      const repaired = await save(body({ expected_version: 1, notify_on_allow: true }));
      assert.equal(repaired.status, 200);
      assert.equal(repaired.json.settings.version, 2);
      assert.equal(repaired.json.settings.notify_on_allow, true);
      assert.equal('settings_invalid' in repaired.json, false);
      assert.deepEqual((await audits()).map((item) => item.changes), [{
        previous_version: 1,
        new_version: 2,
        previous_value: '저장된 값 형식 오류',
        new_value: DEFAULT_SUMMARY.replace('허용 알림 끔', '허용 알림 켬'),
      }]);
      assert.equal('settings_invalid' in (await get()).json, false);
      assert.deepEqual((await report(metrics())).json.gateway_settings.timeout, defaults.timeout);
    }, { store: new JsonEventStore(storePath) });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('an old JSON store file without the settings field still opens', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-settings-legacy-'));
  const storePath = path.join(root, 'events.json');
  try {
    await writeFile(storePath, JSON.stringify({ version: 1, records: [], auditRecords: [] }), 'utf8');
    await withBackend(async ({ settings, save }) => {
      assert.equal((await settings()).json.settings.version, 0);
      assert.equal((await save(body())).status, 200);
    }, { store: new JsonEventStore(storePath) });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
