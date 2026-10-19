// 시스템 상태(2026-10-12): 지표의 relay 칸, GET /api/system/status의 모양·상태 규칙·인증·5초 캐시·로컬 저장소 모드
// Detection은 가짜 HTTP 서버, DB는 가짜 저장소(ping 지연·실패)로 대신한다. 인스턴스 ID·IP는 모두 가짜 값이다
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { mock, test } from 'node:test';
import { createAppServer, parseGatewayRelay } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';
import { scrubText } from '../system-status.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-sysstatus@example.test',
  adminPassword: 'local-password-sysstatus-tests',
  ingestToken: 'local-ingest-token-sysstatus-tests',
};
const KEYS = ['dashboard', 'rds', 'gateway', 'relay', 'detection', 'redis', 'log_shipping', 'keyword_jobs', 'gpu'];
const ISO_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

const metrics = (over = {}) => ({
  active_clients: 2, concurrent_requests: 1, requests_per_sec: 0.2, avg_latency_ms: 30, p95_latency_ms: 80, timeout_rate: 0, degraded_rate: 0,
  total_requests: 5, completed_requests: 5, error_requests: 0, action_distribution: {}, llm_distribution: { Claude: 3 },
  detector_distribution: {}, window_seconds: 300, ...over,
});
const instances = () => ({
  ok: true, error: null, status_checks: 'permission_missing',
  items: [
    { role: 'gateway', instance_id: 'i-0aaaaaaaaaaaaaaa1', name: 'llm-gateway', state: 'running', system_status: null, instance_status: null },
    { role: 'detection', instance_id: 'i-0aaaaaaaaaaaaaaa2', name: 'llm-detection', state: 'running', system_status: null, instance_status: null },
    { role: 'dashboard', instance_id: 'i-0aaaaaaaaaaaaaaa3', name: null, state: 'running', system_status: null, instance_status: null },
    { role: 'gpu', instance_id: 'i-0aaaaaaaaaaaaaaa4', name: 'llm-gpu', state: 'stopped', system_status: null, instance_status: null },
  ],
});
const rds = () => ({ ok: true, error: null, identifier: 'promptgate-db', status: 'available', engine: 'postgres' });
const systemPayload = (over = {}) => ({
  checked_at: '2026-10-12T01:00:00.000Z',
  detection: {
    status: 'ok', started_at: '2026-10-10T00:00:00Z', uptime_s: 180_000,
    signatures: { builtin: 9, database: 3, keywords: 105 }, documents: 19, policies: 4, redact_pdf: true,
  },
  redis: { ok: true, latency_ms: 0.4, error: null },
  log_shipping: { ok: true, pending_bytes: 0, last_ok_at: '2026-10-12T00:59:50Z', consecutive_failures: 0, rejected_total: 0, last_error: null },
  keyword_jobs: { queued: 0, running: 0, failed: 0 },
  instances: instances(),
  rds: rds(),
  ...over,
});
const gpuPayload = (over = {}) => ({
  connected: true, models: ['qwen3-8b'], latency_ms: 6, error: null, checked_at: '2026-10-12T01:00:00+00:00', instance_state: 'running', ...over,
});

// state.system / state.gpu = { status, delay, body } - 시험이 도중에 바꿀 수 있다
function startDetection(state) {
  const calls = [];
  const server = createServer((req, res) => {
    const pathname = new URL(req.url, 'http://fake').pathname;
    calls.push({ method: req.method, path: pathname, adminId: req.headers['x-admin-id'] ?? null });
    const route = pathname === '/admin/system-status' ? state.system : pathname === '/admin/gpu' ? state.gpu : pathname === '/health' ? state.health : null;
    const reply = () => {
      res.writeHead(route ? (route.status ?? 200) : 404, { 'Content-Type': 'application/json' });
      res.end(!route ? '{"detail":"Not Found"}' : typeof route.body === 'string' ? route.body : JSON.stringify(route.body));
    };
    if (route?.delay) setTimeout(reply, route.delay);
    else reply();
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, calls, state, baseUrl: `http://127.0.0.1:${server.address().port}` }));
  });
}

const closeServer = (server) => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); });

// detection: 'refused'(닫힌 포트) · 'none'(주소 미설정) · 아니면 { system, gpu } 상태
// dbMethods가 있으면 PostgreSQL 모드처럼 ping·latestEventStoredAt을 가진 저장소를 쓴다(없으면 로컬 JSON 저장소)
async function withEnv({ detection = {}, dbMethods } = {}, run) {
  const root = await mkdtemp(path.join(tmpdir(), 'system-status-'));
  const storePath = path.join(root, 'events.json');
  let fake = null;
  let policyBaseUrl;
  if (detection === 'refused') {
    const closed = await startDetection({});
    policyBaseUrl = closed.baseUrl;
    await closeServer(closed.server);
  } else if (detection !== 'none') {
    fake = await startDetection({ system: { body: systemPayload() }, gpu: { body: gpuPayload() }, health: { body: { status: 'ok' } }, ...detection });
    policyBaseUrl = fake.baseUrl;
  }
  const store = dbMethods ? Object.assign(new JsonEventStore(storePath), dbMethods) : undefined;
  const server = createAppServer({ ...CONFIG, storePath, policyBaseUrl, store });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }),
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const status = async ({ method = 'GET', headers = { Cookie: cookie } } = {}) => {
      const response = await fetch(`${base}/api/system/status`, { method, headers });
      return { status: response.status, json: await response.json() };
    };
    const report = async (payload) => (await fetch(`${base}/api/traffic/metrics`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(payload),
    })).status;
    return await run({ status, report, calls: fake?.calls ?? [], state: fake?.state, cookie });
  } finally {
    await new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); });
    if (fake) await closeServer(fake.server);
    await rm(root, { recursive: true, force: true });
  }
}

const byKey = (body) => Object.fromEntries(body.components.map((item) => [item.key, item]));
const silenced = () => mock.method(console, 'error', () => {});

// 한 번 점검한 결과의 구성 요소만 돌려준다
async function componentsFor(options) {
  let result;
  await withEnv(options, async ({ status }) => {
    result = byKey((await status()).json);
  });
  return result;
}

void test('relay report: exact shape only, counts are whole numbers', () => {
  assert.deepEqual(parseGatewayRelay({ ok: true, connected: 12, registered: 3 }), { ok: true, connected: 12, registered: 3 });
  assert.deepEqual(parseGatewayRelay({ registered: 0, connected: 0, ok: false }), { ok: false, connected: 0, registered: 0 });
  const bad = {
    null: null, array: [], string: 'x', number: 1, empty: {},
    'missing registered': { ok: true, connected: 1 },
    'extra key': { ok: true, connected: 1, registered: 1, extra: 1 },
    'ok not boolean': { ok: 'true', connected: 1, registered: 1 },
    'ok number': { ok: 1, connected: 1, registered: 1 },
    'negative connected': { ok: true, connected: -1, registered: 0 },
    'fractional registered': { ok: true, connected: 0, registered: 1.5 },
    'string connected': { ok: true, connected: '1', registered: 0 },
    'null registered': { ok: true, connected: 0, registered: null },
    'unsafe integer': { ok: true, connected: 2 ** 53, registered: 0 },
  };
  for (const [name, value] of Object.entries(bad)) assert.throws(() => parseGatewayRelay(value), Error, name);
});

void test('metrics with relay are accepted; an invalid relay drops only that field', async () => {
  const warn = mock.method(console, 'warn', () => {});
  try {
    await withEnv({}, async ({ status, report }) => {
      assert.equal(await report(metrics({ relay: { ok: true, connected: 4, registered: 2 } })), 202);
      const ok = byKey((await status()).json);
      assert.equal(ok.relay.status, 'ok');
      assert.deepEqual(ok.relay.details, { '연결 수': 4, '등록된 클라이언트': 2 });
      assert.equal(ok.gateway.status, 'ok');
    });
    await withEnv({}, async ({ status, report }) => {
      // 모양이 틀린 relay: 지표는 202로 받고(Gateway 칸은 정상), 릴레이 칸만 버려 '확인 불가'
      assert.equal(await report(metrics({ relay: { ok: 'yes', connected: 4, registered: 2 } })), 202);
      assert.equal(await report(metrics({ relay: { ok: true, connected: 4, registered: 2, extra: 1 } })), 202);
      const body = byKey((await status()).json);
      assert.equal(body.relay.status, 'unknown');
      assert.match(body.relay.summary, /형식/);
      assert.deepEqual(body.relay.details, {});
      assert.equal(body.gateway.status, 'ok');
      assert.equal(body.gateway.details['응답 대기 요청이 있는 IP'], 2);
    });
    assert.equal(warn.mock.calls.filter((call) => /relay report ignored/.test(call.arguments[0])).length, 2);
    await withEnv({}, async ({ status, report }) => {
      // 옛 Gateway(relay 칸 없음): 릴레이는 '확인 불가', 그 밖의 지표 처리는 그대로
      assert.equal(await report(metrics()), 202);
      const body = byKey((await status()).json);
      assert.equal(body.relay.status, 'unknown');
      assert.match(body.relay.summary, /보고하지 않음/);
      assert.equal(body.gateway.status, 'ok');
    });
  } finally {
    warn.mock.restore();
  }
});

void test('relay ok=false is down; the relay is unknown when the gateway is silent', async () => {
  await withEnv({}, async ({ status, report }) => {
    assert.equal(await report(metrics({ relay: { ok: false, connected: 0, registered: 0 } })), 202);
    const { relay } = byKey((await status()).json);
    assert.equal(relay.status, 'down');
    assert.deepEqual(relay.details, { '연결 수': 0, '등록된 클라이언트': 0 });
  });
  assert.equal((await componentsFor({})).relay.status, 'unknown');
});

void test('GET /api/system/status needs a session and only allows GET', async () => {
  await withEnv({}, async ({ status, calls }) => {
    assert.equal((await status({ headers: {} })).status, 401);
    assert.equal((await status({ headers: { Cookie: 'local_admin_session=forged' } })).status, 401);
    assert.equal((await status({ method: 'POST', headers: {} })).status, 401);
    assert.equal(calls.length, 0);
    assert.equal((await status({ method: 'POST' })).status, 405);
    assert.equal(calls.length, 0);
  });
});

void test('response shape: nine components in order, flat details, Detection called read-only with the admin id', async () => {
  await withEnv({}, async ({ status, report, calls }) => {
    assert.equal(await report(metrics({ relay: { ok: true, connected: 1, registered: 1 } })), 202);
    const before = Date.now();
    const { status: code, json } = await status();
    assert.equal(code, 200);
    assert.deepEqual(Object.keys(json), ['checked_at', 'components', 'instances', 'rds_instance']);
    assert.match(json.checked_at, ISO_Z);
    assert.ok(Date.parse(json.checked_at) >= before - 1000);
    assert.deepEqual(json.components.map((item) => item.key), KEYS);
    for (const item of json.components) {
      assert.deepEqual(Object.keys(item), ['key', 'label', 'status', 'summary', 'details', 'checked_at'], item.key);
      assert.ok(['ok', 'slow', 'down', 'unknown'].includes(item.status), item.key);
      assert.ok(/[가-힣A-Za-z]/.test(item.label) && item.summary.length > 0 && item.summary.length <= 60, item.key);
      assert.match(item.checked_at, ISO_Z, item.key);
      assert.ok(!Array.isArray(item.details) && typeof item.details === 'object');
      for (const [name, value] of Object.entries(item.details))
        assert.ok(typeof value === 'string' || typeof value === 'number', `${item.key}.${name}`);
    }
    const by = byKey(json);
    assert.deepEqual(Object.fromEntries(KEYS.map((key) => [key, by[key].status])), {
      dashboard: 'ok', rds: 'unknown', gateway: 'ok', relay: 'ok', detection: 'ok', redis: 'ok', log_shipping: 'ok', keyword_jobs: 'ok', gpu: 'ok',
    });
    assert.equal(by.dashboard.details['Node 버전'], process.version);
    assert.match(by.dashboard.details['시작 시각'], ISO_Z);
    assert.ok(by.dashboard.details['가동 시간(초)'] >= 0);
    assert.equal(by.detection.details['시그니처(키워드)'], 105);
    assert.equal(by.detection.details['등록 문서'], 19);
    assert.equal(by.detection.details['PDF 가림'], '사용');
    assert.equal(by.detection.checked_at, '2026-10-12T01:00:00.000Z');
    assert.equal(by.gateway.details['응답 대기 요청이 있는 IP'], 2);
    assert.equal(by.detection.details['응답 시간 기준'], '상태 확인(/health) 왕복');
    assert.equal(by.keyword_jobs.summary, '대기 0 · 실행 0 · 실패 0');
    assert.deepEqual(json.instances, instances());
    assert.deepEqual(json.rds_instance, rds());
    // Detection 호출은 GET 세 번뿐(시스템 상태·GPU 조회·응답 시간용 /health, 2026-10-15). GPU 켜기·끄기는 부르지 않는다
    assert.deepEqual(calls.map((call) => [call.method, call.path, call.adminId]).sort(),
      [['GET', '/admin/gpu', 'local-admin'], ['GET', '/admin/system-status', 'local-admin'], ['GET', '/health', 'local-admin']]);
  });
});

void test('JSON store mode: the database component is unknown and says it is local', async () => {
  const { rds: database } = await componentsFor({});
  assert.equal(database.status, 'unknown');
  assert.equal(database.summary, '로컬 저장소');
  assert.deepEqual(database.details, { 저장소: '로컬 JSON 파일' });
});

void test('database rules: SELECT 1 under 300 ms ok, under 2 s slow, failure or 2 s timeout down', async () => {
  const log = silenced();
  try {
    const stored = '2026-10-12T00:58:00.000Z';
    const fast = await componentsFor({ dbMethods: { ping: async () => {}, latestEventStoredAt: async () => stored } });
    assert.equal(fast.rds.status, 'ok');
    assert.match(fast.rds.summary, /^응답 \d+ms$/);
    assert.equal(fast.rds.details['저장소'], 'PostgreSQL');
    assert.equal(fast.rds.details['마지막 이벤트 저장'], stored);
    assert.ok(fast.rds.details['지연 시간(ms)'] < 300);

    const noEvents = await componentsFor({ dbMethods: { ping: async () => {}, latestEventStoredAt: async () => null } });
    assert.equal(noEvents.rds.status, 'ok');
    assert.equal('마지막 이벤트 저장' in noEvents.rds.details, false);

    // 마지막 이벤트 시각을 못 읽어도 연결 상태 판정은 그대로
    const noLatest = await componentsFor({ dbMethods: { ping: async () => {}, latestEventStoredAt: async () => { throw new Error('boom'); } } });
    assert.equal(noLatest.rds.status, 'ok');

    const slowRun = componentsFor({ dbMethods: { ping: () => new Promise((resolve) => setTimeout(resolve, 380)) } });
    const failedRun = componentsFor({ dbMethods: { ping: async () => { throw Object.assign(new Error('connect ECONNREFUSED 10.0.9.9:5432'), { code: 'ECONNREFUSED' }); } } });
    const hungRun = componentsFor({ dbMethods: { ping: () => new Promise(() => {}) } });
    const [slow, failed, hung] = await Promise.all([slowRun, failedRun, hungRun]);
    assert.equal(slow.rds.status, 'slow');
    assert.ok(slow.rds.details['지연 시간(ms)'] >= 300 && slow.rds.details['지연 시간(ms)'] < 2000);
    assert.equal(failed.rds.status, 'down');
    assert.equal(failed.rds.summary, '연결 실패');
    assert.equal(JSON.stringify(failed).includes('10.0.9.9'), false);
    assert.equal(hung.rds.status, 'down');
    assert.equal(hung.rds.summary, '응답 없음(2초 초과)');
    // 기록에는 오류 코드만 남고 접속 주소는 남지 않는다
    assert.ok(log.mock.calls.every((call) => !JSON.stringify(call.arguments).includes('10.0.9.9')));
  } finally {
    log.mock.restore();
  }
});

void test('PostgreSQL store ping and latest stored time use cheap single-row queries', async () => {
  const queries = [];
  const pool = {
    async query(sql) {
      queries.push(sql);
      return /created_at/.test(sql)
        ? { rowCount: 1, rows: [{ created_at: new Date('2026-10-12T00:58:00Z') }] }
        : { rowCount: 1, rows: [{ '?column?': 1 }] };
    },
  };
  const store = new PostgresEventStore({ pool });
  assert.equal(await store.ping(), undefined);
  assert.equal(await store.latestEventStoredAt(), '2026-10-12T00:58:00.000Z');
  assert.equal(queries[0], 'SELECT 1');
  assert.match(queries[1], /FROM dashboard_security_events ORDER BY created_at DESC LIMIT 1$/);   // 저장 시각이 가장 늦은 것(2026-10-15)
  const empty = new PostgresEventStore({ pool: { query: async () => ({ rowCount: 0, rows: [] }) } });
  assert.equal(await empty.latestEventStoredAt(), null);
});

void test('gateway: down with no report, ok under 30 s, down from 30 s; relay follows the gateway', async () => {
  mock.timers.enable({ apis: ['Date'], now: Date.UTC(2026, 9, 12, 1, 0, 0) });
  // 연결 중인 IP = 열린 연결이 있는 IP만(2026-10-15): 연결 0인 셋째 IP(10분 안 활동만)는 세지 않는다
  const clients = ['203.0.113.10', '203.0.113.11', '203.0.113.12'].map((ip, index) => ({
    ip, client_id: null, connections: index < 2 ? 1 : 0, inflight: 0, requests_5m: 1, targets: {}, first_seen_at: '2026-10-12T01:00:00Z', last_seen_at: '2026-10-12T01:00:05Z',
  }));
  const delivery = { storage_ready: true, pending: 4, blocked: 1, oldest_age_sec: 12.4, delivered: 99, retries: 2, capacity_rejections: 0, conflicts: 0, enqueue_errors: 0 };
  // 보고한 뒤 elapsedMs가 지난 시점의 점검 결과(캐시가 5초라 시점마다 새 서버로 본다)
  const afterReport = (elapsedMs, payload) => withEnv({}, async ({ status, report }) => {
    const reportedAt = new Date().toISOString();
    assert.equal(await report(payload), 202);
    mock.timers.tick(elapsedMs);
    return { body: byKey((await status()).json), reportedAt };
  });
  try {
    const none = await withEnv({}, async ({ status }) => byKey((await status()).json));
    assert.deepEqual([none.gateway.status, none.gateway.summary, none.relay.status], ['down', '지표를 받은 적 없음', 'unknown']);

    const payload = metrics({ relay: { ok: true, connected: 3, registered: 3 }, event_delivery: delivery, clients });
    const fresh = await afterReport(5_000, payload);
    assert.equal(fresh.body.gateway.status, 'ok');
    assert.equal(fresh.body.gateway.summary, '마지막 보고 5초 전');
    assert.deepEqual(fresh.body.gateway.details, {
      '마지막 보고': fresh.reportedAt, '연결 중인 IP': 2, '응답 대기 요청이 있는 IP': 2, '이벤트 전송 대기': 4, '이벤트 전송 막힘': 1, '설정 반영': '지원 안 함(옛 Gateway)',
    });
    assert.equal(fresh.body.relay.status, 'ok');

    const edge = await afterReport(29_999, payload);
    assert.deepEqual([edge.body.gateway.status, edge.body.relay.status], ['ok', 'ok']);

    const stale = await afterReport(30_000, payload);
    assert.deepEqual([stale.body.gateway.status, stale.body.gateway.summary], ['down', '마지막 보고 30초 전']);
    assert.deepEqual(stale.body.gateway.details, { '마지막 보고': stale.reportedAt });
    assert.equal(stale.body.relay.status, 'unknown');

    // 이벤트 저장소가 준비되지 않은 보고
    const notReady = await afterReport(0, metrics({ event_delivery: { storage_ready: false } }));
    assert.equal(notReady.body.gateway.details['이벤트 저장소'], '준비 안 됨');
    assert.equal('이벤트 전송 대기' in notReady.body.gateway.details, false);
  } finally {
    mock.timers.reset();
  }
});

void test('detection: ok under 1 s, slow from 1 s, down on refusal, timeout, error or bad body', async () => {
  const refused = await componentsFor({ detection: 'refused' });
  assert.equal(refused.detection.status, 'down');
  assert.match(refused.detection.summary, /응답 없음/);
  for (const key of ['redis', 'log_shipping', 'keyword_jobs'])
    assert.deepEqual([refused[key].status, refused[key].details], ['unknown', {}], key);
  assert.equal(refused.gpu.status, 'unknown');

  const serverError = await componentsFor({ detection: { system: { status: 500, body: { detail: 'boom' } } } });
  assert.deepEqual([serverError.detection.status, serverError.detection.summary], ['down', '오류 응답(HTTP 500)']);
  assert.equal(serverError.redis.status, 'unknown');

  for (const body of ['not json', '[]', 'null', '"text"']) {
    const bad = await componentsFor({ detection: { system: { body } } });
    assert.deepEqual([bad.detection.status, bad.detection.summary], ['down', '응답 형식 오류'], body);
  }

  // 옛 Detection(이 경로 없음, 404)은 고장이 아니라 알 수 없음
  const old = await componentsFor({ detection: { system: null } });
  assert.equal(old.detection.status, 'unknown');
  assert.match(old.detection.summary, /업데이트/);

  const none = await componentsFor({ detection: 'none' });
  assert.deepEqual([none.detection.status, none.gpu.status], ['unknown', 'unknown']);
  assert.match(none.detection.summary, /주소/);

  // 느린 응답 둘을 동시에: 1.1초 → 느림, 3초 → 2.5초에 끊어 끊김. 응답 시간은 /health 왕복이라 /health도 같이 늦춘다(2026-10-15)
  const [slow, timedOut] = await Promise.all([
    withEnv({ detection: { system: { body: systemPayload(), delay: 1_100 }, health: { body: { status: 'ok' }, delay: 1_100 } } }, async ({ status }) => (await status()).json),
    withEnv({ detection: { system: { body: systemPayload(), delay: 3_000 } } }, async ({ status }) => {
      const started = Date.now();
      const json = (await status()).json;
      json.elapsed = Date.now() - started;
      return json;
    }),
  ]);
  assert.equal(byKey(slow).detection.status, 'slow');
  assert.ok(byKey(slow).detection.details['응답 시간(ms)'] >= 1000);
  assert.equal(byKey(slow).redis.status, 'ok');
  assert.equal(byKey(timedOut).detection.status, 'down');
  assert.ok(timedOut.elapsed >= 2400 && timedOut.elapsed < 3_500, `elapsed ${timedOut.elapsed}`);
  assert.deepEqual(timedOut.instances, { ok: false, error: 'unavailable', items: [] });
  assert.deepEqual(timedOut.rds_instance, { ok: false, error: 'unavailable', identifier: null, status: null, engine: null });
});

void test('fallbacks for instances and rds_instance when Detection cannot answer or omits them', async () => {
  await withEnv({ detection: 'refused' }, async ({ status }) => {
    const { json } = await status();
    assert.deepEqual(json.instances, { ok: false, error: 'unavailable', items: [] });
    assert.deepEqual(json.rds_instance, { ok: false, error: 'unavailable', identifier: null, status: null, engine: null });
  });
  await withEnv({ detection: { system: { body: systemPayload({ instances: undefined, rds: 'x' }) } } }, async ({ status }) => {
    const { json } = await status();
    assert.deepEqual(json.instances, { ok: false, error: 'unavailable', items: [] });
    assert.equal(json.rds_instance.ok, false);
    assert.equal(json.rds_instance.error, 'unavailable');
  });
  // IAM 권한이 없을 때의 값은 그대로 전달한다
  const denied = {
    instances: { ok: true, error: null, status_checks: 'permission_missing', items: [{ role: 'gateway', instance_id: 'i-0aaaaaaaaaaaaaaa1', name: 'llm-gateway', state: 'running', system_status: null, instance_status: null }] },
    rds: { ok: false, error: 'permission_missing', identifier: 'promptgate-db', status: null, engine: null },
  };
  await withEnv({ detection: { system: { body: systemPayload(denied) } } }, async ({ status }) => {
    const { json } = await status();
    assert.deepEqual(json.instances, denied.instances);
    assert.deepEqual(json.rds_instance, denied.rds);
  });
});

void test('redis, log shipping and keyword job rules', async () => {
  const now = Date.now();
  const ago = (ms) => new Date(now - ms).toISOString();
  const shipping = (over) => ({ ok: true, pending_bytes: 0, last_ok_at: ago(5_000), consecutive_failures: 0, rejected_total: 0, last_error: null, ...over });
  const run = async (over) => componentsFor({ detection: { system: { body: systemPayload(over) } } });

  const redisDown = await run({ redis: { ok: false, latency_ms: null, error: 'ConnectionError' } });
  assert.deepEqual([redisDown.redis.status, redisDown.redis.details], ['down', { 오류: 'ConnectionError' }]);
  assert.match((await run({})).redis.summary, /^응답 0\.4ms$/);

  const cases = [
    ['healthy', shipping({}), 'ok'],
    ['pending but recent success', shipping({ pending_bytes: 4096, last_ok_at: ago(9 * 60_000) }), 'ok'],
    ['3 consecutive failures', shipping({ ok: false, consecutive_failures: 3, last_error: 'HTTP 500' }), 'down'],
    ['2 failures only', shipping({ ok: false, consecutive_failures: 2 }), 'slow'],
    ['pending and no success for 11 min', shipping({ pending_bytes: 10, last_ok_at: ago(11 * 60_000) }), 'down'],
    ['nothing pending, old success', shipping({ pending_bytes: 0, last_ok_at: ago(3 * 3_600_000) }), 'ok'],
    ['pending, never succeeded, detection up 20 min', shipping({ pending_bytes: 10, last_ok_at: null, ok: false }), 'down'],
  ];
  for (const [name, section, expected] of cases) {
    const result = await run({
      log_shipping: section,
      detection: { ...systemPayload().detection, started_at: ago(20 * 60_000) },
    });
    assert.equal(result.log_shipping.status, expected, name);
  }
  const recentStart = await run({
    log_shipping: shipping({ pending_bytes: 10, last_ok_at: null, ok: false }),
    detection: { ...systemPayload().detection, started_at: ago(60_000) },
  });
  assert.equal(recentStart.log_shipping.status, 'slow');
  const detailed = await run({ log_shipping: shipping({ pending_bytes: 2048, consecutive_failures: 1, ok: false, rejected_total: 7, last_error: 'timeout' }) });
  assert.equal(detailed.log_shipping.details['대기 크기(바이트)'], 2048);
  assert.equal(detailed.log_shipping.details['거부 누계'], 7);
  assert.equal(detailed.log_shipping.details['마지막 오류'], 'timeout');
  assert.equal(detailed.log_shipping.details['연속 실패'], 1);

  const failed = await run({ keyword_jobs: { queued: 2, running: 1, failed: 3 } });
  assert.deepEqual([failed.keyword_jobs.status, failed.keyword_jobs.summary], ['slow', '대기 2 · 실행 1 · 실패 3']);
  assert.equal((await run({ keyword_jobs: { queued: 2, running: 1, failed: 0 } })).keyword_jobs.status, 'ok');

  // 보고하지 않은 칸은 확인 불가
  const missing = await run({ redis: undefined, keyword_jobs: 'x' });
  assert.deepEqual([missing.redis.status, missing.keyword_jobs.status], ['unknown', 'unknown']);
});

void test('gpu is read through Detection and never started', async () => {
  const gpu = async (body, extra = {}) => withEnv({ detection: { gpu: { body, ...extra } } }, async ({ status, calls }) => {
    const result = byKey((await status()).json).gpu;
    assert.deepEqual(calls.filter((call) => call.path.startsWith('/admin/gpu')).map((call) => call.method), ['GET']);
    return result;
  });
  const up = await gpu(gpuPayload());
  assert.deepEqual([up.status, up.summary], ['ok', '응답 6ms']);
  assert.equal(up.details['모델'], 'qwen3-8b');
  assert.equal(up.checked_at, '2026-10-12T01:00:00.000Z');
  const stopped = await gpu(gpuPayload({ connected: false, models: [], latency_ms: null, error: 'URLError', instance_state: 'stopped' }));
  assert.deepEqual([stopped.status, stopped.summary, stopped.details['인스턴스 상태']], ['unknown', '꺼져 있음', 'stopped']);
  const starting = await gpu(gpuPayload({ connected: false, models: [], latency_ms: null, error: 'URLError', instance_state: 'pending' }));
  assert.deepEqual([starting.status, starting.summary], ['unknown', '켜는 중']);
  const broken = await gpu(gpuPayload({ connected: false, models: [], latency_ms: null, error: 'URLError', instance_state: 'running' }));
  assert.deepEqual([broken.status, broken.summary, broken.details['오류']], ['down', '연결되지 않음', 'URLError']);
  const failedCall = await gpu({ detail: 'x' }, { status: 502 });
  assert.equal(failedCall.status, 'unknown');
  const malformed = await gpu({ models: [] });
  assert.equal(malformed.status, 'unknown');
});

void test('nothing secret leaves: free text is scrubbed and unknown fields are dropped', async () => {
  const leaky = systemPayload({
    redis: { ok: false, latency_ms: null, error: 'Error 111 connecting to 10.0.2.5:6379. password=hunter2' },
    log_shipping: { ok: false, pending_bytes: 1, last_ok_at: null, consecutive_failures: 1, rejected_total: 0, last_error: 'connect postgres://app:S3cretPw@db.abc123.ap-northeast-2.rds.amazonaws.com:5432/dlp failed' },
    dsn: 'postgres://app:S3cretPw@db.internal/dlp',
    instances: {
      ok: true, error: null, status_checks: 'ok', private_ip: '10.0.1.7',
      items: [
        { role: 'gateway', instance_id: 'i-0aaaaaaaaaaaaaaa1', name: 'gw', state: 'running', system_status: 'ok', instance_status: 'ok', private_ip: '10.0.1.7', public_dns: 'ec2-1-2-3-4.ap-northeast-2.compute.amazonaws.com' },
        { role: 'bastion', instance_id: 'i-0aaaaaaaaaaaaaaa9', name: 'x', state: 'running', system_status: null, instance_status: null },
      ],
    },
    rds: { ok: true, error: null, identifier: 'dlp-db.abc123.ap-northeast-2.rds.amazonaws.com', status: 'available', engine: 'postgres', endpoint: 'dlp-db.abc123.ap-northeast-2.rds.amazonaws.com' },
  });
  const gpu = gpuPayload({ error: 'URLError http://10.0.3.254:9000/v1/models', connected: false, instance_state: 'running' });
  await withEnv({ detection: { system: { body: leaky }, gpu: { body: gpu } } }, async ({ status }) => {
    const { json } = await status();
    const text = JSON.stringify(json);
    for (const secret of ['hunter2', 'S3cretPw', '10.0.2.5', '10.0.1.7', '10.0.3.254', 'amazonaws.com', 'private_ip', 'public_dns', 'endpoint', 'dsn', 'postgres://', 'http://'])
      assert.equal(text.includes(secret), false, secret);
    const by = byKey(json);
    assert.equal(by.redis.details['오류'], 'Error 111 connecting to [주소]. password=[숨김]');
    assert.equal(by.log_shipping.details['마지막 오류'], 'connect [주소] failed');
    assert.deepEqual(json.instances.items.map((item) => item.role), ['gateway']);
    assert.deepEqual(Object.keys(json.instances.items[0]), ['role', 'instance_id', 'name', 'state', 'system_status', 'instance_status']);
    assert.deepEqual(json.rds_instance, { ok: true, error: null, identifier: null, status: 'available', engine: 'postgres' });
  });
  assert.equal(scrubText('x'.repeat(500)).length, 120);
  assert.equal(scrubText('   '), null);
  assert.equal(scrubText(7), null);
});

void test('the whole response is cached for 5 seconds and concurrent requests share one check', async () => {
  mock.timers.enable({ apis: ['Date'], now: Date.UTC(2026, 9, 12, 1, 0, 0) });
  try {
    const count = (calls, route) => calls.filter((call) => call.path === route).length;
    await withEnv({}, async ({ status, calls }) => {
      const first = await status();
      const second = await status();
      assert.deepEqual(second.json, first.json);
      assert.equal(count(calls, '/admin/system-status'), 1);
      assert.equal(count(calls, '/admin/gpu'), 1);
      mock.timers.tick(4_999);
      assert.deepEqual((await status()).json, first.json);
      assert.equal(count(calls, '/admin/system-status'), 1);
      mock.timers.tick(1);
      const third = await status();
      assert.equal(count(calls, '/admin/system-status'), 2);
      assert.equal(count(calls, '/admin/gpu'), 2);
      assert.notEqual(third.json.checked_at, first.json.checked_at);
    });
    await withEnv({ detection: { system: { body: systemPayload(), delay: 250 } } }, async ({ status, calls }) => {
      const results = await Promise.all([status(), status(), status()]);
      assert.equal(count(calls, '/admin/system-status'), 1);
      assert.deepEqual(results[1].json, results[0].json);
      assert.deepEqual(results[2].json, results[0].json);
    });
  } finally {
    mock.timers.reset();
  }
});
