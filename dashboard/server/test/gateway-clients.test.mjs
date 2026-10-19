// 연결 중인 IP(2026-10-12): Gateway 지표의 clients 칸 검사, GET /api/traffic/clients
// 대기 연결: 새 Gateway 항목은 waiting 칸이 하나 더 있고(옛 Gateway는 8칸), 옛 항목은 waiting 0으로 돌려준다
// IP는 문서용 범위(203.0.113.x, 198.51.100.x, 2001:db8::)만 쓴다
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createAppServer, gatewayClientsView, parseGatewayClients } from '../app.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-clients@example.test',
  adminPassword: 'local-password-clients-tests',
  ingestToken: 'local-ingest-token-clients-tests',
};
const metrics = (over = {}) => ({
  active_clients: 2, concurrent_requests: 1, requests_per_sec: 0.2, avg_latency_ms: 30, p95_latency_ms: 80, timeout_rate: 0, degraded_rate: 0,
  total_requests: 5, completed_requests: 5, error_requests: 0, action_distribution: {}, llm_distribution: { Claude: 3, ChatGPT: 2 },
  detector_distribution: {}, window_seconds: 300, ...over,
});
const client = (over = {}) => ({
  ip: '203.0.113.10', client_id: 'chrome-0f8a2c1e-5b7d-4e3a-9c61-2d4b8e7f1a30', connections: 2, inflight: 1, requests_5m: 4,
  targets: { Claude: 3, ChatGPT: 1 }, first_seen_at: '2026-10-12T01:00:00.000Z', last_seen_at: '2026-10-12T01:04:30.000Z', ...over,
});

async function withBackend(run) {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-clients-'));
  // 로컬 JSON 저장소(DATABASE_URL 없이 도는 경로)로 띄운다
  const server = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json') });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const get = async (pathname, headers = { Cookie: cookie }) => {
      const response = await fetch(`${base}${pathname}`, { headers });
      return { status: response.status, json: await response.json() };
    };
    const report = async (payload) => (await fetch(`${base}/api/traffic/metrics`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(payload) })).status;
    await run({ get, report });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

void test('valid clients are kept, times normalized to Z and sorted by last_seen_at desc', () => {
  const parsed = parseGatewayClients([
    client({ ip: '198.51.100.7', client_id: null, connections: 0, inflight: 0, requests_5m: 0, targets: {},
      first_seen_at: '2026-10-12T00:58:00+00:00', last_seen_at: '2026-10-12T00:59:10.123456+00:00' }),
    client(),
    client({ ip: '2001:db8::5', last_seen_at: '2026-10-12T01:05:00Z' }),
    client({ ip: '::ffff:203.0.113.9', last_seen_at: '2026-10-12T01:01:00.5Z' }),
  ]);
  assert.deepEqual(parsed.map((item) => item.ip), ['2001:db8::5', '203.0.113.10', '::ffff:203.0.113.9', '198.51.100.7']);
  assert.deepEqual(parsed[3], {
    ip: '198.51.100.7', client_id: null, connections: 0, inflight: 0, waiting: 0, requests_5m: 0, targets: {},
    first_seen_at: '2026-10-12T00:58:00.000Z', last_seen_at: '2026-10-12T00:59:10.123Z',
  });
  assert.equal(parsed[0].last_seen_at, '2026-10-12T01:05:00.000Z');
  assert.deepEqual(parseGatewayClients([]), []);
  const many = Array.from({ length: 200 }, (_, i) => client({ ip: i < 100 ? `203.0.113.${i + 1}` : `198.51.100.${i - 99}` }));
  assert.equal(parseGatewayClients(many).length, 200);
  const targets = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`LLM${i}`, i]));
  assert.deepEqual(parseGatewayClients([client({ targets })])[0].targets, targets);
});

void test('waiting: items with 9 keys keep it, old 8-key items get waiting 0, both may be mixed', () => {
  const parsed = parseGatewayClients([
    client({ ip: '203.0.113.1', inflight: 1, waiting: 2, last_seen_at: '2026-10-12T01:04:00.000Z' }),
    client({ ip: '203.0.113.2', waiting: 0, last_seen_at: '2026-10-12T01:03:00.000Z' }),
    client({ ip: '203.0.113.3', last_seen_at: '2026-10-12T01:02:00.000Z' }),
    client({ ip: '203.0.113.4', inflight: 0, waiting: 7, last_seen_at: '2026-10-12T01:01:00.000Z' }),
  ]);
  assert.deepEqual(parsed.map((item) => [item.ip, item.inflight, item.waiting]), [
    ['203.0.113.1', 1, 2], ['203.0.113.2', 1, 0], ['203.0.113.3', 1, 0], ['203.0.113.4', 0, 7],
  ]);
  // 옛 항목의 값이 그대로이고 waiting만 0으로 채워진다
  assert.deepEqual(parsed[2], { ...client({ ip: '203.0.113.3', last_seen_at: '2026-10-12T01:02:00.000Z' }), waiting: 0 });
  // 큰 값도 정수면 받는다
  assert.equal(parseGatewayClients([client({ waiting: 1_000_000 })])[0].waiting, 1_000_000);
});

void test('any invalid item rejects the whole clients list', () => {
  const missing = (({ inflight, ...rest }) => rest)(client());
  const cases = {
    'not array': { ...client() },
    null: null,
    'too many': Array.from({ length: 201 }, (_, i) => client({ ip: `203.0.113.${(i % 250) + 1}` })),
    'item not object': [client(), 'x'],
    'item array': [[client()]],
    'item null': [null],
    'missing field': [missing],
    'extra field': [client({ hostname: 'pc-1' })],
    'bad ip': [client({ ip: '203.0.113' })],
    'ip with spaces': [client({ ip: ' 203.0.113.10' })],
    'ip too long': [client({ ip: `2001:db8::1%${'a'.repeat(40)}` })],
    'ip number': [client({ ip: 3405803786 })],
    'empty client_id': [client({ client_id: '' })],
    'client_id too long': [client({ client_id: `chrome-${'a'.repeat(80)}` })],
    'client_id number': [client({ client_id: 7 })],
    'negative connections': [client({ connections: -1 })],
    'fractional inflight': [client({ inflight: 0.5 })],
    'string requests_5m': [client({ requests_5m: '4' })],
    'targets array': [client({ targets: ['Claude'] })],
    'targets null': [client({ targets: null })],
    'too many targets': [client({ targets: Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`LLM${i}`, 1])) })],
    'empty target name': [client({ targets: { '': 1 } })],
    'negative target count': [client({ targets: { Claude: -2 } })],
    'local offset': [client({ last_seen_at: '2026-10-12T10:04:30+09:00' })],
    'no timezone': [client({ first_seen_at: '2026-10-12T01:00:00' })],
    'date only': [client({ first_seen_at: '2026-10-12' })],
    'rolled-over date': [client({ last_seen_at: '2026-02-30T00:00:00Z' })],
    'epoch number': [client({ last_seen_at: 1791766923 })],
    // waiting을 더한 새 모양도 엄격하다
    'negative waiting': [client({ waiting: -1 })],
    'fractional waiting': [client({ waiting: 0.5 })],
    'string waiting': [client({ waiting: '1' })],
    'null waiting': [client({ waiting: null })],
    'boolean waiting': [client({ waiting: true })],
    'huge waiting': [client({ waiting: 2 ** 53 })],
    'waiting with extra field': [client({ waiting: 0, hostname: 'pc-1' })],
    'waiting replaces a missing field': [{ ...missing, waiting: 0 }],
    'waiting typo': [client({ waitting: 0 })],
  };
  for (const [name, value] of Object.entries(cases))
    assert.throws(() => parseGatewayClients(value), undefined, name);
  // 가운데 하나만 틀려도 전체를 버린다
  assert.throws(() => parseGatewayClients([client(), client({ ip: 'not-an-ip' }), client({ ip: '198.51.100.2' })]));
  assert.throws(() => parseGatewayClients([client({ waiting: 1 }), client({ ip: '198.51.100.2', waiting: -3 })]));
});

void test('clients view is stale without metrics or after 30 seconds and keeps the last list', () => {
  const now = Date.parse('2026-10-12T01:05:00.000Z');
  const at = (secondsAgo) => new Date(now - secondsAgo * 1000).toISOString();
  assert.deepEqual(gatewayClientsView(null, now), { received_at: null, stale: true, window_seconds: 300, clients: [] });
  const clients = parseGatewayClients([client()]);
  assert.deepEqual(gatewayClientsView({ ...metrics(), clients, received_at: at(10) }, now),
    { received_at: at(10), stale: false, window_seconds: 300, clients });
  // 2026-10-15: 시스템 상태·트래픽과 같은 기준(30초 미만이 '지금 값', 30초부터 지난 값)
  assert.equal(gatewayClientsView({ ...metrics(), clients, received_at: at(29.999) }, now).stale, false);
  assert.equal(gatewayClientsView({ ...metrics(), clients, received_at: at(30) }, now).stale, true);
  const old = gatewayClientsView({ ...metrics(), clients, received_at: at(31) }, now);
  assert.equal(old.stale, true);
  assert.deepEqual(old.clients, clients);
  // 옛 Gateway(칸 없음)는 빈 목록
  assert.deepEqual(gatewayClientsView({ ...metrics(), received_at: at(5) }, now).clients, []);
});

void test('GET /api/traffic/clients needs an admin session', async () => {
  await withBackend(async ({ get }) => {
    assert.equal((await get('/api/traffic/clients', {})).status, 401);
    assert.equal((await get('/api/traffic/clients', { Cookie: 'local_admin_session=forged' })).status, 401);
    assert.equal((await get('/api/traffic/clients', { Authorization: `Bearer ${CONFIG.ingestToken}` })).status, 401);   // Gateway 토큰으로는 못 읽음
    const empty = await get('/api/traffic/clients');
    assert.equal(empty.status, 200);
    assert.deepEqual(empty.json, { received_at: null, stale: true, window_seconds: 300, clients: [] });
  });
});

void test('metrics with clients, invalid clients and no clients field', async (t) => {
  const warn = t.mock.method(console, 'warn', () => {});
  await withBackend(async ({ get, report }) => {
    // 정상 목록
    assert.equal(await report(metrics({ clients: [
      client({ ip: '198.51.100.20', client_id: null, last_seen_at: '2026-10-12T01:02:00+00:00' }),
      client({ ip: '2001:db8::7' }),
    ] })), 202);
    let view = await get('/api/traffic/clients');
    assert.equal(view.status, 200);
    assert.equal(view.json.stale, false);
    assert.equal(view.json.window_seconds, 300);
    assert.ok(Math.abs(Date.now() - Date.parse(view.json.received_at)) < 10_000);
    assert.deepEqual(view.json.clients.map((item) => [item.ip, item.client_id, item.last_seen_at]), [
      ['2001:db8::7', client().client_id, '2026-10-12T01:04:30.000Z'],
      ['198.51.100.20', null, '2026-10-12T01:02:00.000Z'],
    ]);
    // 요약의 active_clients는 그대로, 요약에 IP 목록은 싣지 않는다
    let summary = (await get('/api/traffic/summary?period=24H')).json;
    assert.equal(summary.gateway_metrics_status, 'FRESH');
    assert.equal(summary.active_clients, 2);
    assert.equal(JSON.stringify(summary).includes('198.51.100.20'), false);

    // 틀린 목록: 지표는 받고 목록만 버린다(앞서 받은 목록도 남기지 않음)
    assert.equal(await report(metrics({ total_requests: 9, clients: [client(), client({ ip: '203.0.113.300' })] })), 202);
    view = await get('/api/traffic/clients');
    assert.equal(view.json.stale, false);
    assert.deepEqual(view.json.clients, []);
    summary = (await get('/api/traffic/summary?period=24H')).json;
    assert.equal(summary.gateway_metrics_status, 'FRESH');
    assert.equal(summary.gateway_total_requests, 9);
    assert.equal(await report(metrics({ clients: [client({ ip: '203.0.113.300' })] })), 202);   // 같은 사유는 한 번만 남긴다
    assert.equal(await report(metrics({ clients: 'x' })), 202);
    assert.deepEqual(warn.mock.calls.map((call) => call.arguments.join(' ')), [
      'Gateway clients report ignored: invalid ip',
      'Gateway clients report ignored: invalid clients',
    ]);

    // 다시 정상 목록
    assert.equal(await report(metrics({ clients: [client()] })), 202);
    assert.deepEqual((await get('/api/traffic/clients')).json.clients.map((item) => item.ip), ['203.0.113.10']);

    // 대기 연결: 새 Gateway(waiting 있음)와 옛 Gateway(없음) 항목이 섞여도 받고, 응답에는 모두 waiting이 있다
    assert.equal(await report(metrics({ clients: [
      client({ ip: '203.0.113.31', inflight: 0, waiting: 3 }),
      client({ ip: '203.0.113.32', last_seen_at: '2026-10-12T01:03:00.000Z' }),
    ] })), 202);
    view = await get('/api/traffic/clients');
    assert.deepEqual(view.json.clients.map((item) => [item.ip, item.inflight, item.waiting]), [['203.0.113.31', 0, 3], ['203.0.113.32', 1, 0]]);
    // waiting이 틀리면 그 목록만 버린다(지표는 받는다)
    assert.equal(await report(metrics({ clients: [client({ waiting: -1 })] })), 202);
    view = await get('/api/traffic/clients');
    assert.equal(view.json.stale, false);
    assert.deepEqual(view.json.clients, []);
    assert.equal(warn.mock.calls.at(-1).arguments.join(' '), 'Gateway clients report ignored: invalid count');

    // 옛 Gateway(칸 없음): 지표는 받고 목록은 비운다
    assert.equal(await report(metrics({ total_requests: 11 })), 202);
    view = await get('/api/traffic/clients');
    assert.equal(view.json.stale, false);
    assert.deepEqual(view.json.clients, []);
    assert.equal((await get('/api/traffic/summary?period=24H')).json.gateway_total_requests, 11);

    // 다른 칸은 지금처럼 엄격하다
    assert.equal(await report(metrics({ clients: [client()], unknown_metric: 1 })), 400);
    assert.equal(await report(metrics({ clients: [client()], total_requests: -1 })), 422);
  });
});
