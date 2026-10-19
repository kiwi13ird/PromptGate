// Gateway 처리 시간 기준 변경(2026-10-11): 기준 시각 전 이벤트의 processing_ms(LLM 응답까지)는 평균·P95·화면에서 뺀다
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createAppServer, liveProcessingTimeReported } from '../app.mjs';
import { defaultGatewaySettings } from '../gateway-settings.mjs';
import {
  DEFAULT_GATEWAY_PROCESSING_MS_SINCE,
  gatewayProcessingCutoff,
  requiredGatewayProcessingSince,
  withGatewayProcessing,
} from '../processing-time.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-latency@example.test',
  adminPassword: 'local-password-latency-tests',
  ingestToken: 'local-ingest-token-latency-tests',
};
const ago = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();
const event = (eventId, minutes, processingMs) => ({
  type: 'SECURITY_EVENT', eventId, requestId: `req-${eventId}`, timestamp: ago(minutes), clientId: 'chrome-latency-test',
  targetLlm: 'ChatGPT', contentType: 'prompt', finalAction: 'BLOCK', recommendedAction: 'BLOCK', detectionOutcome: 'MATCH',
  enforcement: { applied: true, httpStatus: 403 }, processingMs,
  detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: [{ entityType: 'KR_RRN', count: 1 }] }],
});

void test('cutoff parsing needs a time zone; empty means the code default', () => {
  assert.equal(gatewayProcessingCutoff(undefined), Date.parse(DEFAULT_GATEWAY_PROCESSING_MS_SINCE));
  assert.equal(gatewayProcessingCutoff(''), Date.parse(DEFAULT_GATEWAY_PROCESSING_MS_SINCE));
  assert.equal(gatewayProcessingCutoff('2026-10-11T15:30:00+09:00'), Date.parse('2026-10-11T06:30:00Z'));
  assert.equal(gatewayProcessingCutoff('2026-10-11T06:30:00.123Z'), Date.parse('2026-10-11T06:30:00.123Z'));
  for (const bad of ['2026-10-11 15:30', '2026-10-11T15:30:00', '2026-10-11', 'yesterday', '2026-13-40T00:00:00Z', 1_760_000_000_000])
    assert.throws(() => gatewayProcessingCutoff(bad), /GATEWAY_PROCESSING_MS_SINCE/, String(bad));
  assert.throws(() => createAppServer({ ...CONFIG, storePath: 'unused.json', gatewayProcessingSince: '2026-10-11 15:30' }), /GATEWAY_PROCESSING_MS_SINCE/);
});

void test('the production start requires the cutoff; library callers keep the code default', async () => {
  for (const missing of [undefined, null, ''])
    assert.throws(() => requiredGatewayProcessingSince(missing), /GATEWAY_PROCESSING_MS_SINCE is required/, String(missing));
  assert.throws(() => requiredGatewayProcessingSince('2026-10-11 15:30'), /GATEWAY_PROCESSING_MS_SINCE must be an ISO 8601/);
  assert.equal(requiredGatewayProcessingSince('2026-10-11T15:30:00+09:00'), '2026-10-11T15:30:00+09:00');

  // index.mjs를 실제로 띄운다. 기준 시각이 없으면 저장소·포트 검사 전에 멈춘다. 있으면 다음 검사(잘못된 포트)까지 가서 멈춘다(서버는 열지 않음)
  const index = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'index.mjs');
  const start = (extra) => new Promise((resolve) => {
    const env = { ...process.env, BACKEND_PORT: '0', ...extra };
    delete env.DATABASE_URL;
    if (extra.GATEWAY_PROCESSING_MS_SINCE === undefined) delete env.GATEWAY_PROCESSING_MS_SINCE;
    execFile(process.execPath, [index], { env, timeout: 15_000 }, (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, killed: error?.killed ?? false, stdout, stderr }));
  });
  const missing = await start({ GATEWAY_PROCESSING_MS_SINCE: undefined });
  assert.equal(missing.killed, false);
  assert.notEqual(missing.code, 0);
  assert.match(missing.stderr, /GATEWAY_PROCESSING_MS_SINCE is required/);
  assert.doesNotMatch(missing.stderr, /BACKEND_PORT/);
  const empty = await start({ GATEWAY_PROCESSING_MS_SINCE: '' });
  assert.match(empty.stderr, /GATEWAY_PROCESSING_MS_SINCE is required/);
  const naive = await start({ GATEWAY_PROCESSING_MS_SINCE: '2026-10-11T15:30:00' });
  assert.match(naive.stderr, /GATEWAY_PROCESSING_MS_SINCE must be an ISO 8601/);
  const valid = await start({ GATEWAY_PROCESSING_MS_SINCE: '2026-10-11T15:30:00+09:00' });
  assert.notEqual(valid.code, 0);
  assert.doesNotMatch(valid.stderr, /GATEWAY_PROCESSING_MS_SINCE/);
  assert.match(valid.stderr, /BACKEND_PORT must be an integer/);
  assert.equal(valid.stdout, '');
});

void test('events before the cutoff lose processing_ms in a copy; later events and the original are untouched', () => {
  const cutoff = Date.parse('2026-10-11T06:00:00Z');
  const old = { event_id: 'old', occurred_at: '2026-10-11T05:59:59.999Z', processing_ms: 17_000, final_action: 'ALLOW' };
  const viewed = withGatewayProcessing(old, cutoff);
  assert.deepEqual(viewed, { event_id: 'old', occurred_at: '2026-10-11T05:59:59.999Z', final_action: 'ALLOW' });
  assert.equal(old.processing_ms, 17_000);
  const atCutoff = { event_id: 'new', occurred_at: '2026-10-11T06:00:00.000Z', processing_ms: 42 };
  assert.equal(withGatewayProcessing(atCutoff, cutoff), atCutoff);
  const unmeasured = { event_id: 'none', occurred_at: '2026-10-01T00:00:00Z' };
  assert.equal(withGatewayProcessing(unmeasured, cutoff), unmeasured);
  assert.equal(withGatewayProcessing(null, cutoff), null);
});

void test('every event read in app.mjs goes through the processing-time view', async () => {
  const source = await readFile(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'app.mjs'), 'utf8');
  // readEvents/readEvent 두 곳만 저장소를 직접 읽는다. 새 경로가 저장소를 직접 읽으면 옛 처리 시간이 다시 섞인다
  assert.equal(source.split('eventStore.list()').length - 1, 1);
  assert.equal(source.split('eventStore.get(').length - 1, 1);
  for (const mutation of ['updateStatus', 'assign', 'addNote'])
    assert.equal(source.split(`await eventStore.${mutation}(`).length - 1, 1, mutation);
  assert.match(source, /sendJson\(response, 200, withGatewayProcessing\(event, processingSince\)\);/);
});

void test('averages, P95, recent rows, event list/detail and mutations exclude processing times recorded before the cutoff', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-dashboard-latency-'));
  const storePath = path.join(root, 'events.json');
  const server = createAppServer({ ...CONFIG, storePath, gatewayProcessingSince: ago(60) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const ingest = (body) => fetch(`${base}/api/events/ingest`, {
      method: 'POST', headers: { Authorization: `Bearer ${CONFIG.ingestToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    // 옛 Gateway: LLM 답변까지 17초 · 새 Gateway: 자체 처리 120ms·80ms
    for (const body of [event('evt-old-round-trip', 120, 17_000), event('evt-new-a', 10, 120), event('evt-new-b', 5, 80)])
      assert.equal((await ingest(body)).status, 201);

    const login = await fetch(`${base}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }),
    });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const get = async (pathname) => {
      const response = await fetch(`${base}${pathname}`, { headers: { Cookie: cookie } });
      assert.equal(response.status, 200, pathname);
      return response.json();
    };

    const summary = await get('/api/traffic/summary?period=24H');
    assert.equal(summary.event_count, 3);
    assert.equal(summary.latency_sample_count, 2);
    assert.equal(summary.average_latency_ms, 100);
    assert.equal(summary.p95_latency_ms, 120);

    const series = await get('/api/traffic/timeseries?period=24H');
    assert.equal(series.reduce((total, bucket) => total + bucket.request_count, 0), 3);
    assert.equal(series.every((bucket) => (bucket.p95_latency_ms ?? 0) <= 120), true);
    const oldBucket = series.find((bucket) => Date.parse(bucket.timestamp) <= Date.now() - 119 * 60_000);
    assert.equal(oldBucket.request_count, 1);
    assert.equal('average_latency_ms' in oldBucket, false);

    const recent = await get('/api/traffic/recent?period=24H&limit=10');
    assert.deepEqual(Object.fromEntries(recent.map((row) => [row.event_id, row.latency_ms])),
      { 'evt-new-b': 80, 'evt-new-a': 120, 'evt-old-round-trip': undefined });

    const stats = await get('/api/dashboard/stats?period=24H');
    assert.equal(stats.average_processing_ms, 100);
    assert.equal(stats.recent.find((item) => item.event_id === 'evt-old-round-trip').processing_ms, undefined);

    const list = await get('/api/events?period=24H&page=1&page_size=20');
    assert.deepEqual(Object.fromEntries(list.items.map((item) => [item.event_id, item.processing_ms])),
      { 'evt-new-b': 80, 'evt-new-a': 120, 'evt-old-round-trip': undefined });
    assert.equal((await get('/api/events/evt-old-round-trip')).processing_ms, undefined);
    assert.equal((await get('/api/events/evt-new-a')).processing_ms, 120);

    const patched = await fetch(`${base}/api/events/evt-old-round-trip/status`, {
      method: 'PATCH', headers: { Cookie: cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'INVESTIGATING' }),
    });
    assert.equal(patched.status, 200);
    const patchedBody = await patched.json();
    assert.equal(patchedBody.status, 'INVESTIGATING');
    assert.equal('processing_ms' in patchedBody, false);

    // 저장된 값은 그대로(읽을 때만 뺀다)
    const stored = JSON.parse(await readFile(storePath, 'utf8'));
    assert.equal(stored.records.find((record) => record.eventId === 'evt-old-round-trip').event.processing_ms, 17_000);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

// 실시간 평균·P95(2026-10-11): 처리 시간을 새로 재는 Gateway만 settings_applied를 보낸다. 칸이 없는 지표(옛 Gateway·되돌린 Gateway)의
// 평균·P95는 LLM 응답까지 잰 값일 수 있어 싣지 않고, 저장 이벤트 값으로 채우지도 않는다
const liveMetrics = (over = {}) => ({
  active_clients: 1, concurrent_requests: 0, requests_per_sec: 0.2, avg_latency_ms: 17_000, p95_latency_ms: 21_000, timeout_rate: 0, degraded_rate: 0,
  total_requests: 5, completed_requests: 5, error_requests: 0, action_distribution: {}, llm_distribution: {}, detector_distribution: {}, window_seconds: 300, ...over,
});
const settingsApplied = () => ({ version: 0, revision: null, source: 'ENV_DEFAULT', applied_at: '2026-10-11T06:00:00.000Z', rejected: null,
  effective: defaultGatewaySettings() });

void test('live average and P95 are shown only when the reporting Gateway sends settings_applied', async () => {
  assert.equal(liveProcessingTimeReported(null), false);
  assert.equal(liveProcessingTimeReported({}), false);
  assert.equal(liveProcessingTimeReported({ settings_applied: settingsApplied() }), true);
  assert.equal(liveProcessingTimeReported({ settings_applied_invalid: true }), true);

  const root = await mkdtemp(path.join(tmpdir(), 'llm-dashboard-live-latency-'));
  const server = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json'), gatewayProcessingSince: ago(60) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const ingestHeaders = { Authorization: `Bearer ${CONFIG.ingestToken}`, 'Content-Type': 'application/json' };
    const report = async (body) => {
      const response = await fetch(`${base}/api/traffic/metrics`, { method: 'POST', headers: ingestHeaders, body: JSON.stringify(body) });
      assert.equal(response.status, 202);
    };
    // 기준 시각 뒤 저장 이벤트(평균 100ms)가 있어도 옛 Gateway 실시간 값 자리를 채우지 않는다
    for (const body of [event('evt-live-a', 10, 120), event('evt-live-b', 5, 80)])
      assert.equal((await fetch(`${base}/api/events/ingest`, { method: 'POST', headers: ingestHeaders, body: JSON.stringify(body) })).status, 201);
    const login = await fetch(`${base}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }),
    });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const summary = async () => {
      const response = await fetch(`${base}/api/traffic/summary?period=24H`, { headers: { Cookie: cookie } });
      assert.equal(response.status, 200);
      return response.json();
    };
    const withheld = (body) => {
      assert.equal(body.metric_source, 'GATEWAY_LIVE');
      assert.equal(body.latency_unavailable_reason, 'LEGACY_GATEWAY');
      for (const name of ['average_latency_ms', 'p95_latency_ms', 'latency_sample_count']) assert.equal(name in body, false, name);
      // 다른 실시간 값은 그대로
      assert.equal(body.requests_per_sec, 0.2);
      assert.equal(body.gateway_completed_requests, 5);
      assert.equal(body.timeout_rate, 0);
      assert.equal(body.gateway_status, 'HEALTHY');
    };

    // 옛 Gateway(LLM 응답까지 17초): settings_applied 없음
    await report(liveMetrics());
    withheld(await summary());

    // 새 Gateway: 같은 지표 + settings_applied → Gateway 처리 시간
    await report(liveMetrics({ avg_latency_ms: 30, p95_latency_ms: 80, settings_applied: settingsApplied() }));
    let body = await summary();
    assert.equal(body.metric_source, 'GATEWAY_LIVE');
    assert.equal('latency_unavailable_reason' in body, false);
    assert.equal(body.average_latency_ms, 30);
    assert.equal(body.p95_latency_ms, 80);
    // 2026-10-15: 확장 칸이 없는 Gateway는 표본 수를 모른다 → 싣지 않는다(전에는 완료 요청 수 = 화면 로딩까지 든 수)
    assert.equal('latency_sample_count' in body, false);

    // 새 Gateway가 형식이 틀린 settings_applied를 보내도(REPORT_INVALID) 처리 시간은 새 기준이다
    await report(liveMetrics({ avg_latency_ms: 31, p95_latency_ms: 81, settings_applied: { ...settingsApplied(), source: 'SOMEWHERE' } }));
    body = await summary();
    assert.equal('latency_unavailable_reason' in body, false);
    assert.equal(body.average_latency_ms, 31);

    // 새 Gateway, 완료 요청 0건: 값 없음(측정 없음), 이유 칸 없음
    await report(liveMetrics({ completed_requests: 0, total_requests: 0, avg_latency_ms: 0, p95_latency_ms: 0, settings_applied: settingsApplied() }));
    body = await summary();
    assert.equal('latency_unavailable_reason' in body, false);
    assert.equal('average_latency_ms' in body, false);
    assert.equal('latency_sample_count' in body, false);

    // Gateway를 옛 판으로 되돌리면 다음 지표부터 바로 다시 뺀다(한 번 본 칸을 기억하지 않음)
    await report(liveMetrics());
    withheld(await summary());
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
