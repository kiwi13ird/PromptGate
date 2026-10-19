// 시험·데모 이벤트 제외(2번) · Gateway 실시간 상태(5번) — 2026-10-10
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createAppServer, dashboardStats, entityCategory, liveGatewayState } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import { canonicalEventToDto, validateCanonicalEvent } from '../validation.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';
import { isTestEvent, TEST_CLIENT_PATTERN, TEST_CLIENT_PREFIXES } from '../test-events.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-scope@example.test',
  adminPassword: 'local-password-scope-tests',
  ingestToken: 'local-ingest-token-scope-tests',
};
const ago = (seconds) => new Date(Date.now() - seconds * 1000).toISOString();
const block = (eventId, clientId, seconds = 60) => ({
  type: 'SECURITY_EVENT', eventId, requestId: `req-${eventId}`, timestamp: ago(seconds), clientId, targetLlm: 'ChatGPT', contentType: 'prompt',
  finalAction: 'BLOCK', detectionOutcome: 'MATCH',
  detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: [{ entityType: 'KR_RRN', count: 1 }] }],
});
const metrics = (over = {}) => ({
  active_clients: 1, concurrent_requests: 0, requests_per_sec: 0.2, avg_latency_ms: 30, p95_latency_ms: 80, timeout_rate: 0, degraded_rate: 0,
  total_requests: 5, completed_requests: 5, error_requests: 0, action_distribution: {}, llm_distribution: {}, detector_distribution: {}, window_seconds: 300, ...over,
});

void test('test clients are recognised by prefix only', () => {
  assert.deepEqual([...TEST_CLIENT_PREFIXES], ['demo', 'evidence', 'codex', 'diag', 'gateway', 'legacy']);   // 2026-10-16 legacy 추가(stats-rules SPEC 2.1)
  const regex = new RegExp(TEST_CLIENT_PATTERN);
  for (const [id, expected] of [
    ['demo', true], ['demo-17', true], ['codex-run', true], ['diag-1', true], ['evidence-a', true], ['gateway-smoke', true],
    ['chrome-1b73', false], ['unknown-9', false], ['legacy-2', true], ['legacyX', false], ['demonstration-1', false], ['chrome-demo', false], ['', false],
  ]) {
    assert.equal(isTestEvent({ client_id: id }), expected, id);
    assert.equal(regex.test(id), expected, `sql ${id}`);   // SQL과 JS가 같은 기준
  }
});

void test('gateway state follows live metrics, not stored events', () => {
  const now = Date.parse('2026-10-10T00:10:00Z');
  const at = (seconds) => new Date(now - seconds * 1000).toISOString();
  assert.deepEqual(liveGatewayState(null, now), { status: 'UNKNOWN', metricsStatus: 'NOT_RECEIVED' });
  assert.deepEqual(liveGatewayState({ ...metrics(), received_at: at(121) }, now), { status: 'UNKNOWN', metricsStatus: 'STALE' });
  // 2026-10-15: '최근' = 30초 미만(시스템 상태·연결 IP 표와 같은 기준, 전에는 2분)
  assert.deepEqual(liveGatewayState({ ...metrics(), received_at: at(29) }, now), { status: 'HEALTHY', metricsStatus: 'FRESH', completed: 5 });
  assert.deepEqual(liveGatewayState({ ...metrics(), received_at: at(30) }, now), { status: 'UNKNOWN', metricsStatus: 'STALE' });
  // 옛 Gateway의 error_requests는 브라우저가 끊은 요청까지 들어 있어 판정에 쓰지 않는다(감사 4번). 검사 응답 없음만
  assert.equal(liveGatewayState({ ...metrics({ error_requests: 1 }), received_at: at(20) }, now).status, 'HEALTHY');
  assert.deepEqual(liveGatewayState({ ...metrics({ degraded_rate: 0.1 }), received_at: at(20) }, now),
    { status: 'DEGRADED', metricsStatus: 'FRESH', completed: 5, reason: '보안 검사 응답 없음 기록' });
  assert.deepEqual(liveGatewayState({ ...metrics({ completed_requests: 0, total_requests: 0 }), received_at: at(20) }, now),
    { status: 'UNKNOWN', metricsStatus: 'FRESH', completed: 0 });
});

void test('document detection counts skip test clients in SQL', async () => {
  const seen = [];
  const pool = { async query(sql, params) { seen.push({ sql, params }); return { rows: [] }; } };
  await new PostgresEventStore({ pool }).listDocuments();
  const counts = seen.find((call) => /FROM dashboard_security_events/.test(call.sql));
  assert.match(counts.sql, /client_id !~ \$1/);
  assert.deepEqual(counts.params, [TEST_CLIENT_PATTERN]);
});

async function withBackend(run, makeStore) {
  const root = await mkdtemp(path.join(tmpdir(), 'stats-scope-'));
  const server = createAppServer({ ...CONFIG, ...(makeStore ? { store: makeStore(path.join(root, 'events.json')) } : { storePath: path.join(root, 'events.json') }) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const post = async (pathname, body) => {
      const response = await fetch(`${base}${pathname}`, { method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(body) });
      assert.ok([200, 201, 202].includes(response.status), `${pathname} ${response.status}`);
    };
    const get = async (pathname) => {
      const response = await fetch(`${base}${pathname}`, { headers: { Cookie: cookie } });
      assert.equal(response.status, 200, pathname);
      return response.json();
    };
    await run({ post, get });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

void test('lists, overview and traffic leave test events out; the list can bring them back', async () => {
  await withBackend(async ({ post, get }) => {
    await post('/api/events/ingest', block('evt-real', 'chrome-1b73', 120));
    await post('/api/events/ingest', block('evt-demo', 'demo-7', 90));
    await post('/api/events/ingest', block('evt-codex', 'codex-run', 30));

    const list = await get('/api/events?period=24H');
    assert.deepEqual(list.items.map((event) => event.event_id), ['evt-real']);
    assert.equal(list.total, 1);
    assert.equal(list.excluded_test, 2);
    const filtered = await get('/api/events?period=24H&query=evt-demo');   // 같은 조건의 시험 건수만 센다
    assert.equal(filtered.excluded_test, 1);
    const all = await get('/api/events?period=24H&include_test=1');
    assert.deepEqual(all.items.map((event) => event.event_id).sort(), ['evt-codex', 'evt-demo', 'evt-real']);
    assert.equal(all.excluded_test, undefined);   // 포함해서 볼 때는 빠진 건이 없으므로 싣지 않는다

    const stats = await get('/api/dashboard/stats?period=24H');
    assert.equal(stats.total, 1);
    assert.equal(stats.block, 1);
    assert.deepEqual(stats.recent.map((event) => event.event_id), ['evt-real']);
    const recent = await get('/api/traffic/recent?period=24H');
    assert.deepEqual(recent.map((row) => row.event_id), ['evt-real']);

    // 상세는 그대로 열린다(지우지 않았으므로)
    assert.equal((await get('/api/events/evt-demo')).event_id, 'evt-demo');
  });
});

void test('overview insights count types, documents, services, input kinds and Korean-time hours', async () => {
  await withBackend(async ({ post, get }) => {
    const at = (iso) => ({ timestamp: iso });
    // 2026-10-06(화) 09:30 UTC = 한국 시간 18:30 화요일
    await post('/api/events/ingest', { ...block('evt-a', 'chrome-1', 60), ...at(new Date(Date.now() - 3600_000).toISOString()),
      detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: [{ entityType: 'KR_RRN', count: 2 }, { entityType: 'EMAIL_ADDRESS', count: 1 }] }] });
    await post('/api/events/ingest', { ...block('evt-b', 'chrome-1', 30), targetLlm: 'Gemini', contentType: 'file', finalAction: 'MASK',
      detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'MASK', entityCounts: [{ entityType: 'KR_RRN', count: 1 }] }] });
    await post('/api/events/ingest', { ...block('evt-c', 'chrome-1', 20), finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [] });
    const hash = (id, seconds) => ({ ...block(id, 'chrome-1', seconds), detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE',
      action: 'BLOCK', matchedDocumentId: id === 'evt-d3' ? 'doc-05' : 'doc-13', score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } }] });
    await post('/api/events/ingest', hash('evt-d1', 50));
    await post('/api/events/ingest', hash('evt-d2', 40));
    await post('/api/events/ingest', hash('evt-d3', 35));
    await post('/api/events/ingest', block('evt-demo', 'demo-1', 10));   // 시험 기록은 그래프에도 안 들어간다
    const { insights } = await get('/api/dashboard/stats?period=24H');
    assert.deepEqual(insights.entity_counts, [{ key: 'KR_RRN', count: 3 }, { key: 'EMAIL_ADDRESS', count: 1 }]);
    assert.deepEqual(insights.documents.map((d) => [d.key, d.count]), [['doc-13', 2], ['doc-05', 1]]);
    assert.deepEqual(insights.llm_actions, [{ key: 'ChatGPT', block: 4, mask: 0, allow: 1 }, { key: 'Gemini', block: 0, mask: 1, allow: 0 }]);
    assert.deepEqual(insights.content_actions, [{ key: 'prompt', block: 4, mask: 0, allow: 1 }, { key: 'file', block: 0, mask: 1, allow: 0 }]);
    assert.equal(insights.heatmap.length, 7);
    assert.ok(insights.heatmap.every((row) => row.length === 24));
    assert.equal(insights.heatmap.flat().reduce((sum, value) => sum + value, 0), 5);   // 차단 4 + 마스킹 1, 허용 제외
    const kst = new Date(Date.now() - 30_000 + 9 * 3600_000);
    assert.ok(insights.heatmap[kst.getUTCDay()][kst.getUTCHours()] >= 1);   // 한국 시간 요일·시각 칸
  });
});

void test('overview documents carry their registered names', async () => {
  class NamedStore extends JsonEventStore {
    async listDocuments() { return [{ document_id: 'doc-13', document_name: '13_파트너사협상자료.docx' }]; }
  }
  await withBackend(async ({ post, get }) => {
    const hash = (id, doc) => ({ ...block(id, 'chrome-1', 40), detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE',
      action: 'BLOCK', matchedDocumentId: doc, score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } }] });
    await post('/api/events/ingest', hash('evt-1', 'doc-13'));
    await post('/api/events/ingest', hash('evt-2', 'doc-13'));
    await post('/api/events/ingest', hash('evt-3', 'doc-05'));
    const { insights } = await get('/api/dashboard/stats?period=24H');
    assert.deepEqual(insights.documents, [
      { key: 'doc-13', count: 2, blocked: 2, name: '13_파트너사협상자료.docx' },
      { key: 'doc-05', count: 1, blocked: 1 },   // 등록되지 않은 문서는 이름 없이
    ]);
  }, (file) => new NamedStore(file));
});

void test('heatmap places events by Korean weekday and hour', () => {
  const dto = (id, iso, finalAction) => canonicalEventToDto(validateCanonicalEvent({ ...block(id, 'chrome-1'), timestamp: iso, finalAction,
    detectionOutcome: finalAction === 'ALLOW' ? 'NO_MATCH' : 'MATCH', detections: finalAction === 'ALLOW' ? [] : block(id, 'chrome-1').detections }));
  const events = [
    dto('e1', '2026-10-05T15:30:00Z', 'BLOCK'),   // 월 15:30 UTC = 화 00:30 KST
    dto('e2', '2026-10-06T09:30:00Z', 'MASK'),    // 화 18:30 KST
    dto('e3', '2026-10-04T14:59:00Z', 'BLOCK'),   // 일 23:59 KST
    dto('e4', '2026-10-06T10:00:00Z', 'ALLOW'),   // 허용은 세지 않는다
  ];
  const { heatmap } = dashboardStats(events, new URLSearchParams('period=7D'), Date.parse('2026-10-06T12:00:00Z')).insights;
  assert.equal(heatmap[2][0], 1);
  assert.equal(heatmap[2][18], 1);
  assert.equal(heatmap[0][23], 1);
  assert.equal(heatmap.flat().reduce((sum, value) => sum + value, 0), 3);
});

void test('hits are counted per policy category, once per event', () => {
  assert.deepEqual(['KR_RRN', 'EMAIL_ADDRESS', 'GITHUB_TOKEN', 'PASSWORD', 'AWS_ACCESS_KEY', 'DOC_KEYWORD', 'NEW_TYPE'].map(entityCategory),
    ['PII', 'PII', 'CREDENTIAL', 'CREDENTIAL', 'CREDENTIAL', 'KEYWORD', 'PII']);
  const dto = (id, counts) => canonicalEventToDto(validateCanonicalEvent({ ...block(id, 'chrome-1'), timestamp: '2026-10-06T09:00:00Z',
    detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: counts }] }));
  const events = [
    dto('a', [{ entityType: 'KR_RRN', count: 2 }, { entityType: 'EMAIL_ADDRESS', count: 1 }]),   // 개인정보 1건(값 3개)
    dto('b', [{ entityType: 'GITHUB_TOKEN', count: 1 }, { entityType: 'KR_RRN', count: 1 }]),   // 자격증명 1건 + 개인정보 1건
  ];
  const { category_counts, entity_event_counts } = dashboardStats(events, new URLSearchParams('period=7D'), Date.parse('2026-10-06T12:00:00Z')).insights;
  assert.deepEqual(entity_event_counts, [{ key: 'KR_RRN', count: 2 }, { key: 'EMAIL_ADDRESS', count: 1 }, { key: 'GITHUB_TOKEN', count: 1 }]);
  assert.deepEqual(category_counts, [
    { key: 'PII', events: 2, values: 4 },
    { key: 'CREDENTIAL', events: 1, values: 1 },
    { key: 'KEYWORD', events: 0, values: 0 },
  ]);
});

void test('the event list filters by detected information kind', async () => {
  await withBackend(async ({ post, get }) => {
    const sig = (id, types) => ({ ...block(id, 'chrome-1', 30), detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK',
      entityCounts: types.map((entityType) => ({ entityType, count: 1 })) }] });
    await post('/api/events/ingest', sig('evt-pii', ['KR_RRN']));
    await post('/api/events/ingest', sig('evt-cred', ['GITHUB_TOKEN']));
    await post('/api/events/ingest', sig('evt-kw', ['DOC_KEYWORD']));
    await post('/api/events/ingest', sig('evt-mixed', ['DOC_KEYWORD', 'EMAIL_ADDRESS']));
    const ids = async (query) => (await get(`/api/events?period=24H${query}`)).items.map((event) => event.event_id).sort();
    assert.deepEqual(await ids('&entity_category=KEYWORD'), ['evt-kw', 'evt-mixed']);
    assert.deepEqual(await ids('&entity_category=CREDENTIAL'), ['evt-cred']);
    assert.deepEqual(await ids('&entity_category=PII'), ['evt-mixed', 'evt-pii']);
    assert.equal((await ids('')).length, 4);
  });
});

void test('a question row matches the kind found in its attached file', async () => {
  await withBackend(async ({ post, get }) => {
    const FILE = '00000000aaaabbbbccccddddeeeeffff';
    await post('/api/events/ingest', { ...block('evt-file', 'chrome-1', 40), contentType: 'file', fileId: FILE,
      detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: [{ entityType: 'DOC_KEYWORD', count: 1 }] }] });
    await post('/api/events/ingest', { ...block('evt-question', 'chrome-1', 30), finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [], attachedFileIds: [FILE] });
    const ids = async (query) => (await get(`/api/events?period=24H&group=request${query}`)).items.map((event) => event.event_id);
    assert.deepEqual(await ids('&entity_category=KEYWORD'), ['evt-question']);   // 묶음 전체(질문+파일)로 거른다
    assert.deepEqual(await ids('&entity_category=PII'), []);
  });
});

void test('overview gateway status comes from live metrics', async () => {
  await withBackend(async ({ post, get }) => {
    await post('/api/events/ingest', block('evt-real', 'chrome-1b73'));
    let stats = await get('/api/dashboard/stats?period=24H');
    assert.equal(stats.gateway_status, 'UNKNOWN');                 // 이벤트가 있어도 지표가 없으면 판정하지 않는다
    assert.equal(stats.gateway_metrics_status, 'NOT_RECEIVED');

    await post('/api/traffic/metrics', metrics());
    stats = await get('/api/dashboard/stats?period=24H');
    assert.equal(stats.gateway_status, 'HEALTHY');
    assert.equal(stats.gateway_metrics_status, 'FRESH');
    assert.equal(stats.gateway_completed_requests, 5);
    assert.equal((await get('/api/traffic/summary?period=24H')).gateway_status, 'HEALTHY');   // 트래픽 화면과 같은 값

    await post('/api/traffic/metrics', metrics({ error_requests: 2 }));   // 옛 Gateway: 브라우저 취소가 섞인 수라 판정에 안 씀
    assert.equal((await get('/api/dashboard/stats?period=24H')).gateway_status, 'HEALTHY');
    await post('/api/traffic/metrics', metrics({ degraded_rate: 0.2 }));
    assert.equal((await get('/api/dashboard/stats?period=24H')).gateway_status, 'DEGRADED');
  });
});
