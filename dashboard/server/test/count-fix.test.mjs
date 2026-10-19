// 숫자 산정 수정(2026-10-15 감사 docs/audit-2026-10-15): 접속 차단 분리 · 재전송 접기(리포트 규칙) · 요청 단위 카드 ·
// 민감정보 검출 수 · 문서 누적 탐지 · 트래픽 저장 기록 분모 · 키워드 재시도 감사 · 내 요청 기록 시험 제외 · 탐지 서버 응답 시간
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  ACCESS_REASON_CODES, RESEND_CUTOFF_MS, RESEND_GAP_MS, countedEvents, createAppServer, dashboardStats, hasSensitiveFinding,
  isAccessBlockEvent, listEvents, mergeFingerprintEvidence, ownRequests, resendEventIds, trafficSummary, withCountedDocumentDetections,
} from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import { defaultGatewaySettings } from '../gateway-settings.mjs';
import { liveGatewayState, parseGatewayClients } from '../app.mjs';
import { canonicalEventToDto, validateCanonicalEvent } from '../validation.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-count@example.test',
  adminPassword: 'local-password-count-tests',
  ingestToken: 'local-ingest-token-count-tests',
};
const FILE_A = '00000000aaaabbbbccccddddeeeeffff';
const FILE_B = '11111111aaaabbbbccccddddeeeeffff';
const pii = (count = 1, entityType = 'KR_RRN') => ({ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: [{ entityType, count }] });
const doc = (documentId) => ({ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE', action: 'BLOCK', matchedDocumentId: documentId, score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } });
const canonical = (eventId, timestamp, over = {}) => ({
  type: 'SECURITY_EVENT', eventId, requestId: `req-${eventId}`, timestamp, clientId: 'chrome-1', targetLlm: 'ChatGPT', contentType: 'prompt',
  finalAction: 'BLOCK', detectionOutcome: 'MATCH', detections: [pii()], ...over,
});
const dto = (...args) => canonicalEventToDto(validateCanonicalEvent(canonical(...args)));
const allow = { finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [] };
const access = (code = 'client_id_missing') => ({ finalAction: 'BLOCK', detectionOutcome: 'UNAVAILABLE', detections: [], reasonCode: code, clientId: 'unknown-1' });
const fileBlock = (fileId, over = {}) => ({ contentType: 'file', fileId, ...over });
const at = (base, seconds) => new Date(Date.parse(base) + seconds * 1000).toISOString();

// 2026-10-16 공통 규칙(stats-rules SPEC 2.4): 보고서처럼 사유 코드만 본다 — 검출이 붙어 있어도 접속 차단(전에는 문서·키워드 검출이 먼저)
void test('access-block reason codes match the report (current and old names); the reason code alone decides', () => {
  assert.deepEqual([...ACCESS_REASON_CODES].sort(), ['client_blocked', 'client_id_missing', 'extension_blocked', 'ip_blocked']);
  for (const code of ACCESS_REASON_CODES) assert.equal(isAccessBlockEvent(dto('a', '2026-10-14T00:00:00Z', access(code))), true, code);
  assert.equal(isAccessBlockEvent(dto('b', '2026-10-14T00:00:00Z', { ...access(), detections: [doc('doc-1')], detectionOutcome: 'MATCH' })), true);
  assert.equal(isAccessBlockEvent(dto('c', '2026-10-14T00:00:00Z', { ...access(), detections: [pii(1, 'DOC_KEYWORD')], detectionOutcome: 'MATCH' })), true);
  assert.equal(isAccessBlockEvent(dto('d', '2026-10-14T00:00:00Z', { ...access(), detections: [pii(1, 'KR_RRN')], detectionOutcome: 'MATCH' })), true);
  assert.equal(isAccessBlockEvent(dto('e', '2026-10-14T00:00:00Z', { reasonCode: 'file_uninspectable_image', ...allow, detectionOutcome: 'UNAVAILABLE' })), false);
});

void test('resend folding is the report rule: file only, gap <= 4.348 s, before 2026-10-11 04:23 UTC, chained, same partition', () => {
  assert.equal(RESEND_GAP_MS, 4_348);
  assert.equal(new Date(RESEND_CUTOFF_MS).toISOString(), '2026-10-11T04:23:00.000Z');
  const t0 = '2026-10-01T05:00:00.000Z';
  const events = [
    dto('f1', t0, fileBlock(FILE_A)),
    dto('f2', at(t0, 4.348), fileBlock(FILE_A)),          // 같음 포함 → 접음
    dto('f3', at(t0, 8.0), fileBlock(FILE_A)),            // 바로 앞(f2)에서 3.652초 → 접음(연쇄)
    dto('f4', at(t0, 12.349), fileBlock(FILE_A)),         // 4.349초 → 새 건
    dto('g1', at(t0, 1), fileBlock(FILE_B)),              // 다른 파일 → 새 건
    dto('p1', at(t0, 2), {}),                             // 질문은 접지 않음
    dto('p2', at(t0, 3), {}),
    dto('m1', at(t0, 2), fileBlock(FILE_A, { finalAction: 'MASK', detections: [{ ...pii(), action: 'MASK' }] })),   // 조치가 다르면 다른 칸
  ];
  assert.deepEqual([...resendEventIds(events)].sort(), ['f2', 'f3']);
  // 기준 시각 뒤는 Gateway가 이미 묶으므로 접지 않는다(미만 비교)
  const after = '2026-10-11T04:22:58.000Z';
  assert.deepEqual([...resendEventIds([dto('a1', after, fileBlock(FILE_A)), dto('a2', at(after, 1), fileBlock(FILE_A)), dto('a3', at(after, 2), fileBlock(FILE_A))])], ['a2']);
  // 순서가 섞여 들어와도 시각·이벤트 ID 순으로 본다
  assert.deepEqual([...resendEventIds([...events].reverse())].sort(), ['f2', 'f3']);
  const { counted, access: blocked, resend } = countedEvents([...events, dto('x1', at(t0, 5), access())]);
  assert.equal(resend, 2);
  assert.deepEqual(blocked.map((event) => event.event_id), ['x1']);
  assert.equal(counted.length, 6);   // 9건 - 재전송 2 - 접속 차단 1
});

void test('sensitive finding = document match or a pattern value, not a bare reason code', () => {
  assert.equal(hasSensitiveFinding(dto('a', '2026-10-14T00:00:00Z')), true);
  assert.equal(hasSensitiveFinding(dto('b', '2026-10-14T00:00:00Z', { detections: [doc('doc-1')] })), true);
  assert.equal(hasSensitiveFinding(dto('c', '2026-10-14T00:00:00Z', access())), false);
  assert.equal(hasSensitiveFinding(dto('d', '2026-10-14T00:00:00Z', { reasonCode: 'mask_application_failed', detections: [], detectionOutcome: 'UNAVAILABLE' })), false);
});

void test('overview cards: request units like the list, access blocks counted apart, resends folded, sensitive = real findings', () => {
  const now = Date.parse('2026-10-05T00:00:00Z');
  const t = (minutes) => new Date(now - minutes * 60_000).toISOString();
  const events = [
    dto('q1', t(10), { ...allow, attachedFileIds: [FILE_A] }),                         // 질문 허용 + 파일 마스킹 → 묶음 1건(마스킹)
    dto('f1', t(10.5), fileBlock(FILE_A, { finalAction: 'MASK', detections: [{ ...pii(), action: 'MASK' }] })),
    dto('b1', t(20), { detections: [doc('doc-13'), doc('doc-13')] }),                   // 같은 문서 2번 검출 → 문서 1건
    dto('r1', t(30), fileBlock(FILE_B)),
    dto('r2', new Date(Date.parse(t(30)) + 2_000).toISOString(), fileBlock(FILE_B)),  // 재전송 → 접음
    dto('u1', t(40), { reasonCode: 'file_uninspectable_image', contentType: 'file', finalAction: 'BLOCK', detections: [], detectionOutcome: 'UNAVAILABLE' }),
    dto('x1', t(50), access('client_id_missing')),
    dto('x2', t(60), access('client_blocked')),
    dto('d1', t(70), { ...allow, degraded: true, detectionOutcome: 'UNAVAILABLE', degradedReason: 'TIMEOUT', failurePolicy: 'FAIL_OPEN' }),
    dto('old', new Date(now - 8 * 86_400_000).toISOString()),                          // 기간 밖
  ];
  const stats = dashboardStats(events, new URLSearchParams('period=7D'), now);
  // 요청: q1(+f1) · b1 · r1 · u1 · d1 = 5. 접속 차단 2·재전송 1은 빠짐
  assert.deepEqual([stats.total, stats.block, stats.mask, stats.allow], [5, 3, 1, 1]);
  assert.deepEqual(stats.counting, {
    unit: 'REQUEST', records: 6, list_total: 8, access_blocked: 2, resend_folded: 1, resend_file: 1, resend_prompt: 0, sensitive: 3, last_degraded_at: t(70),   // 2026-10-16 파일·질문 나눠 셈
  });
  assert.deepEqual(stats.recent.map((event) => event.event_id), ['q1', 'b1', 'r1', 'u1', 'd1']);
  assert.equal(stats.recent[0].group_final_action, 'MASK');
  assert.equal(stats.trend.reduce((sum, point) => sum + point.total, 0), 5);
  assert.equal(stats.new_events, 5);
  assert.equal(stats.last_success_at, t(10));
  assert.equal(stats.detection_status, 'DEGRADED');
  // 그래프는 기록 단위(프롬프트·파일 각각), 접속 차단 없음
  assert.deepEqual(stats.insights.content_actions, [{ key: 'prompt', block: 1, mask: 0, allow: 2 }, { key: 'file', block: 2, mask: 1, allow: 0 }]);
  assert.deepEqual(stats.insights.llm_actions, [{ key: 'ChatGPT', block: 3, mask: 1, allow: 2 }]);
  assert.deepEqual(stats.insights.documents, [{ key: 'doc-13', count: 1, blocked: 1 }]);
  assert.equal(stats.insights.heatmap.flat().reduce((sum, value) => sum + value, 0), 4);
});

void test('the list can return the same records as the cards; without scope it is unchanged', () => {
  const now = Date.parse('2026-10-05T00:00:00Z');
  const t = (minutes) => new Date(now - minutes * 60_000).toISOString();
  const events = [
    dto('q1', t(10), { ...allow, attachedFileIds: [FILE_A] }),
    dto('f1', t(10.5), fileBlock(FILE_A, { ...allow })),
    dto('r1', t(30), fileBlock(FILE_B)),
    dto('r2', new Date(Date.parse(t(30)) + 2_000).toISOString(), fileBlock(FILE_B)),
    dto('x1', t(50), access()),
  ];
  const ids = (query) => listEvents(events, new URLSearchParams(`period=7D&page_size=100${query}`), now).items.map((event) => event.event_id).sort();
  assert.deepEqual(ids(''), ['f1', 'q1', 'r1', 'r2', 'x1']);                    // 그대로
  assert.deepEqual(ids('&group=request'), ['q1', 'r1', 'r2', 'x1']);            // 목록 화면(그대로)
  assert.deepEqual(ids('&group=request&scope=counted'), ['q1', 'r1']);          // 보안 현황 카드와 같은 기록
  assert.deepEqual(ids('&scope=inspected'), ['f1', 'q1', 'r1', 'r2']);          // 트래픽 저장 기록(접속 차단만 뺌)
  assert.throws(() => ids('&scope=nope'), (error) => error.statusCode === 400);   // 모르는 값은 다른 칸처럼 400
  const stats = dashboardStats(events, new URLSearchParams('period=7D'), now);
  assert.equal(listEvents(events, new URLSearchParams('period=7D&group=request&scope=counted'), now).total, stats.total);
  assert.equal(listEvents(events, new URLSearchParams('period=7D&group=request'), now).total, stats.counting.list_total);
});

void test('traffic stored records leave access blocks out of counts and denominators', () => {
  const now = Date.parse('2026-10-14T12:00:00Z');
  const t = (minutes) => new Date(now - minutes * 60_000).toISOString();
  const events = [
    { ...dto('p1', t(10), allow), processing_ms: 12 },
    { ...dto('p2', t(20), { ...allow, degraded: true, detectionOutcome: 'UNAVAILABLE', degradedReason: 'TIMEOUT', failurePolicy: 'FAIL_OPEN' }), processing_ms: -1 },
    dto('x1', t(30), access()),
    dto('x2', t(40), access()),
  ];
  const summary = trafficSummary(events, new URLSearchParams('period=24H'), now);
  assert.equal(summary.event_count, 2);
  assert.equal(summary.access_blocked, 2);
  assert.equal(summary.timeout_rate, 0.5);
  assert.equal(summary.degraded_rate, 0.5);
  assert.equal(summary.latency_sample_count, 1);   // 음수 처리 시간은 표본이 아님(화면 그림과 같은 규칙)
  assert.equal(summary.p95_latency_ms, 12);
});

void test('protected document counts use the same records: test clients out (caller), resends folded, one per event', () => {
  const t0 = '2026-10-01T05:00:00.000Z';
  const events = [
    dto('a', t0, fileBlock(FILE_A, { detections: [doc('doc-1'), doc('doc-1')] })),
    dto('b', at(t0, 2), fileBlock(FILE_A, { detections: [doc('doc-1'), doc('doc-1')] })),     // 재전송
    dto('c', at(t0, 60), { detections: [{ detector: 'SHA256', matchType: 'EXACT_DOCUMENT', action: 'BLOCK', outboundDocumentName: 'x.docx', matchedDocumentId: 'doc-1' }] }),
  ];
  const documents = [{ document_id: 'doc-1', exact_detection_count: 9, modified_partial_detection_count: 9, last_detected_at: '2026-10-09T00:00:00.000Z' }, { document_id: 'doc-2', exact_detection_count: 1, modified_partial_detection_count: 1, last_detected_at: t0 }];
  const result = withCountedDocumentDetections(documents, events);
  assert.equal(result[0].modified_partial_detection_count, 1);
  assert.equal(result[0].exact_detection_count, 1);
  assert.equal(result[0].last_detected_at, at(t0, 60));
  assert.deepEqual([result[1].exact_detection_count, result[1].modified_partial_detection_count, 'last_detected_at' in result[1]], [0, 0, false]);
});

void test('a failed RDS index is not shown as protected because Detection still has the previous index', () => {
  const evidence = [{ document_id: 'doc-1', indexed: true, window_count: 21 }, { document_id: 'doc-2', indexed: true, window_count: 5 }];
  const [failed, ready] = mergeFingerprintEvidence([
    { document_id: 'doc-1', status: 'ACTIVE', processing_status: 'FAILED', chunk_index_status: 'FAILED', chunk_count: 0 },
    { document_id: 'doc-2', status: 'ACTIVE', processing_status: 'PROCESSING', chunk_index_status: 'PROCESSING', chunk_count: 0 },
  ], evidence);
  assert.deepEqual([failed.processing_status, failed.chunk_index_status], ['FAILED', 'FAILED']);
  assert.deepEqual([ready.processing_status, ready.chunk_count], ['READY', 5]);
});

void test('own requests never include test clients', () => {
  const hash = 'a'.repeat(64);
  const now = Date.parse('2026-10-14T12:00:00Z');
  const mine = (id, clientId) => ({ ...dto(id, '2026-10-14T11:00:00Z', { clientId }), viewer_key_hash: hash });
  assert.deepEqual(ownRequests([mine('real', 'chrome-1'), mine('demo', 'demo-3'), mine('codex', 'codex-run')], hash, now).items.map((item) => item.event_id), ['real']);
});

async function withBackend(run, { detection } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'count-fix-'));
  let fake = null;
  const calls = [];
  if (detection) {
    fake = createServer((req, res) => {
      const pathname = new URL(req.url, 'http://fake').pathname;
      calls.push({ method: req.method, path: pathname });
      const route = detection[`${req.method} ${pathname}`];
      const reply = () => { res.writeHead(route ? route.status ?? 200 : 404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(route ? route.body : { detail: 'Not Found' })); };
      if (route?.delay) setTimeout(reply, route.delay); else reply();
    });
    await new Promise((resolve) => fake.listen(0, '127.0.0.1', resolve));
  }
  const server = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json'), policyBaseUrl: fake ? `http://127.0.0.1:${fake.address().port}` : undefined });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const request = async (pathname, { method = 'GET', body } = {}) => {
      const response = await fetch(`${base}${pathname}`, { method, headers: { Cookie: cookie, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
      return { status: response.status, json: await response.json() };
    };
    const ingest = async (event) => {
      const response = await fetch(`${base}/api/events/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(event) });
      assert.ok([200, 201, 202].includes(response.status), String(response.status));
    };
    const report = async (body) => {
      const response = await fetch(`${base}/api/traffic/metrics`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(body) });
      return { status: response.status, json: await response.json() };
    };
    await run({ request, ingest, calls, report });
  } finally {
    await new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); });
    if (fake) await new Promise((resolve) => { fake.closeAllConnections?.(); fake.close(resolve); });
    await rm(root, { recursive: true, force: true });
  }
}

void test('HTTP: overview stats, traffic summary and the scoped list agree; access blocks are reported apart', async () => {
  await withBackend(async ({ request, ingest }) => {
    const ago = (seconds) => new Date(Date.now() - seconds * 1000).toISOString();
    await ingest(canonical('evt-real', ago(120)));
    await ingest(canonical('evt-access', ago(90), access()));
    await ingest(canonical('evt-demo', ago(60), { clientId: 'demo-1' }));
    const stats = (await request('/api/dashboard/stats?period=24H')).json;
    assert.deepEqual([stats.total, stats.block, stats.counting.access_blocked, stats.counting.list_total], [1, 1, 1, 2]);
    const list = (await request('/api/events?period=24H&group=request')).json;
    assert.equal(list.total, 2);                                           // 목록 화면은 그대로(접속 차단 포함)
    const scoped = (await request('/api/events?period=24H&group=request&scope=counted')).json;
    assert.deepEqual(scoped.items.map((event) => event.event_id), ['evt-real']);
    const summary = (await request('/api/traffic/summary?period=24H')).json;
    assert.deepEqual([summary.event_count, summary.access_blocked], [1, 1]);
  });
});

void test('HTTP: retrying a keyword extraction is written to the audit log', async () => {
  const detection = { 'POST /admin/keyword-jobs/7/retry': { body: { id: 7, doc_id: 'doc-13', status: 'queued' } } };
  await withBackend(async ({ request }) => {
    const retried = await request('/api/keyword-jobs/7/retry', { method: 'POST' });
    assert.equal(retried.status, 200);
    const logs = (await request('/api/audit-logs?period=24H')).json.items;
    const entry = logs.find((item) => item.action === 'KEYWORD_EXTRACT_REQUEST');
    assert.ok(entry, 'audit entry');
    assert.deepEqual([entry.target_type, entry.target_id, entry.result], ['DOCUMENT', 'doc-13', 'SUCCESS']);
    assert.deepEqual(entry.changes, { retry_of_job_id: 7, job_id: 7, status: 'queued' });
  }, { detection });
});

void test('HTTP: the detection response time is the /health round trip, not the AWS-waiting status call', async () => {
  const systemBody = { checked_at: '2026-10-15T00:00:00Z', detection: { status: 'ok', uptime_s: 100, signatures: {} } };
  const detection = {
    'GET /admin/system-status': { body: systemBody, delay: 1_100 },     // AWS 조회를 기다린 응답
    'GET /health': { body: { status: 'ok' } },
    'GET /admin/gpu': { body: { connected: false, models: [], latency_ms: null, error: null, checked_at: '2026-10-15T00:00:00Z', instance_state: 'stopped' } },
  };
  await withBackend(async ({ request }) => {
    const body = (await request('/api/system/status')).json;
    const component = body.components.find((item) => item.key === 'detection');
    assert.equal(component.status, 'ok');
    assert.ok(component.details['응답 시간(ms)'] < 1_000, String(component.details['응답 시간(ms)']));
    assert.equal(component.details['응답 시간 기준'], '상태 확인(/health) 왕복');
  }, { detection });
});

// ── Gateway 지표 확장 칸(2026-10-15, docs/handoff/gateway-metrics-fix-2026-10-15): 표본 수 · 검사 요청 분모 · 브라우저 취소 제외 오류 · IP 안 확장 ID 묶음
const gwMetrics = (over = {}) => ({
  active_clients: 1, concurrent_requests: 0, requests_per_sec: 0.2, avg_latency_ms: 30, p95_latency_ms: 80, timeout_rate: 0.0003, degraded_rate: 0.0003,
  total_requests: 2888, completed_requests: 2880, error_requests: 7, action_distribution: {}, llm_distribution: {}, detector_distribution: {}, window_seconds: 300,
  settings_applied: { version: 0, revision: null, source: 'ENV_DEFAULT', applied_at: '2026-10-11T06:00:00.000Z', rejected: null, effective: defaultGatewaySettings() },
  ...over,
});
const ext = (over = {}) => ({
  metrics_ext: 1, latency_samples: 11, inspected_requests: 11, degraded_requests: 1, timeout_requests: 1, inspected_timeout_requests: 0,
  client_cancelled_requests: 6, connection_error_requests: 1, ...over,
});

void test('HTTP: the dashboard advertises the metrics extension and uses its counts (samples, inspected denominator, errors without browser cancels)', async () => {
  await withBackend(async ({ request, report }) => {
    const accepted = await report(gwMetrics());
    assert.equal(accepted.status, 202);
    assert.equal(accepted.json.metrics_ext, 1);                               // Gateway는 이 알림을 본 뒤에만 확장 칸을 싣는다
    let summary = (await request('/api/traffic/summary?period=24H')).json;
    // 옛 Gateway(확장 칸 없음): 표본 수 모름, 분모 = 전체 요청, 오류 수는 브라우저 취소 포함이라 판정에 안 씀
    assert.equal('latency_sample_count' in summary, false);
    assert.equal('gateway_inspected_requests' in summary, false);
    assert.deepEqual([summary.gateway_error_basis, summary.gateway_error_requests, summary.degraded_rate], ['ALL_DISCONNECTS', 7, 0.0003]);
    assert.equal(summary.gateway_status, 'DEGRADED');                           // degraded_rate > 0
    assert.equal(summary.gateway_status_reason, '보안 검사 응답 없음 기록');

    assert.equal((await report(gwMetrics({ ...ext() }))).status, 202);
    summary = (await request('/api/traffic/summary?period=24H')).json;
    assert.equal(summary.latency_sample_count, 11);
    assert.equal(summary.gateway_inspected_requests, 11);
    assert.equal(summary.degraded_rate, 1 / 11);                               // 검사 요청 중(전에는 2,888건 중 = 0.03%)
    assert.equal(summary.timeout_rate, 0);
    assert.deepEqual([summary.gateway_error_basis, summary.gateway_error_requests, summary.gateway_client_cancelled_requests], ['GATEWAY_ERRORS', 1, 6]);
    assert.equal(summary.gateway_status_reason, 'Gateway 오류 1건(브라우저 취소 제외) · 보안 검사 응답 없음 1건');
    assert.deepEqual([summary.average_latency_ms, summary.p95_latency_ms], [30, 80]);

    // 브라우저 취소만 있으면 정상(옛 판정은 '오류 기록 있음'이었다)
    await report(gwMetrics({ ...ext({ degraded_requests: 0, connection_error_requests: 0, client_cancelled_requests: 7 }) }));
    summary = (await request('/api/traffic/summary?period=24H')).json;
    assert.equal(summary.gateway_status, 'HEALTHY');
    assert.equal((await request('/api/dashboard/stats?period=24H')).json.gateway_status, 'HEALTHY');   // 보안 현황도 같은 판정
    const gateway = (await request('/api/system/status')).json.components.find((item) => item.key === 'gateway');
    assert.equal(gateway.status, 'ok');                                         // 시스템 상태도 같은 판정

    // 표본 0건: 새 Gateway는 평균·P95를 null로 보낸다 → 받되 값은 싣지 않는다('0초'가 아니라 기록 없음)
    assert.equal((await report(gwMetrics({ ...ext({ latency_samples: 0, degraded_requests: 0, connection_error_requests: 0 }), avg_latency_ms: null, p95_latency_ms: null }))).status, 202);
    summary = (await request('/api/traffic/summary?period=24H')).json;
    assert.equal(summary.latency_sample_count, 0);
    assert.equal('average_latency_ms' in summary, false);
    assert.equal('p95_latency_ms' in summary, false);
    // 확장 칸 없이 null이면 예전처럼 거부(옛 계약 그대로)
    assert.equal((await report(gwMetrics({ avg_latency_ms: null }))).status, 422);
  });
});

void test('HTTP: a malformed extension body is refused (400) so the Gateway falls back to the 10/14 body; the system status shows the same judgement', async () => {
  await withBackend(async ({ request, report }) => {
    const warn = console.warn;
    const warnings = [];
    console.warn = (...args) => warnings.push(args.join(' '));
    try {
      assert.equal((await report(gwMetrics({ ...ext({ degraded_requests: 99 }) }))).status, 400);   // 검사 요청보다 많음
      const { client_cancelled_requests: _dropped, ...missing } = ext();
      assert.equal((await report(gwMetrics(missing))).status, 400);                                  // 8칸 중 하나가 빠짐(CONTRACT 4절 1)
      assert.equal((await report(gwMetrics({ ...ext({ inspected_requests: 1.5 }) }))).status, 400);
      assert.equal((await report(gwMetrics({ ...ext(), metrics_ext: true }))).status, 400);
      assert.equal((await report(gwMetrics({ ...ext({ latency_samples: 3 }), avg_latency_ms: null }))).status, 422);   // 표본이 있으면 null 안 됨
    } finally { console.warn = warn; }
    assert.equal(warnings.length, 4);
    assert.ok(warnings.every((line) => line.startsWith('Gateway metrics extension rejected: ')));
    // 그 뒤 Gateway가 보내는 10/14 본문은 지금처럼 받는다
    assert.equal((await report(gwMetrics())).status, 202);
    const summary = (await request('/api/traffic/summary?period=24H')).json;
    assert.equal('gateway_inspected_requests' in summary, false);
    assert.equal(summary.gateway_error_basis, 'ALL_DISCONNECTS');
    // 오류(브라우저 취소 제외)가 있는 새 Gateway → 시스템 상태 Gateway '느림' + 같은 근거
    await report(gwMetrics({ ...ext({ degraded_requests: 0 }), degraded_rate: 0 }));
    const gateway = (await request('/api/system/status')).json.components.find((item) => item.key === 'gateway');
    assert.equal(gateway.status, 'slow');
    assert.match(gateway.summary, /^오류 기록 있음 · 마지막 보고/);
    assert.equal(gateway.details['판정 근거'], 'Gateway 오류 1건(브라우저 취소 제외)');
  });
});

void test('connected IP rows: by_client groups become (IP, extension ID) rows, the old shape still works', () => {
  const row = (over = {}) => ({ ip: '203.0.113.10', client_id: 'chrome-b', connections: 3, inflight: 1, waiting: 0, requests_5m: 4, targets: { Claude: 3, ChatGPT: 1 },
    first_seen_at: '2026-10-15T01:00:00Z', last_seen_at: '2026-10-15T01:04:30Z', ...over });
  const group = (over = {}) => { const { ip: _ip, ...rest } = row(over); return rest; };
  const rows = parseGatewayClients([
    { ...row(), by_client: [group({ client_id: 'chrome-b', connections: 2, requests_5m: 3, targets: { Claude: 3 } }),
      group({ client_id: 'chrome-a', connections: 1, inflight: 0, requests_5m: 1, targets: { ChatGPT: 1 }, last_seen_at: '2026-10-15T01:02:00Z' })] },
    row({ ip: '203.0.113.11', client_id: null }),                                          // 옛 모양(묶음 없음)
  ]);
  assert.deepEqual(rows.map((item) => [item.ip, item.client_id, item.connections, item.requests_5m]),
    [['203.0.113.10', 'chrome-b', 2, 3], ['203.0.113.11', null, 3, 4], ['203.0.113.10', 'chrome-a', 1, 1]]);
  // 틀린 by_client는 그 묶음만 버리고 IP 한 줄(CONTRACT 3절) — 목록 전체를 버리지 않는다
  assert.deepEqual(parseGatewayClients([{ ...row(), by_client: [{ ...group(), ip: 'x' }] }]).map((item) => [item.ip, item.client_id, item.connections]), [['203.0.113.10', 'chrome-b', 3]]);
  assert.equal(parseGatewayClients([{ ...row(), by_client: [] }]).length, 1);
  assert.equal(parseGatewayClients([{ ...row(), by_client: [group({ connections: -1 })] }])[0].connections, 3);
  // null 묶음(식별 헤더를 아직 못 본 연결)은 확장 ID 없는 줄
  assert.deepEqual(parseGatewayClients([{ ...row(), by_client: [group({ client_id: null, requests_5m: 0 })] }]).map((item) => item.client_id), [null]);
  assert.throws(() => parseGatewayClients([{ ...row({ connections: -1 }), by_client: [group()] }]), /count/);   // IP 항목이 틀리면 지금처럼
  // 펼친 줄이 많아도 화면 계약(200줄)을 넘지 않는다
  const many = Array.from({ length: 20 }, (_, index) => ({ ...row({ ip: `203.0.113.${index}` }), by_client: Array.from({ length: 20 }, (_, k) => group({ client_id: `chrome-${k}` })) }));
  assert.equal(parseGatewayClients(many).length, 200);
});

void test('one judgement for the strip, the overview and the system status', () => {
  const now = Date.parse('2026-10-15T00:00:00Z');
  const fresh = (over) => ({ ...gwMetrics(over), received_at: new Date(now - 5_000).toISOString() });
  assert.equal(liveGatewayState(fresh({ degraded_rate: 0 }), now).status, 'HEALTHY');            // 옛 Gateway: error_requests 7(브라우저 취소 포함)은 무시
  assert.equal(liveGatewayState({ ...fresh({ degraded_rate: 0 }), ext: { connection_error_requests: 1, degraded_requests: 0 } }, now).status, 'DEGRADED');
  assert.equal(liveGatewayState({ ...fresh({ degraded_rate: 0.5 }), ext: { connection_error_requests: 0, degraded_requests: 0 } }, now).status, 'HEALTHY');   // 새 Gateway는 건수로
});
