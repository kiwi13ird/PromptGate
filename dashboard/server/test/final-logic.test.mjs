// 남은 로직 정리(2026-10-16): 보안 이벤트 목록 보기(보안 이벤트 = 카드와 같은 기록 · 접속 차단 기록 · 전체 기록) ·
// 내 요청 기록 100건 상한 알림 · Detection 5xx를 '응답 해석 실패'가 아닌 '탐지 서버 오류'로
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { countedEvents, createAppServer, dashboardStats, listEvents, ownRequests } from '../app.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';
import { isDemoDocumentEvent, isExcludedEvent, TEST_CLIENT_PREFIXES } from '../test-events.mjs';
import { canonicalEventToDto, validateCanonicalEvent } from '../validation.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-final@example.test',
  adminPassword: 'local-password-final-tests',
  ingestToken: 'local-ingest-token-final-tests',
};
const FILE_A = '00000000aaaabbbbccccddddeeeeffff';
const HASH_A = 'a'.repeat(64);
const pii = () => ({ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'BLOCK', entityCounts: [{ entityType: 'KR_RRN', count: 1 }] });
const canonical = (eventId, timestamp, over = {}) => ({
  type: 'SECURITY_EVENT', eventId, requestId: `req-${eventId}`, timestamp, clientId: 'chrome-1', targetLlm: 'ChatGPT', contentType: 'prompt',
  finalAction: 'BLOCK', detectionOutcome: 'MATCH', detections: [pii()], ...over,
});
const dto = (...args) => canonicalEventToDto(validateCanonicalEvent(canonical(...args)));
const access = (code = 'client_id_missing') => ({ finalAction: 'BLOCK', detectionOutcome: 'UNAVAILABLE', detections: [], reasonCode: code, clientId: 'unknown-1' });
const allow = { finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [] };
const at = (base, seconds) => new Date(Date.parse(base) + seconds * 1000).toISOString();

// 10/11 전 파일 재전송 2건(f2·f3 접힘) + 질문 2 + 접속 차단 2
const T0 = '2026-10-10T01:00:00Z';
const NOW = Date.parse('2026-10-10T12:00:00Z');
const EVENTS = [
  dto('f1', T0, { contentType: 'file', fileId: FILE_A }),
  dto('f2', at(T0, 2), { contentType: 'file', fileId: FILE_A }),
  dto('f3', at(T0, 4), { contentType: 'file', fileId: FILE_A }),
  dto('q1', at(T0, 60)),
  dto('q2', at(T0, 120), allow),
  dto('x1', at(T0, 180), access('client_id_missing')),
  dto('x2', at(T0, 240), access('client_blocked')),
];
const list = (query) => listEvents(EVENTS, new URLSearchParams(`period=24H&group=request&page_size=100${query}`), NOW);
const ids = (page) => page.items.map((event) => event.event_id).sort();

void test('list views: security events = the cards, access blocks apart, all = everything; totals for each view', () => {
  const counted = list('&scope=counted');
  const stats = dashboardStats(EVENTS, new URLSearchParams('period=24H'), NOW);
  assert.deepEqual(ids(counted), ['f1', 'q1', 'q2']);                     // 재전송 접고 접속 차단 뺌
  assert.equal(counted.total, stats.total);                                // 카드 '전체 이벤트'와 같은 수
  assert.equal(list('&scope=counted&final_action=BLOCK').total, stats.block);
  const accessView = list('&scope=access');
  assert.deepEqual(ids(accessView), ['x1', 'x2']);
  assert.equal(accessView.total, stats.counting.access_blocked);           // 카드 아래 '접속 차단 n건'과 같은 수
  assert.deepEqual(counted.view_totals, { counted: 3, access: 2, all: 7 });
  assert.deepEqual(accessView.view_totals, { counted: 3, access: 2, all: 7 });
  assert.equal(list('').total, 7);                                          // scope 없음 = 지금처럼 전부
  assert.equal(list('').view_totals, undefined);                            // 옛 모양 그대로
  assert.equal(list('&scope=inspected').view_totals, undefined);
  // 보기 건수도 같은 조건으로 센다
  assert.deepEqual(list('&scope=counted&final_action=ALLOW').view_totals, { counted: 1, access: 0, all: 1 });
  assert.deepEqual(list('&scope=access&query=x1').view_totals, { counted: 0, access: 1, all: 1 });
  assert.equal(list('&scope=counted').view_totals.all, list('').total);
  assert.throws(() => list('&scope=nope'), (error) => error.statusCode === 400);
});

void test('my requests: at most 100 rows, and the response says when older rows were left out', () => {
  const now = Date.now();
  const masked = (index) => dto(`m${index}`, new Date(now - (index + 1) * 60_000).toISOString(), { finalAction: 'MASK', viewerKeyHash: HASH_A,
    detections: [{ ...pii(), action: 'MASK' }] });
  const many = Array.from({ length: 101 }, (_, index) => masked(index));
  const full = ownRequests(many, HASH_A, now);
  assert.equal(full.items.length, 100);
  assert.equal(full.items[0].event_id, 'm0');                             // 최신 100건
  assert.equal(full.limit, 100);
  assert.equal(full.truncated, true);
  const few = ownRequests(many.slice(0, 100), HASH_A, now);
  assert.equal(few.items.length, 100);
  assert.equal(few.truncated, false);                                     // 딱 100건이면 빠진 것이 없다
  assert.equal(ownRequests([], HASH_A, now).truncated, false);
});

// ─── Detection 5xx
function startFakeDetection(mode) {
  const server = createServer((req, res) => {
    const json = (status, payload) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); };
    if (req.url.startsWith('/admin/policies')) {
      if (mode.value === 'text500') { res.writeHead(500, { 'Content-Type': 'text/plain' }); return res.end('Internal Server Error'); }
      if (mode.value === 'json500') return json(500, { detail: 'boom' });
      if (mode.value === 'coded503') return json(503, { detail: { code: 'POLICY_UNAVAILABLE', message: 'policy store down' } });
      if (mode.value === 'badjson200') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{not json'); }
      if (mode.value === 'text404') { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    }
    return json(404, { detail: { code: 'FAKE_NOT_FOUND', message: req.url } });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` })));
}

void test('policy relay: Detection 5xx is a server error, not an unreadable answer; codes from Detection are kept', async () => {
  const mode = { value: 'text500' };
  const detection = await startFakeDetection(mode);
  const root = await mkdtemp(path.join(tmpdir(), 'final-logic-'));
  const backend = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json'), policyBaseUrl: detection.baseUrl });
  await new Promise((resolve) => backend.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${backend.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const get = async () => {
      const response = await fetch(`${base}/api/policies`, { headers: { Cookie: cookie } });
      return { status: response.status, error: (await response.json()).error };
    };
    let result = await get();
    assert.equal(result.status, 502);
    assert.equal(result.error.code, 'POLICY_UPSTREAM_SERVER_ERROR');      // 전: POLICY_UPSTREAM_INVALID_RESPONSE
    assert.deepEqual(result.error.details, { upstream_status: 500 });
    mode.value = 'json500';
    result = await get();
    assert.equal(result.error.code, 'POLICY_UPSTREAM_SERVER_ERROR');      // 전: POLICY_UPSTREAM_ERROR(500)
    assert.equal(result.status, 502);
    mode.value = 'coded503';
    result = await get();
    assert.equal(result.status, 503);
    assert.equal(result.error.code, 'POLICY_UNAVAILABLE');                // Detection이 정한 코드는 그대로
    mode.value = 'badjson200';
    result = await get();
    assert.equal(result.status, 502);
    assert.equal(result.error.code, 'POLICY_UPSTREAM_INVALID_RESPONSE');  // 정상 상태인데 못 읽는 응답은 그대로 '해석 실패'
    mode.value = 'text404';
    result = await get();
    assert.equal(result.error.code, 'POLICY_UPSTREAM_INVALID_RESPONSE');  // 4xx 글 응답도 그대로
  } finally {
    await new Promise((resolve) => backend.close(resolve));
    await new Promise((resolve) => detection.server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

// ─── 통계 제외·재시도 접기 공통 규칙(docs/handoff/stats-rules-2026-10-16/SPEC.md 6절 시험 사례, 대시보드 몫)
const hashDoc = (documentId) => ({ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE', action: 'BLOCK', matchedDocumentId: documentId, score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } });
const ask = (eventId, timestamp, hash, over = {}) => ({ ...dto(eventId, timestamp, over), prompt_hash: hash });
const P0 = '2026-10-12T01:00:00Z';   // 10/11 04:23 UTC 뒤(질문은 기준 시각 없음)
const kept = (events) => countedEvents(events.filter((event) => !isExcludedEvent(event)));
const later = (ms) => new Date(Date.parse(P0) + ms).toISOString();

void test('SPEC 1-4: legacy prefix and demo-document-only events are excluded, nothing else', () => {
  assert.equal(TEST_CLIENT_PREFIXES.includes('legacy'), true);
  assert.equal(isExcludedEvent(dto('l1', P0, { clientId: 'legacy-gateway' })), true);               // 1
  assert.equal(isExcludedEvent(dto('l2', P0, { clientId: 'legacyX' })), false);                     // 2
  assert.equal(isExcludedEvent(dto('l3', P0, { clientId: 'my-legacy' })), false);
  assert.equal(isDemoDocumentEvent(dto('d1', P0, { detections: [hashDoc('DEMO_a')] })), true);       // 3
  assert.equal(isExcludedEvent(dto('d2', P0, { detections: [hashDoc('DEMO_a'), hashDoc('01_사업전략')] })), false);   // 4
  assert.equal(isExcludedEvent(dto('d3', P0, allow)), false);
  assert.equal(isExcludedEvent(dto('d4', P0)), false);                                              // SIGNATURE만
});

void test('SPEC 5-11: prompt retries fold at 4.348 s on the same key and body hash, chained, with no cutoff; files keep the old rule', () => {
  let result = kept([ask('p1', later(0), 'h'), ask('p2', later(4_348), 'h')]);                            // 5
  assert.deepEqual([result.counted.map((e) => e.event_id), result.resend_prompt, result.resend], [['p1'], 1, 1]);
  result = kept([ask('p1', later(0), 'h'), ask('p2', later(4_349), 'h')]);                                 // 6
  assert.equal(result.counted.length, 2);
  result = kept([ask('p1', later(0), 'h'), ask('p2', later(3_000), 'h'), ask('p3', later(6_000), 'h')]);   // 7
  assert.deepEqual(result.counted.map((e) => e.event_id), ['p1']);
  for (const over of [{ ...allow }, { targetLlm: 'Gemini' }, { clientId: 'chrome-2' }])                   // 8
    assert.equal(kept([ask('p1', later(0), 'h'), ask('p2', later(1_000), 'h', over)]).counted.length, 2, JSON.stringify(over));
  assert.equal(kept([ask('p1', later(0), 'h'), ask('p2', later(1_000), 'other')]).counted.length, 2);      // 본문 다름
  result = kept([ask('p1', later(0), null), ask('p2', later(1_000), null)]);                               // 9
  assert.equal(result.counted.length, 2);
  result = kept([ask('x1', later(0), null, access()), ask('x2', later(1_000), null, access())]);
  assert.deepEqual([result.counted.length, result.access.length], [0, 2]);
  assert.equal(kept([ask('p1', later(0), 'h'), ask('p2', later(1_000), 'h')]).resend_prompt, 1);           // 10 (P0는 10/11 뒤)
  const FILE = '00000000aaaabbbbccccddddeeeeffff';
  result = kept([dto('f1', later(0), { contentType: 'file', fileId: FILE }), dto('f2', later(1_000), { contentType: 'file', fileId: FILE })]);   // 11
  assert.deepEqual([result.counted.length, result.resend_file], [2, 0]);
});

void test('SPEC 12 and 14: excluded rows and rows before the period do not start a fold', () => {
  // 12: 시연 문서 기록(제외) → 1초 뒤 같은 칸·같은 해시 질문 → 남음
  const result = kept([ask('d1', later(0), 'h', { detections: [hashDoc('DEMO_a')] }), ask('p1', later(1_000), 'h')]);
  assert.deepEqual(result.counted.map((e) => e.event_id), ['p1']);
  // 14: 기간 첫 기록과 기간 밖 직전 기록 간격 1초 → 첫 기록 남음(기간 안에서만 추적)
  const now = Date.parse(P0) + 24 * 3600_000;
  const stats = dashboardStats([ask('old', later(-1_000), 'h'), ask('first', later(500), 'h')], new URLSearchParams('period=24H'), now);
  assert.equal(stats.total, 1);
  assert.equal(stats.counting.resend_prompt, 0);
});

void test('overview counting reports file resends and prompt retries apart; the access rule is the reason code alone', () => {
  const now = Date.parse(P0) + 3600_000;
  const stats = dashboardStats([ask('p1', later(0), 'h'), ask('p2', later(2_000), 'h'), dto('x1', later(3_000), { ...access(), detections: [hashDoc('01_사업전략')], detectionOutcome: 'MATCH' })],
    new URLSearchParams('period=24H'), now);
  assert.deepEqual([stats.total, stats.counting.resend_folded, stats.counting.resend_file, stats.counting.resend_prompt, stats.counting.access_blocked], [1, 1, 0, 1, 1]);
  // 목록 기본 보기 = 카드
  const page = listEvents([ask('p1', later(0), 'h'), ask('p2', later(2_000), 'h')], new URLSearchParams('period=24H&group=request&scope=counted'), now);
  assert.deepEqual(page.items.map((e) => e.event_id), ['p1']);
  assert.deepEqual(page.view_totals, { counted: 1, access: 0, all: 2 });
});

void test('prompt hashes come from the decision log once per event (same SQL as the report) and are remembered', async () => {
  const calls = [];
  const pool = { async query(sql, params) { calls.push({ sql, params }); return { rows: params[0].filter((id) => id !== 'q-none').map((id) => ({ event_id: id, prompt_hash: `md5-${id}` })) }; } };
  const store = new PostgresEventStore({ pool });
  const events = [{ event_id: 'q1', request_id: 'r1', content_type: 'prompt' }, { event_id: 'q-none', request_id: 'r2', content_type: 'prompt' },
    { event_id: 'f1', request_id: 'r3', content_type: 'file' }, { event_id: 'q-old', content_type: 'prompt' }];
  assert.deepEqual([...await store.promptHashes(events)], [['q1', 'md5-q1']]);
  assert.ok(calls[0].sql.includes("md5(btrim(regexp_replace(max(x.prompt), '\\s+', ' ', 'g')))"), calls[0].sql);
  assert.ok(calls[0].sql.includes('count(*) = 1 AND bool_and(x.prompt IS NOT NULL)'));
  assert.deepEqual(calls[0].params, [['q1', 'q-none']]);              // 질문이고 요청 ID 있는 것만
  await store.promptHashes(events);
  assert.deepEqual(calls[1].params, [['q-none']]);                    // 해시가 생긴 것은 다시 묻지 않음, 없는 것만 다시
});

void test('the HTTP list leaves legacy and demo-document events out by default and counts them with test events', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'final-logic-http-'));
  const backend = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json') });
  await new Promise((resolve) => backend.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${backend.address().port}`;
  try {
    const recent = (seconds) => new Date(Date.now() - seconds * 1000).toISOString();
    for (const body of [canonical('evt-real', recent(60)), canonical('evt-legacy', recent(50), { clientId: 'legacy-gateway' }),
      canonical('evt-demo-doc', recent(40), { detections: [hashDoc('DEMO_반도체_공정_시연_20261003')] }), canonical('evt-access', recent(30), access())]) {
      const response = await fetch(`${base}/api/events/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(body) });
      assert.ok([200, 201, 202].includes(response.status), String(response.status));
    }
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const get = async (pathname) => (await fetch(`${base}${pathname}`, { headers: { Cookie: cookie } })).json();
    const list = await get('/api/events?period=24H&group=request&scope=counted');
    assert.deepEqual(list.items.map((e) => e.event_id), ['evt-real']);
    assert.equal(list.excluded_test, 2);
    assert.deepEqual(list.view_totals, { counted: 1, access: 1, all: 2 });
    assert.deepEqual((await get('/api/events?period=24H&group=request&scope=access')).items.map((e) => e.event_id), ['evt-access']);
    const stats = await get('/api/dashboard/stats?period=24H');
    assert.deepEqual([stats.total, stats.counting.access_blocked], [1, 1]);
    assert.equal((await get('/api/events?period=24H&include_test=1')).total, 4);
  } finally {
    await new Promise((resolve) => backend.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
