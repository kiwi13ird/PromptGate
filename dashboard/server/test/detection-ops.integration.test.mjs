// 리포트·키워드 승인(HITL) 경로 - 가짜 Detection 관리 API를 붙여 대시보드 백엔드가 올바로 넘기는지 본다.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createAppServer } from '../app.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-ops@example.test',
  adminPassword: 'local-password-ops-tests',
  ingestToken: 'local-ingest-token-ops-tests',
};
const REPORT_ID = 'report_2026-09-15_2026-09-30_20261004T000000';
const DOC_ID = '13_파트너사협상자료';
// 2026-10-12 설계 v2: 목록 응답에 전역 내용 경향 스위치(content_trend_enabled)와 새 상태 칸이 붙는다. 대시보드 서버는 그대로 넘겨야 한다
const REPORT_LIST = {
  reports: [{
    report_id: REPORT_ID, status: 'done', from: '2026-09-15', to: '2026-09-30', compare_from: '2026-08-30', compare_to: '2026-09-14',
    mode: 'partial', llm_lines: 41, llm_dropped: 3, content_trend: false, content_trend_state: 'off_global',
    incidents: { total: 62, narrated: 12, by_grade: { '1': 11, '2': 5, '3': 7, '4': 4, '5': 35 } }, users_high: 2, gpu_auto_stop: null, blind: false,
  }],
  content_trend_enabled: false,
};

function startFakeDetection({ reloadFails = false, gpuConnected = true, gpuBusy = false, reportBusy = false } = {}) {
  const calls = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    const url = new URL(req.url, 'http://fake');
    calls.push({
      method: req.method,
      path: decodeURIComponent(url.pathname),
      query: url.search,
      adminId: req.headers['x-admin-id'] ?? null,
      body: raw ? JSON.parse(raw) : undefined,
    });
    const json = (status, payload) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    };
    const p = decodeURIComponent(url.pathname);
    if (req.method === 'GET' && p === '/admin/reports') return json(200, REPORT_LIST);
    if (req.method === 'POST' && p === '/admin/reports') return reportBusy
      ? json(409, { detail: { code: 'REPORT_BUSY', message: 'Another report is being generated.' } })
      : json(202, { report_id: REPORT_ID, status: 'running' });
    if (req.method === 'GET' && p === `/admin/reports/${REPORT_ID}/file`) {
      const download = url.searchParams.get('download') === '1';
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `${download ? 'attachment' : 'inline'}; filename="${REPORT_ID}.html"`,
      });
      return res.end('<!doctype html><title>리포트</title><script>1</script>');
    }
    if (req.method === 'GET' && p === '/admin/keywords') return json(200, { keywords: [{ id: 1, keyword: 'NeoBoard', doc_id: DOC_ID, status: 'pending' }] });
    if (req.method === 'POST' && p === '/admin/keywords') {
      const body = JSON.parse(raw);
      return json(201, { id: 2, keyword: body.keyword, doc_id: body.doc_id, status: body.approve ? 'approved' : 'pending' });
    }
    if (req.method === 'PATCH' && p === '/admin/keywords/1') return json(200, { id: 1, keyword: JSON.parse(raw).keyword.trim(), doc_id: DOC_ID, status: 'pending', doc_hits: null, neg_hits: null });
    if (req.method === 'PATCH' && p === '/admin/keywords/2') return json(409, { detail: { code: 'NOT_PENDING', message: 'Only pending keywords can be edited.' } });
    if (req.method === 'POST' && p === '/admin/keywords/1/approve') return json(200, { id: 1, keyword: 'NeoBoard', doc_id: DOC_ID, status: 'approved', reload_required: true });
    if (req.method === 'DELETE' && p === '/admin/keywords/1') { res.writeHead(204); return res.end(); }
    if (req.method === 'POST' && p === '/admin/reload-signatures') {
      return reloadFails ? json(500, { detail: { code: 'RELOAD_FAILED', message: 'reload failed' } }) : json(200, { status: 'ok' });
    }
    if (req.method === 'GET' && p === '/admin/gpu') return json(200, gpuConnected
      ? { connected: true, models: ['qwen3-8b'], latency_ms: 6, error: null, checked_at: '2026-10-06T12:00:00+00:00' }
      : { connected: false, models: [], latency_ms: null, error: 'URLError', checked_at: '2026-10-06T12:00:00+00:00' });
    if (req.method === 'POST' && p === '/admin/gpu/start') return json(200, { instance_id: 'i-0gpu', previous_state: 'stopped', instance_state: 'pending' });
    if (req.method === 'POST' && p === '/admin/gpu/stop') return gpuBusy
      ? json(409, { detail: { code: 'GPU_BUSY', message: 'GPU is in use: report.' } })
      : json(200, { instance_id: 'i-0gpu', previous_state: 'running', instance_state: 'stopping' });
    if (req.method === 'GET' && p === '/admin/keyword-jobs') return json(200, { jobs: [], counts: { queued: 0, running: 0, done: 1, failed: 0 } });
    if (req.method === 'POST' && p === `/admin/documents/${DOC_ID}/extract-keywords`) return json(202, { id: 5, doc_id: DOC_ID, status: 'queued' });
    if (req.method === 'POST' && p === '/admin/documents/없는문서/extract-keywords') return json(404, { detail: { code: 'DOC_NOT_FOUND', message: 'Document is not indexed.' } });
    if (req.method === 'POST' && p === '/admin/keyword-jobs/5/retry') return json(200, { id: 5, status: 'queued' });
    return json(404, { detail: { code: 'FAKE_NOT_FOUND', message: `${req.method} ${p}` } });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, calls, baseUrl: `http://127.0.0.1:${server.address().port}` }));
  });
}

async function startBackend(policyBaseUrl) {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-ops-'));
  const storePath = path.join(root, 'data', 'events.json');
  const server = createAppServer({ ...CONFIG, storePath, policyBaseUrl });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, root, storePath, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

const close = (server) => new Promise((resolve) => server.close(resolve));

async function request(baseUrl, pathname, { method = 'GET', body, cookie } = {}) {
  const headers = {};
  if (cookie) headers.Cookie = cookie;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${baseUrl}${pathname}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const type = response.headers.get('content-type') ?? '';
  const payload = type.includes('application/json') ? await response.json() : await response.text();
  return { response, payload };
}

async function login(baseUrl) {
  const { response } = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    body: { identifier: CONFIG.adminEmail, password: CONFIG.adminPassword },
  });
  assert.equal(response.status, 200);
  return response.headers.get('set-cookie').split(';')[0];
}

async function withServers(options, run) {
  const detection = await startFakeDetection(options);
  const backend = await startBackend(detection.baseUrl);
  try {
    await run({ detection, backend, cookie: await login(backend.baseUrl) });
  } finally {
    await close(backend.server);
    await close(detection.server);
    await rm(backend.root, { recursive: true, force: true });
  }
}

void test('every report and keyword route requires a session', async () => {
  await withServers({}, async ({ backend, detection }) => {
    const routes = [
      ['GET', '/api/reports'], ['POST', '/api/reports'],
      ['GET', `/api/reports/${REPORT_ID}/file`], ['GET', '/api/keywords'], ['POST', '/api/keywords'],
      ['POST', '/api/keywords/1/approve'], ['POST', '/api/keywords/1/reject'], ['GET', '/api/keyword-jobs'],
      ['POST', `/api/documents/${encodeURIComponent(DOC_ID)}/extract-keywords`], ['POST', '/api/keyword-jobs/5/retry'], ['GET', '/api/system/gpu'], ['PATCH', '/api/keywords/1'],
      ['POST', '/api/system/gpu/start'], ['POST', '/api/system/gpu/stop'],
    ];
    for (const [method, pathname] of routes) {
      const { response } = await request(backend.baseUrl, pathname, { method });
      assert.equal(response.status, 401, `${method} ${pathname}`);
    }
    assert.equal(detection.calls.length, 0);
  });
});

void test('report create validates dates and forwards the period with the admin id', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const bad = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body: { from: '9/15', to: '2026-09-30' } });
    assert.equal(bad.response.status, 400);
    const extra = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body: { from: '2026-09-15', to: '2026-09-30', x: 1 } });
    assert.equal(extra.response.status, 400);
    const ok = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body: { from: '2026-09-15', to: '2026-09-30', use_llm: true } });
    assert.equal(ok.response.status, 202);
    assert.equal(ok.payload.report_id, REPORT_ID);
    const sent = detection.calls.find((c) => c.method === 'POST' && c.path === '/admin/reports');
    assert.deepEqual(sent.body, { from: '2026-09-15', to: '2026-09-30', use_llm: true });
    assert.equal(sent.adminId, 'local-admin');
    const audit = JSON.parse(await readFile(backend.storePath, 'utf8')).auditRecords.find((r) => r.action === 'REPORT_CREATE');
    assert.equal(audit.target_id, REPORT_ID);
  });
});

void test('report create accepts content_trend and blind_pair as strict booleans and passes them through untouched', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const bodies = [
      { from: '2026-09-15', to: '2026-09-30', use_llm: true, content_trend: true },
      { from: '2026-09-15', to: '2026-09-30', use_llm: true, content_trend: false, blind_pair: true },
      { from: '2026-09-15', to: '2026-09-30', content_trend: null },
      { from: '2026-09-15', to: '2026-09-30', use_llm: false, blind_pair: false },
    ];
    for (const body of bodies) {
      const { response } = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body });
      assert.equal(response.status, 202, JSON.stringify(body));
    }
    const sent = detection.calls.filter((c) => c.method === 'POST' && c.path === '/admin/reports').map((c) => c.body);
    assert.deepEqual(sent, bodies);
    // 필드를 안 보내면 Detection에도 안 보낸다(옛 Detection이 모르는 칸을 받지 않게)
    const plain = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body: { from: '2026-09-15', to: '2026-09-30', use_llm: true } });
    assert.equal(plain.response.status, 202);
    assert.deepEqual(detection.calls.filter((c) => c.method === 'POST' && c.path === '/admin/reports').at(-1).body, { from: '2026-09-15', to: '2026-09-30', use_llm: true });
  });
});

void test('report create rejects content_trend and blind_pair that are not booleans before reaching Detection', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const period = { from: '2026-09-15', to: '2026-09-30' };
    const bad = [
      { ...period, content_trend: 'true' },
      { ...period, content_trend: 1 },
      { ...period, content_trend: 0 },
      { ...period, content_trend: 'on' },
      { ...period, content_trend: [] },
      { ...period, content_trend: {} },
      { ...period, blind_pair: 'true' },
      { ...period, blind_pair: 1 },
      { ...period, blind_pair: null },   // blind_pair는 null 없이 불린만(Detection StrictBool)
    ];
    for (const body of bad) {
      const { response, payload } = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body });
      assert.equal(response.status, 400, JSON.stringify(body));
      assert.equal(payload.error.code, 'VALIDATION', JSON.stringify(body));
    }
    // 모르는 칸은 지금처럼 거부(설계 지시문의 옛 이름 content_tendency는 환경변수에만 있고 API 칸이 아니다)
    for (const body of [{ ...period, content_tendency: true }, { ...period, blindPair: true }, { ...period, contentTrend: true }]) {
      const { response } = await request(backend.baseUrl, '/api/reports', { method: 'POST', cookie, body });
      assert.equal(response.status, 400, JSON.stringify(body));
    }
    assert.equal(detection.calls.length, 0);
    const audit = JSON.parse(await readFile(backend.storePath, 'utf8')).auditRecords ?? [];
    assert.equal(audit.some((r) => r.action === 'REPORT_CREATE'), false);
  });
});

void test('report create audit keeps the same record shape when the new fields are sent', async () => {
  await withServers({}, async ({ backend, cookie }) => {
    const { response } = await request(backend.baseUrl, '/api/reports', {
      method: 'POST', cookie, body: { from: '2026-09-15', to: '2026-09-30', use_llm: true, content_trend: true, blind_pair: true },
    });
    assert.equal(response.status, 202);
    const rows = JSON.parse(await readFile(backend.storePath, 'utf8')).auditRecords.filter((r) => r.action === 'REPORT_CREATE');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].target_id, REPORT_ID);
    assert.deepEqual(rows[0].changes, { from: '2026-09-15', to: '2026-09-30', use_llm: true });
  });
});

void test('report create keeps Detection errors (409 busy) readable', async () => {
  await withServers({ reportBusy: true }, async ({ backend, cookie }) => {
    const { response, payload } = await request(backend.baseUrl, '/api/reports', {
      method: 'POST', cookie, body: { from: '2026-09-15', to: '2026-09-30', use_llm: true, content_trend: true },
    });
    assert.equal(response.status, 409);
    assert.equal(payload.error.code, 'REPORT_BUSY');
  });
});

void test('report list passes through and a bare report id is not a route', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    assert.equal((await request(backend.baseUrl, '/api/reports', { cookie })).payload.reports.length, 1);
    for (const id of [REPORT_ID, 'report_missing']) {
      const bare = await request(backend.baseUrl, `/api/reports/${id}`, { cookie });
      assert.equal(bare.response.status, 404, id);
      assert.equal(bare.payload.error.code, 'NOT_FOUND', id);
    }
    assert.equal(detection.calls.some((call) => call.path.startsWith('/admin/reports/')), false);
  });
});

void test('report list passes the global content trend switch and the new status fields through unchanged', async () => {
  await withServers({}, async ({ backend, cookie }) => {
    const { response, payload } = await request(backend.baseUrl, '/api/reports', { cookie });
    assert.equal(response.status, 200);
    assert.deepEqual(payload, REPORT_LIST);
    assert.equal(payload.content_trend_enabled, false);
  });
});

void test('report file is sandboxed html, inline by default and attachment on download=1', async () => {
  await withServers({}, async ({ backend, cookie }) => {
    const inline = await request(backend.baseUrl, `/api/reports/${REPORT_ID}/file`, { cookie });
    assert.equal(inline.response.status, 200);
    assert.match(inline.response.headers.get('content-type'), /^text\/html/);
    assert.match(inline.response.headers.get('content-disposition'), /^inline/);
    assert.equal(inline.response.headers.get('content-security-policy'), 'sandbox allow-scripts');
    assert.match(inline.payload, /<title>리포트<\/title>/);
    const download = await request(backend.baseUrl, `/api/reports/${REPORT_ID}/file?download=1`, { cookie });
    assert.match(download.response.headers.get('content-disposition'), /^attachment/);
  });
});

void test('report ids with path tricks are rejected before reaching Detection', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    for (const id of ['..%2F..%2Fetc', 'a%20b', '%E0%A4%A']) {
      const { response } = await request(backend.baseUrl, `/api/reports/${id}/file`, { cookie });
      assert.equal(response.status, 400, id);
    }
    assert.equal(detection.calls.length, 0);
  });
});

void test('keyword list forwards a valid status filter and rejects unknown ones', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const listed = await request(backend.baseUrl, '/api/keywords?status=pending', { cookie });
    assert.equal(listed.payload.keywords[0].keyword, 'NeoBoard');
    assert.equal(detection.calls.at(-1).query, '?status=pending');
    const bad = await request(backend.baseUrl, '/api/keywords?status=deleted', { cookie });
    assert.equal(bad.response.status, 400);
  });
});

void test('approve and reject apply the change to detection right away', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const approved = await request(backend.baseUrl, '/api/keywords/1/approve', { method: 'POST', cookie });
    assert.equal(approved.response.status, 200);
    assert.equal(approved.payload.status, 'approved');
    assert.equal(approved.payload.applied, true);
    const order = detection.calls.map((c) => `${c.method} ${c.path}`);
    assert.deepEqual(order, ['POST /admin/keywords/1/approve', 'POST /admin/reload-signatures']);
    const rejected = await request(backend.baseUrl, '/api/keywords/1/reject', { method: 'POST', cookie });
    assert.equal(rejected.response.status, 200);
    assert.deepEqual(rejected.payload, { id: 1, rejected: true, applied: true });
    assert.deepEqual(detection.calls.slice(2).map((c) => `${c.method} ${c.path}`), ['DELETE /admin/keywords/1', 'POST /admin/reload-signatures']);
  });
});

void test('a failed reload keeps the approval and reports applied=false', async () => {
  await withServers({ reloadFails: true }, async ({ backend, cookie }) => {
    const approved = await request(backend.baseUrl, '/api/keywords/1/approve', { method: 'POST', cookie });
    assert.equal(approved.response.status, 200);
    assert.equal(approved.payload.applied, false);
    assert.equal(approved.payload.apply_error, 'reload failed');
  });
});

void test('manual keyword: pending stays unapplied, approved is applied', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const pending = await request(backend.baseUrl, '/api/keywords', { method: 'POST', cookie, body: { keyword: 'PRJ-2026-07', doc_id: DOC_ID } });
    assert.equal(pending.response.status, 201);
    assert.equal(pending.payload.applied, false);
    assert.equal(detection.calls.filter((c) => c.path === '/admin/reload-signatures').length, 0);
    const approved = await request(backend.baseUrl, '/api/keywords', { method: 'POST', cookie, body: { keyword: 'NeoBoard', doc_id: DOC_ID, approve: true } });
    assert.equal(approved.payload.applied, true);
    const bad = await request(backend.baseUrl, '/api/keywords', { method: 'POST', cookie, body: { keyword: '', doc_id: DOC_ID } });
    assert.equal(bad.response.status, 400);
  });
});

void test('extraction jobs: request by document, list, retry and unknown document', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const queued = await request(backend.baseUrl, `/api/documents/${encodeURIComponent(DOC_ID)}/extract-keywords`, { method: 'POST', cookie });
    assert.equal(queued.response.status, 202);
    assert.equal(queued.payload.id, 5);
    assert.equal(detection.calls.at(-1).path, `/admin/documents/${DOC_ID}/extract-keywords`);
    const jobs = await request(backend.baseUrl, '/api/keyword-jobs?status=done', { cookie });
    assert.equal(jobs.payload.counts.done, 1);
    const retried = await request(backend.baseUrl, '/api/keyword-jobs/5/retry', { method: 'POST', cookie });
    assert.equal(retried.payload.status, 'queued');
    const missing = await request(backend.baseUrl, `/api/documents/${encodeURIComponent('없는문서')}/extract-keywords`, { method: 'POST', cookie });
    assert.equal(missing.response.status, 404);
    assert.equal(missing.payload.error.code, 'DOC_NOT_FOUND');
  });
});

void test('unsupported methods return 405 and an unreachable Detection returns 503', async () => {
  await withServers({}, async ({ backend, cookie }) => {
    const wrong = await request(backend.baseUrl, '/api/keywords/1/approve', { method: 'GET', cookie });
    assert.equal(wrong.response.status, 405);
  });
  const backend = await startBackend('http://127.0.0.1:9');
  try {
    const cookie = await login(backend.baseUrl);
    const down = await request(backend.baseUrl, '/api/reports', { cookie });
    assert.equal(down.response.status, 503);
  } finally {
    await close(backend.server);
    await rm(backend.root, { recursive: true, force: true });
  }
});

void test('existing document status route is not shadowed', async () => {
  await withServers({}, async ({ backend, cookie }) => {
    const { response } = await request(backend.baseUrl, `/api/documents/${encodeURIComponent(DOC_ID)}/status`, { method: 'PATCH', cookie, body: { status: 'ACTIVE' } });
    assert.notEqual(response.status, 405);
  });
});

void test('gpu status is forwarded from Detection read-only', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const up = await request(backend.baseUrl, '/api/system/gpu', { cookie });
    assert.equal(up.response.status, 200);
    assert.deepEqual(up.payload, { connected: true, models: ['qwen3-8b'], latency_ms: 6, error: null, checked_at: '2026-10-06T12:00:00+00:00' });
    const gpuCalls = detection.calls.filter((call) => call.path === '/admin/gpu');
    assert.equal(gpuCalls.length, 1);
    assert.equal(gpuCalls[0].method, 'GET');
    const post = await request(backend.baseUrl, '/api/system/gpu', { method: 'POST', cookie });
    assert.equal(post.response.status, 405);
  });
  await withServers({ gpuConnected: false }, async ({ backend, cookie }) => {
    const down = await request(backend.baseUrl, '/api/system/gpu', { cookie });
    assert.equal(down.response.status, 200);
    assert.equal(down.payload.connected, false);
    assert.equal(down.payload.error, 'URLError');
  });
});

void test('gpu start and stop are forwarded and audited with the state change', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    const started = await request(backend.baseUrl, '/api/system/gpu/start', { method: 'POST', cookie });
    assert.equal(started.response.status, 200);
    assert.deepEqual(started.payload, { instance_id: 'i-0gpu', previous_state: 'stopped', instance_state: 'pending' });
    const stopped = await request(backend.baseUrl, '/api/system/gpu/stop', { method: 'POST', cookie });
    assert.equal(stopped.response.status, 200);
    const controls = detection.calls.filter((call) => call.path.startsWith('/admin/gpu/'));
    assert.deepEqual(controls.map((call) => [call.method, call.path, call.adminId]),
      [['POST', '/admin/gpu/start', 'local-admin'], ['POST', '/admin/gpu/stop', 'local-admin']]);
    const audit = JSON.parse(await readFile(backend.storePath, 'utf8')).auditRecords.filter((r) => r.target_type === 'GPU');
    assert.deepEqual(audit.map((r) => [r.action, r.target_id, r.result, r.changes]), [
      ['GPU_START', 'i-0gpu', 'SUCCESS', { previous_instance_state: 'stopped', new_instance_state: 'pending' }],
      ['GPU_STOP', 'i-0gpu', 'SUCCESS', { previous_instance_state: 'running', new_instance_state: 'stopping' }],
    ]);
    for (const [method, pathname, status] of [['GET', '/api/system/gpu/start', 405], ['POST', '/api/system/gpu/reboot', 404]]) {
      const { response } = await request(backend.baseUrl, pathname, { method, cookie });
      assert.equal(response.status, status, `${method} ${pathname}`);
    }
  });
});

void test('gpu stop refused by Detection keeps its code and leaves no audit row', async () => {
  await withServers({ gpuBusy: true }, async ({ backend, cookie }) => {
    const { response, payload } = await request(backend.baseUrl, '/api/system/gpu/stop', { method: 'POST', cookie });
    assert.equal(response.status, 409);
    assert.equal(payload.error.code, 'GPU_BUSY');
    const audit = JSON.parse(await readFile(backend.storePath, 'utf8')).auditRecords ?? [];
    assert.equal(audit.filter((r) => r.target_type === 'GPU').length, 0);
  });
});

void test('gpu status is 503 when Detection does not answer', async () => {
  const backend = await startBackend('http://127.0.0.1:9');
  try {
    const cookie = await login(backend.baseUrl);
    const { response, payload } = await request(backend.baseUrl, '/api/system/gpu', { cookie });
    assert.equal(response.status, 503);
    assert.equal(payload.error.code, 'POLICY_UPSTREAM_UNAVAILABLE');
  } finally {
    await close(backend.server);
    await rm(backend.root, { recursive: true, force: true });
  }
});

void test('pending keyword edit validates the body and forwards it without reloading detection', async () => {
  await withServers({}, async ({ backend, detection, cookie }) => {
    for (const body of [{}, { keyword: '' }, { keyword: '   ' }, { keyword: 3 }, { keyword: 'TBS', doc_id: 'x' }]) {
      const bad = await request(backend.baseUrl, '/api/keywords/1', { method: 'PATCH', cookie, body });
      assert.equal(bad.response.status, 400, JSON.stringify(body));
    }
    assert.equal(detection.calls.length, 0);
    const ok = await request(backend.baseUrl, '/api/keywords/1', { method: 'PATCH', cookie, body: { keyword: ' 24억원 ' } });
    assert.equal(ok.response.status, 200);
    assert.equal(ok.payload.keyword, '24억원');
    const forwarded = detection.calls.filter((call) => call.path === '/admin/keywords/1');
    assert.equal(forwarded.length, 1);
    assert.equal(forwarded[0].method, 'PATCH');
    assert.equal(forwarded[0].adminId, 'local-admin');
    assert.deepEqual(forwarded[0].body, { keyword: ' 24억원 ' });
    assert.equal(detection.calls.some((call) => call.path === '/admin/reload-signatures'), false);
    const approved = await request(backend.baseUrl, '/api/keywords/2', { method: 'PATCH', cookie, body: { keyword: 'SPK' } });
    assert.equal(approved.response.status, 409);
    const get = await request(backend.baseUrl, '/api/keywords/1', { cookie });
    assert.equal(get.response.status, 405);
  });
});
