import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { createAppServer } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';

const ADMIN_EMAIL = 'local-admin@example.test';
const ADMIN_PASSWORD = 'local-password-for-tests';
const INGEST_TOKEN = 'local-ingest-token-for-tests';
const TEST_TIMESTAMP = new Date().toISOString();
let root;
let storePath;
let server;
let baseUrl;
let sessionCookie;

function localWindowHashEvent(overrides = {}) {
  return {
    type: 'SECURITY_EVENT',
    eventId: 'evt-local-test-integration',
    requestId: 'req-local-test-integration',
    timestamp: TEST_TIMESTAMP,
    clientId: 'client-local-test',
    targetLlm: 'ChatGPT',
    contentType: 'prompt',
    detectionOutcome: 'MATCH',
    recommendedAction: 'BLOCK',
    finalAction: 'BLOCK',
    severity: 'HIGH',
    enforcement: { applied: true, httpStatus: 403 },
    processingMs: 142,
    degraded: false,
    detections: [
      {
        detector: 'WINDOW_HASH',
        matchType: 'TEXT_FRAGMENT',
        score: 0.82,
        scoreKind: 'COVERAGE',
        threshold: null,
        matchedDocumentId: 'DOC-LOCAL-001',
        inputSpan: { charStart: 120, charEnd: 340, endExclusive: true },
        documentSpan: { charStart: 840, charEnd: 1060, endExclusive: true },
        action: 'BLOCK',
        recommendedAction: 'BLOCK',
      },
    ],
    ...overrides,
  };
}

async function jsonRequest(pathname, options = {}) {
  const headers = { ...options.headers };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${baseUrl}${pathname}`, {
    ...options,
    headers,
    body:
      options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const body = response.status === 204 ? null : await response.json();
  return { response, body };
}

before(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'llm-dashboard-events-'));
  storePath = path.join(root, 'events.json');
  server = createAppServer({
    storePath,
    allowedOrigin: 'http://127.0.0.1:4173',
    adminEmail: ADMIN_EMAIL,
    adminPassword: ADMIN_PASSWORD,
    ingestToken: INGEST_TOKEN,
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
  const login = await jsonRequest('/api/auth/login', {
    method: 'POST',
    body: { identifier: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  });
  assert.equal(login.response.status, 200);
  sessionCookie = login.response.headers.get('set-cookie').split(';')[0];
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await rm(root, { recursive: true, force: true });
});

void test('ingest, list and detail preserve detector, score and enforcement metadata', async () => {
  const event = localWindowHashEvent();
  const ingest = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
    body: event,
  });
  assert.equal(ingest.response.status, 201);
  assert.equal(ingest.body.created, true);
  assert.equal(ingest.body.event.status, 'NEW');
  assert.deepEqual(ingest.body.event.admin_notes, []);
  assert.deepEqual(ingest.body.event.timeline, []);
  assert.equal(ingest.body.event.detections[0].detector, 'WINDOW_HASH');
  assert.equal(ingest.body.event.detections[0].score_kind, 'COVERAGE');
  assert.equal(ingest.body.event.detections[0].score, 0.82);
  assert.deepEqual(ingest.body.event.enforcement, {
    applied: true,
    http_status: 403,
  });

  const list = await jsonRequest(
    '/api/events?period=30D&detector=WINDOW_HASH&score_kind=COVERAGE&page=1&page_size=20',
    { headers: { Cookie: sessionCookie } },
  );
  assert.equal(list.response.status, 200);
  assert.equal(list.body.total, 1);
  assert.equal(list.body.items[0].event_id, event.eventId);

  const detail = await jsonRequest(
    `/api/events/${encodeURIComponent(event.eventId)}`,
    { headers: { Cookie: sessionCookie } },
  );
  assert.equal(detail.response.status, 200);
  assert.equal(detail.body.event_id, event.eventId);
  assert.deepEqual(detail.body.detections[0].input_location, {
    char_start: 120,
    char_end: 340,
  });
  assert.deepEqual(detail.body.detections[0].matched_location, {
    char_start: 840,
    char_end: 1060,
  });
});

void test('same event id is idempotent, while changed content conflicts', async () => {
  const event = localWindowHashEvent();
  const retry = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
    body: event,
  });
  assert.equal(retry.response.status, 200);
  assert.equal(retry.body.created, false);

  const changedScore = structuredClone(event);
  changedScore.detections[0].score = 0.83;
  const conflict = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
    body: changedScore,
  });
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, 'EVENT_ID_CONFLICT');

  const list = await jsonRequest('/api/events?period=30D', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(list.body.total, 1);
});

void test('overview, investigation mutations and administrator activity use persisted events', async () => {
  const eventId = 'evt-local-test-integration';
  const status = await jsonRequest(
    `/api/events/${encodeURIComponent(eventId)}/status`,
    {
      method: 'PATCH',
      headers: { Cookie: sessionCookie },
      body: { status: 'INVESTIGATING' },
    },
  );
  assert.equal(status.response.status, 200);
  assert.equal(status.body.status, 'INVESTIGATING');

  const assigned = await jsonRequest(
    `/api/events/${encodeURIComponent(eventId)}/assignee`,
    {
      method: 'PATCH',
      headers: { Cookie: sessionCookie },
      body: { assignee: 'local-admin' },
    },
  );
  assert.equal(assigned.response.status, 200);
  assert.equal(assigned.body.assignee, 'local-admin');

  const noted = await jsonRequest(
    `/api/events/${encodeURIComponent(eventId)}/notes`,
    {
      method: 'POST',
      headers: { Cookie: sessionCookie },
      body: { content: 'Metadata-only investigation note.' },
    },
  );
  assert.equal(noted.response.status, 200);
  assert.equal(noted.body.admin_notes.length, 1);
  assert.equal(noted.body.timeline.length, 3);

  const audit = await jsonRequest('/api/audit-logs?period=30D&page=1&page_size=20', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(audit.response.status, 200);
  assert.equal(audit.body.total, 3);
  assert.deepEqual(
    new Set(audit.body.items.map((item) => item.action)),
    new Set(['EVENT_STATUS_CHANGED', 'EVENT_ASSIGNED', 'EVENT_NOTE_ADDED']),
  );

  const overview = await jsonRequest('/api/dashboard/stats?period=30D', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(overview.response.status, 200);
  assert.equal(overview.body.block >= 1, true);
  assert.equal(overview.body.total >= overview.body.block, true);
  assert.equal(
    overview.body.insights.llm_actions.some((item) => item.key === 'ChatGPT'),
    true,
  );

  const trafficSummary = await jsonRequest('/api/traffic/summary?period=30D', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(trafficSummary.response.status, 200);
  assert.equal(trafficSummary.body.active_clients >= 1, true);
  assert.equal(trafficSummary.body.average_latency_ms, 142);

  const trafficRecent = await jsonRequest('/api/traffic/recent?period=30D&limit=10', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(trafficRecent.response.status, 200);
  assert.equal(trafficRecent.body[0].detector, 'WINDOW_HASH');
  assert.equal(trafficRecent.body[0].score_kind, 'COVERAGE');
  assert.equal(trafficRecent.body[0].action, 'BLOCK');

  const timeSeries = await jsonRequest('/api/traffic/timeseries?period=30D', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(timeSeries.response.status, 200);
  assert.equal(timeSeries.body.some((bucket) => bucket.block_count >= 1), true);

  const documents = await jsonRequest('/api/documents', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(documents.response.status, 200);
  assert.deepEqual(documents.body, []);

  const policies = await jsonRequest('/api/policies', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(policies.response.status, 501);
  assert.equal(policies.body.error.code, 'POLICY_INTEGRATION_UNAVAILABLE');
});

void test('canonical validation makes JSON field order irrelevant to idempotency', async () => {
  const event = localWindowHashEvent({
    eventId: 'evt-local-test-reordered-fields',
    requestId: 'req-local-test-reordered-fields',
  });
  const first = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
    body: event,
  });
  assert.equal(first.response.status, 201);

  const reorderedDetection = Object.fromEntries(
    Object.entries(event.detections[0]).reverse(),
  );
  const reordered = Object.fromEntries(
    Object.entries({ ...event, detections: [reorderedDetection] }).reverse(),
  );
  const retry = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
    body: reordered,
  });
  assert.equal(retry.response.status, 200);
  assert.equal(retry.body.created, false);

  const list = await jsonRequest(
    '/api/events?period=30D&query=evt-local-test-reordered-fields',
    { headers: { Cookie: sessionCookie } },
  );
  assert.equal(list.body.total, 1);
});

void test('invalid detector combinations and sensitive raw fields are rejected', async () => {
  const invalidCombination = localWindowHashEvent({
    eventId: 'evt-local-test-invalid-combination',
  });
  invalidCombination.detections[0].scoreKind = 'SIMILARITY';
  const invalid = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
    body: invalidCombination,
  });
  assert.equal(invalid.response.status, 422);
  assert.equal(invalid.body.error.details.path, 'body.detections[0].scoreKind');

  const forbiddenFields = {
    rawPrompt: 'raw-prompt-must-not-persist',
    authorization: 'Bearer local-secret-must-not-persist',
    cookie: 'session=local-secret-must-not-persist',
    credential: 'credential-must-not-persist',
    phoneNumber: '010-1234-5678',
    emailAddress: 'sensitive-person@example.test',
    sha256: 'digest-must-not-persist',
    minHashSignature: 'signature-must-not-persist',
    internalFingerprint: 'fingerprint-must-not-persist',
    embeddingVector: [0.1, 0.2, 0.3],
  };
  for (const [field, value] of Object.entries(forbiddenFields)) {
    const sensitive = await jsonRequest('/api/events/ingest', {
      method: 'POST',
      headers: { Authorization: `Bearer ${INGEST_TOKEN}` },
      body: {
        ...localWindowHashEvent({
          eventId: `evt-local-test-sensitive-${field}`,
        }),
        [field]: value,
      },
    });
    assert.equal(sensitive.response.status, 422);
    assert.equal(sensitive.body.error.details.path, `body.${field}`);
  }
  const stored = await readFile(storePath, 'utf8');
  for (const value of Object.values(forbiddenFields))
    assert.equal(stored.includes(JSON.stringify(value)), false);
});

void test('event store survives a new store instance and missing details return 404', async () => {
  const restartedStore = new JsonEventStore(storePath);
  const persisted = await restartedStore.get('evt-local-test-integration');
  assert.equal(persisted.event_id, 'evt-local-test-integration');

  const missing = await jsonRequest('/api/events/does-not-exist', {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(missing.response.status, 404);
});

void test('event APIs require the expected authentication boundary', async () => {
  const list = await jsonRequest('/api/events');
  assert.equal(list.response.status, 401);
  const ingest = await jsonRequest('/api/events/ingest', {
    method: 'POST',
    body: localWindowHashEvent({ eventId: 'evt-local-test-no-token' }),
  });
  assert.equal(ingest.response.status, 401);
});
