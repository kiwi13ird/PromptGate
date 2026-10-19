import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createAppServer } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-edge@example.test',
  adminPassword: 'local-password-edge-tests',
  ingestToken: 'local-ingest-token-edge-tests',
};

function eventFixture(eventId, timestamp = new Date().toISOString()) {
  return {
    type: 'SECURITY_EVENT',
    eventId,
    requestId: `req-${eventId}`,
    timestamp,
    clientId: 'client-local-edge-test',
    targetLlm: 'ChatGPT',
    contentType: 'prompt',
    detectionOutcome: 'MATCH',
    recommendedAction: 'BLOCK',
    finalAction: 'BLOCK',
    severity: 'HIGH',
    enforcement: { applied: true, httpStatus: 403 },
    degraded: false,
    detections: [
      {
        detector: 'WINDOW_HASH',
        matchType: 'TEXT_FRAGMENT',
        score: 0.82,
        scoreKind: 'COVERAGE',
        matchedDocumentId: 'DOC-LOCAL-EDGE',
        documentSpan: { charStart: 10, charEnd: 30 },
        action: 'BLOCK',
        recommendedAction: 'BLOCK',
      },
    ],
  };
}

async function startBackend(storePath) {
  const server = createAppServer({ ...CONFIG, storePath });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

async function stopBackend(server) {
  await new Promise((resolve) => server.close(resolve));
}

async function request(baseUrl, pathname, options = {}) {
  const headers = { ...options.headers };
  let body = options.rawBody;
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(options.body);
  }
  const response = await fetch(`${baseUrl}${pathname}`, {
    method: options.method,
    headers,
    body,
  });
  const payload = response.status === 204 ? null : await response.json();
  return { response, payload };
}

async function login(baseUrl) {
  const result = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    body: {
      identifier: CONFIG.adminEmail,
      password: CONFIG.adminPassword,
    },
  });
  assert.equal(result.response.status, 200);
  return result.response.headers.get('set-cookie').split(';')[0];
}

async function ingest(baseUrl, event) {
  return request(baseUrl, '/api/events/ingest', {
    method: 'POST',
    headers: { Authorization: `Bearer ${CONFIG.ingestToken}` },
    body: event,
  });
}

void test('an actual Backend restart retains an ingested event', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-restart-'));
  const storePath = path.join(root, 'data', 'events.json');
  let running;
  try {
    running = await startBackend(storePath);
    const created = await ingest(
      running.baseUrl,
      eventFixture('evt-local-test-backend-restart'),
    );
    assert.equal(created.response.status, 201);
    await stopBackend(running.server);
    running = null;

    running = await startBackend(storePath);
    const cookie = await login(running.baseUrl);
    const detail = await request(
      running.baseUrl,
      '/api/events/evt-local-test-backend-restart',
      { headers: { Cookie: cookie } },
    );
    assert.equal(detail.response.status, 200);
    assert.equal(detail.payload.event_id, 'evt-local-test-backend-restart');
  } finally {
    if (running) await stopBackend(running.server);
    await rm(root, { recursive: true, force: true });
  }
});

void test('pagination, empty results, large pages, sort and invalid limits follow the DTO contract', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-pagination-'));
  const running = await startBackend(path.join(root, 'events.json'));
  try {
    const cookie = await login(running.baseUrl);
    const authenticated = { headers: { Cookie: cookie } };
    const empty = await request(
      running.baseUrl,
      '/api/events?period=24H&page=1&page_size=20',
      authenticated,
    );
    assert.deepEqual(empty.payload, {
      items: [],
      total: 0,
      page: 1,
      page_size: 20,
      total_pages: 1,
    });

    await Promise.all(
      Array.from({ length: 21 }, (_, index) =>
        ingest(
          running.baseUrl,
          eventFixture(
            `evt-page-${String(index).padStart(2, '0')}`,
            new Date(Date.now() - index * 1000).toISOString(),
          ),
        ),
      ),
    );
    const firstPage = await request(
      running.baseUrl,
      '/api/events?period=24H&page=1&page_size=20&sort=OCCURRED_AT_DESC',
      authenticated,
    );
    assert.equal(firstPage.payload.total, 21);
    assert.equal(firstPage.payload.items.length, 20);
    assert.equal(firstPage.payload.total_pages, 2);
    assert.equal(firstPage.payload.items[0].event_id, 'evt-page-00');

    const secondPage = await request(
      running.baseUrl,
      '/api/events?period=24H&page=2&page_size=20',
      authenticated,
    );
    assert.equal(secondPage.payload.items.length, 1);
    const clampedPage = await request(
      running.baseUrl,
      '/api/events?period=24H&page=999&page_size=20',
      authenticated,
    );
    assert.equal(clampedPage.payload.page, 2);
    assert.equal(clampedPage.payload.items.length, 1);

    const ascending = await request(
      running.baseUrl,
      '/api/events?period=24H&page=1&page_size=20&sort=OCCURRED_AT_ASC',
      authenticated,
    );
    assert.equal(ascending.payload.items[0].event_id, 'evt-page-20');
    const filteredEmpty = await request(
      running.baseUrl,
      '/api/events?period=24H&detector=SIGNATURE',
      authenticated,
    );
    assert.equal(filteredEmpty.payload.total, 0);
    assert.equal(filteredEmpty.payload.page, 1);
    assert.equal(filteredEmpty.payload.total_pages, 1);

    for (const invalidSize of ['0', '101']) {
      const invalid = await request(
        running.baseUrl,
        `/api/events?page_size=${invalidSize}`,
        authenticated,
      );
      assert.equal(invalid.response.status, 400);
      assert.equal(invalid.payload.error.code, 'BAD_REQUEST');
    }
  } finally {
    await stopBackend(running.server);
    await rm(root, { recursive: true, force: true });
  }
});

void test('timezone offsets sort by instant rather than timestamp text', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-timezone-'));
  const running = await startBackend(path.join(root, 'events.json'));
  try {
    const older = new Date(Date.now() - 2000);
    const offsetTimestamp = new Date(older.getTime() + 9 * 60 * 60 * 1000)
      .toISOString()
      .replace('Z', '+09:00');
    await ingest(
      running.baseUrl,
      eventFixture('evt-timezone-older-offset', offsetTimestamp),
    );
    await ingest(
      running.baseUrl,
      eventFixture('evt-timezone-newer-z', new Date(Date.now() - 1000).toISOString()),
    );
    const cookie = await login(running.baseUrl);
    const ascending = await request(
      running.baseUrl,
      '/api/events?period=24H&sort=OCCURRED_AT_ASC',
      { headers: { Cookie: cookie } },
    );
    assert.deepEqual(
      ascending.payload.items.map((event) => event.event_id),
      ['evt-timezone-older-offset', 'evt-timezone-newer-z'],
    );
  } finally {
    await stopBackend(running.server);
    await rm(root, { recursive: true, force: true });
  }
});

void test('health and common HTTP errors use stable metadata-only responses', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-errors-'));
  const running = await startBackend(path.join(root, 'events.json'));
  try {
    const health = await request(running.baseUrl, '/health');
    assert.deepEqual(health.payload, { status: 'ok' });

    const unsupported = await request(running.baseUrl, '/api/events/ingest', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${CONFIG.ingestToken}`,
        'Content-Type': 'text/plain',
      },
      rawBody: '{}',
    });
    assert.equal(unsupported.response.status, 415);
    assert.equal(unsupported.payload.error.code, 'UNSUPPORTED_MEDIA_TYPE');

    const tooLarge = await request(running.baseUrl, '/api/events/ingest', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${CONFIG.ingestToken}`,
        'Content-Type': 'application/json',
      },
      rawBody: JSON.stringify({ padding: 'x'.repeat(300_000) }),
    });
    assert.equal(tooLarge.response.status, 413);
    assert.equal(tooLarge.payload.error.code, 'PAYLOAD_TOO_LARGE');

    const validation = await ingest(running.baseUrl, {
      ...eventFixture('evt-invalid-field'),
      rawPrompt: 'must-not-be-returned-or-stored',
    });
    assert.equal(validation.response.status, 422);
    assert.equal(validation.payload.error.code, 'VALIDATION');
    assert.equal(
      JSON.stringify(validation.payload).includes('must-not-be-returned-or-stored'),
      false,
    );
  } finally {
    await stopBackend(running.server);
    await rm(root, { recursive: true, force: true });
  }
});

void test('corrupt persistence returns a generic 500 without leaking file contents', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-corrupt-'));
  const storePath = path.join(root, 'events.json');
  await writeFile(storePath, '{private-corrupt-content', 'utf8');
  const running = await startBackend(storePath);
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    const cookie = await login(running.baseUrl);
    const result = await request(running.baseUrl, '/api/events', {
      headers: { Cookie: cookie },
    });
    assert.equal(result.response.status, 500);
    assert.deepEqual(result.payload, {
      error: { code: 'SERVER', message: 'Internal server error.' },
    });
  } finally {
    console.error = originalConsoleError;
    await stopBackend(running.server);
    await rm(root, { recursive: true, force: true });
  }
});

void test('local startup configuration fails fast and never provides credentials by default', () => {
  assert.throws(
    () =>
      createAppServer({
        storePath: 'unused.json',
        allowedOrigin: CONFIG.allowedOrigin,
        adminPassword: CONFIG.adminPassword,
        ingestToken: CONFIG.ingestToken,
      }),
    /LOCAL_ADMIN_EMAIL/,
  );
  assert.throws(
    () =>
      createAppServer({
        storePath: 'unused.json',
        allowedOrigin: CONFIG.allowedOrigin,
        adminEmail: CONFIG.adminEmail,
        ingestToken: CONFIG.ingestToken,
      }),
    /LOCAL_ADMIN_PASSWORD/,
  );
  assert.throws(
    () =>
      createAppServer({
        storePath: 'unused.json',
        allowedOrigin: CONFIG.allowedOrigin,
        adminEmail: CONFIG.adminEmail,
        adminPassword: CONFIG.adminPassword,
      }),
    /EVENT_INGEST_TOKEN/,
  );
});

// 2026-10-10 Gateway 처리 설정 저장(PUT)도 브라우저 사전 요청에서 허용한다
void test('CORS preflight allows PUT', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-preflight-'));
  const running = await startBackend(path.join(root, 'events.json'));
  try {
    const response = await fetch(`${running.baseUrl}/api/gateway-settings`, {
      method: 'OPTIONS',
      headers: { Origin: CONFIG.allowedOrigin, 'Access-Control-Request-Method': 'PUT' },
    });
    assert.equal(response.status, 204);
    assert.deepEqual(response.headers.get('access-control-allow-methods').split(/,\s*/), ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS']);
    assert.equal(response.headers.get('access-control-allow-origin'), CONFIG.allowedOrigin);
  } finally {
    await stopBackend(running.server);
    await rm(root, { recursive: true, force: true });
  }
});

// 2026-10-10 보호 문서 등록 20 MiB: 백엔드는 파일 20 MiB까지 받고 1바이트라도 넘으면 413(nginx는 별도로 21m)
void test('document registration accepts exactly 20 MiB and rejects one byte more', async () => {
  class UploadStore extends JsonEventStore {
    sizes = [];
    async registerDocument({ filename, data }) {
      this.sizes.push(data.length);
      return { outcome: 'created', document: { document_id: 'local-large', document_name: filename, version: '1' } };
    }
  }
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-upload-'));
  const store = new UploadStore(path.join(root, 'events.json'));
  const server = createAppServer({ ...CONFIG, store });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const cookie = await login(baseUrl);
    const upload = (size) => {
      const form = new FormData();
      form.append('file', new Blob([Buffer.alloc(size, 0x41)]), 'local-large.pdf');
      return fetch(`${baseUrl}/api/documents`, { method: 'POST', headers: { Cookie: cookie }, body: form });
    };
    const limit = 20 * 1024 * 1024;
    const accepted = await upload(limit);
    assert.equal(accepted.status, 201);
    assert.deepEqual(store.sizes, [limit]);
    const rejected = await upload(limit + 1);
    assert.equal(rejected.status, 413);
    assert.equal((await rejected.json()).error.code, 'PAYLOAD_TOO_LARGE');
    assert.deepEqual(store.sizes, [limit]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
