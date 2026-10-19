// 보호 문서 본문 보기(2026-10-13, 설계안 6.8 '보안' 행): 세션·열람 번호·응답 머리·엄격 감사·20 MiB·스위치·텍스트 가림.
// 문서 조회는 진짜 PostgresEventStore 코드를 가짜 풀(documents 한 표)로 돌린다. 감사는 JsonEventStore 파일에 남는다
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { attachmentDisposition, createAppServer, documentViewEnabled } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import { buildMatchEvidence } from '../match-evidence.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-docview@example.test',
  adminPassword: 'local-password-docview-tests',
  ingestToken: 'local-ingest-token-docview-tests',
};
const LIMIT = 20 * 1024 * 1024;
const TEXT_LIMIT = 2_000_000;
const PHONE = '010-1234-5678';
const ORIGINAL_MARK = 'ORIGINAL-BYTES-기밀-본문';
// 1쪽(1,800자) 안에 전화번호, 2쪽 이후에도 글자가 이어지는 본문
const LONG_TEXT = `담당자 직통 연락처는 ${PHONE}이며 회신은 이 번호로 받는다.\n${'협상 목표 수수료 22%와 최소보장 조건을 유지한다. '.repeat(140)}마지막 줄`;
const VIEW_ID = /^[A-Za-z0-9_-]{22}$/;
const pdfBytes = (body) => Buffer.from(`%PDF-1.7\n${body}\n%%EOF`);

function documentRows() {
  return new Map([
    ['plan-2026', { doc_id: 'plan-2026', filename: '협상 계획 2026.pdf', format: 'pdf', version: 2, status: 'active', index_status: 'indexed', original: pdfBytes(ORIGINAL_MARK), normalized_text: LONG_TEXT }],
    ['old-contract', { doc_id: 'old-contract', filename: 'old-contract.docx', format: 'docx', version: 1, status: 'retired', index_status: 'pending', original: Buffer.from('PK\u0003\u0004old docx'), normalized_text: null }],
    ['sheet', { doc_id: 'sheet', filename: 'sheet.xlsx', format: 'xlsx', version: 1, status: 'active', index_status: 'indexed', original: Buffer.from('PK\u0003\u0004xlsx'), normalized_text: '시트 글자' }],
    ['report', { doc_id: 'report', filename: 'report.hwp', format: 'hwp', version: 1, status: 'active', index_status: 'indexed', original: Buffer.from([0xd0, 0xcf, 0x11, 0xe0]), normalized_text: '한글' }],
    ['notes', { doc_id: 'notes', filename: 'notes.hwpx', format: 'HWPX', version: 1, status: 'active', index_status: 'error', original: Buffer.from('PK\u0003\u0004hwpx'), normalized_text: null }],
    ['looks-pdf', { doc_id: 'looks-pdf', filename: 'looks-pdf.pdf', format: 'hwp', version: 1, status: 'active', index_status: 'indexed', original: Buffer.from('%PDF-but-hwp'), normalized_text: '' }],
    ['legacy', { doc_id: 'legacy', filename: 'legacy.bin', format: null, version: 1, status: 'active', index_status: 'indexed', original: Buffer.from('legacy'), normalized_text: '옛 문서' }],
    ['huge', { doc_id: 'huge', filename: 'huge.pdf', format: 'pdf', version: 1, status: 'active', index_status: 'indexed', original: Buffer.alloc(LIMIT + 1, 0x41), normalized_text: '큰 문서' }],
    ['edge', { doc_id: 'edge', filename: 'edge.pdf', format: 'pdf', version: 1, status: 'active', index_status: 'indexed', original: Buffer.alloc(LIMIT, 0x42), normalized_text: '딱 20MiB' }],
    ['long-text', { doc_id: 'long-text', filename: 'long-text.pdf', format: 'pdf', version: 1, status: 'active', index_status: 'indexed', original: pdfBytes('x'), normalized_text: '가'.repeat(TEXT_LIMIT + 1) }],
    ['evil', { doc_id: 'evil', filename: 'evil"; x=1\r\nSet-Cookie: pwned=1\r\nX-Injected: yes\u202Efdp.exe', format: 'pdf', version: 1, status: 'active', index_status: 'indexed', original: pdfBytes('evil'), normalized_text: 'evil' }],
  ]);
}

// documents 표 하나를 흉내 내는 풀: 저장소가 보낸 SQL 모양대로(크기 상한·글자 수 상한 매개변수) 칸을 돌려준다
function documentPool(rows) {
  const calls = [];
  const pool = {
    async query(sql, params) {
      calls.push({ sql, params });
      assert.match(sql, /FROM documents WHERE doc_id = \$1/);
      const row = rows.get(params[0]);
      if (!row) return { rowCount: 0, rows: [] };
      const result = { doc_id: row.doc_id, filename: row.filename, format: row.format, version: row.version, status: row.status, index_status: row.index_status, size: row.original.length };
      if (/THEN original ELSE NULL END AS original/.test(sql)) result.original = row.original.length <= params[1] ? Buffer.from(row.original) : null;
      if (/AS normalized_text/.test(sql)) {
        const chars = typeof row.normalized_text === 'string' ? Array.from(row.normalized_text).length : null;
        result.text_chars = chars;
        result.normalized_text = chars !== null && chars <= params[1] ? row.normalized_text : null;
      }
      return { rowCount: 1, rows: [result] };
    },
  };
  return { pool, calls };
}

class ViewStore extends JsonEventStore {
  failAudit = null;
  #documents;
  constructor(file, documents) {
    super(file);
    this.#documents = documents;
  }
  getDocumentForView(id) { return this.#documents.getDocumentForView(id); }
  getDocumentOriginal(id, maxBytes) { return this.#documents.getDocumentOriginal(id, maxBytes); }
  getDocumentText(id, maxChars) { return this.#documents.getDocumentText(id, maxChars); }
  async recordAudit(record) {
    if (this.failAudit?.(record)) throw new Error('new row violates check constraint "dashboard_admin_activity_history_action_check"');
    return super.recordAudit(record);
  }
}

async function start(options = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-docview-'));
  const rows = documentRows();
  const { pool, calls } = documentPool(rows);
  const store = new ViewStore(path.join(root, 'events.json'), new PostgresEventStore({ pool }));
  const server = createAppServer({ ...CONFIG, store, ...options });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const login = async () => {
    const response = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    assert.equal(response.status, 200);
    return response.headers.get('set-cookie').split(';')[0];
  };
  const call = (method, pathname, { cookie, body, rawBody, headers = {} } = {}) => fetch(`${base}${pathname}`, {
    method,
    headers: { ...(cookie ? { Cookie: cookie } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : rawBody,
  });
  const open = async (cookie, id, body) => {
    const response = await call('POST', `/api/documents/${encodeURIComponent(id)}/views`, { cookie, body });
    return { status: response.status, json: await response.json() };
  };
  const original = (cookie, id, view, extra = '') => call('GET', `/api/documents/${encodeURIComponent(id)}/original${view === undefined ? '' : `?view=${encodeURIComponent(view)}`}${extra}`, { cookie });
  const text = (cookie, id, view, offset) => call('GET', `/api/documents/${encodeURIComponent(id)}/text?view=${encodeURIComponent(view)}${offset === undefined ? '' : `&offset=${offset}`}`, { cookie });
  const audits = async (action) => (await store.listAudit()).filter((row) => !action || row.action === action);
  const stop = async () => {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  };
  return { base, store, rows, calls, login, call, open, original, text, audits, stop };
}

afterEach(() => {
  delete process.env.EVIDENCE_SHOW_RAW;
  delete process.env.DASHBOARD_DOCUMENT_VIEW;
});

void test('every document view route needs a session (401) and accepts only its own method (405)', async () => {
  const app = await start();
  try {
    for (const cookie of [undefined, 'local_admin_session=not-a-session']) {
      assert.equal((await app.call('POST', '/api/documents/plan-2026/views', { cookie })).status, 401);
      assert.equal((await app.call('GET', '/api/documents/plan-2026/original?view=x', { cookie })).status, 401);
      assert.equal((await app.call('GET', '/api/documents/plan-2026/original?view=x&download=1', { cookie })).status, 401);
      assert.equal((await app.call('GET', '/api/documents/plan-2026/text?view=x', { cookie })).status, 401);
    }
    assert.equal(app.calls.length, 0, 'no document query before the session check');
    const cookie = await app.login();
    assert.equal((await app.call('GET', '/api/documents/plan-2026/views', { cookie })).status, 405);
    assert.equal((await app.call('POST', '/api/documents/plan-2026/original', { cookie })).status, 405);
    assert.equal((await app.call('DELETE', '/api/documents/plan-2026/text', { cookie })).status, 405);
    assert.deepEqual((await app.audits()).map((row) => row.action), ['ADMIN_LOGIN']);
  } finally {
    await app.stop();
  }
});

void test('opening a view records DOCUMENT_VIEW first and returns the view number; each open is one record', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const first = await app.open(cookie, 'plan-2026');
    assert.equal(first.status, 201);
    assert.deepEqual(Object.keys(first.json).sort(), ['document_id', 'document_name', 'expires_at', 'format', 'index_status', 'issued_at', 'mode', 'size', 'status', 'version', 'view_id', 'view_ref'].sort());
    assert.match(first.json.view_id, VIEW_ID);
    assert.match(first.json.view_ref, /^[0-9A-F]{8}$/);
    assert.deepEqual(
      { ...first.json, view_id: undefined, view_ref: undefined, issued_at: undefined, expires_at: undefined },
      { document_id: 'plan-2026', document_name: '협상 계획 2026.pdf', version: '2', format: 'pdf', size: pdfBytes(ORIGINAL_MARK).length, status: 'ACTIVE', index_status: 'READY', mode: 'original', view_id: undefined, view_ref: undefined, issued_at: undefined, expires_at: undefined },
    );
    assert.equal(Date.parse(first.json.expires_at) - Date.parse(first.json.issued_at), 28_800_000);
    // 열람 시작은 크기만 본다: 원본 바이트·텍스트를 읽는 조회가 없다
    assert.ok(app.calls.every(({ sql }) => !/THEN original/.test(sql) && !/normalized_text/.test(sql)));

    const second = await app.open(cookie, 'plan-2026', { mode: 'text' });
    assert.equal(second.status, 201);
    assert.notEqual(second.json.view_id, first.json.view_id);
    const rows = await app.audits('DOCUMENT_VIEW');
    assert.equal(rows.length, 2);
    for (const [row, opened, mode] of [[rows[0], first.json, 'original'], [rows[1], second.json, 'text']]) {
      assert.deepEqual(
        { admin_id: row.admin_id, target_type: row.target_type, target_id: row.target_id, result: row.result, changes: row.changes },
        { admin_id: 'local-admin', target_type: 'DOCUMENT', target_id: 'plan-2026', result: 'SUCCESS', changes: { version: '2', format: 'pdf', mode, view_ref: opened.view_ref } },
      );
      // 감사 값에 원문·열람 번호·세션 키가 없다
      const stored = JSON.stringify(row);
      for (const secret of [first.json.view_id, second.json.view_id, cookie.split('=')[1], ORIGINAL_MARK, PHONE, '협상 목표'])
        assert.equal(stored.includes(secret), false, secret);
    }

    // 잘못된 열람 시작 요청은 기록도 번호도 없다
    assert.equal((await app.open(cookie, 'plan-2026', { mode: 'print' })).status, 422);
    assert.equal((await app.open(cookie, 'plan-2026', { mode: 'text', extra: 1 })).status, 400);
    assert.equal((await app.call('POST', '/api/documents/plan-2026/views', { cookie, rawBody: 'mode=text', headers: { 'Content-Type': 'text/plain' } })).status, 415);
    assert.equal((await app.call('POST', '/api/documents/plan-2026/views', { cookie, rawBody: '{', headers: { 'Content-Type': 'application/json' } })).status, 400);
    assert.equal((await app.open(cookie, 'no-such-document')).status, 404);
    assert.equal((await app.call('POST', '/api/documents/%E0%A4%A/views', { cookie })).status, 400);
    assert.equal((await app.audits('DOCUMENT_VIEW')).length, 2);
  } finally {
    await app.stop();
  }
});

void test('original and text need a view from the same session for the same document, before it expires (403)', async () => {
  const app = await start({ documentViewTtlMs: 300 });
  try {
    const cookie = await app.login();
    const other = await app.login();
    const plan = (await app.open(cookie, 'plan-2026')).json.view_id;
    const sheet = (await app.open(cookie, 'sheet')).json.view_id;
    const forbidden = async (response) => {
      assert.equal(response.status, 403);
      assert.match(response.headers.get('content-type'), /^application\/json/);
      const body = await response.json();
      assert.equal(body.error.code, 'VIEW_FORBIDDEN');
      assert.equal(JSON.stringify(body).includes(ORIGINAL_MARK), false);
    };
    const before = app.calls.length;
    await forbidden(await app.original(cookie, 'plan-2026', undefined));                       // 번호 없음
    await forbidden(await app.original(cookie, 'plan-2026', ''));
    await forbidden(await app.original(cookie, 'plan-2026', 'not a view'));                   // 모양이 틀림
    await forbidden(await app.original(cookie, 'plan-2026', 'A'.repeat(22)));                 // 발급하지 않은 번호
    await forbidden(await app.original(other, 'plan-2026', plan));                            // 다른 세션
    await forbidden(await app.original(cookie, 'sheet', plan));                               // 다른 문서
    await forbidden(await app.original(cookie, 'no-such-document', plan));
    await forbidden(await app.text(other, 'plan-2026', plan));
    await forbidden(await app.text(cookie, 'sheet', plan));
    assert.equal(app.calls.length, before, 'no document read without a valid view');
    assert.equal((await app.original(cookie, 'plan-2026', plan)).status, 200);
    assert.equal((await app.original(cookie, 'sheet', sheet)).status, 200);

    // 만료
    await new Promise((resolve) => setTimeout(resolve, 350));
    await forbidden(await app.original(cookie, 'plan-2026', plan));
    await forbidden(await app.text(cookie, 'plan-2026', plan));

    // 로그아웃하면 그 세션의 번호도 끝난다(다시 로그인해도 새 세션이라 못 쓴다)
    const fresh = (await app.open(cookie, 'plan-2026')).json.view_id;
    assert.equal((await app.original(cookie, 'plan-2026', fresh)).status, 200);
    assert.equal((await app.call('POST', '/api/auth/logout', { cookie })).status, 204);
    assert.equal((await app.original(cookie, 'plan-2026', fresh)).status, 401);
    await forbidden(await app.original(await app.login(), 'plan-2026', fresh));
  } finally {
    await app.stop();
  }
});

void test('the original carries all eight response headers, the exact bytes and a Content-Type from the stored format', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const { view_id: view } = (await app.open(cookie, 'plan-2026')).json;
    const response = await app.original(cookie, 'plan-2026', view);
    assert.equal(response.status, 200);
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.deepEqual(bytes, pdfBytes(ORIGINAL_MARK));
    const headers = Object.fromEntries(['content-type', 'content-disposition', 'content-security-policy', 'x-content-type-options', 'cache-control', 'cross-origin-resource-policy', 'content-length', 'x-document-version'].map((name) => [name, response.headers.get(name)]));
    assert.deepEqual(headers, {
      'content-type': 'application/pdf',
      'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent('협상 계획 2026.pdf')}`,
      'content-security-policy': 'sandbox',
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
      'cross-origin-resource-policy': 'same-origin',
      'content-length': String(bytes.length),
      'x-document-version': '2',
    });
    // 보기만 할 때는 열람 시작 기록 1건뿐(원본을 여러 번 받아도 늘지 않음)
    assert.equal((await app.original(cookie, 'plan-2026', view)).status, 200);
    assert.deepEqual((await app.audits()).map((row) => row.action), ['ADMIN_LOGIN', 'DOCUMENT_VIEW']);

    const typeOf = async (id) => {
      const opened = await app.open(cookie, id);
      const result = await app.original(cookie, id, opened.json.view_id);
      assert.equal(result.status, 200, id);
      return [opened.json.format, result.headers.get('content-type')];
    };
    assert.deepEqual(await typeOf('old-contract'), ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']);
    assert.deepEqual(await typeOf('sheet'), ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']);
    assert.deepEqual(await typeOf('report'), ['hwp', 'application/octet-stream']);
    assert.deepEqual(await typeOf('notes'), ['hwpx', 'application/octet-stream']);
    assert.deepEqual(await typeOf('looks-pdf'), ['hwp', 'application/octet-stream']);   // 파일 이름(.pdf)을 믿지 않는다
    assert.deepEqual(await typeOf('legacy'), [null, 'application/octet-stream']);
  } finally {
    await app.stop();
  }
});

// 원본 내려받기는 2026-10-13 화면에서 뺐다: download=1은 404, 원본을 읽지 않고 DOCUMENT_DOWNLOAD 기록도 남기지 않는다
void test('download=1 is gone: 404 without reading the original or writing a DOCUMENT_DOWNLOAD record', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const opened = (await app.open(cookie, 'plan-2026')).json;
    const reads = () => app.calls.filter(({ sql }) => /THEN original/.test(sql)).length;
    const before = reads();
    const response = await app.original(cookie, 'plan-2026', opened.view_id, '&download=1');
    assert.equal(response.status, 404);
    assert.match(response.headers.get('content-type'), /^application\/json/);
    assert.equal(response.headers.get('content-disposition'), null);
    const body = Buffer.from(await response.arrayBuffer());
    assert.equal(body.includes(Buffer.from(ORIGINAL_MARK)), false);
    assert.equal(body.includes(Buffer.from('%PDF-')), false);
    assert.equal(JSON.parse(body.toString('utf8')).error.code, 'NOT_FOUND');
    assert.equal(reads(), before, 'the original was not read for a download');
    const rows = await app.audits();
    assert.deepEqual(rows.map((row) => row.action), ['ADMIN_LOGIN', 'DOCUMENT_VIEW']);
    for (const secret of [opened.view_id, cookie.split('=')[1], ORIGINAL_MARK, PHONE])
      assert.equal(JSON.stringify(rows).includes(secret), false, secret);
    // 다른 값(download=0 등)은 보기로 다룬다(그리기용 원본은 그대로): 기록이 늘지 않는다
    assert.equal((await app.original(cookie, 'plan-2026', opened.view_id, '&download=0')).status, 200);
    assert.equal((await app.original(cookie, 'plan-2026', opened.view_id)).status, 200);
    assert.equal((await app.audits('DOCUMENT_DOWNLOAD')).length, 0);
  } finally {
    await app.stop();
  }
});

void test('an audit failure refuses the view with 403 and sends no original bytes', async () => {
  const app = await start();
  const errors = [];
  const originalError = console.error;
  console.error = (...args) => errors.push(args.join(' '));
  try {
    const cookie = await app.login();
    app.store.failAudit = (record) => record.action === 'DOCUMENT_VIEW';
    const refused = await app.open(cookie, 'plan-2026');
    assert.equal(refused.status, 403);
    assert.equal(refused.json.error.code, 'AUDIT_REQUIRED');
    assert.equal('view_id' in refused.json, false);
    assert.equal((await app.audits('DOCUMENT_VIEW')).length, 0);
    assert.ok(app.calls.every(({ sql }) => !/THEN original/.test(sql)), 'the original was never read');
    assert.ok(errors.some((line) => /Document view audit write failed/.test(line)));

    // (내려받기 기록 실패 경우는 내려받기를 뺀 2026-10-13에 함께 뺐다 — download=1은 이제 기록 없이 404)
    app.store.failAudit = () => false;
    const opened = (await app.open(cookie, 'plan-2026')).json;
    // 열람 시작은 기록됐으므로 보기는 된다
    assert.equal((await app.original(cookie, 'plan-2026', opened.view_id)).status, 200);
  } finally {
    console.error = originalError;
    await app.stop();
  }
});

void test('an original over 20 MiB is refused with 413 and its bytes are never read; exactly 20 MiB is served', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const huge = (await app.open(cookie, 'huge')).json;
    assert.equal(huge.size, LIMIT + 1);
    const refused = await app.original(cookie, 'huge', huge.view_id);
    assert.equal(refused.status, 413);
    assert.equal((await refused.json()).error.code, 'PAYLOAD_TOO_LARGE');
    const read = app.calls.find(({ sql, params }) => /THEN original/.test(sql) && params[0] === 'huge');
    assert.equal(read.params[1], LIMIT);
    const edge = (await app.open(cookie, 'edge')).json;
    const served = await app.original(cookie, 'edge', edge.view_id);
    assert.equal(served.status, 200);
    assert.equal(served.headers.get('content-length'), String(LIMIT));
    assert.equal((await served.arrayBuffer()).byteLength, LIMIT);
  } finally {
    await app.stop();
  }
});

void test('a retired document can still be viewed; its text waits for the indexer', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const opened = await app.open(cookie, 'old-contract');
    assert.equal(opened.status, 201);
    assert.equal(opened.json.status, 'INACTIVE');
    assert.equal(opened.json.index_status, 'PROCESSING');
    assert.equal((await app.original(cookie, 'old-contract', opened.json.view_id)).status, 200);
    const text = await app.text(cookie, 'old-contract', opened.json.view_id);
    assert.equal(text.status, 200);
    assert.deepEqual(await text.json(), {
      document_id: 'old-contract', version: '1', index_status: 'PROCESSING', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', redaction: 'APPLIED',
      page: { status: 'NOT_RECORDED', side: 'document', document_id: 'old-contract' },
    });
    const failed = await app.open(cookie, 'notes');
    assert.equal(failed.json.index_status, 'FAILED');
  } finally {
    await app.stop();
  }
});

void test('text pages follow the evidence page rules: 1,800 characters, the same redaction and EVIDENCE_SHOW_RAW', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const { view_id: view } = (await app.open(cookie, 'plan-2026', { mode: 'text' })).json;
    const page = async (offset) => {
      const response = await app.text(cookie, 'plan-2026', view, offset);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      return response.json();
    };
    const total = Array.from(LONG_TEXT).length;
    const first = await page();
    assert.deepEqual(Object.keys(first), ['document_id', 'version', 'index_status', 'coordinate_system', 'redaction', 'page']);
    assert.deepEqual([first.version, first.index_status, first.redaction], ['2', 'READY', 'APPLIED']);
    assert.deepEqual(
      { ...first.page, segments: undefined },
      { status: 'AVAILABLE', side: 'document', document_id: 'plan-2026', char_start: 0, char_end: 1800, total_chars: total, page_size: 1800, content_source: 'CURRENT_PROTECTED_DOCUMENT', segments: undefined },
    );
    const shown = first.page.segments.map((segment) => segment.text).join('');
    assert.equal(Array.from(shown).length, 1800);
    assert.equal(shown.includes(PHONE), false);
    assert.ok(first.page.segments.some((segment) => segment.redacted && /^█+$/.test(segment.text)));
    assert.ok(first.page.segments.every((segment) => segment.matched === false));

    // 이벤트 근거 화면이 같은 문서를 보여 주는 글자·가림과 같다(같은 documentPage·redactEvidence)
    const evidencePage = (offset) => buildMatchEvidence(
      { event_id: 'e', request_id: 'r', occurred_at: '2026-10-13T00:00:00Z', detection_outcome: 'MATCH', final_action: 'BLOCK',
        detections: [{ detector: 'WINDOW_HASH', matched_document_id: 'plan-2026', score: 1, input_location: { char_start: 0, char_end: 40 }, matched_location: { char_start: 0, char_end: 40 } }] },
      [{ request_id: 'r', decided_by: 'windowhash', doc_id: 'plan-2026', input_span: '0-40', doc_span: '0-40', prompt: LONG_TEXT, prompt_kept: true, prompt_chars: total, reason: 'r' }],
      [{ doc_id: 'plan-2026', filename: 'f', normalized_text: LONG_TEXT, normalized_chars: total }],
      { side: 'document', offset, documentId: 'plan-2026' },
    ).page;
    const flat = (segments) => segments.flatMap((segment) => Array.from(segment.text, (ch) => `${ch}${segment.redacted ? 1 : 0}`)).join('');
    for (const offset of [0, 1800]) {
      const ours = offset ? await page(offset) : first;
      const theirs = evidencePage(offset);
      assert.equal(ours.page.char_start, theirs.char_start);
      assert.equal(ours.page.total_chars, theirs.total_chars);
      assert.equal(flat(ours.page.segments), flat(theirs.segments));
    }
    // 끝을 넘는 offset은 마지막 쪽, 잘못된 offset은 400(근거 API와 같은 검사)
    assert.equal((await page(TEXT_LIMIT)).page.char_start, Math.floor((total - 1) / 1800) * 1800);
    for (const bad of ['abc', '-1', '1.5', '12345678', String(TEXT_LIMIT + 1)])
      assert.equal((await app.text(cookie, 'plan-2026', view, bad)).status, 400, bad);

    process.env.EVIDENCE_SHOW_RAW = '1';
    const raw = await page();
    assert.equal(raw.redaction, 'OFF');
    assert.equal(raw.page.segments.map((segment) => segment.text).join(''), Array.from(LONG_TEXT).slice(0, 1800).join(''));
    assert.ok(raw.page.segments.every((segment) => segment.redacted === false));
    delete process.env.EVIDENCE_SHOW_RAW;

    // 근거 화면과 같은 글자 수 상한: 넘으면 TOO_LARGE(텍스트를 읽어 오지 않음)
    const long = (await app.open(cookie, 'long-text')).json.view_id;
    const tooLarge = await (await app.text(cookie, 'long-text', long)).json();
    assert.deepEqual(tooLarge.page, { status: 'TOO_LARGE', side: 'document', document_id: 'long-text' });
    const textRead = app.calls.find(({ sql, params }) => /AS normalized_text/.test(sql) && params[0] === 'long-text');
    assert.equal(textRead.params[1], TEXT_LIMIT);
  } finally {
    await app.stop();
  }
});

void test('a version registered while viewing is refused with 409 until the document is opened again', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const old = (await app.open(cookie, 'plan-2026')).json;
    app.rows.get('plan-2026').version = 3;
    app.rows.get('plan-2026').original = pdfBytes('새 판');
    const changed = await app.original(cookie, 'plan-2026', old.view_id);
    assert.equal(changed.status, 409);
    assert.deepEqual((await changed.json()).error, { code: 'DOCUMENT_VERSION_CHANGED', message: 'A new version of the document was registered. Open it again.', details: { view_version: '2', current_version: '3' } });
    assert.equal((await app.text(cookie, 'plan-2026', old.view_id)).status, 409);
    assert.equal((await app.original(cookie, 'plan-2026', old.view_id, '&download=1')).status, 404);   // 내려받기는 경로 없음(2026-10-13)
    assert.equal((await app.audits('DOCUMENT_DOWNLOAD')).length, 0);
    const reopened = (await app.open(cookie, 'plan-2026')).json;
    assert.equal(reopened.version, '3');
    const response = await app.original(cookie, 'plan-2026', reopened.view_id);
    assert.equal(response.headers.get('x-document-version'), '3');
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), pdfBytes('새 판'));
    assert.deepEqual((await app.audits('DOCUMENT_VIEW')).map((row) => row.changes.version), ['2', '3']);
  } finally {
    await app.stop();
  }
});

void test('filenames cannot inject response headers', async () => {
  const app = await start();
  try {
    const cookie = await app.login();
    const { view_id: view } = (await app.open(cookie, 'evil')).json;
    const response = await app.original(cookie, 'evil', view);   // 그리기용 원본 응답도 같은 이름 머리를 쓴다(내려받기는 2026-10-13 404)
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('x-injected'), null);
    const disposition = response.headers.get('content-disposition');
    assert.match(disposition, /^attachment; filename\*=UTF-8''[A-Za-z0-9%!._~-]+$/);
    assert.equal(decodeURIComponent(disposition.slice("attachment; filename*=UTF-8''".length)), 'evil"; x=1Set-Cookie: pwned=1X-Injected: yesfdp.exe');
  } finally {
    await app.stop();
  }
  // 함수 단위: 따옴표·세미콜론·괄호는 인코딩, 경로·제어·방향 문자는 제거, 빈 이름은 형식으로 대신, 200자 제한, 깨진 서로게이트도 안전
  assert.equal(attachmentDisposition('a"b;c\'(d)*.pdf', 'pdf'), "attachment; filename*=UTF-8''a%22b%3Bc%27%28d%29%2A.pdf");
  assert.equal(attachmentDisposition('..\\..//etc/passwd\u0000\u2028', 'pdf'), "attachment; filename*=UTF-8''....etcpasswd");
  assert.equal(attachmentDisposition('\r\n\t ', 'xlsx'), "attachment; filename*=UTF-8''document.xlsx");
  assert.equal(attachmentDisposition('', null), "attachment; filename*=UTF-8''document");
  assert.equal(decodeURIComponent(attachmentDisposition(`${'가'.repeat(300)}.pdf`, 'pdf').split("''")[1]), '가'.repeat(200));
  assert.match(attachmentDisposition('broken\uD800name.pdf', 'pdf'), /^attachment; filename\*=UTF-8''broken%EF%BF%BDname\.pdf$/);
});

void test('DASHBOARD_DOCUMENT_VIEW=off removes the routes (404); empty or on keeps them; any other value stops the start', async () => {
  for (const value of ['off', ' OFF ']) {
    process.env.DASHBOARD_DOCUMENT_VIEW = value;
    const app = await start();
    try {
      const cookie = await app.login();
      for (const [method, pathname, withCookie] of [
        ['POST', '/api/documents/plan-2026/views', cookie],
        ['POST', '/api/documents/plan-2026/views', undefined],
        ['GET', '/api/documents/plan-2026/original?view=x', cookie],
        ['GET', '/api/documents/plan-2026/original?view=x&download=1', cookie],
        ['GET', '/api/documents/plan-2026/text?view=x', cookie],
      ]) {
        const response = await app.call(method, pathname, { cookie: withCookie });
        assert.equal(response.status, 404, `${value} ${method} ${pathname}`);
        assert.equal((await response.json()).error.message, 'Route not found.');
      }
      assert.equal((await app.call('GET', '/api/documents', { cookie })).status, 200, 'the document list stays');
      assert.equal(app.calls.length, 0);
      assert.equal((await app.audits('DOCUMENT_VIEW')).length, 0);
    } finally {
      await app.stop();
    }
  }
  // 생성 인자로도 끌 수 있다(값은 환경 변수와 같은 규칙)
  const off = await start({ documentView: 'off' });
  try {
    assert.equal((await off.call('POST', '/api/documents/plan-2026/views', { cookie: await off.login() })).status, 404);
  } finally {
    await off.stop();
  }
  for (const value of [undefined, '', 'on', ' On ']) assert.equal(documentViewEnabled(value), true, String(value));
  for (const value of ['false', '0', 'no', 'disabled']) {
    assert.throws(() => documentViewEnabled(value), /DASHBOARD_DOCUMENT_VIEW/);
    process.env.DASHBOARD_DOCUMENT_VIEW = value;
    assert.throws(() => createAppServer({ ...CONFIG, storePath: 'unused.json' }), /DASHBOARD_DOCUMENT_VIEW/);
  }
});

void test('view numbers are bounded in memory: the oldest is dropped first', async () => {
  const app = await start({ documentViewLimit: 2 });
  try {
    const cookie = await app.login();
    const views = [];
    for (let index = 0; index < 3; index++) views.push((await app.open(cookie, 'plan-2026')).json.view_id);
    assert.equal((await app.original(cookie, 'plan-2026', views[0])).status, 403);
    assert.equal((await app.original(cookie, 'plan-2026', views[1])).status, 200);
    assert.equal((await app.original(cookie, 'plan-2026', views[2])).status, 200);
    assert.equal((await app.audits('DOCUMENT_VIEW')).length, 3);   // 버린 번호도 열람 기록은 남아 있다
  } finally {
    await app.stop();
  }
  assert.throws(() => createAppServer({ ...CONFIG, storePath: 'unused.json', documentViewLimit: 0 }), /positive integers/);
  assert.throws(() => createAppServer({ ...CONFIG, storePath: 'unused.json', documentViewTtlMs: -1 }), /positive integers/);
});

void test('the local JSON store has no documents, so a view is 404', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-docview-json-'));
  const server = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json') });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const response = await fetch(`${base}/api/documents/plan-2026/views`, { method: 'POST', headers: { Cookie: cookie } });
    assert.equal(response.status, 404);
    const store = new JsonEventStore(path.join(root, 'events.json'));
    assert.deepEqual([await store.getDocumentForView('x'), await store.getDocumentOriginal('x', LIMIT), await store.getDocumentText('x', TEXT_LIMIT)], [null, null, null]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

void test('PostgreSQL: only getDocumentOriginal selects the original bytes, size-guarded and with bound parameters', async () => {
  const seen = [];
  const pool = { async query(sql, params) { seen.push({ sql, params }); return { rowCount: 0, rows: [] }; } };
  const store = new PostgresEventStore({ pool });
  const id = "x'; DROP TABLE documents; --";
  assert.equal(await store.getDocumentForView(id), null);
  assert.equal(await store.getDocumentText(id, TEXT_LIMIT), null);
  assert.equal(await store.getDocumentOriginal(id, LIMIT), null);
  await store.listDocuments();
  const [view, text, original, list] = seen;
  for (const { sql } of seen) assert.equal(sql.includes('DROP TABLE'), false);
  assert.deepEqual(view.params, [id]);
  assert.deepEqual(text.params, [id, TEXT_LIMIT]);
  assert.deepEqual(original.params, [id, LIMIT]);
  const selectsOriginal = (sql) => sql.replace(/octet_length\(original\)/g, '').includes('original');
  assert.equal(selectsOriginal(view.sql), false);
  assert.equal(selectsOriginal(text.sql), false);
  assert.equal(selectsOriginal(list.sql), false);
  assert.match(original.sql, /CASE WHEN octet_length\(original\) <= \$2 THEN original ELSE NULL END AS original/);
  assert.match(text.sql, /CASE WHEN length\(normalized_text\) <= \$2 THEN normalized_text ELSE NULL END AS normalized_text/);
});
