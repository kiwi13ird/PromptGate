// 보호 문서 본문 보기의 진짜 SQL을 메모리 PostgreSQL(PGlite)로 확인: 감사 작업 2개 제약 목록(재적용·올리기),
// documents 표에서 판·크기·원본 바이트(bytea)·정규화 텍스트 읽기, 이관 전 DB에서 열람이 막히는지(기록 실패 = 열람 불가).
// 운영 서버에는 PGlite가 없으므로(개발 PC 전용) 설치되어 있지 않으면 건너뛴다. 설치 위치가 다르면 PGLITE_MODULE.
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createAppServer } from '../app.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

let PGlite = null;
try {
  ({ PGlite } = await import(process.env.PGLITE_MODULE ? pathToFileURL(process.env.PGLITE_MODULE).href : '@electric-sql/pglite'));
} catch {
  PGlite = null;
}
const skip = PGlite ? false : '@electric-sql/pglite is not installed (set PGLITE_MODULE to run)';

const directory = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const migrationFiles = (await readdir(directory)).filter((name) => /^\d+.*\.sql$/.test(name)).sort();
const readMigration = (name) => readFile(path.join(directory, name), 'utf8');
const applyAll = async (db, replace = {}) => {
  for (const name of migrationFiles) await db.exec(replace[name] ?? (await readMigration(name)));
};
const NEW_ACTIONS = ['DOCUMENT_VIEW', 'DOCUMENT_DOWNLOAD'];
const LIMIT = 20 * 1024 * 1024;
// 대시보드 이관 파일에는 documents 표가 없다(PromptGate/db/schema_mvp.sql이 만든다). 그 정의를 그대로 옮긴다
const DOCUMENTS_TABLE = `CREATE TABLE IF NOT EXISTS documents (
    doc_id         text PRIMARY KEY,
    filename       text NOT NULL,
    original       bytea NOT NULL,
    version        integer NOT NULL DEFAULT 1,
    title          text,
    classification text,
    status         text NOT NULL DEFAULT 'active'  CHECK (status IN ('active', 'retired')),
    index_status   text NOT NULL DEFAULT 'pending' CHECK (index_status IN ('pending', 'indexing', 'indexed', 'error')),
    index_windows  integer,
    format         text,
    normalized_text text,
    text_chars     integer,
    index_error    text,
    registered_at  timestamptz NOT NULL DEFAULT now(),
    registered_by  text,
    indexed_at     timestamptz,
    retired_at     timestamptz
)`;
const oldAuditMigration = async () => {
  const current = await readMigration('002_admin_auth_audit.sql');
  const old = current.replace(/,(\r?\n)\s*-- 2026-10-13 [^\r\n]*(\r?\n)\s*'DOCUMENT_VIEW',\s*'DOCUMENT_DOWNLOAD'/, '');
  assert.ok(old !== current && !old.includes('DOCUMENT_VIEW') && old.includes("'CLIENT_ALIAS_UPDATE'"), 'the old list is rebuilt from the current file');
  return old;
};

// pg의 Pool 모양(query·connect). PGlite는 연결이 하나라 트랜잭션이 겹치는 시험은 하지 않는다
function poolFor(db) {
  const run = async (sql, params) => {
    const result = await db.query(sql, params);
    return { rows: result.rows, rowCount: result.rows.length > 0 ? result.rows.length : (result.affectedRows ?? 0) };
  };
  return { query: run, async connect() { return { query: run, release() {} }; } };
}
const one = async (db, sql, params = []) => (await db.query(sql, params)).rows[0];

const CONFIG = { allowedOrigin: 'http://127.0.0.1:4173', adminEmail: 'local-admin-docview-pglite@example.test', adminPassword: 'local-password-docview-pglite', ingestToken: 'local-ingest-token-docview-pglite' };
async function startApp(db) {
  const server = createAppServer({ ...CONFIG, store: new PostgresEventStore({ pool: poolFor(db) }) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const call = (method, pathname) => fetch(`${base}${pathname}`, { method, headers: { Cookie: cookie } });
  return { server, call, close: () => new Promise((resolve) => server.close(resolve)) };
}

void test('the audit list takes DOCUMENT_VIEW and DOCUMENT_DOWNLOAD, still rejects unknown actions, and upgrades an existing database', { skip }, async () => {
  const fresh = new PGlite();
  try {
    await applyAll(fresh);
    await applyAll(fresh);   // migrate.mjs는 매번 전부 다시 적용한다
    for (const action of NEW_ACTIONS)
      await fresh.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result, changes) VALUES ($1, now(), 'local-admin', $2, 'DOCUMENT', 'doc-1', 'SUCCESS', '{"version":"1","format":"pdf","mode":"original"}'::jsonb)`, [`audit-${action}`, action]);
    await assert.rejects(() => fresh.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ('audit-bogus', now(), 'a', 'DOCUMENT_PRINT', 'DOCUMENT', 'x', 'SUCCESS')`), /check/i);
  } finally {
    await fresh.close();
  }

  const old = await oldAuditMigration();
  const oldActions = [...old.matchAll(/^\s*'([A-Z_]+)',?\s*$/gm)].map((match) => match[1]);
  assert.ok(oldActions.length >= 25 && oldActions.includes('CLIENT_ALIAS_UPDATE'));
  const db = new PGlite();
  try {
    await applyAll(db, { '002_admin_auth_audit.sql': old });
    await assert.rejects(() => db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ('audit-early', now(), 'a', 'DOCUMENT_VIEW', 'DOCUMENT', 'x', 'SUCCESS')`), /check/i);
    for (const action of oldActions)
      await db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ($1, now(), 'a', $2, 'DOCUMENT', 'target', 'SUCCESS')`, [`audit-old-${action}`, action]);
    const before = (await one(db, 'SELECT count(*)::int AS n FROM dashboard_admin_activity_history')).n;
    await applyAll(db);   // 운영에서 migrate.mjs가 하는 일
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_admin_activity_history')).n, before);
    for (const action of NEW_ACTIONS)
      await db.query(`INSERT INTO dashboard_admin_activity_history (audit_id, occurred_at, admin_id, action, target_type, target_id, result) VALUES ($1, now(), 'a', $2, 'DOCUMENT', 'x', 'SUCCESS')`, [`audit-new-${action}`, action]);
    await applyAll(db);   // 새 작업 기록이 생긴 뒤에도 다시 적용된다
    await applyAll(db);
    assert.equal((await one(db, 'SELECT count(*)::int AS n FROM dashboard_admin_activity_history')).n, before + NEW_ACTIONS.length);
    const definition = (await one(db, "SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'dashboard_admin_activity_history_action_check'")).def;
    for (const action of [...oldActions, ...NEW_ACTIONS]) assert.ok(definition.includes(`'${action}'`), action);   // 목록은 줄지 않았다
  } finally {
    await db.close();
  }
});

void test('the real documents table: view, exact original bytes, no download (404, no record), 413 without reading the bytes, and text pages', { skip }, async () => {
  const db = new PGlite();
  await applyAll(db);
  await db.exec(DOCUMENTS_TABLE);
  const bytes = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.from(Array.from({ length: 256 }, (_, index) => index)), Buffer.from('\n%%EOF')]);
  // 한글·이모지(서로게이트 쌍)·전화번호: PostgreSQL length()와 화면 좌표(코드 포인트)가 같은지 본다
  const text = `보고서 😀 첫 줄 담당 010-1234-5678\n${'본문 문장입니다. '.repeat(250)}끝`;
  await db.query(`INSERT INTO documents (doc_id, filename, original, version, status, index_status, format, normalized_text, registered_by)
                  VALUES ('bin', '바이너리 보고서.pdf', $1, 4, 'retired', 'indexed', 'pdf', $2, 'local-admin')`, [bytes, text]);
  await db.query(`INSERT INTO documents (doc_id, filename, original, version, status, index_status, format)
                  VALUES ('huge', 'huge.pdf', convert_to(repeat('A', $1::integer), 'UTF8'), 1, 'active', 'indexed', 'pdf')`, [LIMIT + 1]);
  await db.query(`INSERT INTO documents (doc_id, filename, original, status, index_status, format)
                  VALUES ('pending', 'pending.docx', $1, 'active', 'pending', 'docx')`, [Buffer.from('PK\x03\x04docx')]);
  const store = new PostgresEventStore({ pool: poolFor(db) });
  const app = await startApp(db);
  try {
    // 저장소: 정보 조회에는 바이트가 없고, 원본은 상한 안에서만 온다
    const info = await store.getDocumentForView('bin');
    assert.deepEqual(info, { doc_id: 'bin', filename: '바이너리 보고서.pdf', format: 'pdf', version: '4', status: 'INACTIVE', index_status: 'READY', size: bytes.length });
    const huge = await store.getDocumentOriginal('huge', LIMIT);
    assert.deepEqual({ ...huge, data: huge.data === null }, { doc_id: 'huge', filename: 'huge.pdf', format: 'pdf', version: '1', status: 'ACTIVE', index_status: 'READY', size: LIMIT + 1, data: true });
    assert.deepEqual((await store.getDocumentOriginal('bin', LIMIT)).data, bytes);
    assert.ok(Buffer.isBuffer((await store.getDocumentOriginal('bin', LIMIT)).data));
    const stored = await store.getDocumentText('bin', 2_000_000);
    assert.equal(stored.text, text);
    assert.equal(stored.text_chars, Array.from(text).length);
    assert.equal((await store.getDocumentText('bin', 10)).text, null);
    assert.equal(await store.getDocumentForView('none'), null);
    const listed = await store.listDocuments();
    assert.equal(listed.length, 3);
    assert.equal(JSON.stringify(listed).includes('PDF-1.7'), false);

    // API: 열람 시작 → 감사 행(DB) → 원본(내려받기 download=1은 2026-10-13부터 404·기록 없음) → 텍스트
    const opened = await app.call('POST', '/api/documents/bin/views');
    assert.equal(opened.status, 201);
    const view = await opened.json();
    assert.deepEqual([view.version, view.status, view.index_status, view.size], ['4', 'INACTIVE', 'READY', bytes.length]);
    const viewRow = await one(db, "SELECT admin_id, target_type, target_id, result, changes FROM dashboard_admin_activity_history WHERE action = 'DOCUMENT_VIEW'");
    assert.deepEqual(viewRow, { admin_id: 'local-admin', target_type: 'DOCUMENT', target_id: 'bin', result: 'SUCCESS', changes: { version: '4', format: 'pdf', mode: 'original', view_ref: view.view_ref } });
    const original = await app.call('GET', `/api/documents/bin/original?view=${view.view_id}`);
    assert.equal(original.status, 200);
    assert.deepEqual(Buffer.from(await original.arrayBuffer()), bytes);
    assert.equal(original.headers.get('x-document-version'), '4');
    const download = await app.call('GET', `/api/documents/bin/original?view=${view.view_id}&download=1`);
    assert.equal(download.status, 404);
    assert.equal(await one(db, "SELECT target_id FROM dashboard_admin_activity_history WHERE action = 'DOCUMENT_DOWNLOAD'"), undefined);
    const page = await (await app.call('GET', `/api/documents/bin/text?view=${view.view_id}`)).json();
    assert.equal(page.page.total_chars, Array.from(text).length);
    const shown = page.page.segments.map((segment) => segment.text).join('');
    assert.ok(shown.startsWith('보고서 😀 첫 줄 담당 '));
    assert.equal(shown.includes('010-1234-5678'), false);

    const big = await (await app.call('POST', '/api/documents/huge/views')).json();
    assert.equal(big.size, LIMIT + 1);
    assert.equal((await app.call('GET', `/api/documents/huge/original?view=${big.view_id}`)).status, 413);
    const waiting = await (await app.call('POST', '/api/documents/pending/views')).json();
    const pending = await (await app.call('GET', `/api/documents/pending/text?view=${waiting.view_id}`)).json();
    assert.deepEqual([pending.index_status, pending.page.status], ['PROCESSING', 'NOT_RECORDED']);
    assert.equal((await one(db, "SELECT count(*)::int AS n FROM dashboard_admin_activity_history WHERE action = 'DOCUMENT_VIEW'")).n, 3);
  } finally {
    await app.close();
    await db.close();
  }
});

void test('a database not yet migrated refuses every view: the audit insert fails, so no view number and no bytes', { skip }, async () => {
  const db = new PGlite();
  await applyAll(db, { '002_admin_auth_audit.sql': await oldAuditMigration() });
  await db.exec(DOCUMENTS_TABLE);
  await db.query(`INSERT INTO documents (doc_id, filename, original, status, index_status, format) VALUES ('doc', 'doc.pdf', $1, 'active', 'indexed', 'pdf')`, [Buffer.from('%PDF-1.7 secret')]);
  const app = await startApp(db);
  const originalError = console.error;
  console.error = () => {};
  try {
    const refused = await app.call('POST', '/api/documents/doc/views');
    assert.equal(refused.status, 403);
    const body = await refused.json();
    assert.equal(body.error.code, 'AUDIT_REQUIRED');
    assert.equal('view_id' in body, false);
    assert.equal((await one(db, "SELECT count(*)::int AS n FROM dashboard_admin_activity_history WHERE target_type = 'DOCUMENT'")).n, 0);
  } finally {
    console.error = originalError;
    await app.close();
    await db.close();
  }
});
