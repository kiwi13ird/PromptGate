import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PostgresEventStore } from '../postgres-event-store.mjs';
import { SettingsConflictError } from '../event-store.mjs';

const canonicalEvent = {
  eventId: 'evt-postgres-test',
  timestamp: '2026-09-22T00:00:00Z',
  clientId: 'client-postgres-test',
  targetLlm: 'ChatGPT',
  finalAction: 'ALLOW',
  detections: [],
};
const eventDto = {
  event_id: 'evt-postgres-test',
  occurred_at: '2026-09-22T00:00:00Z',
  client_id: 'client-postgres-test',
  target_llm: 'ChatGPT',
  action: 'ALLOW',
  final_action: 'ALLOW',
  detection_outcome: 'NO_MATCH',
  status: 'NEW',
  admin_notes: [],
  timeline: [],
  detections: [],
};

void test('PostgreSQL store inserts the same metadata-only DTO contract', async () => {
  const calls = [];
  const pool = {
    async query(sql, parameters) {
      calls.push({ sql, parameters });
      return { rowCount: 1, rows: [{ event: structuredClone(eventDto) }] };
    },
  };
  const store = new PostgresEventStore({ pool });
  const result = await store.ingest(canonicalEvent, eventDto);

  assert.equal(result.created, true);
  assert.deepEqual(result.event, eventDto);
  assert.match(calls[0].sql, /INSERT INTO dashboard_security_events/);
  assert.equal(calls[0].parameters[0], canonicalEvent.eventId);
  assert.equal(calls[0].parameters[6], 'ALLOW');
  assert.equal(calls[0].parameters[7], 'NO_MATCH');
  assert.equal(calls[0].parameters.at(-1), JSON.stringify(eventDto));
});

void test('PostgreSQL store requires an explicit connection source', () => {
  assert.throws(
    () => new PostgresEventStore(),
    /DATABASE_URL is required/,
  );
});

void test('PostgreSQL document inventory exposes index metadata without document text', async () => {
  const pool = {
    async query(sql) {
      assert.match(sql, /FROM documents/);
      return {
        rows: [
          {
            doc_id: 'DOC-RDS-001',
            filename: 'protected.docx',
            format: 'docx',
            version: '1',
            classification: 'CONFIDENTIAL',
            status: 'ACTIVE',
            index_status: 'INDEXED',
            index_windows: 501,
            registered_at: new Date('2026-09-22T00:00:00Z'),
            registered_by: 'admin',
          },
        ],
      };
    },
  };
  const store = new PostgresEventStore({ pool });
  const documents = await store.listDocuments();

  assert.deepEqual(documents, [
    {
      document_id: 'DOC-RDS-001',
      document_name: 'protected.docx',
      registered_at: '2026-09-22T00:00:00.000Z',
      status: 'ACTIVE',
      processing_status: 'READY',
      file_type: 'docx',
      exact_fingerprint_status: 'NOT_AVAILABLE',
      similarity_fingerprint_status: 'NOT_AVAILABLE',
      chunk_index_status: 'READY',
      chunk_count: 501,
      version: '1',
      classification: 'CONFIDENTIAL',
      owner: 'admin',
      active_detectors: ['WINDOW_HASH'],
    },
  ]);
  assert.equal(JSON.stringify(documents).includes('normalized_text'), false);
  assert.equal(JSON.stringify(documents).includes('original'), false);
});

// 2026-10-10 Gateway 처리 설정: 설정 행과 감사 행을 한 트랜잭션으로
const SETTINGS_REVISION = '00000000-0000-4000-8000-000000000001';
const gatewaySettingsValue = {
  timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'block', seconds: 2 } },
  uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
  notify_on_allow: false,
};
const settingsAudit = { adminId: 'local-admin', action: 'GATEWAY_SETTINGS_UPDATE', targetType: 'GATEWAY', targetId: 'gateway-settings',
  result: 'SUCCESS', changes: { new_version: 1, previous_value: '기본값 · …', new_value: '…' } };

function settingsClient(onInsert, onAudit = () => ({ rowCount: 1, rows: [] })) {
  const calls = [];
  const client = {
    async query(sql, parameters) {
      const statement = sql.trim();
      calls.push({ statement, parameters });
      if (/INSERT INTO dashboard_gateway_settings/.test(statement)) return onInsert(parameters);
      if (/INSERT INTO dashboard_admin_activity_history/.test(statement)) return onAudit(parameters);
      if (/COALESCE\(max\(version\), 0\)/.test(statement)) return { rowCount: 1, rows: [{ version: 4 }] };
      return { rowCount: 0, rows: [] };
    },
    release() { calls.push({ statement: 'release' }); },
  };
  const names = () => calls.map(({ statement }) =>
    /^INSERT INTO (\w+)/.exec(statement)?.[1] ?? (/COALESCE/.test(statement) ? 'SELECT current' : statement));
  return { pool: { connect: async () => client }, calls, names };
}

void test('PostgreSQL gateway settings save inserts the row and its audit in one transaction', async () => {
  const { pool, calls, names } = settingsClient(() => ({ rowCount: 1, rows: [{ version: 1, revision: SETTINGS_REVISION,
    settings: gatewaySettingsValue, updated_by: 'local-admin', updated_at: new Date('2026-10-10T05:12:00Z') }] }));
  const saved = await new PostgresEventStore({ pool }).saveGatewaySettings({ expectedVersion: 0, revision: SETTINGS_REVISION,
    settings: gatewaySettingsValue, updatedBy: 'local-admin', audit: settingsAudit });
  assert.deepEqual(saved, { version: 1, revision: SETTINGS_REVISION, settings: gatewaySettingsValue, updated_by: 'local-admin', updated_at: '2026-10-10T05:12:00.000Z' });
  assert.deepEqual(names(), ['BEGIN', 'dashboard_gateway_settings', 'dashboard_admin_activity_history', 'COMMIT', 'release']);
  const insert = calls[1];
  assert.match(insert.statement, /SELECT \$1::integer \+ 1, \$2, \$3::jsonb, \$4/);
  assert.match(insert.statement, /WHERE COALESCE\(\(SELECT max\(version\) FROM dashboard_gateway_settings\), 0\) = \$1::integer/);
  assert.deepEqual(insert.parameters, [0, SETTINGS_REVISION, JSON.stringify(gatewaySettingsValue), 'local-admin']);
  const auditCall = calls[2];
  assert.match(auditCall.parameters[0], /^audit-/);
  assert.deepEqual(auditCall.parameters.slice(2), ['local-admin', 'GATEWAY_SETTINGS_UPDATE', 'GATEWAY', 'gateway-settings', 'SUCCESS', JSON.stringify(settingsAudit.changes)]);
});

void test('PostgreSQL gateway settings conflicts roll back on zero rows and on 23505', async () => {
  for (const onInsert of [
    () => ({ rowCount: 0, rows: [] }),
    () => { throw Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' }); },
  ]) {
    const { pool, names } = settingsClient(onInsert);
    await assert.rejects(
      new PostgresEventStore({ pool }).saveGatewaySettings({ expectedVersion: 3, revision: SETTINGS_REVISION, settings: gatewaySettingsValue,
        updatedBy: 'local-admin', audit: settingsAudit }),
      (error) => error instanceof SettingsConflictError && error.currentVersion === 4,
    );
    assert.deepEqual(names(), ['BEGIN', 'dashboard_gateway_settings', 'ROLLBACK', 'SELECT current', 'release']);
  }
});

void test('PostgreSQL gateway settings: an audit failure rolls back and is not reported as a conflict', async () => {
  const { pool, names } = settingsClient(
    () => ({ rowCount: 1, rows: [{ version: 1, revision: SETTINGS_REVISION, settings: gatewaySettingsValue, updated_by: 'local-admin', updated_at: new Date() }] }),
    () => { throw Object.assign(new Error('violates check constraint'), { code: '23514' }); },
  );
  await assert.rejects(
    new PostgresEventStore({ pool }).saveGatewaySettings({ expectedVersion: 0, revision: SETTINGS_REVISION, settings: gatewaySettingsValue,
      updatedBy: 'local-admin', audit: settingsAudit }),
    (error) => !(error instanceof SettingsConflictError) && error.code === '23514',
  );
  assert.deepEqual(names(), ['BEGIN', 'dashboard_gateway_settings', 'dashboard_admin_activity_history', 'ROLLBACK', 'release']);
});

void test('PostgreSQL gateway settings read takes the highest version', async () => {
  const seen = [];
  let rows = [];
  const pool = { async query(sql) { seen.push(sql); return { rowCount: rows.length, rows }; } };
  const store = new PostgresEventStore({ pool });
  assert.equal(await store.getGatewaySettings(), null);
  assert.match(seen[0], /FROM dashboard_gateway_settings\s+ORDER BY version DESC\s+LIMIT 1/);
  rows = [{ version: '7', revision: SETTINGS_REVISION, settings: JSON.stringify(gatewaySettingsValue), updated_by: 'local-admin', updated_at: new Date('2026-10-10T05:12:00Z') }];
  assert.deepEqual(await store.getGatewaySettings(), { version: 7, revision: SETTINGS_REVISION, settings: gatewaySettingsValue, updated_by: 'local-admin', updated_at: '2026-10-10T05:12:00.000Z' });
});

void test('PostgreSQL gateway settings read treats a missing table (42P01) as no stored settings, other errors still fail', async () => {
  let failure;
  const pool = { async query() { throw failure; } };
  const store = new PostgresEventStore({ pool });
  failure = Object.assign(new Error('relation "dashboard_gateway_settings" does not exist'), { code: '42P01' });
  assert.equal(await store.getGatewaySettings(), null);
  for (const other of [
    Object.assign(new Error('terminating connection due to administrator command'), { code: '57P01' }),
    Object.assign(new Error('permission denied for table dashboard_gateway_settings'), { code: '42501' }),
    new Error('connect ECONNREFUSED 127.0.0.1:5432'),
  ]) {
    failure = other;
    await assert.rejects(store.getGatewaySettings(), (error) => error === other);
  }
});
