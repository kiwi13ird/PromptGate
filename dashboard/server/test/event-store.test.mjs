import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { JsonEventStore, SettingsConflictError } from '../event-store.mjs';
import { defaultGatewaySettings } from '../gateway-settings.mjs';
import {
  canonicalEventToDto,
  validateCanonicalEvent,
} from '../validation.mjs';

function canonicalEvent(eventId, score = 0.82) {
  return validateCanonicalEvent({
    type: 'SECURITY_EVENT',
    eventId,
    timestamp: new Date().toISOString(),
    clientId: 'client-local-store-test',
    targetLlm: 'ChatGPT',
    detectionOutcome: 'MATCH',
    finalAction: 'BLOCK',
    detections: [
      {
        detector: 'WINDOW_HASH',
        matchType: 'TEXT_FRAGMENT',
        score,
        scoreKind: 'COVERAGE',
        matchedDocumentId: 'DOC-LOCAL-STORE',
        documentSpan: { charStart: 10, charEnd: 30 },
        action: 'BLOCK',
      },
    ],
  });
}

void test('concurrent ingest is serialized, readable and leaves no temp files', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-event-store-concurrent-'));
  const storePath = path.join(root, 'missing', 'nested', 'events.json');
  const store = new JsonEventStore(storePath);
  try {
    const writes = Array.from({ length: 20 }, (_, index) => {
      const event = canonicalEvent(`evt-concurrent-${index}`);
      return store.ingest(event, canonicalEventToDto(event));
    });
    const readDuringQueuedWrites = store.list();
    const results = await Promise.all(writes);
    assert.equal(results.every((result) => result.created), true);
    assert.equal((await readDuringQueuedWrites).length, 20);
    assert.equal((await store.list()).length, 20);
    assert.deepEqual(
      await readdir(path.dirname(storePath)),
      ['events.json'],
    );
    if (process.platform !== 'win32')
      assert.equal((await stat(storePath)).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('duplicate canonical event is idempotent and changed score conflicts', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-event-store-duplicate-'));
  const store = new JsonEventStore(path.join(root, 'events.json'));
  try {
    const firstEvent = canonicalEvent('evt-store-duplicate');
    const first = await store.ingest(
      firstEvent,
      canonicalEventToDto(firstEvent),
    );
    const retry = await store.ingest(
      firstEvent,
      canonicalEventToDto(firstEvent),
    );
    assert.equal(first.created, true);
    assert.equal(retry.created, false);
    assert.equal((await store.list()).length, 1);

    const changed = canonicalEvent('evt-store-duplicate', 0.83);
    await assert.rejects(
      store.ingest(changed, canonicalEventToDto(changed)),
      { name: 'EventConflictError' },
    );
    assert.equal((await store.list()).length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('malformed JSON and unsupported store versions fail closed', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-event-store-invalid-'));
  const storePath = path.join(root, 'events.json');
  const store = new JsonEventStore(storePath);
  try {
    await writeFile(storePath, '{broken-json', 'utf8');
    await assert.rejects(store.list(), /not valid JSON/);
    await writeFile(
      storePath,
      JSON.stringify({ version: 999, records: [] }),
      'utf8',
    );
    await assert.rejects(store.list(), /unsupported format/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// 2026-10-10 Gateway 처리 설정: 옛 파일(칸 없음)은 저장된 설정 없음으로 열리고, 저장은 번호 비교·설정·감사를 한 번에 쓴다
void test('gateway settings open from an old file, append with their audit row and reject stale versions', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-event-store-gateway-'));
  const storePath = path.join(root, 'events.json');
  const revision = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
  const audit = { adminId: 'local-admin', action: 'GATEWAY_SETTINGS_UPDATE', targetType: 'GATEWAY', targetId: 'gateway-settings', result: 'SUCCESS',
    changes: { new_version: 1, previous_value: '기본값 · …', new_value: '…' } };
  const save = (expectedVersion, n) => store.saveGatewaySettings({ expectedVersion, revision: revision(n), settings: defaultGatewaySettings(), updatedBy: 'local-admin', audit });
  const store = new JsonEventStore(storePath);
  try {
    await writeFile(storePath, JSON.stringify({ version: 1, records: [], auditRecords: [] }), 'utf8');
    assert.equal(await store.getGatewaySettings(), null);
    assert.deepEqual(await store.list(), []);
    const first = await save(0, 1);
    assert.equal(first.version, 1);
    assert.equal(first.revision, revision(1));
    assert.deepEqual(await store.getGatewaySettings(), first);
    await assert.rejects(save(0, 2), (error) => error instanceof SettingsConflictError && error.currentVersion === 1);
    await assert.rejects(save(1, 1), (error) => error instanceof SettingsConflictError);   // 같은 revision
    const results = await Promise.allSettled([save(1, 3), save(1, 4)]);
    assert.deepEqual(results.map((result) => result.status).sort(), ['fulfilled', 'rejected']);
    assert.equal((await store.getGatewaySettings()).version, 2);
    const audits = await store.listAudit();
    assert.deepEqual(audits.map((record) => [record.action, record.target_type, record.target_id]), [
      ['GATEWAY_SETTINGS_UPDATE', 'GATEWAY', 'gateway-settings'],
      ['GATEWAY_SETTINGS_UPDATE', 'GATEWAY', 'gateway-settings'],
    ]);
    assert.equal(audits[0].occurred_at, first.updated_at);

    for (const invalid of [{ gatewaySettings: {} }, { gatewaySettings: [{ version: 0, revision: revision(9), settings: {}, updated_by: 'x', updated_at: 'x' }] }]) {
      await writeFile(storePath, JSON.stringify({ version: 1, records: [], auditRecords: [], ...invalid }), 'utf8');
      await assert.rejects(store.getGatewaySettings(), /invalid gateway settings/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
