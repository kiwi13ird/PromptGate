import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

const EMPTY_DATABASE = Object.freeze({ version: 1, records: [], auditRecords: [], gatewaySettings: [], gatewayAccess: [], clientAliases: [] });
// 운영 DB의 감사 대상 허용 목록(migrations/002)과 같게 둔다 - 리포트·키워드(10/4), GPU(10/7), Gateway 처리 설정·접속 차단(10/10·10/12)
const AUDIT_TARGET_TYPES = ['EVENT', 'ADMIN', 'POLICY', 'DOCUMENT', 'REPORT', 'KEYWORD', 'GPU', 'GATEWAY'];

export class EventConflictError extends Error {
  constructor(eventId) {
    super(`Event ${eventId} already exists with different content.`);
    this.name = 'EventConflictError';
    this.eventId = eventId;
  }
}

// Gateway 처리 설정(2026-10-10): 저장 요청의 expected_version이 지금 번호와 다를 때(다른 관리자가 먼저 저장)
export class SettingsConflictError extends Error {
  constructor(currentVersion) {
    super('Gateway settings were changed by another administrator.');
    this.name = 'SettingsConflictError';
    this.currentVersion = currentVersion;
  }
}

// 접속 차단(2026-10-12): 저장 요청의 expected_version이 지금 번호와 다를 때(다른 관리자가 먼저 저장)
export class AccessConflictError extends Error {
  constructor(currentVersion) {
    super('Gateway access rules were changed by another administrator.');
    this.name = 'AccessConflictError';
    this.currentVersion = currentVersion;
  }
}

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// 저장소가 한 번의 쓰기로 함께 남기는 감사 행(audit = { adminId, action, targetType, targetId, result, changes })
function auditRecordFrom(audit, occurredAt) {
  return {
    audit_id: `audit-${randomUUID()}`,
    occurred_at: occurredAt,
    admin_id: audit.adminId,
    action: audit.action,
    target_type: audit.targetType,
    target_id: audit.targetId,
    result: audit.result,
    ...(audit.changes ? { changes: structuredClone(audit.changes) } : {}),
  };
}

function assertDatabase(value) {
  if (
    typeof value !== 'object' ||
    value === null ||
    value.version !== 1 ||
    !Array.isArray(value.records)
  )
    throw new Error('Event store file has an unsupported format.');
  for (const record of value.records) {
    if (
      typeof record !== 'object' ||
      record === null ||
      typeof record.eventId !== 'string' ||
      typeof record.fingerprint !== 'string' ||
      typeof record.event !== 'object' ||
      record.event === null ||
      record.event.event_id !== record.eventId
    )
      throw new Error('Event store file contains an invalid record.');
  }
  const auditRecords = value.auditRecords ?? [];
  if (!Array.isArray(auditRecords))
    throw new Error('Event store file contains invalid audit records.');
  for (const record of auditRecords) {
    if (
      typeof record !== 'object' ||
      record === null ||
      typeof record.audit_id !== 'string' ||
      typeof record.occurred_at !== 'string' ||
      typeof record.admin_id !== 'string' ||
      typeof record.action !== 'string' ||
      !AUDIT_TARGET_TYPES.includes(record.target_type) ||
      typeof record.target_id !== 'string' ||
      !['SUCCESS', 'FAILURE'].includes(record.result)
    )
      throw new Error('Event store file contains an invalid audit record.');
  }
  // Gateway 처리 설정(2026-10-10). 이 칸이 없는 옛 파일은 저장된 설정이 없는 것으로 읽는다
  const gatewaySettings = value.gatewaySettings ?? [];
  if (!Array.isArray(gatewaySettings))
    throw new Error('Event store file contains invalid gateway settings.');
  for (const row of gatewaySettings) {
    if (
      typeof row !== 'object' ||
      row === null ||
      !Number.isSafeInteger(row.version) ||
      row.version < 1 ||
      typeof row.revision !== 'string' ||
      typeof row.settings !== 'object' ||
      row.settings === null ||
      typeof row.updated_by !== 'string' ||
      typeof row.updated_at !== 'string'
    )
      throw new Error('Event store file contains an invalid gateway settings record.');
  }
  // 접속 차단(2026-10-12). 이 칸이 없는 옛 파일은 저장된 차단 목록·별칭이 없는 것으로 읽는다
  const gatewayAccess = value.gatewayAccess ?? [];
  if (!Array.isArray(gatewayAccess))
    throw new Error('Event store file contains invalid gateway access rules.');
  for (const row of gatewayAccess) {
    if (
      typeof row !== 'object' ||
      row === null ||
      !Number.isSafeInteger(row.version) ||
      row.version < 1 ||
      typeof row.revision !== 'string' ||
      typeof row.require_client_id !== 'boolean' ||
      !Array.isArray(row.rules) ||
      typeof row.updated_by !== 'string' ||
      typeof row.updated_at !== 'string'
    )
      throw new Error('Event store file contains an invalid gateway access record.');
  }
  const clientAliases = value.clientAliases ?? [];
  if (!Array.isArray(clientAliases))
    throw new Error('Event store file contains invalid client aliases.');
  for (const row of clientAliases) {
    if (
      typeof row !== 'object' ||
      row === null ||
      typeof row.client_id !== 'string' ||
      typeof row.alias !== 'string' ||
      typeof row.updated_by !== 'string' ||
      typeof row.updated_at !== 'string'
    )
      throw new Error('Event store file contains an invalid client alias record.');
  }
  return { ...value, auditRecords, gatewaySettings, gatewayAccess, clientAliases };
}

export class JsonEventStore {
  #filePath;
  #writeQueue = Promise.resolve();

  constructor(filePath) {
    this.#filePath = path.resolve(filePath);
  }

  async #readDatabase() {
    try {
      return assertDatabase(JSON.parse(await readFile(this.#filePath, 'utf8')));
    } catch (error) {
      if (error?.code === 'ENOENT') return structuredClone(EMPTY_DATABASE);
      if (error instanceof SyntaxError)
        throw new Error('Event store file is not valid JSON.', { cause: error });
      throw error;
    }
  }

  async #writeDatabase(database) {
    await mkdir(path.dirname(this.#filePath), { recursive: true });
    const temporaryPath = `${this.#filePath}.${process.pid}.${Date.now()}.tmp`;
    try {
      await writeFile(temporaryPath, `${JSON.stringify(database, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      });
      await rename(temporaryPath, this.#filePath);
    } catch (error) {
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }

  #enqueueWrite(execute) {
    const result = this.#writeQueue.then(execute, execute);
    this.#writeQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async ingest(canonicalEvent, eventDto) {
    const execute = async () => {
      const database = await this.#readDatabase();
      const eventFingerprint = fingerprint(canonicalEvent);
      const existing = database.records.find(
        (record) => record.eventId === canonicalEvent.eventId,
      );
      if (existing) {
        if (existing.fingerprint !== eventFingerprint)
          throw new EventConflictError(canonicalEvent.eventId);
        return { created: false, event: structuredClone(existing.event) };
      }
      const record = {
        eventId: canonicalEvent.eventId,
        fingerprint: eventFingerprint,
        event: structuredClone(eventDto),
      };
      database.records.push(record);
      await this.#writeDatabase(database);
      return { created: true, event: structuredClone(record.event) };
    };
    return this.#enqueueWrite(execute);
  }

  async #mutateEvent(eventId, actor, action, changes, mutate, summary) {
    return this.#enqueueWrite(async () => {
      const database = await this.#readDatabase();
      const record = database.records.find((item) => item.eventId === eventId);
      if (!record) return null;

      const occurredAt = new Date().toISOString();
      const auditChanges =
        typeof changes === 'function' ? changes(record.event) : changes;
      mutate(record.event, occurredAt);
      record.event.timeline ??= [];
      record.event.timeline.push({
        timeline_id: `timeline-${randomUUID()}`,
        occurred_at: occurredAt,
        actor,
        type:
          action === 'EVENT_STATUS_CHANGED'
            ? 'STATUS_CHANGED'
            : action === 'EVENT_ASSIGNED'
              ? 'ASSIGNEE_CHANGED'
              : 'NOTE_ADDED',
        summary,
      });
      database.auditRecords.push({
        audit_id: `audit-${randomUUID()}`,
        occurred_at: occurredAt,
        admin_id: actor,
        action,
        target_type: 'EVENT',
        target_id: eventId,
        result: 'SUCCESS',
        changes: auditChanges,
      });
      await this.#writeDatabase(database);
      return structuredClone(record.event);
    });
  }

  async updateStatus(eventId, status, actor) {
    return this.#mutateEvent(
      eventId,
      actor,
      'EVENT_STATUS_CHANGED',
      (event) => ({
        previous_incident_status: event.status,
        new_incident_status: status,
      }),
      (event) => {
        event.status = status;
      },
      `조사 상태를 ${status}(으)로 변경`,
    );
  }

  async assign(eventId, assignee, actor) {
    return this.#mutateEvent(
      eventId,
      actor,
      'EVENT_ASSIGNED',
      (event) => ({
        previous_assignee: event.assignee ?? '',
        new_assignee: assignee,
      }),
      (event) => {
        event.assignee = assignee;
      },
      `담당자를 ${assignee}(으)로 변경`,
    );
  }

  async addNote(eventId, content, actor) {
    return this.#mutateEvent(
      eventId,
      actor,
      'EVENT_NOTE_ADDED',
      { note_added: true },
      (event, occurredAt) => {
        event.admin_notes ??= [];
        event.admin_notes.push({
          note_id: `note-${randomUUID()}`,
          author: actor,
          created_at: occurredAt,
          content,
        });
      },
      '관리자 메모 추가',
    );
  }

  async recordAudit({ adminId, action, targetType, targetId, result, changes }) {
    return this.#enqueueWrite(async () => {
      const database = await this.#readDatabase();
      database.auditRecords.push({
        audit_id: `audit-${randomUUID()}`,
        occurred_at: new Date().toISOString(),
        admin_id: adminId,
        action,
        target_type: targetType,
        target_id: targetId,
        result,
        ...(changes ? { changes: structuredClone(changes) } : {}),
      });
      await this.#writeDatabase(database);
    });
  }

  // Gateway 처리 설정: 마지막 항목이 현재 설정(추가만 한다)
  async getGatewaySettings() {
    await this.#writeQueue;
    const database = await this.#readDatabase();
    const row = database.gatewaySettings.at(-1);
    return row ? structuredClone(row) : null;
  }

  // 번호 비교·설정 추가·감사 추가를 한 번의 파일 쓰기로(PostgreSQL 저장소의 한 트랜잭션과 같은 뜻)
  async saveGatewaySettings({ expectedVersion, revision, settings, updatedBy, audit }) {
    return this.#enqueueWrite(async () => {
      const database = await this.#readDatabase();
      const currentVersion = database.gatewaySettings.at(-1)?.version ?? 0;
      if (
        currentVersion !== expectedVersion ||
        database.gatewaySettings.some((row) => row.revision === revision)
      )
        throw new SettingsConflictError(currentVersion);
      const occurredAt = new Date().toISOString();
      const row = {
        version: expectedVersion + 1,
        revision,
        settings: structuredClone(settings),
        updated_by: updatedBy,
        updated_at: occurredAt,
      };
      database.gatewaySettings.push(row);
      database.auditRecords.push({
        audit_id: `audit-${randomUUID()}`,
        occurred_at: occurredAt,
        admin_id: audit.adminId,
        action: audit.action,
        target_type: audit.targetType,
        target_id: audit.targetId,
        result: audit.result,
        ...(audit.changes ? { changes: structuredClone(audit.changes) } : {}),
      });
      await this.#writeDatabase(database);
      return structuredClone(row);
    });
  }

  // 접속 차단: 마지막 항목이 현재 판(추가만 한다)
  async getGatewayAccess() {
    await this.#writeQueue;
    const database = await this.#readDatabase();
    const row = database.gatewayAccess.at(-1);
    return row ? structuredClone(row) : null;
  }

  // 번호 비교·판 추가·감사 추가를 한 번의 파일 쓰기로(PostgreSQL 저장소의 한 트랜잭션과 같은 뜻)
  async saveGatewayAccess({ expectedVersion, revision, requireClientId, rules, updatedBy, audit }) {
    return this.#enqueueWrite(async () => {
      const database = await this.#readDatabase();
      const currentVersion = database.gatewayAccess.at(-1)?.version ?? 0;
      if (
        currentVersion !== expectedVersion ||
        database.gatewayAccess.some((row) => row.revision === revision)
      )
        throw new AccessConflictError(currentVersion);
      const occurredAt = new Date().toISOString();
      const row = {
        version: expectedVersion + 1,
        revision,
        require_client_id: requireClientId,
        rules: structuredClone(rules),
        updated_by: updatedBy,
        updated_at: occurredAt,
      };
      database.gatewayAccess.push(row);
      database.auditRecords.push(auditRecordFrom(audit, occurredAt));
      await this.#writeDatabase(database);
      return structuredClone(row);
    });
  }

  async listClientAliases() {
    await this.#writeQueue;
    const database = await this.#readDatabase();
    return database.clientAliases
      .map((row) => structuredClone(row))
      .sort((left, right) => (left.client_id < right.client_id ? -1 : left.client_id > right.client_id ? 1 : 0));
  }

  // alias === null이면 삭제. 같은 값이면 쓰지 않고(changed: false) 감사 행도 남기지 않는다.
  // audit은 이전 별칭을 받아 감사 정보를 돌려주는 함수(이전 값을 쓰기와 같은 순서 안에서 읽기 위해)
  async saveClientAlias({ clientId, alias, updatedBy, audit }) {
    return this.#enqueueWrite(async () => {
      const database = await this.#readDatabase();
      const index = database.clientAliases.findIndex((row) => row.client_id === clientId);
      const previous = index >= 0 ? database.clientAliases[index].alias : null;
      if (previous === alias) return { previous, alias, changed: false };
      const occurredAt = new Date().toISOString();
      if (alias === null) database.clientAliases.splice(index, 1);
      else {
        const row = { client_id: clientId, alias, updated_by: updatedBy, updated_at: occurredAt };
        if (index >= 0) database.clientAliases[index] = row;
        else database.clientAliases.push(row);
      }
      database.auditRecords.push(auditRecordFrom(audit(previous), occurredAt));
      await this.#writeDatabase(database);
      return { previous, alias, changed: true };
    });
  }

  async list() {
    await this.#writeQueue;
    const database = await this.#readDatabase();
    return database.records.map((record) => structuredClone(record.event));
  }

  async get(eventId) {
    await this.#writeQueue;
    const database = await this.#readDatabase();
    const record = database.records.find((item) => item.eventId === eventId);
    return record ? structuredClone(record.event) : null;
  }

  async listAudit() {
    await this.#writeQueue;
    const database = await this.#readDatabase();
    return database.auditRecords.map((record) => structuredClone(record));
  }

  async listDocuments() {
    return [];
  }

  async registerDocument() {
    const error = new Error('Document management requires the PostgreSQL store.');
    error.statusCode = 501;
    error.code = 'DOCUMENT_INTEGRATION_UNAVAILABLE';
    throw error;
  }

  async changeDocumentStatus() {
    const error = new Error('Document management requires the PostgreSQL store.');
    error.statusCode = 501;
    error.code = 'DOCUMENT_INTEGRATION_UNAVAILABLE';
    throw error;
  }

  // 보호 문서 본문 보기(2026-10-13): 이 저장소에는 문서가 없다(listDocuments가 빈 목록인 것과 같음) → 없는 문서(404)
  async getDocumentForView() {
    return null;
  }

  async getDocumentOriginal() {
    return null;
  }

  async getDocumentText() {
    return null;
  }
}
