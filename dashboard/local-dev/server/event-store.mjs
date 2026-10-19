import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

const EMPTY_DATABASE = Object.freeze({ version: 1, records: [], auditRecords: [] });
// 운영 DB의 감사 대상 허용 목록(migrations/002)과 같게 둔다 - 리포트·키워드(10/4), GPU(10/7)
const AUDIT_TARGET_TYPES = ['EVENT', 'ADMIN', 'POLICY', 'DOCUMENT', 'REPORT', 'KEYWORD', 'GPU'];

export class EventConflictError extends Error {
  constructor(eventId) {
    super(`Event ${eventId} already exists with different content.`);
    this.name = 'EventConflictError';
    this.eventId = eventId;
  }
}

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
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
  return { ...value, auditRecords };
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
}
