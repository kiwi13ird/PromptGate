import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { AccessConflictError, EventConflictError, SettingsConflictError } from './event-store.mjs';
import { sniffHangulDocument } from './hwp-format.mjs';
import { buildMatchEvidence, comparisonBodies, buildOwnEvidence, evidenceTextLimit, fileSegmentLimit, fileSegmentTextLimit } from './match-evidence.mjs';
import { TEST_CLIENT_PATTERN } from './test-events.mjs';

const { Pool } = pg;

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function eventColumns(event) {
  return [
    event.occurred_at,
    event.request_id ?? null,
    event.client_id,
    event.target_llm,
    event.final_action ?? event.action,
    event.detection_outcome ?? null,
    event.status,
    event.assignee ?? null,
  ];
}

const DOCUMENT_COLUMNS = `doc_id, filename, format, version, classification, status,
  index_status, index_windows, registered_at, registered_by`;

function documentFormat(filename, data) {
  const extension = filename.split('.').pop()?.toLowerCase();
  if (extension === 'pdf' && data.subarray(0, 5).toString('ascii') === '%PDF-')
    return 'pdf';
  if (
    ['docx', 'xlsx'].includes(extension) &&
    data.length >= 4 &&
    data[0] === 0x50 &&
    data[1] === 0x4b &&
    [0x03, 0x05, 0x07].includes(data[2])
  )
    return extension;
  // 2026-10-11 HWP·HWPX: 확장자와 파일 구조가 맞아야 함(다른 CFB·ZIP은 거절). 글자 추출 가능 여부는 인덱서가 판정
  if (['hwp', 'hwpx'].includes(extension) && sniffHangulDocument(data) === extension) return extension;
  const error = new Error('Only valid PDF, DOCX, XLSX, HWP, and HWPX documents are supported.');
  error.statusCode = 422;
  error.code = 'UNSUPPORTED_DOCUMENT';
  throw error;
}

function documentIdFromFilename(filename) {
  const documentId = filename.replace(/\.[^.]+$/, '').trim();
  if (!documentId || documentId.length > 240) {
    const error = new Error('Document id derived from filename is invalid.');
    error.statusCode = 422;
    error.code = 'VALIDATION';
    throw error;
  }
  return documentId;
}

function documentDto(row) {
  const indexStatus = String(row.index_status ?? '').toUpperCase();
  const ready = ['READY', 'INDEXED', 'COMPLETE', 'COMPLETED'].includes(indexStatus);
  const failed = ['FAILED', 'ERROR'].includes(indexStatus);
  const classification = String(row.classification ?? '').toUpperCase();
  return {
    document_id: String(row.doc_id),
    document_name: String(row.filename),
    registered_at: new Date(row.registered_at).toISOString(),
    status: String(row.status ?? '').toUpperCase() === 'ACTIVE' ? 'ACTIVE' : 'INACTIVE',
    processing_status: failed ? 'FAILED' : ready ? 'READY' : 'PROCESSING',
    file_type:
      String(row.format ?? '').trim() ||
      String(row.filename).split('.').pop()?.toUpperCase() ||
      'UNKNOWN',
    exact_fingerprint_status: 'NOT_AVAILABLE',
    similarity_fingerprint_status: 'NOT_AVAILABLE',
    chunk_index_status: failed ? 'FAILED' : ready ? 'READY' : 'PROCESSING',
    chunk_count: Number(row.index_windows ?? 0),
    ...(row.version ? { version: String(row.version) } : {}),
    ...(['INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'].includes(classification)
      ? { classification }
      : {}),
    ...(row.registered_by ? { owner: String(row.registered_by) } : {}),
    active_detectors: ready && String(row.status).toLowerCase() === 'active' ? ['WINDOW_HASH'] : [],
  };
}

// 본문 보기(2026-10-13)용 문서 정보. 상태·색인 상태는 documentDto와 같은 기준으로 바꾼다.
// format은 등록 때 서버가 파일 머리로 확인해 저장한 값(소문자)만 쓴다 - 파일 이름으로 짐작하지 않는다
const VIEW_COLUMNS = `doc_id, filename, format, version, status, index_status, octet_length(original) AS size`;

function documentViewRow(row) {
  const indexStatus = String(row.index_status ?? '').toUpperCase();
  const format = String(row.format ?? '').trim().toLowerCase();
  return {
    doc_id: String(row.doc_id),
    filename: String(row.filename),
    format: format || null,
    version: String(row.version),
    status: String(row.status ?? '').toUpperCase() === 'ACTIVE' ? 'ACTIVE' : 'INACTIVE',
    index_status: ['FAILED', 'ERROR'].includes(indexStatus)
      ? 'FAILED'
      : ['READY', 'INDEXED', 'COMPLETE', 'COMPLETED'].includes(indexStatus) ? 'READY' : 'PROCESSING',
    size: Number(row.size),
  };
}

// Gateway 처리 설정 행(2026-10-10). settings 열에는 timeout·uninspectable·notify_on_allow만 있다
function gatewaySettingsRow(row) {
  return {
    version: Number(row.version),
    revision: String(row.revision),
    settings: typeof row.settings === 'string' ? JSON.parse(row.settings) : row.settings,
    updated_by: String(row.updated_by),
    updated_at: new Date(row.updated_at).toISOString(),
  };
}

// 접속 차단 행(2026-10-12). rules 열에는 해제·만료된 규칙까지 전체 기록이 들어 있다
function gatewayAccessRow(row) {
  return {
    version: Number(row.version),
    revision: String(row.revision),
    require_client_id: row.require_client_id === true,
    rules: typeof row.rules === 'string' ? JSON.parse(row.rules) : row.rules,
    updated_by: String(row.updated_by),
    updated_at: new Date(row.updated_at).toISOString(),
  };
}

const AUDIT_INSERT = `INSERT INTO dashboard_admin_activity_history (
         audit_id, occurred_at, admin_id, action, target_type, target_id, result, changes
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`;

function auditParameters({ adminId, action, targetType, targetId, result, changes }) {
  return [
    `audit-${randomUUID()}`,
    new Date().toISOString(),
    adminId,
    action,
    targetType,
    targetId,
    result,
    changes ? JSON.stringify(changes) : null,
  ];
}

export class PostgresEventStore {
  #pool;

  constructor({ connectionString, pool } = {}) {
    if (!pool && (!connectionString || typeof connectionString !== 'string'))
      throw new Error('DATABASE_URL is required for the PostgreSQL event store.');
    this.#pool = pool ?? new Pool({ connectionString, max: 10 });
  }

  async ingest(canonicalEvent, eventDto) {
    const eventFingerprint = fingerprint(canonicalEvent);
    const result = await this.#pool.query(
      `INSERT INTO dashboard_security_events (
         event_id, fingerprint, occurred_at, request_id, client_id, target_llm,
         final_action, detection_outcome, status, assignee, gateway_evidence, event
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING event`,
      [
        canonicalEvent.eventId,
        eventFingerprint,
        ...eventColumns(eventDto),
        canonicalEvent.finalAction==='MASK' && canonicalEvent.enforcement?.applied && canonicalEvent.maskEvidence
          ? JSON.stringify(canonicalEvent.maskEvidence) : null,
        JSON.stringify(eventDto),
      ],
    );
    if (result.rowCount === 1)
      return { created: true, event: structuredClone(result.rows[0].event) };

    const existing = await this.#pool.query(
      'SELECT fingerprint, event FROM dashboard_security_events WHERE event_id = $1',
      [canonicalEvent.eventId],
    );
    if (existing.rowCount !== 1 || existing.rows[0].fingerprint !== eventFingerprint)
      throw new EventConflictError(canonicalEvent.eventId);
    return { created: false, event: structuredClone(existing.rows[0].event) };
  }

  async #mutateEvent(eventId, actor, action, changes, mutate, summary) {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const selected = await client.query(
        'SELECT event FROM dashboard_security_events WHERE event_id = $1 FOR UPDATE',
        [eventId],
      );
      if (selected.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const event = selected.rows[0].event;
      const occurredAt = new Date().toISOString();
      const auditChanges = typeof changes === 'function' ? changes(event) : changes;
      mutate(event, occurredAt);
      event.timeline ??= [];
      event.timeline.push({
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
      const columns = eventColumns(event);
      await client.query(
        `UPDATE dashboard_security_events
         SET occurred_at = $2, request_id = $3, client_id = $4, target_llm = $5,
             final_action = $6, detection_outcome = $7, status = $8, assignee = $9,
             event = $10::jsonb, updated_at = now()
         WHERE event_id = $1`,
        [eventId, ...columns, JSON.stringify(event)],
      );
      await client.query(
        `INSERT INTO dashboard_admin_activity_history (
           audit_id, occurred_at, admin_id, action, target_type, target_id, result, changes
         ) VALUES ($1, $2, $3, $4, 'EVENT', $5, 'SUCCESS', $6::jsonb)`,
        [
          `audit-${randomUUID()}`,
          occurredAt,
          actor,
          action,
          eventId,
          JSON.stringify(auditChanges),
        ],
      );
      await client.query('COMMIT');
      return structuredClone(event);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  updateStatus(eventId, status, actor) {
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

  assign(eventId, assignee, actor) {
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

  addNote(eventId, content, actor) {
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

  async recordAudit(record) {
    await this.#pool.query(AUDIT_INSERT, auditParameters(record));
  }

  // Gateway 처리 설정: 가장 큰 version이 현재 설정. 없으면 null.
  // 표가 없으면(42P01: 되돌리며 DROP TABLE, 이관 전 시작) 저장된 설정이 없는 것으로 읽는다 → 지표 응답 null → Gateway 환경변수 기본값.
  // 다른 오류는 그대로 올린다(시작 때 읽기는 타이머로 다시 시도)
  async getGatewaySettings() {
    let result;
    try {
      result = await this.#pool.query(
        `SELECT version, revision, settings, updated_by, updated_at
         FROM dashboard_gateway_settings
         ORDER BY version DESC
         LIMIT 1`,
      );
    } catch (error) {
      if (error?.code === '42P01') return null;
      throw error;
    }
    return result.rows.length ? gatewaySettingsRow(result.rows[0]) : null;
  }

  // 설정 행과 감사 행을 한 트랜잭션으로. 감사 기록이 실패하면 설정도 저장하지 않는다.
  // 번호가 expected_version과 다르거나(0행) 같은 번호·revision이 동시에 들어오면(23505) SettingsConflictError
  async saveGatewaySettings({ expectedVersion, revision, settings, updatedBy, audit }) {
    const client = await this.#pool.connect();
    let open = false;
    try {
      await client.query('BEGIN');
      open = true;
      let inserted = null;
      try {
        inserted = await client.query(
          `INSERT INTO dashboard_gateway_settings (version, revision, settings, updated_by)
           SELECT $1::integer + 1, $2, $3::jsonb, $4
           WHERE COALESCE((SELECT max(version) FROM dashboard_gateway_settings), 0) = $1::integer
           RETURNING version, revision, settings, updated_by, updated_at`,
          [expectedVersion, revision, JSON.stringify(settings), updatedBy],
        );
      } catch (error) {
        if (error?.code !== '23505') throw error;
      }
      if (inserted?.rowCount !== 1) {
        await client.query('ROLLBACK');
        open = false;
        let currentVersion;
        try {
          const current = await client.query(
            'SELECT COALESCE(max(version), 0) AS version FROM dashboard_gateway_settings',
          );
          currentVersion = Number(current.rows[0]?.version);
        } catch {
          currentVersion = undefined;
        }
        throw new SettingsConflictError(Number.isSafeInteger(currentVersion) ? currentVersion : undefined);
      }
      await client.query(AUDIT_INSERT, auditParameters(audit));
      await client.query('COMMIT');
      open = false;
      return gatewaySettingsRow(inserted.rows[0]);
    } catch (error) {
      if (open) await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  // 접속 차단: 가장 큰 version이 현재 판. 없으면 null. 표가 없으면(42P01) 저장된 목록이 없는 것으로 읽는다(Gateway 설정과 같음)
  async getGatewayAccess() {
    let result;
    try {
      result = await this.#pool.query(
        `SELECT version, revision, require_client_id, rules, updated_by, updated_at
         FROM dashboard_gateway_access
         ORDER BY version DESC
         LIMIT 1`,
      );
    } catch (error) {
      if (error?.code === '42P01') return null;
      throw error;
    }
    return result.rows.length ? gatewayAccessRow(result.rows[0]) : null;
  }

  // 판 행과 감사 행을 한 트랜잭션으로. 번호가 expected_version과 다르거나(0행) 같은 번호·revision이 동시에 들어오면(23505) AccessConflictError
  async saveGatewayAccess({ expectedVersion, revision, requireClientId, rules, updatedBy, audit }) {
    const client = await this.#pool.connect();
    let open = false;
    try {
      await client.query('BEGIN');
      open = true;
      let inserted = null;
      try {
        inserted = await client.query(
          `INSERT INTO dashboard_gateway_access (version, revision, require_client_id, rules, updated_by)
           SELECT $1::integer + 1, $2, $3::boolean, $4::jsonb, $5
           WHERE COALESCE((SELECT max(version) FROM dashboard_gateway_access), 0) = $1::integer
           RETURNING version, revision, require_client_id, rules, updated_by, updated_at`,
          [expectedVersion, revision, requireClientId, JSON.stringify(rules), updatedBy],
        );
      } catch (error) {
        if (error?.code !== '23505') throw error;
      }
      if (inserted?.rowCount !== 1) {
        await client.query('ROLLBACK');
        open = false;
        let currentVersion;
        try {
          const current = await client.query(
            'SELECT COALESCE(max(version), 0) AS version FROM dashboard_gateway_access',
          );
          currentVersion = Number(current.rows[0]?.version);
        } catch {
          currentVersion = undefined;
        }
        throw new AccessConflictError(Number.isSafeInteger(currentVersion) ? currentVersion : undefined);
      }
      await client.query(AUDIT_INSERT, auditParameters(audit));
      await client.query('COMMIT');
      open = false;
      return gatewayAccessRow(inserted.rows[0]);
    } catch (error) {
      if (open) await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async listClientAliases() {
    let result;
    try {
      result = await this.#pool.query(
        `SELECT client_id, alias, updated_by, updated_at
         FROM dashboard_client_aliases
         ORDER BY client_id COLLATE "C"`,
      );
    } catch (error) {
      if (error?.code === '42P01') return [];
      throw error;
    }
    return result.rows.map((row) => ({
      client_id: String(row.client_id),
      alias: String(row.alias),
      updated_by: String(row.updated_by),
      updated_at: new Date(row.updated_at).toISOString(),
    }));
  }

  // alias === null이면 삭제. 같은 값이면 쓰지 않고(changed: false) 감사 행도 남기지 않는다.
  // 이전 별칭은 같은 트랜잭션 안에서 잠그고 읽어 audit(이전 별칭) 함수에 넘긴다. 별칭 행과 감사 행은 한 트랜잭션
  async saveClientAlias({ clientId, alias, updatedBy, audit }) {
    const client = await this.#pool.connect();
    let open = false;
    try {
      await client.query('BEGIN');
      open = true;
      const current = await client.query(
        'SELECT alias FROM dashboard_client_aliases WHERE client_id = $1 FOR UPDATE',
        [clientId],
      );
      const previous = current.rowCount === 1 ? String(current.rows[0].alias) : null;
      if (previous === alias) {
        await client.query('COMMIT');
        open = false;
        return { previous, alias, changed: false };
      }
      if (alias === null)
        await client.query('DELETE FROM dashboard_client_aliases WHERE client_id = $1', [clientId]);
      else
        await client.query(
          `INSERT INTO dashboard_client_aliases (client_id, alias, updated_by)
           VALUES ($1, $2, $3)
           ON CONFLICT (client_id) DO UPDATE
             SET alias = EXCLUDED.alias, updated_by = EXCLUDED.updated_by, updated_at = now()`,
          [clientId, alias, updatedBy],
        );
      await client.query(AUDIT_INSERT, auditParameters(audit(previous)));
      await client.query('COMMIT');
      open = false;
      return { previous, alias, changed: true };
    } catch (error) {
      if (open) await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async list() {
    const result = await this.#pool.query(
      'SELECT event FROM dashboard_security_events ORDER BY occurred_at DESC',
    );
    return result.rows.map((row) => structuredClone(row.event));
  }

  // 질문 재시도 접기용 본문 해시(2026-10-16, docs/handoff/stats-rules-2026-10-16/SPEC.md 3.1과 같은 식 — Detection 보고서도 같은 SQL):
  // 이벤트 요청 ID와 같은 판정 기록이 정확히 1행이고 prompt가 있으면 md5(btrim(regexp_replace(prompt, '\s+', ' ', 'g'))), 아니면 없음.
  // 원문은 DB 밖으로 나오지 않는다. 전체를 매번 계산하면 실측 약 0.27초라, 한 번 구한 해시는 이벤트 번호로 기억하고
  // 새 질문·아직 해시가 없는 질문(판정 기록이 늦게 오는 경우)만 다시 묻는다. 돌려주는 값: 이벤트 번호 → 해시(해시 있는 것만)
  #promptHashCache = new Map();
  async promptHashes(events) {
    const missing = events
      .filter((event) => event.content_type === 'prompt' && event.request_id && !this.#promptHashCache.has(event.event_id))
      .map((event) => event.event_id);
    if (missing.length) {
      const result = await this.#pool.query(
        `SELECT e.event_id, h.prompt_hash
         FROM dashboard_security_events e
         CROSS JOIN LATERAL (
           SELECT CASE WHEN count(*) = 1 AND bool_and(x.prompt IS NOT NULL)
                       THEN md5(btrim(regexp_replace(max(x.prompt), '\\s+', ' ', 'g'))) END AS prompt_hash
           FROM decisions x WHERE x.request_id = e.request_id
         ) h
         WHERE e.event_id = ANY($1::text[])`,
        [missing],
      );
      for (const row of result.rows) if (row.prompt_hash) this.#promptHashCache.set(row.event_id, row.prompt_hash);
    }
    return new Map(events.flatMap((event) => (this.#promptHashCache.has(event.event_id) ? [[event.event_id, this.#promptHashCache.get(event.event_id)]] : [])));
  }

  async get(eventId) {
    const result = await this.#pool.query(
      'SELECT event FROM dashboard_security_events WHERE event_id = $1',
      [eventId],
    );
    return result.rowCount === 1 ? structuredClone(result.rows[0].event) : null;
  }

  async listAudit() {
    const result = await this.#pool.query(
      `SELECT audit_id, occurred_at, admin_id, action, target_type, target_id, result, changes
       FROM dashboard_admin_activity_history
       ORDER BY occurred_at DESC`,
    );
    return result.rows.map((row) => ({
      ...row,
      occurred_at: new Date(row.occurred_at).toISOString(),
    }));
  }

  async getEvidence(event, pageRequest) {
    if (!event.request_id) return buildMatchEvidence(event, []);
    const { decisions, documents } = await this.#evidenceRows(event);
    const proof = await this.#pool.query('SELECT gateway_evidence FROM dashboard_security_events WHERE event_id = $1',[event.event_id]);
    const segments = event.content_type === 'file' ? await this.#fileSegments(event) : null;
    return buildMatchEvidence(event, decisions.rows, documents.rows, pageRequest, proof.rows[0]?.gateway_evidence, segments);
  }

  // 같은 글자 비율(2026-10-16 '일치 비율' 통일): 근거 화면과 같은 판정 기록·문서(보존본 우선)의 입력·문서 본문
  async getComparisonBodies(event) {
    if (!event.request_id) return [];
    const { decisions, documents } = await this.#evidenceRows(event);
    return comparisonBodies(event, decisions.rows, documents.rows);
  }

  // 목록 캐시 열쇠용: 문서의 지금 판(본문은 읽지 않음)
  async documentVersions(docIds) {
    if (!docIds.length) return new Map();
    const result = await this.#pool.query('SELECT doc_id, version FROM documents WHERE doc_id = ANY($1::text[])', [docIds]);
    return new Map(result.rows.map((row) => [row.doc_id, row.version == null ? '' : String(row.version)]));
  }

  // 근거 화면·같은 글자 비율이 함께 쓰는 판정 기록·문서 행(getEvidence에 있던 조회를 그대로 옮김)
  async #evidenceRows(event) {
    const decisions = await this.#pool.query(
      `SELECT request_id, ts, decided_by, doc_id, doc_span, input_span, match_rate,
         reason, total_ms, text_chars, hash_status, signature_status, filename,
         format, content_type, prompt_kept, document_ref, length(prompt) AS prompt_chars, findings,
         CASE WHEN length(prompt) <= $2 THEN prompt ELSE NULL END AS prompt,
         CASE WHEN length(masked_text) <= $2 THEN masked_text ELSE NULL END AS masked_text
       FROM decisions WHERE request_id = $1 LIMIT 2`,
      [event.request_id, evidenceTextLimit],
    );
    const ids = [...new Set(event.detections.filter(d=>d.detector==='WINDOW_HASH').map(d=>d.matched_document_id))];
    const documents = ids.length ? await this.#pool.query(
      `SELECT doc_id, filename, version, classification, index_status,
         length(normalized_text) AS normalized_chars,
         CASE WHEN length(normalized_text) <= $2 THEN normalized_text ELSE NULL END AS normalized_text
       FROM documents WHERE doc_id = ANY($1::text[])`, [ids, evidenceTextLimit],
    ) : {rows:[]};
    const ref = decisions.rows.length===1 ? decisions.rows[0].document_ref : null;
    if (ref?.basis==='STABLE_INDEX_VERSION' && ids.includes(ref.doc_id) && Number.isSafeInteger(ref.version)
      && /^[a-f0-9]{64}$/.test(ref.normalized_sha256??'')) {
      const archived = await this.#pool.query(
        `SELECT doc_id,filename,version,normalized_sha256,length(normalized_text) AS normalized_chars,
          CASE WHEN length(normalized_text) <= $4 THEN normalized_text ELSE NULL END AS normalized_text
         FROM dashboard_document_versions WHERE doc_id=$1 AND version=$2 AND normalized_sha256=$3`,
        [ref.doc_id,ref.version,ref.normalized_sha256,evidenceTextLimit]);
      documents.rows.push(...archived.rows.map(d=>({...d,evidence_source:'EVENT_DOCUMENT_VERSION'})));
    }
    return { decisions, documents };
  }

  // 파일 업로드는 Gateway가 칸 단위로도 검사한다(요청 번호#f:0:docx:…). 칸별 원문·가린 결과로 문서 구조를 보여 준다
  // 2026-10-11 PDF 쪽(Detection)·HWP·HWPX 칸도 같은 모양. 가린 파일 재검사('…#verify')는 칸이 아니라 빼고, 파일 이름은 Claude 여러 파일 구분용
  async #fileSegments(event) {
    const result = await this.#pool.query(
      `SELECT request_id, decided_by, pii_hits, block_order, findings, filename, length(prompt) AS prompt_chars,
         CASE WHEN length(prompt) <= $2 THEN prompt ELSE NULL END AS prompt,
         CASE WHEN length(masked_text) <= $2 THEN masked_text ELSE NULL END AS masked_text
       FROM decisions WHERE request_id LIKE $1 ESCAPE '\\' AND request_id NOT LIKE '%#verify'
       ORDER BY ts, request_id LIMIT $3`,
      [`${event.request_id.replace(/[\\%_]/g, '\\$&')}#%`, fileSegmentTextLimit, fileSegmentLimit + 1],
    );
    return result.rows;
  }

  // 내 요청 기록(2026-10-09): 본인에게 보여 줄 근거 - 판정 기록 한 행(+ 파일 칸)만 읽는다
  async getOwnEvidence(event) {
    if (!event.request_id) return buildOwnEvidence(event, null, null);
    const decisions = await this.#pool.query(
      `SELECT request_id, decided_by, content_type, filename, text_chars, ts, findings,
         CASE WHEN length(prompt) <= $2 THEN prompt ELSE NULL END AS prompt,
         CASE WHEN length(masked_text) <= $2 THEN masked_text ELSE NULL END AS masked_text
       FROM decisions WHERE request_id = $1 LIMIT 2`,
      [event.request_id, evidenceTextLimit],
    );
    const decision = decisions.rows.length === 1 ? decisions.rows[0] : null;
    const segments = event.content_type === 'file' ? await this.#fileSegments(event) : null;
    return buildOwnEvidence(event, decision, segments);
  }

  async listDocuments() {
    const result = await this.#pool.query(
      `SELECT ${DOCUMENT_COLUMNS}
       FROM documents
       ORDER BY registered_at DESC`,
    );
    const detections = await this.#pool.query(`
      SELECT detection->>'matched_document_id' AS doc_id,
        count(DISTINCT event_id) FILTER (WHERE detection->>'match_type' = 'EXACT_DOCUMENT') AS exact_detection_count,
        count(DISTINCT event_id) FILTER (WHERE detection->>'match_type' IN ('TEXT_FRAGMENT', 'SIMILAR_DOCUMENT')) AS modified_partial_detection_count,
        max(occurred_at) AS last_detected_at
      FROM dashboard_security_events
      CROSS JOIN LATERAL jsonb_array_elements(event->'detections') AS detection
      WHERE detection->>'matched_document_id' IS NOT NULL
        AND client_id !~ $1   -- 시험·데모 이벤트는 문서 탐지 건수에서 뺀다(2026-10-10)
      GROUP BY detection->>'matched_document_id'
    `, [TEST_CLIENT_PATTERN]);
    const counts = new Map(detections.rows.map(row => [String(row.doc_id), row]));
    return result.rows.map(row => {
      const count = counts.get(String(row.doc_id));
      return {
        ...documentDto(row),
        exact_detection_count: Number(count?.exact_detection_count ?? 0),
        modified_partial_detection_count: Number(count?.modified_partial_detection_count ?? 0),
        ...(count?.last_detected_at ? { last_detected_at: new Date(count.last_detected_at).toISOString() } : {}),
      };
    });
  }

  async listPerformanceRuns(limit = 20) {
    const result = await this.#pool.query(
      `SELECT run_id, started_at, duration_sec, concurrent_clients, total_requests,
              throughput_rps, avg_latency_ms, p95_latency_ms, timeout_rate, test_context
       FROM dashboard_performance_runs
       ORDER BY started_at DESC
       LIMIT $1`,
      [limit],
    );
    return result.rows.map((row) => ({
      ...row,
      started_at: new Date(row.started_at).toISOString(),
      duration_sec: Number(row.duration_sec),
      concurrent_clients: Number(row.concurrent_clients),
      total_requests: Number(row.total_requests),
      throughput_rps: Number(row.throughput_rps),
      avg_latency_ms: Number(row.avg_latency_ms),
      p95_latency_ms: Number(row.p95_latency_ms),
      timeout_rate: Number(row.timeout_rate),
    }));
  }

  async recordPerformanceRun(run) {
    const result = await this.#pool.query(
      `INSERT INTO dashboard_performance_runs (
         run_id, started_at, duration_sec, concurrent_clients, total_requests,
         throughput_rps, avg_latency_ms, p95_latency_ms, timeout_rate, test_context
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
       ON CONFLICT (run_id) DO UPDATE SET
         started_at = EXCLUDED.started_at,
         duration_sec = EXCLUDED.duration_sec,
         concurrent_clients = EXCLUDED.concurrent_clients,
         total_requests = EXCLUDED.total_requests,
         throughput_rps = EXCLUDED.throughput_rps,
         avg_latency_ms = EXCLUDED.avg_latency_ms,
         p95_latency_ms = EXCLUDED.p95_latency_ms,
         timeout_rate = EXCLUDED.timeout_rate,
         test_context = EXCLUDED.test_context
       RETURNING run_id, started_at, duration_sec, concurrent_clients, total_requests,
                 throughput_rps, avg_latency_ms, p95_latency_ms, timeout_rate, test_context`,
      [
        run.run_id,
        run.started_at,
        run.duration_sec,
        run.concurrent_clients,
        run.total_requests,
        run.throughput_rps,
        run.avg_latency_ms,
        run.p95_latency_ms,
        run.timeout_rate,
        run.test_context ? JSON.stringify(run.test_context) : null,
      ],
    );
    const row = result.rows[0];
    return {
      ...row,
      started_at: new Date(row.started_at).toISOString(),
      duration_sec: Number(row.duration_sec),
      concurrent_clients: Number(row.concurrent_clients),
      total_requests: Number(row.total_requests),
      throughput_rps: Number(row.throughput_rps),
      avg_latency_ms: Number(row.avg_latency_ms),
      p95_latency_ms: Number(row.p95_latency_ms),
      timeout_rate: Number(row.timeout_rate),
    };
  }

  async registerDocument({ filename, data, registeredBy }) {
    const format = documentFormat(filename, data);
    const documentId = documentIdFromFilename(filename);
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await client.query(
        `SELECT ${DOCUMENT_COLUMNS}, original = $1 AS same_content
         FROM documents WHERE doc_id = $2 FOR UPDATE`,
        [data, documentId],
      );
      let outcome;
      let row;
      if (existing.rowCount === 0) {
        const inserted = await client.query(
          `INSERT INTO documents (
             doc_id, filename, original, version, status, index_status,
             registered_at, registered_by, format
           ) VALUES ($1, $2, $3, 1, 'active', 'pending', now(), $4, $5)
           RETURNING ${DOCUMENT_COLUMNS}`,
          [documentId, filename, data, registeredBy, format],
        );
        outcome = 'created';
        [row] = inserted.rows;
      } else {
        const current = existing.rows[0];
        if (
          current.same_content &&
          String(current.status).toLowerCase() === 'active' &&
          String(current.index_status).toLowerCase() !== 'error'
        ) {
          outcome = 'unchanged';
          row = current;
        } else {
          const updated = await client.query(
            `UPDATE documents
             SET filename = $1, original = $2, version = version + 1,
                 status = 'active', index_status = 'pending', index_error = NULL,
                 retired_at = NULL, registered_at = now(), registered_by = $3,
                 format = $4
             WHERE doc_id = $5
             RETURNING ${DOCUMENT_COLUMNS}`,
            [filename, data, registeredBy, format, documentId],
          );
          outcome = 'updated';
          [row] = updated.rows;
        }
      }
      await client.query('COMMIT');
      return { outcome, document: documentDto(row) };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async changeDocumentStatus(documentId, requestedStatus) {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const selected = await client.query(
        `SELECT ${DOCUMENT_COLUMNS} FROM documents WHERE doc_id = $1 FOR UPDATE`,
        [documentId],
      );
      if (selected.rowCount === 0) {
        await client.query('ROLLBACK');
        return null;
      }
      const current = selected.rows[0];
      const previousStatus =
        String(current.status).toLowerCase() === 'active' ? 'ACTIVE' : 'INACTIVE';
      if (previousStatus === requestedStatus) {
        await client.query('COMMIT');
        return {
          changed: false,
          previousStatus,
          document: documentDto(current),
        };
      }
      const updated = await client.query(
        requestedStatus === 'ACTIVE'
          ? `UPDATE documents
             SET status = 'active', version = version + 1, index_status = 'pending',
                 index_error = NULL, retired_at = NULL
             WHERE doc_id = $1 RETURNING ${DOCUMENT_COLUMNS}`
          : `UPDATE documents
             SET status = 'retired', index_status = 'pending', index_error = NULL,
                 retired_at = now()
             WHERE doc_id = $1 RETURNING ${DOCUMENT_COLUMNS}`,
        [documentId],
      );
      await client.query('COMMIT');
      return {
        changed: true,
        previousStatus,
        document: documentDto(updated.rows[0]),
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  // ───────────────────────── 보호 문서 본문 보기 (2026-10-13)
  // 원본 바이트는 아래 getDocumentOriginal만 읽는다. 목록·등록·상태 변경(DOCUMENT_COLUMNS)과 이 조회는 크기(octet_length)만 본다
  async getDocumentForView(documentId) {
    const result = await this.#pool.query(
      `SELECT ${VIEW_COLUMNS} FROM documents WHERE doc_id = $1`,
      [documentId],
    );
    return result.rows.length ? documentViewRow(result.rows[0]) : null;
  }

  // 크기가 maxBytes 이하일 때만 DB가 바이트를 보낸다(넘으면 data = null, 크기·판만). 판과 바이트를 한 행에서 같이 읽어 서로 어긋나지 않는다
  async getDocumentOriginal(documentId, maxBytes) {
    const result = await this.#pool.query(
      `SELECT ${VIEW_COLUMNS},
         CASE WHEN octet_length(original) <= $2 THEN original ELSE NULL END AS original
       FROM documents WHERE doc_id = $1`,
      [documentId, maxBytes],
    );
    if (!result.rows.length) return null;
    const row = result.rows[0];
    const data = row.original instanceof Uint8Array
      ? Buffer.from(row.original.buffer, row.original.byteOffset, row.original.byteLength)
      : null;
    return { ...documentViewRow(row), data };
  }

  // 탐지 기준 텍스트(normalized_text). 근거 화면과 같은 글자 수 상한을 넘으면 글자 수만(text = null)
  async getDocumentText(documentId, maxChars) {
    const result = await this.#pool.query(
      `SELECT ${VIEW_COLUMNS}, length(normalized_text) AS text_chars,
         CASE WHEN length(normalized_text) <= $2 THEN normalized_text ELSE NULL END AS normalized_text
       FROM documents WHERE doc_id = $1`,
      [documentId, maxChars],
    );
    if (!result.rows.length) return null;
    const row = result.rows[0];
    return {
      ...documentViewRow(row),
      text_chars: row.text_chars === null || row.text_chars === undefined ? null : Number(row.text_chars),
      text: typeof row.normalized_text === 'string' ? row.normalized_text : null,
    };
  }

  // 시스템 상태(2026-10-12): 연결이 되는지만 본다. 걸린 시간은 부르는 쪽이 잰다(같은 풀을 쓰므로 대기열이 밀려 있으면 그만큼 늘어난다)
  async ping() {
    await this.#pool.query('SELECT 1');
  }

  // 가장 최근 이벤트가 저장된 시각(occurred_at 인덱스로 한 줄만 읽는다). 이벤트가 없으면 null
  async latestEventStoredAt() {
    const result = await this.#pool.query(
      // 저장 시각이 가장 늦은 것(2026-10-15 감사 19번): 재전송으로 옛 이벤트가 늦게 들어와도 '마지막 이벤트 저장'이 바뀐다
      'SELECT created_at FROM dashboard_security_events ORDER BY created_at DESC LIMIT 1',
    );
    return result.rowCount === 1 ? new Date(result.rows[0].created_at).toISOString() : null;
  }

  async close() {
    await this.#pool.end();
  }
}
