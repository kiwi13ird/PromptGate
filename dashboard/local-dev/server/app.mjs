import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { JsonEventStore, EventConflictError } from './event-store.mjs';
import { lookupRequest } from './demo-tools.mjs';
import { buildOwnEvidence } from './match-evidence.mjs';
import { isTestEvent } from './test-events.mjs';
import {
  canonicalEventToDto,
  validateCanonicalEvent,
  ValidationError,
} from './validation.mjs';

const JSON_LIMIT_BYTES = 256 * 1024;
const DOCUMENT_LIMIT_BYTES = 20 * 1024 * 1024;
const MULTIPART_LIMIT_BYTES = DOCUMENT_LIMIT_BYTES + 1024 * 1024;
const SESSION_COOKIE = 'local_admin_session';
const SEVERITY_PRIORITY = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const PERIOD_MS = { '24H': 86_400_000, '7D': 604_800_000, '30D': 2_592_000_000 };

function hashSecret(value) {
  return createHash('sha256').update(value).digest();
}

function secretsEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  return timingSafeEqual(hashSecret(left), hashSecret(right));
}

function setCors(response, request, allowedOrigin) {
  const origin = request.headers.origin;
  if (origin && origin === allowedOrigin) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Access-Control-Allow-Credentials', 'true');
    response.setHeader('Vary', 'Origin');
  }
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(body);
}

function sendError(response, status, code, message, details) {
  sendJson(response, status, {
    error: {
      code,
      message,
      ...(details ? { details } : {}),
    },
  });
}

async function readJson(request, limit = JSON_LIMIT_BYTES) {
  const contentType = request.headers['content-type'] ?? '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    const error = new Error('Content-Type must be application/json.');
    error.statusCode = 415;
    error.code = 'UNSUPPORTED_MEDIA_TYPE';
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) {
      const error = new Error('Request body is too large.');
      error.statusCode = 413;
      error.code = 'PAYLOAD_TOO_LARGE';
      throw error;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    const error = new Error('Request body is required.');
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const error = new Error('Request body must be valid JSON.');
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
}

async function readBody(request, limit) {
  const contentLength = Number(request.headers['content-length'] ?? 0);
  if (Number.isFinite(contentLength) && contentLength > limit) {
    const error = new Error('Request body is too large.');
    error.statusCode = 413;
    error.code = 'PAYLOAD_TOO_LARGE';
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) {
      const error = new Error('Request body is too large.');
      error.statusCode = 413;
      error.code = 'PAYLOAD_TOO_LARGE';
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readDocumentUpload(request) {
  const contentType = request.headers['content-type'] ?? '';
  if (!contentType.toLowerCase().startsWith('multipart/form-data;')) {
    const error = new Error('Content-Type must be multipart/form-data.');
    error.statusCode = 415;
    error.code = 'UNSUPPORTED_MEDIA_TYPE';
    throw error;
  }
  const raw = await readBody(request, MULTIPART_LIMIT_BYTES);
  let form;
  try {
    form = await new Request('http://localhost/api/documents', {
      method: 'POST',
      headers: { 'Content-Type': contentType },
      body: raw,
    }).formData();
  } catch {
    const error = new Error('Malformed multipart document upload.');
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  const entries = [...form.entries()];
  const file = form.get('file');
  if (
    entries.length !== 1 ||
    entries[0][0] !== 'file' ||
    !file ||
    typeof file === 'string' ||
    typeof file.arrayBuffer !== 'function'
  ) {
    const error = new Error('Exactly one file field is required.');
    error.statusCode = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  if (file.size <= 0 || file.size > DOCUMENT_LIMIT_BYTES) {
    const error = new Error('Document must be between 1 byte and 20 MiB.');
    error.statusCode = file.size > DOCUMENT_LIMIT_BYTES ? 413 : 422;
    error.code = file.size > DOCUMENT_LIMIT_BYTES ? 'PAYLOAD_TOO_LARGE' : 'VALIDATION';
    throw error;
  }
  const filename = String(file.name ?? '').split(/[\\/]/).pop()?.trim();
  if (!filename || filename.length > 255) {
    const error = new Error('Document filename is invalid.');
    error.statusCode = 422;
    error.code = 'VALIDATION';
    throw error;
  }
  return { filename, data: Buffer.from(await file.arrayBuffer()) };
}

function parseCookies(request) {
  const cookies = new Map();
  for (const part of (request.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key) cookies.set(key, value);
  }
  return cookies;
}

function requireSession(request, sessions) {
  const token = parseCookies(request).get(SESSION_COOKIE);
  if (!token || !sessions.has(token)) return null;
  return sessions.get(token);
}

function requireIngestToken(request, expectedToken) {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) return false;
  return secretsEqual(authorization.slice('Bearer '.length), expectedToken);
}

function enumQuery(searchParams, name, allowed, fallback) {
  const value = searchParams.get(name);
  if (value === null || value === '') return fallback;
  if (!allowed.has(value)) {
    const error = new Error(`Unsupported ${name} query value.`);
    error.statusCode = 400;
    throw error;
  }
  return value;
}

function positiveIntegerQuery(searchParams, name, fallback, max) {
  const value = searchParams.get(name);
  if (value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) {
    const error = new Error(`${name} must be an integer between 1 and ${max}.`);
    error.statusCode = 400;
    throw error;
  }
  return parsed;
}

function documentIds(event) {
  return event.detections.flatMap((detection) =>
    'matched_document_id' in detection ? [detection.matched_document_id] : [],
  );
}

function eventScoreKinds(event) {
  return event.detections.flatMap((detection) => {
    if (detection.detector === 'WINDOW_HASH') return [detection.score_kind];
    if (detection.detector === 'MINHASH') return ['SIMILARITY'];
    if (detection.detector === 'SIGNATURE' && detection.confidence !== undefined)
      return ['CONFIDENCE'];
    return [];
  });
}

// ───────────────────────── 질문과 첨부 파일 연결 (2026-10-09)
// ChatGPT는 파일을 먼저 올리고 질문을 따로 보낸다. Gateway가 파일 이벤트에 파일 번호(file_id)를,
// 질문 이벤트에 붙은 파일 번호들(attached_file_ids)을 남기면 같은 브라우저(client_id)의 같은 번호끼리 잇는다.
// 시간·사용자로 짐작하지 않는다 - 번호가 같을 때만 묶는다.
const ACTION_RANK = { ALLOW: 0, MASK: 1, BLOCK: 2 };
const ATTACH_WINDOW_MS = 24 * 60 * 60 * 1000;
const eventAction = (event) => event.final_action ?? event.action;

export function attachmentLinks(events) {
  const files = new Map();
  for (const event of events) {
    if (event.content_type !== 'file' || typeof event.file_id !== 'string') continue;
    const key = `${event.client_id}\n${event.file_id}`;
    if (!files.has(key)) files.set(key, []);
    files.get(key).push(event);
  }
  const attached = new Map();
  const parents = new Map();
  for (const event of events) {
    if (event.content_type === 'file' || !Array.isArray(event.attached_file_ids)) continue;
    const at = Date.parse(event.occurred_at);
    const list = [];
    for (const fileId of event.attached_file_ids)
      for (const file of files.get(`${event.client_id}\n${fileId}`) ?? []) {
        const fileAt = Date.parse(file.occurred_at);
        if (fileAt <= at + 60_000 && at - fileAt <= ATTACH_WINDOW_MS && !list.includes(file)) list.push(file);
      }
    if (!list.length) continue;
    list.sort((left, right) => Date.parse(left.occurred_at) - Date.parse(right.occurred_at));
    attached.set(event.event_id, list);
    for (const file of list) {
      if (!parents.has(file.event_id)) parents.set(file.event_id, []);
      parents.get(file.event_id).push(event);
    }
  }
  return { attached, parents };
}

// 목록 묶음: 첨부된 파일 이벤트는 질문 아래로 들어가고, 묶음의 조치는 질문·파일 중 가장 강한 것
export function groupAttachments(events) {
  const { attached, parents } = attachmentLinks(events);
  const grouped = [];
  for (const event of events) {
    if (parents.has(event.event_id)) continue;
    const files = attached.get(event.event_id);
    if (!files) {
      grouped.push(event);
      continue;
    }
    const strongest = [event, ...files].reduce((best, item) =>
      (ACTION_RANK[eventAction(item)] ?? 0) > (ACTION_RANK[eventAction(best)] ?? 0) ? item : best);
    grouped.push({ ...event, attached_files: files, group_final_action: eventAction(strongest) });
  }
  return grouped;
}

// 거르기·검색은 묶음 전체로 본다(조치는 묶음 조치, 탐지는 질문·파일 모두)
function groupFilterView(event) {
  if (!event.attached_files) return event;
  const members = [event, ...event.attached_files];
  return {
    ...event,
    action: event.group_final_action,
    final_action: event.group_final_action,
    detections: members.flatMap((item) => item.detections ?? []),
    detection_outcome: members.some((item) => item.detection_outcome === 'MATCH') ? 'MATCH' : event.detection_outcome,
  };
}

function attachedSummary(event) {
  return {
    event_id: event.event_id,
    request_id: event.request_id,
    occurred_at: event.occurred_at,
    final_action: eventAction(event),
    content_type: event.content_type,
  };
}

// ───────────────────────── 내 요청 기록 (2026-10-09)
// 관리자 로그인 없이, 확장 프로그램의 열람 키(X-Viewer-Key)가 맞는 요청만. 서버에는 키의 지문만 있다.
const VIEWER_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const OWN_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export function viewerKeyHash(request) {
  const key = request.headers['x-viewer-key'];
  if (typeof key !== 'string' || !VIEWER_KEY_PATTERN.test(key)) return null;
  return createHash('sha256').update(key).digest('hex');
}

function ownEntityCounts(event) {
  const counts = new Map();
  for (const detection of event.detections ?? [])
    for (const item of detection.entity_counts ?? []) counts.set(item.entity_type, (counts.get(item.entity_type) ?? 0) + item.count);
  return [...counts.entries()].map(([entity_type, count]) => ({ entity_type, count }));
}

function ownItem(event) {
  return {
    event_id: event.event_id,
    occurred_at: event.occurred_at,
    target_llm: event.target_llm,
    content_type: event.content_type,
    final_action: eventAction(event),
    ...(event.group_final_action ? { group_final_action: event.group_final_action } : {}),
    protected_document: (event.detections ?? []).some((d) => d.detector !== 'SIGNATURE'),
    entity_counts: ownEntityCounts(event),
    ...(event.attached_files ? { attached_files: event.attached_files.map(ownItem) } : {}),
  };
}

export function ownRequests(events, hash, now = Date.now()) {
  const mine = events.filter((event) => event.viewer_key_hash === hash && now - Date.parse(event.occurred_at) <= OWN_WINDOW_MS);
  const items = groupAttachments(mine)
    .filter((event) => ['BLOCK', 'MASK'].includes(event.group_final_action ?? eventAction(event)))
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at))
    .slice(0, 100)
    .map(ownItem);
  return { items, window_days: 7 };
}

function listEvents(events, searchParams, now = Date.now(), documentNames = new Map()) {
  const period = enumQuery(
    searchParams,
    'period',
    new Set(['24H', '7D', '30D']),
    '30D',
  );
  const finalAction = enumQuery(
    searchParams,
    'final_action',
    new Set(['ALLOW', 'BLOCK', 'MASK']),
    null,
  );
  const recommendedAction = enumQuery(
    searchParams,
    'recommended_action',
    new Set(['ALLOW', 'BLOCK', 'MASK']),
    null,
  );
  const detector = enumQuery(
    searchParams,
    'detector',
    new Set(['SHA256', 'WINDOW_HASH', 'MINHASH', 'SIGNATURE']),
    null,
  );
  const matchType = enumQuery(
    searchParams,
    'match_type',
    new Set([
      'EXACT_DOCUMENT',
      'TEXT_FRAGMENT',
      'SIMILAR_DOCUMENT',
      'SIGNATURE_RULE',
    ]),
    null,
  );
  const scoreKind = enumQuery(
    searchParams,
    'score_kind',
    new Set(['COVERAGE', 'SIMILARITY', 'CONFIDENCE']),
    null,
  );
  const degraded = enumQuery(
    searchParams,
    'degraded',
    new Set(['YES', 'NO']),
    null,
  );
  const detectionOutcome = enumQuery(
    searchParams,
    'detection_outcome',
    new Set(['MATCH', 'NO_MATCH', 'UNAVAILABLE']),
    null,
  );
  const degradedReason = enumQuery(
    searchParams,
    'degraded_reason',
    new Set(['TIMEOUT', 'UNREACHABLE', 'PARSE_ERROR', 'OTHER']),
    null,
  );
  const failurePolicy = enumQuery(
    searchParams,
    'failure_policy',
    new Set(['FAIL_OPEN', 'FAIL_CLOSED']),
    null,
  );
  const severity = enumQuery(
    searchParams,
    'severity',
    new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    null,
  );
  const status = enumQuery(
    searchParams,
    'status',
    new Set(['NEW', 'INVESTIGATING', 'RESOLVED']),
    null,
  );
  const targetLlm = enumQuery(
    searchParams,
    'target_llm',
    new Set(['ChatGPT', 'Gemini', 'Claude']),
    null,
  );
  const sort = enumQuery(
    searchParams,
    'sort',
    new Set(['OCCURRED_AT_DESC', 'OCCURRED_AT_ASC', 'SEVERITY_DESC']),
    'OCCURRED_AT_DESC',
  );
  const page = positiveIntegerQuery(searchParams, 'page', 1, 1_000_000);
  const pageSize = positiveIntegerQuery(searchParams, 'page_size', 20, 100);
  const query = (searchParams.get('query') ?? '').trim().toLowerCase();
  const documentId = (searchParams.get('document_id') ?? '').trim();
  const threshold = now - PERIOD_MS[period];
  const group = enumQuery(searchParams, 'group', new Set(['request']), null);
  // 탐지 정보 종류(2026-10-10): 개인정보·자격증명·기밀 키워드 중 하나라도 포함된 이벤트
  const category = enumQuery(searchParams, 'entity_category', new Set(['PII', 'CREDENTIAL', 'KEYWORD']), null);
  const candidates = group === 'request' ? groupAttachments(events) : events;

  const filtered = candidates.filter((item) => {
    const event = groupFilterView(item);
    const recommended =
      event.recommended_action ??
      event.detections[0]?.recommended_action ??
      event.detections[0]?.action;
    const searchable = [
      event.event_id,
      event.request_id,
      event.client_id,
      ...documentIds(event),
      ...documentIds(event).map(id => documentNames.get(id)),
      ...event.detections.flatMap(item => [item.matched_document_name, item.outbound_document_name]),
      ...(event.attached_files ?? []).flatMap(item => [item.event_id, item.request_id]),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return (
      Date.parse(event.occurred_at) >= threshold &&
      (!query || searchable.includes(query)) &&
      (!finalAction || (event.final_action ?? event.action) === finalAction) &&
      (!recommendedAction || recommended === recommendedAction) &&
      (!detector || event.detections.some((item) => item.detector === detector)) &&
      (!matchType || event.detections.some((item) => item.match_type === matchType)) &&
      (!scoreKind || eventScoreKinds(event).includes(scoreKind)) &&
      (!degraded || (degraded === 'YES' ? event.degraded === true : event.degraded !== true)) &&
      (!detectionOutcome || event.detection_outcome === detectionOutcome) &&
      (!degradedReason || event.degraded_reason === degradedReason) &&
      (!failurePolicy || event.failure_policy === failurePolicy) &&
      (!documentId || documentIds(event).includes(documentId)) &&
      (!severity || event.severity === severity) &&
      (!status || event.status === status) &&
      (!category || event.detections.some((item) => (item.entity_counts ?? []).some((entity) => entityCategory(entity.entity_type) === category))) &&
      (!targetLlm || event.target_llm === targetLlm)
    );
  });

  filtered.sort((left, right) => {
    if (sort === 'OCCURRED_AT_ASC')
      return Date.parse(left.occurred_at) - Date.parse(right.occurred_at);
    if (sort === 'SEVERITY_DESC')
      return (
        SEVERITY_PRIORITY[right.severity ?? 'LOW'] -
          SEVERITY_PRIORITY[left.severity ?? 'LOW'] ||
        Date.parse(right.occurred_at) - Date.parse(left.occurred_at)
      );
    return Date.parse(right.occurred_at) - Date.parse(left.occurred_at);
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  return {
    items: filtered.slice((safePage - 1) * pageSize, safePage * pageSize),
    total: filtered.length,
    page: safePage,
    page_size: pageSize,
    total_pages: totalPages,
  };
}

function increment(map, key, blocked = false) {
  const current = map.get(key) ?? { key, count: 0, blocked: 0 };
  current.count += 1;
  if (blocked) current.blocked += 1;
  map.set(key, current);
}

// 탐지 유형 → 정책 분류(Detection과 같은 기준). 이벤트에 정책 ID가 없어 정책별 적중은 이 분류로 센다
const CREDENTIAL_TYPES = new Set(['GENERIC_API_KEY', 'GITHUB_TOKEN', 'PASSWORD', 'AWS_ACCESS_KEY', 'PRIVATE_KEY']);
export const entityCategory = (type) => (type === 'DOC_KEYWORD' ? 'KEYWORD' : CREDENTIAL_TYPES.has(type) ? 'CREDENTIAL' : 'PII');

export function dashboardStats(events, searchParams, now = Date.now()) {
  const period = enumQuery(
    searchParams,
    'period',
    new Set(['24H', '7D', '30D']),
    '30D',
  );
  const threshold = now - PERIOD_MS[period];
  const selected = events
    .filter((event) => Date.parse(event.occurred_at) >= threshold)
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at));
  const actionOf = (event) => event.final_action ?? event.action;
  const blocked = selected.filter((event) => actionOf(event) === 'BLOCK');
  const processing = selected
    .map((event) => event.processing_ms)
    .filter((value) => Number.isFinite(value));
  const documentCounts = new Map();
  const trend = new Map();

  for (const event of selected) {
    const isBlocked = actionOf(event) === 'BLOCK';
    for (const documentId of documentIds(event)) increment(documentCounts, documentId, isBlocked);
    const bucket = event.occurred_at.slice(0, 10);
    const point = trend.get(bucket) ?? { bucket, total: 0, block: 0, mask: 0, allow: 0 };
    const action = actionOf(event).toLowerCase();
    point.total += 1;
    point[action] += 1;
    trend.set(bucket, point);
  }

  const orderedCounts = (map, limit) =>
    [...map.values()]
      .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key))
      .slice(0, limit)
      .map((item) => ({
        key: item.key,
        count: item.count,
        ...(item.blocked > 0 ? { blocked: item.blocked } : {}),
      }));
  const enforcedBlocks = blocked.filter((event) => event.enforcement?.applied === true).length;

  // 보안 현황 그래프(2026-10-10): 정보 유형·보호 문서 상위, 서비스·입력 형태별 조치, 요일·시간대 분포(한국 시간, 차단·마스킹만)
  const entityCounts = new Map();
  const llmActions = new Map();
  const contentActions = new Map(['prompt', 'file'].map((key) => [key, { key, block: 0, mask: 0, allow: 0 }]));
  const heatmap = Array.from({ length: 7 }, () => Array(24).fill(0));
  const categoryCounts = new Map(['PII', 'CREDENTIAL', 'KEYWORD'].map((key) => [key, { key, events: 0, values: 0 }]));
  const entityEvents = new Map();   // 유형별로 그 유형이 하나라도 나온 이벤트 수(유형 정책의 적중용)
  for (const event of selected) {
    const action = String(actionOf(event)).toLowerCase();
    const categories = new Set();
    const types = new Set();
    for (const detection of event.detections)
      for (const item of detection.entity_counts ?? []) {
        types.add(item.entity_type);
        entityCounts.set(item.entity_type, (entityCounts.get(item.entity_type) ?? 0) + item.count);
        const category = entityCategory(item.entity_type);
        categoryCounts.get(category).values += item.count;
        categories.add(category);
      }
    for (const category of categories) categoryCounts.get(category).events += 1;
    for (const type of types) entityEvents.set(type, (entityEvents.get(type) ?? 0) + 1);
    const llm = llmActions.get(event.target_llm) ?? { key: event.target_llm, block: 0, mask: 0, allow: 0 };
    llm[action] += 1;
    llmActions.set(event.target_llm, llm);
    contentActions.get(event.content_type === 'file' ? 'file' : 'prompt')[action] += 1;
    if (action !== 'allow') {
      const kst = new Date(Date.parse(event.occurred_at) + 9 * 60 * 60 * 1000);
      heatmap[kst.getUTCDay()][kst.getUTCHours()] += 1;
    }
  }
  const actionTotal = (row) => row.block + row.mask + row.allow;

  return {
    total: selected.length,
    block: blocked.length,
    mask: selected.filter((event) => actionOf(event) === 'MASK').length,
    allow: selected.filter((event) => actionOf(event) === 'ALLOW').length,
    degraded: selected.filter((event) => event.degraded === true).length,
    enforcement_rate: blocked.length === 0 ? 0 : enforcedBlocks / blocked.length,
    action_mismatch: selected.filter(
      (event) =>
        event.recommended_action !== undefined &&
        event.recommended_action !== actionOf(event),
    ).length,
    new_events: selected.filter((event) => event.status === 'NEW').length,
    average_processing_ms:
      processing.length === 0
        ? 0
        : processing.reduce((total, value) => total + value, 0) / processing.length,
    detection_status:
      selected.length === 0
        ? 'UNKNOWN'
        : selected.some((event) => event.degraded === true)
          ? 'DEGRADED'
          : 'HEALTHY',
    ...(selected[0] ? { last_success_at: selected[0].occurred_at } : {}),
    trend: [...trend.values()].sort((left, right) => left.bucket.localeCompare(right.bucket)),
    recent: selected.slice(0, 10),
    insights: {
      entity_counts: [...entityCounts]
        .map(([key, count]) => ({ key, count }))
        .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key)),
      documents: orderedCounts(documentCounts, 5),
      llm_actions: [...llmActions.values()].sort((left, right) => actionTotal(right) - actionTotal(left) || left.key.localeCompare(right.key)),
      content_actions: [...contentActions.values()],
      heatmap,
      category_counts: [...categoryCounts.values()],
      entity_event_counts: [...entityEvents]
        .map(([key, count]) => ({ key, count }))
        .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key)),
    },
  };
}

function eventsForPeriod(events, searchParams, now = Date.now()) {
  const period = enumQuery(
    searchParams,
    'period',
    new Set(['24H', '7D', '30D']),
    '24H',
  );
  const selected = events
    .filter((event) => Date.parse(event.occurred_at) >= now - PERIOD_MS[period])
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at));
  return { period, selected };
}

function percentile95(values) {
  if (values.length === 0) return undefined;
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * 0.95) - 1)];
}

function trafficSummary(events, searchParams, now = Date.now()) {
  const { selected } = eventsForPeriod(events, searchParams, now);
  const processing = selected
    .map((event) => event.processing_ms)
    .filter((value) => Number.isFinite(value));
  const degraded = selected.filter((event) => event.degraded === true).length;
  const activeWindow = selected.filter(
    (event) => Date.parse(event.occurred_at) >= now - 5 * 60 * 1000,
  );
  const recentMinute = selected.filter(
    (event) => Date.parse(event.occurred_at) >= now - 60 * 1000,
  );
  return compactObject({
    metric_source: 'STORED_EVENTS',
    event_count: selected.length,
    latency_sample_count: processing.length,
    active_clients: new Set(activeWindow.map((event) => event.client_id).filter(id => id && id !== 'unknown-client' && id !== 'legacy-gateway')).size,
    client_identity_incomplete: activeWindow.some(event => !event.client_id || ['unknown-client', 'legacy-gateway'].includes(event.client_id)),
    requests_per_sec: recentMinute.length / 60,
    average_latency_ms:
      processing.length === 0
        ? undefined
        : processing.reduce((total, value) => total + value, 0) / processing.length,
    p95_latency_ms: percentile95(processing),
    timeout_rate:
      selected.length === 0
        ? 0
        : selected.filter((event) => event.degraded_reason === 'TIMEOUT').length /
          selected.length,
    degraded_rate: selected.length === 0 ? 0 : degraded / selected.length,
    // Historical events do not establish the current gateway's health.
    gateway_status: 'UNKNOWN',
  });
}

function trafficTimeSeries(events, searchParams, now = Date.now()) {
  const { period, selected } = eventsForPeriod(events, searchParams, now);
  const buckets = new Map();
  for (const event of selected) {
    const date = new Date(event.occurred_at);
    if (period === '24H') date.setUTCMinutes(0, 0, 0);
    else date.setUTCHours(0, 0, 0, 0);
    const timestamp = date.toISOString();
    const bucket = buckets.get(timestamp) ?? {
      timestamp,
      request_count: 0,
      allow_count: 0,
      mask_count: 0,
      block_count: 0,
      processing: [],
    };
    const action = event.final_action ?? event.action;
    bucket.request_count += 1;
    if (action === 'ALLOW') bucket.allow_count += 1;
    if (action === 'MASK') bucket.mask_count += 1;
    if (action === 'BLOCK') bucket.block_count += 1;
    if (Number.isFinite(event.processing_ms)) bucket.processing.push(event.processing_ms);
    buckets.set(timestamp, bucket);
  }
  return [...buckets.values()]
    .sort((left, right) => left.timestamp.localeCompare(right.timestamp))
    .map(({ processing, ...bucket }) =>
      compactObject({
        ...bucket,
        average_latency_ms:
          processing.length === 0
            ? undefined
            : processing.reduce((total, value) => total + value, 0) /
              processing.length,
        p95_latency_ms: percentile95(processing),
      }),
    );
}

function trafficRecent(events, searchParams, now = Date.now()) {
  const { selected } = eventsForPeriod(events, searchParams, now);
  const limit = positiveIntegerQuery(searchParams, 'limit', 50, 100);
  return selected.slice(0, limit).map((event) => {
    const detection = event.detections[0];
    const score =
      detection?.detector === 'WINDOW_HASH'
        ? detection.score
        : detection?.detector === 'MINHASH'
          ? detection.similarity
          : detection?.detector === 'SIGNATURE'
            ? detection.confidence
            : undefined;
    const scoreKind =
      detection?.detector === 'WINDOW_HASH'
        ? 'COVERAGE'
        : detection?.detector === 'MINHASH'
          ? 'SIMILARITY'
          : detection?.detector === 'SIGNATURE' && detection.confidence !== undefined
            ? 'CONFIDENCE'
            : undefined;
    return compactObject({
      request_id: event.request_id ?? event.event_id,
      event_id: event.event_id,
      timestamp: event.occurred_at,
      client_id: event.client_id,
      target_llm: event.target_llm,
      request_type: event.content_type === 'file' ? 'FILE' : 'PROMPT',
      detector: detection?.detector,
      score,
      score_kind: scoreKind,
      action: event.final_action ?? event.action,
      latency_ms: event.processing_ms,
      degraded: event.degraded,
    });
  });
}

function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => item !== undefined),
  );
}

function finiteNumber(value, name, { integer = false, min = 0, max } = {}) {
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    (integer && !Number.isInteger(value)) ||
    value < min ||
    (max !== undefined && value > max)
  ) {
    const error = new Error(`${name} is invalid.`);
    error.statusCode = 422;
    error.code = 'VALIDATION';
    throw error;
  }
  return value;
}

// Gateway 상태(2026-10-10): Gateway가 몇 초마다 보내는 실시간 지표가 2분 안에 왔는지로 판정한다.
// 트래픽 화면과 같은 규칙 — 완료 요청이 없으면 상태는 판정하지 않고(요청 대기), 오류·검사 장애가 있으면 DEGRADED
export function liveGatewayState(metrics, now = Date.now()) {
  if (!metrics) return { status: 'UNKNOWN', metricsStatus: 'NOT_RECEIVED' };
  const age = now - Date.parse(metrics.received_at);
  if (!(age <= 120_000)) return { status: 'UNKNOWN', metricsStatus: 'STALE' };
  return {
    metricsStatus: 'FRESH',
    completed: metrics.completed_requests,
    status: metrics.completed_requests === 0 ? 'UNKNOWN'
      : metrics.degraded_rate > 0 || metrics.error_requests > 0 ? 'DEGRADED' : 'HEALTHY',
  };
}

function gatewayMetricsPayload(value) {
  const fields = [
    'active_clients',
    'concurrent_requests',
    'requests_per_sec',
    'avg_latency_ms',
    'p95_latency_ms',
    'timeout_rate',
    'degraded_rate',
    'total_requests',
    'completed_requests',
    'error_requests',
    'action_distribution',
    'llm_distribution',
    'detector_distribution',
    'window_seconds',
    'event_delivery',
  ];
  const body = exactObject(value, fields, fields.filter(name=>name!=='event_delivery'));
  for (const name of [
    'active_clients',
    'concurrent_requests',
    'total_requests',
    'completed_requests',
    'error_requests',
    'window_seconds',
  ])
    finiteNumber(body[name], name, { integer: true });
  for (const name of ['requests_per_sec', 'avg_latency_ms', 'p95_latency_ms'])
    finiteNumber(body[name], name);
  for (const name of ['timeout_rate', 'degraded_rate'])
    finiteNumber(body[name], name, { max: 1 });
  for (const name of [
    'action_distribution',
    'llm_distribution',
    'detector_distribution',
  ]) {
    if (!body[name] || typeof body[name] !== 'object' || Array.isArray(body[name])) {
      const error = new Error(`${name} must be an object.`);
      error.statusCode = 422;
      error.code = 'VALIDATION';
      throw error;
    }
    for (const count of Object.values(body[name]))
      finiteNumber(count, `${name} count`, { integer: true });
  }
  if(body.event_delivery!==undefined){
    const data=exactObject(body.event_delivery,['storage_ready','pending','blocked','oldest_age_sec','delivered','retries','capacity_rejections','conflicts','enqueue_errors'],['storage_ready']);
    if(typeof data.storage_ready!=='boolean'){const error=new Error('Invalid storage status.');error.statusCode=422;throw error;}
    if(data.storage_ready)exactObject(data,['storage_ready','pending','blocked','oldest_age_sec','delivered','retries','capacity_rejections','conflicts','enqueue_errors']);
    for(const [key,value] of Object.entries(data))if(key!=='storage_ready')finiteNumber(value,key,{integer:key!=='oldest_age_sec'});
  }
  return { ...body, received_at: new Date().toISOString() };
}

function performanceRunPayload(value) {
  const fields = [
    'run_id',
    'started_at',
    'duration_sec',
    'concurrent_clients',
    'total_requests',
    'throughput_rps',
    'avg_latency_ms',
    'p95_latency_ms',
    'timeout_rate',
  ];
  const body = exactObject(value, [...fields, 'test_context'], fields);
  if (typeof body.run_id !== 'string' || !/^[A-Za-z0-9._:-]{1,120}$/.test(body.run_id)) {
    const error = new Error('run_id is invalid.');
    error.statusCode = 422;
    error.code = 'VALIDATION';
    throw error;
  }
  if (typeof body.started_at !== 'string' || !Number.isFinite(Date.parse(body.started_at))) {
    const error = new Error('started_at is invalid.');
    error.statusCode = 422;
    error.code = 'VALIDATION';
    throw error;
  }
  finiteNumber(body.duration_sec, 'duration_sec', { min: 0.001 });
  finiteNumber(body.concurrent_clients, 'concurrent_clients', { integer: true, min: 1 });
  finiteNumber(body.total_requests, 'total_requests', { integer: true });
  finiteNumber(body.throughput_rps, 'throughput_rps');
  finiteNumber(body.avg_latency_ms, 'avg_latency_ms');
  finiteNumber(body.p95_latency_ms, 'p95_latency_ms');
  finiteNumber(body.timeout_rate, 'timeout_rate', { max: 1 });
  if (body.test_context !== undefined) {
    const context = exactObject(body.test_context, ['kind', 'measurement', 'blocked_requests', 'saved_events', 'clients_same_host']);
    if (context.kind !== 'SECURITY_BLOCK' || context.measurement !== 'CLIENT_ROUNDTRIP' || typeof context.clients_same_host !== 'boolean') {
      const error = new Error('Invalid performance test context.'); error.statusCode = 422; throw error;
    }
    finiteNumber(context.blocked_requests, 'blocked_requests', { integer: true, max: body.total_requests });
    finiteNumber(context.saved_events, 'saved_events', { integer: true, max: body.total_requests });
  }
  return body;
}

function mergeFingerprintEvidence(documents, evidence) {
  const byId = new Map(
    evidence.map((item) => [String(item.document_id), item]),
  );
  return documents.map((document) => {
    const fingerprint = byId.get(document.document_id);
    if (fingerprint?.indexed === true) {
      return {
        ...document,
        processing_status: 'READY',
        chunk_index_status: 'READY',
        chunk_count: Number(fingerprint.window_count ?? document.chunk_count ?? 0),
        active_detectors: ['WINDOW_HASH'],
      };
    }
    if (document.status === 'INACTIVE') {
      return {
        ...document,
        processing_status: 'READY',
        chunk_index_status: 'NOT_AVAILABLE',
        chunk_count: 0,
        active_detectors: [],
      };
    }
    return document;
  });
}

function listAuditLogs(records, searchParams, now = Date.now()) {
  const period = enumQuery(
    searchParams,
    'period',
    new Set(['24H', '7D', '30D']),
    '30D',
  );
  const action = (searchParams.get('action') ?? '').trim();
  const result = enumQuery(searchParams, 'result', new Set(['SUCCESS', 'FAILURE']), null);
  const admin = (searchParams.get('admin') ?? '').trim().toLowerCase();
  const page = positiveIntegerQuery(searchParams, 'page', 1, 1_000_000);
  const pageSize = positiveIntegerQuery(searchParams, 'page_size', 20, 100);
  const threshold = now - PERIOD_MS[period];
  const filtered = records
    .filter(
      (record) =>
        Date.parse(record.occurred_at) >= threshold &&
        (!action || action === 'ALL' || record.action === action) &&
        (!result || record.result === result) &&
        (!admin || record.admin_id.toLowerCase().includes(admin)),
    )
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at));
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  return {
    items: filtered.slice((safePage - 1) * pageSize, safePage * pageSize),
    total: filtered.length,
    page: safePage,
    page_size: pageSize,
    total_pages: totalPages,
  };
}

function exactObject(value, allowed, required = allowed) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    const error = new Error('Request body must be an object.');
    error.statusCode = 400;
    throw error;
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) {
    const error = new Error('Request body contains invalid fields.');
    error.statusCode = 400;
    throw error;
  }
  return value;
}

function eventMutationPath(pathname) {
  const match = /^\/api\/events\/([^/]+)\/(status|assignee|notes)$/.exec(pathname);
  if (!match) return null;
  try {
    return { eventId: decodeURIComponent(match[1]), operation: match[2] };
  } catch {
    const error = new Error('Invalid event id encoding.');
    error.statusCode = 400;
    throw error;
  }
}

function documentMutationPath(pathname) {
  const match = /^\/api\/documents\/([^/]+)\/status$/.exec(pathname);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    const error = new Error('Invalid document id encoding.');
    error.statusCode = 400;
    throw error;
  }
}

function policyPath(pathname) {
  if (pathname === '/api/policies') return { operation: 'list' };
  const match = /^\/api\/policies\/([^/]+)(?:\/(versions|status))?$/.exec(pathname);
  if (!match) return null;
  try {
    return {
      policyId: decodeURIComponent(match[1]),
      operation: match[2] ?? 'detail',
    };
  } catch {
    const error = new Error('Invalid policy id encoding.');
    error.statusCode = 400;
    error.code = 'VALIDATION';
    throw error;
  }
}

async function detectionPolicyRequest(baseUrl, pathname, { method = 'GET', body, adminId } = {}) {
  if (!baseUrl) {
    const error = new Error('Detection policy API integration is not available.');
    error.statusCode = 503;
    error.code = 'POLICY_INTEGRATION_UNAVAILABLE';
    throw error;
  }
  let response;
  try {
    response = await fetch(`${baseUrl.replace(/\/$/, '')}${pathname}`, {
      method,
      headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(adminId ? { 'X-Admin-Id': adminId } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(3_000),
    });
  } catch {
    const error = new Error('Detection policy API is unreachable.');
    error.statusCode = 503;
    error.code = 'POLICY_UPSTREAM_UNAVAILABLE';
    throw error;
  }
  let payload;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const detail = payload?.detail;
    const error = new Error(detail?.message ?? 'Detection policy request failed.');
    error.statusCode = response.status;
    error.code = detail?.code ?? 'POLICY_UPSTREAM_ERROR';
    throw error;
  }
  return payload;
}

function configurationValue(value, name) {
  if (typeof value !== 'string' || value.length < 8)
    throw new Error(`${name} must be configured with at least 8 characters.`);
  return value;
}

function configurationEmail(value) {
  const email = configurationValue(value, 'LOCAL_ADMIN_EMAIL');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    throw new Error('LOCAL_ADMIN_EMAIL must be a valid email address.');
  return email;
}

// ───────────────────────── 리포트·키워드 승인(HITL) 연동 (2026-10-04 추가, Detection 담당)
// 화면에서 쓰는 /api/reports·/api/keywords·/api/keyword-jobs 를 Detection 관리 API로 넘긴다.
// 이 블록과 아래 라우트 블록은 서버에서 직접 추가한 것이다 - 로컬 사본으로 app.mjs를 덮어쓸 때 함께 옮길 것.
const REPORT_ID_PATTERN = /^[A-Za-z0-9_.-]{1,120}$/;
const REPORT_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const KEYWORD_STATUSES = new Set(['pending', 'approved']);
const KEYWORD_JOB_STATUSES = new Set(['queued', 'running', 'done', 'failed']);

function detectionOpsValidation(message) {
  const error = new Error(message);
  error.statusCode = 400;
  error.code = 'VALIDATION';
  return error;
}

function detectionOpsSegment(value, name) {
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw detectionOpsValidation(`Invalid ${name} encoding.`);
  }
  if (!decoded || decoded.includes('/') || decoded.length > 200) throw detectionOpsValidation(`Invalid ${name}.`);
  return decoded;
}

function detectionOpsPath(pathname) {
  if (pathname === '/api/reports') return { kind: 'reports' };
  let match = /^\/api\/reports\/([^/]+)\/file$/.exec(pathname);
  if (match) {
    const reportId = detectionOpsSegment(match[1], 'report id');
    if (!REPORT_ID_PATTERN.test(reportId)) throw detectionOpsValidation('Invalid report id.');
    return { kind: 'report-file', id: reportId };
  }
  if (pathname === '/api/system/gpu') return { kind: 'gpu' };
  match = /^\/api\/system\/gpu\/(start|stop)$/.exec(pathname);
  if (match) return { kind: 'gpu-control', id: match[1] };
  if (pathname === '/api/keywords') return { kind: 'keywords' };
  match = /^\/api\/keywords\/(\d{1,12})$/.exec(pathname);
  if (match) return { kind: 'keyword', id: match[1] };
  match = /^\/api\/keywords\/(\d{1,12})\/(approve|reject)$/.exec(pathname);
  if (match) return { kind: `keyword-${match[2]}`, id: match[1] };
  if (pathname === '/api/keyword-jobs') return { kind: 'keyword-jobs' };
  match = /^\/api\/keyword-jobs\/(\d{1,12})\/retry$/.exec(pathname);
  if (match) return { kind: 'keyword-job-retry', id: match[1] };
  match = /^\/api\/documents\/([^/]+)\/extract-keywords$/.exec(pathname);
  if (match) return { kind: 'keyword-extract', id: detectionOpsSegment(match[1], 'document id') };
  return null;
}

function detectionOpsQuery(searchParams, allowed) {
  const query = new URLSearchParams();
  for (const [name, values] of Object.entries(allowed)) {
    const value = searchParams.get(name);
    if (value === null || value === '') continue;
    if (values && !values.has(value)) throw detectionOpsValidation(`Invalid ${name}.`);
    if (value.length > 200) throw detectionOpsValidation(`Invalid ${name}.`);
    query.set(name, value);
  }
  const text = query.toString();
  return text ? `?${text}` : '';
}

async function detectionReportFile(baseUrl, reportId, download) {
  if (!baseUrl) {
    const error = new Error('Detection API integration is not available.');
    error.statusCode = 503;
    error.code = 'POLICY_INTEGRATION_UNAVAILABLE';
    throw error;
  }
  let upstream;
  try {
    upstream = await fetch(
      `${baseUrl.replace(/\/$/, '')}/admin/reports/${encodeURIComponent(reportId)}/file${download ? '?download=1' : ''}`,
      { signal: AbortSignal.timeout(10_000) },
    );
  } catch {
    const error = new Error('Detection report API is unreachable.');
    error.statusCode = 503;
    error.code = 'POLICY_UPSTREAM_UNAVAILABLE';
    throw error;
  }
  if (!upstream.ok) {
    let detail = null;
    try {
      detail = (await upstream.json())?.detail ?? null;
    } catch {
      detail = null;
    }
    const error = new Error(detail?.message ?? 'Detection report request failed.');
    error.statusCode = upstream.status;
    error.code = detail?.code ?? 'POLICY_UPSTREAM_ERROR';
    throw error;
  }
  return {
    body: Buffer.from(await upstream.arrayBuffer()),
    disposition:
      upstream.headers.get('content-disposition') ??
      `${download ? 'attachment' : 'inline'}; filename="${reportId}.html"`,
  };
}

export function createAppServer({
  store,
  storePath,
  allowedOrigin = 'http://127.0.0.1:4173',
  adminEmail,
  adminPassword,
  ingestToken,
  policyBaseUrl,
}) {
  const eventStore = store ?? new JsonEventStore(storePath);
  const configuredEmail = configurationEmail(adminEmail);
  const configuredPassword = configurationValue(
    adminPassword,
    'LOCAL_ADMIN_PASSWORD',
  );
  const configuredIngestToken = configurationValue(
    ingestToken,
    'EVENT_INGEST_TOKEN',
  );
  const sessions = new Map();
  let latestGatewayMetrics = null;
  const adminUser = {
    id: 'local-admin',
    email: configuredEmail,
    display_name: 'Local Administrator',
    role: 'ADMIN',
  };
  const recordAuditSafely = async (record) => {
    try {
      await eventStore.recordAudit(record);
    } catch (error) {
      console.error('Administrator audit write failed:', error?.message ?? error);
    }
  };

  return createServer(async (request, response) => {
    setCors(response, request, allowedOrigin);
    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '600',
      });
      response.end();
      return;
    }

    try {
      const url = new URL(request.url ?? '/', 'http://localhost');
      if (request.method === 'GET' && url.pathname === '/health') {
        sendJson(response, 200, { status: 'ok' });
        return;
      }

      if (request.method === 'POST' && url.pathname === '/api/auth/login') {
        const body = await readJson(request, 16 * 1024);
        const keys = Object.keys(body ?? {});
        if (
          typeof body !== 'object' ||
          body === null ||
          Array.isArray(body) ||
          keys.some((key) => !['identifier', 'password'].includes(key)) ||
          !secretsEqual(body.identifier, configuredEmail) ||
          !secretsEqual(body.password, configuredPassword)
        ) {
          await recordAuditSafely({
            adminId: 'local-admin',
            action: 'ADMIN_LOGIN',
            targetType: 'ADMIN',
            targetId: 'local-admin',
            result: 'FAILURE',
          });
          sendError(response, 401, 'UNAUTHORIZED', 'Invalid credentials.');
          return;
        }
        const sessionToken = randomBytes(32).toString('base64url');
        sessions.set(sessionToken, adminUser);
        await recordAuditSafely({
          adminId: adminUser.id,
          action: 'ADMIN_LOGIN',
          targetType: 'ADMIN',
          targetId: adminUser.id,
          result: 'SUCCESS',
        });
        response.setHeader(
          'Set-Cookie',
          `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800`,
        );
        sendJson(response, 200, adminUser);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
        const sessionToken = parseCookies(request).get(SESSION_COOKIE);
        const user = sessionToken ? sessions.get(sessionToken) : null;
        if (sessionToken) sessions.delete(sessionToken);
        if (user)
          await recordAuditSafely({
            adminId: user.id,
            action: 'ADMIN_LOGOUT',
            targetType: 'ADMIN',
            targetId: user.id,
            result: 'SUCCESS',
          });
        response.setHeader(
          'Set-Cookie',
          `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
        );
        response.writeHead(204, { 'Cache-Control': 'no-store' });
        response.end();
        return;
      }

      if (request.method === 'GET' && url.pathname === '/api/auth/session') {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        sendJson(response, 200, user);
        return;
      }

      // 내 요청 기록(2026-10-09): 관리자 세션이 아니라 열람 키로 본인 요청만 연다
      if (url.pathname === '/api/my/requests' || url.pathname.startsWith('/api/my/requests/')) {
        if (request.method !== 'GET') {
          sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Only GET is supported.');
          return;
        }
        const viewerHash = viewerKeyHash(request);
        if (!viewerHash) {
          sendError(response, 401, 'VIEWER_KEY_REQUIRED', 'A valid viewer key is required.');
          return;
        }
        if (url.pathname === '/api/my/requests') {
          sendJson(response, 200, ownRequests(await eventStore.list(), viewerHash));
          return;
        }
        const match = /^\/api\/my\/requests\/([^/]{1,200})\/evidence$/.exec(url.pathname);
        let eventId = null;
        try {
          eventId = match ? decodeURIComponent(match[1]) : null;
        } catch {
          eventId = null;
        }
        const event = eventId ? await eventStore.get(eventId) : null;
        if (!event || event.viewer_key_hash !== viewerHash) {
          sendError(response, 404, 'NOT_FOUND', 'Request not found.');
          return;
        }
        sendJson(response, 200, eventStore.getOwnEvidence ? await eventStore.getOwnEvidence(event) : buildOwnEvidence(event, null, null));
        return;
      }

      if (request.method === 'POST' && url.pathname === '/api/events/ingest') {
        if (!requireIngestToken(request, configuredIngestToken)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Valid ingest token required.');
          return;
        }
        const canonicalEvent = validateCanonicalEvent(await readJson(request));
        const result = await eventStore.ingest(
          canonicalEvent,
          canonicalEventToDto(canonicalEvent),
        );
        sendJson(response, result.created ? 201 : 200, result);
        return;
      }

      if (request.method==='GET'&&url.pathname==='/api/events/lookup'){
        if(!requireSession(request,sessions)){sendError(response,401,'UNAUTHORIZED','Authentication required.');return;}
        sendJson(response,200,lookupRequest(await eventStore.list(),url.searchParams));
        return;
      }
      if (url.pathname === '/api/events' && request.method === 'GET') {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        // Historical events can retain only a document ID. Use inventory names
        // for search without rewriting their event-time metadata or reading text.
        const names = new Map();
        if (url.searchParams.get('query')?.trim() && eventStore.listDocuments) {
          for (const document of await eventStore.listDocuments()) {
            if (document.document_id && document.document_name) names.set(document.document_id, document.document_name);
          }
        }
        const allEvents = await eventStore.list();
        const includeTest = url.searchParams.get('include_test') === '1';
        const page = listEvents(includeTest ? allEvents : allEvents.filter((event) => !isTestEvent(event)), url.searchParams, Date.now(), names);
        // 같은 조건에서 빠진 시험·데모 건수. 0이면 싣지 않아 기존 응답 모양을 그대로 둔다
        const excludedTest = includeTest ? 0 : listEvents(allEvents.filter(isTestEvent), url.searchParams, Date.now(), names).total;
        sendJson(response, 200, excludedTest ? { ...page, excluded_test: excludedTest } : page);
        return;
      }

      if (url.pathname === '/api/dashboard/stats' && request.method === 'GET') {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const gateway = liveGatewayState(latestGatewayMetrics);
        const stats = dashboardStats((await eventStore.list()).filter((event) => !isTestEvent(event)), url.searchParams);
        if (stats.insights.documents.length && eventStore.listDocuments) {
          const names = new Map((await eventStore.listDocuments()).map((document) => [document.document_id, document.document_name]));
          stats.insights.documents = stats.insights.documents.map((document) =>
            names.get(document.key) ? { ...document, name: names.get(document.key) } : document);
        }
        sendJson(response, 200, {
          ...stats,
          gateway_status: gateway.status,
          gateway_metrics_status: gateway.metricsStatus,
          ...(gateway.completed === undefined ? {} : { gateway_completed_requests: gateway.completed }),
        });
        return;
      }

      if (url.pathname === '/api/traffic/metrics' && request.method === 'POST') {
        if (!requireIngestToken(request, configuredIngestToken)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Valid ingest token required.');
          return;
        }
        latestGatewayMetrics = gatewayMetricsPayload(await readJson(request));
        sendJson(response, 202, { accepted: true });
        return;
      }

      if (
        url.pathname === '/api/traffic/performance-runs' &&
        request.method === 'POST'
      ) {
        if (!requireIngestToken(request, configuredIngestToken)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Valid ingest token required.');
          return;
        }
        sendJson(
          response,
          201,
          await eventStore.recordPerformanceRun(
            performanceRunPayload(await readJson(request)),
          ),
        );
        return;
      }

      if (request.method === 'GET' && url.pathname.startsWith('/api/traffic/')) {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const events = (await eventStore.list()).filter((event) => !isTestEvent(event));
        if (url.pathname === '/api/traffic/summary') {
          const summary = trafficSummary(events, url.searchParams);
          const metricsAge = latestGatewayMetrics
            ? Date.now() - Date.parse(latestGatewayMetrics.received_at)
            : Number.POSITIVE_INFINITY;
          sendJson(
            response,
            200,
            metricsAge <= 120_000
              ? {
                  ...summary,
                  metric_source: 'GATEWAY_LIVE',
                  gateway_metrics_status: 'FRESH',
                  gateway_metrics_received_at: latestGatewayMetrics.received_at,
                  gateway_metrics_age_sec: Math.max(0, metricsAge / 1000),
                  gateway_status: liveGatewayState(latestGatewayMetrics).status,
                  gateway_total_requests: latestGatewayMetrics.total_requests,
                  gateway_completed_requests: latestGatewayMetrics.completed_requests,
                  gateway_error_requests: latestGatewayMetrics.error_requests,
                  gateway_window_seconds: latestGatewayMetrics.window_seconds,
                  latency_sample_count: Math.min(latestGatewayMetrics.completed_requests, 5000),
                  active_clients: latestGatewayMetrics.active_clients,
                  concurrent_requests: latestGatewayMetrics.concurrent_requests,
                  requests_per_sec: latestGatewayMetrics.requests_per_sec,
                  average_latency_ms: latestGatewayMetrics.completed_requests ? latestGatewayMetrics.avg_latency_ms : undefined,
                  p95_latency_ms: latestGatewayMetrics.completed_requests ? latestGatewayMetrics.p95_latency_ms : undefined,
                  timeout_rate: latestGatewayMetrics.completed_requests ? latestGatewayMetrics.timeout_rate : undefined,
                  degraded_rate: latestGatewayMetrics.completed_requests ? latestGatewayMetrics.degraded_rate : undefined,
                }
              : {
                  ...summary,
                  gateway_metrics_status: latestGatewayMetrics ? 'STALE' : 'NOT_RECEIVED',
                  ...(latestGatewayMetrics ? {
                    gateway_metrics_received_at: latestGatewayMetrics.received_at,
                    gateway_metrics_age_sec: Math.max(0, metricsAge / 1000),
                  } : {}),
                },
          );
          return;
        }
        if (url.pathname === '/api/traffic/timeseries') {
          sendJson(response, 200, trafficTimeSeries(events, url.searchParams));
          return;
        }
        if (url.pathname === '/api/traffic/recent') {
          sendJson(response, 200, trafficRecent(events, url.searchParams));
          return;
        }
        if (url.pathname === '/api/traffic/performance-runs') {
          sendJson(response, 200, await eventStore.listPerformanceRuns());
          return;
        }
      }

      if (url.pathname === '/api/documents' && request.method === 'GET') {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const documents = await eventStore.listDocuments();
        try {
          const evidence = await detectionPolicyRequest(
            policyBaseUrl,
            '/admin/documents/fingerprints',
          );
          sendJson(response, 200, mergeFingerprintEvidence(documents, evidence));
        } catch (error) {
          console.error('Fingerprint evidence lookup failed:', error?.message ?? error);
          sendJson(response, 200, documents);
        }
        return;
      }

      if (url.pathname === '/api/documents' && request.method === 'POST') {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const upload = await readDocumentUpload(request);
        const result = await eventStore.registerDocument({
          ...upload,
          registeredBy: user.id,
        });
        await recordAuditSafely({
          adminId: user.id,
          action: 'DOCUMENT_REGISTER',
          targetType: 'DOCUMENT',
          targetId: result.document.document_id,
          result: 'SUCCESS',
          changes: {
            outcome: result.outcome,
            version: result.document.version,
            filename: result.document.document_name,
          },
        });
        sendJson(response, result.outcome === 'created' ? 201 : 200, result.document);
        return;
      }

      const documentId = documentMutationPath(url.pathname);
      if (documentId && request.method === 'PATCH') {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const body = exactObject(await readJson(request, 16 * 1024), ['status']);
        if (!['ACTIVE', 'INACTIVE'].includes(body.status)) {
          sendError(response, 422, 'VALIDATION', 'Unsupported document status.');
          return;
        }
        const result = await eventStore.changeDocumentStatus(documentId, body.status);
        if (!result) {
          sendError(response, 404, 'NOT_FOUND', 'Document not found.');
          return;
        }
        if (result.changed)
          await recordAuditSafely({
            adminId: user.id,
            action: body.status === 'ACTIVE' ? 'DOCUMENT_ENABLE' : 'DOCUMENT_DISABLE',
            targetType: 'DOCUMENT',
            targetId: documentId,
            result: 'SUCCESS',
            changes: {
              previous_status: result.previousStatus,
              new_status: body.status,
              version: result.document.version,
            },
          });
        sendJson(response, 200, result.document);
        return;
      }

      const detectionOps = detectionOpsPath(url.pathname);
      if (detectionOps) {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const call = (pathname, options = {}) =>
          detectionPolicyRequest(policyBaseUrl, pathname, { ...options, adminId: user.id });
        // 승인·반려 직후 탐지에 반영한다. 반영 실패는 승인 자체를 되돌리지 않고 applied=false로 알린다
        const applyKeywords = async () => {
          try {
            await call('/admin/reload-signatures', { method: 'POST' });
            return { applied: true };
          } catch (error) {
            return { applied: false, apply_error: error.message };
          }
        };
        const { kind, id } = detectionOps;
        if (kind === 'reports' && request.method === 'GET') {
          sendJson(response, 200, await call('/admin/reports'));
          return;
        }
        if (kind === 'reports' && request.method === 'POST') {
          const body = exactObject(await readJson(request, 16 * 1024), ['from', 'to', 'use_llm'], ['from', 'to']);
          if (!REPORT_DATE_PATTERN.test(String(body.from)) || !REPORT_DATE_PATTERN.test(String(body.to)))
            throw detectionOpsValidation('from/to must be YYYY-MM-DD.');
          if (body.use_llm !== undefined && typeof body.use_llm !== 'boolean')
            throw detectionOpsValidation('use_llm must be a boolean.');
          const result = await call('/admin/reports', { method: 'POST', body });
          await recordAuditSafely({
            adminId: user.id,
            action: 'REPORT_CREATE',
            targetType: 'REPORT',
            targetId: String(result?.report_id ?? `${body.from}_${body.to}`),
            result: 'SUCCESS',
            changes: { from: body.from, to: body.to, use_llm: body.use_llm ?? true },
          });
          sendJson(response, 202, result);
          return;
        }
        if (kind === 'report-file' && request.method === 'GET') {
          const file = await detectionReportFile(policyBaseUrl, id, url.searchParams.get('download') === '1');
          response.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': file.body.length,
            'Content-Disposition': file.disposition,
            // 리포트 HTML의 스크립트(차트)는 돌리되 대시보드 쿠키·API에는 닿지 못하게 격리한다
            'Content-Security-Policy': 'sandbox allow-scripts',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
          });
          response.end(file.body);
          return;
        }
        if (kind === 'keywords' && request.method === 'GET') {
          const query = detectionOpsQuery(url.searchParams, { status: KEYWORD_STATUSES, doc_id: null });
          sendJson(response, 200, await call(`/admin/keywords${query}`));
          return;
        }
        if (kind === 'keywords' && request.method === 'POST') {
          const body = exactObject(await readJson(request, 16 * 1024), ['keyword', 'doc_id', 'approve'], ['keyword', 'doc_id']);
          if (typeof body.keyword !== 'string' || typeof body.doc_id !== 'string' || !body.keyword.trim())
            throw detectionOpsValidation('keyword and doc_id must be strings.');
          if (body.approve !== undefined && typeof body.approve !== 'boolean')
            throw detectionOpsValidation('approve must be a boolean.');
          const created = await call('/admin/keywords', { method: 'POST', body });
          const applied = created?.status === 'approved' ? await applyKeywords() : { applied: false };
          await recordAuditSafely({
            adminId: user.id,
            action: 'KEYWORD_CREATE',
            targetType: 'KEYWORD',
            targetId: String(created?.id ?? body.keyword),
            result: 'SUCCESS',
            changes: { keyword: body.keyword, doc_id: body.doc_id, status: created?.status, applied: applied.applied },
          });
          sendJson(response, 201, { ...created, ...applied });
          return;
        }
        // 승인 대기 키워드 표현 고치기(승인 전 검토). 탐지에 쓰이지 않는 상태라 재로딩하지 않는다. 승인된 것은 Detection이 409
        if (kind === 'keyword' && request.method === 'PATCH') {
          const body = exactObject(await readJson(request, 16 * 1024), ['keyword'], ['keyword']);
          if (typeof body.keyword !== 'string' || !body.keyword.trim())
            throw detectionOpsValidation('keyword must be a non-empty string.');
          const updated = await call(`/admin/keywords/${id}`, { method: 'PATCH', body });
          await recordAuditSafely({
            adminId: user.id,
            action: 'KEYWORD_UPDATE',
            targetType: 'KEYWORD',
            targetId: id,
            result: 'SUCCESS',
            changes: { keyword: updated?.keyword, doc_id: updated?.doc_id },
          });
          sendJson(response, 200, updated);
          return;
        }
        if (kind === 'keyword-approve' && request.method === 'POST') {
          const approved = await call(`/admin/keywords/${id}/approve`, { method: 'POST' });
          const applied = await applyKeywords();
          await recordAuditSafely({
            adminId: user.id,
            action: 'KEYWORD_APPROVE',
            targetType: 'KEYWORD',
            targetId: id,
            result: 'SUCCESS',
            changes: { keyword: approved?.keyword, doc_id: approved?.doc_id, applied: applied.applied },
          });
          sendJson(response, 200, { ...approved, ...applied });
          return;
        }
        if (kind === 'keyword-reject' && request.method === 'POST') {
          await call(`/admin/keywords/${id}`, { method: 'DELETE' });
          const applied = await applyKeywords();
          await recordAuditSafely({
            adminId: user.id,
            action: 'KEYWORD_REJECT',
            targetType: 'KEYWORD',
            targetId: id,
            result: 'SUCCESS',
            changes: { applied: applied.applied },
          });
          sendJson(response, 200, { id: Number(id), rejected: true, ...applied });
          return;
        }
        // GPU(LLM 서버) 연결 상태 - Detection이 대신 확인한다(GPU는 Detection에서만 닿는다). 읽기 전용
        if (kind === 'gpu' && request.method === 'GET') {
          sendJson(response, 200, await call('/admin/gpu'));
          return;
        }
        // GPU 켜기·끄기(2026-10-07) - Detection이 EC2를 부른다(권한은 Detection IAM 역할, 이 GPU 하나만).
        // 켜기는 꺼진 상태에서만, 끄기는 켜진 상태에서만, 끄기는 리포트 생성·키워드 추출 중이면 Detection이 409
        if (kind === 'gpu-control' && request.method === 'POST') {
          const result = await call(`/admin/gpu/${id}`, { method: 'POST' });
          await recordAuditSafely({
            adminId: user.id,
            action: id === 'start' ? 'GPU_START' : 'GPU_STOP',
            targetType: 'GPU',
            targetId: String(result?.instance_id ?? 'gpu'),
            result: 'SUCCESS',
            changes: { previous_instance_state: result?.previous_state, new_instance_state: result?.instance_state },
          });
          sendJson(response, 200, result);
          return;
        }
        if (kind === 'keyword-jobs' && request.method === 'GET') {
          const query = detectionOpsQuery(url.searchParams, { status: KEYWORD_JOB_STATUSES });
          sendJson(response, 200, await call(`/admin/keyword-jobs${query}`));
          return;
        }
        if (kind === 'keyword-extract' && request.method === 'POST') {
          const job = await call(`/admin/documents/${encodeURIComponent(id)}/extract-keywords`, { method: 'POST' });
          await recordAuditSafely({
            adminId: user.id,
            action: 'KEYWORD_EXTRACT_REQUEST',
            targetType: 'DOCUMENT',
            targetId: id,
            result: 'SUCCESS',
            changes: { job_id: job?.id, status: job?.status },
          });
          sendJson(response, 202, job);
          return;
        }
        if (kind === 'keyword-job-retry' && request.method === 'POST') {
          sendJson(response, 200, await call(`/admin/keyword-jobs/${id}/retry`, { method: 'POST' }));
          return;
        }
        sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Unsupported report or keyword operation.');
        return;
      }

      const policyRoute = policyPath(url.pathname);
      if (policyRoute) {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const encodedId = policyRoute.policyId
          ? encodeURIComponent(policyRoute.policyId)
          : null;
        if (policyRoute.operation === 'list' && request.method === 'GET') {
          sendJson(response, 200, await detectionPolicyRequest(policyBaseUrl, '/admin/policies'));
          return;
        }
        if (policyRoute.operation === 'versions' && request.method === 'GET') {
          sendJson(
            response,
            200,
            await detectionPolicyRequest(policyBaseUrl, `/admin/policies/${encodedId}/versions`),
          );
          return;
        }
        if (policyRoute.operation === 'list' && request.method === 'POST') {
          const body = exactObject(await readJson(request, 16 * 1024), [
            'detection_target',
            'action',
          ]);
          const result = await detectionPolicyRequest(policyBaseUrl, '/admin/policies', {
            method: 'POST',
            body,
            adminId: user.id,
          });
          await recordAuditSafely({
            adminId: user.id,
            action: 'POLICY_CREATE',
            targetType: 'POLICY',
            targetId: result.policy_id,
            result: 'SUCCESS',
            changes: {
              new_version: result.version,
              new_action: result.action,
            },
          });
          sendJson(response, 201, result);
          return;
        }
        if (policyRoute.operation === 'detail' && request.method === 'PATCH') {
          const body = exactObject(await readJson(request, 16 * 1024), [
            'action',
            'expected_version',
          ]);
          const previous = await detectionPolicyRequest(
            policyBaseUrl,
            `/admin/policies/${encodedId}`,
          );
          const result = await detectionPolicyRequest(
            policyBaseUrl,
            `/admin/policies/${encodedId}`,
            { method: 'PATCH', body, adminId: user.id },
          );
          await recordAuditSafely({
            adminId: user.id,
            action: 'POLICY_UPDATE',
            targetType: 'POLICY',
            targetId: result.policy_id,
            result: 'SUCCESS',
            changes: {
              previous_version: previous.version,
              new_version: result.version,
              previous_action: previous.action,
              new_action: result.action,
            },
          });
          sendJson(response, 200, result);
          return;
        }
        if (policyRoute.operation === 'status' && request.method === 'PATCH') {
          const body = exactObject(await readJson(request, 16 * 1024), [
            'enabled',
            'expected_version',
          ]);
          const previous = await detectionPolicyRequest(
            policyBaseUrl,
            `/admin/policies/${encodedId}`,
          );
          const result = await detectionPolicyRequest(
            policyBaseUrl,
            `/admin/policies/${encodedId}/status`,
            { method: 'PATCH', body, adminId: user.id },
          );
          await recordAuditSafely({
            adminId: user.id,
            action: result.enabled ? 'POLICY_ENABLE' : 'POLICY_DISABLE',
            targetType: 'POLICY',
            targetId: result.policy_id,
            result: 'SUCCESS',
            changes: {
              previous_version: previous.version,
              new_version: result.version,
              previous_value: previous.enabled ? 'ENABLED' : 'DISABLED',
              new_value: result.enabled ? 'ENABLED' : 'DISABLED',
            },
          });
          sendJson(response, 200, result);
          return;
        }
        sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Unsupported policy operation.');
        return;
      }

      const mutation = eventMutationPath(url.pathname);
      if (
        mutation &&
        ((mutation.operation === 'notes' && request.method === 'POST') ||
          (mutation.operation !== 'notes' && request.method === 'PATCH'))
      ) {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const requestField = mutation.operation === 'notes' ? 'content' : mutation.operation;
        const body = exactObject(await readJson(request), [requestField]);
        let event;
        if (mutation.operation === 'status') {
          if (!['NEW', 'INVESTIGATING', 'RESOLVED'].includes(body.status)) {
            sendError(response, 422, 'VALIDATION', 'Unsupported incident status.');
            return;
          }
          event = await eventStore.updateStatus(mutation.eventId, body.status, user.id);
        } else if (mutation.operation === 'assignee') {
          if (typeof body.assignee !== 'string' || body.assignee.trim().length === 0 || body.assignee.length > 200) {
            sendError(response, 422, 'VALIDATION', 'Assignee must be a non-empty string.');
            return;
          }
          event = await eventStore.assign(mutation.eventId, body.assignee.trim(), user.id);
        } else {
          if (typeof body.content !== 'string' || body.content.trim().length === 0 || body.content.length > 2_000) {
            sendError(response, 422, 'VALIDATION', 'Note must be a non-empty string.');
            return;
          }
          event = await eventStore.addNote(mutation.eventId, body.content.trim(), user.id);
        }
        if (!event) {
          sendError(response, 404, 'NOT_FOUND', 'Event not found.');
          return;
        }
        sendJson(response, 200, event);
        return;
      }

      if (url.pathname === '/api/audit-logs' && request.method === 'GET') {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        sendJson(
          response,
          200,
          listAuditLogs(await eventStore.listAudit(), url.searchParams),
        );
        return;
      }

      if (request.method === 'GET' && /^\/api\/events\/[^/]+\/evidence$/.test(url.pathname)) {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        let eventId;
        try { eventId = decodeURIComponent(url.pathname.split('/')[3]); }
        catch { sendError(response, 400, 'VALIDATION', 'Invalid event id encoding.'); return; }
        const event = !eventId.includes('/') && await eventStore.get(eventId);
        if (!event) { sendError(response, 404, 'NOT_FOUND', 'Event not found.'); return; }
        let pageRequest;
        if (url.searchParams.has('view')) {
          const side=url.searchParams.get('view');
          const offsetValue=url.searchParams.get('offset') ?? '0';
          const documentId=url.searchParams.get('document_id') || undefined;
          if (!['input','document'].includes(side) || !/^\d{1,7}$/.test(offsetValue)
            || Number(offsetValue)>2000000 || (side==='document' && !documentId)
            || (documentId && documentId.length>500)) {
            sendError(response,400,'VALIDATION','Invalid evidence page request.'); return;
          }
          pageRequest={side,offset:Number(offsetValue),documentId};
        }
        if (typeof eventStore.getEvidence !== 'function') {
          sendJson(response, 200, {event_id:eventId,source:'RDS_DECISION_LOG',status:'NOT_RECORDED',coordinate_system:'NORMALIZED_UNICODE_CODE_POINTS',comparisons:[]});
          return;
        }
        sendJson(response, 200, await eventStore.getEvidence(event,pageRequest));
        return;
      }

      if (request.method === 'GET' && url.pathname.startsWith('/api/events/')) {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        let eventId;
        try {
          eventId = decodeURIComponent(url.pathname.slice('/api/events/'.length));
        } catch {
          sendError(response, 400, 'VALIDATION', 'Invalid event id encoding.');
          return;
        }
        if (!eventId || eventId.includes('/')) {
          sendError(response, 404, 'NOT_FOUND', 'Event not found.');
          return;
        }
        const event = await eventStore.get(eventId);
        if (!event) {
          sendError(response, 404, 'NOT_FOUND', 'Event not found.');
          return;
        }
        // 질문이면 붙은 파일, 파일이면 이 파일을 붙인 질문을 함께 준다(번호가 있는 이벤트만)
        if (event.file_id || event.attached_file_ids) {
          const { attached, parents } = attachmentLinks(await eventStore.list());
          const files = attached.get(event.event_id);
          const prompts = parents.get(event.event_id);
          sendJson(response, 200, {
            ...event,
            ...(files ? { attached_files: files.map(attachedSummary) } : {}),
            ...(prompts ? { attached_to: prompts.map(attachedSummary) } : {}),
          });
          return;
        }
        sendJson(response, 200, event);
        return;
      }

      sendError(response, 404, 'NOT_FOUND', 'Route not found.');
    } catch (error) {
      if (error instanceof ValidationError) {
        sendError(response, 422, 'VALIDATION', error.message, {
          path: error.path,
        });
        return;
      }
      if (error instanceof EventConflictError) {
        sendError(
          response,
          409,
          'EVENT_ID_CONFLICT',
          'The event id already exists with different content.',
        );
        return;
      }
      if (error?.statusCode) {
        sendError(
          response,
          error.statusCode,
          error.code ?? 'BAD_REQUEST',
          error.message,
        );
        return;
      }
      console.error('Local event backend request failed:', error?.message ?? error);
      sendError(response, 500, 'SERVER', 'Internal server error.');
    }
  });
}
