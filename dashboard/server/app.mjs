import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { policyCapabilities, validatePolicyAction, validatePolicyVersion, validatePolicyStatus, normalizePolicyResponse } from './policy-capabilities.mjs';
import { JsonEventStore, AccessConflictError, EventConflictError, SettingsConflictError } from './event-store.mjs';
import { lookupRequest } from './demo-tools.mjs';
import {
  defaultGatewaySettings,
  gatewaySettingsDocument,
  gatewaySettingsUpdate,
  parseSettingsApplied,
  settingsAppliedKey,
  storedSettingsProblem,
  summarizeGatewaySettings,
  summarizeStoredSettings,
} from './gateway-settings.mjs';
import {
  ACCESS_METHODS,
  ACCESS_RULE_LIMIT,
  ALIAS_LIMIT,
  accessDocumentTooLarge,
  accessPath,
  accessRuleView,
  accessRulesView,
  activeRuleFor,
  gatewayAccessDocument,
  gatewayAccessState,
  isRuleId,
  newRule,
  ownAccessReasonCode,
  ownBlockDetails,
  parseAccessApplied,
  parseAliasClientId,
  parseAliasUpdate,
  parseExpectedVersionQuery,
  parseModeUpdate,
  parseRuleCreate,
  pruneRules,
  removeRule,
  ruleIsActive,
  storedRules,
  summarizeAccessMode,
  summarizeAlias,
  summarizeRule,
  BLOCK_DURATIONS,
} from './gateway-access.mjs';
import { buildOwnEvidence, documentPage, evidenceShowsRaw, evidenceTextLimit, ownReasonCode } from './match-evidence.mjs';
import { gatewayProcessingCutoff, withGatewayProcessing } from './processing-time.mjs';
import { collectSystemStatus, GATEWAY_METRICS_FRESH_MS, SYSTEM_STATUS_CACHE_MS } from './system-status.mjs';
import { isExcludedEvent, isTestEvent } from './test-events.mjs';
import { createSameTextService } from './same-text.mjs';
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

// ───────────────────────── 보안 이벤트 집계 기준 (2026-10-15 숫자 감사)
// 접속 차단: 확장 ID가 없거나 관리자가 막은 접속을 내용 검사 전에 거부한 기록. 보안 검사 결과가 아니라
// 보안 현황 카드·비율·추이·트래픽 저장 기록에서 빼고 따로 센다. 옛 이름(ip_blocked·extension_blocked)도 같은 뜻으로 받는다
// (Detection 리포트 src/reporting/aggregate.py ACCESS_RC·_cat와 같은 규칙, docs/handoff/report-count-fix-2026-10-15/FOLD_RULE.md)
export const ACCESS_REASON_CODES = new Set(['client_blocked', 'client_id_missing', 'ip_blocked', 'extension_blocked']);
// 2026-10-16 공통 규칙(docs/handoff/stats-rules-2026-10-16/SPEC.md 2.4): 사유 코드만 본다 — 보고서 _cat처럼 검출이 붙어 있어도
// 접속 차단(전에는 문서·키워드 검출이 있으면 접속 차단으로 안 봤다. 운영 자료에는 그런 기록이 0건이라 숫자는 같다)
export const isAccessBlockEvent = (event) => ACCESS_REASON_CODES.has(event?.reason_code);

// 재전송 접기: Detection 리포트 src/reporting/aggregate.py prepare_events의 규칙을 그대로 옮겼다(RESEND_GAP·RESEND_CUTOFF 같은 값).
// 같은 칸(client_id·target_llm·content_type·final_action·reason_code·file_id)의 파일 이벤트가 바로 앞 같은 칸 이벤트에서
// 4.348초 안에 다시 오고 2026-10-11 04:23 UTC 전이면 재전송 1건으로 접는다(그 뒤는 Gateway가 이미 묶어 보낸다).
// 시각·이벤트 ID 순으로 보고, 접힌 이벤트도 다음 비교의 '바로 앞'이 된다(리포트와 같음). 리포트처럼 고른 기간 안 이벤트에만 쓴다
export const RESEND_GAP_MS = 4_348;
export const RESEND_CUTOFF_MS = Date.parse('2026-10-11T04:23:00Z');

// 질문 재시도 접기(2026-10-16 공통 규칙 SPEC 2.3): 질문 본문 해시(판정 기록이 정확히 1행일 때 DB가 계산한
// md5(공백 정리한 prompt), 원문은 DB 밖으로 나오지 않음)가 같은 질문이 같은 칸(client_id·target_llm·final_action·reason_code)에서
// 4.348초 안에 다시 오면 접는다. 기준 시각 없음(Gateway는 파일만 묶는다). 해시 없는 질문(판정 기록 없음)은 접지 않고 추적도 안 한다.
// 해시는 저장소가 판정 기록에서 읽어 이 표에 넣는다(이벤트 번호 → 해시). 시험은 이벤트의 prompt_hash 칸으로 바로 줄 수 있다
export const promptHashes = new Map();
export const promptHashOf = (event) => event.prompt_hash ?? promptHashes.get(event.event_id) ?? null;

// 접을 기록(SPEC 3.2 의사코드 그대로): 시각·이벤트 ID 순으로 보며 파일 칸은 모든 기록이, 질문 칸은 해시 있는 질문만 '바로 앞'을 갱신
// (접힌 기록도 갱신 → 연쇄는 첫 기록만 남음). 리포트처럼 고른 기간 안 기록에만 쓴다(기간 첫 기록은 안 접힘)
export function foldedEventIds(events) {
  const ordered = [...events].sort((left, right) =>
    Date.parse(left.occurred_at) - Date.parse(right.occurred_at) || (left.event_id < right.event_id ? -1 : left.event_id > right.event_id ? 1 : 0));
  const lastFile = new Map();
  const lastPrompt = new Map();
  const file = new Set();
  const prompt = new Set();
  for (const event of ordered) {
    const at = Date.parse(event.occurred_at);
    const head = [event.client_id ?? '', event.target_llm ?? ''];
    const tail = [eventAction(event) ?? '', event.reason_code ?? ''];
    const fileKey = [...head, event.content_type ?? '', ...tail, event.file_id ?? ''].join('\n');
    const previous = lastFile.get(fileKey);
    lastFile.set(fileKey, at);
    if (event.content_type === 'file' && previous !== undefined && at - previous <= RESEND_GAP_MS && at < RESEND_CUTOFF_MS) { file.add(event.event_id); continue; }
    const hash = event.content_type === 'prompt' ? promptHashOf(event) : null;
    if (!hash) continue;
    const promptKey = [...head, 'prompt', ...tail, hash].join('\n');
    const before = lastPrompt.get(promptKey);
    lastPrompt.set(promptKey, at);
    if (before !== undefined && at - before <= RESEND_GAP_MS) prompt.add(event.event_id);
  }
  return { file, prompt };
}

// 재전송(파일) + 재시도(질문)로 접는 기록 번호
export function resendEventIds(events) {
  const { file, prompt } = foldedEventIds(events);
  return new Set([...file, ...prompt]);
}

// 보안 현황·보호 문서·목록 기본 보기가 세는 기록(SPEC 처리 순서: 시험·시연 제외는 호출자 → 접기 → 접속 차단 분리)
export function countedEvents(events) {
  const { file, prompt } = foldedEventIds(events);
  const access = [];
  const counted = [];
  for (const event of events) {
    if (file.has(event.event_id) || prompt.has(event.event_id)) continue;
    if (isAccessBlockEvent(event)) access.push(event);
    else counted.push(event);
  }
  return { counted, access, resend: file.size + prompt.size, resend_file: file.size, resend_prompt: prompt.size };
}

// 민감정보·기밀이 실제로 검출된 기록: 보호 문서 일치(문서 검출기가 낸 탐지) 또는 패턴 검사(SIGNATURE)가 값을 1개 이상 찾음.
// 리포트 _cat의 'doc'·'keyword'·패턴 값과 같은 판단(사유 코드만 있는 접속 차단·검사 불가·마스킹 실패는 들지 않는다)
export function hasSensitiveFinding(event) {
  return (event.detections ?? []).some((detection) => detection.detector !== 'SIGNATURE'
    || (detection.entity_counts ?? []).some((item) => item.count > 0));
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
const OWN_LIMIT = 100;

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

// 요청 ID(2026-10-12): 관리자 이벤트 상세의 '요청 ID'와 같은 값이라 관리자가 '요청 ID로 기록 조회'로 찾을 수 있다.
// 요청 ID가 없는 옛 기록은 트래픽 목록처럼 이벤트 ID로 대신한다(관리자는 '이벤트 ID'로 찾는다). 본인 요청의 식별자일 뿐 내용이 아니다
function ownRequestId(event) {
  return event.request_id ?? event.event_id;
}

// ruleFor(event): client_blocked 기록이 가리키는 차단 규칙(없으면 null) - 사유 코드·공개 메모를 본인 화면에 싣는다(2026-10-12)
function ownItem(event, ruleFor) {
  const reasonCode = ownReasonCode(event) ?? ownAccessReasonCode(event);   // 2026-10-10 검사하지 못했거나 가릴 수 없어 막은 사유(정해진 목록만) + 접속 차단 사유
  return {
    event_id: event.event_id,
    request_id: ownRequestId(event),
    occurred_at: event.occurred_at,
    target_llm: event.target_llm,
    content_type: event.content_type,
    final_action: eventAction(event),
    ...(event.group_final_action ? { group_final_action: event.group_final_action } : {}),
    protected_document: (event.detections ?? []).some((d) => d.detector !== 'SIGNATURE'),
    entity_counts: ownEntityCounts(event),
    ...(reasonCode ? { reason_code: reasonCode } : {}),
    ...(reasonCode === 'client_blocked' ? ownBlockDetails(ruleFor(event)) : {}),
    ...(event.attached_files ? { attached_files: event.attached_files.map((file) => ownItem(file, ruleFor)) } : {}),
  };
}

export function ownRequests(events, hash, now = Date.now(), ruleFor = () => null) {
  const mine = events.filter((event) => event.viewer_key_hash === hash && !isTestEvent(event) && now - Date.parse(event.occurred_at) <= OWN_WINDOW_MS);
  const acted = groupAttachments(mine)
    .filter((event) => ['BLOCK', 'MASK'].includes(event.group_final_action ?? eventAction(event)))
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at));
  const items = acted.slice(0, OWN_LIMIT).map((event) => ownItem(event, ruleFor));
  // 상한(2026-10-16): 최근 100건까지만 싣는다. 넘으면 truncated = true(화면이 '최근 100건까지 표시'를 알림). 옛 화면은 두 칸을 무시
  return { items, window_days: 7, limit: OWN_LIMIT, truncated: acted.length > OWN_LIMIT };
}

export function listEvents(events, searchParams, now = Date.now(), documentNames = new Map()) {
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
  // 집계와 같은 기록만(2026-10-15, 선택): counted = 접속 차단·재전송을 뺌(보안 현황 카드와 같은 기록), inspected = 접속 차단만 뺌
  // (트래픽 저장 기록). 칸이 없으면 지금처럼 전부(전체 기록).
  // 2026-10-16 보안 이벤트 목록 보기: 기본 보기 = counted(카드와 같은 건수), access = 접속 차단 기록만(카드가 따로 세는 기록).
  // counted·access로 물으면 같은 조건의 세 보기 건수(view_totals: counted·access·all)를 같이 싣는다 — 화면의 보기 전환 건수
  const scope = enumQuery(searchParams, 'scope', new Set(['counted', 'access', 'inspected']), null);
  const inPeriod = scope ? events.filter((event) => Date.parse(event.occurred_at) >= threshold) : null;
  const split = scope === 'counted' || scope === 'access' ? countedEvents(inPeriod) : null;
  const source = !scope ? events
    : scope === 'counted' ? split.counted
    : scope === 'access' ? split.access
    : inPeriod.filter((event) => !isAccessBlockEvent(event));
  const matches = (records) => (group === 'request' ? groupAttachments(records) : records).filter((item) => {
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
  const filtered = matches(source);

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
    ...(split ? {
      view_totals: {
        counted: scope === 'counted' ? filtered.length : matches(split.counted).length,
        access: scope === 'access' ? filtered.length : matches(split.access).length,
        all: matches(events).length,   // 접속 차단·재전송까지 전부(scope 없는 목록과 같은 수)
      },
    } : {}),
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

// 보안 현황 집계. 2026-10-15 숫자 감사로 기준을 정했다:
//  · 카드·추이·최근 이벤트 = 요청 단위. 보안 이벤트 목록(group=request)과 같은 묶음(첨부 파일은 프롬프트 아래, 조치는 가장 강한 것)
//  · 그래프(정보 유형·보호 문서·서비스·입력 형태·요일 시간대·정책 분류) = 기록 단위(프롬프트·파일 각각)
//  · 둘 다 접속 차단은 빼서 counting.access_blocked로 따로 싣고, 10/11 전 파일 재전송은 접는다(counting.resend_folded, 리포트와 같은 규칙)
//  · counting.list_total = 같은 기간 보안 이벤트 목록 건수(접속 차단·재전송 포함) — 화면이 카드와 목록의 차이를 적는 데 쓴다
export function dashboardStats(events, searchParams, now = Date.now()) {
  const period = enumQuery(
    searchParams,
    'period',
    new Set(['24H', '7D', '30D']),
    '30D',
  );
  const threshold = now - PERIOD_MS[period];
  const inPeriod = events.filter((event) => Date.parse(event.occurred_at) >= threshold);
  const { counted, access, resend, resend_file: resendFile, resend_prompt: resendPrompt } = countedEvents(inPeriod);
  const newestFirst = (left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at);
  const selected = [...counted].sort(newestFirst);                 // 기록 단위
  const requests = groupAttachments(counted).sort(newestFirst);     // 요청 단위(목록과 같은 묶음)
  const requestAction = (request) => request.group_final_action ?? eventAction(request);
  const members = (request) => [request, ...(request.attached_files ?? [])];
  const blocked = requests.filter((request) => requestAction(request) === 'BLOCK');
  const processing = selected
    .map((event) => event.processing_ms)
    .filter((value) => Number.isFinite(value) && value >= 0);
  const documentCounts = new Map();
  const trend = new Map();

  for (const event of selected) {
    const isBlocked = eventAction(event) === 'BLOCK';
    // 이벤트 1건에 같은 문서가 여러 번 검출돼도 1건(감사 12번)
    for (const documentId of new Set(documentIds(event))) increment(documentCounts, documentId, isBlocked);
  }
  for (const request of requests) {
    const bucket = request.occurred_at.slice(0, 10);
    const point = trend.get(bucket) ?? { bucket, total: 0, block: 0, mask: 0, allow: 0 };
    point.total += 1;
    point[requestAction(request).toLowerCase()] += 1;
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
  const enforcedBlocks = blocked.filter((request) => request.enforcement?.applied === true).length;

  // 보안 현황 그래프(2026-10-10): 정보 유형·보호 문서 상위, 서비스·입력 형태별 조치, 요일·시간대 분포(한국 시간, 차단·마스킹만)
  const entityCounts = new Map();
  const llmActions = new Map();
  const contentActions = new Map(['prompt', 'file'].map((key) => [key, { key, block: 0, mask: 0, allow: 0 }]));
  const heatmap = Array.from({ length: 7 }, () => Array(24).fill(0));
  const categoryCounts = new Map(['PII', 'CREDENTIAL', 'KEYWORD'].map((key) => [key, { key, events: 0, values: 0 }]));
  const entityEvents = new Map();   // 유형별로 그 유형이 하나라도 나온 이벤트 수(유형 정책의 적중용)
  for (const event of selected) {
    const action = String(eventAction(event)).toLowerCase();
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
    total: requests.length,
    block: blocked.length,
    mask: requests.filter((request) => requestAction(request) === 'MASK').length,
    allow: requests.filter((request) => requestAction(request) === 'ALLOW').length,
    degraded: selected.filter((event) => event.degraded === true).length,
    enforcement_rate: blocked.length === 0 ? 0 : enforcedBlocks / blocked.length,
    action_mismatch: selected.filter(
      (event) =>
        event.recommended_action !== undefined &&
        event.recommended_action !== eventAction(event),
    ).length,
    new_events: requests.filter((request) => request.status === 'NEW').length,
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
    ...(requests[0] ? { last_success_at: requests[0].occurred_at } : {}),
    trend: [...trend.values()].sort((left, right) => left.bucket.localeCompare(right.bucket)),
    recent: requests.slice(0, 10),
    counting: {
      unit: 'REQUEST',
      records: selected.length,
      list_total: groupAttachments(inPeriod).length,
      access_blocked: access.length,
      resend_folded: resend,
      resend_file: resendFile,       // 2026-10-16: 10/11 전 파일 재전송
      resend_prompt: resendPrompt,   // 2026-10-16: 4.348초 안 같은 질문 재시도(SPEC 2.3)
      // 민감정보·기밀이 실제로 검출돼 차단·마스킹한 요청(사유 코드만 있는 차단·검사 못 한 파일·마스킹 실패는 들지 않음)
      sensitive: requests.filter((request) => members(request).some((member) => eventAction(member) !== 'ALLOW' && hasSensitiveFinding(member))).length,
      // Detection 오류(검사 응답 없음) 기록의 마지막 시각 — 화면이 '지금 상태'와 '기간 중 기록'을 나눠 적는 데 쓴다
      ...(() => {
        const last = selected.find((event) => event.degraded === true);
        return last ? { last_degraded_at: last.occurred_at } : {};
      })(),
    },
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
  // 트래픽 저장 기록(2026-10-15): 접속 차단은 검사 기록이 아니라 빼고 건수만 따로(accessBlocked). 재전송은 접지 않는다(시도마다 실제로 처리함)
  const inPeriod = events.filter((event) => Date.parse(event.occurred_at) >= now - PERIOD_MS[period]);
  const selected = inPeriod
    .filter((event) => !isAccessBlockEvent(event))
    .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at));
  return { period, selected, accessBlocked: inPeriod.length - selected.length };
}

function percentile95(values) {
  if (values.length === 0) return undefined;
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * 0.95) - 1)];
}

export function trafficSummary(events, searchParams, now = Date.now()) {
  const { selected, accessBlocked } = eventsForPeriod(events, searchParams, now);
  const processing = selected
    .map((event) => event.processing_ms)
    .filter((value) => Number.isFinite(value) && value >= 0);   // 화면 그림과 같은 규칙(0 이상)
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
    access_blocked: accessBlocked,   // 위 건수·비율 분모에서 뺀 접속 차단 기록(2026-10-15)
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
    if (Number.isFinite(event.processing_ms) && event.processing_ms >= 0) bucket.processing.push(event.processing_ms);
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

// Gateway 상태(2026-10-10): Gateway가 몇 초마다 보내는 실시간 지표가 최근에 왔는지로 판정한다.
// 2026-10-15: '최근' = GATEWAY_METRICS_FRESH_MS(30초, 시스템 상태·연결 IP 표와 같은 값. 전에는 여기만 2분)
// 트래픽 화면과 같은 규칙 — 완료 요청이 없으면 상태는 판정하지 않고(요청 대기), 오류·검사 장애가 있으면 DEGRADED
// 2026-10-15(감사 4번): 판정 규칙을 한 곳에 — 트래픽 띠·보안 현황·시스템 상태가 같이 쓴다(시스템 상태는 DEGRADED를 '느림'으로).
//  · 새 Gateway(확장 칸 metrics_ext): 브라우저 취소를 뺀 Gateway 오류(connection_error_requests) 또는 검사 응답 없음(degraded_requests)이 있으면 DEGRADED
//  · 옛 Gateway: error_requests에 브라우저가 끊은 요청까지 들어 있어(10/11~10/15 가동 17회 중 16회 1~34건) 판정에 쓰지 않는다 → 검사 응답 없음만
export function liveGatewayState(metrics, now = Date.now()) {
  if (!metrics) return { status: 'UNKNOWN', metricsStatus: 'NOT_RECEIVED' };
  const age = now - Date.parse(metrics.received_at);
  if (!(age < GATEWAY_METRICS_FRESH_MS)) return { status: 'UNKNOWN', metricsStatus: 'STALE' };
  const ext = metrics.ext ?? null;
  const reasons = [];
  if (ext ? ext.connection_error_requests > 0 : false) reasons.push(`Gateway 오류 ${ext.connection_error_requests}건(브라우저 취소 제외)`);
  if (ext ? ext.degraded_requests > 0 : metrics.degraded_rate > 0) reasons.push(ext ? `보안 검사 응답 없음 ${ext.degraded_requests}건` : '보안 검사 응답 없음 기록');
  return {
    metricsStatus: 'FRESH',
    completed: metrics.completed_requests,
    status: metrics.completed_requests === 0 ? 'UNKNOWN' : reasons.length ? 'DEGRADED' : 'HEALTHY',
    ...(metrics.completed_requests !== 0 && reasons.length ? { reason: reasons.join(' · ') } : {}),
  };
}

// Gateway 지표 확장 칸(2026-10-15, docs/handoff/gateway-metrics-fix-2026-10-15/CONTRACT.md, Gateway gateway_metrics_ext.py).
// 대시보드가 지표 응답에 metrics_ext를 알려야 Gateway가 싣는다(옛 대시보드는 모르는 칸이면 지표 전체를 거부하므로).
// 칸이 틀리면 지표는 받고 확장 칸만 버린다(ext_rejected, 옛 Gateway처럼 표시)
export const METRICS_EXT_VERSION = 1;
export const GATEWAY_EXT_COUNT_FIELDS = ['latency_samples', 'inspected_requests', 'degraded_requests', 'timeout_requests',
  'inspected_timeout_requests', 'client_cancelled_requests', 'connection_error_requests'];
export function parseGatewayMetricsExt(body) {
  if (!Number.isSafeInteger(body.metrics_ext) || body.metrics_ext < 1) throw new Error('invalid metrics_ext');
  const ext = { version: body.metrics_ext };
  for (const name of GATEWAY_EXT_COUNT_FIELDS) {
    if (!Number.isSafeInteger(body[name]) || body[name] < 0) throw new Error(`invalid ${name}`);
    ext[name] = body[name];
  }
  if (ext.degraded_requests > ext.inspected_requests || ext.inspected_timeout_requests > ext.inspected_requests) throw new Error('counts exceed inspected_requests');
  return ext;
}

// 실시간 평균·P95가 Gateway 처리 시간인지(2026-10-11): 처리 시간을 새로 재는 Gateway만 settings_applied 칸을 보낸다(옛 Gateway 0건).
// 칸이 없으면 LLM 응답까지 잰 값일 수 있어(재시작 전·되돌린 옛 Gateway) 평균·P95를 싣지 않는다. 형식만 틀린 칸(REPORT_INVALID)도 새 Gateway가 보낸 것.
// 새 Gateway도 재시작 직후 첫 보고(최대 10초)와 백엔드가 설정을 아직 못 읽은 동안은 칸을 싣지 않는다 → 그동안도 싣지 않는다. 지표마다 다시 본다(되돌리면 바로 빠짐)
export function liveProcessingTimeReported(metrics) {
  return Boolean(metrics?.settings_applied || metrics?.settings_applied_invalid);
}

// Gateway 처리 설정 반영 상태(2026-10-10): 지표가 최근인지는 위와 같은 기준, 반영 여부는 revision으로 맞춘다.
// stored = 저장된 설정 행(없으면 null), firstSeen = { key, at } 같은 판을 처음 보고한 지표의 대시보드 받은 시각
export function gatewaySettingsState(stored, metrics, firstSeen = null, now = Date.now()) {
  const { metricsStatus } = liveGatewayState(metrics, now);
  const applied = metrics?.settings_applied ?? null;
  let state = 'PENDING';
  if (metricsStatus !== 'FRESH') state = 'NOT_REPORTING';
  else if (metrics.settings_applied_invalid) state = 'REPORT_INVALID';
  else if (!applied) state = 'LEGACY_GATEWAY';
  else if (stored ? applied.revision === stored.revision : applied.source === 'ENV_DEFAULT') state = 'APPLIED';
  else if (stored && applied.rejected?.revision === stored.revision) state = 'REJECTED';
  return {
    state,
    metrics_status: metricsStatus,
    reported_at: metrics?.received_at ?? null,
    applied_version: applied?.version ?? null,
    applied_revision: applied?.revision ?? null,
    applied_source: applied?.source ?? null,
    applied_at: applied?.applied_at ?? null,
    first_seen_at: applied && firstSeen?.key === settingsAppliedKey(applied) ? firstSeen.at : null,
    rejected: applied?.rejected ?? null,
    effective: applied?.effective ?? null,
  };
}

// 연결 중인 IP(2026-10-12): Gateway가 지표에 실어 보내는 접속 목록(선택, 옛 Gateway는 칸 없음).
// 하나라도 틀리면 예외 - 호출자는 지표는 받고 이 칸만 버린다(settings_applied와 같은 방식). 메모리에만 두고 기록하지 않는다
// 2026-10-12 대기 연결: 새 Gateway는 항목마다 waiting(30초 넘게 응답을 받는 중인 요청 수)을 더 보내고, 이때 inflight는 30초 미만만 센다.
// 옛 Gateway(8칸)도 받는다 - 저장·응답에서는 waiting 0으로 채운다. 그 밖의 칸은 지금처럼 엄격하다
const GATEWAY_CLIENT_FIELDS = ['ip', 'client_id', 'connections', 'inflight', 'requests_5m', 'targets', 'first_seen_at', 'last_seen_at'];
const GATEWAY_CLIENT_FIELDS_WITH_WAITING = [...GATEWAY_CLIENT_FIELDS, 'waiting'];
// 2026-10-15 확장 칸: IP 항목마다 by_client = 확장 ID별 묶음(IP 항목에서 ip를 뺀 모양, 최대 20개). 받으면 (IP, 확장 ID) 줄로 펼친다
const GATEWAY_CLIENT_GROUP_FIELDS = ['client_id', 'connections', 'inflight', 'waiting', 'requests_5m', 'targets', 'first_seen_at', 'last_seen_at'];
const GATEWAY_CLIENT_ROWS_MAX = 200;
const GATEWAY_CLIENT_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/;
export const GATEWAY_CLIENTS_WINDOW_SECONDS = 300;
export const GATEWAY_CLIENTS_STALE_MS = GATEWAY_METRICS_FRESH_MS;

function gatewayClientCount(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('invalid count');
  return value;
}

// UTC만 받는다(끝이 Z 또는 +00:00, Python isoformat 포함). 2026-02-30처럼 넘어가는 날짜는 거부. 돌려줄 때는 Z 형식으로 맞춘다
function gatewayClientTime(value) {
  if (typeof value !== 'string' || !GATEWAY_CLIENT_TIME.test(value)) throw new Error('invalid time');
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 19) !== value.slice(0, 19)) throw new Error('invalid time');
  return parsed.toISOString();
}

function parseClientGroup(ip, group) {
  if (typeof group !== 'object' || group === null || Array.isArray(group)) throw new Error('invalid client group');
  const keys = Object.keys(group);
  if (keys.length !== GATEWAY_CLIENT_GROUP_FIELDS.length || keys.some((key) => !GATEWAY_CLIENT_GROUP_FIELDS.includes(key))) throw new Error('invalid client group fields');
  return parseClientRow({ ip, ...group });
}

export function parseGatewayClients(value) {
  if (!Array.isArray(value) || value.length > 200) throw new Error('invalid clients');
  const rows = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) throw new Error('invalid client');
    const { by_client: groups, ...rest } = item;
    const ipRow = parseClientRow(rest);   // IP 항목 9칸은 지금 규칙 그대로(틀리면 목록 전체를 버림)
    if (groups === undefined) { rows.push(ipRow); continue; }
    // CONTRACT.md 3절: 틀린 by_client는 그 묶음만 버리고 IP 한 줄로(목록 전체를 버리지 않음)
    try {
      if (!Array.isArray(groups) || groups.length === 0 || groups.length > 20) throw new Error('invalid by_client');
      rows.push(...groups.map((group) => parseClientGroup(item.ip, group)));
    } catch {
      rows.push(ipRow);
    }
  }
  return rows
    .sort((a, b) => Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at))
    .slice(0, GATEWAY_CLIENT_ROWS_MAX);   // 화면 계약(최대 200줄)
}

function parseClientRow(item) {
      if (typeof item !== 'object' || item === null || Array.isArray(item)) throw new Error('invalid client');
      const keys = Object.keys(item);
      const expected = keys.includes('waiting') ? GATEWAY_CLIENT_FIELDS_WITH_WAITING : GATEWAY_CLIENT_FIELDS;
      if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) throw new Error('invalid client fields');
      if (typeof item.ip !== 'string' || item.ip.length > 45 || isIP(item.ip) === 0) throw new Error('invalid ip');
      if (item.client_id !== null && (typeof item.client_id !== 'string' || !item.client_id || item.client_id.length > 80))
        throw new Error('invalid client_id');
      const { targets } = item;
      if (typeof targets !== 'object' || targets === null || Array.isArray(targets)) throw new Error('invalid targets');
      const names = Object.keys(targets);
      if (names.length > 10 || names.some((name) => !name || name.length > 64)) throw new Error('invalid targets');
      return {
        ip: item.ip,
        client_id: item.client_id,
        connections: gatewayClientCount(item.connections),
        inflight: gatewayClientCount(item.inflight),
        waiting: expected === GATEWAY_CLIENT_FIELDS ? 0 : gatewayClientCount(item.waiting),
        requests_5m: gatewayClientCount(item.requests_5m),
        targets: Object.fromEntries(names.map((name) => [name, gatewayClientCount(targets[name])])),
        first_seen_at: gatewayClientTime(item.first_seen_at),
        last_seen_at: gatewayClientTime(item.last_seen_at),
      };
}

// 릴레이 연결 상태(2026-10-12): Gateway가 지표에 실어 보내는 선택 칸 { ok, connected, registered }.
// 모양이 틀리면 예외 - 호출자는 지표는 받고 이 칸만 버린다(clients와 같은 방식). 메모리에만 두고 기록하지 않는다
export function parseGatewayRelay(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid relay');
  const keys = Object.keys(value);
  if (keys.length !== 3 || !['ok', 'connected', 'registered'].every((key) => keys.includes(key))) throw new Error('invalid relay fields');
  if (typeof value.ok !== 'boolean') throw new Error('invalid relay ok');
  return { ok: value.ok, connected: gatewayClientCount(value.connected), registered: gatewayClientCount(value.registered) };
}

// GET /api/traffic/clients 응답. 지표가 없거나 30초 넘게 안 오면 stale(목록은 마지막 보고 그대로)
export function gatewayClientsView(metrics, now = Date.now()) {
  const receivedAt = metrics?.received_at ?? null;
  return {
    received_at: receivedAt,
    stale: receivedAt === null || !(now - Date.parse(receivedAt) < GATEWAY_CLIENTS_STALE_MS),
    window_seconds: GATEWAY_CLIENTS_WINDOW_SECONDS,
    clients: metrics?.clients ?? [],
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
    // 2026-10-10 Gateway 처리 설정 적용 보고(선택). 형식이 틀리면 지표는 받고 이 칸만 버린다(REPORT_INVALID)
    'settings_applied',
    // 2026-10-12 연결 중인 IP 목록(선택). 틀리면 지표는 받고 이 칸만 버린다
    'clients',
    // 2026-10-12 릴레이 연결 상태(선택). 틀리면 지표는 받고 이 칸만 버린다
    'relay',
    // 2026-10-12 접속 차단 적용 보고(선택). 틀리면 지표는 받고 이 칸만 버린다
    'access_applied',
    // 2026-10-15 확장 칸(선택, metrics_ext를 알린 뒤에만 옴). 틀리면 지표는 받고 확장 칸만 버린다
    'metrics_ext',
    ...GATEWAY_EXT_COUNT_FIELDS,
  ];
  const optional = new Set(['event_delivery', 'settings_applied', 'clients', 'relay', 'access_applied', 'metrics_ext', ...GATEWAY_EXT_COUNT_FIELDS]);
  const body = exactObject(value, fields, fields.filter((name) => !optional.has(name)));
  let ext = null;
  let extRejected = null;
  if (body.metrics_ext !== undefined || GATEWAY_EXT_COUNT_FIELDS.some((name) => body[name] !== undefined)) {
    // CONTRACT.md 4절 1: metrics_ext가 있으면 8칸이 모두 맞아야 받는다(틀리거나 빠지면 400 → Gateway가 확장 칸을 끄고 300초 뒤 다시 시도, 지표는 10/14 칸으로 계속)
    try {
      ext = parseGatewayMetricsExt(body);
    } catch (error) {
      console.warn(`Gateway metrics extension rejected: ${error.message}`);
      const rejected = new Error('Invalid metrics extension fields.');
      rejected.statusCode = 400;
      throw rejected;
    }
  }
  // 새 Gateway는 표본이 0건이면 평균·P95를 0.0 대신 null로 보낸다(확장 칸이 맞을 때만 받는다)
  for (const name of ['avg_latency_ms', 'p95_latency_ms'])
    if (body[name] === null && ext && ext.latency_samples === 0) body[name] = undefined;
  for (const name of [
    'active_clients',
    'concurrent_requests',
    'total_requests',
    'completed_requests',
    'error_requests',
    'window_seconds',
  ])
    finiteNumber(body[name], name, { integer: true });
  finiteNumber(body.requests_per_sec, 'requests_per_sec');
  for (const name of ['avg_latency_ms', 'p95_latency_ms'])
    if (!(ext && body[name] === undefined)) finiteNumber(body[name], name);
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
  const { settings_applied: reported, clients: reportedClients, relay: reportedRelay, access_applied: reportedAccess, metrics_ext: _ext, ...rest } = body;
  const metrics = Object.fromEntries(Object.entries(rest).filter(([name, item]) => !GATEWAY_EXT_COUNT_FIELDS.includes(name) && item !== undefined));
  let applied = null;
  if (reported !== undefined) {
    try {
      applied = parseSettingsApplied(reported);
    } catch {
      applied = null;
    }
  }
  let clients = null;
  let clientsRejected = null;
  if (reportedClients !== undefined) {
    try {
      clients = parseGatewayClients(reportedClients);
    } catch (error) {
      clientsRejected = error.message;
    }
  }
  let relay = null;
  let relayRejected = null;
  if (reportedRelay !== undefined) {
    try {
      relay = parseGatewayRelay(reportedRelay);
    } catch (error) {
      relayRejected = error.message;
    }
  }
  let access = null;
  let accessRejected = null;
  if (reportedAccess !== undefined) {
    try {
      access = parseAccessApplied(reportedAccess);
    } catch (error) {
      accessRejected = error.message;
    }
  }
  return {
    ...metrics,
    ...(access ? { access_applied: access } : {}),
    ...(accessRejected ? { access_rejected: accessRejected } : {}),
    ...(applied ? { settings_applied: applied } : {}),
    ...(reported !== undefined && !applied ? { settings_applied_invalid: true } : {}),
    ...(clients ? { clients } : {}),
    ...(clientsRejected ? { clients_rejected: clientsRejected } : {}),
    ...(relay ? { relay } : {}),
    ...(relayRejected ? { relay_rejected: relayRejected } : {}),
    ...(ext ? { ext } : {}),
    ...(extRejected ? { ext_rejected: extRejected } : {}),
    received_at: new Date().toISOString(),
  };
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

// 보호 문서 '누적 탐지'(2026-10-15): DB가 센 수(문서 ID가 같은 이벤트 전부)를 보안 현황과 같은 기록으로 다시 센다 —
// 시험 제외(호출자) · 재전송 접기(리포트 규칙, countedEvents) · 이벤트 1건에 같은 문서는 1건. 마지막 탐지 시각도 같은 기록에서
export function withCountedDocumentDetections(documents, events) {
  const counts = new Map();
  for (const event of countedEvents(events).counted)
    for (const detection of event.detections ?? []) {
      if (!detection.matched_document_id) continue;
      const id = String(detection.matched_document_id);
      const count = counts.get(id) ?? { exact: new Set(), partial: new Set(), last: 0 };
      if (detection.match_type === 'EXACT_DOCUMENT') count.exact.add(event.event_id);
      if (detection.match_type === 'TEXT_FRAGMENT' || detection.match_type === 'SIMILAR_DOCUMENT') count.partial.add(event.event_id);
      count.last = Math.max(count.last, Date.parse(event.occurred_at));
      counts.set(id, count);
    }
  return documents.map((document) => {
    const count = counts.get(String(document.document_id));
    const { last_detected_at: _previous, ...rest } = document;
    return {
      ...rest,
      exact_detection_count: count?.exact.size ?? 0,
      modified_partial_detection_count: count?.partial.size ?? 0,
      ...(count?.last ? { last_detected_at: new Date(count.last).toISOString() } : {}),
    };
  });
}

export function mergeFingerprintEvidence(documents, evidence) {
  const byId = new Map(
    evidence.map((item) => [String(item.document_id), item]),
  );
  return documents.map((document) => {
    const fingerprint = byId.get(document.document_id);
    // RDS가 이번 판 색인 실패(FAILED)라고 하면 Detection에 남은 옛 판 색인으로 '보호 중'을 만들지 않는다(2026-10-15 감사 13번)
    if (fingerprint?.indexed === true && document.processing_status !== 'FAILED') {
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

// ───────────────────────── 보호 문서 본문 보기 (2026-10-13, 설계안 6장)
// 열람 시작(POST …/views)마다 감사 DOCUMENT_VIEW를 먼저 남기고(실패 = 열람 불가) 열람 번호를 준다.
// 열람 번호는 서버 메모리에만 있고 발급한 세션·문서·판에 묶인다. 원본·텍스트는 이 번호가 있어야 준다
const DOCUMENT_VIEW_TTL_MS = 28_800_000;   // 로그인 쿠키 수명(Max-Age=28800)과 같다
const DOCUMENT_VIEW_LIMIT = 1_000;         // 메모리 보호: 넘으면 가장 오래된 번호부터 버린다
const DOCUMENT_VIEW_ID = /^[A-Za-z0-9_-]{22}$/;   // 무작위 128비트(base64url)
const DOCUMENT_VIEW_MODES = new Set(['original', 'text']);
// Content-Type은 등록 때 서버가 파일 머리로 확인한 format 칸으로만 정한다(파일 이름을 믿지 않음). HWP·HWPX·모르는 형식은 그냥 바이트
const DOCUMENT_CONTENT_TYPES = new Map([
  ['pdf', 'application/pdf'],
  ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
]);

// DASHBOARD_DOCUMENT_VIEW: 비우거나 on = 켬, off = 경로 없음(404). 다른 값은 잘못 쓴 것이라 시작하지 않는다(끈 줄 알고 켜 둔 채 두지 않게)
export function documentViewEnabled(value) {
  const setting = String(value ?? '').trim().toLowerCase();
  if (setting === '' || setting === 'on') return true;
  if (setting === 'off') return false;
  throw new Error('DASHBOARD_DOCUMENT_VIEW must be "on" or "off" (empty means on).');
}

function documentViewPath(pathname) {
  const match = /^\/api\/documents\/([^/]+)\/(views|original|text)$/.exec(pathname);
  return match ? { rawId: match[1], kind: match[2] } : null;
}

// 파일 이름은 등록한 사람이 정한 값이다. 제어 문자(개행 등)·방향 바꿈 문자·경로 구분자를 빼고 RFC 5987 인코딩으로만 싣는다(머리 주입 방지)
export function attachmentDisposition(filename, format) {
  const cleaned = Array.from(
    String(filename ?? '')
      .toWellFormed()
      .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028-\u202e\u2066-\u2069\\/]/g, '')
      .trim(),
  ).slice(0, 200).join('');
  const name = cleaned || `document${format ? `.${format}` : ''}`;
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename*=UTF-8''${encoded}`;
}

// 열람 시작 요청 본문은 없어도 된다(= 원본 모양). 있으면 {"mode": "original" | "text"}만 - 감사 기록의 mode
async function readDocumentViewMode(request) {
  const length = request.headers['content-length'];
  if ((length === undefined || length === '0') && request.headers['transfer-encoding'] === undefined) return 'original';
  const body = exactObject(await readJson(request, 1024), ['mode'], []);
  const mode = body.mode ?? 'original';
  if (!DOCUMENT_VIEW_MODES.has(mode)) {
    const error = new Error('mode must be "original" or "text".');
    error.statusCode = 422;
    error.code = 'VALIDATION';
    throw error;
  }
  return mode;
}

function policyPath(pathname) {
  if (pathname === '/api/policies/capabilities') return { operation: 'capabilities' };
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

// Detection이 5xx로 답함(응답은 받았으나 서버 안에서 실패). 502로 전하고 원래 상태는 upstream_status로 남긴다
function upstreamServerError(status) {
  const error = new Error(`Detection API failed with HTTP ${status}.`);
  error.statusCode = 502;
  error.code = 'POLICY_UPSTREAM_SERVER_ERROR';
  error.upstreamStatus = status;
  return error;
}

async function detectionPolicyRequest(baseUrl, pathname, { method = 'GET', body, adminId, timeoutMs = 3_000 } = {}) {
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
      signal: AbortSignal.timeout(timeoutMs),
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
    // 2026-10-16: Detection 5xx(예: FastAPI 'Internal Server Error' 글 응답)는 응답 해석 실패가 아니라 탐지 서버 오류로 구분한다
    if (response.status >= 500) throw upstreamServerError(response.status);
    const error = new Error('Detection policy API returned invalid JSON.');
    error.statusCode = 502;
    error.code = 'POLICY_UPSTREAM_INVALID_RESPONSE';
    throw error;
  }
  if (!response.ok) {
    const detail = payload?.detail;
    // 5xx인데 Detection이 정한 코드가 없으면 탐지 서버 오류(코드가 있으면 그 코드를 그대로 전한다)
    if (response.status >= 500 && typeof detail?.code !== 'string') throw upstreamServerError(response.status);
    const error = new Error(detail?.message ?? 'Detection policy request failed.');
    error.statusCode = response.status;
    error.code = detail?.code ?? 'POLICY_UPSTREAM_ERROR';
    throw error;
  }
  return pathname === '/admin/policies' || pathname.startsWith('/admin/policies/')
    ? normalizePolicyResponse(payload) : payload;
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
  if (pathname === '/api/system/status') return { kind: 'system-status' };
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
  gatewaySettingsRetryMs = 1_000,
  gatewayProcessingSince,
  documentView = process.env.DASHBOARD_DOCUMENT_VIEW,
  documentViewTtlMs = DOCUMENT_VIEW_TTL_MS,
  documentViewLimit = DOCUMENT_VIEW_LIMIT,
}) {
  const eventStore = store ?? new JsonEventStore(storePath);
  // 이벤트는 모두 이 두 함수로 읽는다: 처리 시간 기준이 바뀌기 전 이벤트의 processing_ms를 뺀다(processing-time.mjs)
  const processingSince = gatewayProcessingCutoff(gatewayProcessingSince);
  const readEvents = async () => {
    const events = (await eventStore.list()).map((event) => withGatewayProcessing(event, processingSince));
    // 질문 재시도 접기용 본문 해시(2026-10-16): 판정 기록을 읽는 저장소만(PostgreSQL). 읽지 못하면 접지 않고 그대로 센다
    if (eventStore.promptHashes) {
      try {
        for (const [eventId, hash] of await eventStore.promptHashes(events)) promptHashes.set(eventId, hash);
      } catch (error) {
        console.error('Prompt hash lookup failed:', error?.message ?? error);
      }
    }
    return events;
  };
  const readEvent = async (eventId) => withGatewayProcessing(await eventStore.get(eventId), processingSince);
  // '일치 비율' 통일(2026-10-16): 문서 구간 일치 탐지에 '입력 중 문서와 같은 글자' 비율(same_text)을 붙인다(same-text.mjs)
  const sameText = createSameTextService(eventStore);
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
  let gatewayClientsRejected = null;
  let gatewayRelayRejected = null;
  let gatewayAccessRejected = null;
  let gatewayExtRejected = null;
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

  // ───────────────────────── 보호 문서 본문 보기 (2026-10-13)
  // 이 경로만 감사 기록 실패 = 거절(403). 열람 번호·원본을 주기 전에 기록한다(recordAuditSafely는 실패해도 넘어가므로 쓰지 않는다)
  const recordAuditStrict = async (record) => {
    try {
      await eventStore.recordAudit(record);
    } catch (error) {
      console.error('Document view audit write failed:', error?.message ?? error);
      const refused = new Error('The document view could not be recorded, so it was refused.');
      refused.statusCode = 403;
      refused.code = 'AUDIT_REQUIRED';
      throw refused;
    }
  };
  const documentViewOn = documentViewEnabled(documentView);
  if (!Number.isSafeInteger(documentViewTtlMs) || documentViewTtlMs < 1 || !Number.isSafeInteger(documentViewLimit) || documentViewLimit < 1)
    throw new Error('Document view lifetime and limit must be positive integers.');
  // 열람 번호 → { session, documentId, version, viewRef, expiresAt }. 세션이 끝나면(로그아웃·재시작) 함께 못 쓴다
  const documentViews = new Map();
  const pruneDocumentViews = (now) => {
    for (const [id, view] of documentViews)
      if (view.expiresAt <= now || !sessions.has(view.session)) documentViews.delete(id);
    while (documentViews.size >= documentViewLimit) documentViews.delete(documentViews.keys().next().value);
  };
  // 같은 세션·같은 문서·만료 전인 번호만. 왜 거절했는지는 알려 주지 않는다(모두 403)
  const documentViewFor = (sessionToken, documentId, viewId) => {
    if (typeof viewId !== 'string' || !DOCUMENT_VIEW_ID.test(viewId)) return null;
    const view = documentViews.get(viewId);
    if (!view || view.expiresAt <= Date.now()) return null;
    return view.session === sessionToken && view.documentId === documentId ? view : null;
  };

  // ───────────────────────── Gateway 처리 설정 (2026-10-10)
  // 지표 응답(Gateway 제한시간 0.3초)에서 DB를 읽지 않도록 메모리 사본을 둔다. undefined = 아직 못 읽음, null = 저장된 설정 없음.
  // 시작 때 읽고, 실패하면 지표 처리와 따로 타이머로 다시 읽는다(1·2·4·…·최대 60초). 그동안 지표 응답에 칸을 싣지 않고 조회·저장은 503
  let gatewaySettings;
  let gatewaySettingsLoad = null;
  let gatewaySettingsRetry = null;
  let gatewaySettingsDelay = gatewaySettingsRetryMs;
  let gatewaySettingsStopped = false;
  let gatewaySettingsSeen = null;
  const loadGatewaySettings = () => {
    if (gatewaySettings !== undefined || gatewaySettingsLoad || gatewaySettingsStopped) return;
    if (typeof eventStore.getGatewaySettings !== 'function') return;
    gatewaySettingsLoad = Promise.resolve()
      .then(() => eventStore.getGatewaySettings())
      .then(
        (row) => {
          if (gatewaySettings === undefined) gatewaySettings = row ?? null;
        },
        (error) => {
          console.error('Gateway settings read failed:', error?.message ?? error);
          if (gatewaySettingsStopped) return;
          gatewaySettingsRetry = setTimeout(() => {
            gatewaySettingsRetry = null;
            loadGatewaySettings();
          }, gatewaySettingsDelay);
          gatewaySettingsRetry.unref?.();
          gatewaySettingsDelay = Math.min(gatewaySettingsDelay * 2, 60_000);
        },
      )
      .finally(() => {
        gatewaySettingsLoad = null;
      });
  };
  // 시작 때 읽기가 진행 중이면 기다린다(조회·저장만, 지표는 기다리지 않는다)
  const gatewaySettingsReady = async () => {
    if (gatewaySettingsLoad) await gatewaySettingsLoad;
    return gatewaySettings !== undefined;
  };
  // 저장소가 번호 충돌을 알리면 사본이 DB와 다를 수 있으므로 다시 읽는다. 그사이 다른 저장이 사본을 바꿨으면 그 값을 둔다
  const refreshGatewaySettings = async () => {
    const before = gatewaySettings;
    try {
      const row = await eventStore.getGatewaySettings();
      if (gatewaySettings === before) gatewaySettings = row ?? null;
    } catch (error) {
      console.error('Gateway settings read failed:', error?.message ?? error);
    }
  };
  // 저장된 행의 값이 형식에 맞지 않으면(손으로 넣은 행 등) 그 번호에 기본값을 보여 주고 settings_invalid로 틀린 칸을 알린다.
  // 화면이 열려 그 위에 맞는 판을 저장할 수 있어야 한다. Gateway에는 저장된 그대로 보내 거부(REJECTED)하게 둔다(마지막 값 유지)
  const gatewaySettingsResponse = () => {
    const invalidField = gatewaySettings ? storedSettingsProblem(gatewaySettings.settings) : null;
    return {
      settings: gatewaySettings
        ? {
            ...gatewaySettingsDocument(invalidField ? { ...gatewaySettings, settings: defaultGatewaySettings() } : gatewaySettings),
            source: 'STORED',
          }
        : { version: 0, revision: null, updated_at: null, updated_by: null, ...defaultGatewaySettings(), source: 'DEFAULT' },
      ...(invalidField ? { settings_invalid: { field: invalidField } } : {}),
      defaults: defaultGatewaySettings(),
      gateway: gatewaySettingsState(gatewaySettings, latestGatewayMetrics, gatewaySettingsSeen),
    };
  };

  // ───────────────────────── 접속 차단 (2026-10-12)
  // Gateway 처리 설정과 같은 구조: 지표 응답에서 DB를 읽지 않도록 메모리 사본을 둔다. undefined = 아직 못 읽음, null = 저장된 목록 없음.
  // 시작 때 읽고, 실패하면 타이머로 다시 읽는다(1·2·4·…·최대 60초). 그동안 지표 응답에 gateway_access 칸을 싣지 않고(Gateway는 지금 목록 유지) 조회·저장은 503
  let gatewayAccess;
  let gatewayAccessLoad = null;
  let gatewayAccessRetry = null;
  let gatewayAccessDelay = gatewaySettingsRetryMs;
  let gatewayAccessStopped = false;
  const loadGatewayAccess = () => {
    if (gatewayAccess !== undefined || gatewayAccessLoad || gatewayAccessStopped) return;
    if (typeof eventStore.getGatewayAccess !== 'function') return;
    gatewayAccessLoad = Promise.resolve()
      .then(() => eventStore.getGatewayAccess())
      .then(
        (row) => {
          if (gatewayAccess === undefined) gatewayAccess = row ?? null;
        },
        (error) => {
          console.error('Gateway access read failed:', error?.message ?? error);
          if (gatewayAccessStopped) return;
          gatewayAccessRetry = setTimeout(() => {
            gatewayAccessRetry = null;
            loadGatewayAccess();
          }, gatewayAccessDelay);
          gatewayAccessRetry.unref?.();
          gatewayAccessDelay = Math.min(gatewayAccessDelay * 2, 60_000);
        },
      )
      .finally(() => {
        gatewayAccessLoad = null;
      });
  };
  const gatewayAccessReady = async () => {
    if (gatewayAccessLoad) await gatewayAccessLoad;
    return gatewayAccess !== undefined;
  };
  // 저장소가 번호 충돌을 알리면 사본이 DB와 다를 수 있으므로 다시 읽는다. 그사이 다른 저장이 사본을 바꿨으면 그 값을 둔다
  const refreshGatewayAccess = async () => {
    const before = gatewayAccess;
    try {
      const row = await eventStore.getGatewayAccess();
      if (gatewayAccess === before) gatewayAccess = row ?? null;
    } catch (error) {
      console.error('Gateway access read failed:', error?.message ?? error);
    }
  };
  // 관리자 화면용: 모든 규칙(active 표시)·방식·Gateway가 마지막으로 보고한 적용 상태
  const gatewayAccessResponse = () => {
    const now = Date.now();
    const reported = latestGatewayMetrics?.access_applied;
    return {
      version: gatewayAccess?.version ?? 0,
      revision: gatewayAccess?.revision ?? null,
      require_client_id: gatewayAccess?.require_client_id ?? false,
      rules: gatewayAccess ? accessRulesView(gatewayAccess, now) : [],
      applied: reported ? { ...reported, received_at: latestGatewayMetrics.received_at } : null,
      gateway: gatewayAccessState(gatewayAccess, latestGatewayMetrics, liveGatewayState(latestGatewayMetrics, now).metricsStatus),
    };
  };
  // 내 요청 기록(2026-10-12): client_blocked 기록이 가리키는 규칙을 메모리 사본에서 찾는다(DB를 읽지 않음). 이벤트와 규칙의 확장 ID가 같을 때만.
  // 해제·만료된 규칙도 목록에 남아 있는 동안은 찾는다(오래되어 정리됐으면 null → 사유 줄 없이 '접속 차단'만 보인다)
  const ownAccessRule = (event) => {
    if (event.reason_code !== 'client_blocked' || typeof event.access_rule_id !== 'string' || !gatewayAccess) return null;
    const rule = storedRules(gatewayAccess).find((item) => item.id === event.access_rule_id);
    return rule && rule.client_id === event.client_id ? rule : null;
  };
  // 새 판을 저장하고(감사 행과 한 트랜잭션) 메모리 사본을 바꾼다. 번호 충돌이면 사본을 다시 읽는다
  const saveGatewayAccess = async ({ previous, requireClientId, rules, audit }) => {
    try {
      gatewayAccess = await eventStore.saveGatewayAccess({
        expectedVersion: previous?.version ?? 0,
        revision: randomUUID(),
        requireClientId,
        rules,
        updatedBy: audit.adminId,
        audit,
      });
    } catch (error) {
      if (error instanceof AccessConflictError) await refreshGatewayAccess();
      throw error;
    }
  };
  const accessVersions = (previous) => ({
    ...((previous?.version ?? 0) > 0 ? { previous_version: previous.version } : {}),
    new_version: (previous?.version ?? 0) + 1,
  });

  // ───────────────────────── 시스템 상태 (2026-10-12)
  // GET /api/system/status: 점검 결과를 5초 동안 그대로 돌려준다(화면 15초 새로고침·여러 창이 와도 점검은 5초에 한 번).
  // 점검 중에 들어온 요청은 같은 점검을 기다린다. 점검은 DB(SELECT 1)·Detection(/admin/system-status, /admin/gpu)을 부르며 /detect 경로와 무관하다
  let systemStatusCache = null;
  let systemStatusPending = null;
  const systemStatus = async (adminId) => {
    if (systemStatusCache && Date.now() - systemStatusCache.at < SYSTEM_STATUS_CACHE_MS) return systemStatusCache.value;
    systemStatusPending ??= collectSystemStatus({
      store: eventStore,
      getGateway: () => ({
        metrics: latestGatewayMetrics,
        liveState: liveGatewayState(latestGatewayMetrics),
        settingsState: gatewaySettingsState(gatewaySettings, latestGatewayMetrics, gatewaySettingsSeen),
      }),
      fetchDetection: (pathname, options) => detectionPolicyRequest(policyBaseUrl, pathname, { ...options, adminId }),
    })
      .then((value) => {
        systemStatusCache = { at: Date.now(), value };
        return value;
      })
      .finally(() => {
        systemStatusPending = null;
      });
    return systemStatusPending;
  };

  const server = createServer(async (request, response) => {
    setCors(response, request, allowedOrigin);
    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
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
        if (sessionToken) {
          sessions.delete(sessionToken);
          // 이 세션의 문서 열람 번호도 함께 끝낸다
          for (const [id, view] of documentViews) if (view.session === sessionToken) documentViews.delete(id);
        }
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
          sendJson(response, 200, ownRequests(await readEvents(), viewerHash, Date.now(), ownAccessRule));
          return;
        }
        const match = /^\/api\/my\/requests\/([^/]{1,200})\/evidence$/.exec(url.pathname);
        let eventId = null;
        try {
          eventId = match ? decodeURIComponent(match[1]) : null;
        } catch {
          eventId = null;
        }
        const event = eventId ? await readEvent(eventId) : null;
        if (!event || event.viewer_key_hash !== viewerHash) {
          sendError(response, 404, 'NOT_FOUND', 'Request not found.');
          return;
        }
        const stored = eventStore.getOwnEvidence ? await eventStore.getOwnEvidence(event) : buildOwnEvidence(event, null, null);
        const evidence = { ...stored, request_id: ownRequestId(event) };   // 목록 항목과 같은 요청 ID(2026-10-12)
        // 접속 차단 기록: 고정 사유 코드(+ client_blocked는 규칙의 사유 코드·공개 메모)를 근거 응답에도 싣는다(2026-10-12)
        const accessReason = ownAccessReasonCode(event);
        sendJson(response, 200, accessReason
          ? { ...evidence, reason_code: accessReason, ...(accessReason === 'client_blocked' ? ownBlockDetails(ownAccessRule(event)) : {}) }
          : evidence);
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
        sendJson(response,200,lookupRequest(await readEvents(),url.searchParams));
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
        const allEvents = await readEvents();
        const includeTest = url.searchParams.get('include_test') === '1';
        // 2026-10-16: 시험 접두어 + 시연 문서만 일치한 기록을 같이 뺀다(SPEC 2.1·2.2, '시험·데모 n건 제외'에 같이 셈)
        const listed = listEvents(includeTest ? allEvents : allEvents.filter((event) => !isExcludedEvent(event)), url.searchParams, Date.now(), names);
        const page = { ...listed, items: await sameText.annotate(listed.items) };
        // 같은 조건에서 빠진 시험·데모 건수. 0이면 싣지 않아 기존 응답 모양을 그대로 둔다
        const excludedTest = includeTest ? 0 : listEvents(allEvents.filter(isExcludedEvent), url.searchParams, Date.now(), names).total;
        sendJson(response, 200, excludedTest ? { ...page, excluded_test: excludedTest } : page);
        return;
      }

      if (url.pathname === '/api/dashboard/stats' && request.method === 'GET') {
        if (!requireSession(request, sessions)) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const gateway = liveGatewayState(latestGatewayMetrics);
        const stats = dashboardStats((await readEvents()).filter((event) => !isExcludedEvent(event)), url.searchParams);
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
        // 연결 IP 칸을 버릴 때 처음 한 번만 남긴다(사유만, IP 값은 남기지 않음)
        const clientsRejected = latestGatewayMetrics.clients_rejected ?? null;
        if (clientsRejected && clientsRejected !== gatewayClientsRejected)
          console.warn(`Gateway clients report ignored: ${clientsRejected}`);
        gatewayClientsRejected = clientsRejected;
        // 릴레이 칸도 같은 방식: 버릴 때 처음 한 번만 사유를 남긴다
        const relayRejected = latestGatewayMetrics.relay_rejected ?? null;
        if (relayRejected && relayRejected !== gatewayRelayRejected)
          console.warn(`Gateway relay report ignored: ${relayRejected}`);
        gatewayRelayRejected = relayRejected;
        // 접속 차단 적용 보고도 같은 방식
        const accessRejected = latestGatewayMetrics.access_rejected ?? null;
        if (accessRejected && accessRejected !== gatewayAccessRejected)
          console.warn(`Gateway access report ignored: ${accessRejected}`);
        gatewayAccessRejected = accessRejected;
        const applied = latestGatewayMetrics.settings_applied;
        if (applied && gatewaySettingsSeen?.key !== settingsAppliedKey(applied))
          gatewaySettingsSeen = { key: settingsAppliedKey(applied), at: latestGatewayMetrics.received_at };
        // 응답으로 Gateway 처리 설정을 준다(메모리 사본만, DB를 읽지 않음). 저장된 것이 없으면 null(→ Gateway 환경변수 기본값),
        // 아직 못 읽었으면 칸을 싣지 않는다(→ Gateway는 지금 값 유지)
        // 접속 차단 목록도 같은 응답으로(2026-10-12): 못 읽었으면 칸 없음(Gateway는 유지), 저장된 것이 없으면 null(Gateway는 비움).
        // 문서를 만들다 예외가 나도 지표 응답은 보낸다(칸만 뺀다)
        let accessField = {};
        if (gatewayAccess !== undefined) {
          try {
            accessField = { gateway_access: gatewayAccessDocument(gatewayAccess) };
          } catch (error) {
            console.error('Gateway access document failed:', error?.message ?? error);
          }
        }
        const extRejected = latestGatewayMetrics.ext_rejected ?? null;
        if (extRejected && extRejected !== gatewayExtRejected)
          console.warn(`Gateway metrics extension ignored: ${extRejected}`);
        gatewayExtRejected = extRejected;
        sendJson(response, 202, {
          accepted: true,
          // 2026-10-15: 이 대시보드는 확장 칸(표본 수·검사 요청 수·브라우저 취소 수·IP 안 확장 ID 묶음)을 받는다
          metrics_ext: METRICS_EXT_VERSION,
          ...(gatewaySettings === undefined ? {} : { gateway_settings: gatewaySettingsDocument(gatewaySettings) }),
          ...accessField,
        });
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
        // 연결 중인 IP(2026-10-12): 마지막 지표의 메모리 사본만 본다(저장 이벤트·DB를 읽지 않음)
        if (url.pathname === '/api/traffic/clients') {
          sendJson(response, 200, gatewayClientsView(latestGatewayMetrics));
          return;
        }
        const events = (await readEvents()).filter((event) => !isExcludedEvent(event));
        if (url.pathname === '/api/traffic/summary') {
          const summary = trafficSummary(events, url.searchParams);
          const metricsAge = latestGatewayMetrics
            ? Date.now() - Date.parse(latestGatewayMetrics.received_at)
            : Number.POSITIVE_INFINITY;
          const processingReported = liveProcessingTimeReported(latestGatewayMetrics);
          // 2026-10-15 확장 칸(새 Gateway): 표본 수 = 처리 시간 표본(검사·판정한 요청), 비율 분모 = 검사 요청, 오류 = 브라우저 취소 제외.
          // 옛 Gateway는 표본 수를 모른다(전에는 완료 요청 수 = 화면 로딩까지 든 수를 표본 수로 실어 '20건 미만'이 거의 안 떴다) → 칸을 싣지 않는다
          const ext = latestGatewayMetrics?.ext ?? null;
          const latencyMeasured = processingReported && (ext ? ext.latency_samples > 0 : latestGatewayMetrics.completed_requests > 0);
          const liveState = liveGatewayState(latestGatewayMetrics);
          const share = (count) => (ext.inspected_requests > 0 ? count / ext.inspected_requests : 0);
          sendJson(
            response,
            200,
            metricsAge < GATEWAY_METRICS_FRESH_MS
              ? {
                  ...summary,
                  metric_source: 'GATEWAY_LIVE',
                  gateway_metrics_status: 'FRESH',
                  gateway_metrics_received_at: latestGatewayMetrics.received_at,
                  gateway_metrics_age_sec: Math.max(0, metricsAge / 1000),
                  gateway_status: liveState.status,
                  gateway_status_reason: liveState.reason,
                  gateway_total_requests: latestGatewayMetrics.total_requests,
                  gateway_completed_requests: latestGatewayMetrics.completed_requests,
                  gateway_error_requests: ext ? ext.connection_error_requests : latestGatewayMetrics.error_requests,
                  gateway_error_basis: ext ? 'GATEWAY_ERRORS' : 'ALL_DISCONNECTS',
                  gateway_client_cancelled_requests: ext ? ext.client_cancelled_requests : undefined,
                  gateway_inspected_requests: ext ? ext.inspected_requests : undefined,
                  gateway_window_seconds: latestGatewayMetrics.window_seconds,
                  latency_sample_count: processingReported && ext ? ext.latency_samples : undefined,
                  active_clients: latestGatewayMetrics.active_clients,
                  concurrent_requests: latestGatewayMetrics.concurrent_requests,
                  requests_per_sec: latestGatewayMetrics.requests_per_sec,
                  average_latency_ms: latencyMeasured ? latestGatewayMetrics.avg_latency_ms : undefined,
                  p95_latency_ms: latencyMeasured ? latestGatewayMetrics.p95_latency_ms : undefined,
                  // 저장 이벤트 값으로 채우지 않는다: 옛 Gateway가 도는 동안 저장된 값도 LLM 응답까지 잰 것일 수 있다
                  ...(processingReported ? {} : { latency_unavailable_reason: 'LEGACY_GATEWAY' }),
                  // 새 Gateway: 검사 요청 중 비율(반올림 전 건수로 계산). 옛 Gateway: 전체 HTTP 요청 중 비율(화면이 분모를 그렇게 적는다)
                  timeout_rate: !latestGatewayMetrics.completed_requests ? undefined : ext ? share(ext.inspected_timeout_requests) : latestGatewayMetrics.timeout_rate,
                  degraded_rate: !latestGatewayMetrics.completed_requests ? undefined : ext ? share(ext.degraded_requests) : latestGatewayMetrics.degraded_rate,
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
        const documents = withCountedDocumentDetections(await eventStore.listDocuments(), (await readEvents()).filter((event) => !isExcludedEvent(event)));
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

      // 보호 문서 본문 보기(2026-10-13): 열람 시작·원본·텍스트. 스위치(DASHBOARD_DOCUMENT_VIEW=off)면 경로가 없다(404)
      const viewRoute = documentViewOn ? documentViewPath(url.pathname) : null;
      if (viewRoute) {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        const sessionToken = parseCookies(request).get(SESSION_COOKIE);
        if (request.method !== (viewRoute.kind === 'views' ? 'POST' : 'GET')) {
          sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Unsupported document view operation.');
          return;
        }
        let viewDocumentId;
        try {
          viewDocumentId = decodeURIComponent(viewRoute.rawId);
        } catch {
          sendError(response, 400, 'VALIDATION', 'Invalid document id encoding.');
          return;
        }
        if (viewRoute.kind === 'views') {
          const mode = await readDocumentViewMode(request);
          const document = viewDocumentId.length <= 500 ? await eventStore.getDocumentForView?.(viewDocumentId) : null;
          if (!document) {
            sendError(response, 404, 'NOT_FOUND', 'Document not found.');
            return;
          }
          const viewId = randomBytes(16).toString('base64url');
          // 화면 워터마크·감사 기록에 함께 남기는 짧은 번호. 열람 번호(view_id)와 달리 비밀이 아니다 - 캡처가 새도 원본을 열 수 없다
          const viewRef = randomBytes(4).toString('hex').toUpperCase();
          await recordAuditStrict({
            adminId: user.id,
            action: 'DOCUMENT_VIEW',
            targetType: 'DOCUMENT',
            targetId: document.doc_id,
            result: 'SUCCESS',
            changes: { version: document.version, ...(document.format ? { format: document.format } : {}), mode, view_ref: viewRef },
          });
          const issuedAt = Date.now();
          pruneDocumentViews(issuedAt);
          const expiresAt = issuedAt + documentViewTtlMs;
          documentViews.set(viewId, { session: sessionToken, documentId: document.doc_id, version: document.version, viewRef, expiresAt });
          sendJson(response, 201, {
            view_id: viewId,
            view_ref: viewRef,
            document_id: document.doc_id,
            document_name: document.filename,
            version: document.version,
            format: document.format,
            size: document.size,
            status: document.status,
            index_status: document.index_status,
            mode,
            issued_at: new Date(issuedAt).toISOString(),
            expires_at: new Date(expiresAt).toISOString(),
          });
          return;
        }
        const view = documentViewFor(sessionToken, viewDocumentId, url.searchParams.get('view'));
        if (!view) {
          sendError(response, 403, 'VIEW_FORBIDDEN', 'A document view started in this session is required.');
          return;
        }
        // 보는 사이 재등록되면 감사에 남긴 판과 다른 바이트를 주지 않는다 → 409(화면은 '새 판이 등록됨 · 다시 열기')
        const versionChanged = (current) => {
          sendError(response, 409, 'DOCUMENT_VERSION_CHANGED', 'A new version of the document was registered. Open it again.', {
            view_version: view.version,
            current_version: current,
          });
        };
        if (viewRoute.kind === 'original') {
          // 원본 내려받기(download=1)는 2026-10-13 화면에서 뺐다 → 경로 없음(404). 원본을 읽지 않고 감사 기록(DOCUMENT_DOWNLOAD)도 남기지 않는다.
          // 감사 작업 이름 DOCUMENT_DOWNLOAD는 옛 기록을 보여 주려고 DB 허용 목록·화면 이름표에 그대로 둔다
          if (url.searchParams.get('download') === '1') {
            sendError(response, 404, 'NOT_FOUND', 'Document download is not available.');
            return;
          }
          const original = await eventStore.getDocumentOriginal(view.documentId, DOCUMENT_LIMIT_BYTES);
          if (!original) {
            sendError(response, 404, 'NOT_FOUND', 'Document not found.');
            return;
          }
          if (original.version !== view.version) {
            versionChanged(original.version);
            return;
          }
          // 등록 상한(20 MiB)보다 크면 저장소가 바이트를 읽지 않는다
          if (original.size > DOCUMENT_LIMIT_BYTES) {
            sendError(response, 413, 'PAYLOAD_TOO_LARGE', 'The document original is larger than 20 MiB.');
            return;
          }
          if (!Buffer.isBuffer(original.data)) {
            sendError(response, 404, 'NOT_FOUND', 'Document original not found.');
            return;
          }
          response.writeHead(200, {
            'Content-Type': DOCUMENT_CONTENT_TYPES.get(original.format) ?? 'application/octet-stream',
            'Content-Length': original.data.length,
            'Content-Disposition': attachmentDisposition(original.filename, original.format),
            // 주소를 직접 열어 그려지더라도 스크립트·쿠키에 닿지 않게(리포트 파일과 달리 스크립트도 막는다)
            'Content-Security-Policy': 'sandbox',
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-store',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'X-Document-Version': original.version,
          });
          response.end(original.data);
          return;
        }
        // 텍스트: 근거 화면의 문서 쪽과 같은 1,800자 쪽·같은 가림(EVIDENCE_SHOW_RAW)·같은 범위 검사
        const offsetValue = url.searchParams.get('offset') ?? '0';
        if (!/^\d{1,7}$/.test(offsetValue) || Number(offsetValue) > evidenceTextLimit) {
          sendError(response, 400, 'VALIDATION', 'Invalid document text page request.');
          return;
        }
        const stored = await eventStore.getDocumentText(view.documentId, evidenceTextLimit);
        if (!stored) {
          sendError(response, 404, 'NOT_FOUND', 'Document not found.');
          return;
        }
        if (stored.version !== view.version) {
          versionChanged(stored.version);
          return;
        }
        const pageRequest = { side: 'document', offset: Number(offsetValue), documentId: view.documentId };
        sendJson(response, 200, {
          document_id: view.documentId,
          version: stored.version,
          index_status: stored.index_status,   // READY가 아니면 텍스트는 이전 판일 수 있다(재등록 뒤 색인 전)
          coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS',
          redaction: evidenceShowsRaw() ? 'OFF' : 'APPLIED',
          page: typeof stored.text === 'string'
            ? documentPage(stored.text, undefined, pageRequest, 'CURRENT_PROTECTED_DOCUMENT')
            : { status: stored.text_chars > evidenceTextLimit ? 'TOO_LARGE' : 'NOT_RECORDED', side: 'document', document_id: view.documentId },
        });
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
          // content_trend(내용 경향 포함)·blind_pair(블라인드 비교판)는 2026-10-12 설계 v2 4.6-e·시험 4. Detection도 불린만 받으므로(문자열 "true" 거부) 여기서 먼저 막는다
          const body = exactObject(await readJson(request, 16 * 1024), ['from', 'to', 'use_llm', 'content_trend', 'blind_pair'], ['from', 'to']);
          if (!REPORT_DATE_PATTERN.test(String(body.from)) || !REPORT_DATE_PATTERN.test(String(body.to)))
            throw detectionOpsValidation('from/to must be YYYY-MM-DD.');
          if (body.use_llm !== undefined && typeof body.use_llm !== 'boolean')
            throw detectionOpsValidation('use_llm must be a boolean.');
          if (body.content_trend !== undefined && body.content_trend !== null && typeof body.content_trend !== 'boolean')
            throw detectionOpsValidation('content_trend must be a boolean or null.');
          if (body.blind_pair !== undefined && typeof body.blind_pair !== 'boolean')
            throw detectionOpsValidation('blind_pair must be a boolean.');
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
        // 시스템 상태(2026-10-12): 구성 요소별 점검 결과. 읽기 전용, 위 GPU 조회와 같은 세션 규칙
        if (kind === 'system-status' && request.method === 'GET') {
          sendJson(response, 200, await systemStatus(user.id));
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
        // 재시도도 추출 요청이라 감사 로그에 남긴다(2026-10-15 감사 18번). DB 허용 목록을 바꾸지 않도록 같은 작업 이름에 retry_of_job_id를 싣는다
        if (kind === 'keyword-job-retry' && request.method === 'POST') {
          const job = await call(`/admin/keyword-jobs/${id}/retry`, { method: 'POST' });
          const documentId = typeof job?.doc_id === 'string' && job.doc_id ? job.doc_id : null;
          await recordAuditSafely({
            adminId: user.id,
            action: 'KEYWORD_EXTRACT_REQUEST',
            targetType: documentId ? 'DOCUMENT' : 'KEYWORD',
            targetId: documentId ?? `keyword-job-${id}`,
            result: 'SUCCESS',
            changes: { retry_of_job_id: Number(id), job_id: job?.id, status: job?.status },
          });
          sendJson(response, 200, job);
          return;
        }
        sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Unsupported report or keyword operation.');
        return;
      }

      // Gateway 처리 설정(2026-10-10): 관리자 조회·저장. Gateway는 지표 응답(/api/traffic/metrics)으로 받는다
      if (url.pathname === '/api/gateway-settings') {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        if (request.method !== 'GET' && request.method !== 'PUT') {
          sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Unsupported gateway settings operation.');
          return;
        }
        if (!(await gatewaySettingsReady())) {
          sendError(response, 503, 'SETTINGS_UNAVAILABLE', 'Gateway settings are not loaded yet.');
          return;
        }
        if (request.method === 'PUT') {
          const update = gatewaySettingsUpdate(await readJson(request, 16 * 1024));
          const previous = gatewaySettings;
          const previousVersion = previous?.version ?? 0;
          if (update.expectedVersion !== previousVersion) throw new SettingsConflictError(previousVersion);
          // 설정 행과 감사 행은 저장소가 한 트랜잭션으로 쓴다(감사 기록 실패 = 저장 실패 500). 실패(422·409)는 기록하지 않는다
          try {
            gatewaySettings = await eventStore.saveGatewaySettings({
              expectedVersion: previousVersion,
              revision: randomUUID(),
              settings: update.settings,
              updatedBy: user.id,
              audit: {
                adminId: user.id,
                action: 'GATEWAY_SETTINGS_UPDATE',
                targetType: 'GATEWAY',
                targetId: 'gateway-settings',
                result: 'SUCCESS',
                changes: {
                  ...(previousVersion > 0 ? { previous_version: previousVersion } : {}),
                  new_version: previousVersion + 1,
                  previous_value: previous
                    ? summarizeStoredSettings(previous)
                    : summarizeGatewaySettings(defaultGatewaySettings(), { isDefault: true }),
                  new_value: summarizeGatewaySettings(update.settings),
                },
              },
            });
          } catch (error) {
            if (error instanceof SettingsConflictError) await refreshGatewaySettings();
            throw error;
          }
        }
        sendJson(response, 200, gatewaySettingsResponse());
        return;
      }

      // 접속 차단(2026-10-12): 확장 ID 차단 목록·'확장 ID 없는 접속 차단' 방식·ID 별칭. Gateway는 지표 응답(/api/traffic/metrics)의 gateway_access로 받는다
      const accessRoute = accessPath(url.pathname);
      if (accessRoute) {
        const user = requireSession(request, sessions);
        if (!user) {
          sendError(response, 401, 'UNAUTHORIZED', 'Authentication required.');
          return;
        }
        if (request.method !== ACCESS_METHODS[accessRoute.kind]) {
          sendError(response, 405, 'METHOD_NOT_ALLOWED', 'Unsupported gateway access operation.');
          return;
        }
        // 별칭은 화면 표시용이라 Gateway 목록과 무관하다
        if (accessRoute.kind === 'aliases') {
          const items = await eventStore.listClientAliases();
          sendJson(response, 200, { items: items.map(({ client_id, alias }) => ({ client_id, alias })) });
          return;
        }
        if (accessRoute.kind === 'alias') {
          const clientId = parseAliasClientId(accessRoute.clientId);
          const alias = parseAliasUpdate(await readJson(request, 4 * 1024));
          if (alias !== null) {
            const items = await eventStore.listClientAliases();
            if (items.length >= ALIAS_LIMIT && !items.some((item) => item.client_id === clientId))
              throw new ValidationError(`at most ${ALIAS_LIMIT} aliases`, 'alias');
          }
          const saved = await eventStore.saveClientAlias({
            clientId,
            alias,
            updatedBy: user.id,
            audit: (previous) => ({
              adminId: user.id,
              action: 'CLIENT_ALIAS_UPDATE',
              targetType: 'GATEWAY',
              targetId: clientId,
              result: 'SUCCESS',
              changes: { previous_value: summarizeAlias(previous), new_value: alias ?? '(삭제)' },
            }),
          });
          sendJson(response, 200, { client_id: clientId, alias: saved.alias });
          return;
        }
        if (!(await gatewayAccessReady())) {
          sendError(response, 503, 'ACCESS_UNAVAILABLE', 'Gateway access rules are not loaded yet.');
          return;
        }
        if (accessRoute.kind === 'state') {
          sendJson(response, 200, gatewayAccessResponse());
          return;
        }
        const previous = gatewayAccess;
        const previousVersion = previous?.version ?? 0;
        const now = Date.now();
        if (accessRoute.kind === 'rules') {
          const input = parseRuleCreate(await readJson(request, 16 * 1024));
          if (input.expectedVersion !== previousVersion) throw new AccessConflictError(previousVersion);
          const existing = activeRuleFor(previous, input.clientId, now);
          if (existing) {
            sendError(response, 409, 'ACCESS_RULE_EXISTS', 'An active rule already exists for this client id.', { rule_id: existing.id });
            return;
          }
          const rules = storedRules(previous);
          if (rules.filter((rule) => ruleIsActive(rule, now)).length >= ACCESS_RULE_LIMIT)
            throw new ValidationError(`at most ${ACCESS_RULE_LIMIT} active rules`, 'rules');
          const rule = newRule({ id: randomUUID(), input, createdBy: user.id, now });
          const nextRules = pruneRules([...rules, rule], now);
          // Gateway는 지표 응답이 64KiB를 넘으면 통째로 버린다 - 문서가 너무 커지는 저장은 막는다
          if (accessDocumentTooLarge({ version: previousVersion + 1, revision: randomUUID(), updated_at: new Date(now).toISOString(), require_client_id: previous?.require_client_id ?? false, rules: nextRules }, now))
            throw new ValidationError('too many active rules for the Gateway response size', 'rules');
          await saveGatewayAccess({
            previous,
            requireClientId: previous?.require_client_id ?? false,
            rules: nextRules,
            audit: {
              adminId: user.id,
              action: 'ACCESS_RULE_ADD',
              targetType: 'GATEWAY',
              targetId: rule.id,
              result: 'SUCCESS',
              changes: { ...accessVersions(previous), new_value: summarizeRule(rule, { durationLabel: BLOCK_DURATIONS[input.duration].label }) },
            },
          });
          sendJson(response, 201, { ...gatewayAccessResponse(), rule: accessRuleView(rule, now) });
          return;
        }
        if (accessRoute.kind === 'mode') {
          const input = parseModeUpdate(await readJson(request, 4 * 1024));
          if (input.expectedVersion !== previousVersion) throw new AccessConflictError(previousVersion);
          await saveGatewayAccess({
            previous,
            requireClientId: input.requireClientId,
            rules: pruneRules(storedRules(previous), now),
            audit: {
              adminId: user.id,
              action: 'ACCESS_MODE_UPDATE',
              targetType: 'GATEWAY',
              targetId: 'gateway-access',
              result: 'SUCCESS',
              changes: {
                ...accessVersions(previous),
                previous_value: summarizeAccessMode(previous?.require_client_id ?? false),
                new_value: summarizeAccessMode(input.requireClientId),
              },
            },
          });
          sendJson(response, 200, gatewayAccessResponse());
          return;
        }
        // 해제(DELETE /api/gateway-access/rules/:id?expected_version=N)
        if (!isRuleId(accessRoute.id)) {
          sendError(response, 404, 'NOT_FOUND', 'Rule not found.');
          return;
        }
        const expectedVersion = parseExpectedVersionQuery(url.searchParams);
        if (expectedVersion !== previousVersion) throw new AccessConflictError(previousVersion);
        const target = storedRules(previous).find((rule) => rule.id === accessRoute.id);
        if (!target) {
          sendError(response, 404, 'NOT_FOUND', 'Rule not found.');
          return;
        }
        if (!ruleIsActive(target, now)) {
          sendError(response, 409, 'ACCESS_RULE_INACTIVE', 'The rule is already released or expired.');
          return;
        }
        await saveGatewayAccess({
          previous,
          requireClientId: previous.require_client_id,
          rules: pruneRules(removeRule(storedRules(previous), target.id, { removedBy: user.id, now }), now),
          audit: {
            adminId: user.id,
            action: 'ACCESS_RULE_REMOVE',
            targetType: 'GATEWAY',
            targetId: target.id,
            result: 'SUCCESS',
            changes: { ...accessVersions(previous), previous_value: summarizeRule(target) },
          },
        });
        sendJson(response, 200, gatewayAccessResponse());
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
        if (policyRoute.operation === 'capabilities' && request.method === 'GET') {
          sendJson(response, 200, policyCapabilities());
          return;
        }
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
            body: validatePolicyAction(body.detection_target, body.action, { creating: true }),
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
          validatePolicyVersion(body.expected_version);
          const previous = await detectionPolicyRequest(
            policyBaseUrl,
            `/admin/policies/${encodedId}`,
          );
          const result = await detectionPolicyRequest(
            policyBaseUrl,
            `/admin/policies/${encodedId}`,
            { method: 'PATCH', body: {
              action: validatePolicyAction(previous.detection_target, body.action).action,
              expected_version: body.expected_version,
            }, adminId: user.id },
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
          validatePolicyStatus(body.enabled, body.expected_version);
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
        sendJson(response, 200, withGatewayProcessing(event, processingSince));
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
        const event = !eventId.includes('/') && await readEvent(eventId);
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
        const event = await readEvent(eventId);
        if (!event) {
          sendError(response, 404, 'NOT_FOUND', 'Event not found.');
          return;
        }
        // 상세 한 건은 같은 글자 비율을 그 자리에서 계산한다(목록은 뒤에서)
        const [detailed] = await sameText.annotate([event], { wait: true });
        // 질문이면 붙은 파일, 파일이면 이 파일을 붙인 질문을 함께 준다(번호가 있는 이벤트만)
        if (event.file_id || event.attached_file_ids) {
          const { attached, parents } = attachmentLinks(await readEvents());
          const files = attached.get(event.event_id);
          const prompts = parents.get(event.event_id);
          sendJson(response, 200, {
            ...detailed,
            ...(files ? { attached_files: files.map(attachedSummary) } : {}),
            ...(prompts ? { attached_to: prompts.map(attachedSummary) } : {}),
          });
          return;
        }
        sendJson(response, 200, detailed);
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
      if (error instanceof AccessConflictError) {
        sendError(response, 409, 'ACCESS_VERSION_CONFLICT', error.message, {
          current_version: error.currentVersion ?? gatewayAccess?.version ?? 0,
        });
        return;
      }
      if (error instanceof SettingsConflictError) {
        sendError(response, 409, 'SETTINGS_VERSION_CONFLICT', error.message, {
          current_version: error.currentVersion ?? gatewaySettings?.version ?? 0,
        });
        return;
      }
      if (error?.statusCode) {
        sendError(
          response,
          error.statusCode,
          error.code ?? 'BAD_REQUEST',
          error.message,
          error.upstreamStatus ? { upstream_status: error.upstreamStatus } : undefined,
        );
        return;
      }
      console.error('Local event backend request failed:', error?.message ?? error);
      sendError(response, 500, 'SERVER', 'Internal server error.');
    }
  });
  server.on('close', () => {
    gatewaySettingsStopped = true;
    clearTimeout(gatewaySettingsRetry);
    gatewayAccessStopped = true;
    clearTimeout(gatewayAccessRetry);
  });
  loadGatewaySettings();
  loadGatewayAccess();
  return server;
}
