// 접속 차단(2026-10-12): 확장 프로그램 ID 차단 목록·'확장 ID 없는 접속 차단' 방식·ID 별칭.
// 대시보드가 저장하고, Gateway는 지표 전송(10초 주기) 응답의 gateway_access 칸으로 받아 집행한다(gateway-settings.mjs와 같은 통로, 칸은 따로).
// Gateway로 가는 문서에는 규칙 번호·확장 ID·만료·사유 코드, 그리고 관리자가 '사용자에게 메모도 보이기'를 고른 규칙의 메모(user_memo)만 싣는다.
// 별칭·등록자·관리자 전용 메모는 싣지 않는다(2026-10-12 사유 안내: 차단된 사용자에게 사유를 보여 주기 위해 사유 코드와 공개 메모를 추가).
import { ValidationError } from './validation.mjs';

export const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$/;
export const REVISION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const GATEWAY_ACCESS_SOURCES = Object.freeze(['NONE', 'CACHE', 'DASHBOARD']);

// 사유 이름표(고정 코드). 하나 이상 필수, OTHER는 메모 필수
export const BLOCK_REASONS = Object.freeze({
  LEAK_DOC_REPEAT: '기밀 문서 반복 유출 시도',
  PII_REPEAT: '개인정보 반복 입력',
  INVESTIGATION: '보안 조사 중',
  LEAVE: '퇴사·휴직 예정',
  ADMIN_REQUEST: '관리자 요청',
  OTHER: '기타',
});
export const BLOCK_DURATIONS = Object.freeze({
  '1h': { ms: 3_600_000, label: '1시간' },
  '1d': { ms: 86_400_000, label: '1일' },
  permanent: { ms: null, label: '영구' },
});

export const MEMO_MAX_CHARS = 200;
export const ALIAS_MAX_CHARS = 40;
export const ALIAS_LIMIT = 1000;
// 적용 중 규칙 상한 500(계약). Gateway는 지표 응답 본문이 64KiB(65536바이트)를 넘으면 응답 전체를 버리므로
// (dashboard_event_sender.py METRICS_RESPONSE_MAX_BYTES) gateway_access 문서가 이 바이트 수를 넘는 저장도 막는다
// (gateway_settings 문서 약 0.5KB와 여유를 뺀 값). chrome-<uuid> 규칙 하나가 약 144바이트라 실제로는 500개 전에 이 상한이 먼저 걸린다
export const ACCESS_RULE_LIMIT = 500;
export const ACCESS_DOCUMENT_MAX_BYTES = 56_000;
// 해제·만료된 규칙은 감사 기록이 남으므로 목록(판마다 통째로 저장)에는 최근 것만 둔다
export const ACCESS_INACTIVE_KEEP = 200;

const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

function badRequest(message) {
  const error = new Error(message);
  error.statusCode = 400;
  error.code = 'BAD_REQUEST';
  return error;
}

// 모르는 칸·빠진 칸 → 400(gateway-settings와 같은 방식). 값은 그 뒤에 본다(422)
function exactKeys(value, required, optional = []) {
  if (!isPlainObject(value)) throw badRequest('Request body must be an object.');
  const keys = Object.keys(value);
  if (keys.some((key) => !required.includes(key) && !optional.includes(key)) || required.some((key) => !keys.includes(key)))
    throw badRequest('Request body contains unknown or missing fields.');
  return value;
}

const codePoints = (text) => Array.from(text).length;
// 줄바꿈·탭 외의 제어 문자는 받지 않는다
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000e-\u001f\u007f]/;

function expectedVersionValue(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new ValidationError('must be an integer of at least 0', 'expected_version');
  return value;
}

function clientIdValue(value, path = 'client_id') {
  if (typeof value !== 'string' || !CLIENT_ID_PATTERN.test(value))
    throw new ValidationError('must be an extension client id (letters, digits, . _ : @ -, at most 80 characters)', path);
  return value;
}

// 한 줄 글로 맞춘다(여러 줄·연속 공백 → 공백 하나). 비면 null
function singleLine(value, path, max) {
  if (typeof value !== 'string' || CONTROL_CHARACTERS.test(value)) throw new ValidationError('must be a text without control characters', path);
  const text = value.replace(/\s+/g, ' ').trim();
  if (codePoints(text) > max) throw new ValidationError(`must be at most ${max} characters`, path);
  return text || null;
}

// POST /api/gateway-access/rules 본문: { client_id, reasons, memo?, show_memo_to_user?, duration, expected_version }
// show_memo_to_user: 메모를 차단된 사용자에게도 보일지(기본 false, true면 메모 필수)
export function parseRuleCreate(value) {
  const body = exactKeys(value, ['client_id', 'reasons', 'duration', 'expected_version'], ['memo', 'show_memo_to_user']);
  const clientId = clientIdValue(body.client_id);
  const codes = Object.keys(BLOCK_REASONS);
  if (!Array.isArray(body.reasons) || body.reasons.length === 0 || body.reasons.length > codes.length)
    throw new ValidationError('must contain 1 to 6 reason codes', 'reasons');
  if (body.reasons.some((code) => typeof code !== 'string' || !codes.includes(code)))
    throw new ValidationError(`must be among ${codes.join(', ')}`, 'reasons');
  const reasons = [...new Set(body.reasons)];
  if (!Object.hasOwn(BLOCK_DURATIONS, body.duration)) throw new ValidationError('must be one of 1h, 1d, permanent', 'duration');
  const memo = body.memo === undefined || body.memo === null ? null : singleLine(body.memo, 'memo', MEMO_MAX_CHARS);
  if (reasons.includes('OTHER') && memo === null) throw new ValidationError('is required when the reason is OTHER', 'memo');
  if (body.show_memo_to_user !== undefined && typeof body.show_memo_to_user !== 'boolean') throw new ValidationError('must be a boolean', 'show_memo_to_user');
  const showMemoToUser = body.show_memo_to_user === true;
  if (showMemoToUser && memo === null) throw new ValidationError('is required when show_memo_to_user is true', 'memo');
  return { expectedVersion: expectedVersionValue(body.expected_version), clientId, reasons, memo, showMemoToUser, duration: body.duration };
}

// PUT /api/gateway-access/mode 본문: { require_client_id, expected_version }
export function parseModeUpdate(value) {
  const body = exactKeys(value, ['require_client_id', 'expected_version']);
  if (typeof body.require_client_id !== 'boolean') throw new ValidationError('must be a boolean', 'require_client_id');
  return { expectedVersion: expectedVersionValue(body.expected_version), requireClientId: body.require_client_id };
}

// DELETE /api/gateway-access/rules/:id?expected_version=N
export function parseExpectedVersionQuery(searchParams) {
  const raw = searchParams.get('expected_version');
  if (raw === null || !/^\d{1,15}$/.test(raw)) throw new ValidationError('must be an integer of at least 0', 'expected_version');
  return Number(raw);
}

// PUT /api/client-aliases/:clientId 본문: { alias }. 빈 별칭(공백뿐 포함)은 삭제 → null
export function parseAliasUpdate(value) {
  const body = exactKeys(value, ['alias']);
  return singleLine(body.alias, 'alias', ALIAS_MAX_CHARS);
}

export function parseAliasClientId(value) {
  return clientIdValue(value, 'client_id');
}

export function isRuleId(value) {
  return typeof value === 'string' && REVISION_PATTERN.test(value);
}

// 경로: /api/gateway-access[/rules[/:id]|/mode], /api/client-aliases[/:clientId]
export function accessPath(pathname) {
  if (pathname === '/api/gateway-access') return { kind: 'state' };
  if (pathname === '/api/gateway-access/rules') return { kind: 'rules' };
  if (pathname === '/api/gateway-access/mode') return { kind: 'mode' };
  if (pathname === '/api/client-aliases') return { kind: 'aliases' };
  const match = /^\/api\/(gateway-access\/rules|client-aliases)\/([^/]+)$/.exec(pathname);
  if (!match) return null;
  let id;
  try {
    id = decodeURIComponent(match[2]);
  } catch {
    throw badRequest('Invalid id encoding.');
  }
  return match[1] === 'client-aliases' ? { kind: 'alias', clientId: id } : { kind: 'rule', id };
}

export const ACCESS_METHODS = Object.freeze({ state: 'GET', rules: 'POST', mode: 'PUT', rule: 'DELETE', aliases: 'GET', alias: 'PUT' });

// ───────────────────────── 규칙

const toIso = (ms) => new Date(ms).toISOString();

export function ruleIsActive(rule, now = Date.now()) {
  if (!isPlainObject(rule) || (rule.removed_at !== null && rule.removed_at !== undefined)) return false;
  return rule.expires_at === null || rule.expires_at === undefined || Date.parse(rule.expires_at) > now;
}

export function newRule({ id, input, createdBy, now = Date.now() }) {
  const { ms } = BLOCK_DURATIONS[input.duration];
  return {
    id,
    client_id: input.clientId,
    reasons: input.reasons,
    memo: input.memo,
    show_memo_to_user: input.showMemoToUser === true,
    expires_at: ms === null ? null : toIso(now + ms),
    created_by: createdBy,
    created_at: toIso(now),
    removed_by: null,
    removed_at: null,
  };
}

// 저장된 행의 rules를 배열로(손으로 고친 행이어도 예외를 내지 않는다 - 지표 응답에서 쓰므로)
export function storedRules(row) {
  return Array.isArray(row?.rules) ? row.rules.filter((rule) => isPlainObject(rule) && typeof rule.id === 'string' && typeof rule.client_id === 'string') : [];
}

export function activeRuleFor(row, clientId, now = Date.now()) {
  return storedRules(row).find((rule) => rule.client_id === clientId && ruleIsActive(rule, now)) ?? null;
}

// 새 판에 넣을 규칙 목록: 적용 중인 것은 모두, 해제·만료된 것은 가장 최근 ACCESS_INACTIVE_KEEP개만
export function pruneRules(rules, now = Date.now()) {
  const inactiveAt = (rule) => Date.parse(rule.removed_at ?? rule.expires_at ?? rule.created_at) || 0;
  const inactive = rules.filter((rule) => !ruleIsActive(rule, now)).sort((a, b) => inactiveAt(b) - inactiveAt(a)).slice(0, ACCESS_INACTIVE_KEEP);
  const keep = new Set([...rules.filter((rule) => ruleIsActive(rule, now)), ...inactive]);
  return rules.filter((rule) => keep.has(rule));
}

export function removeRule(rules, ruleId, { removedBy, now = Date.now() }) {
  return rules.map((rule) => (rule.id === ruleId ? { ...rule, removed_by: removedBy, removed_at: toIso(now) } : rule));
}

// 규칙의 사유 코드: 알려진 코드만, 중복 없이, 관리자가 고른 순서대로. 하나도 없으면 null
// (손으로 고친 행·옛 규칙이어도 Gateway가 문서 전체를 거부하지 않도록 틀린 값은 걸러 낸다)
function knownReasons(rule) {
  if (!Array.isArray(rule.reasons)) return null;
  const codes = [...new Set(rule.reasons.filter((code) => typeof code === 'string' && Object.hasOwn(BLOCK_REASONS, code)))];
  return codes.length ? codes : null;
}

// 차단된 사용자에게 보여도 되는 메모: 관리자가 공개를 고른 규칙(show_memo_to_user === true)의 1~200자 메모뿐. 옛 규칙(칸 없음)은 공개하지 않는다
function sharedMemo(rule) {
  if (rule.show_memo_to_user !== true || typeof rule.memo !== 'string' || CONTROL_CHARACTERS.test(rule.memo)) return null;
  const length = codePoints(rule.memo);
  return length >= 1 && length <= MEMO_MAX_CHARS ? rule.memo : null;
}

// Gateway로 가는 문서. 칸은 정확히 version·revision·updated_at·require_client_id·rules
// (규칙은 적용 중인 것만: id·client_id·expires_at + 사유 코드 reasons, 공개 메모 user_memo는 공개를 고른 규칙에만). 저장된 행이 없으면 null(→ Gateway는 비움)
export function gatewayAccessDocument(row, now = Date.now()) {
  if (!row) return null;
  return {
    version: row.version,
    revision: row.revision,
    updated_at: row.updated_at,
    require_client_id: row.require_client_id === true,
    rules: storedRules(row)
      .filter((rule) => ruleIsActive(rule, now))
      .map((rule) => {
        const reasons = knownReasons(rule);
        const userMemo = sharedMemo(rule);
        return {
          id: rule.id,
          client_id: rule.client_id,
          expires_at: rule.expires_at ?? null,
          ...(reasons ? { reasons } : {}),
          ...(userMemo ? { user_memo: userMemo } : {}),
        };
      }),
  };
}

export function accessDocumentTooLarge(row, now = Date.now()) {
  return Buffer.byteLength(JSON.stringify(gatewayAccessDocument(row, now))) > ACCESS_DOCUMENT_MAX_BYTES;
}

// 관리자 화면용 규칙(모든 규칙, active 표시). 새것이 위로
export function accessRuleView(rule, now = Date.now()) {
  return {
    id: rule.id,
    client_id: rule.client_id,
    reasons: Array.isArray(rule.reasons) ? rule.reasons : [],
    memo: rule.memo ?? null,
    show_memo_to_user: rule.show_memo_to_user === true,
    expires_at: rule.expires_at ?? null,
    created_by: rule.created_by ?? null,
    created_at: rule.created_at ?? null,
    removed_by: rule.removed_by ?? null,
    removed_at: rule.removed_at ?? null,
    active: ruleIsActive(rule, now),
  };
}

export function accessRulesView(row, now = Date.now()) {
  return storedRules(row)
    .map((rule) => accessRuleView(rule, now))
    .sort((a, b) => (Date.parse(b.created_at) || 0) - (Date.parse(a.created_at) || 0));
}

// ───────────────────────── 감사 기록용 요약(화면이 아는 previous_value·new_value 문자열)

const pad = (number) => String(number).padStart(2, '0');

// 한국 시각(UTC+9) "MM/DD HH:mm"
function koreanStamp(iso) {
  const kst = new Date(Date.parse(iso) + 9 * 3_600_000);
  return `${pad(kst.getUTCMonth() + 1)}/${pad(kst.getUTCDate())} ${pad(kst.getUTCHours())}:${pad(kst.getUTCMinutes())}`;
}

const MEMO_SUMMARY_CHARS = 50;

export function summarizeRule(rule, { durationLabel } = {}) {
  const until = rule.expires_at ? `${koreanStamp(rule.expires_at)}까지` : null;
  const period = rule.expires_at ? (durationLabel ? `${durationLabel}(${until})` : until) : '영구';
  const reasons = (Array.isArray(rule.reasons) ? rule.reasons : []).map((code) => BLOCK_REASONS[code] ?? String(code)).join(', ');
  const memo = typeof rule.memo === 'string' && rule.memo
    ? ` · 메모 ${codePoints(rule.memo) > MEMO_SUMMARY_CHARS ? `${Array.from(rule.memo).slice(0, MEMO_SUMMARY_CHARS).join('')}…` : rule.memo}`
    : '';
  // 사용자에게 메모를 공개한 규칙은 감사 기록에도 남긴다(공개한 사실을 나중에 확인할 수 있게)
  const shown = rule.show_memo_to_user === true && memo ? ' · 사용자에게 메모 공개' : '';
  return `확장 ID ${rule.client_id} · ${period} · 사유 ${reasons}${memo}${shown}`;
}

// ───────────────────────── 내 요청 기록(본인 화면)에 싣는 차단 사유 (2026-10-12)
// 이벤트의 reason_code가 이 둘이고 최종 조치가 BLOCK일 때만 본인 기록에 사유로 보인다. client_id_missing은 고정 사유라 코드만 싣는다
export const ACCESS_REASON_CODES = Object.freeze(['client_blocked', 'client_id_missing']);

export function ownAccessReasonCode(event) {
  return (event.final_action ?? event.action) === 'BLOCK' && ACCESS_REASON_CODES.includes(event.reason_code) ? event.reason_code : undefined;
}

// client_blocked 기록에 붙일 규칙의 사유 코드(block_reasons)와 공개 메모(user_memo). 규칙이 없으면(오래되어 정리됨) 빈 객체 - 사유 줄 없이 '접속 차단'만 보인다.
// 메모는 관리자가 공개를 고른 규칙에서만 - 그 밖의 규칙 내용(등록자·별칭·관리자 전용 메모)은 싣지 않는다
export function ownBlockDetails(rule) {
  if (!isPlainObject(rule)) return {};
  const reasons = knownReasons(rule);
  const userMemo = sharedMemo(rule);
  return { ...(reasons ? { block_reasons: reasons } : {}), ...(userMemo ? { user_memo: userMemo } : {}) };
}

export const summarizeAccessMode = (requireClientId) => `확장 ID 없는 접속 차단 ${requireClientId ? '켬' : '끔'}`;
export const summarizeAlias = (alias) => alias ?? '(없음)';

// ───────────────────────── Gateway 적용 보고(지표 본문 access_applied)

function strictFields(value, fields) {
  if (!isPlainObject(value)) throw new Error('not an object');
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) throw new Error('invalid fields');
  return value;
}

const count = (value) => {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('invalid count');
  return value;
};

// applied_at은 화면 표시용(Gateway 시계)이라 형식이 틀려도 보고 전체를 버리지 않고 그 값만 null로 둔다(gateway-settings.mjs와 같음)
function appliedAt(value) {
  return typeof value === 'string' && value.length <= 50 && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value)) ? value : null;
}

// 틀리면 예외 - 호출자는 지표는 받고 이 칸만 버린다. 받지 못한 목록(NONE)은 번호·revision이 null, 받은 목록(CACHE·DASHBOARD)은 번호 1 이상·revision 있음
export function parseAccessApplied(value) {
  const body = strictFields(value, ['version', 'revision', 'source', 'applied_at', 'rejected', 'active_rules', 'require_client_id', 'denied_5m']);
  if (!GATEWAY_ACCESS_SOURCES.includes(body.source)) throw new Error('invalid source');
  if (body.version !== null && (!Number.isSafeInteger(body.version) || body.version < 1)) throw new Error('invalid version');
  if (body.revision !== null && (typeof body.revision !== 'string' || !REVISION_PATTERN.test(body.revision))) throw new Error('invalid revision');
  const noList = body.version === null && body.revision === null;
  const someList = body.version !== null && body.revision !== null;
  if (body.source === 'NONE' ? !noList : !someList) throw new Error('source does not match version');
  if (body.rejected !== null && (typeof body.rejected !== 'string' || !body.rejected || body.rejected.length > 100 || CONTROL_CHARACTERS.test(body.rejected) || /[\r\n]/.test(body.rejected)))
    throw new Error('invalid rejected');
  if (typeof body.require_client_id !== 'boolean') throw new Error('invalid require_client_id');
  return {
    version: body.version,
    revision: body.revision,
    source: body.source,
    applied_at: appliedAt(body.applied_at),
    rejected: body.rejected,
    active_rules: count(body.active_rules),
    require_client_id: body.require_client_id,
    denied_5m: count(body.denied_5m),
  };
}

// 반영 상태(화면 머리). 지표가 최근(metricsStatus FRESH)이 아니거나 적용 보고가 없으면 NOT_REPORTING,
// 보고한 revision이 저장된 판과 같으면 APPLIED(저장된 것이 없으면 Gateway도 목록이 없을 때),
// 다르면서 거부 사유가 있으면 REJECTED, 아니면 PENDING.
// 거부 사유(rejected)는 문자열 하나뿐이라 어느 판을 거부했는지는 모른다 - 새 판을 저장한 직후 Gateway가 가져가기 전에는 이전 거부 사유가 남아 REJECTED로 보일 수 있다
export function gatewayAccessState(stored, metrics, metricsStatus) {
  const applied = metrics?.access_applied ?? null;
  let state = 'PENDING';
  if (metricsStatus !== 'FRESH' || !applied) state = 'NOT_REPORTING';
  else if (stored ? applied.revision === stored.revision : applied.revision === null) state = 'APPLIED';
  else if (stored && applied.rejected !== null) state = 'REJECTED';
  return { state, metrics_status: metricsStatus, reported_at: metrics?.received_at ?? null };
}
