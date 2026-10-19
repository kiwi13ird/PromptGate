// Gateway 처리 설정(2026-10-10): 검사 지연·검사할 수 없는 파일·허용 알림.
// 대시보드가 저장하고, Gateway는 지표 전송(10초 주기) 응답의 gateway_settings 칸으로 받아 적용한다.
// 검증 규칙은 Gateway gateway_settings.py·환경변수와 같다(칸이 정확히 같을 것, 대기 시간 0.05~30초, 소수 자리 규칙 없음).
import { ValidationError } from './validation.mjs';

export const GATEWAY_SETTINGS_FIELDS = Object.freeze(['timeout', 'uninspectable', 'notify_on_allow']);
export const GATEWAY_SETTINGS_SOURCES = Object.freeze(['ENV_DEFAULT', 'CACHE', 'DASHBOARD']);
export const REVISION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TIMEOUT_ACTIONS = ['block', 'forward'];
const UNINSPECTABLE_ACTIONS = ['block', 'allow'];
const UNINSPECTABLE_GROUPS = ['image', 'scanned_pdf', 'other'];
const MIN_SECONDS = 0.05;
const MAX_SECONDS = 30;
const REJECTED_FIELD_PATTERN = /^[a-z_.]{1,100}$/;

// 대시보드에 저장된 설정이 없을 때(= Gateway 환경변수 기본값과 같은 값)
export function defaultGatewaySettings() {
  return {
    timeout: {
      prompt: { action: 'forward', seconds: 0.5 },
      file: { action: 'block', seconds: 2.0 },
    },
    uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
    notify_on_allow: false,
  };
}

const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

// 모르는 칸·빠진 칸 → 400(다른 관리 변경의 exactObject와 같음)
function fieldsError(path) {
  const error = new Error(`${path} contains unknown or missing fields.`);
  error.statusCode = 400;
  error.code = 'BAD_REQUEST';
  error.path = path;
  return error;
}

function exactFields(value, fields, path) {
  if (!isPlainObject(value)) throw new ValidationError('must be an object', path);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) throw fieldsError(path);
  return value;
}

function choice(value, allowed, path) {
  if (!allowed.includes(value)) throw new ValidationError(`must be one of ${allowed.join(', ')}`, path);
  return value;
}

function seconds(value, path) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < MIN_SECONDS || value > MAX_SECONDS)
    throw new ValidationError(`must be a number between ${MIN_SECONDS} and ${MAX_SECONDS}`, path);
  return value;
}

// 칸 모양을 먼저 모두 본 뒤(400) 값을 본다(422, details.path = Gateway 거부 칸과 같은 이름)
export function parseGatewaySettings(value, path = '') {
  const at = (name) => (path ? `${path}.${name}` : name);
  const body = exactFields(value, GATEWAY_SETTINGS_FIELDS, path || 'body');
  const timeout = exactFields(body.timeout, ['prompt', 'file'], at('timeout'));
  for (const kind of ['prompt', 'file']) exactFields(timeout[kind], ['action', 'seconds'], at(`timeout.${kind}`));
  const uninspectable = exactFields(body.uninspectable, UNINSPECTABLE_GROUPS, at('uninspectable'));
  const rule = (kind) => ({
    action: choice(timeout[kind].action, TIMEOUT_ACTIONS, at(`timeout.${kind}.action`)),
    seconds: seconds(timeout[kind].seconds, at(`timeout.${kind}.seconds`)),
  });
  const parsed = {
    timeout: { prompt: rule('prompt'), file: rule('file') },
    uninspectable: Object.fromEntries(UNINSPECTABLE_GROUPS.map((group) =>
      [group, choice(uninspectable[group], UNINSPECTABLE_ACTIONS, at(`uninspectable.${group}`))])),
    notify_on_allow: body.notify_on_allow,
  };
  if (typeof parsed.notify_on_allow !== 'boolean') throw new ValidationError('must be a boolean', at('notify_on_allow'));
  return parsed;
}

// PUT /api/gateway-settings 본문: { expected_version, timeout, uninspectable, notify_on_allow }
export function gatewaySettingsUpdate(value) {
  if (!isPlainObject(value)) {
    const error = new Error('Request body must be an object.');
    error.statusCode = 400;
    throw error;
  }
  const keys = Object.keys(value);
  const fields = ['expected_version', ...GATEWAY_SETTINGS_FIELDS];
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) throw fieldsError('body');
  const { expected_version: expectedVersion, ...settings } = value;
  const parsed = parseGatewaySettings(settings);
  if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0)
    throw new ValidationError('must be an integer of at least 0', 'expected_version');
  return { expectedVersion, settings: parsed };
}

// 저장된 값은 저장 때 검사했다. 칸 순서만 맞추고, 그래도 틀린 값이면 그대로 둬 Gateway가 거부(REJECTED)하게 한다
function storedSettings(settings) {
  try {
    return parseGatewaySettings(settings);
  } catch {
    return { timeout: settings?.timeout, uninspectable: settings?.uninspectable, notify_on_allow: settings?.notify_on_allow };
  }
}

// 저장된 행의 값이 형식에 맞지 않을 때(손으로 넣은 행, 앞으로 모양이 바뀐 행) 틀린 칸 경로, 맞으면 null.
// PG CHECK·JSON 저장소는 settings가 객체인지만 본다
export function storedSettingsProblem(settings) {
  try {
    parseGatewaySettings(settings);
    return null;
  } catch (error) {
    return typeof error?.path === 'string' && error.path !== 'body' ? error.path : 'settings';
  }
}

// 지표 응답으로 Gateway에 주는 문서(§1.1) - 칸이 정확히 이 7개여야 Gateway가 받는다
export function gatewaySettingsDocument(row) {
  if (!row) return null;
  return {
    version: row.version,
    revision: row.revision,
    updated_at: row.updated_at,
    updated_by: row.updated_by,
    ...storedSettings(row.settings),
  };
}

const ACTION_WORDS = { forward: '원본 전송', block: '차단', allow: '허용' };

// 감사 기록용 요약(정해진 순서). 저장된 설정이 없던 상태(기본값)는 앞에 "기본값 · "
export function summarizeGatewaySettings(settings, { isDefault = false } = {}) {
  const word = (value) => ACTION_WORDS[value] ?? String(value);
  const text = [
    `질문 지연 시 ${word(settings.timeout.prompt.action)}(${settings.timeout.prompt.seconds}초)`,
    `파일 지연 시 ${word(settings.timeout.file.action)}(${settings.timeout.file.seconds}초)`,
    `이미지 ${word(settings.uninspectable.image)}`,
    `스캔 PDF ${word(settings.uninspectable.scanned_pdf)}`,
    `기타 형식 ${word(settings.uninspectable.other)}`,
    `허용 알림 ${settings.notify_on_allow ? '켬' : '끔'}`,
  ].join(' · ');
  return isDefault ? `기본값 · ${text}` : text;
}

export const INVALID_STORED_SUMMARY = '저장된 값 형식 오류';

// 감사 기록의 이전 값 요약. 저장된 행의 값이 틀렸으면 요약 대신 정해진 문구(요약하다 예외가 나면 고치는 저장까지 막힌다)
export function summarizeStoredSettings(row) {
  return storedSettingsProblem(row.settings) ? INVALID_STORED_SUMMARY : summarizeGatewaySettings(parseGatewaySettings(row.settings));
}

function nullableRevision(value) {
  if (value !== null && (typeof value !== 'string' || !REVISION_PATTERN.test(value))) throw new Error('invalid revision');
  return value;
}

function nullableVersion(value) {
  if (value !== null && (!Number.isSafeInteger(value) || value < 0)) throw new Error('invalid version');
  return value;
}

function strictFields(value, fields) {
  if (!isPlainObject(value)) throw new Error('not an object');
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) throw new Error('invalid fields');
  return value;
}

// applied_at은 화면 표시용(Gateway 시계)이라 형식이 틀려도 보고 전체를 버리지 않고 그 값만 null로 둔다
// (Python isoformat()의 시간대 없는 값, strftime %z의 +0000 등). 받는 형식: ISO-8601, 끝이 Z 또는 ±HH:MM, 50자 이하
function appliedAt(value) {
  return typeof value === 'string' && value.length <= 50 && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value))
    ? value
    : null;
}

// Gateway가 지표에 실어 보내는 적용 보고(§3.3). 틀리면 예외 - 호출자는 지표는 받고 이 칸만 버린다(applied_at만 예외: 위)
export function parseSettingsApplied(value) {
  const body = strictFields(value, ['version', 'revision', 'source', 'applied_at', 'rejected', 'effective']);
  if (!GATEWAY_SETTINGS_SOURCES.includes(body.source)) throw new Error('invalid source');
  if (!Number.isSafeInteger(body.version) || body.version < 0) throw new Error('invalid version');
  nullableRevision(body.revision);
  // 환경변수 기본값은 번호 0·revision 없음, 대시보드에서 받은 판(디스크 사본 포함)은 번호 1 이상·revision 있음
  if (body.source === 'ENV_DEFAULT' ? body.version !== 0 || body.revision !== null : body.version < 1 || body.revision === null)
    throw new Error('source does not match version');
  let rejected = null;
  if (body.rejected !== null) {
    const raw = strictFields(body.rejected, ['version', 'revision', 'field']);
    if (typeof raw.field !== 'string' || !REJECTED_FIELD_PATTERN.test(raw.field)) throw new Error('invalid rejected field');
    rejected = { version: nullableVersion(raw.version), revision: nullableRevision(raw.revision), field: raw.field };
  }
  return {
    version: body.version,
    revision: body.revision,
    source: body.source,
    applied_at: appliedAt(body.applied_at),
    rejected,
    effective: parseGatewaySettings(body.effective, 'effective'),
  };
}

// 같은 판을 처음 보고한 시각(first_seen_at)을 가리는 열쇠
export const settingsAppliedKey = (applied) => `${applied.version}\n${applied.revision}`;
