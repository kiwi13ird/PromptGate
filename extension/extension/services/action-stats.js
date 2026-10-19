import { ACTION_STATS_STALE_MS } from "../config/defaults.js";
import { isPlainObject } from "../utils/validation.js";
import { ACCESS_REASON_CODES } from "./access-state.js";

// 1.4.8: 차단·마스킹 집계. 크롬 API를 쓰지 않는 순수 함수만 둔다(저장·조회는 action-stats-service.js).
// 저장하는 것은 요청 번호(eventId) · 시각 · 종류(B=차단, M=마스킹, R=사용 제한 기록)뿐이다. 프롬프트·파일 이름·탐지 값·서비스 이름·사유 코드는 저장하지 않는다.
// 센 단위 = Gateway가 남긴 기록 1건(eventId). 질문과 첨부 파일은 각각 1건이다. 같은 업로드 재시도는 Gateway가 처음 한 번만 기록·알림하므로 여기서 다시 합치지 않고,
// 실시간 알림과 내 요청 기록(중계) 두 곳에서 같은 기록이 오면 eventId로 한 번만 센다.
// 1.4.8(10/15 수정): 관리자 사용 제한·확장 번호 없음으로 막힌 기록(사유 client_blocked·client_id_missing)은 10분에 한 번만 남는 대표 기록이라
// 실제 막힌 요청 수가 아니다 -> '차단'에 넣지 않고 R로 따로 센다. 조치 값은 운영에 있는 BLOCK·MASK만 인정한다(ALLOW는 세지 않음).
export const ACTION_STATS_KEY = "actionStats";
export const ACTION_STATS_VERSION = 2;   // 2: 사용 제한 기록(R) 추가. 1(시험판)은 접속 차단이 차단에 섞여 있어 버린다
export const ACTION_STATS_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;   // 중계가 주는 기간(7일)보다 길게: 이 안의 번호는 기억해 중복을 거른다
export const ACTION_STATS_MAX_RECORDS = 5000;                         // 번호 목록 상한. 넘치거나 오래된 건은 건수만 남기고 번호는 버린다
const MAX_FUTURE_MS = 24 * 60 * 60 * 1000;
const EVENT_ID_PATTERN = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const CODE_BY_ACTION = Object.freeze({ BLOCK: "B", MASK: "M" });
const CODES = new Set(["B", "M", "R"]);
const KEY_BY_CODE = Object.freeze({ B: "block", M: "mask", R: "restricted" });
const ACCESS_RESTRICTION_REASONS = new Set(Object.values(ACCESS_REASON_CODES));

export const defaultActionStats = () => ({
  v: ACTION_STATS_VERSION,
  startedAt: null,
  from: null,
  archived: { block: 0, mask: 0, restricted: 0 },
  recent: [],
  sync: { attemptedAt: null, okAt: null, error: "" }
});

const isoOrNull = (value) => {
  if (typeof value !== "string" || value.length > 64) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
};
const countOr0 = (value) => (Number.isSafeInteger(value) && value > 0 ? value : 0);

// 저장값 -> 올바른 형식만 남긴 집계(망가진 칸은 버린다). 번호가 겹치면 먼저 나온 것만, 시각 오름차순
export function normalizeActionStats(raw) {
  const d = defaultActionStats();
  if (!isPlainObject(raw) || raw.v === 1) return d;   // 1.4.8 시험판 저장값은 버리고 서버 기록에서 다시 센다
  const seen = new Set();
  const recent = [];
  for (const row of Array.isArray(raw.recent) ? raw.recent : []) {
    if (!Array.isArray(row) || row.length !== 3) continue;
    const [id, ms, code] = row;
    if (typeof id !== "string" || !EVENT_ID_PATTERN.test(id) || seen.has(id) || !Number.isFinite(ms) || !CODES.has(code)) continue;
    seen.add(id);
    recent.push([id, Math.trunc(ms), code]);
  }
  recent.sort((a, b) => a[1] - b[1]);
  const sync = isPlainObject(raw.sync) ? raw.sync : {};
  return {
    v: ACTION_STATS_VERSION,
    startedAt: isoOrNull(raw.startedAt),
    from: isoOrNull(raw.from),
    archived: { block: countOr0(raw.archived?.block), mask: countOr0(raw.archived?.mask), restricted: countOr0(raw.archived?.restricted) },
    recent: recent.slice(-ACTION_STATS_MAX_RECORDS),
    sync: {
      attemptedAt: isoOrNull(sync.attemptedAt),
      okAt: isoOrNull(sync.okAt),
      error: typeof sync.error === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(sync.error) ? sync.error : ""
    }
  };
}

// 조치 + 사유 코드 -> 종류. 운영 값(BLOCK·MASK)만 센다. 접속 차단 사유가 붙은 BLOCK은 R. 그 밖(ALLOW·모르는 값)은 null
export function actionCode(action, reasonCode) {
  if (typeof action !== "string" || !Object.hasOwn(CODE_BY_ACTION, action)) return null;
  if (action === "BLOCK" && typeof reasonCode === "string" && ACCESS_RESTRICTION_REASONS.has(reasonCode)) return "R";
  return CODE_BY_ACTION[action];
}

// 실시간 알림 한 건 -> 기록. 차단·마스킹이 아니면(허용 알림 등) null: 허용은 어느 경로로도 전부 알 수 없어 세지 않는다
export function recordFromEvent(event) {
  if (!isPlainObject(event) || typeof event.eventId !== "string") return null;
  const code = actionCode(event.action, event.reasonCode);
  return code ? { id: event.eventId, ts: event.timestamp, code } : null;
}

// 내 요청 기록 응답(/__llmsgw/my/requests) -> 기록들. 형식이 다르면 null(= 조회 실패로 처리, 0건으로 보지 않는다).
// 질문에 묶인 첨부 파일도 각자의 기록이므로 따로 센다(각각 실시간 알림이 따로 오는 것과 같은 단위).
export function recordsFromMyRequests(body) {
  if (!isPlainObject(body) || !Array.isArray(body.items)) return null;
  const records = [];
  const collect = (item) => {
    if (!isPlainObject(item) || typeof item.event_id !== "string") return;
    const code = actionCode(item.final_action, item.reason_code);
    if (code) records.push({ id: item.event_id, ts: item.occurred_at, code });
  };
  for (const item of body.items) {
    collect(item);
    if (isPlainObject(item) && Array.isArray(item.attached_files)) for (const file of item.attached_files) collect(file);
  }
  return records;
}

// 기록을 더한다(입력은 건드리지 않고 새 집계를 돌려준다). 이미 있는 번호·형식이 틀린 번호·보관 기간보다 오래된 건은 건너뛴다.
export function ingestRecords(stats, records, nowMs) {
  const next = normalizeActionStats(stats);
  const seen = new Set(next.recent.map((row) => row[0]));
  const startedAt = next.startedAt ?? new Date(nowMs).toISOString();
  let from = next.from ? Date.parse(next.from) : null;
  let added = 0;
  for (const record of records) {
    if (!record || typeof record.id !== "string" || !EVENT_ID_PATTERN.test(record.id) || seen.has(record.id) || !CODES.has(record.code)) continue;
    let ts = Date.parse(record.ts);
    if (!Number.isFinite(ts) || ts > nowMs + MAX_FUTURE_MS) ts = nowMs;   // 시각을 못 믿으면 받은 시각
    if (ts < nowMs - ACTION_STATS_RETENTION_MS) continue;
    seen.add(record.id);
    next.recent.push([record.id, ts, record.code]);
    if (from === null || ts < from) from = ts;
    added += 1;
  }
  next.startedAt = startedAt;
  const startedMs = Date.parse(startedAt);
  next.from = new Date(from === null ? startedMs : Math.min(from, startedMs)).toISOString();
  next.recent.sort((a, b) => a[1] - b[1]);
  const horizon = nowMs - ACTION_STATS_RETENTION_MS;
  let drop = 0;
  while (drop < next.recent.length && (next.recent[drop][1] < horizon || next.recent.length - drop > ACTION_STATS_MAX_RECORDS)) drop += 1;
  if (drop) {
    for (const [, , code] of next.recent.slice(0, drop)) next.archived[KEY_BY_CODE[code]] += 1;
    next.recent = next.recent.slice(drop);
  }
  return { stats: next, added };
}

// 오늘 0시(이 PC의 시간대)부터의 건수와 누적 건수
export function summarizeActionStats(stats, nowMs) {
  const normalized = normalizeActionStats(stats);
  const midnight = new Date(nowMs); midnight.setHours(0, 0, 0, 0);
  const today = { block: 0, mask: 0, restricted: 0 };
  const total = { block: normalized.archived.block, mask: normalized.archived.mask, restricted: normalized.archived.restricted };
  for (const [, ms, code] of normalized.recent) {
    const key = KEY_BY_CODE[code];
    total[key] += 1;
    if (ms >= midnight.getTime()) today[key] += 1;
  }
  return { today, total };
}

// 질문과 첨부 파일은 각각 한 건으로 센다(Gateway 기록 단위). '요청'이라고 쓰면 질문+파일 한 번이 1로 읽혀 단위가 어긋난다
const CAPTION_BASIS = "이 PC에서 확장이 확인한 기록 기준 · 질문·파일을 각각 셈";
const RESTRICTED_NOTE = "사용 제한 기록은 10분에 한 번만 남아, 실제로 막힌 요청 수가 아닙니다.";
const hhmm = (ms) => new Date(ms).toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit" });
const monthDay = (iso) => { const date = new Date(Date.parse(iso)); return `${date.getMonth() + 1}/${date.getDate()}`; };

// 집계를 새로 읽을 수 없는 이유(없으면 null). 순서: 앞의 것이 더 근본적인 이유
export function statsIneligibleReason({ protectionOn, configured, proxyApplied, identityEnabled, hasViewerKey }) {
  if (!protectionOn) return "PROTECTION_OFF";
  if (!configured) return "NOT_CONFIGURED";
  if (!proxyApplied) return "PROXY";
  if (!identityEnabled) return "IDENTITY_OFF";
  if (!hasViewerKey) return "NO_VIEWER_KEY";
  return null;
}
const REASON_TEXT = Object.freeze({
  PROTECTION_OFF: "보호가 꺼져 있습니다. 보호를 켜면 집계됩니다.",
  NOT_CONFIGURED: "설정에서 보안 서버 주소를 입력해 주세요.",
  PROXY: "연결 설정에 문제가 있어 집계할 수 없습니다.",
  IDENTITY_OFF: "설정에서 ‘AI 사이트 요청에 내 확장 번호 함께 보내기’를 켜 주세요.",
  NO_VIEWER_KEY: "열람 키가 없습니다. 확장 프로그램을 새로고침해 주세요."
});
const STALE_REASON_TEXT = Object.freeze({
  PROTECTION_OFF: "보호가 꺼져 있어 새 건은 집계되지 않습니다.",
  NOT_CONFIGURED: "보안 서버 주소가 없어 새 건은 집계되지 않습니다.",
  PROXY: "연결 설정 문제로 새 건은 집계되지 않습니다.",
  IDENTITY_OFF: "내 확장 번호를 보내지 않아 새 건은 집계되지 않습니다.",
  NO_VIEWER_KEY: "열람 키가 없어 새 건은 집계되지 않습니다."
});

// 팝업 표시용. tone: ok(최신) | stale(숫자는 있지만 최신이 아닐 수 있음) | checking(처음 확인하는 중) | unavailable(숫자를 믿을 수 없어 '확인 불가')
// 숫자가 없는 상태에서는 today·total이 null이어서 0으로 보이지 않는다. 0은 '확인했더니 0건'일 때만 나온다.
export function actionStatsView(stats, context, nowMs) {
  const view = buildActionStatsView(stats, context, nowMs);
  // 숫자가 없는 상태에서는 기간 안내(오늘·누적 시작일)도 사용 제한 안내도 붙이지 않는다
  if (view.today === null) return { ...view, caption: CAPTION_BASIS, restrictedText: "", restrictedNote: "" };
  // 사용 제한 기록: 있을 때만 작게 따로. 10분에 한 번만 남는 대표 기록이라 실제 막힌 요청 수가 아님을 같이 적는다
  const restricted = view.total.restricted > 0;
  return { ...view, restrictedText: restricted ? `사용 제한 기록 ${view.total.restricted.toLocaleString("ko-KR")}회 · 오늘 ${view.today.restricted.toLocaleString("ko-KR")}회` : "", restrictedNote: restricted ? RESTRICTED_NOTE : "" };
}

function buildActionStatsView(stats, context, nowMs) {
  const state = normalizeActionStats(stats);
  const reason = statsIneligibleReason(context);
  const okMs = state.sync.okAt ? Date.parse(state.sync.okAt) : null;
  const hasData = okMs !== null || state.recent.length > 0 || state.archived.block + state.archived.mask + state.archived.restricted > 0;
  const since = state.from ?? state.startedAt;
  const caption = `${CAPTION_BASIS} · 오늘은 0시부터${since ? ` · 누적은 ${monthDay(since)}부터` : ""}`;
  const numbers = summarizeActionStats(state, nowMs);
  const base = { caption, syncText: "", syncDot: "unknown" };
  const lastOk = okMs !== null ? ` 마지막 확인 ${hhmm(okMs)}.` : "";

  if (reason) {
    if (!hasData) return { ...base, tone: "unavailable", today: null, total: null, note: REASON_TEXT[reason], syncText: "확인 불가", syncDot: "degraded" };
    return { ...base, tone: "stale", ...numbers, note: `${STALE_REASON_TEXT[reason]}${lastOk}`, syncText: okMs !== null ? `마지막 ${hhmm(okMs)}` : "확인 불가", syncDot: "degraded" };
  }
  if (okMs !== null && nowMs - okMs <= ACTION_STATS_STALE_MS) return { ...base, tone: "ok", ...numbers, note: "", syncText: `정상 · ${hhmm(okMs)}`, syncDot: "healthy" };
  if (okMs !== null) return { ...base, tone: "stale", ...numbers, note: `지금은 보안 서버에서 새 기록을 가져오지 못해 최근 건이 빠졌을 수 있습니다.${lastOk}`, syncText: `마지막 ${hhmm(okMs)}`, syncDot: "degraded" };
  if (state.sync.error) {
    const note = "보안 서버에서 기록을 가져오지 못했습니다. 계속되면 보안 관리자에게 문의해 주세요.";
    if (!hasData) return { ...base, tone: "unavailable", today: null, total: null, note, syncText: "확인 불가", syncDot: "degraded" };
    return { ...base, tone: "stale", ...numbers, note: `보안 서버의 지난 기록을 아직 확인하지 못했습니다. 실시간으로 받은 건만 보입니다.`, syncText: "확인 불가", syncDot: "degraded" };
  }
  if (!hasData) return { ...base, tone: "checking", today: null, total: null, note: "집계를 확인하는 중입니다.", syncText: "확인 중", syncDot: "unknown" };
  return { ...base, tone: "checking", ...numbers, note: "지난 기록을 확인하는 중입니다.", syncText: "확인 중", syncDot: "unknown" };
}
