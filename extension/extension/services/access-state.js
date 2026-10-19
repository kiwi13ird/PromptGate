import { ACCESS_STATES } from "../config/statuses.js";
import { cleanText, isPlainObject } from "../utils/validation.js";

// 1.4.5: Gateway 접속 제한 상태(/__llmsgw/access-status) 해석·저장 형식·화면 문구. 크롬 API를 쓰지 않는 순수 함수만 둔다.
// 사유 코드별 고정 문구는 Gateway 차단 페이지와 같다. 알려진 코드는 여기 문구만 쓰고(응답의 label로 바꿔치기 불가), 모르는 코드만 응답의 label을 쓴다.
export const ACCESS_REASON_LABELS = Object.freeze({
  LEAK_DOC_REPEAT: "기밀 문서 반복 유출 시도",
  PII_REPEAT: "개인정보 반복 입력",
  INVESTIGATION: "보안 조사 중",
  LEAVE: "퇴사·휴직 예정",
  ADMIN_REQUEST: "관리자 요청",
  OTHER: "기타"
});
export const CLIENT_ID_MISSING_TEXT = "확장 프로그램 식별 정보 없음";
export const ACCESS_REASON_CODES = Object.freeze({ BLOCKED: "client_blocked", ID_MISSING: "client_id_missing" });
export const ADMIN_UNTIL_TEXT = "관리자가 풀 때까지";
export const ACCESS_BLOCKED_TITLE = "사용이 제한되었습니다";
const MAX_REASONS = 6;
const MAX_MEMO = 200;
const MAX_UNKNOWN_LABEL = 40;
const REASON_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,31}$/;
const BLOCK_ID_PATTERN = /^[A-Za-z0-9_-]{1,16}$/;

export const defaultAccessState = () => ({
  status: ACCESS_STATES.UNKNOWN,
  lastConfirmed: null,
  reasonCode: null,
  reasons: [],
  userMemo: null,
  until: null,
  blockId: null,
  requireClientId: false,
  clientIdPresent: false,
  checkedAt: null,
  attemptedAt: null
});

const isoOrNull = (value) => {
  if (typeof value !== "string" || value.length > 64) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
};
const boolOr = (value, fallback) => (typeof value === "boolean" ? value : fallback);
const reasonCodeOrNull = (value) => (Object.values(ACCESS_REASON_CODES).includes(value) ? value : null);

function normalizeReasons(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const reasons = [];
  for (const item of value) {
    if (!isPlainObject(item) || typeof item.code !== "string" || !REASON_CODE_PATTERN.test(item.code) || seen.has(item.code)) continue;
    const label = Object.hasOwn(ACCESS_REASON_LABELS, item.code) ? ACCESS_REASON_LABELS[item.code] : cleanText(item.label, MAX_UNKNOWN_LABEL);
    if (!label) continue;
    seen.add(item.code);
    reasons.push({ code: item.code, label });
    if (reasons.length >= MAX_REASONS) break;
  }
  return reasons;
}

// Gateway 응답 -> 저장용 상세. 차단인데 사유 코드가 올바르지 않거나 blocked가 불리언이 아니면 null(= 확인 불가로 처리, 가짜 '차단' 없음)
export function parseAccessStatusResponse(body) {
  if (!isPlainObject(body) || typeof body.blocked !== "boolean") return null;
  const blocked = body.blocked;
  const reasonCode = blocked ? reasonCodeOrNull(body.reason_code) : null;
  if (blocked && !reasonCode) return null;
  const memo = blocked && typeof body.user_memo === "string" ? cleanText(body.user_memo, MAX_MEMO) : "";
  return {
    blocked,
    reasonCode,
    reasons: blocked ? normalizeReasons(body.reasons) : [],
    userMemo: memo || null,
    until: blocked ? isoOrNull(body.until) : null,
    blockId: blocked && typeof body.block_id === "string" && BLOCK_ID_PATTERN.test(body.block_id) ? body.block_id : null,
    requireClientId: boolOr(body.require_client_id, false),
    clientIdPresent: boolOr(body.client_id_present, false),
    checkedAt: isoOrNull(body.checked_at)
  };
}

// 저장본 -> 안전한 형식. 차단 상태인데 사유 코드가 없으면 '확인 전'으로 낮춘다
export function normalizeAccessState(raw) {
  const d = defaultAccessState();
  const source = isPlainObject(raw) ? raw : {};
  const status = Object.values(ACCESS_STATES).includes(source.status) ? source.status : d.status;
  const reasonCode = reasonCodeOrNull(source.reasonCode);
  const lastConfirmed = [ACCESS_STATES.ALLOWED, ACCESS_STATES.BLOCKED].includes(source.lastConfirmed) ? source.lastConfirmed : null;
  const base = { ...d, lastConfirmed, requireClientId: boolOr(source.requireClientId, false), clientIdPresent: boolOr(source.clientIdPresent, false), checkedAt: isoOrNull(source.checkedAt), attemptedAt: isoOrNull(source.attemptedAt) };
  if (status !== ACCESS_STATES.BLOCKED) return { ...base, status };
  if (!reasonCode) return { ...base, status: ACCESS_STATES.UNKNOWN };
  const memo = typeof source.userMemo === "string" ? cleanText(source.userMemo, MAX_MEMO) : "";
  return { ...base, status, reasonCode, reasons: normalizeReasons(source.reasons), userMemo: memo || null, until: isoOrNull(source.until), blockId: typeof source.blockId === "string" && BLOCK_ID_PATTERN.test(source.blockId) ? source.blockId : null };
}

// 보호가 꺼졌거나 확인할 수 없는 조건: 화면에 보일 상태는 지우되, 마지막으로 확인한 결과(차단/허용)는 알림 판단용으로 남긴다
export function resetAccessState(previous) {
  return { ...defaultAccessState(), lastConfirmed: normalizeAccessState(previous).lastConfirmed };
}

// 조회 결과 하나를 상태에 반영한다. change: "BLOCKED"(처음 차단 확인) | "UNBLOCKED"(차단 후 허용 확인) | null
// 조회 실패는 '확인 불가'로만 기록한다(차단/허용 어느 쪽도 추정하지 않고, 마지막 확인 결과만 유지)
export function reduceAccessState(previous, outcome, nowIso) {
  const before = normalizeAccessState(previous);
  const attemptedAt = isoOrNull(nowIso);
  const access = outcome?.ok === true ? outcome.access : null;
  if (!access) return { state: { ...defaultAccessState(), status: ACCESS_STATES.UNAVAILABLE, lastConfirmed: before.lastConfirmed, attemptedAt }, change: null };
  const status = access.blocked ? ACCESS_STATES.BLOCKED : ACCESS_STATES.ALLOWED;
  const state = normalizeAccessState({ ...access, status, lastConfirmed: status, checkedAt: access.checkedAt || attemptedAt, attemptedAt });
  const change = status === ACCESS_STATES.BLOCKED && before.lastConfirmed !== ACCESS_STATES.BLOCKED ? "BLOCKED"
    : status === ACCESS_STATES.ALLOWED && before.lastConfirmed === ACCESS_STATES.BLOCKED ? "UNBLOCKED" : null;
  return { state, change };
}

// 해제 예정 시각 표시: 한국 표준시(KST) 'YYYY-MM-DD HH:mm'
export function formatKst(iso) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms + 9 * 3600 * 1000);
  const two = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}`;
}

// 해제 예정 표시(한국 시간): '10월 13일 오후 6:00'
export function formatUntil(iso) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms + 9 * 3600 * 1000);
  const hour = d.getUTCHours();
  return `${d.getUTCMonth() + 1}월 ${d.getUTCDate()}일 ${hour < 12 ? "오전" : "오후"} ${hour % 12 === 0 ? 12 : hour % 12}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

export function accessReasonText(state) {
  if (state?.reasonCode === ACCESS_REASON_CODES.ID_MISSING) return CLIENT_ID_MISSING_TEXT;
  return (state?.reasons || []).map((reason) => reason.label).join(" · ");
}

export function accessUntilText(state) {
  if (state?.reasonCode === ACCESS_REASON_CODES.ID_MISSING) return "";
  return state?.until ? formatUntil(state.until) : ADMIN_UNTIL_TEXT;
}

// 팝업 표시용: 상태 줄(접속 제한)과 빨간 카드. active=false(보호 꺼짐·프록시 불일치)면 저장된 차단 상태가 남아 있어도 보이지 않는다
export function accessView(access, { active = true, identityEnabled = true } = {}) {
  const state = normalizeAccessState(access);
  if (!active) return { statusText: "보호 꺼짐", dot: "unknown", card: null };
  if (state.status === ACCESS_STATES.BLOCKED) {
    const rows = [];
    const reason = accessReasonText(state);
    if (reason) rows.push({ label: "사유", value: reason });
    if (state.userMemo) rows.push({ label: "관리자 안내", value: state.userMemo });
    const until = accessUntilText(state);
    if (until) rows.push({ label: "해제 예정", value: until });
    if (state.reasonCode === ACCESS_REASON_CODES.ID_MISSING && !identityEnabled) rows.push({ label: "조치", value: "설정에서 'AI 사이트 요청에 내 확장 번호 함께 보내기'를 켜 주세요." });
    // 차단 번호는 맨 아래 문의 줄에 작게 붙인다(관리자에게 알려 줄 때 쓰는 번호)
    return { statusText: "제한됨", dot: "error", card: { title: ACCESS_BLOCKED_TITLE, rows, contact: `문의: 보안 관리자${state.blockId ? ` · 차단 번호 ${state.blockId}` : ""}` } };
  }
  if (state.status === ACCESS_STATES.ALLOWED) return { statusText: "없음", dot: "healthy", card: null };
  if (state.status === ACCESS_STATES.UNAVAILABLE) return { statusText: "확인 불가", dot: "degraded", card: null };
  return { statusText: "확인 중", dot: "unknown", card: null };
}

// 데스크톱 알림 문구: 처음 차단이 확인됐을 때 / 차단이 풀렸을 때 한 번씩. 알림은 짧게(제목 + 사유 + 해제 예정) - 관리자 안내·차단 번호는 팝업 카드에서 본다
export function accessNotificationText(change, state) {
  if (change === "UNBLOCKED") return { title: "사용 제한이 해제되었습니다", message: "AI 사이트를 다시 사용할 수 있습니다." };
  if (change !== "BLOCKED") return null;
  const normalized = normalizeAccessState(state);
  const lines = [];
  const reason = accessReasonText(normalized);
  if (reason) lines.push(`사유: ${reason}`);
  const until = accessUntilText(normalized);
  if (until) lines.push(`해제 예정: ${until}`);
  if (!lines.length) lines.push("브라우저 오른쪽 위 PromptGate 아이콘을 눌러 확인해 주세요.");
  return { title: ACCESS_BLOCKED_TITLE, message: lines.join("\n") };
}
