import { SECURITY_ACTIONS } from "../config/statuses.js";
import { cleanText, isPlainObject } from "../utils/validation.js";

const NOTIFIABLE_ACTIONS = new Set([SECURITY_ACTIONS.BLOCK, SECURITY_ACTIONS.MASK]);
const ALLOWED_SEVERITIES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]);
// 1.4.2: Gateway가 붙이는 사유·종류·장애 여부·알림 표시. 형식이 틀리면 그 칸만 버린다
const REASON_CODE_PATTERN = /^[a-z][a-z0-9_]{0,99}$/;
const CONTENT_TYPES = new Set(["prompt", "file"]);

// ALLOW는 Gateway가 알림을 요청한 경우(notify === true)만 받는다
function isNotifiableAction(candidate) {
  return NOTIFIABLE_ACTIONS.has(candidate.action) || (candidate.action === SECURITY_ACTIONS.ALLOW && candidate.notify === true);
}

function normalizedTimestamp(value, now) {
  if (typeof value === "string") {
    const timestamp = Date.parse(value);
    if (Number.isFinite(timestamp)) return new Date(timestamp).toISOString();
  }
  return new Date(now()).toISOString();
}

export function normalizeSecurityEvent(candidate, { now = Date.now, expectedClientId = "", requireClientId = false } = {}) {
  if (!isPlainObject(candidate)) return null;
  const eventId = cleanText(candidate.eventId, 128);
  const clientId = cleanText(candidate.clientId, 64);
  const targetLlm = cleanText(candidate.targetLlm ?? candidate.service, 64);
  if (!eventId || !targetLlm || !isNotifiableAction(candidate)) return null;
  if (requireClientId && (!clientId || clientId !== expectedClientId)) return null;
  const severity = cleanText(candidate.severity, 16).toUpperCase();
  return Object.freeze({
    eventId,
    timestamp: normalizedTimestamp(candidate.timestamp, now),
    targetLlm,
    action: candidate.action,
    detector: cleanText(candidate.detector, 64) || "Unknown",
    matchType: cleanText(candidate.matchType ?? candidate.category, 64) || "Unknown",
    severity: ALLOWED_SEVERITIES.has(severity) ? severity : "UNKNOWN",
    reasonCode: typeof candidate.reasonCode === "string" && REASON_CODE_PATTERN.test(candidate.reasonCode) ? candidate.reasonCode : null,
    contentType: CONTENT_TYPES.has(candidate.contentType) ? candidate.contentType : null,
    degraded: candidate.degraded === true,
    notify: candidate.notify === true
  });
}

export function parseEventChannelMessage(data, options) {
  if (typeof data !== "string") return null;
  let candidate;
  try { candidate = JSON.parse(data); } catch { return null; }
  if (isPlainObject(candidate) && ["HEARTBEAT", "PONG"].includes(candidate.type)) return Object.freeze({ kind: "HEARTBEAT" });
  if (!isPlainObject(candidate) || candidate.type !== "SECURITY_EVENT") return null;
  const expectedClientId = cleanText(options?.expectedClientId, 64);
  const clientId = cleanText(candidate.clientId, 64);
  const eventId = cleanText(candidate.eventId, 128);
  if (!expectedClientId || clientId !== expectedClientId || !eventId) return null;
  if (candidate.action === SECURITY_ACTIONS.ALLOW && candidate.notify !== true) return Object.freeze({ kind: "IGNORED_ACTION" });
  const event = normalizeSecurityEvent(candidate, { ...options, requireClientId: true });
  return event ? Object.freeze({ kind: "SECURITY_EVENT", event }) : null;
}
