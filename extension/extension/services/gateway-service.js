import { GATEWAY_PROBE_HOST } from "../routing/protected-domains.js";
import { HEALTH_TIMEOUT_MS, DEGRADED_LATENCY_MS, MAX_CONTROL_RESPONSE_BYTES, MY_REQUESTS_MAX_BYTES, MY_REQUESTS_TIMEOUT_MS } from "../config/defaults.js";
import { GATEWAY_PROFILES, GATEWAY_STATES } from "../config/statuses.js";
import { isValidIdentity, isValidViewerKey } from "../utils/validation.js";
import { parseAccessStatusResponse } from "./access-state.js";

const HEALTH_UNSUPPORTED_STATUSES = new Set([404, 405, 501]);
const M1_LEGACY_HEALTH_STATUSES = new Set([502, 503, 504]);

function failure(errorCode, userMessage, technicalDetail = "", extra = {}) {
  return { ok: false, state: GATEWAY_STATES.OFFLINE, errorCode, userMessage, technicalDetail: String(technicalDetail || "").slice(0, 500), ...extra };
}

export function gatewayStateForLatency(latencyMs) { return latencyMs >= DEGRADED_LATENCY_MS ? GATEWAY_STATES.DEGRADED : GATEWAY_STATES.HEALTHY; }

async function readJsonBounded(response, maxBytes = MAX_CONTROL_RESPONSE_BYTES) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw Object.assign(new Error(`Content-Length ${declared}`), { code: "RESPONSE_TOO_LARGE" });
  const reader = response.body?.getReader();
  if (!reader) throw Object.assign(new Error("Readable response body is unavailable"), { code: "BODY_UNAVAILABLE" });
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel(); throw Object.assign(new Error(`Response exceeded ${maxBytes} bytes`), { code: "RESPONSE_TOO_LARGE" }); }
    chunks.push(value);
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder().decode(merged)); }
  catch (error) { throw Object.assign(error, { code: "MALFORMED_JSON" }); }
}

async function probe(path, { legacyM1HealthFallback = false, headers = null, cacheBust = true, init = null, timeoutMs = HEALTH_TIMEOUT_MS, maxBytes = MAX_CONTROL_RESPONSE_BYTES } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const started = performance.now();
  try {
    const response = await fetch(`http://${GATEWAY_PROBE_HOST}${path}${cacheBust ? `?t=${Date.now()}` : ""}`, { cache: "no-store", signal: controller.signal, ...(headers ? { headers } : {}), ...(init || {}) });
    if (HEALTH_UNSUPPORTED_STATUSES.has(response.status)) return failure("HEALTH_UNSUPPORTED", "Gateway Health API를 지원하지 않습니다.", `HTTP ${response.status}`, { state: GATEWAY_STATES.UNSUPPORTED, status: response.status, latencyMs: Math.round(performance.now() - started) });
    if (legacyM1HealthFallback && M1_LEGACY_HEALTH_STATUSES.has(response.status)) {
      return failure("M1_LEGACY_HEALTH_UNSUPPORTED", "M1 Legacy Gateway의 Health API 상태를 확인할 수 없습니다.", `HTTP ${response.status} from M1 legacy health probe`, { state: GATEWAY_STATES.UNSUPPORTED, status: response.status, latencyMs: Math.round(performance.now() - started) });
    }
    let body;
    try { body = await readJsonBounded(response, maxBytes); }
    catch (error) {
      const tooLarge = error.code === "RESPONSE_TOO_LARGE";
      return failure(error.code || "MALFORMED_JSON", tooLarge ? "게이트웨이 응답이 허용 크기를 초과했습니다." : "게이트웨이 응답 형식이 올바르지 않습니다.", error.message, { status: response.status });
    }
    if (!response.ok) return failure("HTTP_ERROR", "게이트웨이가 오류를 반환했습니다.", `HTTP ${response.status}`, { status: response.status });
    return { ok: true, status: response.status, body, latencyMs: Math.round(performance.now() - started) };
  } catch (error) {
    return error?.name === "AbortError"
      ? failure("TIMEOUT", "게이트웨이 응답 시간이 초과되었습니다.", `Timeout after ${timeoutMs} ms`)
      : failure("NETWORK_ERROR", "게이트웨이에 연결할 수 없습니다.", error?.message || error);
  } finally { clearTimeout(timeout); }
}

export async function healthCheck({ gatewayProfile = GATEWAY_PROFILES.CUSTOM } = {}) {
  const result = await probe("/__llmsgw/health", { legacyM1HealthFallback: gatewayProfile === GATEWAY_PROFILES.M1_TEST });
  if (!result.ok) return result;
  if (result.body?.status !== "ok" || typeof result.body?.version !== "string") return failure("INVALID_HEALTH", "게이트웨이 상태 응답이 올바르지 않습니다.", "Expected status=ok and string version", { status: result.status });
  return { ...result, state: gatewayStateForLatency(result.latencyMs), userMessage: "", technicalDetail: "" };
}

export async function statsCheck() {
  const result = await probe("/__llmsgw/stats");
  if (!result.ok) return result;
  const body = result.body;
  const valid = body && typeof body === "object" && !Array.isArray(body) && ["uptime_sec", "total_requests", "total_responses", "error_responses"].every((key) => Number.isFinite(body[key])) && body.services && typeof body.services === "object" && !Array.isArray(body.services);
  if (!valid) return failure("INVALID_STATS", "게이트웨이 통계 응답이 올바르지 않습니다.", "Expected finite counters and services object", { status: result.status });
  return result;
}

// 1.4.5: 이 클라이언트의 접속 제한 상태. 식별 정보(clientId)는 보호가 켜져 있고 PAC가 llm-gateway.local을 설정된 Gateway로 보낼 때만 호출자가 넘긴다.
// 쿼리 없는 고정 주소, 쿠키 없음, 리다이렉트 거부(식별 헤더가 다른 곳으로 따라가지 않게). 응답이 계약과 다르면 실패로 처리해 가짜 '차단'을 만들지 않는다.
export const ACCESS_STATUS_PATH = "/__llmsgw/access-status";
export const ACCESS_STATUS_CLIENT_HEADER = "X-LLMSGW-Client-Id";

export async function accessStatusCheck({ clientId = "" } = {}) {
  const headers = isValidIdentity(clientId) ? { [ACCESS_STATUS_CLIENT_HEADER]: clientId.trim() } : null;
  const result = await probe(ACCESS_STATUS_PATH, { headers, cacheBust: false, init: { credentials: "omit", redirect: "error" } });
  if (!result.ok) return result;
  const access = parseAccessStatusResponse(result.body);
  if (!access) return failure("INVALID_ACCESS_STATUS", "접속 제한 상태 응답이 올바르지 않습니다.", "Expected boolean blocked and a valid reason_code when blocked", { status: result.status });
  return { ok: true, status: result.status, access, latencyMs: result.latencyMs };
}

// 1.4.8: 내 요청 기록 목록(차단·마스킹 집계용). 내 요청 기록 페이지가 부르는 것과 같은 주소·같은 열람 키.
// 열람 키는 호출자가 보호 켜짐 + PAC 일치를 확인한 뒤에만 넘긴다(보호가 꺼져 있으면 llm-gateway.local이 공용 DNS로 풀린다). 쿠키 없음, 리다이렉트 거부, Referer 없음.
export const MY_REQUESTS_PATH = "/__llmsgw/my/requests";
export const VIEWER_KEY_HEADER = "X-Viewer-Key";

export async function myRequestsCheck({ viewerKey = "" } = {}) {
  if (!isValidViewerKey(viewerKey)) return failure("NO_VIEWER_KEY", "열람 키가 올바르지 않습니다.");
  return probe(MY_REQUESTS_PATH, { headers: { [VIEWER_KEY_HEADER]: viewerKey, Accept: "application/json" }, cacheBust: false, timeoutMs: MY_REQUESTS_TIMEOUT_MS, maxBytes: MY_REQUESTS_MAX_BYTES, init: { credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" } });
}
