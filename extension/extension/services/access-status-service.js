import { ACCESS_STATUS_MIN_INTERVAL_MS } from "../config/defaults.js";
import { ACCESS_STATES } from "../config/statuses.js";
import { isValidIdentity } from "../utils/validation.js";
import { reduceAccessState, resetAccessState } from "./access-state.js";
import { accessStatusCheck } from "./gateway-service.js";
import { applyManagedSettings, getManagedPolicy } from "./policy-service.js";
import { captureProxySnapshot, proxySnapshotMatchesSettings } from "./proxy-service.js";
import { readModel, writeAccessState } from "./storage-service.js";

// 1.4.5: 접속 제한 상태를 조회해도 되는 조건 = 내 요청 기록 페이지(GET_MODEL)와 같은 보호 확인.
// 보호 켜짐 + Gateway 주소 있음 + 이 확장 프로그램이 PAC 소유 + 현재 PAC가 설정값으로 만든 PAC와 같음(llm-gateway.local -> 설정된 Gateway).
// 보호가 꺼져 있으면 llm-gateway.local이 공용 DNS로 풀리므로 식별 정보를 절대 보내지 않는다.
// clientId: 사용자가 '클라이언트 식별 헤더 전송'을 켠 경우에만 넘긴다(꺼져 있으면 LLM 요청과 같이 식별 정보 없이 조회 -> Gateway가 같은 기준으로 판정).
export async function resolveAccessContext() {
  const model = await readModel();
  if (!model.runtimeState.desiredProtection) return { eligible: false, reason: "PROTECTION_OFF" };
  const policy = await getManagedPolicy();
  if (policy.errors.length) return { eligible: false, reason: "INVALID_POLICY" };
  const settings = applyManagedSettings(model.settings, policy);
  if (!settings.gateway.host) return { eligible: false, reason: "NOT_CONFIGURED" };
  const snapshot = await captureProxySnapshot();
  if (!proxySnapshotMatchesSettings(snapshot, settings)) return { eligible: false, reason: "PROXY_MISMATCH" };
  const clientId = settings.identity.enabled && isValidIdentity(model.identity.clientId) ? model.identity.clientId.trim() : "";
  return { eligible: true, clientId };
}

export function createAccessStatusService({
  resolveContext = resolveAccessContext,
  check = accessStatusCheck,
  readState = async () => (await readModel()).accessState,
  writeState = writeAccessState,
  notifyChange = async () => false,
  onUpdate = async () => undefined,
  now = () => Date.now()
} = {}) {
  async function settle(previous, state, change) {
    await writeState(state);
    if (change) { try { await notifyChange(change, state); } catch { /* 알림 실패가 조회 결과를 막지 않는다 */ } }
    if (change || state.status !== previous.status) await onUpdate({ change, state, previous });
  }

  // force=false: 마지막 시도 후 짧은 시간 안이면 건너뛴다(팝업을 자주 여는 경우). 예외는 밖으로 내보내지 않는다
  async function refresh({ force = true } = {}) {
    try {
      const context = await resolveContext();
      const previous = await readState();
      if (!context.eligible) {
        if (previous.status !== ACCESS_STATES.UNKNOWN) await settle(previous, resetAccessState(previous), null);
        return { ok: false, skipped: context.reason || "NOT_ELIGIBLE" };
      }
      const last = Date.parse(previous.attemptedAt);
      if (!force && Number.isFinite(last) && now() - last < ACCESS_STATUS_MIN_INTERVAL_MS) return { ok: true, skipped: "RECENT", status: previous.status };
      const outcome = await check({ clientId: context.clientId });
      const { state, change } = reduceAccessState(previous, outcome, new Date(now()).toISOString());
      await settle(previous, state, change);
      return { ok: outcome?.ok === true, status: state.status, change };
    } catch {
      return { ok: false, errorCode: "ACCESS_STATUS_FAILED" };
    }
  }

  // 보호를 끌 때: 화면에 남은 차단 표시를 지운다(마지막 확인 결과는 유지)
  async function reset() {
    try {
      const previous = await readState();
      if (previous.status !== ACCESS_STATES.UNKNOWN) await settle(previous, resetAccessState(previous), null);
      return { ok: true };
    } catch {
      return { ok: false, errorCode: "ACCESS_STATUS_FAILED" };
    }
  }

  return { refresh, reset };
}
