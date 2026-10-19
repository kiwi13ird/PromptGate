import { ACCESS_STATUS_ALARM, EVENT_RECONNECT_ALARM, HEALTH_ALARM } from "../config/defaults.js";
import { supportedServiceLabels } from "../routing/protected-domains.js";
import { GATEWAY_STATES } from "../config/statuses.js";
import { createEventChannelService } from "../event-channel/event-channel-service.js";
import { clearSecurityEvents, storeSecurityEvent } from "../event-channel/event-store.js";
import { notifyAccessChange, notifySecurityEvent } from "../event-channel/notification-service.js";
import { createAccessStatusService } from "../services/access-status-service.js";
import { createActionStatsService } from "../services/action-stats-service.js";
import { ensureAccessStatusAlarm, ensureHealthAlarm } from "../services/alarm-service.js";
import { badgeFor } from "../services/badge.js";
import { createCommandHandler } from "../services/command-service.js";
import { healthCheck, statsCheck } from "../services/gateway-service.js";
import { captureIdentityRule, identityRuleMatches, removeIdentityRuleVerified, restoreIdentityRule, syncIdentityRule } from "../services/identity-service.js";
import { applyManagedSettings, getManagedPolicy, isManagedField, preserveManagedLocalSettings } from "../services/policy-service.js";
import { applyWithRollback, createBootstrapOnce, createSerialExecutor, enforceIdentityFailSafe } from "../services/protection-transaction.js";
import { canSetProxy, captureProxySnapshot, clearProtectionPac, proxySnapshotMatchesSettings, readProxyState, restoreProxySnapshot, setProtectionPac } from "../services/proxy-service.js";
import { appendEvent, commitProtectionState, initializeStorage, readModel, updateRuntime } from "../services/storage-service.js";
import { operationError, publicError } from "../utils/operation-error.js";

const enqueue = createSerialExecutor();
let recentHealth = { at: 0, result: null };
let recentStats = { at: 0, result: null };

async function processSecurityEvent(event) {
  const model = await readModel();
  if (!model.runtimeState.desiredProtection) return { stored: false, reason: "PROTECTION_DISABLED", events: model.recentSecurityEvents };
  const result = await storeSecurityEvent(event);
  if (result.stored) {
    await notifySecurityEvent(result.event);
    await updateRuntime({ lastSecurityEventAt: result.event.timestamp });
  }
  return result;
}

// 1.4.8: 이 PC에서 확장이 확인한 차단·마스킹 건수(팝업 표시). 실시간 알림 + 내 요청 기록(Gateway 중계) 조회, 요청 번호로 중복 제거
const actionStats = createActionStatsService();

const eventChannel = createEventChannelService({
  readSettings: async () => {
    const model = await readModel();
    const policy = await getManagedPolicy();
    if (policy.errors.length) return { ...model.settings, eventChannel: { enabled: false, url: "" }, clientId: model.identity.clientId, protectionEnabled: false };
    return { ...applyManagedSettings(model.settings, policy), clientId: model.identity.clientId, protectionEnabled: model.runtimeState.desiredProtection };
  },
  updateRuntime,
  // 1.4.8: 차단·마스킹 집계는 알림 저장보다 먼저, 실패해도 알림 흐름은 그대로(recordEvent는 예외를 내보내지 않는다)
  storeEvent: async (event) => { await actionStats.recordEvent(event); return storeSecurityEvent(event); },
  notifyEvent: notifySecurityEvent
});

async function setBadge(state) {
  const badge = badgeFor(state, (await readModel()).accessState);
  await chrome.action.setBadgeText({ text: badge.text });
  await chrome.action.setBadgeBackgroundColor({ color: badge.color });
  await chrome.action.setTitle({ title: badge.title });
}

// 1.4.5: 접속 제한 상태(/__llmsgw/access-status) 조회 - 1분 알람, 팝업 열 때, 시작 시. 보호가 켜져 있고 PAC가 일치할 때만 조회한다(식별 정보 포함)
const accessStatus = createAccessStatusService({
  notifyChange: notifyAccessChange,
  onUpdate: async ({ change, state }) => {
    if (change === "BLOCKED") await appendEvent("ACCESS_BLOCKED", state.reasonCode || "");
    if (change === "UNBLOCKED") await appendEvent("ACCESS_RESTORED");
    const model = await readModel();
    await setBadge(model.runtimeState.desiredProtection ? model.runtimeState.gatewayState : GATEWAY_STATES.DISABLED);
  }
});

async function markConflict(proxy, technicalDetail = "") {
  await updateRuntime({ gatewayState: "CONFLICT", proxyLevelOfControl: proxy.levelOfControl, proxyMode: proxy.mode, lastErrorCode: "PROXY_CONFLICT", lastTechnicalDetail: technicalDetail });
  await setBadge("CONFLICT");
}

async function ensureIdentitySafeForProxy(proxy) {
  const model = await readModel();
  return enforceIdentityFailSafe({
    desiredProtection: model.runtimeState.desiredProtection,
    proxyState: proxy,
    removeIdentity: removeIdentityRuleVerified,
    markConflict: async () => {
      await markConflict(proxy, "Proxy ownership or PAC mode no longer belongs to this extension.");
      await appendEvent("PROXY_OWNERSHIP_LOST", proxy.levelOfControl);
    }
  });
}

async function health({ log = false } = {}) {
  const model = await readModel();
  if (!model.runtimeState.desiredProtection) { await setBadge("DISABLED"); return { ok: false, disabled: true, userMessage: "보호가 꺼져 있습니다." }; }
  const proxy = await readProxyState();
  if (await ensureIdentitySafeForProxy(proxy)) {
    const conflict = { ok: false, state: "CONFLICT", errorCode: "PROXY_CONFLICT", userMessage: "다른 확장 프로그램 또는 정책이 프록시를 제어하고 있습니다." };
    recentHealth = { at: Date.now(), result: conflict };
    return conflict;
  }
  // Reuse only the network result; proxy ownership is revalidated for every call.
  if (recentHealth.result && Date.now() - recentHealth.at < 1000) return recentHealth.result;
  const result = await healthCheck({ gatewayProfile: model.settings.gateway.profile });
  await updateRuntime({ gatewayState: result.state, lastHealthAt: new Date().toISOString(), lastHealthLatencyMs: result.latencyMs ?? null, lastHealthError: result.userMessage || "", lastErrorCode: result.errorCode || "", lastTechnicalDetail: result.technicalDetail || "", proxyLevelOfControl: proxy.levelOfControl, proxyMode: proxy.mode });
  await setBadge(result.state);
  if (log) await appendEvent(result.ok ? "HEALTH_OK" : result.state === GATEWAY_STATES.UNSUPPORTED ? "HEALTH_UNSUPPORTED" : "HEALTH_FAILED", result.ok ? `${result.latencyMs} ms` : result.errorCode || "UNKNOWN");
  recentHealth = { at: Date.now(), result };
  return result;
}

async function stats() {
  const model = await readModel();
  if (!model.runtimeState.desiredProtection) return { ok: false, disabled: true, errorCode: "PROTECTION_DISABLED", userMessage: "보호를 켠 뒤 Gateway 통계를 확인해 주세요." };
  const proxy = await readProxyState();
  if (await ensureIdentitySafeForProxy(proxy)) return { ok: false, state: "CONFLICT", errorCode: "PROXY_CONFLICT", userMessage: "프록시 충돌로 Gateway 통계를 확인할 수 없습니다." };
  if (recentStats.result && Date.now() - recentStats.at < 1000) return recentStats.result;
  const result = await statsCheck();
  recentStats = { at: Date.now(), result };
  return result;
}

async function applyConfiguration(settings, { saveUserSettings = true, eventType = "PROTECTION_ENABLED", runHealth = true } = {}) {
  const current = await readModel();
  const policy = await getManagedPolicy();
  if (policy.errors.length) throw operationError("INVALID_MANAGED_POLICY", "관리자 정책 형식이 올바르지 않습니다.", policy.errors.join("; "));
  if (policy.values.protectionEnabled === false && eventType === "PROTECTION_ENABLED") throw operationError("PROTECTION_DISABLED_BY_POLICY", "관리자 정책에서 보호 기능을 해제하도록 설정했습니다.");
  const userSettings = preserveManagedLocalSettings(settings, current.settings, policy);
  const effectiveSettings = applyManagedSettings(userSettings, policy);
  recentHealth = { at: 0, result: null };
  recentStats = { at: 0, result: null };
  const startingProxy = await readProxyState();
  if (startingProxy.levelOfControl !== "controlled_by_this_extension" || startingProxy.mode !== "pac_script") await removeIdentityRuleVerified();
  try {
    await applyWithRollback({
      capture: async () => ({ proxy: await captureProxySnapshot(), identityRule: await captureIdentityRule(), runtime: current.runtimeState }),
      applyNext: async () => {
        await setProtectionPac(effectiveSettings);
        await syncIdentityRule(effectiveSettings, current.identity);
        const finalProxy = await captureProxySnapshot();
        if (!proxySnapshotMatchesSettings(finalProxy, effectiveSettings)) {
          await removeIdentityRuleVerified();
          const error = new Error("Proxy ownership changed after identity rule synchronization.");
          error.code = "PROXY_OWNERSHIP_LOST_DURING_APPLY";
          throw error;
        }
        return effectiveSettings;
      },
      commit: async () => {
        await commitProtectionState({ settings: userSettings, saveUserSettings, runtimePatch: { desiredProtection: true, gatewayState: "UNKNOWN", lastProxyError: "", lastErrorCode: "", lastTechnicalDetail: "" }, eventType, eventDetail: supportedServiceLabels().join(", ") });
      },
      rollback: async (previous) => { await removeIdentityRuleVerified(); await restoreProxySnapshot(previous.proxy); await restoreIdentityRule(previous.identityRule); await updateRuntime(previous.runtime); },
      failSafe: async (applyError, rollbackError) => {
        try { await removeIdentityRuleVerified(); } catch { /* runtime records the critical failure */ }
        const proxy = await readProxyState();
        if (!canSetProxy(proxy.levelOfControl)) await markConflict(proxy, `${applyError?.message}; ${rollbackError?.message}`);
        else { await updateRuntime({ gatewayState: "PROXY_ERROR", lastErrorCode: "ROLLBACK_FAILED", lastTechnicalDetail: `${applyError?.message}; ${rollbackError?.message}` }); await setBadge("PROXY_ERROR"); }
      }
    });
  } catch (error) {
    if (error.code === "ROLLBACK_FAILED") {
      const proxy = await readProxyState();
      if (!canSetProxy(proxy.levelOfControl)) throw operationError("PROXY_CONFLICT", "다른 확장 프로그램이 연결 설정을 바꿔 보호를 켜지 못했습니다.", error.technicalDetail || error.message);
      throw error;
    }
    throw operationError("APPLY_FAILED_ROLLED_BACK", "새 설정을 적용하지 못해 변경 전 상태로 복구했습니다.", error?.message || error);
  }
  try { await eventChannel.sync(); } catch { console.warn("Event Channel 연결 오류를 Proxy 보호와 분리했습니다."); }
  return runHealth ? health() : { ok: true, healthDeferred: true };
}

async function disable({ policyChange = false } = {}) {
  recentHealth = { at: 0, result: null };
  recentStats = { at: 0, result: null };
  const policy = await getManagedPolicy();
  if (!policyChange && isManagedField(policy, "runtime.desiredProtection")) throw operationError("PROTECTION_REQUIRED_BY_POLICY", "보호 상태는 관리자 정책으로 관리되어 변경할 수 없습니다.");
  try { await removeIdentityRuleVerified(); }
  catch (error) {
    await appendEvent("IDENTITY_RULE_REMOVE_FAILED", "DNR_REMOVE_FAILED");
    throw operationError("IDENTITY_RULE_REMOVE_FAILED", "보호를 끄지 못했습니다. 보호는 켜진 상태로 유지됩니다.", error?.message || error);
  }
  const proxy = await clearProtectionPac();
  await updateRuntime({ desiredProtection: false, gatewayState: "DISABLED", proxyLevelOfControl: proxy.levelOfControl, proxyMode: proxy.mode, lastErrorCode: "", lastTechnicalDetail: "" });
  await eventChannel.stop();
  await appendEvent("PROTECTION_DISABLED");
  await accessStatus.reset();
  await setBadge("DISABLED");
  return { ok: true };
}

async function bootstrapTask() {
  await initializeStorage();
  try { await actionStats.ensureStarted(); } catch { console.warn("집계 시작 시각을 저장하지 못했습니다."); }
  await ensureHealthAlarm();
  await ensureAccessStatusAlarm();
  const model = await readModel();
  const policy = await getManagedPolicy();
  if (policy.errors.length) {
    await removeIdentityRuleVerified();
    await updateRuntime({ gatewayState: "CONFIGURATION_ERROR", lastErrorCode: "INVALID_MANAGED_POLICY", lastTechnicalDetail: policy.errors.join("; ") });
    await eventChannel.stop();
    await setBadge("CONFIGURATION_ERROR");
    return;
  }
  const desiredProtection = typeof policy.values.protectionEnabled === "boolean" ? policy.values.protectionEnabled : model.runtimeState.desiredProtection;
  if (desiredProtection !== model.runtimeState.desiredProtection) await updateRuntime({ desiredProtection });
  if (!desiredProtection) {
    await removeIdentityRuleVerified();
    await clearProtectionPac();
    await eventChannel.stop();
    await setBadge("DISABLED");
    return;
  }
  const effectiveSettings = applyManagedSettings(model.settings, policy);
  const proxy = await captureProxySnapshot();
  const identityRule = await captureIdentityRule();
  if (proxySnapshotMatchesSettings(proxy, effectiveSettings) && identityRuleMatches(identityRule, effectiveSettings, model.identity)) { await setBadge(model.runtimeState.gatewayState); await eventChannel.sync(); return; }
  if (proxy.levelOfControl !== "controlled_by_this_extension" || proxy.value?.mode !== "pac_script") {
    await removeIdentityRuleVerified();
    if (!canSetProxy(proxy.levelOfControl)) { await markConflict({ levelOfControl: proxy.levelOfControl, mode: proxy.value?.mode || "unknown" }); await eventChannel.sync(); return; }
  }
  await applyConfiguration(model.settings, { saveUserSettings: false, eventType: "PROTECTION_RESTORED", runHealth: false });
}

const bootstrap = createBootstrapOnce(bootstrapTask);

async function handlePolicyChange() {
  const model = await readModel();
  const policy = await getManagedPolicy();
  await appendEvent("MANAGED_POLICY_CHANGED", policy.active ? policy.mode : "removed");
  if (policy.errors.length) {
    await removeIdentityRuleVerified();
    await updateRuntime({ gatewayState: "CONFIGURATION_ERROR", lastErrorCode: "INVALID_MANAGED_POLICY", lastTechnicalDetail: policy.errors.join("; ") });
    await setBadge("CONFIGURATION_ERROR");
    await eventChannel.stop();
    return;
  }
  if (policy.values.protectionEnabled === false) {
    if (model.runtimeState.desiredProtection || (await readProxyState()).levelOfControl === "controlled_by_this_extension") await disable({ policyChange: true });
    return;
  }
  const effectiveSettings = applyManagedSettings(model.settings, policy);
  if (policy.values.protectionEnabled === true || model.runtimeState.desiredProtection) {
    const proxy = await captureProxySnapshot();
    const identityRule = await captureIdentityRule();
    if (!proxySnapshotMatchesSettings(proxy, effectiveSettings) || !identityRuleMatches(identityRule, effectiveSettings, model.identity)) await applyConfiguration(model.settings, { saveUserSettings: false, eventType: "MANAGED_POLICY_APPLIED" });
    else { await health(); await eventChannel.sync(); }
  }
}

chrome.runtime.onInstalled.addListener(() => enqueue(async () => { await bootstrap(); if ((await readModel()).runtimeState.desiredProtection) { await health(); await accessStatus.refresh(); void actionStats.refresh({ force: true }); } }));
chrome.runtime.onStartup.addListener(() => enqueue(async () => { await bootstrap(); if ((await readModel()).runtimeState.desiredProtection) { await health(); await accessStatus.refresh(); void actionStats.refresh({ force: true }); } }));
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HEALTH_ALARM) enqueue(async () => { await bootstrap(); await health(); void actionStats.refresh({ force: false }); });
  if (alarm.name === EVENT_RECONNECT_ALARM) enqueue(async () => { await bootstrap(); await eventChannel.reconnectFromAlarm(); });
  if (alarm.name === ACCESS_STATUS_ALARM) enqueue(async () => { await bootstrap(); await accessStatus.refresh(); });
});
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "managed") enqueue(async () => { await bootstrap(); await handlePolicyChange(); await eventChannel.sync(); });
  if (areaName === "local" && (changes.settings || changes.identity)) enqueue(async () => { await bootstrap(); await eventChannel.sync(); });
});

chrome.proxy.settings.onChange.addListener((details) => {
  const proxy = { levelOfControl: details.levelOfControl || "unknown", mode: details.value?.mode || "unknown" };
  if (proxy.levelOfControl === "controlled_by_this_extension" && proxy.mode === "pac_script") return;
  // Identity removal runs before serialized UI/state work so an ownership change is fail-safe.
  removeIdentityRuleVerified()
    .then(() => enqueue(async () => { await bootstrap(); const model = await readModel(); if (model.runtimeState.desiredProtection) { await markConflict(proxy); await appendEvent("PROXY_OWNERSHIP_LOST", proxy.levelOfControl); } }))
    .catch((error) => enqueue(async () => { await updateRuntime({ gatewayState: "PROXY_ERROR", lastErrorCode: "IDENTITY_FAIL_SAFE_FAILED", lastTechnicalDetail: error?.message || error }); await setBadge("PROXY_ERROR"); }));
});

chrome.proxy.onProxyError.addListener((details) => enqueue(async () => {
  const technical = String(details?.error || "Unknown proxy error").slice(0, 250);
  await updateRuntime({ gatewayState: "PROXY_ERROR", lastProxyError: "프록시 연결 오류가 발생했습니다.", lastErrorCode: "PROXY_ERROR", lastTechnicalDetail: technical });
  await appendEvent("PROXY_ERROR", "PROXY_ERROR");
  await setBadge("PROXY_ERROR");
}));

const handleCommand = createCommandHandler({ applyConfiguration, disable, health, stats, processSecurityEvent, clearSecurityEvents, accessStatus: accessStatus.refresh, actionStatsSync: (options) => { void actionStats.refresh(options); } });

// 내 요청 기록(1.4.3): 확장 프로그램 안의 myrequests 페이지가 요청 직전마다 GET_MODEL로 보호 상태(보호 켜짐, PAC 일치)를 확인한다.
// 외부 웹페이지에는 열람 키를 주지 않는다(manifest에 외부 연결 허용 없음, 외부 메시지 수신기 없음)
chrome.runtime.onMessage.addListener((message, _sender, respond) => {
  enqueue(async () => {
    try { await bootstrap(); respond(await handleCommand(message)); }
    catch (error) { const response = publicError(error); await appendEvent("OPERATION_FAILED", response.errorCode); respond(response); }
  });
  return true;
});

enqueue(bootstrap);
