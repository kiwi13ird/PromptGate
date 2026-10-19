import { applyManagedSettings, getManagedPolicy, isManagedField, preserveManagedLocalSettings } from "./policy-service.js";
import { appendEvent, clearEvents, normalizeBackupReport, persistImportedBackup, readModel, saveSettings } from "./storage-service.js";
import { captureProxySnapshot, proxySnapshotMatchesSettings, readProxyState } from "./proxy-service.js";
import { SECURITY_ACTIONS } from "../config/statuses.js";
import { operationError } from "../utils/operation-error.js";

export function createCommandHandler({ applyConfiguration, disable, health, stats, processSecurityEvent, clearSecurityEvents, accessStatus = async () => ({ ok: false, skipped: "UNSUPPORTED" }), actionStatsSync = () => undefined }) {
  return async function handleCommand(message) {
    if (message?.type === "GET_MODEL") {
      const policy = await getManagedPolicy();
      const model = await readModel();
      model.settings = applyManagedSettings(model.settings, policy);
      const snapshot = await captureProxySnapshot();
      const proxy = { levelOfControl: snapshot.levelOfControl, mode: snapshot.value?.mode || "unknown", matchesSettings: proxySnapshotMatchesSettings(snapshot, model.settings) };
      return { ok: true, model, policy, proxy };
    }
    if (message?.type === "SAVE_SETTINGS") {
      const model = await readModel();
      if (model.runtimeState.desiredProtection) throw operationError("ACTIVE_SETTINGS_REQUIRE_APPLY", "보호가 켜져 있을 때는 ‘저장하고 보호 켜기’를 눌러 주세요.");
      const policy = await getManagedPolicy();
      await saveSettings(preserveManagedLocalSettings(message.settings, model.settings, policy));
      await appendEvent("SETTINGS_SAVED");
      return { ok: true };
    }
    if (message?.type === "APPLY") {
      const policy = await getManagedPolicy();
      if (isManagedField(policy, "runtime.desiredProtection")) throw operationError("MASTER_MANAGED", "보호 상태는 관리자 정책으로 관리되어 변경할 수 없습니다.");
      return { ok: true, result: await applyConfiguration(message.settings) };
    }
    if (message?.type === "SET_MASTER") {
      const model = await readModel();
      const policy = await getManagedPolicy();
      if (isManagedField(policy, "runtime.desiredProtection")) throw operationError("MASTER_MANAGED", "보호 상태는 관리자 정책으로 관리되어 변경할 수 없습니다.");
      if (message.enabled === true) {
        return { ok: true, result: await applyConfiguration(model.settings) };
      }
      if (message.enabled === false) return disable();
      throw operationError("INVALID_MASTER_VALUE", "보호 상태 값이 올바르지 않습니다.");
    }
    if (message?.type === "DISABLE") return disable();
    if (message?.type === "HEALTH") return { ok: true, result: await health({ log: true }) };
    if (message?.type === "STATS") return { ok: true, result: await stats() };
    // 1.4.5: 팝업을 열 때 접속 제한 상태를 다시 조회(force가 아니면 마지막 시도 후 15초 이내는 건너뜀). 보호가 꺼져 있으면 조회하지 않는다
    if (message?.type === "ACCESS_STATUS") return { ok: true, result: await accessStatus({ force: message.force === true }) };
    // 1.4.8: 팝업을 열 때 차단·마스킹 집계를 다시 읽는다. 기다리지 않고 바로 응답한다(결과는 저장소(actionStats)가 바뀌면서 화면에 반영됨)
    if (message?.type === "ACTION_STATS_SYNC") { actionStatsSync({ force: message.force === true }); return { ok: true }; }
    if (message?.type === "IMPORT_BACKUP") {
      const model = await readModel();
      if (model.runtimeState.desiredProtection) throw operationError("DISABLE_BEFORE_IMPORT", "설정 백업을 가져오기 전에 보호를 꺼 주세요.");
      const policy = await getManagedPolicy();
      const backup = normalizeBackupReport(message.report);
      const importedBackup = {
        ...backup,
        settings: preserveManagedLocalSettings(backup.settings, model.settings, policy),
        desiredProtection: isManagedField(policy, "runtime.desiredProtection") ? model.runtimeState.desiredProtection : backup.desiredProtection
      };
      await persistImportedBackup(importedBackup);
      if (importedBackup.desiredProtection) await applyConfiguration(importedBackup.settings, { saveUserSettings: false, eventType: "IMPORTED_PROTECTION_RESTORED" });
      return { ok: true, protectionRestored: importedBackup.desiredProtection };
    }
    if (message?.type === "SIMULATE_SECURITY_EVENT") {
      const model = await readModel();
      const policy = await getManagedPolicy();
      const effective = applyManagedSettings(model.settings, policy);
      if (!effective.developmentMode || !effective.developerToolsEnabled) throw operationError("DEVELOPMENT_ONLY", "Development Mode에서 개발 테스트 도구를 명시적으로 켠 경우에만 사용할 수 있습니다.");
      if (![SECURITY_ACTIONS.BLOCK, SECURITY_ACTIONS.MASK].includes(message.action)) throw operationError("INVALID_SECURITY_ACTION", "지원하지 않는 Security Event action입니다.");
      const event = { type: "SECURITY_EVENT", eventId: `DEV-${crypto.randomUUID()}`, clientId: model.identity.clientId, action: message.action, targetLlm: "Development Test", detector: "DEVELOPMENT", matchType: "TEST", severity: "LOW", timestamp: new Date().toISOString() };
      const result = await processSecurityEvent(event);
      return { ok: true, eventId: event.eventId, stored: result.stored };
    }
    if (message?.type === "CLEAR_SECURITY_EVENTS") { await clearSecurityEvents(); return { ok: true }; }
    if (message?.type === "CLEAR_EVENTS") { await clearEvents(); return { ok: true }; }
    return { ok: false, errorCode: "UNKNOWN_MESSAGE", errorMessage: "지원하지 않는 요청입니다." };
  };
}
