import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defaultSettings } from "../extension/config/defaults.js";
import { ACCESS_STATES, EVENT_CHANNEL_STATES, GATEWAY_PROFILES, GATEWAY_STATES, SECURITY_ACTIONS } from "../extension/config/statuses.js";
import { createEventChannelService, reconnectDelay } from "../extension/event-channel/event-channel-service.js";
import { normalizeStoredSecurityEvents, storeSecurityEvent } from "../extension/event-channel/event-store.js";
import { accessNotificationOptions, notificationOptions, notifyAccessChange, notifySecurityEvent } from "../extension/event-channel/notification-service.js";
import { normalizeSecurityEvent, parseEventChannelMessage } from "../extension/event-channel/event-validator.js";
import { EXTENSION_VERSION, SUPPORTED_LLM_DOMAINS, SUPPORTED_LLM_SERVICES } from "../extension/routing/protected-domains.js";
import { ensureAccessStatusAlarm, ensureHealthAlarm } from "../extension/services/alarm-service.js";
import { ACCESS_REASON_LABELS, accessNotificationText, accessView, defaultAccessState, formatKst, normalizeAccessState, parseAccessStatusResponse, reduceAccessState, resetAccessState } from "../extension/services/access-state.js";
import { createAccessStatusService, resolveAccessContext } from "../extension/services/access-status-service.js";
import { badgeFor } from "../extension/services/badge.js";
import { createCommandHandler } from "../extension/services/command-service.js";
import { accessStatusCheck, gatewayStateForLatency, healthCheck, statsCheck } from "../extension/services/gateway-service.js";
import { buildIdentityRule, removeIdentityRuleVerified } from "../extension/services/identity-service.js";
import { applyManagedSettings, isManagedField, preserveManagedLocalSettings, validateManagedPolicy } from "../extension/services/policy-service.js";
import { applyWithRollback, createBootstrapOnce, createSerialExecutor, enforceIdentityFailSafe } from "../extension/services/protection-transaction.js";
import { buildPacScript, canSetProxy, clearProtectionPac } from "../extension/services/proxy-service.js";
import { initializeStorage, normalizeBackupReport, normalizeSettings, persistImportedBackup, randomViewerKey, readModel, writeAccessState } from "../extension/services/storage-service.js";
import { isValidDashboardBaseUrl, isValidEventChannelUrl, isValidGatewayHost, isValidIdentity, isValidPort, isValidViewerKey } from "../extension/utils/validation.js";
import * as defaultsModule from "../extension/config/defaults.js";

const flush = async () => { await new Promise((resolve) => setImmediate(resolve)); await new Promise((resolve) => setImmediate(resolve)); };
const base = { gateway: { host: "gateway.example.internal", port: 8080, profile: GATEWAY_PROFILES.CUSTOM }, identity: { enabled: false, tenantId: "oide" }, eventChannel: { enabled: false, url: "" }, developmentMode: true };

const manifest = JSON.parse(await readFile(new URL("../extension/manifest.json", import.meta.url), "utf8"));
const keyDigest = createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest();
const idAlphabet = "abcdefghijklmnop";
const stableId = [...keyDigest.subarray(0, 16)].map((byte) => idAlphabet[byte >> 4] + idAlphabet[byte & 15]).join("");
assert.equal(stableId, "mdeejegfkckeeolcgbkkblnccealmgan");
assert.equal(manifest.version, "1.4.8");
assert.equal(EXTENSION_VERSION, manifest.version);   // 식별 헤더·REGISTER에 실리는 버전도 같게
assert.equal(manifest.minimum_chrome_version, "116");
assert.deepEqual(manifest.permissions, ["proxy", "storage", "alarms", "declarativeNetRequestWithHostAccess", "notifications"]);
assert.equal(manifest.host_permissions.some((permission) => permission === "<all_urls>" || permission === "http://*/*" || permission === "https://*/*"), false);
for (const iconPath of Object.values(manifest.icons)) { const icon = await readFile(new URL(`../extension/${iconPath}`, import.meta.url)); assert.deepEqual([...icon.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]); }

for (const value of ["3.38.149.176", "gateway.example.com", "a-b.internal"]) assert.equal(isValidGatewayHost(value), true, value);
for (const value of ["", "999.1.1.1", "http://gateway", "gateway:8080", 'x"; return "DIRECT";', "a..b", "${host}"]) assert.equal(isValidGatewayHost(value), false, value);
for (const value of [1, 8080, 65535, "443"]) assert.equal(isValidPort(value), true);
for (const value of [0, -1, 65536, "80;DIRECT", "", 1.1]) assert.equal(isValidPort(value), false);
assert.equal(isValidIdentity("chrome-a83d104"), true); assert.equal(isValidIdentity("bad\r\nHeader: injected"), false);
assert.equal(isValidEventChannelUrl("wss://events.example.internal/client", { developmentMode: false }), true);
assert.equal(isValidEventChannelUrl("ws://localhost:9090", { developmentMode: true }), true);
assert.equal(isValidEventChannelUrl("ws://localhost:9090", { developmentMode: false }), false);
assert.equal(isValidEventChannelUrl("wss://events.example.internal/client?token=secret", { developmentMode: false }), false);
assert.equal(isValidDashboardBaseUrl("https://dashboard.example.internal/", { developmentMode: false }), true);

// A single fixed routing configuration sends every supported LLM domain to Gateway and all other hosts DIRECT.
assert.deepEqual(Object.keys(SUPPORTED_LLM_SERVICES), ["chatgpt", "gemini", "claude"]);
const pac = buildPacScript(base);
for (const domain of SUPPORTED_LLM_DOMAINS) assert.ok(pac.includes(domain), domain);
assert.match(pac, /return "PROXY gateway\.example\.internal:8080"/);
assert.match(pac, /return "DIRECT"/);
assert.ok(pac.indexOf('return "PROXY') < pac.lastIndexOf('return "DIRECT"')); // matched hosts return before the only DIRECT branch
assert.throws(() => buildPacScript({ ...base, gateway: { host: 'x"; return "DIRECT";', port: 8080 } }), /invalid/);
assert.equal(canSetProxy("controllable_by_this_extension"), true); assert.equal(canSetProxy("controlled_by_this_extension"), true); assert.equal(canSetProxy("controlled_by_other_extensions"), false);

const identity = { clientId: "chrome-a83d104" };
const identityRule = buildIdentityRule({ ...base, identity: { enabled: true, tenantId: "oide" } }, identity);
assert.deepEqual(identityRule.condition.requestDomains, [...SUPPORTED_LLM_DOMAINS]);
assert.equal(buildIdentityRule(base, identity), null);

// 내 요청 기록(2026-10-09): 열람 키는 식별 헤더와 함께만, 형식이 맞을 때만 붙는다
const viewerKey = randomViewerKey();
assert.equal(isValidViewerKey(viewerKey), true); assert.equal(viewerKey.length, 43); assert.notEqual(randomViewerKey(), viewerKey);
for (const bad of ["", "short", `${viewerKey}x`, viewerKey.slice(0, 42) + "+", null]) assert.equal(isValidViewerKey(bad), false, String(bad));
const keyedRule = buildIdentityRule({ ...base, identity: { enabled: true, tenantId: "oide" } }, { ...identity, viewerKey });
assert.deepEqual(keyedRule.action.requestHeaders.find((h) => h.header === "X-LLMSGW-Viewer-Key"), { header: "X-LLMSGW-Viewer-Key", operation: "set", value: viewerKey });
assert.equal(identityRule.action.requestHeaders.some((h) => h.header === "X-LLMSGW-Viewer-Key"), false);
assert.equal(buildIdentityRule({ ...base, identity: { enabled: true, tenantId: "oide" } }, { ...identity, viewerKey: "bad key" }).action.requestHeaders.some((h) => h.header === "X-LLMSGW-Viewer-Key"), false);
assert.equal(buildIdentityRule(base, { ...identity, viewerKey }), null);
// 1.4.3: 내 요청 기록은 확장 프로그램 안의 페이지 - 외부 웹페이지(대시보드 포함)가 열람 키를 물을 길을 없앤다
assert.equal("externally_connectable" in manifest, false);
assert.equal("DEFAULT_DASHBOARD_URL" in defaultsModule, false); assert.equal("VIEWER_PAGE_ORIGINS" in defaultsModule, false);
assert.ok(manifest.host_permissions.includes("http://llm-gateway.local/*"));   // 페이지 fetch가 CORS 사전 확인 없이 Gateway 응답을 읽는 근거
assert.equal("web_accessible_resources" in manifest, false); assert.equal("content_security_policy" in manifest, false);   // 웹페이지가 기록 페이지를 띄울 수 없고, MV3 기본 CSP 그대로
assert.deepEqual(defaultSettings().dashboard, { baseUrl: "" });   // 저장 형식 호환을 위해 설정 칸은 남긴다

// OFF never clears another owner; it only clears an extension-owned PAC.
let clearCalls = 0;
globalThis.chrome = { proxy: { settings: { get: async () => ({ levelOfControl: "controlled_by_other_extensions", value: { mode: "fixed_servers" } }), clear: async () => { clearCalls += 1; } } } };
await clearProtectionPac(); assert.equal(clearCalls, 0);
globalThis.chrome.proxy.settings.get = async () => ({ levelOfControl: clearCalls ? "controllable_by_this_extension" : "controlled_by_this_extension", value: { mode: clearCalls ? "system" : "pac_script" } });
await clearProtectionPac(); assert.equal(clearCalls, 1);
delete globalThis.chrome;

const normalizedLegacy = normalizeSettings({ ...base, schemaVersion: 4, routingMode: "NETWORK_MANAGED", services: { chatgpt: false, gemini: false, claude: false } });
assert.equal(normalizedLegacy.schemaVersion, 5); assert.equal("services" in normalizedLegacy, false); assert.equal("routingMode" in normalizedLegacy, false);
assert.equal(normalizeSettings({ ...base, gateway: { ...base.gateway, profile: GATEWAY_PROFILES.M1_TEST } }).gateway.port, 8081);
assert.equal(normalizeSettings({ ...base, gateway: { ...base.gateway, profile: GATEWAY_PROFILES.M2_TEST } }).gateway.port, 8080);
assert.equal(defaultSettings().eventChannel.enabled, false);

const ownershipOrder = [];
assert.equal(await enforceIdentityFailSafe({ desiredProtection: true, proxyState: { levelOfControl: "controlled_by_other_extensions", mode: "pac_script" }, removeIdentity: async () => ownershipOrder.push("identity-removed"), markConflict: async () => ownershipOrder.push("conflict") }), true);
assert.deepEqual(ownershipOrder, ["identity-removed", "conflict"]);
let dynamicRules = [{ id: 20001 }];
globalThis.chrome = { declarativeNetRequest: { updateDynamicRules: async ({ removeRuleIds }) => { dynamicRules = dynamicRules.filter((rule) => !removeRuleIds.includes(rule.id)); }, getDynamicRules: async () => structuredClone(dynamicRules) } };
await removeIdentityRuleVerified(); assert.equal(dynamicRules.length, 0); delete globalThis.chrome;

const transactionState = { pac: "old-pac", rule: "old-rule", runtime: "HEALTHY" };
await assert.rejects(() => applyWithRollback({ capture: async () => ({ ...transactionState }), applyNext: async () => { transactionState.pac = "new-pac"; throw new Error("apply failed"); }, commit: async () => assert.fail(), rollback: async (previous) => Object.assign(transactionState, previous) }), /apply failed/);
assert.deepEqual(transactionState, { pac: "old-pac", rule: "old-rule", runtime: "HEALTHY" });
let bootstrapCount = 0; const bootstrapOnce = createBootstrapOnce(async () => { bootstrapCount += 1; }); await Promise.all([bootstrapOnce(), bootstrapOnce(), bootstrapOnce()]); assert.equal(bootstrapCount, 1);
const serialOrder = []; const serial = createSerialExecutor(); await Promise.all([serial(async () => { serialOrder.push("ON-start"); await Promise.resolve(); serialOrder.push("ON-end"); }), serial(async () => serialOrder.push("OFF"))]); assert.deepEqual(serialOrder, ["ON-start", "ON-end", "OFF"]);
let alarmCreates = 0; assert.equal(await ensureHealthAlarm({ get: async () => null, create: async () => { alarmCreates += 1; } }), true); assert.equal(alarmCreates, 1);

const managed = validateManagedPolicy({ gatewayHost: "managed.example.com", gatewayPort: 8443, eventChannelEnabled: true, eventChannelUrl: "wss://events.managed.example/client", protectionEnabled: true, developmentMode: false });
assert.equal(managed.mode, "managed"); assert.equal(isManagedField(managed, "runtime.desiredProtection"), true); assert.equal(managed.lockedFields.some((field) => field.startsWith("services.")), false);
const managedSettings = applyManagedSettings(normalizeSettings(base), managed); assert.equal(managedSettings.gateway.host, "managed.example.com"); assert.equal(managedSettings.eventChannel.enabled, true);
const preserved = preserveManagedLocalSettings(normalizeSettings({ ...base, gateway: { host: "user.example", port: 9999, profile: GATEWAY_PROFILES.CUSTOM } }), normalizeSettings(base), managed); assert.equal(preserved.gateway.host, base.gateway.host);

function storageApi(seed) {
  const data = structuredClone(seed);
  return { data, api: { get: async (keys) => keys === null ? structuredClone(data) : Object.fromEntries(keys.filter((key) => key in data).map((key) => [key, structuredClone(data[key])])), set: async (patch) => Object.assign(data, structuredClone(patch)), remove: async (keys) => keys.forEach((key) => delete data[key]) } };
}
const migratedStorage = storageApi({ settings: { ...base, schemaVersion: 4, services: { chatgpt: false, gemini: true, claude: false } }, identity: { clientId: "chrome-existing-client" }, runtimeState: { desiredProtection: true }, recentSecurityEvents: [{ eventId: "OLD-1", action: "BLOCK", service: "ChatGPT", category: "PII", timestamp: "2026-09-08T00:00:00Z" }], events: [] });
globalThis.chrome = { storage: { local: migratedStorage.api } }; await initializeStorage();
assert.equal(migratedStorage.data.identity.clientId, "chrome-existing-client"); assert.equal(migratedStorage.data.settings.schemaVersion, 5); assert.equal("services" in migratedStorage.data.settings, false); assert.equal(migratedStorage.data.runtimeState.desiredProtection, true); assert.equal(migratedStorage.data.recentSecurityEvents[0].targetLlm, "ChatGPT");
const freshStorage = storageApi({}); globalThis.chrome = { storage: { local: freshStorage.api } }; await initializeStorage(); assert.match(freshStorage.data.identity.clientId, /^chrome-[0-9a-f-]{36}$/i); assert.equal(isValidViewerKey(freshStorage.data.identity.viewerKey), true); delete globalThis.chrome;
assert.equal(isValidViewerKey(migratedStorage.data.identity.viewerKey), true);   // 예전 저장본에도 키가 생긴다
const keptStorage = storageApi({ settings: normalizeSettings(base), identity: { clientId: "chrome-kept", viewerKey }, runtimeState: {}, events: [], recentSecurityEvents: [] });
globalThis.chrome = { storage: { local: keptStorage.api } }; await initializeStorage(); assert.equal(keptStorage.data.identity.viewerKey, viewerKey);
await persistImportedBackup(normalizeBackupReport({ backup: { settings: base, identity: { clientId: "chrome-from-backup" }, desiredProtection: false } }));
assert.equal(keptStorage.data.identity.clientId, "chrome-from-backup"); assert.equal(keptStorage.data.identity.viewerKey, viewerKey);   // 백업을 가져와도 이 브라우저의 키는 그대로
delete globalThis.chrome;

const clientId = "chrome-event-client";
const rawPrivateEvent = { type: "SECURITY_EVENT", eventId: "EVT-PRIVATE", clientId, timestamp: "2026-09-08T00:00:00Z", targetLlm: "ChatGPT", action: "BLOCK", severity: "HIGH", detector: "WINDOW_HASH", matchType: "TEXT_FRAGMENT", prompt: "SECRET_PROMPT", credential: "SECRET_KEY", detectedValue: "SECRET_VALUE" };
const parsedPrivate = parseEventChannelMessage(JSON.stringify(rawPrivateEvent), { expectedClientId: clientId });
assert.equal(parsedPrivate.kind, "SECURITY_EVENT");
assert.deepEqual(Object.keys(parsedPrivate.event), ["eventId", "timestamp", "targetLlm", "action", "detector", "matchType", "severity", "reasonCode", "contentType", "degraded", "notify"]); assert.ok(!JSON.stringify(parsedPrivate).includes("SECRET"));
assert.deepEqual([parsedPrivate.event.reasonCode, parsedPrivate.event.contentType, parsedPrivate.event.degraded, parsedPrivate.event.notify], [null, null, false, false]);   // 사유 없는 옛 이벤트
assert.equal(parseEventChannelMessage(JSON.stringify({ ...rawPrivateEvent, clientId: "other-client" }), { expectedClientId: clientId }), null);
assert.equal(parseEventChannelMessage(JSON.stringify({ ...rawPrivateEvent, action: "ALLOW" }), { expectedClientId: clientId }).kind, "IGNORED_ACTION");
assert.equal(parseEventChannelMessage('{"type":"HEARTBEAT"}', { expectedClientId: clientId }).kind, "HEARTBEAT"); assert.equal(parseEventChannelMessage("{bad", { expectedClientId: clientId }), null);

const securityStorage = storageApi({ recentSecurityEvents: [] });
assert.equal((await storeSecurityEvent(parsedPrivate.event, securityStorage.api)).stored, true); assert.equal((await storeSecurityEvent(parsedPrivate.event, securityStorage.api)).reason, "DUPLICATE");
for (let index = 0; index < 25; index += 1) await storeSecurityEvent(normalizeSecurityEvent({ eventId: `EVT-${index}`, action: index % 2 ? "BLOCK" : "MASK", targetLlm: "Gateway supplied", detector: "TEST", matchType: "TEST", severity: "LOW", timestamp: new Date(index * 1000).toISOString() }), securityStorage.api);
assert.equal(securityStorage.data.recentSecurityEvents.length, 20); assert.equal(new Set(securityStorage.data.recentSecurityEvents.map((event) => event.eventId)).size, 20); assert.equal(normalizeStoredSecurityEvents([parsedPrivate.event, parsedPrivate.event]).length, 1);
const notificationCalls = [];
assert.equal(await notifySecurityEvent(parsedPrivate.event, { create: (id, options, callback) => { notificationCalls.push({ id, options }); callback(); } }, {}), true); assert.equal(notificationCalls.length, 1); assert.match(notificationCalls[0].options.title, /차단/); assert.match(notificationCalls[0].options.message, /ChatGPT/); assert.ok(!JSON.stringify(notificationCalls).includes("SECRET")); assert.equal(notificationOptions({ ...parsedPrivate.event, action: "ALLOW" }), null);

// 1.4.2: 사유별 알림 문구·새 칸(reasonCode·contentType·degraded·notify). Gateway 이벤트에는 원문 칸을 일부러 섞는다
const gatewayEvent = (extra, eventId = `EVT-${Object.values(extra).join("-")}`) => ({ ...rawPrivateEvent, eventId, severity: undefined, detector: "Gateway", matchType: "POLICY", actionLabel: "차단", severityRecorded: false, reviewUrl: "http://dashboard.example.internal/review/REQ-1", inspectionMessage: "SECRET_GUIDE", userMessage: "SECRET_USER_MESSAGE", ...extra });
const parseGateway = (extra) => parseEventChannelMessage(JSON.stringify(gatewayEvent(extra)), { expectedClientId: clientId });
const UNREADABLE_BLOCK = "검사할 수 없는 파일 차단"; const DOWN_BLOCK = ["보안 검사 응답 없음", "보안 검사가 제때 끝나지 않아 ChatGPT 전송을 막았습니다. 잠시 후 다시 시도해 주세요."];
const LEGACY_BLOCK = ["요청 차단됨", "보안 정책에 따라 ChatGPT 전송을 막았습니다. 민감한 내용을 빼고 다시 보내 주세요."]; const LEGACY_MASK = ["민감정보 마스킹", "ChatGPT에 보낸 내용 중 민감정보를 마스킹하고 전송했습니다."];
const MASK_FAILED = ["마스킹할 수 없어 차단", "ChatGPT 요청에서 민감정보가 발견되었지만 마스킹할 수 없는 형식이라 전송을 막았습니다."];
const SENT_FILE = ["검사 없이 전송됨", "ChatGPT에 올린 파일은 내용을 검사하지 못한 채 전송되었습니다. 관리자 기록에 남습니다."]; const SENT_DELAYED = ["검사 없이 전송됨", "보안 검사가 지연되어 ChatGPT 요청이 검사 없이 전송되었습니다. 관리자 기록에 남습니다."];
const reasonCases = [
  [{ action: "BLOCK", reasonCode: "file_uninspectable_image", contentType: "file" }, [UNREADABLE_BLOCK, "ChatGPT에 올리려던 이미지 파일은 내용을 검사할 수 없어 전송이 차단되었습니다."]],
  [{ action: "BLOCK", reasonCode: "file_uninspectable_scanned_pdf", contentType: "file" }, [UNREADABLE_BLOCK, "ChatGPT에 올리려던 스캔 PDF는 글자를 읽을 수 없어 전송이 차단되었습니다."]],
  [{ action: "BLOCK", reasonCode: "file_uninspectable_other", contentType: "file" }, [UNREADABLE_BLOCK, "ChatGPT에 올리려던 파일은 검사할 수 없는 형식이라 전송이 차단되었습니다."]],
  [{ action: "BLOCK", reasonCode: "file_too_large", contentType: "file" }, ["파일이 커서 차단", "ChatGPT에 올리려던 파일이 커서 제한 시간 안에 검사할 수 없어 전송이 차단되었습니다."]],
  [{ action: "BLOCK", reasonCode: "mask_application_failed", contentType: "prompt" }, MASK_FAILED],
  [{ action: "BLOCK", reasonCode: "file_masking_failed", contentType: "file", degraded: true }, MASK_FAILED],
  ...["detection_timeout", "detection_unreachable", "detection_error", "detection_parse_error"].map((reasonCode) => [{ action: "BLOCK", reasonCode, contentType: "file", degraded: true, failurePolicy: "FAIL_CLOSED" }, DOWN_BLOCK]),
  [{ action: "BLOCK", reasonCode: "detection_timeout" }, DOWN_BLOCK],
  [{ action: "BLOCK", degraded: true, degradedReason: "TIMEOUT" }, DOWN_BLOCK],   // 사유 코드를 아직 싣지 않는 Gateway
  [{ action: "BLOCK", reasonCode: "doc_excerpt", contentType: "prompt" }, LEGACY_BLOCK],
  [{ action: "BLOCK", reasonCode: "some_future_reason" }, LEGACY_BLOCK],
  [{ action: "BLOCK" }, LEGACY_BLOCK],
  [{ action: "MASK", reasonCode: "pii", contentType: "prompt" }, LEGACY_MASK],
  [{ action: "MASK", reasonCode: "detection_timeout", contentType: "file", degraded: true }, LEGACY_MASK],   // 칸 일부 마스킹 후 무응답
  ...["file_uninspectable_image", "file_uninspectable_scanned_pdf", "file_uninspectable_other", "file_too_large"].map((reasonCode) => [{ action: "ALLOW", reasonCode, contentType: "file", notify: true }, SENT_FILE]),
  ...["detection_timeout", "detection_unreachable", "detection_error", "detection_parse_error"].map((reasonCode) => [{ action: "ALLOW", reasonCode, contentType: "prompt", degraded: true, failurePolicy: "FAIL_OPEN", notify: true }, SENT_DELAYED]),
  [{ action: "ALLOW", reasonCode: "pii", notify: true }, null],
  [{ action: "ALLOW", degraded: true, notify: true }, null]
];
for (const [extra, expected] of reasonCases) {
  const parsed = parseGateway(extra);
  assert.equal(parsed?.kind, "SECURITY_EVENT", JSON.stringify(extra));
  const options = notificationOptions(parsed.event);
  if (expected === null) { assert.equal(options, null, JSON.stringify(extra)); continue; }
  assert.deepEqual([options.title, options.message], [expected[0], expected[1]], JSON.stringify(extra));   // 1.4.6: 알림에는 긴 Event ID 줄을 붙이지 않는다(번호는 팝업의 복사 버튼으로)
  assert.ok(!options.message.includes("Event ID") && !options.message.includes(parsed.event.eventId), JSON.stringify(extra));
  assert.ok(!JSON.stringify([parsed, options]).includes("SECRET"), JSON.stringify(extra));
  assert.equal(parsed.event.reasonCode, extra.reasonCode ?? null); assert.equal(parsed.event.contentType, extra.contentType ?? null); assert.equal(parsed.event.degraded, extra.degraded === true); assert.equal(parsed.event.notify, extra.notify === true);
}
// notify가 정확히 true인 ALLOW만 받는다(BLOCK·MASK는 notify와 무관)
for (const notify of [undefined, false, "true", 1, null]) assert.equal(parseGateway({ action: "ALLOW", reasonCode: "file_too_large", notify }).kind, "IGNORED_ACTION", String(notify));
assert.equal(normalizeSecurityEvent(gatewayEvent({ action: "ALLOW", reasonCode: "file_too_large" })), null); assert.equal(normalizeSecurityEvent(gatewayEvent({ action: "ALLOW", reasonCode: "file_too_large", notify: "true" })), null);
assert.equal(parseGateway({ action: "BLOCK", notify: false }).event.action, "BLOCK"); assert.equal(parseGateway({ action: "MASK" }).event.notify, false);
for (const notify of ["true", 1, {}, [true]]) assert.equal(parseGateway({ action: "BLOCK", notify }).event.notify, false, JSON.stringify(notify));
assert.equal(parseEventChannelMessage(JSON.stringify(gatewayEvent({ action: "ALLOW", reasonCode: "file_too_large", notify: true, clientId: "other-client" })), { expectedClientId: clientId }), null);
// 형식이 틀린 칸은 그 칸만 버린다(이벤트는 남고 기존 문구)
for (const reasonCode of ["File_too_large", "file too large", "file_too_large\n", " file_too_large", "1file", "_file", "", "a".repeat(101), "file-too-large", "파일", 42, true, null, ["file_too_large"], { code: "file_too_large" }]) {
  const parsed = parseGateway({ action: "BLOCK", reasonCode });
  assert.equal(parsed.kind, "SECURITY_EVENT"); assert.equal(parsed.event.reasonCode, null, JSON.stringify(reasonCode)); assert.equal(notificationOptions(parsed.event).title, LEGACY_BLOCK[0]);
}
assert.equal(parseGateway({ action: "BLOCK", reasonCode: `a${"b".repeat(99)}` }).event.reasonCode.length, 100);
assert.equal(parseGateway({ action: "ALLOW", reasonCode: "FILE_TOO_LARGE", notify: true }).event.reasonCode, null);   // 받되 알림 없음
for (const contentType of ["image", "PROMPT", " file", "", 1, null, ["file"]]) assert.equal(parseGateway({ action: "BLOCK", reasonCode: "file_too_large", contentType }).event.contentType, null, JSON.stringify(contentType));
for (const degraded of ["true", 1, null, {}]) { const parsed = parseGateway({ action: "BLOCK", degraded }); assert.equal(parsed.event.degraded, false); assert.equal(notificationOptions(parsed.event).title, LEGACY_BLOCK[0]); }
// 저장본을 다시 읽어도 새 칸이 남는다(chrome.storage는 JSON으로 보관). 1.4.1 저장본(새 칸 없음)은 기본값
const reasonStorage = storageApi({ recentSecurityEvents: [{ eventId: "OLD-141", timestamp: "2026-10-09T00:00:00.000Z", targetLlm: "Claude", action: "MASK", detector: "Gateway", matchType: "POLICY", severity: "UNKNOWN" }] });
const allowNotified = parseGateway({ action: "ALLOW", reasonCode: "file_uninspectable_image", contentType: "file", notify: true }).event;
const blockTooLarge = parseGateway({ action: "BLOCK", reasonCode: "file_too_large", contentType: "file" }).event;
for (const event of [allowNotified, blockTooLarge]) assert.equal((await storeSecurityEvent(event, reasonStorage.api)).stored, true);
const reread = normalizeStoredSecurityEvents(JSON.parse(JSON.stringify(reasonStorage.data.recentSecurityEvents)));
assert.deepEqual(reread.map((event) => event.eventId), [blockTooLarge.eventId, allowNotified.eventId, "OLD-141"]);
assert.deepEqual(reread[0], blockTooLarge); assert.deepEqual(reread[1], allowNotified); assert.deepEqual([reread[2].reasonCode, reread[2].contentType, reread[2].degraded, reread[2].notify], [null, null, false, false]);
assert.deepEqual(reread.map((event) => notificationOptions(event).title), ["파일이 커서 차단", "검사 없이 전송됨", "민감정보 마스킹"]);
assert.equal(normalizeStoredSecurityEvents([{ ...allowNotified, notify: false }]).length, 0);   // 알림 표시가 없는 ALLOW 저장본은 버린다
assert.equal(notificationOptions({ ...allowNotified, notify: false }), null); assert.equal(notificationOptions({ ...allowNotified, notify: "true" }), null);
assert.ok(!JSON.stringify(reasonStorage.data).includes("SECRET"));
// 실제 알림 호출: ALLOW는 문구가 있을 때만 만든다
const reasonNotifications = [];
const fakeNotifications = { create: (id, options, callback) => { reasonNotifications.push({ id, options }); callback(); } };
assert.equal(await notifySecurityEvent(allowNotified, fakeNotifications, {}), true); assert.equal(reasonNotifications.at(-1).id, `llmsgw-${allowNotified.eventId}`); assert.equal(reasonNotifications.at(-1).options.title, "검사 없이 전송됨");
assert.equal(await notifySecurityEvent(parseGateway({ action: "ALLOW", reasonCode: "pii", notify: true }).event, fakeNotifications, {}), false); assert.equal(reasonNotifications.length, 1);

class MockWebSocket {
  static instances = [];
  constructor(url) { this.url = url; this.readyState = 0; this.listeners = new Map(); this.sent = []; MockWebSocket.instances.push(this); }
  addEventListener(type, listener) { const list = this.listeners.get(type) || []; list.push(listener); this.listeners.set(type, list); }
  send(data) { if (this.readyState !== 1) throw new Error("not open"); this.sent.push(data); }
  emit(type, data = {}) { if (type === "open") this.readyState = 1; if (type === "close") this.readyState = 3; for (const listener of this.listeners.get(type) || []) listener(type === "message" ? { data } : data); }
  close() { if (this.readyState !== 3) this.emit("close"); }
}
const channelStore = storageApi({ recentSecurityEvents: [] });
const channelRuntime = { eventChannelStatus: EVENT_CHANNEL_STATES.DISABLED };
const channelNotifications = []; const timers = []; const alarmCalls = [];
let channelSettings = { ...normalizeSettings({ ...base, eventChannel: { enabled: true, url: "ws://localhost:9090" } }), protectionEnabled: true, clientId };
const channel = createEventChannelService({ readSettings: async () => channelSettings, updateRuntime: async (patch) => Object.assign(channelRuntime, patch), storeEvent: (event) => storeSecurityEvent(event, channelStore.api), notifyEvent: async (event) => { channelNotifications.push(event.eventId); return true; }, WebSocketImpl: MockWebSocket, alarms: { create: (name, info) => alarmCalls.push({ name, info }), clear: async () => true }, setTimer: (callback, delay) => { const timer = { delay, active: true, callback: () => { timer.active = false; callback(); } }; timers.push(timer); return timer; }, clearTimer: (timer) => { timer.active = false; }, now: () => 1000, random: () => 0.5, logger: { warn: () => undefined } });
assert.deepEqual([0, 1, 2, 3, 4, 8].map((attempt) => reconnectDelay(attempt, () => 0.5)), [1000, 2000, 5000, 10000, 30000, 30000]);
assert.deepEqual([reconnectDelay(0, () => 0), reconnectDelay(0, () => 1)], [900, 1100]);
await channel.sync(); assert.equal(MockWebSocket.instances.length, 1); MockWebSocket.instances[0].emit("open"); await flush();
assert.deepEqual(JSON.parse(MockWebSocket.instances[0].sent[0]), { type: "REGISTER", clientId }); assert.equal(channelRuntime.eventChannelStatus, EVENT_CHANNEL_STATES.CONNECTED); assert.equal(MockWebSocket.instances[0].sent.length, 1); // no uncontracted client PING
MockWebSocket.instances[0].emit("message", '{"type":"HEARTBEAT"}'); MockWebSocket.instances[0].emit("message", "{bad json"); MockWebSocket.instances[0].emit("message", JSON.stringify({ ...rawPrivateEvent, action: "ALLOW", eventId: "EVT-ALLOW" }));
const blockJson = JSON.stringify({ ...rawPrivateEvent, eventId: "EVT-CHANNEL" }); MockWebSocket.instances[0].emit("message", blockJson); MockWebSocket.instances[0].emit("message", blockJson); await flush();
assert.equal(channelNotifications.length, 1); assert.equal(channelStore.data.recentSecurityEvents.some((event) => event.eventId === "EVT-ALLOW"), false); assert.ok(!JSON.stringify(channelStore.data).includes("SECRET")); assert.equal(MockWebSocket.instances[0].readyState, 1);
MockWebSocket.instances[0].emit("message", JSON.stringify({ ...rawPrivateEvent, action: "ALLOW", eventId: "EVT-ALLOW-NOTIFY", reasonCode: "file_too_large", contentType: "file", notify: true })); await flush();
assert.deepEqual(channelNotifications, ["EVT-CHANNEL", "EVT-ALLOW-NOTIFY"]); assert.deepEqual([channelStore.data.recentSecurityEvents[0].eventId, channelStore.data.recentSecurityEvents[0].notify, channelStore.data.recentSecurityEvents[0].reasonCode], ["EVT-ALLOW-NOTIFY", true, "file_too_large"]); assert.ok(!JSON.stringify(channelStore.data).includes("SECRET"));
MockWebSocket.instances[0].emit("close"); await flush(); assert.equal(channelRuntime.eventChannelStatus, EVENT_CHANNEL_STATES.RECONNECTING); assert.equal(timers.at(-1).delay, 1000); assert.ok(alarmCalls.length > 0);
timers.at(-1).callback(); await flush(); assert.equal(MockWebSocket.instances.length, 2); MockWebSocket.instances[1].emit("open"); await flush(); assert.equal(channelRuntime.eventReconnectAttempt, 0); assert.deepEqual(JSON.parse(MockWebSocket.instances[1].sent[0]), { type: "REGISTER", clientId });
const liveBeforeOff = MockWebSocket.instances[1]; const notificationsBeforeOff = channelNotifications.length; channelSettings = { ...channelSettings, protectionEnabled: false }; await channel.sync(); assert.equal(channelRuntime.eventChannelStatus, EVENT_CHANNEL_STATES.DISABLED); assert.equal(liveBeforeOff.readyState, 3); assert.equal(timers.every((timer) => !timer.active), true); liveBeforeOff.emit("message", JSON.stringify({ ...rawPrivateEvent, eventId: "EVT-AFTER-OFF" })); await flush(); assert.equal(channelNotifications.length, notificationsBeforeOff); const instanceCountOff = MockWebSocket.instances.length; await flush(); assert.equal(MockWebSocket.instances.length, instanceCountOff);
channelSettings = { ...channelSettings, protectionEnabled: true }; const restartChannel = createEventChannelService({ readSettings: async () => channelSettings, updateRuntime: async () => undefined, storeEvent: (event) => storeSecurityEvent(event, channelStore.api), notifyEvent: async () => true, WebSocketImpl: MockWebSocket, alarms: { create: () => undefined, clear: async () => true }, logger: { warn: () => undefined } }); await restartChannel.sync(); assert.equal(MockWebSocket.instances.length, instanceCountOff + 1); await restartChannel.stop();

// Command surface has Master only; legacy service commands are no longer supported.
const commandStorage = storageApi({ settings: normalizeSettings(base), identity: { clientId: "chrome-command-client" }, runtimeState: { desiredProtection: false, gatewayState: "DISABLED" }, events: [], recentSecurityEvents: [] });
let managedSeed = {}; globalThis.chrome = { storage: { local: commandStorage.api, managed: { get: async () => structuredClone(managedSeed) } }, proxy: { settings: { get: async () => ({ levelOfControl: "controlled_by_this_extension", value: { mode: "pac_script", pacScript: { data: buildPacScript(commandStorage.data.settings) } } }) } } };
let applyCalls = 0; let disableCalls = 0; const simulated = [];
const handleCommand = createCommandHandler({ applyConfiguration: async () => { applyCalls += 1; return { ok: true }; }, disable: async () => { disableCalls += 1; return { ok: true }; }, health: async () => ({ ok: true }), stats: async () => ({ ok: true }), processSecurityEvent: async (event) => { simulated.push(event); return { stored: true }; }, clearSecurityEvents: async () => undefined });
assert.equal((await handleCommand({ type: "GET_MODEL" })).proxy.matchesSettings, true); assert.equal((await handleCommand({ type: "SET_SERVICE", serviceId: "gemini", enabled: false })).errorCode, "UNKNOWN_MESSAGE");
await handleCommand({ type: "SET_MASTER", enabled: true }); assert.equal(applyCalls, 1); await handleCommand({ type: "SET_MASTER", enabled: false }); assert.equal(disableCalls, 1);
managedSeed = { developmentMode: false, protectionEnabled: true }; await assert.rejects(() => handleCommand({ type: "SET_MASTER", enabled: false }), /관리자 정책/);
managedSeed = {}; commandStorage.data.settings = normalizeSettings({ ...base, developerToolsEnabled: true }); commandStorage.data.runtimeState.desiredProtection = true; const simulatedResult = await handleCommand({ type: "SIMULATE_SECURITY_EVENT", action: SECURITY_ACTIONS.MASK }); assert.equal(simulatedResult.stored, true); assert.equal(simulated[0].clientId, "chrome-command-client"); assert.equal(simulated[0].type, "SECURITY_EVENT"); delete globalThis.chrome;

// 1.4.3 내 요청 기록: 확장 프로그램 안 페이지(myrequests/)는 요청 직전마다 GET_MODEL만 보고 열람 키를 보낼지 정한다.
// 보내는 조건 = 보호 켜짐 + Gateway 주소 있음 + 이 확장 프로그램이 PAC 소유 + 현재 PAC 원문이 설정값으로 만든 PAC와 같음(llm-gateway.local → 설정된 Gateway)
const gateSettings = normalizeSettings({ ...base, gateway: { host: "52.78.173.46", port: 8081, profile: GATEWAY_PROFILES.M1_TEST }, identity: { enabled: true, tenantId: "oide" } });
const gateStorage = storageApi({ settings: gateSettings, identity: { clientId: "chrome-gate-client", viewerKey }, runtimeState: { desiredProtection: true, gatewayState: "HEALTHY" }, events: [], recentSecurityEvents: [] });
const ownedPac = (settings) => ({ levelOfControl: "controlled_by_this_extension", value: { mode: "pac_script", pacScript: { data: buildPacScript(settings) } } });
let gateProxy = ownedPac(gateSettings); let gateManaged = {};
globalThis.chrome = { storage: { local: gateStorage.api, managed: { get: async () => structuredClone(gateManaged) } }, proxy: { settings: { get: async () => structuredClone(gateProxy) } } };
const gateHandler = createCommandHandler({ applyConfiguration: async () => assert.fail(), disable: async () => assert.fail(), health: async () => assert.fail(), stats: async () => assert.fail(), processSecurityEvent: async () => assert.fail(), clearSecurityEvents: async () => assert.fail() });
const gateReply = await gateHandler({ type: "GET_MODEL" });
assert.equal(gateReply.ok, true); assert.equal(gateReply.model.runtimeState.desiredProtection, true); assert.equal(gateReply.model.settings.gateway.host, "52.78.173.46"); assert.equal(gateReply.model.settings.identity.enabled, true); assert.equal(gateReply.model.identity.viewerKey, viewerKey);
assert.deepEqual(gateReply.proxy, { levelOfControl: "controlled_by_this_extension", mode: "pac_script", matchesSettings: true });
assert.match(gateProxy.value.pacScript.data, /host == "llm-gateway\.local"\) return "PROXY 52\.78\.173\.46:8081";/);   // 일치하면 llm-gateway.local은 설정된 Gateway로만 간다(DIRECT 대체 없음)
const gateProxyFor = async (proxy) => { gateProxy = proxy; return (await gateHandler({ type: "GET_MODEL" })).proxy; };
const otherGateway = normalizeSettings({ ...gateSettings, gateway: { host: "203.0.113.9", port: 8081, profile: GATEWAY_PROFILES.M1_TEST } });
const divertedPac = ownedPac(gateSettings); divertedPac.value.pacScript.data = divertedPac.value.pacScript.data.replace(' || host == "llm-gateway.local"', "");
for (const [label, proxy] of [["다른 Gateway로 가는 PAC", ownedPac(otherGateway)], ["llm-gateway.local을 빼 DIRECT로 보내는 PAC", divertedPac], ["다른 확장 프로그램 소유", { ...ownedPac(gateSettings), levelOfControl: "controlled_by_other_extensions" }], ["정책 소유", { ...ownedPac(gateSettings), levelOfControl: "not_controllable" }], ["고정 프록시", { levelOfControl: "controlled_by_this_extension", value: { mode: "fixed_servers", rules: { singleProxy: { host: "52.78.173.46", port: 8081 } } } }], ["보호 해제(PAC 없음)", { levelOfControl: "controllable_by_this_extension", value: { mode: "system" } }], ["값 없음", { levelOfControl: "controllable_by_this_extension" }]]) assert.equal((await gateProxyFor(proxy)).matchesSettings, false, label);
gateProxy = ownedPac(gateSettings); gateStorage.data.runtimeState.desiredProtection = false; assert.equal((await gateHandler({ type: "GET_MODEL" })).model.runtimeState.desiredProtection, false); gateStorage.data.runtimeState.desiredProtection = true;
gateStorage.data.identity.viewerKey = "bad key"; assert.equal((await gateHandler({ type: "GET_MODEL" })).model.identity.viewerKey, ""); gateStorage.data.identity.viewerKey = viewerKey;   // 형식이 틀린 키는 넘기지 않는다
// 관리자 정책이 Gateway를 정하면 그 값(실제 적용값)으로 만든 PAC만 일치로 본다
gateManaged = { gatewayHost: "managed.example.com", gatewayPort: 8443 };
const managedGate = applyManagedSettings(gateSettings, validateManagedPolicy(gateManaged));
assert.equal((await gateProxyFor(ownedPac(managedGate))).matchesSettings, true); assert.equal((await gateHandler({ type: "GET_MODEL" })).model.settings.gateway.host, "managed.example.com");
assert.equal((await gateProxyFor(ownedPac(gateSettings))).matchesSettings, false);
delete globalThis.chrome;

const importedBackup = normalizeBackupReport({ backup: { settings: { ...base, services: { chatgpt: false, gemini: false, claude: false }, routingMode: "NETWORK_MANAGED" }, identity: { clientId: "chrome-existing-client" }, desiredProtection: true } });
assert.equal(importedBackup.identity.clientId, "chrome-existing-client"); assert.equal(importedBackup.desiredProtection, true); assert.equal("services" in importedBackup.settings, false); assert.equal("routingMode" in importedBackup.settings, false);

const originalFetch = globalThis.fetch;
globalThis.fetch = async () => new Response("Not Found", { status: 404 }); const unsupportedHealth = await healthCheck(); assert.equal(unsupportedHealth.state, GATEWAY_STATES.UNSUPPORTED);
globalThis.fetch = async () => new Response("<html>bad gateway</html>", { status: 502 }); assert.equal((await healthCheck()).errorCode, "MALFORMED_JSON"); assert.equal((await healthCheck({ gatewayProfile: GATEWAY_PROFILES.M1_TEST })).state, GATEWAY_STATES.UNSUPPORTED);
globalThis.fetch = async () => { const error = new Error("aborted"); error.name = "AbortError"; throw error; }; assert.equal((await healthCheck({ gatewayProfile: GATEWAY_PROFILES.M1_TEST })).state, GATEWAY_STATES.OFFLINE);
globalThis.fetch = async () => new Response(JSON.stringify({ status: "ok", version: "0.6.0" }), { status: 200 }); assert.equal((await healthCheck()).ok, true); assert.equal(gatewayStateForLatency(1000), GATEWAY_STATES.DEGRADED);
globalThis.fetch = async () => new Response(JSON.stringify({ version: "0.6.0", uptime_sec: 1, total_requests: 0, total_responses: 0, error_responses: 0, services: {} }), { status: 200 }); assert.equal((await statsCheck()).ok, true); globalThis.fetch = originalFetch;

// ===== 1.4.5 접속 제한 안내 (Gateway /__llmsgw/access-status) =====
// 응답 해석: 계약과 다르면 null(= '확인 불가'), 알려진 사유 코드는 확장 프로그램 안의 고정 문구만 쓴다
const accessBody = (extra = {}) => ({ blocked: true, reason_code: "client_blocked", reasons: [{ code: "INVESTIGATION", label: "보안 조사 중" }, { code: "ADMIN_REQUEST", label: "관리자 요청" }], user_memo: "내일 오전에 보안팀으로 연락하세요.", until: "2026-10-13T09:00:00Z", block_id: "3f9a1c2e", require_client_id: true, client_id_present: true, checked_at: "2026-10-12T05:00:00Z", ...extra });
assert.deepEqual(parseAccessStatusResponse(accessBody()), { blocked: true, reasonCode: "client_blocked", reasons: [{ code: "INVESTIGATION", label: "보안 조사 중" }, { code: "ADMIN_REQUEST", label: "관리자 요청" }], userMemo: "내일 오전에 보안팀으로 연락하세요.", until: "2026-10-13T09:00:00.000Z", blockId: "3f9a1c2e", requireClientId: true, clientIdPresent: true, checkedAt: "2026-10-12T05:00:00.000Z" });
assert.deepEqual(Object.keys(ACCESS_REASON_LABELS), ["LEAK_DOC_REPEAT", "PII_REPEAT", "INVESTIGATION", "LEAVE", "ADMIN_REQUEST", "OTHER"]);
assert.deepEqual(Object.values(ACCESS_REASON_LABELS), ["기밀 문서 반복 유출 시도", "개인정보 반복 입력", "보안 조사 중", "퇴사·휴직 예정", "관리자 요청", "기타"]);
assert.deepEqual(parseAccessStatusResponse(accessBody({ reasons: [{ code: "INVESTIGATION", label: "위조된 문구" }] })).reasons, [{ code: "INVESTIGATION", label: "보안 조사 중" }]);   // 알려진 코드는 응답의 label을 쓰지 않는다
assert.deepEqual(parseAccessStatusResponse(accessBody({ reasons: [{ code: "FUTURE_CODE", label: "새 사유" }, { code: "FUTURE_NO_LABEL" }, { code: "OTHER", label: "x" }, { code: "OTHER", label: "x" }, "OTHER", null, { code: "lower", label: "x" }, { code: "X".repeat(40), label: "x" }] })).reasons, [{ code: "FUTURE_CODE", label: "새 사유" }, { code: "OTHER", label: "기타" }]);   // 모르는 코드는 label이 있을 때만, 중복·형식 오류는 버림
assert.equal(parseAccessStatusResponse(accessBody({ reasons: Object.keys(ACCESS_REASON_LABELS).concat(["EXTRA_A", "EXTRA_B"]).map((code) => ({ code, label: "x" })) })).reasons.length, 6);   // 최대 6개
assert.deepEqual(parseAccessStatusResponse(accessBody({ reasons: undefined })).reasons, []); assert.deepEqual(parseAccessStatusResponse(accessBody({ reasons: "INVESTIGATION" })).reasons, []);   // 사유 없는 옛 대시보드
assert.equal(parseAccessStatusResponse(accessBody({ user_memo: "a".repeat(250) })).userMemo.length, 200); assert.equal(parseAccessStatusResponse(accessBody({ user_memo: "줄1\r\n줄2\t끝" })).userMemo, "줄1  줄2 끝");
for (const memo of [null, "", "   ", 5, ["x"], undefined]) assert.equal(parseAccessStatusResponse(accessBody({ user_memo: memo })).userMemo, null, JSON.stringify(memo));
assert.equal(parseAccessStatusResponse(accessBody({ user_memo: "<img src=x onerror=alert(1)>" })).userMemo, "<img src=x onerror=alert(1)>");   // 글자 그대로 보관(화면은 textContent로만 그린다)
assert.equal(parseAccessStatusResponse(accessBody({ until: "정해지지 않음" })).until, null); assert.equal(parseAccessStatusResponse(accessBody({ until: null })).until, null); assert.equal(parseAccessStatusResponse(accessBody({ until: 12345 })).until, null);
for (const id of ["ab cd", "<script>", "x".repeat(17), "", null, 1234]) assert.equal(parseAccessStatusResponse(accessBody({ block_id: id })).blockId, null, JSON.stringify(id));
assert.deepEqual(parseAccessStatusResponse({ blocked: true, reason_code: "client_id_missing", reasons: [], user_memo: null, until: null, block_id: null, require_client_id: true, client_id_present: false }), { blocked: true, reasonCode: "client_id_missing", reasons: [], userMemo: null, until: null, blockId: null, requireClientId: true, clientIdPresent: false, checkedAt: null });
const parsedAllowed = parseAccessStatusResponse({ blocked: false, reason_code: null, reasons: [], user_memo: "남은 메모", until: "2026-10-13T09:00:00Z", block_id: "3f9a1c2e", require_client_id: false, client_id_present: true, checked_at: "2026-10-12T05:00:00Z" });
assert.deepEqual([parsedAllowed.blocked, parsedAllowed.reasonCode, parsedAllowed.userMemo, parsedAllowed.until, parsedAllowed.blockId, parsedAllowed.clientIdPresent], [false, null, null, null, null, true]);   // 허용이면 차단 상세는 버림
for (const bad of [null, undefined, [], "blocked", 1, {}, { blocked: "true" }, { blocked: 1 }, { blocked: null }, { blocked: true }, { blocked: true, reason_code: null }, { blocked: true, reason_code: "other" }, { blocked: true, reason_code: "CLIENT_BLOCKED" }, { blocked: true, reason_code: ["client_blocked"] }]) assert.equal(parseAccessStatusResponse(bad), null, JSON.stringify(bad));   // 가짜 '차단'을 만들지 않는다
assert.equal(parseAccessStatusResponse({ blocked: false, reason_code: "garbage" }).blocked, false);

// 조회 요청: 쿼리 없는 고정 주소 + 식별 헤더(형식이 맞을 때만), 쿠키 없음, 리다이렉트 거부
const accessCalls = [];
const fakeAccessFetch = (body, status = 200) => async (url, init) => { accessCalls.push({ url, init }); return new Response(typeof body === "string" ? body : JSON.stringify(body), { status }); };
globalThis.fetch = fakeAccessFetch(accessBody());
const accessResult = await accessStatusCheck({ clientId: "chrome-fake-client" });
assert.equal(accessResult.ok, true); assert.equal(accessResult.access.blocked, true); assert.equal(accessResult.access.reasonCode, "client_blocked");
assert.equal(accessCalls[0].url, "http://llm-gateway.local/__llmsgw/access-status");
assert.deepEqual(accessCalls[0].init.headers, { "X-LLMSGW-Client-Id": "chrome-fake-client" });
assert.deepEqual([accessCalls[0].init.cache, accessCalls[0].init.credentials, accessCalls[0].init.redirect], ["no-store", "omit", "error"]);
for (const badId of ["", "bad id\r\nX-Injected: 1", undefined, "x".repeat(65), null]) { await accessStatusCheck({ clientId: badId }); assert.equal("headers" in accessCalls.at(-1).init, false, String(badId)); }   // 식별 정보가 없거나 형식이 틀리면 헤더를 붙이지 않는다
await accessStatusCheck(); assert.equal(accessCalls.at(-1).url, "http://llm-gateway.local/__llmsgw/access-status"); assert.equal("headers" in accessCalls.at(-1).init, false);
const accessFailure = async (fetchImpl, options) => { globalThis.fetch = fetchImpl; return accessStatusCheck(options); };
assert.deepEqual(await accessFailure(fakeAccessFetch("Not Found", 404)).then((r) => [r.ok, r.state, r.errorCode]), [false, GATEWAY_STATES.UNSUPPORTED, "HEALTH_UNSUPPORTED"]);   // 옛 Gateway(엔드포인트 없음)
assert.equal((await accessFailure(fakeAccessFetch("<html>ISP injected page</html>"))).errorCode, "MALFORMED_JSON");
assert.equal((await accessFailure(fakeAccessFetch({ message: "no" }, 500))).errorCode, "HTTP_ERROR");
assert.equal((await accessFailure(fakeAccessFetch({ blocked: "yes" }))).errorCode, "INVALID_ACCESS_STATUS");
assert.equal((await accessFailure(fakeAccessFetch({ blocked: true }))).errorCode, "INVALID_ACCESS_STATUS");
assert.equal((await accessFailure(async () => { throw new TypeError("Failed to fetch"); })).errorCode, "NETWORK_ERROR");
assert.equal((await accessFailure(async () => { const error = new Error("aborted"); error.name = "AbortError"; throw error; })).errorCode, "TIMEOUT");
assert.equal((await accessFailure(fakeAccessFetch({ blocked: false, reason_code: null }))).ok, true);
globalThis.fetch = originalFetch;

// 상태 갱신: 처음 차단 확인 / 차단 후 허용 확인에서만 알림, 조회 실패는 '확인 불가'로만 기록(마지막 확인 결과 유지)
const t0 = "2026-10-12T05:00:00.000Z";
const okOutcome = (extra) => ({ ok: true, access: parseAccessStatusResponse(accessBody(extra)) });
const allowedOutcome = { ok: true, access: parseAccessStatusResponse({ blocked: false, reason_code: null }) };
assert.deepEqual(defaultAccessState(), normalizeAccessState(undefined)); assert.equal(defaultAccessState().status, ACCESS_STATES.UNKNOWN);
let step = reduceAccessState(undefined, okOutcome(), t0);
assert.equal(step.change, "BLOCKED"); assert.equal(step.state.status, ACCESS_STATES.BLOCKED); assert.equal(step.state.lastConfirmed, ACCESS_STATES.BLOCKED); assert.equal(step.state.checkedAt, "2026-10-12T05:00:00.000Z"); assert.equal(step.state.attemptedAt, t0);
assert.deepEqual(normalizeAccessState(JSON.parse(JSON.stringify(step.state))), step.state);   // 저장했다 다시 읽어도 같다
assert.equal(reduceAccessState(step.state, okOutcome(), t0).change, null);   // 계속 차단이면 알림 없음
const failed = reduceAccessState(step.state, { ok: false, errorCode: "TIMEOUT" }, t0);
assert.deepEqual([failed.state.status, failed.state.lastConfirmed, failed.state.reasonCode, failed.state.reasons, failed.state.userMemo, failed.change], [ACCESS_STATES.UNAVAILABLE, ACCESS_STATES.BLOCKED, null, [], null, null]);   // 실패 = 확인 불가(차단 표시 없음), 알림 없음
assert.equal(accessView(failed.state).statusText, "확인 불가"); assert.equal(accessView(failed.state).card, null);
step = reduceAccessState(failed.state, allowedOutcome, t0);
assert.equal(step.change, "UNBLOCKED"); assert.equal(step.state.status, ACCESS_STATES.ALLOWED); assert.equal(step.state.checkedAt, t0);   // 응답에 checked_at이 없으면 조회 시각
assert.equal(reduceAccessState(step.state, allowedOutcome, t0).change, null);
assert.equal(reduceAccessState(undefined, allowedOutcome, t0).change, null);   // 처음부터 허용이면 알림 없음
assert.equal(reduceAccessState(step.state, okOutcome({ reason_code: "client_id_missing" }), t0).change, "BLOCKED");
assert.deepEqual(resetAccessState(reduceAccessState(undefined, okOutcome(), t0).state), { ...defaultAccessState(), lastConfirmed: ACCESS_STATES.BLOCKED });
// 저장본이 깨졌을 때: 차단인데 사유 코드가 없으면 '확인 전', 알 수 없는 값은 기본값
for (const raw of [null, "x", 5, [], { status: "BLOCKED" }, { status: "BLOCKED", reasonCode: "weird" }, { status: "LOCKED" }, { status: 7 }]) assert.deepEqual(normalizeAccessState(raw), defaultAccessState(), JSON.stringify(raw));
assert.equal(normalizeAccessState({ status: "BLOCKED", reasonCode: "client_blocked", lastConfirmed: "NOPE" }).lastConfirmed, null);
assert.deepEqual(normalizeAccessState({ status: "BLOCKED", reasonCode: "client_blocked", until: "garbage", blockId: "a b", userMemo: 5, reasons: "x" }), { ...defaultAccessState(), status: ACCESS_STATES.BLOCKED, reasonCode: "client_blocked" });

// 화면 문구
assert.equal(formatKst("2026-10-13T09:00:00Z"), "2026-10-13 18:00"); assert.equal(formatKst("2026-10-12T15:30:00Z"), "2026-10-13 00:30"); assert.equal(formatKst("2026-12-31T15:00:00Z"), "2027-01-01 00:00"); assert.equal(formatKst("garbage"), "");
const blockedState = reduceAccessState(undefined, okOutcome(), t0).state;
assert.deepEqual(accessView(blockedState), { statusText: "제한됨", dot: "error", card: { title: "사용이 제한되었습니다", rows: [{ label: "사유", value: "보안 조사 중 · 관리자 요청" }, { label: "관리자 안내", value: "내일 오전에 보안팀으로 연락하세요." }, { label: "해제 예정", value: "10월 13일 오후 6:00" }], contact: "문의: 보안 관리자 · 차단 번호 3f9a1c2e" } });   // 1.4.6: 차단 번호는 행이 아니라 문의 줄 끝
const noExtras = accessView(reduceAccessState(undefined, okOutcome({ reasons: [], user_memo: null, until: null, block_id: null }), t0).state).card;   // 사유 없는 옛 대시보드 / 기한 없음 / 메모 비공개
assert.deepEqual(noExtras.rows, [{ label: "해제 예정", value: "관리자가 풀 때까지" }]); assert.equal(noExtras.contact, "문의: 보안 관리자");   // 차단 번호가 없으면 문의 줄만
const idMissingState = reduceAccessState(undefined, { ok: true, access: parseAccessStatusResponse({ blocked: true, reason_code: "client_id_missing", require_client_id: true, client_id_present: false }) }, t0).state;
assert.deepEqual(accessView(idMissingState, { identityEnabled: true }).card.rows, [{ label: "사유", value: "확장 프로그램 식별 정보 없음" }]);
assert.deepEqual(accessView(idMissingState, { identityEnabled: false }).card.rows.map((row) => row.label), ["사유", "조치"]);
assert.equal(accessView(blockedState, { active: false }).card, null); assert.equal(accessView(blockedState, { active: false }).statusText, "보호 꺼짐");   // 보호 꺼짐·프록시 불일치면 저장된 차단이 남아 있어도 보이지 않는다
assert.deepEqual([accessView({ status: "ALLOWED" }).statusText, accessView({ status: "UNAVAILABLE" }).statusText, accessView(undefined).statusText], ["없음", "확인 불가", "확인 중"]);
assert.equal(accessView({ status: "ALLOWED" }).card, null); assert.equal(accessView(undefined).card, null);
// 데스크톱 알림
assert.deepEqual(accessNotificationText("BLOCKED", blockedState), { title: "사용이 제한되었습니다", message: "사유: 보안 조사 중 · 관리자 요청\n해제 예정: 10월 13일 오후 6:00" });   // 1.4.6: 알림은 제목 + 사유 + 해제 예정(관리자 안내·차단 번호는 팝업 카드)
assert.deepEqual(accessNotificationText("UNBLOCKED", defaultAccessState()), { title: "사용 제한이 해제되었습니다", message: "AI 사이트를 다시 사용할 수 있습니다." });
assert.equal(accessNotificationText(null, blockedState), null); assert.equal(accessNotificationText("OTHER", blockedState), null);
const longMemoState = reduceAccessState(undefined, okOutcome({ user_memo: "가".repeat(150) }), t0).state;
assert.ok(!accessNotificationText("BLOCKED", longMemoState).message.includes("가"));   // 관리자 안내(메모)는 알림에 싣지 않는다
assert.ok(!accessNotificationText("BLOCKED", blockedState).message.includes("3f9a1c2e") && !accessNotificationText("BLOCKED", blockedState).message.includes("문의"));
assert.equal(accessNotificationText("BLOCKED", idMissingState).message, "사유: 확장 프로그램 식별 정보 없음");
assert.equal(accessNotificationText("BLOCKED", reduceAccessState(undefined, okOutcome({ reasons: [], until: null, user_memo: null }), t0).state).message, "해제 예정: 관리자가 풀 때까지");
assert.equal(accessNotificationText("BLOCKED", normalizeAccessState({ status: "BLOCKED", reasonCode: "client_blocked" })).message, "해제 예정: 관리자가 풀 때까지");
const accessNotes = []; const accessRuntime = { getURL: (path) => `chrome-extension://fake/${path}` };
assert.equal(await notifyAccessChange("BLOCKED", blockedState, { create: (id, options, callback) => { accessNotes.push({ id, options }); callback(); } }, accessRuntime), true);
assert.match(accessNotes[0].id, /^llmsgw-access-blocked-\d+$/); assert.equal(accessNotes[0].options.title, "사용이 제한되었습니다"); assert.equal(accessNotes[0].options.iconUrl, "chrome-extension://fake/assets/icon-128.png"); assert.equal(accessNotes[0].options.type, "basic");
assert.equal(await notifyAccessChange("UNBLOCKED", defaultAccessState(), { create: (id, options, callback) => { accessNotes.push({ id, options }); callback(); } }, accessRuntime), true); assert.match(accessNotes[1].id, /^llmsgw-access-unblocked-\d+$/);
assert.equal(await notifyAccessChange(null, blockedState, { create: () => assert.fail() }, accessRuntime), false);
assert.equal(await notifyAccessChange("BLOCKED", blockedState, { create: () => { throw new Error("denied"); } }, accessRuntime), false);
assert.equal(await notifyAccessChange("BLOCKED", blockedState, { create: (id, options, callback) => callback() }, { ...accessRuntime, lastError: { message: "x" } }), false);
assert.equal(accessNotificationOptions("BLOCKED", blockedState).message.includes("Event ID"), false);

// 아이콘 배지: 차단은 보호 중(ON 계열) 상태에서만 덧씌우고 '!'·보호 해제 표시는 그대로. 차단이 아니면 1.4.4 표시와 완전히 같다
const blockedBadge = { text: "차단", color: "#b42318", title: "PromptGate — 사용이 제한되었습니다" };
for (const state of [GATEWAY_STATES.HEALTHY, GATEWAY_STATES.DEGRADED, GATEWAY_STATES.UNSUPPORTED, GATEWAY_STATES.UNKNOWN]) assert.deepEqual(badgeFor(state, blockedState), blockedBadge, state);
for (const state of [GATEWAY_STATES.OFFLINE, GATEWAY_STATES.PROXY_ERROR, GATEWAY_STATES.CONFLICT, GATEWAY_STATES.CONFIGURATION_ERROR]) assert.deepEqual(badgeFor(state, blockedState), { text: "!", color: "#b42318", title: "PromptGate — 확인 필요" }, state);
assert.deepEqual(badgeFor(GATEWAY_STATES.DISABLED, blockedState), { text: "", color: "#000000", title: "PromptGate — 보호 꺼짐" });
for (const access of [undefined, defaultAccessState(), failed.state, step.state]) {
  assert.deepEqual(badgeFor(GATEWAY_STATES.HEALTHY, access), { text: "ON", color: "#16794a", title: "PromptGate — 보호 중" });
  assert.deepEqual(badgeFor(GATEWAY_STATES.DEGRADED, access), { text: "ON", color: "#16794a", title: "PromptGate — 보호 중" });
  assert.deepEqual(badgeFor(GATEWAY_STATES.UNSUPPORTED, access), { text: "ON", color: "#b77900", title: "PromptGate — 보호 중 · 서버 상태 확인 안 됨" });
  assert.deepEqual(badgeFor(GATEWAY_STATES.UNKNOWN, access), { text: "ON", color: "#667085", title: "PromptGate — 보호 중 · 상태 확인 중" });
}   // 조회 실패('확인 불가')나 허용이면 '차단'이 아니다

// 알람: 1분 주기, 이미 있으면 다시 만들지 않는다
const accessAlarmCalls = [];
assert.equal(await ensureAccessStatusAlarm({ get: async () => null, create: async (name, info) => { accessAlarmCalls.push([name, info]); } }), true);
assert.deepEqual(accessAlarmCalls, [["llmsgw-access-status", { delayInMinutes: 1, periodInMinutes: 1 }]]);
assert.equal(await ensureAccessStatusAlarm({ get: async () => ({ periodInMinutes: 1 }), create: async () => assert.fail() }), false);
assert.deepEqual([defaultsModule.ACCESS_STATUS_ALARM, defaultsModule.ACCESS_STATUS_PERIOD_MINUTES, defaultsModule.ACCESS_STATUS_MIN_INTERVAL_MS], ["llmsgw-access-status", 1, 15000]);
assert.notEqual(defaultsModule.ACCESS_STATUS_ALARM, defaultsModule.HEALTH_ALARM);

// 조회 조건 = 내 요청 기록 페이지와 같은 보호 확인(보호 켜짐 + Gateway 주소 + 이 확장 프로그램의 PAC + PAC 일치). 아니면 식별 정보를 보내지 않는다
const accessSettings = normalizeSettings({ ...base, gateway: { host: "52.78.173.46", port: 8081, profile: GATEWAY_PROFILES.M1_TEST }, identity: { enabled: true, tenantId: "oide" } });
const accessPac = (settings) => ({ levelOfControl: "controlled_by_this_extension", value: { mode: "pac_script", pacScript: { data: buildPacScript(settings) } } });
const accessStore = storageApi({ settings: accessSettings, identity: { clientId: "chrome-fake-access-client", viewerKey }, runtimeState: { desiredProtection: true, gatewayState: "HEALTHY" }, events: [], recentSecurityEvents: [] });
let accessProxy = accessPac(accessSettings); let accessManaged = {};
globalThis.chrome = { storage: { local: accessStore.api, managed: { get: async () => structuredClone(accessManaged) } }, proxy: { settings: { get: async () => structuredClone(accessProxy) } } };
assert.deepEqual(await resolveAccessContext(), { eligible: true, clientId: "chrome-fake-access-client" });
const ineligible = async (label, mutate, undo, reason) => { mutate(); const context = await resolveAccessContext(); undo(); assert.deepEqual([label, context.eligible, context.reason], [label, false, reason]); };
await ineligible("보호 꺼짐", () => { accessStore.data.runtimeState.desiredProtection = false; }, () => { accessStore.data.runtimeState.desiredProtection = true; }, "PROTECTION_OFF");
await ineligible("다른 Gateway로 가는 PAC", () => { accessProxy = accessPac(normalizeSettings({ ...accessSettings, gateway: { host: "203.0.113.9", port: 8081, profile: GATEWAY_PROFILES.M1_TEST } })); }, () => { accessProxy = accessPac(accessSettings); }, "PROXY_MISMATCH");
await ineligible("llm-gateway.local을 DIRECT로 보내는 PAC", () => { accessProxy = accessPac(accessSettings); accessProxy.value.pacScript.data = accessProxy.value.pacScript.data.replace(' || host == "llm-gateway.local"', ""); }, () => { accessProxy = accessPac(accessSettings); }, "PROXY_MISMATCH");
await ineligible("다른 확장 프로그램 소유", () => { accessProxy = { ...accessPac(accessSettings), levelOfControl: "controlled_by_other_extensions" }; }, () => { accessProxy = accessPac(accessSettings); }, "PROXY_MISMATCH");
await ineligible("고정 프록시", () => { accessProxy = { levelOfControl: "controlled_by_this_extension", value: { mode: "fixed_servers", rules: { singleProxy: { host: "52.78.173.46", port: 8081 } } } }; }, () => { accessProxy = accessPac(accessSettings); }, "PROXY_MISMATCH");
await ineligible("PAC 없음", () => { accessProxy = { levelOfControl: "controllable_by_this_extension", value: { mode: "system" } }; }, () => { accessProxy = accessPac(accessSettings); }, "PROXY_MISMATCH");
await ineligible("Gateway 주소 없음", () => { accessStore.data.settings = normalizeSettings({ ...accessSettings, gateway: { host: "", port: 8081, profile: GATEWAY_PROFILES.CUSTOM } }); }, () => { accessStore.data.settings = accessSettings; }, "NOT_CONFIGURED");
await ineligible("관리자 정책 오류", () => { accessManaged = { gatewayPort: "bad" }; }, () => { accessManaged = {}; }, "INVALID_POLICY");
accessManaged = { gatewayHost: "managed.example.com", gatewayPort: 8443 }; accessProxy = accessPac(applyManagedSettings(accessSettings, validateManagedPolicy(accessManaged)));
assert.equal((await resolveAccessContext()).eligible, true); accessManaged = {}; accessProxy = accessPac(accessSettings);   // 정책이 정한 Gateway의 PAC는 일치
accessStore.data.settings = normalizeSettings({ ...accessSettings, identity: { enabled: false, tenantId: "oide" } });
assert.deepEqual(await resolveAccessContext(), { eligible: true, clientId: "" });   // 식별 헤더 전송을 끈 사용자는 LLM 요청과 같이 식별 정보 없이 조회
accessStore.data.settings = accessSettings;

// 조회 서비스 전체 흐름(가짜 Gateway 응답, 가짜 시계)
let accessReply = { status: 200, body: accessBody() }; let accessFetchError = null; const serviceCalls = [];
globalThis.fetch = async (url, init) => { serviceCalls.push({ url, init }); if (accessFetchError) throw accessFetchError; return new Response(typeof accessReply.body === "string" ? accessReply.body : JSON.stringify(accessReply.body), { status: accessReply.status }); };
const serviceNotices = []; const serviceUpdates = []; let clock = Date.parse("2026-10-12T05:00:00Z"); let notifyFails = false;
const accessService = createAccessStatusService({ notifyChange: async (change, state) => { serviceNotices.push([change, state.reasonCode]); if (notifyFails) throw new Error("notification denied"); }, onUpdate: async ({ change, state }) => { serviceUpdates.push([change, state.status]); }, now: () => clock });
const savedAccess = () => accessStore.data.accessState;
let outcome = await accessService.refresh();   // 1) 처음 차단 확인
assert.deepEqual([outcome.ok, outcome.status, outcome.change], [true, "BLOCKED", "BLOCKED"]); assert.equal(serviceCalls.length, 1);
assert.deepEqual(serviceCalls[0].init.headers, { "X-LLMSGW-Client-Id": "chrome-fake-access-client" }); assert.equal(serviceCalls[0].url, "http://llm-gateway.local/__llmsgw/access-status");
assert.deepEqual([savedAccess().status, savedAccess().reasonCode, savedAccess().reasons.map((r) => r.code), savedAccess().blockId], ["BLOCKED", "client_blocked", ["INVESTIGATION", "ADMIN_REQUEST"], "3f9a1c2e"]);
assert.deepEqual(serviceNotices, [["BLOCKED", "client_blocked"]]); assert.deepEqual(serviceUpdates, [["BLOCKED", "BLOCKED"]]);
assert.ok(!JSON.stringify(savedAccess()).includes("chrome-fake-access-client"));   // 상태 저장본에는 식별 정보가 없다
clock += 60000; outcome = await accessService.refresh();   // 2) 계속 차단: 알림 없음
assert.deepEqual([outcome.status, outcome.change], ["BLOCKED", null]); assert.equal(serviceCalls.length, 2); assert.equal(serviceNotices.length, 1); assert.equal(serviceUpdates.length, 1);
clock += 5000; outcome = await accessService.refresh({ force: false });   // 3) 팝업: 마지막 시도 후 15초 안이면 건너뜀
assert.deepEqual([outcome.skipped, outcome.status], ["RECENT", "BLOCKED"]); assert.equal(serviceCalls.length, 2);
clock += 11000; outcome = await accessService.refresh({ force: false }); assert.equal(outcome.skipped, undefined); assert.equal(serviceCalls.length, 3);   // 16초 지남 -> 조회
clock += 1000; outcome = await accessService.refresh({ force: true }); assert.equal(serviceCalls.length, 4);   // force는 항상 조회
clock += 60000; accessFetchError = new TypeError("Failed to fetch"); outcome = await accessService.refresh();   // 4) 조회 실패 -> 확인 불가, 가짜 차단/허용 없음
assert.deepEqual([outcome.ok, outcome.status, outcome.change], [false, "UNAVAILABLE", null]); assert.equal(savedAccess().status, "UNAVAILABLE"); assert.equal(savedAccess().lastConfirmed, "BLOCKED"); assert.equal(savedAccess().reasonCode, null);
assert.deepEqual(badgeFor(GATEWAY_STATES.HEALTHY, savedAccess()), { text: "ON", color: "#16794a", title: "PromptGate — 보호 중" }); assert.equal(serviceNotices.length, 1);
accessFetchError = null; accessReply = { status: 404, body: "Not Found" }; clock += 60000; outcome = await accessService.refresh(); assert.equal(outcome.status, "UNAVAILABLE");   // 엔드포인트 없는 옛 Gateway도 확인 불가
accessReply = { status: 200, body: { blocked: false, reason_code: null, reasons: [], user_memo: null, until: null, block_id: null, require_client_id: false, client_id_present: true, checked_at: "2026-10-12T06:00:00Z" } };
clock += 60000; outcome = await accessService.refresh();   // 5) 허용 확인 -> '다시 허용됨' 한 번
assert.deepEqual([outcome.status, outcome.change], ["ALLOWED", "UNBLOCKED"]); assert.deepEqual(serviceNotices.at(-1), ["UNBLOCKED", null]); assert.equal(serviceNotices.length, 2); assert.equal(savedAccess().reasonCode, null);
clock += 60000; await accessService.refresh(); assert.equal(serviceNotices.length, 2);   // 계속 허용: 알림 없음
accessReply = { status: 200, body: accessBody({ reason_code: "client_id_missing", reasons: [], user_memo: null, until: null, block_id: null, client_id_present: false }) };
clock += 60000; notifyFails = true; outcome = await accessService.refresh();   // 6) 다시 차단(알림 실패해도 상태는 저장)
assert.deepEqual([outcome.status, outcome.change], ["BLOCKED", "BLOCKED"]); assert.equal(savedAccess().reasonCode, "client_id_missing"); assert.equal(serviceNotices.length, 3); notifyFails = false;
// 7) 보호 꺼짐/프록시 불일치 동안은 조회하지 않고(식별 정보 전송 없음) 화면에 보일 차단 표시도 지운다. 마지막 확인 결과는 유지 -> 다시 켜도 같은 차단은 알림을 반복하지 않는다
const callsBeforeOff = serviceCalls.length;
accessStore.data.runtimeState.desiredProtection = false; clock += 60000; outcome = await accessService.refresh();
assert.deepEqual([outcome.ok, outcome.skipped], [false, "PROTECTION_OFF"]); assert.equal(serviceCalls.length, callsBeforeOff); assert.deepEqual([savedAccess().status, savedAccess().lastConfirmed, savedAccess().reasonCode], ["UNKNOWN", "BLOCKED", null]);
accessProxy = accessPac(normalizeSettings({ ...accessSettings, gateway: { host: "203.0.113.9", port: 8081, profile: GATEWAY_PROFILES.M1_TEST } })); accessStore.data.runtimeState.desiredProtection = true;
outcome = await accessService.refresh({ force: true }); assert.equal(outcome.skipped, "PROXY_MISMATCH"); assert.equal(serviceCalls.length, callsBeforeOff);
accessProxy = accessPac(accessSettings); outcome = await accessService.refresh(); assert.equal(outcome.status, "BLOCKED"); assert.equal(outcome.change, null); assert.equal(serviceNotices.length, 3);
assert.deepEqual(serviceCalls.slice(callsBeforeOff).map((call) => call.init.headers), [{ "X-LLMSGW-Client-Id": "chrome-fake-access-client" }]);   // 보호 꺼짐·불일치 구간에는 헤더가 나간 적이 없다
// 8) reset(): 보호를 끌 때 호출 - 화면 상태만 지움
await accessService.reset(); assert.deepEqual([savedAccess().status, savedAccess().lastConfirmed], ["UNKNOWN", "BLOCKED"]); const updatesAfterReset = serviceUpdates.length; await accessService.reset(); assert.equal(serviceUpdates.length, updatesAfterReset);
// 9) 저장소 오류도 예외로 번지지 않는다
const brokenService = createAccessStatusService({ resolveContext: async () => { throw new Error("storage unavailable"); } }); assert.deepEqual(await brokenService.refresh(), { ok: false, errorCode: "ACCESS_STATUS_FAILED" });
delete globalThis.chrome; globalThis.fetch = originalFetch;

// 저장소: 새 accessState 키는 설치/업데이트 때 기본값으로 만들어지고, 깨진 값은 정리된다. GET_MODEL도 같은 값을 준다
const accessInit = storageApi({ settings: normalizeSettings(base), identity: { clientId: "chrome-fake-init", viewerKey }, runtimeState: { desiredProtection: false }, events: [], recentSecurityEvents: [] });
globalThis.chrome = { storage: { local: accessInit.api } }; await initializeStorage();
assert.deepEqual(accessInit.data.accessState, defaultAccessState());   // 1.4.4 저장본(accessState 없음) -> 기본값
accessInit.data.accessState = { status: "BLOCKED", reasonCode: "weird", reasons: [{ code: "<x>" }] }; await initializeStorage(); assert.deepEqual(accessInit.data.accessState, defaultAccessState());
await writeAccessState(blockedState); assert.deepEqual((await readModel()).accessState, blockedState); assert.deepEqual(accessInit.data.accessState, blockedState);
accessInit.data.accessState = "garbage"; assert.deepEqual((await readModel()).accessState, defaultAccessState());
accessInit.data.accessState = blockedState; const keptRuntime = structuredClone(accessInit.data.runtimeState); await initializeStorage(); assert.deepEqual(accessInit.data.accessState, blockedState); assert.deepEqual(accessInit.data.runtimeState, keptRuntime);   // 초기화가 저장된 상태를 지우지 않는다
delete globalThis.chrome;

// 명령: 팝업의 ACCESS_STATUS 요청은 force가 정확히 true일 때만 강제 조회
const accessCommandCalls = [];
const accessCommand = createCommandHandler({ applyConfiguration: async () => assert.fail(), disable: async () => assert.fail(), health: async () => assert.fail(), stats: async () => assert.fail(), processSecurityEvent: async () => assert.fail(), clearSecurityEvents: async () => assert.fail(), accessStatus: async (options) => { accessCommandCalls.push(options); return { ok: true, status: "ALLOWED" }; } });
assert.deepEqual(await accessCommand({ type: "ACCESS_STATUS" }), { ok: true, result: { ok: true, status: "ALLOWED" } });
await accessCommand({ type: "ACCESS_STATUS", force: true }); await accessCommand({ type: "ACCESS_STATUS", force: "yes" }); await accessCommand({ type: "ACCESS_STATUS", force: 1 });
assert.deepEqual(accessCommandCalls, [{ force: false }, { force: true }, { force: false }, { force: false }]);
const plainCommand = createCommandHandler({ applyConfiguration: async () => assert.fail(), disable: async () => assert.fail(), health: async () => assert.fail(), stats: async () => assert.fail(), processSecurityEvent: async () => assert.fail(), clearSecurityEvents: async () => assert.fail() });
assert.deepEqual(await plainCommand({ type: "ACCESS_STATUS" }), { ok: true, result: { ok: false, skipped: "UNSUPPORTED" } });

const popupHtml = await readFile(new URL("../extension/popup/popup.html", import.meta.url), "utf8"); const popupJs = await readFile(new URL("../extension/popup/popup.js", import.meta.url), "utf8"); const optionsHtml = await readFile(new URL("../extension/options/options.html", import.meta.url), "utf8"); const optionsJs = await readFile(new URL("../extension/options/options.js", import.meta.url), "utf8"); const eventChannelSource = await readFile(new URL("../extension/event-channel/event-channel-service.js", import.meta.url), "utf8"); const workerSource = await readFile(new URL("../extension/background/service-worker.js", import.meta.url), "utf8"); const policySchema = await readFile(new URL("../extension/managed-policy-schema.json", import.meta.url), "utf8");
for (const source of [popupHtml, popupJs, optionsHtml, optionsJs, workerSource, policySchema]) { assert.doesNotMatch(source, /SET_SERVICE|serviceControls|protectChatgpt|protectGemini|protectClaude|NETWORK_MANAGED|settings\.services/); }
for (const label of ["ChatGPT", "Gemini", "Claude"]) { assert.equal(popupHtml.includes(`>${label}<`), false); assert.equal(optionsHtml.includes(`>${label}<`), false); }
assert.match(eventChannelSource, /type: "REGISTER", clientId: desired\.clientId/); assert.doesNotMatch(eventChannelSource, /type: "PING"/); assert.match(workerSource, /protectionEnabled: model\.runtimeState\.desiredProtection/); assert.match(workerSource, /await eventChannel\.stop\(\)/);
for (const [html, script] of [[popupHtml, popupJs], [optionsHtml, optionsJs]]) { const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1])); for (const match of script.matchAll(/\$\("([^"]+)"\)/g)) assert.ok(ids.has(match[1]), `Missing DOM id: ${match[1]}`); assert.doesNotMatch(script, /\.innerHTML\b/); }
// 1.4.2: 화면 표시 판 숫자, 팝업 최근 이벤트의 사유 한 줄(알림 제목과 같은 문구, textContent로만)
assert.ok(popupHtml.includes(`<strong id="version">v${manifest.version}</strong>`)); assert.ok(optionsHtml.includes(`<strong id="extensionVersion">v${manifest.version}</strong>`));
const popupCss = await readFile(new URL("../extension/popup/popup.css", import.meta.url), "utf8");
assert.match(popupJs, /import \{ notificationText \} from "\.\.\/event-channel\/notification-service\.js";/); assert.match(popupJs, /const title = notificationText\(event\)\?\.title;/); assert.match(popupJs, /reason\.textContent = `\$\{event\.targetLlm\} · \$\{eventSummary\(event\)\}`;/); assert.match(popupCss, /\.event-dot\.block\{/); assert.match(popupCss, /\.event-dot\.mask\{/); assert.match(popupCss, /\.event-reason\{/);
// 1.4.6: 팝업 단순화 - 보이는 글자에 영어 기술 용어가 없고(id·class 값은 제외), 이름은 PromptGate로 통일, 맨 위는 상태 한 칸(+보호 스위치), 버튼은 '내 요청 기록 보기' 하나
const popupVisible = popupHtml.replace(/<script[\s\S]*?<\/script>/g, "").replace(/="[^"]*"/g, "").replace(/<[^>]+>/g, " ");
assert.doesNotMatch(popupVisible, /Proxy|Gateway|Event|Client|Security|PAC|DIRECT|Health|LLM/, popupVisible);
assert.ok(popupHtml.includes("<title>PromptGate</title>") && popupHtml.includes("<h1>PromptGate</h1>"));
assert.equal(manifest.name, "PromptGate"); assert.equal(manifest.action.default_title, "PromptGate"); assert.ok(optionsHtml.includes("<title>PromptGate 설정</title>") && optionsHtml.includes("<h1>PromptGate 설정</h1>"));
assert.deepEqual([...popupHtml.matchAll(/<button\b[^>]*\bid="([^"]+)"/g)].map((match) => match[1]), ["refresh", "openSettings", "openLogs"]);
assert.ok(popupHtml.indexOf('id="masterToggle"') > popupHtml.indexOf('id="hero"') && popupHtml.indexOf('id="masterToggle"') < popupHtml.indexOf('class="more"'), "보호 스위치는 상태 칸 안(자세히 보기 밖)");
assert.match(popupHtml, /<details class="more">/); assert.doesNotMatch(popupHtml, /<details[^>]*\bopen\b/);   // 자세히 보기는 접힌 채로
assert.match(popupJs, /if \(access\.card\) \{ \$\("hero"\)\.className = "hero slim"; \$\("overall"\)\.textContent = "보호"; \}/); assert.doesNotMatch(popupJs, /\$\("hero"\)\.hidden/);   // 사용 제한 중에도 보호 스위치는 보인다(초록 '보호 중' 칸만 한 줄로 줄임)
assert.match(popupCss, /\.hero\.slim \.hero-icon,\.hero\.slim #stateDetail\{display:none\}/);
assert.match(popupJs, /function showLoadError\(\)/); assert.match(popupJs, /try \{ response = await send\("GET_MODEL"\); \} catch \{ response = null; \}/);   // 통신 실패·응답 오류 모두 오류 화면
assert.match(popupJs, /default: return \{ tone: "warn", title: "상태를 확인할 수 없습니다"/);   // 모르는 상태에서는 안심시키지 않는다
assert.match(popupCss, /\[hidden\]\{display:none !important\}/);
for (const file of ["popup/popup.js", "popup/popup.html", "services/badge.js", "services/access-state.js", "event-channel/notification-service.js", "options/options.html", "manifest.json"]) assert.doesNotMatch(await readFile(new URL(`../extension/${file}`, import.meta.url), "utf8"), /LLM Security Gateway/, file);

// 1.4.3: 팝업 '로그 확인'은 확장 프로그램 안 페이지를 연다. 대시보드 서버 주소·외부 메시지 수신은 남기지 않는다
assert.match(popupJs, /chrome\.tabs\.create\(\{ url: chrome\.runtime\.getURL\("myrequests\/myrequests\.html"\) \}\)/);
assert.doesNotMatch(popupJs, /\/my-requests"|DEFAULT_DASHBOARD_URL|dashboard\?\.baseUrl/);
assert.doesNotMatch(workerSource, /onMessageExternal|onConnectExternal|GET_VIEWER_KEY|VIEWER_PAGE_ORIGINS/, "service worker must not answer external pages");
const extensionRoot = new URL("../extension/", import.meta.url);
const extensionFiles = (await readdir(extensionRoot, { recursive: true, withFileTypes: true })).filter((entry) => entry.isFile()).map((entry) => `${entry.parentPath ?? entry.path}/${entry.name}`.replaceAll("\\", "/"));
for (const file of extensionFiles.filter((name) => /\.(js|html|json|css)$/.test(name))) assert.doesNotMatch(await readFile(file, "utf8"), /52\.79\.153\.42|localhost:5173|127\.0\.0\.1:5173/, file);
// 기록 페이지 = 대시보드 MyRequestsPage로 만든 번들(dashboard-frontend-final: npm run build:extension). 파일 이름의 해시는 빌드마다 바뀌므로 HTML에서 읽는다
const myRequestsHtml = await readFile(new URL("myrequests/myrequests.html", extensionRoot), "utf8");
const scriptTags = [...myRequestsHtml.matchAll(/<script\b([^>]*)>/g)].map((match) => match[1]);
assert.equal(scriptTags.length, 1); assert.match(scriptTags[0], /^ type="module" src="\.\/assets\/myrequests-[A-Za-z0-9_-]+\.js"$/);
assert.doesNotMatch(myRequestsHtml, /<script(?![^>]*\bsrc=)/); assert.doesNotMatch(myRequestsHtml, /\son[a-z]+=/i);   // MV3 CSP: 인라인 스크립트·이벤트 속성 없음
const pageRefs = [...myRequestsHtml.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
assert.ok(pageRefs.length === 2 && pageRefs.every((ref) => /^\.\/assets\/myrequests-[A-Za-z0-9_-]+\.(js|css)$/.test(ref)), pageRefs.join(", "));   // 상대 경로만(외부·루트 경로 없음)
assert.match(myRequestsHtml, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; [^"]*connect-src http:\/\/llm-gateway\.local;[^"]*"/);   // 페이지는 llm-gateway.local 밖으로 연결하지 못한다
assert.deepEqual((await readdir(new URL("myrequests/assets/", extensionRoot))).sort(), pageRefs.map((ref) => ref.slice("./assets/".length)).sort());   // 옛 빌드·sourcemap·글꼴이 남지 않음
assert.deepEqual((await readdir(new URL("myrequests/", extensionRoot))).sort(), ["assets", "myrequests.html"]);
const bundleJs = await readFile(new URL(`myrequests/${pageRefs.find((ref) => ref.endsWith(".js")).slice(2)}`, extensionRoot), "utf8");
const bundleCss = await readFile(new URL(`myrequests/${pageRefs.find((ref) => ref.endsWith(".css")).slice(2)}`, extensionRoot), "utf8");
assert.doesNotMatch(bundleJs, /\beval\(|new Function|\bFunction\(|sourceMappingURL|chrome\.storage\.local|storage\.local\.get/);   // CSP 위반 코드 없음, 키는 GET_MODEL로만 받는다
assert.doesNotMatch(bundleCss, /url\(|@import|@font-face/);
const q = "[\"'`]";   // 압축기의 따옴표 형식에 묶이지 않게
for (const pattern of [`type:${q}GET_MODEL${q}`, `${q}controlled_by_this_extension${q}`, `${q}pac_script${q}`, "\\.desiredProtection", "\\.matchesSettings", "\\.viewerKey", `${q}http://llm-gateway\\.local/__llmsgw/my/${q}`, `${q}X-Viewer-Key${q}:`, `credentials:${q}omit${q}`, `cache:${q}no-store${q}`, `redirect:${q}error${q}`, "httpTimeoutMs:1e4", "jitless", `${q}보호가 켜져 있을 때만 기록을 볼 수 있습니다\\.${q}`]) assert.match(bundleJs, new RegExp(pattern), pattern);
assert.deepEqual([...new Set(bundleJs.match(/https?:\/\/[A-Za-z0-9.-]+(?::\d+)?/g))].filter((origin) => !/^https?:\/\/(www\.w3\.org|json-schema\.org|react\.dev)$/.test(origin)), ["http://llm-gateway.local"]);   // 네임스페이스·오류 안내 주소 말고는 llm-gateway.local뿐
// 기록 번호 형식 검사(Gateway 중계 정규식과 같음)와 중계 경로 두 가지(목록·근거)만 허용하는 주소 검사가 번들에 있다 - '..' 같은 번호로 중계 밖 경로에 키를 보내지 않는다
for (const literal of ["/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/", "/^http:\\/\\/llm-gateway\\.local\\/__llmsgw\\/my\\/requests\\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\\/evidence$/", "기록 번호가 올바르지 않습니다."]) assert.ok(bundleJs.includes(literal), literal);

// ===== 1.4.5 접속 제한 안내: 소스 정적 확인 =====
const accessStateSource = await readFile(new URL("../extension/services/access-state.js", import.meta.url), "utf8"); const accessServiceSource = await readFile(new URL("../extension/services/access-status-service.js", import.meta.url), "utf8"); const gatewayServiceSource = await readFile(new URL("../extension/services/gateway-service.js", import.meta.url), "utf8"); const badgeSource = await readFile(new URL("../extension/services/badge.js", import.meta.url), "utf8"); const notificationSource = await readFile(new URL("../extension/event-channel/notification-service.js", import.meta.url), "utf8");
// 서비스 워커: 1분 알람 등록·처리, 시작 시 조회, 보호를 끌 때 표시 지움, 배지는 badgeFor, 명령 연결
assert.match(workerSource, /import \{ ACCESS_STATUS_ALARM, EVENT_RECONNECT_ALARM, HEALTH_ALARM \} from "\.\.\/config\/defaults\.js";/);
assert.match(workerSource, /await ensureAccessStatusAlarm\(\);/); assert.match(workerSource, /if \(alarm\.name === ACCESS_STATUS_ALARM\) enqueue\(async \(\) => \{ await bootstrap\(\); await accessStatus\.refresh\(\); \}\);/);
assert.equal((workerSource.match(/await accessStatus\.refresh\(\);/g) || []).length, 3);   // 알람 + 설치 + 시작
assert.match(workerSource, /await accessStatus\.reset\(\);\n  await setBadge\("DISABLED"\);/); assert.match(workerSource, /accessStatus: accessStatus\.refresh, actionStatsSync: \(options\) => \{ void actionStats\.refresh\(options\); \} \}\);/);   // 1.4.8: 집계 조회 명령 추가
assert.match(workerSource, /const badge = badgeFor\(state, \(await readModel\(\)\)\.accessState\);/); assert.match(workerSource, /notifyChange: notifyAccessChange/);
assert.match(workerSource, /await appendEvent\("ACCESS_BLOCKED", state\.reasonCode \|\| ""\);/); assert.doesNotMatch(workerSource, /appendEvent\("ACCESS_[A-Z]+", [^)]*(?:userMemo|clientId)/);   // 사용자 메모·식별 정보는 확장 프로그램 이벤트 기록에 넣지 않는다
// 조회는 Gateway 한 곳(llm-gateway.local)으로만, 식별 헤더 이름은 계약대로, 로그·콘솔 출력 없음
assert.match(gatewayServiceSource, /export const ACCESS_STATUS_PATH = "\/__llmsgw\/access-status";/); assert.match(gatewayServiceSource, /export const ACCESS_STATUS_CLIENT_HEADER = "X-LLMSGW-Client-Id";/);
assert.match(gatewayServiceSource, /init: \{ credentials: "omit", redirect: "error" \}/);
for (const source of [accessStateSource, accessServiceSource, badgeSource]) assert.doesNotMatch(source, /\bconsole\.|fetch\(|XMLHttpRequest|WebSocket|sendBeacon/);   // 네트워크 호출은 gateway-service 한 곳
assert.doesNotMatch(notificationSource.slice(notificationSource.indexOf("notifyAccessChange")), /console\./);
assert.doesNotMatch(accessServiceSource, /clientId[^;\n]*(?:console|appendEvent|writeState|persist)/);
// 조회 조건: 보호 켜짐 확인이 조회보다 먼저
assert.ok(accessServiceSource.indexOf("desiredProtection") < accessServiceSource.indexOf("captureProxySnapshot()") && accessServiceSource.indexOf("proxySnapshotMatchesSettings(snapshot, settings)") < accessServiceSource.indexOf("await check({"));
assert.match(accessServiceSource, /const clientId = settings\.identity\.enabled && isValidIdentity\(model\.identity\.clientId\)/);
// 팝업: 카드·상태 줄은 textContent로만, 열 때와 설정 변경 뒤 조회 요청, accessState 변경 시 다시 그림
assert.match(popupJs, /import \{ accessView \} from "\.\.\/services\/access-state\.js";/); assert.match(popupJs, /term\.textContent = label; description\.textContent = value;/); assert.match(popupJs, /\$\("accessCard"\)\.hidden = !card;/);
assert.match(popupJs, /function requestAccessRefresh\(force = false\) \{ send\("ACCESS_STATUS", \{ force \}\)\.catch\(\(\) => undefined\); \}/); assert.match(popupJs, /load\(\)\.then\(\(\) => requestAccessRefresh\(false\)\);/); assert.match(popupJs, /finally \{ busy = false; await load\(\); requestAccessRefresh\(true\); \}/);
assert.match(popupJs, /changes\.settings \|\| changes\.accessState\)\) load\(\);/); assert.match(popupJs, /active: runtime\.desiredProtection && proxyApplied/);
for (const id of ["accessCard", "accessTitle", "accessRows", "accessContact", "accessDot", "accessStatus"]) assert.ok(popupHtml.includes(`id="${id}"`), id);
assert.match(popupHtml, /<section id="accessCard" class="access-card" aria-label="사용 제한 안내" hidden>/); assert.ok(popupHtml.indexOf('id="accessCard"') < popupHtml.indexOf('id="notice"') && popupHtml.indexOf('id="notice"') < popupHtml.indexOf('id="hero"'));   // 카드는 팝업 맨 위(헤더 바로 아래)
assert.match(popupCss, /\.access-card\{background:#fde8e7;/); assert.doesNotMatch(popupCss, /\.access-card\{[^}]*display:/);   // display를 덮으면 hidden이 먹지 않는다
// 권한은 늘리지 않는다(알람·알림·llm-gateway.local 접근은 기존 권한)
assert.deepEqual(manifest.permissions, ["proxy", "storage", "alarms", "declarativeNetRequestWithHostAccess", "notifications"]); assert.equal(manifest.host_permissions.filter((permission) => permission.includes("llm-gateway.local")).length, 1);
// 식별 헤더 DNR 규칙(LLM 도메인용)은 1.4.4와 같다 - 접속 제한 조회는 헤더를 직접 붙인다
assert.deepEqual(keyedRule.action.requestHeaders.map((h) => h.header), ["X-LLMSGW-Client-ID", "X-LLMSGW-Tenant-ID", "X-LLMSGW-Extension-Version", "X-LLMSGW-Viewer-Key"]); assert.deepEqual(keyedRule.condition.requestDomains, [...SUPPORTED_LLM_DOMAINS]);
// 서비스 워커 연결(알람 -> 조회 -> 저장 -> 배지·알림, 팝업 메시지, 보호 해제): 워커를 실제로 불러 가짜 chrome으로 실행(별도 프로세스)
const workerRun = spawnSync(process.execPath, [fileURLToPath(new URL("./access-status-worker.mjs", import.meta.url))], { encoding: "utf8" });
assert.equal(workerRun.status, 0, `${workerRun.stdout}
${workerRun.stderr}`.slice(-1500));
// 내 요청 기록 번들은 프런트엔드 빌드로 따로 교체한다. 1.4.7: 요청 ID 줄과 복사 버튼, 마스킹 용어(가림 없음)가 든 빌드여야 한다
assert.equal(createHash("sha256").update(await readFile(new URL("myrequests/myrequests.html", extensionRoot))).digest("hex").length, 64);
const myRequestsBundle = (await readdir(new URL("myrequests/assets/", extensionRoot))).filter((name) => name.endsWith(".js"));
assert.equal(myRequestsBundle.length, 1);
const myRequestsBundleText = await readFile(new URL(`myrequests/assets/${myRequestsBundle[0]}`, extensionRoot), "utf8");
for (const phrase of ["요청 ID 복사", "접속 차단", "관리자 안내", "PromptGate 창에서 보호를 켠 뒤"]) assert.ok(myRequestsBundleText.includes(phrase), phrase);
assert.ok(!myRequestsBundleText.includes("가림") && !myRequestsBundleText.includes("가린"), "내 요청 기록 화면 용어는 '마스킹'으로 통일");

// ===== 1.4.8 차단·마스킹 집계 =====
const statsSource = await readFile(new URL("../extension/services/action-stats.js", import.meta.url), "utf8"); const statsServiceSource = await readFile(new URL("../extension/services/action-stats-service.js", import.meta.url), "utf8");
// 네트워크 호출은 gateway-service 한 곳. 집계 코드는 콘솔·직접 요청·추적 없이 저장소와 순수 계산만
for (const source of [statsSource, statsServiceSource]) assert.doesNotMatch(source, /console\.|fetch\(|XMLHttpRequest|WebSocket|sendBeacon|innerHTML/);
assert.doesNotMatch(statsSource, /chrome\./);   // 순수 함수 파일은 크롬 API를 쓰지 않는다
// 저장하는 칸은 번호·시각·조치 종류뿐: 기록 한 줄은 [번호, 시각(ms), "B"|"M"|"R"], 프롬프트·서비스·탐지·열람 키·확장 번호를 넣을 수 있는 칸이 없다
assert.match(statsSource, /next\.recent\.push\(\[record\.id, ts, record\.code\]\);/); assert.doesNotMatch(statsSource + statsServiceSource, /targetLlm|detector|matchType|prompt|clientId/); assert.doesNotMatch(statsSource, /viewerKey/); assert.equal((statsServiceSource.match(/storage\.set\(/g) || []).length, 1); assert.match(statsServiceSource, /storage\.set\(\{ \[ACTION_STATS_KEY\]: stats \}\)/);   // 쓰는 곳은 집계 키 한 곳뿐
// 열람 키는 조회 조건(보호 켜짐 → PAC 일치 → 식별 헤더 켜짐)을 지난 뒤에만 읽어 넘긴다
assert.ok(statsServiceSource.indexOf("desiredProtection") < statsServiceSource.indexOf("captureProxySnapshot()") && statsServiceSource.indexOf("proxySnapshotMatchesSettings(snapshot, settings)") < statsServiceSource.indexOf("settings.identity.enabled") && statsServiceSource.indexOf("settings.identity.enabled") < statsServiceSource.indexOf("return { eligible: true, viewerKey"));
assert.ok(statsServiceSource.indexOf("const context = await resolveContext()") < statsServiceSource.indexOf("await check({ viewerKey: context.viewerKey })"));
// 서비스 워커: 실시간 알림 집계는 알림 저장 앞(개발 테스트 알림 processSecurityEvent에는 없음), 시작 시각·알람·설치·시작 연결
assert.match(workerSource, /storeEvent: async \(event\) => \{ await actionStats\.recordEvent\(event\); return storeSecurityEvent\(event\); \},/);
assert.doesNotMatch(workerSource.slice(workerSource.indexOf("async function processSecurityEvent"), workerSource.indexOf("const actionStats")), /actionStats/);
assert.match(workerSource, /await actionStats\.ensureStarted\(\)/); assert.match(workerSource, /await health\(\); void actionStats\.refresh\(\{ force: false \}\); \}\);/); assert.equal((workerSource.match(/void actionStats\.refresh\(\{ force: true \}\);/g) || []).length, 2);   // 설치 + 시작
// 팝업: 집계 칸은 textContent로만, 숫자 없는 상태는 문구로, 열 때·보호 변경·새로고침 때 조회 요청, 집계가 바뀌면 다시 그림
for (const id of ["stats", "statsTable", "statsNa", "statsNote", "statsCaption", "statsTodayBlock", "statsTodayMask", "statsTotalBlock", "statsTotalMask", "statsDot", "statsStatus", "statsRestricted", "statsRestrictedText", "statsRestrictedNote"]) assert.ok(popupHtml.includes(`id="${id}"`), id);
assert.match(popupJs, /import \{ ACTION_STATS_KEY, actionStatsView \} from "\.\.\/services\/action-stats\.js";/); assert.match(popupJs, /\$\("statsNote"\)\.textContent = view\.note;/); assert.match(popupJs, /cell\.textContent = Number\.isFinite\(value\) \? value\.toLocaleString\("ko-KR"\) : "–";/);
// 10/15: 접속 차단 기록(client_blocked·client_id_missing)은 차단과 따로 작게 - 운영 사유 코드는 access-state.js 한 곳에서 가져오고, 문구는 textContent로만
assert.match(statsSource, /import \{ ACCESS_REASON_CODES \} from "\.\/access-state\.js";/); assert.match(statsSource, /new Set\(Object\.values\(ACCESS_REASON_CODES\)\)/); assert.match(popupJs, /\$\("statsRestrictedText"\)\.textContent = view\.restrictedText;/); assert.match(popupJs, /\$\("statsRestricted"\)\.hidden = !view\.restrictedText;/);
assert.doesNotMatch(statsSource, /요청 기준/);   // 단위 문구: 질문·파일을 각각 센 '기록 기준'
assert.match(popupJs, /\$\("statsTable"\)\.hidden = !hasNumbers;/); assert.match(popupJs, /function requestStatsRefresh\(force = false\) \{ send\("ACTION_STATS_SYNC", \{ force \}\)\.catch\(\(\) => undefined\); \}/);
assert.match(popupJs, /requestStatsRefresh\(false\);/); assert.equal((popupJs.match(/\.then\(\(\) => requestStatsRefresh\(true\)\)/g) || []).length, 2); assert.match(popupJs, /changes\[ACTION_STATS_KEY\]\) \{ storedStats = changes\[ACTION_STATS_KEY\]\.newValue; renderStats\(\);/);
assert.match(popupJs, /\$\("stats"\)\.hidden = true;/);   // 상태를 못 불러오면 집계도 숨긴다(오래된 숫자로 안심시키지 않음)
// CSP: 팝업은 인라인 style·인라인 스크립트·이벤트 속성이 없다(모양은 popup.css의 클래스로만)
assert.doesNotMatch(popupHtml, /\sstyle\s*=|\son[a-z]+\s*=|<script(?![^>]*\ssrc=)/i); assert.doesNotMatch(popupJs, /setAttribute\("style"|\.cssText|\.innerHTML/);
assert.match(popupCss, /\.stats-table td\{[^}]*font-size:28px/); assert.match(popupCss, /\.stats-table td\.has-block\{/);
// 권한은 늘리지 않는다(storage·alarms·llm-gateway.local 접근은 기존 권한)
assert.deepEqual(manifest.permissions, ["proxy", "storage", "alarms", "declarativeNetRequestWithHostAccess", "notifications"]); assert.equal(manifest.host_permissions.filter((permission) => permission.includes("llm-gateway.local")).length, 1);
// 집계 조회는 내 요청 기록 페이지와 같은 주소·헤더, 쿠키·리다이렉트·Referer 없음
assert.match(gatewayServiceSource, /export const MY_REQUESTS_PATH = "\/__llmsgw\/my\/requests";/); assert.match(gatewayServiceSource, /\[VIEWER_KEY_HEADER\]: viewerKey/); assert.match(gatewayServiceSource, /credentials: "omit", redirect: "error", referrerPolicy: "no-referrer"/);
// 순수 함수·서비스·서비스 워커 연결은 별도 프로세스로(서비스 워커는 import하는 순간 chrome 수신기를 등록한다)
for (const file of ["action-stats.mjs", "action-stats-worker.mjs"]) { const statsRun = spawnSync(process.execPath, [fileURLToPath(new URL(`./${file}`, import.meta.url))], { encoding: "utf8" }); assert.equal(statsRun.status, 0, `${file}
${statsRun.stdout}
${statsRun.stderr}`.slice(-1800)); }

console.log("PASS: v1.4.8 in-extension my-requests page (React bundle, GET_MODEL protection gate contract, no external messaging, CSP-safe static checks); v1.4.0 fixed-domain PAC, Master lifecycle, ownership/fail-closed, schema 5 migration, REGISTER Event Channel, privacy/dedupe/notification, reconnect/OFF stop, M1 health, and MV3 checks; v1.4.2 reason-specific notifications, ALLOW notify, reasonCode/contentType/degraded/notify validation; v1.4.5 access-status polling (protection-gated, no false BLOCK), block popup card, badge, block/unblock notifications, service worker wiring; v1.4.6 simplified popup (plain-language status, no jargon), PromptGate naming, short notifications; v1.4.7 masking wording unified, request ID in my-requests; v1.4.8 block/mask counters (today/cumulative, event-id dedupe across Event Channel and my-requests relay, unavailable instead of zero, no new permissions)");
