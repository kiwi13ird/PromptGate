// 1.4.5 서비스 워커 연결 확인(가짜 chrome): 알람 -> 조회 -> 저장 -> 배지 -> 알림, 팝업 메시지, 보호 해제 시 지움
// 서비스 워커는 import 하는 순간 chrome 수신기를 등록하므로 run-tests.mjs가 별도 프로세스로 실행한다(실패하면 0이 아닌 종료 코드)
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url)).replace(/[\\/]$/, "");
const url = (p) => pathToFileURL(`${root}/${p}`).href;
const { buildPacScript } = await import(url("extension/services/proxy-service.js"));
const { normalizeSettings } = await import(url("extension/services/storage-service.js"));

const settings = normalizeSettings({ gateway: { host: "52.78.173.46", port: 8081, profile: "M1_TEST" }, identity: { enabled: true, tenantId: "oide" }, eventChannel: { enabled: false, url: "" }, developmentMode: true });
const clientId = "chrome-fake-worker-client";
const viewerKey = "A".repeat(43);
const data = { settings, identity: { clientId, viewerKey }, runtimeState: { desiredProtection: true, gatewayState: "HEALTHY" }, events: [], recentSecurityEvents: [] };
let proxyValue = { levelOfControl: "controlled_by_this_extension", value: { mode: "pac_script", pacScript: { data: buildPacScript(settings) } } };
const listeners = {}; const reg = (name) => ({ addListener: (fn) => { (listeners[name] ||= []).push(fn); } });
const badge = { text: null, color: null, title: null }; const notes = []; const alarmsCreated = []; let dnrRules = [];
const { buildIdentityRule } = await import(url("extension/services/identity-service.js"));
dnrRules = [buildIdentityRule(settings, data.identity)];
globalThis.chrome = {
  runtime: { onInstalled: reg("installed"), onStartup: reg("startup"), onMessage: reg("message"), getURL: (p) => `chrome-extension://fake/${p}`, lastError: undefined, id: "fake" },
  alarms: { onAlarm: reg("alarm"), get: async () => null, create: async (name, info) => { alarmsCreated.push([name, info]); }, clear: async () => true },
  storage: { onChanged: reg("storageChanged"), managed: { get: async () => ({}) }, local: {
    get: async (keys) => keys === null ? structuredClone(data) : Object.fromEntries(keys.filter((k) => k in data).map((k) => [k, structuredClone(data[k])])),
    set: async (patch) => Object.assign(data, structuredClone(patch)), remove: async (keys) => keys.forEach((k) => delete data[k]) } },
  proxy: { onProxyError: reg("proxyError"), settings: { onChange: reg("proxyChange"), get: async () => structuredClone(proxyValue), set: async ({ value }) => { proxyValue = { levelOfControl: "controlled_by_this_extension", value }; }, clear: async () => { proxyValue = { levelOfControl: "controllable_by_this_extension", value: { mode: "system" } }; } } },
  declarativeNetRequest: { updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => { dnrRules = dnrRules.filter((r) => !removeRuleIds.includes(r.id)).concat(addRules); }, getDynamicRules: async () => structuredClone(dnrRules) },
  action: { setBadgeText: async ({ text }) => { badge.text = text; }, setBadgeBackgroundColor: async ({ color }) => { badge.color = color; }, setTitle: async ({ title }) => { badge.title = title; } },
  notifications: { create: (id, options, cb) => { notes.push({ id, options }); cb?.(id); } },
  tabs: { create: async () => undefined }
};
const fetchCalls = []; let reply = { blocked: true, reason_code: "client_blocked", reasons: [{ code: "INVESTIGATION", label: "보안 조사 중" }], user_memo: "관리자 안내 예시", until: "2026-10-13T09:00:00Z", block_id: "3f9a1c2e", require_client_id: true, client_id_present: true, checked_at: "2026-10-12T05:00:00Z" };
globalThis.fetch = async (u, init) => { fetchCalls.push({ u, init }); if (String(u).includes("/__llmsgw/health")) return new Response(JSON.stringify({ status: "ok", version: "1" }), { status: 200 }); if (String(u).endsWith("/__llmsgw/access-status")) return new Response(JSON.stringify(reply), { status: 200 }); return new Response("", { status: 404 }); };

await import(url("extension/background/service-worker.js"));
const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
await settle();
assert.ok(alarmsCreated.some(([name, info]) => name === "llmsgw-access-status" && info.periodInMinutes === 1), "access alarm created");
const fireAlarm = async (name) => { for (const fn of listeners.alarm) fn({ name }); await settle(); };
const accessCalls = () => fetchCalls.filter((c) => String(c.u).endsWith("/__llmsgw/access-status"));

await fireAlarm("llmsgw-access-status");   // 1) 처음 차단 확인
assert.equal(accessCalls().length, 1); assert.equal(accessCalls()[0].init.headers["X-LLMSGW-Client-Id"], clientId);
assert.equal(data.accessState.status, "BLOCKED"); assert.equal(badge.text, "차단"); assert.equal(badge.color, "#b42318");
assert.equal(notes.length, 1); assert.equal(notes[0].options.title, "사용이 제한되었습니다"); assert.match(notes[0].options.message, /사유: 보안 조사 중/);
assert.ok(data.events.some((e) => e.type === "ACCESS_BLOCKED" && e.detail === "client_blocked")); assert.ok(!JSON.stringify(data.events).includes("관리자 안내 예시") && !JSON.stringify(data.events).includes(clientId));
// GET_MODEL은 accessState를 싣는다(팝업이 읽음)
const ask = (message) => new Promise((resolve) => { listeners.message[0](message, {}, resolve); });
const model = await ask({ type: "GET_MODEL" }); await settle(); assert.equal(model.ok, true); assert.equal(model.model.accessState.status, "BLOCKED");
await fireAlarm("llmsgw-access-status"); assert.equal(notes.length, 1);   // 2) 계속 차단: 알림 없음
// 3) 팝업 메시지: force 없으면 15초 이내 건너뜀, force면 조회
const before = accessCalls().length; let r = await ask({ type: "ACCESS_STATUS" }); assert.equal(r.result.skipped, "RECENT"); assert.equal(accessCalls().length, before);
r = await ask({ type: "ACCESS_STATUS", force: true }); assert.equal(accessCalls().length, before + 1);
// 4) 상태 새로고침(HEALTH)이 배지를 '차단'에서 'ON'으로 되돌리지 않는다
await ask({ type: "HEALTH" }); assert.equal(badge.text, "차단");
// 5) 조회 실패 -> 확인 불가: 배지 ON, 알림 없음
const savedFetch = globalThis.fetch; globalThis.fetch = async (u, init) => { if (String(u).endsWith("/__llmsgw/access-status")) { fetchCalls.push({ u, init }); throw new TypeError("Failed to fetch"); } return savedFetch(u, init); };
await ask({ type: "ACCESS_STATUS", force: true }); await settle(); assert.equal(data.accessState.status, "UNAVAILABLE"); assert.equal(badge.text, "ON"); assert.equal(notes.length, 1);
globalThis.fetch = savedFetch;
// 6) 허용 -> '다시 허용됨' 알림, 배지 ON
reply = { blocked: false, reason_code: null, reasons: [], user_memo: null, until: null, block_id: null, require_client_id: true, client_id_present: true, checked_at: "2026-10-12T05:05:00Z" };
await ask({ type: "ACCESS_STATUS", force: true }); await settle(); assert.equal(data.accessState.status, "ALLOWED"); assert.equal(badge.text, "ON"); assert.equal(notes.length, 2); assert.equal(notes[1].options.title, "사용 제한이 해제되었습니다");
// 7) 다시 차단 후 보호 해제: 조회 안 함, 표시 지움, 배지 지움
reply = { ...reply, blocked: true, reason_code: "client_blocked", reasons: [{ code: "OTHER", label: "기타" }] };
await ask({ type: "ACCESS_STATUS", force: true }); await settle(); assert.equal(data.accessState.status, "BLOCKED"); assert.equal(badge.text, "차단"); assert.equal(notes.length, 3);
const callsBeforeDisable = accessCalls().length;
const disabled = await ask({ type: "SET_MASTER", enabled: false }); await settle(); assert.equal(disabled.ok, true);
assert.equal(data.runtimeState.desiredProtection, false); assert.equal(data.accessState.status, "UNKNOWN"); assert.equal(data.accessState.lastConfirmed, "BLOCKED"); assert.equal(badge.text, "");
await fireAlarm("llmsgw-access-status"); await ask({ type: "ACCESS_STATUS", force: true }); assert.equal(accessCalls().length, callsBeforeDisable);   // 보호 꺼짐: 알람·팝업 모두 조회·식별 정보 전송 없음
process.exit(0);
