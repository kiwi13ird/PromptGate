// 1.4.8 서비스 워커 연결 확인(가짜 chrome·가짜 WebSocket·가짜 Gateway): 실시간 알림 -> 집계 저장, 알람/팝업 메시지 -> 내 요청 기록 조회,
// 중복 제거, 연결 끊김, 보호 꺼짐·식별 헤더 꺼짐에서는 열람 키를 보내지 않음, 개발 테스트 알림은 세지 않음
// 서비스 워커는 import 하는 순간 chrome 수신기를 등록하므로 run-tests.mjs가 별도 프로세스로 실행한다(실패하면 0이 아닌 종료 코드)
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url)).replace(/[\\/]$/, "");
const url = (p) => pathToFileURL(`${root}/${p}`).href;
const { buildPacScript } = await import(url("extension/services/proxy-service.js"));
const { normalizeSettings } = await import(url("extension/services/storage-service.js"));
const { buildIdentityRule } = await import(url("extension/services/identity-service.js"));
const { summarizeActionStats, normalizeActionStats } = await import(url("extension/services/action-stats.js"));

const settings = normalizeSettings({ gateway: { host: "52.78.173.46", port: 8081, profile: "M1_TEST" }, identity: { enabled: true, tenantId: "oide" }, eventChannel: { enabled: true, url: "ws://52.78.173.46:8765/event" }, developmentMode: true, developerToolsEnabled: true });
const clientId = "chrome-fake-stats-client";
const viewerKey = "Q".repeat(43);
const data = { settings, identity: { clientId, viewerKey }, runtimeState: { desiredProtection: true, gatewayState: "HEALTHY" }, events: [], recentSecurityEvents: [] };
let proxyValue = { levelOfControl: "controlled_by_this_extension", value: { mode: "pac_script", pacScript: { data: buildPacScript(settings) } } };
const listeners = {}; const reg = (name) => ({ addListener: (fn) => { (listeners[name] ||= []).push(fn); } });
const notes = []; let dnrRules = [buildIdentityRule(settings, data.identity)];
globalThis.chrome = {
  runtime: { onInstalled: reg("installed"), onStartup: reg("startup"), onMessage: reg("message"), getURL: (p) => `chrome-extension://fake/${p}`, lastError: undefined, id: "fake" },
  alarms: { onAlarm: reg("alarm"), get: async () => null, create: async () => undefined, clear: async () => true },
  storage: { onChanged: reg("storageChanged"), managed: { get: async () => ({}) }, local: {
    get: async (keys) => keys === null ? structuredClone(data) : Object.fromEntries(keys.filter((k) => k in data).map((k) => [k, structuredClone(data[k])])),
    set: async (patch) => Object.assign(data, structuredClone(patch)), remove: async (keys) => keys.forEach((k) => delete data[k]) } },
  proxy: { onProxyError: reg("proxyError"), settings: { onChange: reg("proxyChange"), get: async () => structuredClone(proxyValue), set: async ({ value }) => { proxyValue = { levelOfControl: "controlled_by_this_extension", value }; }, clear: async () => { proxyValue = { levelOfControl: "controllable_by_this_extension", value: { mode: "system" } }; } } },
  declarativeNetRequest: { updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => { dnrRules = dnrRules.filter((r) => !removeRuleIds.includes(r.id)).concat(addRules); }, getDynamicRules: async () => structuredClone(dnrRules) },
  action: { setBadgeText: async () => undefined, setBadgeBackgroundColor: async () => undefined, setTitle: async () => undefined },
  notifications: { create: (id, options, cb) => { notes.push({ id, options }); cb?.(id); } },
  tabs: { create: async () => undefined }
};

const sockets = [];
class FakeWebSocket {
  constructor(address) { this.address = address; this.readyState = 0; this.handlers = {}; this.sent = []; sockets.push(this); }
  addEventListener(type, fn) { (this.handlers[type] ||= []).push(fn); }
  send(text) { this.sent.push(text); }
  close() { this.readyState = 3; for (const fn of this.handlers.close || []) fn({}); }
  open() { this.readyState = 1; for (const fn of this.handlers.open || []) fn({}); }
  push(message) { for (const fn of this.handlers.message || []) fn({ data: typeof message === "string" ? message : JSON.stringify(message) }); }
}
globalThis.WebSocket = FakeWebSocket;

const fetchCalls = []; let listReply = { window_days: 7, items: [] }; let listMode = "ok"; let pending = null;
globalThis.fetch = async (u, init) => {
  const target = String(u); fetchCalls.push({ u: target, init });
  if (target.includes("/__llmsgw/health")) return new Response(JSON.stringify({ status: "ok", version: "1" }), { status: 200 });
  if (target.endsWith("/__llmsgw/access-status")) return new Response(JSON.stringify({ blocked: false, reason_code: null, reasons: [], user_memo: null, until: null, block_id: null, require_client_id: true, client_id_present: true, checked_at: "2026-10-14T05:00:00Z" }), { status: 200 });
  if (target === "http://llm-gateway.local/__llmsgw/my/requests") {
    if (pending) await pending;
    if (listMode === "network") throw new TypeError("Failed to fetch");
    if (listMode === "502") return new Response(JSON.stringify({ error: { code: "DASHBOARD_UNAVAILABLE" } }), { status: 502, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify(listReply), { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response("", { status: 404 });
};

await import(url("extension/background/service-worker.js"));
const settle = async () => { for (let i = 0; i < 60; i += 1) await new Promise((r) => setImmediate(r)); };
await settle();
const ask = (message) => new Promise((resolve) => { listeners.message[0](message, {}, resolve); });
const fireAlarm = async (name) => { for (const fn of listeners.alarm) fn({ name }); await settle(); };
const listCalls = () => fetchCalls.filter((c) => c.u === "http://llm-gateway.local/__llmsgw/my/requests");
const saved = () => normalizeActionStats(data.actionStats);
const total = () => summarizeActionStats(data.actionStats, Date.now()).total;
const today = () => summarizeActionStats(data.actionStats, Date.now()).today;
const nowIso = () => new Date().toISOString();
const ev = (eventId, action, extra = {}) => ({ type: "SECURITY_EVENT", eventId, clientId, action, targetLlm: "ChatGPT", detector: "Gateway", matchType: "POLICY", timestamp: nowIso(), ...extra });

// 0) 설치·시작: 집계 시작 시각이 저장되고, 실시간 알림 소켓이 열린다
assert.ok(data.actionStats?.startedAt, "집계 시작 시각 저장");
assert.equal(sockets.length, 1, "실시간 알림 연결 시도"); assert.equal(sockets[0].address, "ws://52.78.173.46:8765/event");
sockets[0].open(); await settle();
assert.deepEqual(JSON.parse(sockets[0].sent[0]), { type: "REGISTER", clientId });

// 1) 실시간 알림: 차단 1, 마스킹 1 -> 집계. 알림 표시도 그대로
sockets[0].push(ev("evt-b1", "BLOCK")); sockets[0].push(ev("evt-m1", "MASK")); await settle();
assert.deepEqual(total(), { block: 1, mask: 1, restricted: 0 }); assert.deepEqual(today(), { block: 1, mask: 1, restricted: 0 }); assert.equal(notes.length, 2);
assert.equal(data.recentSecurityEvents.length, 2);
// 2) 같은 번호 재전송: 집계는 그대로
sockets[0].push(ev("evt-b1", "BLOCK")); await settle(); assert.deepEqual(total(), { block: 1, mask: 1, restricted: 0 });
// 3) 허용(알림 요청)은 알림은 가되 세지 않는다. 다른 사람 번호·형식 오류·하트비트는 무시
sockets[0].push(ev("evt-a1", "ALLOW", { notify: true, reasonCode: "file_not_inspected" })); await settle();
assert.equal(data.recentSecurityEvents.length, 3); assert.deepEqual(total(), { block: 1, mask: 1, restricted: 0 });
sockets[0].push(ev("evt-other", "BLOCK", { clientId: "chrome-someone-else" })); sockets[0].push("not json"); sockets[0].push({ type: "HEARTBEAT" }); sockets[0].push({ type: "SECURITY_EVENT", clientId, action: "BLOCK" }); await settle();
assert.deepEqual(total(), { block: 1, mask: 1, restricted: 0 });
// 4) 개발 테스트 알림(SIMULATE)은 세지 않는다
const simulated = await ask({ type: "SIMULATE_SECURITY_EVENT", action: "BLOCK" }); await settle(); assert.equal(simulated.ok, true); assert.equal(simulated.stored, true);
assert.deepEqual(total(), { block: 1, mask: 1, restricted: 0 });
// 4-2) 접속 차단 알림(client_blocked): 알림은 가지만 '차단'이 아니라 사용 제한 기록으로 센다. 같은 번호 재전송은 그대로
sockets[0].push(ev("evt-r1", "BLOCK", { reasonCode: "client_blocked", contentType: "prompt" })); await settle();
assert.equal(data.recentSecurityEvents.length, 5); assert.deepEqual(total(), { block: 1, mask: 1, restricted: 1 });
sockets[0].push(ev("evt-r1", "BLOCK", { reasonCode: "client_blocked" })); await settle(); assert.deepEqual(total(), { block: 1, mask: 1, restricted: 1 });
// 5) 내 요청 기록 조회(5분 알람): 열람 키를 헤더로, 쿠키 없이. 놓친 건(evt-miss)은 채우고 이미 센 건은 그대로. 묶인 첨부 파일도 한 건씩
listReply = { window_days: 7, items: [
  { event_id: "evt-b1", occurred_at: nowIso(), final_action: "BLOCK" },
  { event_id: "evt-miss", occurred_at: nowIso(), final_action: "MASK", attached_files: [{ event_id: "evt-miss-file", occurred_at: nowIso(), final_action: "BLOCK" }] },
  { event_id: "evt-allow", occurred_at: nowIso(), final_action: "ALLOW" },
  { event_id: "evt-r1", occurred_at: nowIso(), final_action: "BLOCK", reason_code: "client_blocked", content_type: "prompt" },
  { event_id: "evt-r9", occurred_at: nowIso(), final_action: "BLOCK", reason_code: "client_id_missing", content_type: "prompt" }] };
await fireAlarm("llmsgw-health");
assert.equal(listCalls().length, 1); const call = listCalls()[0];
assert.equal(call.init.headers["X-Viewer-Key"], viewerKey); assert.equal(call.init.credentials, "omit"); assert.equal(call.init.redirect, "error"); assert.equal(call.init.referrerPolicy, "no-referrer");
assert.equal(call.u.includes("?"), false); assert.ok(!call.u.includes(viewerKey));
assert.deepEqual(total(), { block: 2, mask: 2, restricted: 2 }); assert.ok(saved().sync.okAt); assert.equal(saved().sync.error, "");
// 6) 팝업 메시지: 기다리지 않고 바로 응답하고, 조회가 끝나기 전에도 GET_MODEL이 막히지 않는다. force가 아니면 1분 안에는 건너뜀
const beforeCalls = listCalls().length;
assert.deepEqual(await ask({ type: "ACTION_STATS_SYNC" }), { ok: true }); await settle(); assert.equal(listCalls().length, beforeCalls, "마지막 시도 후 1분 안: 건너뜀");
let release; pending = new Promise((resolve) => { release = resolve; });
assert.deepEqual(await ask({ type: "ACTION_STATS_SYNC", force: true }), { ok: true }); await settle(); assert.equal(listCalls().length, beforeCalls + 1);
const model = await Promise.race([ask({ type: "GET_MODEL" }), new Promise((resolve) => setTimeout(() => resolve("BLOCKED"), 1500))]); assert.notEqual(model, "BLOCKED", "조회가 오래 걸려도 팝업이 멈추지 않는다"); assert.equal(model.ok, true);
release(); pending = null; await settle();
// 7) 연결 끊김: 숫자는 그대로, 마지막 성공 시각 유지, 오류 코드만 기록(응답 502도 0건이 아니라 실패)
const okAt = saved().sync.okAt;
for (const mode of ["network", "502"]) { listMode = mode; await ask({ type: "ACTION_STATS_SYNC", force: true }); await settle(); assert.deepEqual(total(), { block: 2, mask: 2, restricted: 2 }, mode); assert.equal(saved().sync.okAt, okAt, mode); assert.ok(saved().sync.error, mode); }
assert.equal(saved().sync.error, "HTTP_ERROR");
listMode = "ok"; await ask({ type: "ACTION_STATS_SYNC", force: true }); await settle(); assert.equal(saved().sync.error, ""); assert.deepEqual(total(), { block: 2, mask: 2, restricted: 2 });
// 8) 식별 헤더 전송이 꺼져 있으면 조회하지 않는다(열람 키가 Gateway에 실려 가지 않아 목록이 비어 보임)
const callsBeforeIdentityOff = listCalls().length; data.settings = { ...data.settings, identity: { ...data.settings.identity, enabled: false } };
await ask({ type: "ACTION_STATS_SYNC", force: true }); await settle(); await fireAlarm("llmsgw-health"); assert.equal(listCalls().length, callsBeforeIdentityOff);
data.settings = { ...data.settings, identity: { ...data.settings.identity, enabled: true } };
// 9) 보호 꺼짐: 조회·열람 키 전송 없음, 이미 센 숫자는 보존
const callsBeforeOff = listCalls().length;
const off = await ask({ type: "SET_MASTER", enabled: false }); await settle(); assert.equal(off.ok, true);
await ask({ type: "ACTION_STATS_SYNC", force: true }); await fireAlarm("llmsgw-health"); await settle();
assert.equal(listCalls().length, callsBeforeOff); assert.deepEqual(total(), { block: 2, mask: 2, restricted: 2 });
// 10) 열람 키는 알림·기록·집계 어디에도 남지 않는다
for (const [name, value] of [["events", data.events], ["recentSecurityEvents", data.recentSecurityEvents], ["actionStats", data.actionStats], ["notifications", notes]]) assert.ok(!JSON.stringify(value).includes(viewerKey), name);
assert.ok(!JSON.stringify(data.actionStats).includes("ChatGPT") && !JSON.stringify(data.actionStats).includes(clientId));
assert.ok(fetchCalls.every((c) => c.u.startsWith("http://llm-gateway.local/")), "Gateway 말고는 어디에도 요청하지 않는다");
process.exit(0);
