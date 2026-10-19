import { defaultRuntimeState, defaultSettings, EVENT_LIMIT, STORAGE_SCHEMA_VERSION } from "../config/defaults.js";
import { EVENT_CHANNEL_STATES, GATEWAY_PROFILES, GATEWAY_STATES, STORAGE_KEYS } from "../config/statuses.js";
import { normalizeStoredSecurityEvents } from "../event-channel/event-store.js";
import { normalizeAccessState } from "./access-state.js";
import { cleanText, isPlainObject, isValidDashboardBaseUrl, isValidEventChannelUrl, isValidGatewayHost, isValidIdentity, isValidPort, isValidViewerKey } from "../utils/validation.js";

function randomClientId() { return `chrome-${crypto.randomUUID()}`; }
export function randomViewerKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function bool(value, fallback) { return typeof value === "boolean" ? value : fallback; }
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

export function normalizeSettings(raw = {}) {
  const d = defaultSettings();
  const source = isPlainObject(raw) ? raw : {};
  const gatewayRaw = isPlainObject(source.gateway) ? source.gateway : source;
  const identityRaw = isPlainObject(source.identity) ? source.identity : source;
  const eventChannelRaw = isPlainObject(source.eventChannel) ? source.eventChannel : source;
  const dashboardRaw = isPlainObject(source.dashboard) ? source.dashboard : source;
  const host = typeof gatewayRaw.gatewayHost === "string" ? gatewayRaw.gatewayHost.trim() : (typeof gatewayRaw.host === "string" ? gatewayRaw.host.trim() : d.gateway.host);
  const portInput = gatewayRaw.gatewayPort ?? gatewayRaw.port ?? d.gateway.port;
  const gatewayProfile = Object.values(GATEWAY_PROFILES).includes(gatewayRaw.profile) ? gatewayRaw.profile : d.gateway.profile;
  const gatewayPort = gatewayProfile === GATEWAY_PROFILES.M1_TEST ? 8081 : gatewayProfile === GATEWAY_PROFILES.M2_TEST ? 8080 : (isValidPort(portInput) ? Number(portInput) : d.gateway.port);
  const developmentMode = bool(source.developmentMode, d.developmentMode);
  const eventChannelUrl = typeof eventChannelRaw.eventChannelUrl === "string" ? eventChannelRaw.eventChannelUrl.trim() : (typeof eventChannelRaw.url === "string" ? eventChannelRaw.url.trim() : "");
  const dashboardBaseUrl = typeof dashboardRaw.dashboardBaseUrl === "string" ? dashboardRaw.dashboardBaseUrl.trim() : (typeof dashboardRaw.baseUrl === "string" ? dashboardRaw.baseUrl.trim() : "");
  return {
    schemaVersion: STORAGE_SCHEMA_VERSION,
    gateway: { host: isValidGatewayHost(host) ? host : d.gateway.host, port: gatewayPort, profile: gatewayProfile },
    identity: { enabled: bool(identityRaw.identityEnabled ?? identityRaw.enabled, d.identity.enabled), tenantId: isValidIdentity(identityRaw.tenantId) ? identityRaw.tenantId.trim() : d.identity.tenantId },
    eventChannel: { enabled: bool(eventChannelRaw.eventChannelEnabled ?? eventChannelRaw.enabled, false) && Boolean(eventChannelUrl) && isValidEventChannelUrl(eventChannelUrl, { developmentMode }), url: isValidEventChannelUrl(eventChannelUrl, { developmentMode }) ? eventChannelUrl : "" },
    dashboard: { baseUrl: isValidDashboardBaseUrl(dashboardBaseUrl, { developmentMode }) ? dashboardBaseUrl : "" },
    developerToolsEnabled: developmentMode && bool(source.developerToolsEnabled, false),
    developmentMode
  };
}

function normalizeRuntime(raw = {}) {
  const d = defaultRuntimeState();
  const source = isPlainObject(raw) ? raw : {};
  const states = new Set(Object.values(GATEWAY_STATES));
  const eventChannelStates = new Set(Object.values(EVENT_CHANNEL_STATES));
  return {
    ...d,
    desiredProtection: bool(source.desiredProtection ?? source.protectionEnabled, false),
    gatewayState: states.has(source.gatewayState) ? source.gatewayState : d.gatewayState,
    lastHealthAt: typeof source.lastHealthAt === "string" ? source.lastHealthAt : null,
    lastHealthLatencyMs: Number.isFinite(source.lastHealthLatencyMs) && source.lastHealthLatencyMs >= 0 ? source.lastHealthLatencyMs : null,
    lastHealthError: cleanText(source.lastHealthError, 250),
    lastErrorCode: cleanText(source.lastErrorCode, 64),
    lastTechnicalDetail: cleanText(source.lastTechnicalDetail, 500),
    lastProxyError: cleanText(source.lastProxyError, 250),
    proxyLevelOfControl: cleanText(source.proxyLevelOfControl, 64) || d.proxyLevelOfControl,
    proxyMode: cleanText(source.proxyMode, 64) || d.proxyMode,
    eventChannelStatus: eventChannelStates.has(source.eventChannelStatus) ? source.eventChannelStatus : d.eventChannelStatus,
    eventChannelError: cleanText(source.eventChannelError, 250),
    eventReconnectAttempt: Number.isInteger(source.eventReconnectAttempt) && source.eventReconnectAttempt >= 0 ? Math.min(source.eventReconnectAttempt, 100) : 0,
    lastSecurityEventAt: typeof source.lastSecurityEventAt === "string" && Number.isFinite(Date.parse(source.lastSecurityEventAt)) ? new Date(source.lastSecurityEventAt).toISOString() : null
  };
}

function normalizeEvents(events) {
  if (!Array.isArray(events)) return [];
  return events.filter(isPlainObject).slice(0, EVENT_LIMIT).map((event) => ({ ts: typeof event.ts === "string" ? event.ts : new Date().toISOString(), type: cleanText(event.type, 64) || "UNKNOWN", detail: cleanText(event.detail, 300) }));
}

export async function initializeStorage() {
  const raw = await chrome.storage.local.get(null);
  // v0.6 stored flat keys. Keep all valid legacy values, including the generated client ID.
  const settings = normalizeSettings(raw.settings ?? raw);
  const legacyClient = typeof raw.clientId === "string" ? raw.clientId.trim() : "";
  const identity = { clientId: isValidIdentity(raw.identity?.clientId) ? raw.identity.clientId.trim() : (isValidIdentity(legacyClient) ? legacyClient : randomClientId()),
    viewerKey: isValidViewerKey(raw.identity?.viewerKey) ? raw.identity.viewerKey : randomViewerKey() };
  const runtime = normalizeRuntime(raw.runtimeState ?? raw);
  const events = normalizeEvents(raw.events);
  const recentSecurityEvents = normalizeStoredSecurityEvents(raw.recentSecurityEvents);
  const accessState = normalizeAccessState(raw.accessState);
  const canonical = { settings, identity, runtimeState: runtime, events, recentSecurityEvents, accessState };
  const changed = !same(raw.settings, settings) || !same(raw.identity, identity) || !same(raw.runtimeState, runtime) || !same(raw.events, events) || !same(raw.recentSecurityEvents, recentSecurityEvents) || !same(raw.accessState, accessState);
  if (changed) await chrome.storage.local.set(canonical);
  // Only remove known legacy flat keys after the canonical record was written.
  if ((raw.settings?.schemaVersion ?? raw.schemaVersion ?? 0) < STORAGE_SCHEMA_VERSION) await chrome.storage.local.remove(["gatewayHost", "gatewayPort", "clientId", "tenantId", "chatgpt", "gemini", "claude", "identityEnabled", "protectionEnabled", "lastHealthOk", "lastHealthAt", "lastHealthError", "lastProxyError", "schemaVersion"]);
  return canonical;
}

export async function readModel() {
  const raw = await chrome.storage.local.get(Object.values(STORAGE_KEYS));
  return { settings: normalizeSettings(raw.settings), identity: { clientId: isValidIdentity(raw.identity?.clientId) ? raw.identity.clientId.trim() : randomClientId(), viewerKey: isValidViewerKey(raw.identity?.viewerKey) ? raw.identity.viewerKey : "" }, runtimeState: normalizeRuntime(raw.runtimeState), events: normalizeEvents(raw.events), recentSecurityEvents: normalizeStoredSecurityEvents(raw.recentSecurityEvents), accessState: normalizeAccessState(raw.accessState) };
}

export async function saveSettings(settings) { await chrome.storage.local.set({ settings: normalizeSettings(settings) }); }
export async function updateRuntime(patch) { const model = await readModel(); const runtimeState = normalizeRuntime({ ...model.runtimeState, ...patch }); await chrome.storage.local.set({ runtimeState }); return runtimeState; }
export async function appendEvent(type, detail = "") { const model = await readModel(); const events = [{ ts: new Date().toISOString(), type: cleanText(type, 64), detail: cleanText(detail, 300) }, ...model.events].slice(0, EVENT_LIMIT); await chrome.storage.local.set({ events }); }
export async function clearEvents() { await chrome.storage.local.set({ events: [] }); }
// 1.4.5: 접속 제한 상태는 runtimeState와 다른 키에 둔다(서로의 읽고-쓰기가 덮어쓰지 않게)
export async function writeAccessState(state) { const accessState = normalizeAccessState(state); await chrome.storage.local.set({ accessState }); return accessState; }

export async function commitProtectionState({ settings, saveUserSettings, runtimePatch, eventType, eventDetail }) {
  const model = await readModel();
  const patch = {
    runtimeState: normalizeRuntime({ ...model.runtimeState, ...runtimePatch }),
    events: [{ ts: new Date().toISOString(), type: cleanText(eventType, 64), detail: cleanText(eventDetail, 300) }, ...model.events].slice(0, EVENT_LIMIT)
  };
  if (saveUserSettings) patch.settings = normalizeSettings(settings);
  await chrome.storage.local.set(patch);
  return patch;
}

export function normalizeBackupReport(report) {
  if (!isPlainObject(report)) throw new Error("Backup report must be an object.");
  let settingsSource;
  let clientId;
  let desiredProtection = false;
  if (isPlainObject(report.backup)) {
    settingsSource = report.backup.settings;
    clientId = report.backup.identity?.clientId;
    desiredProtection = report.backup.desiredProtection === true;
  } else if (isPlainObject(report.configuration) && isPlainObject(report.client)) {
    settingsSource = {
      gateway: report.configuration.gateway,
      identity: { enabled: report.configuration.identityHeadersEnabled, tenantId: report.client.tenantId }
    };
    clientId = report.client.clientId;
    desiredProtection = report.configuration.desiredProtection === true;
  } else if (isPlainObject(report.settings)) {
    settingsSource = report.settings;
    clientId = report.settings.clientId;
    desiredProtection = report.settings.protectionEnabled === true;
  } else {
    throw new Error("Unsupported diagnostics/backup format.");
  }
  const settings = normalizeSettings(settingsSource);
  const rawSettings = isPlainObject(settingsSource) ? settingsSource : {};
  const rawEventChannel = isPlainObject(rawSettings.eventChannel) ? rawSettings.eventChannel : rawSettings;
  const rawEventUrl = typeof rawEventChannel.url === "string" ? rawEventChannel.url.trim() : (typeof rawEventChannel.eventChannelUrl === "string" ? rawEventChannel.eventChannelUrl.trim() : "");
  const rawEventEnabled = rawEventChannel.enabled === true || rawEventChannel.eventChannelEnabled === true;
  const rawDashboard = isPlainObject(rawSettings.dashboard) ? rawSettings.dashboard.baseUrl : rawSettings.dashboardBaseUrl;
  if (rawEventEnabled && !isValidEventChannelUrl(rawEventUrl, { developmentMode: settings.developmentMode })) throw new Error("Backup Event Channel URL is invalid.");
  if (typeof rawDashboard === "string" && rawDashboard.trim() && !isValidDashboardBaseUrl(rawDashboard.trim(), { developmentMode: settings.developmentMode })) throw new Error("Backup Dashboard Base URL is invalid.");
  if (!isValidGatewayHost(settings.gateway.host)) throw new Error("Backup Gateway host is invalid.");
  if (!isValidIdentity(clientId)) throw new Error("Backup Client ID is invalid.");
  return { settings, identity: { clientId: clientId.trim() }, desiredProtection };
}

export async function persistImportedBackup(backup) {
  const model = await readModel();
  const runtimeState = normalizeRuntime({ ...model.runtimeState, desiredProtection: false, gatewayState: "DISABLED", lastErrorCode: "", lastTechnicalDetail: "" });
  const events = [{ ts: new Date().toISOString(), type: "BACKUP_IMPORTED", detail: "Validated diagnostics backup" }, ...model.events].slice(0, EVENT_LIMIT);
  // 백업에는 열람 키를 넣지 않는다 - 이 브라우저의 키를 그대로 둔다
  const identity = { ...backup.identity, viewerKey: isValidViewerKey(model.identity.viewerKey) ? model.identity.viewerKey : randomViewerKey() };
  await chrome.storage.local.set({ settings: backup.settings, identity, runtimeState, events });
}
