import { isPlainObject, isValidDashboardBaseUrl, isValidEventChannelUrl, isValidGatewayHost, isValidIdentity, isValidPort } from "../utils/validation.js";
import { normalizeSettings } from "./storage-service.js";

const POLICY_FIELDS = Object.freeze({
  gatewayHost: "gateway.host",
  gatewayPort: "gateway.port",
  identityEnabled: "identity.enabled",
  tenantId: "identity.tenantId",
  eventChannelEnabled: "eventChannel.enabled",
  eventChannelUrl: "eventChannel.url",
  dashboardBaseUrl: "dashboard.baseUrl",
  protectionEnabled: "runtime.desiredProtection",
  developmentMode: "developmentMode"
});

export function validateManagedPolicy(raw) {
  if (!isPlainObject(raw) || Object.keys(raw).length === 0) return { active: false, values: {}, lockedFields: [], errors: [], mode: "development" };
  const values = {};
  const errors = [];
  const acceptBoolean = (key) => { if (raw[key] === undefined) return; if (typeof raw[key] === "boolean") values[key] = raw[key]; else errors.push(`${key}: boolean required`); };
  if (raw.gatewayHost !== undefined) isValidGatewayHost(raw.gatewayHost) ? values.gatewayHost = raw.gatewayHost.trim() : errors.push("gatewayHost: invalid hostname or IPv4");
  if (raw.gatewayPort !== undefined) isValidPort(raw.gatewayPort) ? values.gatewayPort = Number(raw.gatewayPort) : errors.push("gatewayPort: invalid port");
  for (const key of ["identityEnabled", "eventChannelEnabled", "protectionEnabled", "developmentMode"]) acceptBoolean(key);
  if (raw.tenantId !== undefined) isValidIdentity(raw.tenantId) ? values.tenantId = raw.tenantId.trim() : errors.push("tenantId: invalid identity");
  const developmentMode = values.developmentMode !== false;
  if (raw.eventChannelUrl !== undefined) isValidEventChannelUrl(raw.eventChannelUrl, { developmentMode }) ? values.eventChannelUrl = raw.eventChannelUrl.trim() : errors.push("eventChannelUrl: invalid WebSocket URL");
  if (raw.dashboardBaseUrl !== undefined) isValidDashboardBaseUrl(raw.dashboardBaseUrl, { developmentMode }) ? values.dashboardBaseUrl = raw.dashboardBaseUrl.trim() : errors.push("dashboardBaseUrl: invalid URL");
  const lockedFields = Object.keys(values).map((key) => POLICY_FIELDS[key]);
  const managedMode = values.developmentMode === false;
  if (managedMode) lockedFields.push("gateway.host", "gateway.port", "gateway.profile", "identity.enabled", "identity.tenantId", "eventChannel.enabled", "eventChannel.url", "dashboard.baseUrl", "developerToolsEnabled", "runtime.desiredProtection");
  return { active: Object.keys(values).length > 0, values, lockedFields: [...new Set(lockedFields)], errors, mode: managedMode ? "managed" : "development" };
}

// Chrome managed storage is the only policy source currently supported. No remote policy API is assumed.
export async function getManagedPolicy() {
  try {
    const raw = await chrome.storage.managed.get(null);
    return validateManagedPolicy(raw);
  } catch (error) {
    return { active: false, values: {}, lockedFields: [], errors: [], mode: "development", technicalDetail: String(error?.message || error) };
  }
}

export function applyManagedSettings(settings, policy) {
  if (!policy?.active || !isPlainObject(policy.values)) return settings;
  const v = policy.values;
  return normalizeSettings({
    ...settings,
    gateway: { ...settings.gateway, ...(v.gatewayHost !== undefined ? { host: v.gatewayHost } : {}), ...(v.gatewayPort !== undefined ? { port: v.gatewayPort, profile: "CUSTOM" } : {}) },
    identity: { ...settings.identity, ...(v.identityEnabled !== undefined ? { enabled: v.identityEnabled } : {}), ...(v.tenantId !== undefined ? { tenantId: v.tenantId } : {}) },
    eventChannel: { ...settings.eventChannel, ...(v.eventChannelEnabled !== undefined ? { enabled: v.eventChannelEnabled } : {}), ...(v.eventChannelUrl !== undefined ? { url: v.eventChannelUrl } : {}) },
    dashboard: { ...settings.dashboard, ...(v.dashboardBaseUrl !== undefined ? { baseUrl: v.dashboardBaseUrl } : {}) },
    developerToolsEnabled: v.developmentMode === false ? false : settings.developerToolsEnabled,
    developmentMode: typeof v.developmentMode === "boolean" ? v.developmentMode : settings.developmentMode
  });
}

export function preserveManagedLocalSettings(proposed, current, policy) {
  const next = normalizeSettings(proposed);
  const previous = normalizeSettings(current);
  const locked = new Set(policy?.lockedFields || []);
  if (locked.has("gateway.host")) next.gateway.host = previous.gateway.host;
  if (locked.has("gateway.port")) next.gateway.port = previous.gateway.port;
  if (locked.has("gateway.profile")) next.gateway.profile = previous.gateway.profile;
  if (locked.has("identity.enabled")) next.identity.enabled = previous.identity.enabled;
  if (locked.has("identity.tenantId")) next.identity.tenantId = previous.identity.tenantId;
  if (locked.has("eventChannel.enabled")) next.eventChannel.enabled = previous.eventChannel.enabled;
  if (locked.has("eventChannel.url")) next.eventChannel.url = previous.eventChannel.url;
  if (locked.has("dashboard.baseUrl")) next.dashboard.baseUrl = previous.dashboard.baseUrl;
  if (locked.has("developerToolsEnabled")) next.developerToolsEnabled = previous.developerToolsEnabled;
  return next;
}

export function isManagedField(policy, field) { return policy?.lockedFields?.includes(field) === true; }
