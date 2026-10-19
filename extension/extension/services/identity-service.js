import { EXTENSION_VERSION, SUPPORTED_LLM_DOMAINS } from "../routing/protected-domains.js";
import { DNR_IDENTITY_RULE_ID } from "../config/defaults.js";
import { isValidIdentity, isValidViewerKey } from "../utils/validation.js";

export function buildIdentityRule(settings, identity) {
  if (!settings?.identity?.enabled) return null;
  if (!isValidIdentity(identity?.clientId) || !isValidIdentity(settings.identity.tenantId)) throw new Error("Identity values must be 1–64 safe characters.");
  return {
    id: DNR_IDENTITY_RULE_ID,
    priority: 1,
    action: { type: "modifyHeaders", requestHeaders: [
      { header: "X-LLMSGW-Client-ID", operation: "set", value: identity.clientId.trim() },
      { header: "X-LLMSGW-Tenant-ID", operation: "set", value: settings.identity.tenantId.trim() },
      { header: "X-LLMSGW-Extension-Version", operation: "set", value: EXTENSION_VERSION },
      // Gateway가 지문(SHA-256)만 이벤트에 남기고 지운다 - LLM 서비스로는 나가지 않는다 (2026-10-09)
      ...(isValidViewerKey(identity?.viewerKey) ? [{ header: "X-LLMSGW-Viewer-Key", operation: "set", value: identity.viewerKey }] : [])
    ] },
    condition: { requestDomains: [...SUPPORTED_LLM_DOMAINS] }
  };
}

export async function syncIdentityRule(settings, identity) {
  const rule = buildIdentityRule(settings, identity);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_IDENTITY_RULE_ID], addRules: rule ? [rule] : [] });
}

export async function removeIdentityRule() {
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_IDENTITY_RULE_ID] });
}

export async function removeIdentityRuleVerified() {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await removeIdentityRule();
    if (!(await captureIdentityRule())) return;
  }
  throw new Error("Owned identity DNR rule is still present after removal.");
}

export async function captureIdentityRule() {
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  return rules.find((rule) => rule.id === DNR_IDENTITY_RULE_ID) || null;
}

export async function restoreIdentityRule(rule) {
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_IDENTITY_RULE_ID], addRules: rule ? [rule] : [] });
}

export function identityRuleMatches(rule, settings, identity) {
  try { return JSON.stringify(rule || null) === JSON.stringify(buildIdentityRule(settings, identity)); } catch { return false; }
}
