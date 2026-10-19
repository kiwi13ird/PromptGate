import { buildSelectivePacScript } from "../routing/selective-pac.js";

export const CONTROLLED_BY_US = "controlled_by_this_extension";
export const CONTROLLABLE = "controllable_by_this_extension";
export const buildPacScript = buildSelectivePacScript;

export async function readProxyState() {
  const details = await chrome.proxy.settings.get({ incognito: false });
  return { levelOfControl: details.levelOfControl || "unknown", mode: details.value?.mode || "unknown" };
}

export async function captureProxySnapshot() {
  const details = await chrome.proxy.settings.get({ incognito: false });
  return { levelOfControl: details.levelOfControl || "unknown", value: structuredClone(details.value || { mode: "system" }) };
}

export function proxySnapshotMatchesSettings(snapshot, settings) {
  if (snapshot?.levelOfControl !== CONTROLLED_BY_US || snapshot?.value?.mode !== "pac_script") return false;
  try { return snapshot.value?.pacScript?.data === buildPacScript(settings); } catch { return false; }
}

export function canSetProxy(levelOfControl) { return levelOfControl === CONTROLLABLE || levelOfControl === CONTROLLED_BY_US; }

export async function setProtectionPac(settings) {
  const before = await readProxyState();
  if (!canSetProxy(before.levelOfControl)) throw new Error(`Proxy cannot be controlled (${before.levelOfControl}).`);
  await chrome.proxy.settings.set({ value: { mode: "pac_script", pacScript: { data: buildPacScript(settings) } }, scope: "regular" });
  const after = await readProxyState();
  if (after.levelOfControl !== CONTROLLED_BY_US || after.mode !== "pac_script") throw new Error("Proxy setting was not retained; another extension or policy may control it.");
  return after;
}

export async function clearProtectionPac() {
  const state = await readProxyState();
  // Never clear a proxy owned by another extension or policy.
  if (state.levelOfControl === CONTROLLED_BY_US) await chrome.proxy.settings.clear({ scope: "regular" });
  return readProxyState();
}

export async function restoreProxySnapshot(snapshot) {
  const current = await readProxyState();
  if (snapshot?.levelOfControl === CONTROLLED_BY_US && snapshot.value) {
    if (!canSetProxy(current.levelOfControl)) throw new Error("Previous proxy configuration cannot be restored because ownership changed.");
    await chrome.proxy.settings.set({ value: snapshot.value, scope: "regular" });
    return readProxyState();
  }
  // No extension-owned proxy existed before the transaction.
  if (current.levelOfControl === CONTROLLED_BY_US) await chrome.proxy.settings.clear({ scope: "regular" });
  return readProxyState();
}
