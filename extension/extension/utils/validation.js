export function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

export function isValidGatewayHost(value) {
  if (typeof value !== "string") return false;
  const host = value.trim();
  if (!host || host.length > 253 || /[\s/:\\"'`;${}()[\]<>]/.test(host)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host.split(".").every((part) => Number.isInteger(Number(part)) && Number(part) >= 0 && Number(part) <= 255);
  if (!/^[A-Za-z0-9.-]+$/.test(host) || host.startsWith(".") || host.endsWith(".") || host.includes("..")) return false;
  return host.split(".").every((label) => label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label));
}

export function isValidPort(value) {
  if (typeof value === "string" && !/^\d+$/.test(value.trim())) return false;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

// 열람 키: 이 브라우저가 보낸 요청만 내 요청 기록에서 보이게 하는 비밀값(32바이트 base64url)
export function isValidViewerKey(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function isValidIdentity(value) {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,64}$/.test(value.trim());
}

export function cleanText(value, max = 200) {
  return typeof value === "string" ? value.replace(/[\r\n\t]/g, " ").trim().slice(0, max) : "";
}

function safeUrl(value) {
  if (typeof value !== "string" || value.length > 2048) return null;
  try { return new URL(value.trim()); } catch { return null; }
}

function isLocalHostname(hostname) { return ["localhost", "127.0.0.1", "[::1]"].includes(hostname.toLowerCase()); }

export function isValidEventChannelUrl(value, { developmentMode = true } = {}) {
  if (value === "") return true;
  const url = safeUrl(value);
  if (!url || url.username || url.password || url.search || url.hash) return false;
  if (url.protocol === "wss:") return Boolean(url.hostname);
  return developmentMode && url.protocol === "ws:" && (isLocalHostname(url.hostname) || url.hostname === "52.78.173.46");
}

export function isValidDashboardBaseUrl(value, { developmentMode = true } = {}) {
  if (value === "") return true;
  const url = safeUrl(value);
  if (!url || url.username || url.password || url.search || url.hash) return false;
  if (url.protocol === "https:") return Boolean(url.hostname);
  return developmentMode && url.protocol === "http:" && isLocalHostname(url.hostname);
}
