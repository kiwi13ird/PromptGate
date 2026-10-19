import { GATEWAY_PROBE_HOST, SUPPORTED_LLM_DOMAINS } from "./protected-domains.js";
import { isValidGatewayHost, isValidPort } from "../utils/validation.js";

export function buildSelectivePacScript(settings) {
  const host = settings?.gateway?.host?.trim();
  const port = settings?.gateway?.port;
  if (!isValidGatewayHost(host)) throw new Error("Gateway host/IP is invalid.");
  if (!isValidPort(port)) throw new Error("Gateway port must be 1–65535.");
  const checks = SUPPORTED_LLM_DOMAINS.map((domain) => `(host == "${domain}" || shExpMatch(host, "*.${domain}"))`);
  checks.push(`host == "${GATEWAY_PROBE_HOST}"`);
  return `function FindProxyForURL(url, host) {\n  if (${checks.join(" || ")}) return "PROXY ${host}:${Number(port)}";\n  return "DIRECT";\n}`;
}
