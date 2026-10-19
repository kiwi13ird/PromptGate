// These domains are static Gateway routing inputs, not an LLM classification
// or security-decision source. Gateway remains authoritative for both.
export const EXTENSION_VERSION = "1.4.8";
export const GATEWAY_PROBE_HOST = "llm-gateway.local";
export const SUPPORTED_LLM_SERVICES = Object.freeze({
  chatgpt: Object.freeze({ label: "ChatGPT", domains: Object.freeze(["chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"]) }),
  gemini: Object.freeze({ label: "Gemini", domains: Object.freeze(["gemini.google.com"]) }),
  claude: Object.freeze({ label: "Claude", domains: Object.freeze(["claude.ai", "anthropic.com"]) })
});

export const SUPPORTED_LLM_DOMAINS = Object.freeze([...new Set(Object.values(SUPPORTED_LLM_SERVICES).flatMap((service) => service.domains))]);
export const supportedServiceLabels = () => Object.values(SUPPORTED_LLM_SERVICES).map((service) => service.label);
