import { GATEWAY_PROFILES, GATEWAY_STATES, SECURITY_ACTIONS } from "../config/statuses.js";
import { EXTENSION_VERSION, supportedServiceLabels } from "../routing/protected-domains.js";
import { isValidDashboardBaseUrl, isValidEventChannelUrl, isValidGatewayHost, isValidIdentity, isValidPort } from "../utils/validation.js";

const $ = (id) => document.getElementById(id);
const send = (type, extra = {}) => chrome.runtime.sendMessage({ type, ...extra });
const STATE_LABELS = { [GATEWAY_STATES.HEALTHY]: "정상", [GATEWAY_STATES.DEGRADED]: "응답 느림", [GATEWAY_STATES.UNSUPPORTED]: "상태 확인 미지원", [GATEWAY_STATES.OFFLINE]: "연결 실패", [GATEWAY_STATES.PROXY_ERROR]: "연결 오류", [GATEWAY_STATES.CONFLICT]: "설정 충돌", [GATEWAY_STATES.CONFIGURATION_ERROR]: "설정 오류", [GATEWAY_STATES.UNKNOWN]: "상태 확인 중", [GATEWAY_STATES.DISABLED]: "보호 꺼짐" };
let current;
let policy;

function tell(message, error = false) { const notice = $("notice"); notice.textContent = message; notice.className = "show"; notice.style.background = error ? "#fde8e7" : "#e8f5ed"; }
function isLocked(name) { return policy?.lockedFields?.includes(name) === true; }
function formSettings() {
  return {
    ...current.settings,
    gateway: { host: $("gatewayHost").value.trim(), port: Number($("gatewayPort").value), profile: $("gatewayProfile").value },
    identity: { enabled: $("identityEnabled").checked, tenantId: $("tenantId").value.trim() },
    eventChannel: { enabled: $("eventChannelEnabled").checked, url: $("eventChannelUrl").value.trim() },
    dashboard: { baseUrl: $("dashboardBaseUrl").value.trim() },
    developerToolsEnabled: $("developerToolsEnabled").checked
  };
}
function validate(settings) {
  if (!isValidGatewayHost(settings.gateway.host)) return "올바른 게이트웨이 Host 또는 IPv4 주소를 입력해 주세요.";
  if (!isValidPort(settings.gateway.port)) return "게이트웨이 포트는 1~65535 범위여야 합니다.";
  if (settings.identity.enabled && (!isValidIdentity(current.identity.clientId) || !isValidIdentity(settings.identity.tenantId))) return "클라이언트 ID와 테넌트 ID는 영문, 숫자, 점, 밑줄, 하이픈만 1~64자로 입력할 수 있습니다.";
  if (settings.eventChannel.enabled && (!settings.eventChannel.url || !isValidEventChannelUrl(settings.eventChannel.url, { developmentMode: settings.developmentMode }))) return "Event Channel은 운영 WSS 또는 Development Mode의 localhost WS 주소를 입력해 주세요.";
  if (!isValidDashboardBaseUrl(settings.dashboard.baseUrl, { developmentMode: settings.developmentMode })) return "Dashboard Base URL은 운영 HTTPS 또는 Development Mode의 localhost HTTP 주소여야 합니다.";
  return "";
}

function refreshConditionalControls() {
  $("eventChannelUrl").disabled = !$("eventChannelEnabled").checked || isLocked("eventChannel.url");
  $("developmentEventTools").hidden = !current?.settings.developmentMode || !$("developerToolsEnabled").checked;
  if (current && policy) $("enable").disabled = isLocked("runtime.desiredProtection") || policy.values?.protectionEnabled === false;
}

function fill(model, managedPolicy) {
  current = model;
  policy = managedPolicy;
  const settings = model.settings;
  $("extensionVersion").textContent = `v${EXTENSION_VERSION}`;
  $("gatewayProfile").value = settings.gateway.profile;
  $("gatewayHost").value = settings.gateway.host;
  $("gatewayPort").value = settings.gateway.port;
  $("clientId").value = model.identity.clientId;
  $("tenantId").value = settings.identity.tenantId;
  $("identityEnabled").checked = settings.identity.enabled;
  $("eventChannelEnabled").checked = settings.eventChannel.enabled;
  $("eventChannelUrl").value = settings.eventChannel.url;
  $("dashboardBaseUrl").value = settings.dashboard.baseUrl;
  $("developerToolsEnabled").checked = settings.developerToolsEnabled;
  $("developmentEventTools").hidden = !settings.developmentMode || !settings.developerToolsEnabled;
  for (const [id, field] of [["gatewayProfile", "gateway.port"], ["gatewayHost", "gateway.host"], ["gatewayPort", "gateway.port"], ["tenantId", "identity.tenantId"], ["identityEnabled", "identity.enabled"], ["eventChannelEnabled", "eventChannel.enabled"], ["eventChannelUrl", "eventChannel.url"], ["dashboardBaseUrl", "dashboard.baseUrl"], ["developerToolsEnabled", "developerToolsEnabled"]]) $(id).disabled = isLocked(field);
  const protectionLocked = managedPolicy.lockedFields.includes("runtime.desiredProtection");
  const forcedProtection = managedPolicy.values?.protectionEnabled;
  $("disable").disabled = protectionLocked || forcedProtection === true;
  $("enable").disabled = protectionLocked || forcedProtection === false;
  $("save").disabled = managedPolicy.mode === "managed";
  if (!managedPolicy.active) $("policyStatus").textContent = "적용된 관리자 정책이 없습니다. 개발 설정을 직접 변경할 수 있습니다.";
  else if (managedPolicy.errors.length) $("policyStatus").textContent = "관리자 정책 형식에 오류가 있어 안전하게 적용하지 않았습니다. 관리자에게 문의해 주세요.";
  else if (managedPolicy.mode === "managed") $("policyStatus").textContent = "Enterprise/Managed Mode입니다. Gateway, Routing, Event Channel 설정은 관리자 정책을 따릅니다.";
  else $("policyStatus").textContent = "Development Mode이며 일부 항목에 관리자 정책이 적용되어 있습니다.";
  const errorList = $("policyErrors"); errorList.replaceChildren(...managedPolicy.errors.map((error) => { const item = document.createElement("li"); item.textContent = error; return item; })); errorList.hidden = managedPolicy.errors.length === 0;
  $("currentState").textContent = `${model.runtimeState.desiredProtection ? STATE_LABELS[model.runtimeState.gatewayState] || "상태 확인 중" : "보호 꺼짐"}`;
  refreshConditionalControls();
}

async function reload() {
  const response = await send("GET_MODEL");
  if (!response?.ok) return tell(response?.errorMessage || "확장 프로그램 상태를 불러오지 못했습니다.", true);
  fill(response.model, response.policy);
}

async function save(enable) {
  const settings = formSettings();
  const validationError = validate(settings);
  if (validationError) return tell(validationError, true);
  const response = await send(enable ? "APPLY" : "SAVE_SETTINGS", { settings });
  if (!response?.ok) {
    $("diagnostics").textContent = JSON.stringify({ error_code: response?.errorCode, technical_detail: response?.technicalDetail, timestamp: response?.timestamp }, null, 2);
    return tell(response?.errorMessage || "작업을 완료하지 못했습니다.", true);
  }
  tell(enable ? "설정을 저장하고 보호 경로에 적용했습니다." : "설정을 저장했습니다. 현재 보호 상태는 변경하지 않았습니다.");
  await reload();
}

function safeReport() {
  const model = current;
  return {
    exportedAt: new Date().toISOString(),
    extensionVersion: EXTENSION_VERSION,
    storageSchemaVersion: model.settings.schemaVersion,
    client: { clientId: model.identity.clientId, tenantId: model.settings.identity.tenantId },
    configuration: { desiredProtection: model.runtimeState.desiredProtection, gateway: model.settings.gateway, routingPolicy: "SUPPORTED_LLM_DOMAINS", supportedLlmTargets: supportedServiceLabels(), identityHeadersEnabled: model.settings.identity.enabled, eventChannelEnabled: model.settings.eventChannel.enabled, eventChannelUrl: model.settings.eventChannel.url, dashboardBaseUrl: model.settings.dashboard.baseUrl, policyMode: policy.mode },
    runtime: model.runtimeState,
    events: model.events,
    recentSecurityEvents: model.recentSecurityEvents,
    backup: { settings: model.settings, identity: { clientId: model.identity.clientId }, desiredProtection: model.runtimeState.desiredProtection },
    privacy: "Prompt/응답 원문, 첨부파일 원문, 탐지 문자열, URL 경로·쿼리, Cookie, Authorization, API Key, 비밀번호는 포함하지 않습니다."
  };
}

function downloadReport() { const blob = new Blob([JSON.stringify(safeReport(), null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `llmsgw-diagnostics-${new Date().toISOString().replace(/[:.]/g, "-")}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); }
async function simulate(action) { const response = await send("SIMULATE_SECURITY_EVENT", { action }); tell(response?.ok ? `${action} 개발 이벤트를 저장하고 알림을 요청했습니다.` : response?.errorMessage || "개발 이벤트를 생성하지 못했습니다.", !response?.ok); await reload(); }

$("gatewayProfile").addEventListener("change", () => { const profile = $("gatewayProfile").value; if (profile === GATEWAY_PROFILES.M1_TEST) $("gatewayPort").value = "8081"; if (profile === GATEWAY_PROFILES.M2_TEST) $("gatewayPort").value = "8080"; });
$("gatewayPort").addEventListener("input", () => { const port = Number($("gatewayPort").value); const profile = $("gatewayProfile").value; if ((profile === GATEWAY_PROFILES.M1_TEST && port !== 8081) || (profile === GATEWAY_PROFILES.M2_TEST && port !== 8080)) $("gatewayProfile").value = GATEWAY_PROFILES.CUSTOM; });
$("eventChannelEnabled").addEventListener("change", refreshConditionalControls);
$("developerToolsEnabled").addEventListener("change", refreshConditionalControls);
$("save").addEventListener("click", () => save(false));
$("enable").addEventListener("click", () => save(true));
$("disable").addEventListener("click", async () => { const response = await send("DISABLE"); tell(response?.ok ? "보호를 껐습니다." : response?.errorMessage || "보호를 끄지 못했습니다.", !response?.ok); await reload(); });
$("health").addEventListener("click", async () => { $("diagnostics").textContent = "게이트웨이 상태를 확인하고 있습니다…"; const response = await send("HEALTH"); $("diagnostics").textContent = JSON.stringify(response?.result ?? response, null, 2); await reload(); });
$("stats").addEventListener("click", async () => { $("diagnostics").textContent = "게이트웨이 통계를 확인하고 있습니다…"; const response = await send("STATS"); $("diagnostics").textContent = JSON.stringify(response?.result ?? response, null, 2); });
$("export").addEventListener("click", downloadReport);
$("import").addEventListener("click", () => $("importFile").click());
$("testBlock").addEventListener("click", () => simulate(SECURITY_ACTIONS.BLOCK));
$("testMask").addEventListener("click", () => simulate(SECURITY_ACTIONS.MASK));
$("clearSecurityEvents").addEventListener("click", async () => { await send("CLEAR_SECURITY_EVENTS"); tell("Security Event 기록을 삭제했습니다."); await reload(); });
$("importFile").addEventListener("change", async () => {
  const file = $("importFile").files?.[0];
  if (!file) return;
  if (file.size > 256 * 1024) { tell("가져오기 파일은 256KB 이하여야 합니다.", true); return; }
  try {
    const report = JSON.parse(await file.text());
    const response = await send("IMPORT_BACKUP", { report });
    if (!response?.ok) { $("diagnostics").textContent = JSON.stringify({ error_code: response?.errorCode, technical_detail: response?.technicalDetail, timestamp: response?.timestamp }, null, 2); tell(response?.errorMessage || "백업을 가져오지 못했습니다.", true); return; }
    tell(response.protectionRestored ? "설정과 클라이언트 ID를 복원하고 보호를 다시 적용했습니다." : "설정과 클라이언트 ID를 복원했습니다."); await reload();
  } catch (error) { tell("JSON 파일 형식이 올바르지 않습니다.", true); $("diagnostics").textContent = JSON.stringify({ error_code: "IMPORT_PARSE_ERROR", technical_detail: String(error?.message || error), timestamp: new Date().toISOString() }, null, 2); }
  finally { $("importFile").value = ""; }
});
$("clearEvents").addEventListener("click", async () => { await send("CLEAR_EVENTS"); tell("확장 프로그램 이벤트 기록을 삭제했습니다."); await reload(); });
reload();
