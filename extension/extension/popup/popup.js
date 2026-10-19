import { EVENT_CHANNEL_STATES, GATEWAY_STATES, SECURITY_ACTIONS } from "../config/statuses.js";
import { EXTENSION_VERSION } from "../routing/protected-domains.js";
import { notificationText } from "../event-channel/notification-service.js";
import { accessView } from "../services/access-state.js";
import { ACTION_STATS_KEY, actionStatsView } from "../services/action-stats.js";
import { isValidViewerKey } from "../utils/validation.js";

const $ = (id) => document.getElementById(id);
const send = (type, extra = {}) => chrome.runtime.sendMessage({ type, ...extra });
const SVG_NS = "http://www.w3.org/2000/svg";
const RECENT_EVENT_COUNT = 3;
let busy = false;
let latest;
let storedStats;   // chrome.storage.local의 actionStats(차단·마스킹 집계). 못 읽으면 undefined -> 집계 없음으로 취급

// 사용자에게 보이는 말은 쉬운 말로: Proxy→연결 설정, Gateway→보안 서버, Event 채널→실시간 알림
const GATEWAY_LABELS = {
  [GATEWAY_STATES.HEALTHY]: "정상",
  [GATEWAY_STATES.DEGRADED]: "응답 느림",
  [GATEWAY_STATES.UNSUPPORTED]: "상태 확인 미지원",
  [GATEWAY_STATES.OFFLINE]: "연결 실패",
  [GATEWAY_STATES.PROXY_ERROR]: "연결 오류",
  [GATEWAY_STATES.CONFLICT]: "설정 충돌",
  [GATEWAY_STATES.CONFIGURATION_ERROR]: "설정 오류",
  [GATEWAY_STATES.UNKNOWN]: "확인 중",
  [GATEWAY_STATES.DISABLED]: "꺼짐"
};
const EVENT_CHANNEL_LABELS = {
  [EVENT_CHANNEL_STATES.DISABLED]: "꺼짐",
  [EVENT_CHANNEL_STATES.CONNECTING]: "연결 중",
  [EVENT_CHANNEL_STATES.CONNECTED]: "연결됨",
  [EVENT_CHANNEL_STATES.RECONNECTING]: "다시 연결 중",
  [EVENT_CHANNEL_STATES.DISCONNECTED]: "끊김",
  [EVENT_CHANNEL_STATES.ERROR]: "오류"
};
const PROTECTING_DETAIL = "AI 사이트에 보내는 내용을 검사하고 있습니다.";
const ASK_ADMIN = "계속되면 보안 관리자에게 문의해 주세요.";

function stateClass(state) {
  if ([GATEWAY_STATES.HEALTHY, EVENT_CHANNEL_STATES.CONNECTED].includes(state)) return "healthy";
  if ([GATEWAY_STATES.DEGRADED, GATEWAY_STATES.UNSUPPORTED, GATEWAY_STATES.UNKNOWN, EVENT_CHANNEL_STATES.CONNECTING, EVENT_CHANNEL_STATES.RECONNECTING].includes(state)) return "degraded";
  if ([GATEWAY_STATES.DISABLED, EVENT_CHANNEL_STATES.DISABLED].includes(state)) return "unknown";
  return "error";
}
// kind: "error"(빨강) | "neutral"(회색: 진행 중·꺼짐) | 그 밖(초록)
function tell(message, kind = "") { const notice = $("notice"); notice.textContent = message; notice.className = message ? `show ${kind === true ? "error" : kind}`.trim() : ""; }
function masterLocked(policy) { return policy?.lockedFields?.includes("runtime.desiredProtection") === true; }
function proxyApplied(proxy) { return proxy.levelOfControl === "controlled_by_this_extension" && proxy.mode === "pac_script" && proxy.matchesSettings === true; }

function proxyPresentation(model, proxy) {
  if (!model.runtimeState.desiredProtection) {
    if (!["controlled_by_this_extension", "controllable_by_this_extension"].includes(proxy.levelOfControl)) return { label: "다른 곳에서 제어 중", detail: "다른 확장 프로그램이나 Chrome 정책이 연결 설정을 제어하고 있습니다.", state: "error" };
    return { label: "미적용", detail: "모든 사이트가 직접 연결됩니다.", state: "unknown" };
  }
  if (proxyApplied(proxy)) return { label: "적용됨", detail: "AI 사이트만 보안 서버를 거칩니다.", state: "healthy" };
  if (proxy.levelOfControl === "controlled_by_this_extension" && proxy.mode === "pac_script") return { label: "설정 불일치", detail: "연결 설정이 저장된 설정과 다릅니다.", state: "error" };
  return { label: "충돌", detail: "다른 확장 프로그램이나 Chrome 정책이 연결 설정을 제어하고 있습니다.", state: "error" };
}

// 맨 위 상태 한 칸: tone = ok(초록) | warn(노랑) | off(회색) | neutral(확인 중). 보호와 상관없는 항목(실시간 알림 연결 등)은 색을 바꾸지 않는다
// 제목은 짧은 명사형, 설명은 '무슨 일인지'와 사용자가 할 일(대부분 보안 관리자 문의)
function overallView(model, proxy, policy) {
  const runtime = model.runtimeState;
  if (!runtime.desiredProtection) return { tone: "off", title: "보호 꺼짐", detail: "AI 사이트가 보안 검사 없이 연결됩니다." };
  if (!model.settings.gateway.host) return { tone: "warn", title: "설정 필요", detail: "설정에서 보안 서버 주소를 입력해 주세요." };
  if (!proxyApplied(proxy)) return { tone: "warn", title: "보호 설정 문제", detail: proxy.levelOfControl === "controlled_by_this_extension" ? "연결 설정이 어긋났습니다. 설정에서 ‘저장하고 보호 켜기’를 눌러 주세요." : `다른 확장 프로그램이 연결 설정을 바꿨습니다. ${ASK_ADMIN}` };
  switch (runtime.gatewayState) {
    case GATEWAY_STATES.OFFLINE: return { tone: "warn", title: "보안 서버 연결 안 됨", detail: `AI 사이트를 잠시 쓸 수 없습니다. ${ASK_ADMIN}` };
    case GATEWAY_STATES.PROXY_ERROR: return { tone: "warn", title: "보안 서버 연결 오류", detail: `AI 사이트가 열리지 않을 수 있습니다. ${ASK_ADMIN}` };
    case GATEWAY_STATES.CONFLICT:
    case GATEWAY_STATES.CONFIGURATION_ERROR: return { tone: "warn", title: "보호 설정 문제", detail: `설정에서 보안 서버 주소를 확인해 주세요. ${ASK_ADMIN}` };
    case GATEWAY_STATES.DEGRADED: return { tone: "ok", title: "보호 중", detail: "보안 서버 응답이 평소보다 느립니다." };
    case GATEWAY_STATES.HEALTHY: return { tone: "ok", title: "보호 중", detail: PROTECTING_DETAIL };
    case GATEWAY_STATES.UNSUPPORTED: return { tone: "ok", title: "보호 중", detail: `${PROTECTING_DETAIL} 보안 서버 상태는 확인할 수 없습니다.` };
    case GATEWAY_STATES.UNKNOWN: return { tone: "neutral", title: "상태 확인 중", detail: "잠시 기다려 주세요." };
    default: return { tone: "warn", title: "상태를 확인할 수 없습니다", detail: `창을 닫았다 다시 열어 주세요. ${ASK_ADMIN}` };   // 모르는 상태에서는 안심시키지 않는다
  }
}

function updateDisabledState(policy) {
  $("masterToggle").disabled = busy || masterLocked(policy);
  $("refresh").disabled = busy;
}

// 오늘이면 시각, 이전이면 날짜만
function formatTime(timestamp) {
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) return "시간 없음";
  const date = new Date(parsed);
  return date.toDateString() === new Date().toDateString() ? date.toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit" }) : `${date.getMonth() + 1}/${date.getDate()}`;
}

async function copyText(value) {
  try { await navigator.clipboard.writeText(value); return true; }
  catch {
    const field = document.createElement("textarea"); field.value = value; field.setAttribute("readonly", ""); field.style.position = "fixed"; field.style.opacity = "0"; document.body.append(field); field.select();
    try { return document.execCommand("copy"); } finally { field.remove(); }
  }
}

function copyIcon() {
  const svg = document.createElementNS(SVG_NS, "svg"); svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true");
  const back = document.createElementNS(SVG_NS, "path"); back.setAttribute("d", "M5 15V5a2 2 0 0 1 2-2h10");
  const front = document.createElementNS(SVG_NS, "rect"); front.setAttribute("x", "9"); front.setAttribute("y", "7"); front.setAttribute("width", "12"); front.setAttribute("height", "14"); front.setAttribute("rx", "2");
  svg.append(back, front); return svg;
}

// 한 줄: 서비스 · 무슨 일(알림 제목과 같은 문구) · 시각. 이벤트 번호는 화면에 드러내지 않고 '문의 번호 복사' 버튼으로만 준다(관리자 문의용)
function eventSummary(event) {
  const title = notificationText(event)?.title;
  if (title) return title;
  return event.action === SECURITY_ACTIONS.MASK ? "민감정보 마스킹" : event.action === SECURITY_ACTIONS.BLOCK ? "요청 차단됨" : "허용됨";
}

function createEventItem(event) {
  const item = document.createElement("div"); item.className = "event-item";
  const dot = document.createElement("span"); dot.className = `event-dot ${event.action.toLowerCase()}`; dot.setAttribute("aria-hidden", "true");
  const reason = document.createElement("span"); reason.className = "event-reason"; reason.textContent = `${event.targetLlm} · ${eventSummary(event)}`; reason.title = reason.textContent;
  const time = document.createElement("span"); time.className = "event-time"; time.textContent = formatTime(event.timestamp);
  const copy = document.createElement("button"); copy.type = "button"; copy.className = "icon-button"; copy.title = "문의 번호 복사"; copy.setAttribute("aria-label", `${reason.textContent} ${time.textContent} 문의 번호 복사`); copy.append(copyIcon());
  copy.addEventListener("click", async () => {
    try { const copied = await copyText(event.eventId); tell(copied ? "문의 번호를 복사했습니다. 관리자에게 문의할 때 붙여 넣어 주세요." : "문의 번호를 복사하지 못했습니다.", !copied); }
    catch { tell("문의 번호를 복사하지 못했습니다.", true); }
  });
  item.append(dot, reason, time, copy); return item;
}

function renderEvents(events) {
  const container = $("recentSecurityEvents"); container.replaceChildren();
  if (!events.length) { const empty = document.createElement("p"); empty.className = "empty-event"; empty.textContent = "최근 차단·마스킹 기록이 없습니다."; container.append(empty); return; }
  for (const event of events.slice(0, RECENT_EVENT_COUNT)) container.append(createEventItem(event));
}

// 1.4.5: 사용 제한 빨간 카드(차단 중일 때만). 모든 글자는 textContent로만 넣는다
function renderAccessCard(card) {
  $("accessCard").hidden = !card;
  const rows = $("accessRows"); rows.replaceChildren();
  if (!card) return;
  $("accessTitle").textContent = card.title;
  $("accessContact").textContent = card.contact;
  for (const { label, value } of card.rows) {
    const row = document.createElement("div"); const term = document.createElement("dt"); const description = document.createElement("dd");
    term.textContent = label; description.textContent = value; row.append(term, description); rows.append(row);
  }
}

// 1.4.8: 차단·마스킹 현황. 숫자가 없는 상태(확인 불가·확인 중)에서는 0 대신 문구를 보인다. 모든 글자는 textContent로만 넣는다
function renderStats() {
  if (!latest) return;
  const { model, proxy } = latest;
  const runtime = model.runtimeState;
  const view = actionStatsView(storedStats, { protectionOn: runtime.desiredProtection, configured: Boolean(model.settings.gateway.host), proxyApplied: proxyApplied(proxy), identityEnabled: model.settings.identity.enabled, hasViewerKey: isValidViewerKey(model.identity.viewerKey) }, Date.now());
  const hasNumbers = view.today !== null;
  $("stats").className = `stats ${view.tone}`;
  $("statsTable").hidden = !hasNumbers;
  $("statsNa").hidden = hasNumbers;
  $("statsNa").textContent = view.tone === "checking" ? "확인 중" : "확인 불가";
  const cells = [["statsTodayBlock", view.today?.block, "has-block"], ["statsTodayMask", view.today?.mask, "has-mask"], ["statsTotalBlock", view.total?.block, "has-block"], ["statsTotalMask", view.total?.mask, "has-mask"]];
  for (const [id, value, hasClass] of cells) {
    const cell = $(id);
    cell.textContent = Number.isFinite(value) ? value.toLocaleString("ko-KR") : "–";
    cell.className = Number.isFinite(value) && value > 0 ? hasClass : "";
  }
  // 사용 제한 기록: 차단 숫자와 따로, 있을 때만 작게(10분에 한 번만 남는 대표 기록이라는 설명 포함)
  $("statsRestricted").hidden = !view.restrictedText;
  $("statsRestrictedText").textContent = view.restrictedText;
  $("statsRestrictedNote").textContent = view.restrictedNote;
  $("statsNote").hidden = !view.note;
  $("statsNote").textContent = view.note;
  $("statsNote").className = `stats-note${view.tone === "checking" ? " neutral" : ""}`;
  $("statsCaption").textContent = view.caption;
  $("statsDot").className = `dot ${view.syncDot}`;
  $("statsStatus").textContent = view.syncText;
}

function render({ model, proxy, policy }) {
  latest = { model, proxy, policy };
  const runtime = model.runtimeState;
  const overall = overallView(model, proxy, policy);
  $("version").textContent = `v${EXTENSION_VERSION}`;
  $("hero").className = `hero ${overall.tone}`;
  $("overall").textContent = overall.title;
  $("stateDetail").textContent = overall.detail;
  $("masterSwitch").hidden = false;
  $("recent").hidden = false;
  $("masterToggle").checked = runtime.desiredProtection;
  $("masterValue").textContent = runtime.desiredProtection ? "켜짐" : "꺼짐";
  $("masterPolicy").hidden = !masterLocked(policy);
  $("policyStatus").hidden = !policy.active;
  $("policyStatus").textContent = policy.mode === "managed" ? "모든 설정을 관리자가 관리합니다." : "일부 설정을 관리자가 관리합니다.";

  const proxyView = proxyPresentation(model, proxy);
  $("proxyDot").className = `dot ${proxyView.state}`;
  $("proxyStatus").textContent = proxyView.label;
  $("proxyMeta").textContent = proxyView.detail;

  const gatewayState = runtime.desiredProtection ? runtime.gatewayState : GATEWAY_STATES.DISABLED;
  $("gatewayDot").className = `dot ${stateClass(gatewayState)}`;
  $("gateway").textContent = `${GATEWAY_LABELS[gatewayState] || "확인 중"}${runtime.lastHealthLatencyMs !== null && [GATEWAY_STATES.HEALTHY, GATEWAY_STATES.DEGRADED].includes(gatewayState) ? ` · ${runtime.lastHealthLatencyMs} ms` : ""}`;
  $("gatewayMeta").textContent = `${model.settings.gateway.host || "주소 미설정"}${model.settings.gateway.host ? `:${model.settings.gateway.port}` : ""}`;
  $("lastCheck").textContent = runtime.lastHealthAt ? `마지막 확인 ${new Date(runtime.lastHealthAt).toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit" })}` : "마지막 확인 기록 없음";

  const channelState = runtime.desiredProtection && model.settings.eventChannel.enabled ? runtime.eventChannelStatus : EVENT_CHANNEL_STATES.DISABLED;
  $("eventChannelDot").className = `dot ${stateClass(channelState)}`;
  $("eventChannelStatus").textContent = EVENT_CHANNEL_LABELS[channelState] || "확인 중";
  const clientId = model.identity.clientId;
  $("clientStatus").textContent = clientId ? `…${clientId.slice(-8)}` : "확인 불가";
  const access = accessView(model.accessState, { active: runtime.desiredProtection && proxyApplied(proxy), identityEnabled: model.settings.identity.enabled });
  $("accessDot").className = `dot ${access.dot}`;
  $("accessStatus").textContent = access.statusText;
  renderAccessCard(access.card);
  if (access.card) { $("hero").className = "hero slim"; $("overall").textContent = "보호"; }   // 사용 제한 중: 빨간 카드가 주인공, 초록 '보호 중' 칸은 '보호 [스위치]' 한 줄로 줄인다(스위치는 계속 보임)
  renderEvents(model.recentSecurityEvents || []);
  $("stats").hidden = false;
  renderStats();

  updateDisabledState(policy);
}

// 상태를 못 불러왔을 때(응답 오류·통신 실패): 노란 칸만 보이고 스위치·최근 기록·사용 제한 카드는 숨긴다(오래된 정보로 안심시키지 않음)
function showLoadError() {
  $("hero").className = "hero warn";
  $("overall").textContent = "확장 프로그램 오류";
  $("stateDetail").textContent = `상태를 불러오지 못했습니다. 창을 닫았다 다시 열어 주세요. ${ASK_ADMIN}`;
  $("accessCard").hidden = true; $("masterSwitch").hidden = true; $("recent").hidden = true; $("stats").hidden = true;
  $("masterToggle").disabled = true;
}

async function load() {
  let response;
  try { response = await send("GET_MODEL"); } catch { response = null; }
  try { storedStats = (await chrome.storage.local.get([ACTION_STATS_KEY]))[ACTION_STATS_KEY]; } catch { storedStats = undefined; }
  if (response?.ok) render(response);
  else showLoadError();
}

// 팝업을 열 때(그리고 설정을 바꾼 뒤) 접속 제한 상태를 다시 조회한다. 결과는 저장소(accessState)가 바뀌면서 화면에 반영된다 - 응답을 기다리지 않아 GET_MODEL이 조회 뒤에 줄 서지 않는다
function requestAccessRefresh(force = false) { send("ACCESS_STATUS", { force }).catch(() => undefined); }
// 1.4.8: 차단·마스킹 집계도 같은 방식 - 응답을 기다리지 않고, 결과는 저장소(actionStats)가 바뀌면서 화면에 반영된다
function requestStatsRefresh(force = false) { send("ACTION_STATS_SYNC", { force }).catch(() => undefined); }

async function runChange(message, successMessage, successKind = "") {
  if (busy) return;
  busy = true; tell("적용 중입니다…", "neutral"); if (latest) updateDisabledState(latest.policy);
  try {
    const response = await chrome.runtime.sendMessage(message);
    if (!response?.ok) tell(response?.errorMessage || "설정을 적용하지 못했습니다.", true);
    else tell(successMessage, successKind);
  } catch { tell("확장 프로그램과 통신하지 못했습니다.", true); }
  finally { busy = false; await load(); requestAccessRefresh(true); }
}

$("masterToggle").addEventListener("change", () => runChange({ type: "SET_MASTER", enabled: $("masterToggle").checked }, $("masterToggle").checked ? "보호를 켰습니다." : "보호를 껐습니다.", $("masterToggle").checked ? "" : "neutral").then(() => requestStatsRefresh(true)));
$("refresh").addEventListener("click", () => runChange({ type: "HEALTH" }, "상태를 새로고침했습니다.").then(() => requestStatsRefresh(true)));
$("openSettings").addEventListener("click", () => chrome.runtime.openOptionsPage());
// 내 요청 기록(1.4.3): 확장 프로그램 안의 페이지를 연다. 기록은 그 페이지가 보호 상태를 확인한 뒤 Gateway(llm-gateway.local)를 거쳐 읽는다
$("openLogs").addEventListener("click", async () => {
  try { await chrome.tabs.create({ url: chrome.runtime.getURL("myrequests/myrequests.html") }); }
  catch { tell("내 요청 기록 페이지를 열지 못했습니다.", true); }
});
chrome.storage.onChanged.addListener((changes, areaName) => { if (areaName === "local" && (changes.runtimeState || changes.recentSecurityEvents || changes.settings || changes.accessState)) load(); });
chrome.storage.onChanged.addListener((changes, areaName) => { if (areaName === "local" && changes[ACTION_STATS_KEY]) { storedStats = changes[ACTION_STATS_KEY].newValue; renderStats(); } });
load().then(() => requestAccessRefresh(false));
requestStatsRefresh(false);
