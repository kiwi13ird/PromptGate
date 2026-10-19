import { SECURITY_ACTIONS } from "../config/statuses.js";
import { accessNotificationText } from "../services/access-state.js";

// 1.4.2: Gateway 사유 코드(reasonCode)별 고정 문구. 사유가 없거나 모르는 코드면 기존 문구
const UNINSPECTED_REASONS = new Set(["file_uninspectable_image", "file_uninspectable_scanned_pdf", "file_uninspectable_other", "file_too_large"]);
const DETECTION_DOWN_REASONS = new Set(["detection_timeout", "detection_unreachable", "detection_error", "detection_parse_error"]);
const MASK_FAILED_REASONS = new Set(["mask_application_failed", "file_masking_failed"]);
const BLOCK_REASON_TEXTS = Object.freeze({
  file_uninspectable_image: ["검사할 수 없는 파일 차단", (llm) => `${llm}에 올리려던 이미지 파일은 내용을 검사할 수 없어 전송이 차단되었습니다.`],
  file_uninspectable_scanned_pdf: ["검사할 수 없는 파일 차단", (llm) => `${llm}에 올리려던 스캔 PDF는 글자를 읽을 수 없어 전송이 차단되었습니다.`],
  file_uninspectable_other: ["검사할 수 없는 파일 차단", (llm) => `${llm}에 올리려던 파일은 검사할 수 없는 형식이라 전송이 차단되었습니다.`],
  file_too_large: ["파일이 커서 차단", (llm) => `${llm}에 올리려던 파일이 커서 제한 시간 안에 검사할 수 없어 전송이 차단되었습니다.`]
});

// 알림·팝업 공용: { title, message } 또는 알리지 않을 이벤트면 null
export function notificationText(event) {
  const llm = event?.targetLlm;
  const reason = event?.reasonCode;
  if (event?.action === SECURITY_ACTIONS.BLOCK) {
    if (Object.hasOwn(BLOCK_REASON_TEXTS, reason)) { const [title, message] = BLOCK_REASON_TEXTS[reason]; return { title, message: message(llm) }; }
    if (MASK_FAILED_REASONS.has(reason)) return { title: "마스킹할 수 없어 차단", message: `${llm} 요청에서 민감정보가 발견되었지만 마스킹할 수 없는 형식이라 전송을 막았습니다.` };
    if (DETECTION_DOWN_REASONS.has(reason) || event.degraded === true) return { title: "보안 검사 응답 없음", message: `보안 검사가 제때 끝나지 않아 ${llm} 전송을 막았습니다. 잠시 후 다시 시도해 주세요.` };
    return { title: "요청 차단됨", message: `보안 정책에 따라 ${llm} 전송을 막았습니다. 민감한 내용을 빼고 다시 보내 주세요.` };
  }
  if (event?.action === SECURITY_ACTIONS.MASK) return { title: "민감정보 마스킹", message: `${llm}에 보낸 내용 중 민감정보를 마스킹하고 전송했습니다.` };
  if (event?.action === SECURITY_ACTIONS.ALLOW && event.notify === true) {
    if (UNINSPECTED_REASONS.has(reason)) return { title: "검사 없이 전송됨", message: `${llm}에 올린 파일은 내용을 검사하지 못한 채 전송되었습니다. 관리자 기록에 남습니다.` };
    if (DETECTION_DOWN_REASONS.has(reason)) return { title: "검사 없이 전송됨", message: `보안 검사가 지연되어 ${llm} 요청이 검사 없이 전송되었습니다. 관리자 기록에 남습니다.` };
  }
  return null;
}

export function notificationOptions(event) {
  const text = notificationText(event);
  if (!text) return null;
  return {
    type: "basic",
    iconUrl: "assets/icon-128.png",
    title: text.title,
    message: text.message
  };
}

export async function notifySecurityEvent(event, notifications = chrome.notifications, runtime = chrome.runtime) {
  const options = notificationOptions(event);
  if (!options) return false;
  if (runtime?.getURL) options.iconUrl = runtime.getURL(options.iconUrl);
  return new Promise((resolve) => {
    let settled = false;
    let timeout;
    const finish = (result) => { if (!settled) { settled = true; clearTimeout(timeout); resolve(result); } };
    timeout = setTimeout(() => finish(false), 2000);
    try {
      const result = notifications.create(`llmsgw-${event.eventId}`, options, () => finish(!runtime?.lastError));
      if (result && typeof result.then === "function") result.then(() => finish(true), () => finish(false));
    } catch { finish(false); }
  });
}

// 1.4.5: 접속 제한 알림 - 처음 차단이 확인됐을 때("BLOCKED")와 풀렸을 때("UNBLOCKED") 한 번씩. 보호가 켜져 있을 때만 호출된다
export function accessNotificationOptions(change, state) {
  const text = accessNotificationText(change, state);
  if (!text) return null;
  return { type: "basic", iconUrl: "assets/icon-128.png", title: text.title, message: text.message };
}

export async function notifyAccessChange(change, state, notifications = chrome.notifications, runtime = chrome.runtime) {
  const options = accessNotificationOptions(change, state);
  if (!options) return false;
  if (runtime?.getURL) options.iconUrl = runtime.getURL(options.iconUrl);
  return new Promise((resolve) => {
    let settled = false;
    let timeout;
    const finish = (result) => { if (!settled) { settled = true; clearTimeout(timeout); resolve(result); } };
    timeout = setTimeout(() => finish(false), 2000);
    try {
      const result = notifications.create(`llmsgw-access-${change.toLowerCase()}-${Date.now()}`, options, () => finish(!runtime?.lastError));
      if (result && typeof result.then === "function") result.then(() => finish(true), () => finish(false));
    } catch { finish(false); }
  });
}
