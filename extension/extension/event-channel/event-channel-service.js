import { EVENT_RECONNECT_ALARM, EVENT_RECONNECT_DELAYS_MS } from "../config/defaults.js";
import { EVENT_CHANNEL_STATES } from "../config/statuses.js";
import { isValidEventChannelUrl, isValidIdentity } from "../utils/validation.js";
import { parseEventChannelMessage } from "./event-validator.js";

export function reconnectDelay(attempt, random = Math.random) {
  const base = EVENT_RECONNECT_DELAYS_MS[Math.min(Math.max(0, attempt), EVENT_RECONNECT_DELAYS_MS.length - 1)];
  const sample = Math.min(1, Math.max(0, Number(random()) || 0));
  return Math.round(base * (0.9 + sample * 0.2));
}

export function createEventChannelService({
  readSettings,
  updateRuntime,
  storeEvent,
  notifyEvent,
  WebSocketImpl = globalThis.WebSocket,
  alarms = chrome.alarms,
  setTimer = globalThis.setTimeout,
  clearTimer = globalThis.clearTimeout,
  now = Date.now,
  random = Math.random,
  logger = console
}) {
  let socket = null;
  let reconnectTimer = null;
  let reconnectAttempt = 0;
  let generation = 0;
  let desired = { enabled: false, url: "", developmentMode: true, protectionEnabled: false, clientId: "" };
  let eventQueue = Promise.resolve();
  let runtimeQueue = Promise.resolve();

  const safeRuntimeUpdate = (patch) => {
    runtimeQueue = runtimeQueue.then(() => updateRuntime(patch)).catch(() => logger.warn("Event Channel 상태를 저장하지 못했습니다."));
    return runtimeQueue;
  };
  const clearReconnectAlarm = () => {
    try {
      const result = alarms.clear(EVENT_RECONNECT_ALARM);
      if (result && typeof result.catch === "function") result.catch(() => undefined);
    } catch { /* alarm cleanup is best effort */ }
  };
  const clearReconnect = () => {
    if (reconnectTimer !== null) clearTimer(reconnectTimer);
    reconnectTimer = null;
    clearReconnectAlarm();
  };
  const isActiveSocket = () => socket && (socket.readyState === 0 || socket.readyState === 1);

  const processMessage = (data) => {
    const parsed = parseEventChannelMessage(data, { expectedClientId: desired.clientId });
    if (["HEARTBEAT", "IGNORED_ACTION"].includes(parsed?.kind)) return;
    if (parsed?.kind !== "SECURITY_EVENT") { logger.warn("형식이 올바르지 않은 Event Channel 메시지를 무시했습니다."); return; }
    eventQueue = eventQueue.then(async () => {
      const result = await storeEvent(parsed.event);
      if (!result.stored) return;
      await notifyEvent(result.event);
      await safeRuntimeUpdate({ lastSecurityEventAt: result.event.timestamp });
    }).catch(() => logger.warn("Security Event 처리 중 오류를 격리했습니다."));
  };

  const scheduleReconnect = async () => {
    if (!desired.protectionEnabled || !desired.enabled || !desired.url || reconnectTimer !== null) return;
    const delay = reconnectDelay(reconnectAttempt, random);
    reconnectAttempt += 1;
    await safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.RECONNECTING, eventChannelError: "", eventReconnectAttempt: reconnectAttempt });
    reconnectTimer = setTimer(() => { reconnectTimer = null; clearReconnectAlarm(); connect(true); }, delay);
    try {
      const alarmResult = alarms.create(EVENT_RECONNECT_ALARM, { when: now() + delay });
      if (alarmResult && typeof alarmResult.catch === "function") alarmResult.catch(() => undefined);
    } catch { /* timer remains active while the worker is alive */ }
  };

  const connect = async (reconnecting = false) => {
    if (!desired.protectionEnabled || !desired.enabled || !desired.url || isActiveSocket()) return;
    clearReconnect();
    const token = ++generation;
    await safeRuntimeUpdate({ eventChannelStatus: reconnecting ? EVENT_CHANNEL_STATES.RECONNECTING : EVENT_CHANNEL_STATES.CONNECTING, eventChannelError: "", eventReconnectAttempt: reconnectAttempt });
    try { socket = new WebSocketImpl(desired.url); }
    catch (error) {
      socket = null;
      await safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.ERROR, eventChannelError: String(error?.message || error).slice(0, 250) });
      await scheduleReconnect();
      return;
    }
    socket.addEventListener("open", () => {
      if (token !== generation) return;
      try {
        socket.send(JSON.stringify({ type: "REGISTER", clientId: desired.clientId }));
        reconnectAttempt = 0;
        clearReconnect();
        safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.CONNECTED, eventChannelError: "", eventReconnectAttempt: 0 });
      } catch {
        safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.ERROR, eventChannelError: "Client registration failed" });
        try { socket.close(); } catch { scheduleReconnect(); }
      }
    });
    socket.addEventListener("message", (message) => { if (token === generation) processMessage(message.data); });
    socket.addEventListener("error", () => {
      if (token !== generation) return;
      safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.ERROR, eventChannelError: "WebSocket connection error" });
      try { socket.close(); } catch { scheduleReconnect(); }
    });
    socket.addEventListener("close", () => {
      if (token !== generation) return;
      socket = null;
      scheduleReconnect();
    });
  };

  const stop = async (status = EVENT_CHANNEL_STATES.DISABLED) => {
    generation += 1;
    clearReconnect();
    const previous = socket;
    socket = null;
    if (previous) { try { previous.close(); } catch { /* already closed */ } }
    reconnectAttempt = 0;
    await safeRuntimeUpdate({ eventChannelStatus: status, eventChannelError: "", eventReconnectAttempt: 0 });
  };

  const sync = async ({ force = false } = {}) => {
    const settings = await readSettings();
    const eventChannel = settings?.eventChannel || {};
    const next = { enabled: eventChannel.enabled === true, url: typeof eventChannel.url === "string" ? eventChannel.url : "", developmentMode: settings?.developmentMode !== false, protectionEnabled: settings?.protectionEnabled === true, clientId: typeof settings?.clientId === "string" ? settings.clientId.trim() : "" };
    if (!next.protectionEnabled || !next.enabled || !next.url) { desired = next; await stop(EVENT_CHANNEL_STATES.DISABLED); return; }
    if (!isValidEventChannelUrl(next.url, { developmentMode: next.developmentMode })) {
      desired = next;
      await stop(EVENT_CHANNEL_STATES.ERROR);
      await safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.ERROR, eventChannelError: "Invalid Event Channel URL" });
      return;
    }
    if (!isValidIdentity(next.clientId)) {
      desired = next;
      await stop(EVENT_CHANNEL_STATES.ERROR);
      await safeRuntimeUpdate({ eventChannelStatus: EVENT_CHANNEL_STATES.ERROR, eventChannelError: "Invalid Client ID" });
      return;
    }
    const changed = desired.url !== next.url || desired.enabled !== next.enabled || desired.clientId !== next.clientId || desired.protectionEnabled !== next.protectionEnabled;
    desired = next;
    if (!force && !changed && isActiveSocket()) return;
    if (changed && socket) await stop(EVENT_CHANNEL_STATES.DISCONNECTED);
    desired = next;
    if (changed) reconnectAttempt = 0;
    await connect(force || reconnectAttempt > 0);
  };

  const reconnectFromAlarm = async () => {
    if (reconnectTimer !== null) { clearTimer(reconnectTimer); reconnectTimer = null; }
    clearReconnectAlarm();
    await sync({ force: true });
  };

  return { sync, stop, reconnectFromAlarm, inspect: () => ({ desired: { ...desired }, reconnectAttempt, hasSocket: Boolean(socket), hasReconnectTimer: reconnectTimer !== null }) };
}
