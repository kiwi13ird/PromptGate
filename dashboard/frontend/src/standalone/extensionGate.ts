// 확장 프로그램 안 '내 요청 기록'(1.4.3)의 보호 상태 확인.
// 열람 키는 (1) 보호가 켜져 있고 (2) 이 확장 프로그램의 PAC가 지금 설정된 Gateway로 llm-gateway.local을 보내고 있을 때만 쓴다.
// 보호가 꺼지면 PAC가 해제되어 llm-gateway.local이 공용 DNS(통신사 안내 서버 등)로 풀린다. 그 상태에서 키를 보내면 외부로 나간다.
// 그래서 요청 직전마다 서비스 워커의 GET_MODEL 응답(model + proxy.matchesSettings)으로 다시 확인한다.
// proxy.matchesSettings는 현재 PAC 원문이 설정값으로 만든 PAC(llm-gateway.local → 설정된 Gateway host:port)와 같을 때만 true다.

const VIEWER_KEY = /^[A-Za-z0-9_-]{43}$/;
export const GATE_CHECK_TIMEOUT_MS = 3000;
export const PROTECTION_REQUIRED_MESSAGE = '보호가 켜져 있을 때만 기록을 볼 수 있습니다.';

export type GateBlockStatus = 'PROTECTION_OFF' | 'NOT_CONFIGURED' | 'PROXY_CONFLICT' | 'UNAVAILABLE';
export type ViewerGate =
  | { status: 'READY'; viewerKey: string; identityEnabled: boolean }
  | { status: 'NOT_READY' }
  | { status: GateBlockStatus };

type RecordLike = Record<string, unknown>;
const record = (value: unknown): RecordLike =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as RecordLike) : {};

// GET_MODEL 응답만으로 키를 보내도 되는지 정한다(순수 함수)
export function viewerGate(model: unknown, proxy: unknown): ViewerGate {
  const current = record(model);
  if (record(current.runtimeState).desiredProtection !== true) return { status: 'PROTECTION_OFF' };
  const settings = record(current.settings);
  const host = record(settings.gateway).host;
  if (typeof host !== 'string' || !host.trim()) return { status: 'NOT_CONFIGURED' };
  const pac = record(proxy);
  if (pac.levelOfControl !== 'controlled_by_this_extension' || pac.mode !== 'pac_script' || pac.matchesSettings !== true)
    return { status: 'PROXY_CONFLICT' };
  const viewerKey = record(current.identity).viewerKey;
  if (typeof viewerKey !== 'string' || !VIEWER_KEY.test(viewerKey)) return { status: 'NOT_READY' };
  return { status: 'READY', viewerKey, identityEnabled: record(settings.identity).enabled === true };
}

interface RuntimeLike {
  id?: unknown;
  sendMessage?: (message: unknown) => unknown;
}
interface StorageChangeEventLike {
  addListener?: (listener: (changes: Record<string, unknown>, areaName: string) => void) => void;
  removeListener?: (listener: (changes: Record<string, unknown>, areaName: string) => void) => void;
}
type ChromeLike = { runtime?: RuntimeLike; storage?: { onChanged?: StorageChangeEventLike } };
const chromeApi = () => (globalThis as { chrome?: ChromeLike }).chrome;

// 서비스 워커에 GET_MODEL을 묻는다. 응답이 없거나(시간 초과·오류) 형식이 다르면 UNAVAILABLE - 키를 보내지 않는다
export async function readViewerGate(timeoutMs = GATE_CHECK_TIMEOUT_MS): Promise<ViewerGate> {
  const runtime = chromeApi()?.runtime;
  if (!runtime || typeof runtime.sendMessage !== 'function' || typeof runtime.id !== 'string' || !runtime.id)
    return { status: 'UNAVAILABLE' };
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const reply = await Promise.race([
      Promise.resolve(runtime.sendMessage({ type: 'GET_MODEL' })),
      new Promise<undefined>((resolve) => { timer = setTimeout(() => resolve(undefined), timeoutMs); }),
    ]);
    const response = record(reply);
    if (response.ok !== true) return { status: 'UNAVAILABLE' };
    return viewerGate(response.model, response.proxy);
  } catch {
    return { status: 'UNAVAILABLE' };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

// 화면 전환용 상태: 확인에 실패하면 페이지 대신 '보호가 켜져 있을 때만…' 안내를 보인다
let blockedStatus: GateBlockStatus | null = null;
const listeners = new Set<() => void>();
export const getBlockedStatus = (): GateBlockStatus | null => blockedStatus;
export function subscribeBlockedStatus(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
export function setBlockedStatus(status: GateBlockStatus | null): void {
  if (blockedStatus === status) return;
  blockedStatus = status;
  for (const listener of Array.from(listeners)) listener();   // 알림 중 구독 해제가 있어도 안전하게 사본으로
}

// 보호 켜기·끄기, Gateway 설정 변경, 프록시 충돌 표시는 모두 chrome.storage.local의 runtimeState·settings 변경으로 드러난다
export function watchProtectionChanges(onChange: () => void): () => void {
  const events = chromeApi()?.storage?.onChanged;
  if (!events || typeof events.addListener !== 'function') return () => undefined;
  const listener = (changes: Record<string, unknown>, areaName: string) => {
    if (areaName === 'local' && ('runtimeState' in changes || 'settings' in changes)) onChange();
  };
  events.addListener(listener);
  return () => events.removeListener?.(listener);
}
