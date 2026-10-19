import { ACTION_STATS_MIN_INTERVAL_MS } from "../config/defaults.js";
import { ACTION_STATS_KEY, defaultActionStats, ingestRecords, normalizeActionStats, recordFromEvent, recordsFromMyRequests } from "./action-stats.js";
import { myRequestsCheck } from "./gateway-service.js";
import { applyManagedSettings, getManagedPolicy } from "./policy-service.js";
import { captureProxySnapshot, proxySnapshotMatchesSettings } from "./proxy-service.js";
import { readModel } from "./storage-service.js";
import { isValidViewerKey } from "../utils/validation.js";

// 1.4.8: 차단·마스킹 집계 저장·갱신. 집계는 runtimeState·accessState와 다른 키(actionStats)에 둔다 - readModel이 매번 읽는 키에 섞지 않는다.
// 내 요청 기록을 읽어도 되는 조건 = 접속 제한 조회·내 요청 기록 페이지와 같은 보호 확인(보호 켜짐 + 주소 있음 + PAC가 설정값과 일치)
// + 열람 키가 Gateway에 실려 가는 조건(식별 헤더 전송 켜짐)과 열람 키 존재. 조건이 안 되면 열람 키를 보내지 않는다.
export async function resolveActionStatsContext() {
  const model = await readModel();
  if (!model.runtimeState.desiredProtection) return { eligible: false, reason: "PROTECTION_OFF" };
  const policy = await getManagedPolicy();
  if (policy.errors.length) return { eligible: false, reason: "PROXY" };
  const settings = applyManagedSettings(model.settings, policy);
  if (!settings.gateway.host) return { eligible: false, reason: "NOT_CONFIGURED" };
  const snapshot = await captureProxySnapshot();
  if (!proxySnapshotMatchesSettings(snapshot, settings)) return { eligible: false, reason: "PROXY" };
  if (!settings.identity.enabled) return { eligible: false, reason: "IDENTITY_OFF" };
  if (!isValidViewerKey(model.identity.viewerKey)) return { eligible: false, reason: "NO_VIEWER_KEY" };
  return { eligible: true, viewerKey: model.identity.viewerKey };
}

export function createActionStatsService({
  storage = globalThis.chrome?.storage?.local,
  resolveContext = resolveActionStatsContext,
  check = myRequestsCheck,
  now = () => Date.now(),
  minIntervalMs = ACTION_STATS_MIN_INTERVAL_MS
} = {}) {
  let queue = Promise.resolve();
  let inflight = null;

  const read = async () => normalizeActionStats((await storage.get([ACTION_STATS_KEY]))[ACTION_STATS_KEY]);
  // 읽고-고쳐-쓰기를 한 줄로 세운다(실시간 알림 처리와 내 요청 기록 조회가 겹쳐도 서로 덮어쓰지 않게). 앞 작업이 실패해도 다음 작업은 돈다
  const mutate = (change) => {
    const run = queue.then(async () => {
      const before = await read();
      const { stats, result } = await change(before);
      if (JSON.stringify(stats) !== JSON.stringify(before)) await storage.set({ [ACTION_STATS_KEY]: stats });
      return result;
    });
    queue = run.catch(() => undefined);
    return run;
  };

  // 설치·시작 때 '집계 시작' 시각을 남긴다
  const ensureStarted = () => mutate(async (before) => ({ stats: before.startedAt ? before : ingestRecords(before, [], now()).stats, result: true }));

  // 실시간 알림(차단·마스킹) 한 건. 허용·형식 오류는 건너뛴다. 예외는 밖으로 내보내지 않는다(알림 표시를 막지 않게)
  async function recordEvent(event) {
    try {
      const record = recordFromEvent(event);
      if (!record) return { added: 0 };
      return await mutate(async (before) => { const { stats, added } = ingestRecords(before, [record], now()); return { stats, result: { added } }; });
    } catch { return { added: 0, errorCode: "ACTION_STATS_FAILED" }; }
  }

  // 내 요청 기록을 읽어 놓친 건을 채운다. force=false면 마지막 시도 후 짧은 시간 안에는 건너뛴다. 조회가 겹치면 먼저 시작한 것을 같이 기다린다
  function refresh({ force = true } = {}) {
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const context = await resolveContext();
        if (!context.eligible) return { ok: false, skipped: context.reason || "NOT_ELIGIBLE" };
        const before = await read();
        const last = Date.parse(before.sync.attemptedAt);
        if (!force && Number.isFinite(last) && now() - last < minIntervalMs) return { ok: true, skipped: "RECENT" };
        const outcome = await check({ viewerKey: context.viewerKey });
        const records = outcome?.ok === true ? recordsFromMyRequests(outcome.body) : null;
        const attemptedAt = new Date(now()).toISOString();
        const errorCode = records ? "" : String(outcome?.ok === true ? "INVALID_MY_REQUESTS" : outcome?.errorCode || "FAILED").replace(/[^A-Z0-9_]/g, "_").slice(0, 64) || "FAILED";
        return await mutate(async (current) => {
          const ingested = records ? ingestRecords(current, records, now()) : { stats: current, added: 0 };
          const stats = { ...ingested.stats, sync: { attemptedAt, okAt: records ? attemptedAt : current.sync.okAt, error: errorCode } };
          return { stats, result: { ok: Boolean(records), added: ingested.added, ...(errorCode ? { errorCode } : {}) } };
        });
      } catch { return { ok: false, errorCode: "ACTION_STATS_FAILED" }; }
      finally { inflight = null; }
    })();
    return inflight;
  }

  return { ensureStarted, recordEvent, refresh, read, defaults: defaultActionStats };
}
