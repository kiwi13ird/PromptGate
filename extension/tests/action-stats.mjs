// 1.4.8 차단·마스킹 집계 시험: 순수 함수(형식·중복 제거·오늘/누적·보관 상한·표시 상태) + 저장·조회 서비스(가짜 저장소·가짜 Gateway)
// 실행: node tests/action-stats.mjs  (run-tests.mjs도 별도 프로세스로 부른다)
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url)).replace(/[\\/]$/, "");
const url = (p) => pathToFileURL(`${root}/${p}`).href;
const stats = await import(url("extension/services/action-stats.js"));
const { createActionStatsService } = await import(url("extension/services/action-stats-service.js"));
const { ACTION_STATS_STALE_MS } = await import(url("extension/config/defaults.js"));
const { ACCESS_REASON_CODES } = await import(url("extension/services/access-state.js"));
const { ACTION_STATS_KEY, ACTION_STATS_MAX_RECORDS, ACTION_STATS_RETENTION_MS, actionStatsView, defaultActionStats, ingestRecords, normalizeActionStats, recordFromEvent, recordsFromMyRequests, summarizeActionStats } = stats;

const NOW = new Date(2026, 9, 14, 15, 0, 0).getTime();     // 이 PC 시간 10/14 15:00
const MIDNIGHT = new Date(2026, 9, 14, 0, 0, 0).getTime();
const iso = (ms) => new Date(ms).toISOString();
const rec = (id, ms, code = "B") => ({ id, ts: iso(ms), code });
const sum = (s, now = NOW) => summarizeActionStats(s, now);

// ── 실시간 알림 한 건 -> 기록: 차단·마스킹만. 허용(알림 요청 포함)·번호 없음·형식 오류는 세지 않는다
// 운영에 있는 조치 값은 BLOCK·MASK·ALLOW 세 가지뿐이다(Gateway extension_event_view.py, 대시보드 eventAction)
assert.deepEqual(recordFromEvent({ eventId: "evt-1", action: "BLOCK", timestamp: iso(NOW) }), { id: "evt-1", ts: iso(NOW), code: "B" });
assert.deepEqual(recordFromEvent({ eventId: "evt-2", action: "MASK", timestamp: iso(NOW) }), { id: "evt-2", ts: iso(NOW), code: "M" });
assert.equal(recordFromEvent({ eventId: "evt-3", action: "ALLOW", notify: true, timestamp: iso(NOW) }), null);
assert.equal(recordFromEvent({ action: "BLOCK" }), null);
assert.equal(recordFromEvent(null), null);
assert.equal(ingestRecords(defaultActionStats(), [recordFromEvent({ eventId: "bad id/with space", action: "BLOCK" })], NOW).added, 0);
// 운영에 없는 조치 이름은 세지 않는다(추측으로 세면 숫자를 믿을 수 없다)
for (const unknownAction of ["MASK_PARTIAL", "MASK_FULL", "BLOCK_NOTIFY", "ALLOW_DEGRADED", "block", "constructor", "", 7, null]) assert.equal(recordFromEvent({ eventId: "evt-u", action: unknownAction, timestamp: iso(NOW) }), null, String(unknownAction));
// 접속 차단(관리자 사용 제한·확장 번호 없음): 같은 BLOCK이어도 '차단'이 아니라 '사용 제한 기록'(R)으로 센다 - 운영 사유 코드는 이 둘뿐
assert.deepEqual(Object.values(ACCESS_REASON_CODES).sort(), ["client_blocked", "client_id_missing"]);
assert.deepEqual(recordFromEvent({ eventId: "evt-r1", action: "BLOCK", reasonCode: "client_blocked", contentType: "prompt", timestamp: iso(NOW) }), { id: "evt-r1", ts: iso(NOW), code: "R" });
assert.deepEqual(recordFromEvent({ eventId: "evt-r2", action: "BLOCK", reasonCode: "client_id_missing", timestamp: iso(NOW) }), { id: "evt-r2", ts: iso(NOW), code: "R" });
// 보안 검사 때문에 막은 사유는 그대로 '차단'
for (const reasonCode of ["file_uninspectable_other", "file_uninspectable_image", "file_uninspectable_scanned_pdf", "file_too_large", "mask_application_failed", "file_masking_failed", "detection_timeout", "detection_unreachable"]) assert.equal(recordFromEvent({ eventId: "evt-x", action: "BLOCK", reasonCode, timestamp: iso(NOW) }).code, "B", reasonCode);
assert.equal(recordFromEvent({ eventId: "evt-m", action: "MASK", reasonCode: "client_blocked", timestamp: iso(NOW) }).code, "M");   // 사유 코드는 BLOCK일 때만 의미가 있다

// ── 내 요청 기록 응답: 묶인 첨부 파일도 각자 한 건, 조치는 운영 값(BLOCK·MASK·ALLOW)만, 형식이 다르면 null
const body = { window_days: 7, items: [
  { event_id: "evt-a", occurred_at: iso(NOW - 1000), final_action: "MASK", content_type: "prompt", attached_files: [
    { event_id: "evt-a-f1", occurred_at: iso(NOW - 900), final_action: "BLOCK", content_type: "file", reason_code: "file_uninspectable_other" },
    { event_id: "evt-a-f2", occurred_at: iso(NOW - 800), final_action: "ALLOW", content_type: "file" }] },
  { event_id: "evt-b", occurred_at: iso(NOW - 2000), final_action: "ALLOW", group_final_action: "MASK", attached_files: [{ event_id: "evt-b-f", occurred_at: iso(NOW - 1900), final_action: "MASK", content_type: "file" }] },
  { event_id: "evt-c", occurred_at: iso(NOW - 3000), final_action: "BLOCK", content_type: "prompt", reason_code: "mask_application_failed" },
  { event_id: "evt-d", occurred_at: iso(NOW - 4000), final_action: "MASK", content_type: "prompt" },
  { event_id: "evt-e", occurred_at: iso(NOW - 5000), final_action: "ALLOW", content_type: "prompt", reason_code: "detection_timeout" },
  { event_id: "evt-r1", occurred_at: iso(NOW - 6000), final_action: "BLOCK", content_type: "prompt", reason_code: "client_blocked", block_id: "blk-1" },
  { event_id: "evt-r2", occurred_at: iso(NOW - 7000), final_action: "BLOCK", content_type: "prompt", reason_code: "client_id_missing" },
  { event_id: "evt-g", occurred_at: iso(NOW - 8000), final_action: "ALLOW", group_final_action: "BLOCK", attached_files: [{ event_id: "evt-g-f", occurred_at: iso(NOW - 7900), final_action: "BLOCK", content_type: "file", reason_code: "client_blocked" }] },
  { occurred_at: iso(NOW), final_action: "BLOCK" }, "junk", null] };
const parsed = recordsFromMyRequests(body);
assert.deepEqual(parsed.map((r) => `${r.id}:${r.code}`), ["evt-a:M", "evt-a-f1:B", "evt-b-f:M", "evt-c:B", "evt-d:M", "evt-r1:R", "evt-r2:R", "evt-g-f:R"]);   // 허용·번호 없음·쓰레기는 빠진다. 접속 차단은 R
assert.deepEqual(recordsFromMyRequests({ items: [{ event_id: "evt-u1", occurred_at: iso(NOW), final_action: "MASK_PARTIAL" }, { event_id: "evt-u2", occurred_at: iso(NOW), final_action: "BLOCK_NOTIFY" }], window_days: 7 }), []);   // 운영에 없는 이름은 세지 않는다
assert.deepEqual(recordsFromMyRequests({ items: [], window_days: 7 }), []);
for (const bad of [null, [], "x", {}, { items: "no" }, { error: { code: "DASHBOARD_UNAVAILABLE" } }]) assert.equal(recordsFromMyRequests(bad), null, JSON.stringify(bad));

// ── 중복 제거: 같은 번호는 한 번(재전송·두 경로), 번호가 다르면 따로
let first = ingestRecords(defaultActionStats(), parsed, NOW);
assert.equal(first.added, 8);
assert.deepEqual(sum(first.stats).total, { block: 2, mask: 3, restricted: 3 });   // 접속 차단 3건은 '차단'에 들어가지 않는다
const again = ingestRecords(first.stats, parsed, NOW);
assert.equal(again.added, 0); assert.deepEqual(again.stats.recent, first.stats.recent);
const viaChannel = ingestRecords(first.stats, [recordFromEvent({ eventId: "evt-c", action: "BLOCK", timestamp: iso(NOW - 3000) }), recordFromEvent({ eventId: "evt-r1", action: "BLOCK", reasonCode: "client_blocked", timestamp: iso(NOW - 6000) }), recordFromEvent({ eventId: "evt-new", action: "BLOCK", timestamp: iso(NOW) })], NOW);
assert.equal(viaChannel.added, 1); assert.deepEqual(sum(viaChannel.stats).total, { block: 3, mask: 3, restricted: 3 });   // 같은 건(evt-c)은 안 늘고 새 건만 늘어남
assert.deepEqual(first.stats.recent.length, 8);   // 입력은 바뀌지 않는다
// 보관 기간보다 오래된 건·시각 없음·먼 미래
const edge = ingestRecords(defaultActionStats(), [rec("old", NOW - ACTION_STATS_RETENTION_MS - 1), { id: "no-ts", ts: "not a date", code: "B" }, rec("future", NOW + 3 * 86400000, "M"), { id: "bad-code", ts: iso(NOW), code: "A" }], NOW);
assert.equal(edge.added, 2); assert.deepEqual(edge.stats.recent.map((r) => [r[0], r[1]]).sort(), [["future", NOW], ["no-ts", NOW]]);   // 시각을 못 믿으면 받은 시각

// ── 오늘(이 PC 0시부터) / 누적
const day = ingestRecords(defaultActionStats(), [rec("y1", MIDNIGHT - 1, "B"), rec("t0", MIDNIGHT, "B"), rec("t1", NOW - 5000, "M"), rec("t2", NOW, "M"), rec("y2", MIDNIGHT - 3600000, "M")], NOW).stats;
assert.deepEqual(sum(day), { today: { block: 1, mask: 2, restricted: 0 }, total: { block: 2, mask: 3, restricted: 0 } });
assert.deepEqual(sum(day, NOW + 12 * 3600000).today, { block: 0, mask: 0, restricted: 0 });   // 날이 바뀌면 오늘은 0, 누적은 그대로
assert.deepEqual(sum(day, NOW + 12 * 3600000).total, { block: 2, mask: 3, restricted: 0 });
// 사용 제한 기록은 차단·마스킹과 합쳐지지 않고 오늘/누적이 따로 센다
const restrictedDay = ingestRecords(defaultActionStats(), [rec("rd-y", MIDNIGHT - 1, "R"), rec("rd-t", NOW - 1000, "R"), rec("rd-b", NOW - 2000, "B"), rec("rd-m", NOW - 3000, "M")], NOW).stats;
assert.deepEqual(sum(restrictedDay), { today: { block: 1, mask: 1, restricted: 1 }, total: { block: 1, mask: 1, restricted: 2 } });
assert.deepEqual(sum(defaultActionStats()), { today: { block: 0, mask: 0, restricted: 0 }, total: { block: 0, mask: 0, restricted: 0 } });

// ── 보관 상한: 건수가 넘쳐도 누적은 줄지 않는다(번호만 버림)
const many = Array.from({ length: ACTION_STATS_MAX_RECORDS + 100 }, (_, i) => rec(`m-${i}`, NOW - 100000 + i, i % 2 ? "B" : "M"));
const capped = ingestRecords(defaultActionStats(), many, NOW).stats;
assert.equal(capped.recent.length, ACTION_STATS_MAX_RECORDS); assert.equal(capped.archived.block + capped.archived.mask, 100);
assert.equal(sum(capped).total.block + sum(capped).total.mask, ACTION_STATS_MAX_RECORDS + 100);
assert.equal(capped.recent[0][0], "m-100");   // 가장 오래된 100건이 건수로만 남음
// 기간 상한: 14일을 넘긴 번호는 건수로만 남고 누적은 유지, 오늘은 0
const aged = ingestRecords(ingestRecords(defaultActionStats(), [rec("k1", NOW - 13 * 86400000, "B"), rec("k2", NOW, "M")], NOW).stats, [], NOW + 3 * 86400000);
assert.deepEqual(aged.stats.archived, { block: 1, mask: 0, restricted: 0 }); assert.deepEqual(sum(aged.stats, NOW + 3 * 86400000).total, { block: 1, mask: 1, restricted: 0 });
const mixedCap = ingestRecords(defaultActionStats(), Array.from({ length: ACTION_STATS_MAX_RECORDS + 30 }, (_, i) => rec(`c-${i}`, NOW - 100000 + i, i < 30 ? "R" : "B")), NOW).stats;
assert.deepEqual(mixedCap.archived, { block: 0, mask: 0, restricted: 30 }); assert.deepEqual(sum(mixedCap).total, { block: ACTION_STATS_MAX_RECORDS, mask: 0, restricted: 30 });   // 밀려난 사용 제한도 건수로 남는다
// 보관된 총량이 클 때 저장 크기(번호 5000개)가 수백 KB 안
assert.ok(JSON.stringify(capped).length < 400 * 1024, `size ${JSON.stringify(capped).length}`);

// ── 저장 형식: 번호·시각·조치 종류만. 프롬프트·서비스·탐지 같은 칸은 들어가지 않는다
const noisy = ingestRecords(defaultActionStats(), [recordFromEvent({ eventId: "evt-p", action: "MASK", timestamp: iso(NOW), targetLlm: "ChatGPT", detector: "SIGNATURE", matchType: "KR_RRN", prompt: "주민번호 900101-1234567", reasonCode: "pii_masked", clientId: "chrome-secret" })], NOW).stats;
const restrictedStored = ingestRecords(noisy, [recordFromEvent({ eventId: "evt-rr", action: "BLOCK", reasonCode: "client_blocked", timestamp: iso(NOW), blockId: "blk-secret-1", userMemo: "퇴사 예정" })], NOW).stats;
assert.deepEqual(restrictedStored.recent, [["evt-p", NOW, "M"], ["evt-rr", NOW, "R"]]);
for (const leaked of ["client_blocked", "blk-secret-1", "퇴사"]) assert.ok(!JSON.stringify(restrictedStored).includes(leaked), leaked);
const serialized = JSON.stringify(noisy);
for (const leaked of ["ChatGPT", "SIGNATURE", "KR_RRN", "900101", "pii_masked", "chrome-secret", "prompt"]) assert.ok(!serialized.includes(leaked), leaked);
assert.deepEqual(Object.keys(noisy).sort(), ["archived", "from", "recent", "startedAt", "sync", "v"]);
assert.deepEqual(noisy.recent, [["evt-p", NOW, "M"]]);
// 망가진 저장값
const broken = normalizeActionStats({ v: 2, startedAt: "x", from: 5, archived: { block: -3, mask: 1.5 }, recent: [["ok-1", NOW, "B"], ["ok-1", NOW, "M"], ["bad id", NOW, "B"], ["x", "no", "B"], ["y", NOW, "Z"], "junk", [1, 2]], sync: { attemptedAt: "no", okAt: 3, error: "lower case" } });
assert.deepEqual(broken, { v: 2, startedAt: null, from: null, archived: { block: 0, mask: 0, restricted: 0 }, recent: [["ok-1", NOW, "B"]], sync: { attemptedAt: null, okAt: null, error: "" } });
// 1.4.8 시험판(v1)은 접속 차단이 '차단'에 섞여 저장돼 있어 종류를 나눌 수 없다 -> 버리고 서버 기록(7일)에서 다시 센다
assert.equal(defaultActionStats().v, 2);
assert.deepEqual(normalizeActionStats({ v: 1, startedAt: iso(NOW), from: iso(NOW), archived: { block: 5, mask: 5 }, recent: [["old-1", NOW, "B"]], sync: { attemptedAt: iso(NOW), okAt: iso(NOW), error: "" } }), defaultActionStats());
assert.deepEqual(normalizeActionStats({ v: 2, recent: [["new-1", NOW, "R"]] }).recent, [["new-1", NOW, "R"]]);
assert.deepEqual(normalizeActionStats(undefined), defaultActionStats()); assert.deepEqual(normalizeActionStats([]), defaultActionStats());

// ── 표시 상태: 0은 '확인했더니 0건'일 때만, 못 믿을 때는 숫자 대신 null
const ok = { protectionOn: true, configured: true, proxyApplied: true, identityEnabled: true, hasViewerKey: true };
const syncedAt = NOW - 60000;
const withSync = (s, sync) => ({ ...s, sync: { attemptedAt: iso(NOW), okAt: null, error: "", ...sync } });
const started = ingestRecords(defaultActionStats(), [], NOW - 3600000).stats;
let view = actionStatsView(withSync(started, { okAt: iso(syncedAt) }), ok, NOW);
assert.equal(view.tone, "ok"); assert.deepEqual(view.today, { block: 0, mask: 0, restricted: 0 }); assert.equal(view.note, ""); assert.match(view.syncText, /^정상 · /);   // 확인했고 0건
view = actionStatsView(withSync(day, { okAt: iso(syncedAt) }), ok, NOW);
assert.equal(view.tone, "ok"); assert.deepEqual(view.today, { block: 1, mask: 2, restricted: 0 }); assert.deepEqual(view.total, { block: 2, mask: 3, restricted: 0 });
assert.match(view.caption, /이 PC에서 확장이 확인한 기록 기준/); assert.match(view.caption, /질문·파일을 각각 셈/); assert.doesNotMatch(view.caption, /요청 기준/); assert.match(view.caption, /오늘은 0시부터/); assert.match(view.caption, /누적은 \d+\/\d+부터/);
// 사용 제한 기록: 있을 때만 작게 따로, 10분에 한 번만 남는 대표 기록이라는 설명과 함께. 없으면 칸 자체가 없다
view = actionStatsView(withSync(restrictedDay, { okAt: iso(syncedAt) }), ok, NOW);
assert.equal(view.tone, "ok"); assert.deepEqual(view.total, { block: 1, mask: 1, restricted: 2 }); assert.equal(view.restrictedText, "사용 제한 기록 2회 · 오늘 1회");
assert.match(view.restrictedNote, /10분에 한 번/); assert.match(view.restrictedNote, /실제로 막힌 요청 수가 아닙니다/);
view = actionStatsView(withSync(day, { okAt: iso(syncedAt) }), ok, NOW); assert.equal(view.restrictedText, ""); assert.equal(view.restrictedNote, "");
view = actionStatsView(restrictedDay, { ...ok, hasViewerKey: false }, NOW); assert.equal(view.tone, "stale"); assert.match(view.restrictedText, /^사용 제한 기록 2회/);   // 흐린 상태에서도 같은 숫자
view = actionStatsView(started, { ...ok, protectionOn: false }, NOW); assert.equal(view.today, null); assert.equal(view.restrictedText, ""); assert.equal(view.restrictedNote, "");   // 숫자가 없으면 칸도 없다
// 처음(아직 한 번도 못 읽음): 확인 중, 숫자 없음
view = actionStatsView(started, ok, NOW); assert.equal(view.tone, "checking"); assert.equal(view.today, null);
// 처음부터 연결 실패: 확인 불가(숫자 없음, 0 아님)
view = actionStatsView(withSync(started, { error: "NETWORK_ERROR" }), ok, NOW); assert.equal(view.tone, "unavailable"); assert.equal(view.today, null); assert.equal(view.total, null); assert.match(view.note, /가져오지 못했습니다/);
// 한 번이라도 읽었는데 지금 끊김: 오래되기 전까지는 정상, 오래되면 숫자는 보이되 '빠졌을 수 있음'
view = actionStatsView(withSync(day, { okAt: iso(syncedAt), error: "TIMEOUT" }), ok, NOW); assert.equal(view.tone, "ok");
const oldOk = NOW - ACTION_STATS_STALE_MS - 1000;
view = actionStatsView(withSync(day, { okAt: iso(oldOk), error: "NETWORK_ERROR" }), ok, NOW); assert.equal(view.tone, "stale"); assert.deepEqual(view.total, { block: 2, mask: 3, restricted: 0 }); assert.match(view.note, /빠졌을 수 있습니다/); assert.match(view.note, /마지막 확인/);
// 실시간으로 받은 건만 있고 과거 기록은 못 읽음
view = actionStatsView(withSync(day, { error: "NETWORK_ERROR" }), ok, NOW); assert.equal(view.tone, "stale"); assert.deepEqual(view.total, { block: 2, mask: 3, restricted: 0 }); assert.match(view.note, /실시간으로 받은 건만/);
// 읽을 수 없는 설정: 기록이 없으면 확인 불가(이유 안내), 있으면 숫자는 보이되 새 건이 안 잡힌다는 안내
const cases = [["protectionOn", "보호가 꺼져"], ["configured", "보안 서버 주소"], ["proxyApplied", "연결 설정"], ["identityEnabled", "내 확장 번호"], ["hasViewerKey", "열람 키"]];
for (const [flag, phrase] of cases) {
  const context = { ...ok, [flag]: false };
  view = actionStatsView(started, context, NOW); assert.equal(view.tone, "unavailable", flag); assert.equal(view.today, null); assert.match(view.note, new RegExp(phrase), flag);
  view = actionStatsView(withSync(day, { okAt: iso(syncedAt) }), context, NOW); assert.equal(view.tone, "stale", flag); assert.deepEqual(view.total, { block: 2, mask: 3, restricted: 0 }); assert.match(view.note, new RegExp(phrase), flag); assert.match(view.note, /집계되지 않습니다/);
}
assert.equal(actionStatsView(undefined, { ...ok, protectionOn: false }, NOW).tone, "unavailable");

// ── 저장·조회 서비스(가짜 저장소)
function fakeStorage(seed = {}) {
  const data = structuredClone(seed); let sets = 0;
  return { data, get sets() { return sets; }, api: {
    get: async (keys) => { await Promise.resolve(); return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((k) => k in data).map((k) => [k, structuredClone(data[k])])); },
    set: async (patch) => { await Promise.resolve(); await Promise.resolve(); sets += 1; Object.assign(data, structuredClone(patch)); } } };
}
const KEY = "K".repeat(43);
const listBody = (...items) => ({ ok: true, status: 200, body: { window_days: 7, items } });
const item = (id, action, ms = NOW) => ({ event_id: id, occurred_at: iso(ms), final_action: action });
let clock = NOW; const now = () => clock;

{ // 1) 실시간 알림 + 조회 겹침: 번호 같으면 1번, 동시에 들어와도 갱신이 사라지지 않는다
  const storage = fakeStorage(); const calls = [];
  const svc = createActionStatsService({ storage: storage.api, now, resolveContext: async () => ({ eligible: true, viewerKey: KEY }), check: async ({ viewerKey }) => { calls.push(viewerKey); await Promise.resolve(); return listBody(item("e-0", "BLOCK"), item("e-1", "MASK"), item("only-list", "BLOCK")); } });
  await svc.ensureStarted();
  const events = Array.from({ length: 40 }, (_, i) => ({ eventId: `e-${i}`, action: i % 2 ? "MASK" : "BLOCK", timestamp: iso(NOW - i) }));
  await Promise.all([...events.map((e) => svc.recordEvent(e)), svc.refresh({ force: true }), ...events.map((e) => svc.recordEvent(e))]);   // 같은 알림을 두 번씩 + 조회
  const saved = normalizeActionStats(storage.data[ACTION_STATS_KEY]);
  assert.equal(saved.recent.length, 41);   // 40건 + 목록에만 있던 1건
  assert.deepEqual(sum(saved).total, { block: 21, mask: 20, restricted: 0 });
  assert.deepEqual(calls, [KEY]);
  assert.equal(saved.sync.error, ""); assert.ok(saved.sync.okAt);
  assert.ok(Date.parse(saved.startedAt) === NOW);
  const setsBefore = storage.sets;
  await svc.recordEvent(events[0]); await svc.recordEvent({ eventId: "x-allow", action: "ALLOW", notify: true, timestamp: iso(NOW) });
  assert.equal(storage.sets, setsBefore, "바뀐 것이 없으면 저장하지 않는다");
}

{ // 2) 조건이 안 되면 조회하지 않는다(열람 키를 보내지 않음). 조건이 되면 조회
  const storage = fakeStorage(); let calls = 0; let context = { eligible: false, reason: "PROTECTION_OFF" };
  const svc = createActionStatsService({ storage: storage.api, now, resolveContext: async () => context, check: async () => { calls += 1; return listBody(); } });
  assert.deepEqual(await svc.refresh({ force: true }), { ok: false, skipped: "PROTECTION_OFF" }); assert.equal(calls, 0); assert.equal(storage.sets, 0);
  context = { eligible: true, viewerKey: KEY };
  assert.equal((await svc.refresh({ force: true })).ok, true); assert.equal(calls, 1);
  assert.equal(normalizeActionStats(storage.data[ACTION_STATS_KEY]).sync.okAt, iso(NOW)); assert.deepEqual(sum(storage.data[ACTION_STATS_KEY]).total, { block: 0, mask: 0, restricted: 0 });   // 읽었더니 0건
}

{ // 3) 실패: 숫자는 그대로, 마지막 성공 시각은 유지, 오류 코드만 기록. 빈 응답·이상한 응답을 0건 성공으로 보지 않는다
  const storage = fakeStorage(); let reply = listBody(item("k-1", "BLOCK"));
  const svc = createActionStatsService({ storage: storage.api, now, resolveContext: async () => ({ eligible: true, viewerKey: KEY }), check: async () => reply });
  await svc.refresh({ force: true });
  const okAt = normalizeActionStats(storage.data[ACTION_STATS_KEY]).sync.okAt;
  for (const [failure, code] of [[{ ok: false, errorCode: "NETWORK_ERROR" }, "NETWORK_ERROR"], [{ ok: false, errorCode: "HTTP_ERROR", status: 502 }, "HTTP_ERROR"], [{ ok: true, status: 200, body: { error: { code: "X" } } }, "INVALID_MY_REQUESTS"], [{ ok: false }, "FAILED"]]) {
    clock += 120000; reply = failure;
    const result = await svc.refresh({ force: true });
    const saved = normalizeActionStats(storage.data[ACTION_STATS_KEY]);
    assert.equal(result.ok, false); assert.equal(result.errorCode, code); assert.equal(saved.sync.error, code); assert.equal(saved.sync.okAt, okAt);
    assert.deepEqual(sum(saved, clock).total, { block: 1, mask: 0, restricted: 0 });
  }
  clock += 120000; reply = listBody(item("k-1", "BLOCK"), item("k-2", "MASK"));   // 회복: 놓친 건이 채워지고 오류가 지워짐
  await svc.refresh({ force: true });
  const healed = normalizeActionStats(storage.data[ACTION_STATS_KEY]);
  assert.equal(healed.sync.error, ""); assert.deepEqual(sum(healed, clock).total, { block: 1, mask: 1, restricted: 0 });
}

{ // 4) 연결이 끊긴 동안 실시간 알림이 놓친 건: 다음 조회에서 채워지고, 이미 센 건은 다시 세지 않는다
  const storage = fakeStorage(); let reply = { ok: false, errorCode: "NETWORK_ERROR" };
  const svc = createActionStatsService({ storage: storage.api, now, resolveContext: async () => ({ eligible: true, viewerKey: KEY }), check: async () => reply });
  await svc.ensureStarted();
  await svc.recordEvent({ eventId: "live-1", action: "BLOCK", timestamp: iso(NOW) });
  await svc.refresh({ force: true });   // 끊김
  assert.equal(actionStatsView(storage.data[ACTION_STATS_KEY], ok, NOW).tone, "stale");
  reply = listBody(item("live-1", "BLOCK"), item("missed-1", "MASK", NOW - 600000), item("missed-2", "BLOCK", NOW - 300000));
  clock += 60000; await svc.refresh({ force: true });
  assert.deepEqual(sum(storage.data[ACTION_STATS_KEY], clock).total, { block: 2, mask: 1, restricted: 0 });
  clock += 60000; await svc.refresh({ force: true });   // 같은 응답이 또 와도 그대로
  assert.deepEqual(sum(storage.data[ACTION_STATS_KEY], clock).total, { block: 2, mask: 1, restricted: 0 });
}

{ // 5) 팝업을 자주 열어도: 강제가 아니면 마지막 시도 후 1분 안에는 건너뜀, 겹친 조회는 하나만
  const storage = fakeStorage(); let calls = 0; let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const svc = createActionStatsService({ storage: storage.api, now, resolveContext: async () => ({ eligible: true, viewerKey: KEY }), check: async () => { calls += 1; await gate; return listBody(); } });
  const a = svc.refresh({ force: false }); const b = svc.refresh({ force: true }); release(); await Promise.all([a, b]);
  assert.equal(calls, 1);
  clock += 10000; assert.deepEqual(await svc.refresh({ force: false }), { ok: true, skipped: "RECENT" }); assert.equal(calls, 1);
  clock += 60000; await svc.refresh({ force: false }); assert.equal(calls, 2);
  clock += 1000; await svc.refresh({ force: true }); assert.equal(calls, 3);
}

{ // 6) 예외가 나도 밖으로 내보내지 않는다(알림 표시·알람 처리를 막지 않음)
  const broken = { get: async () => { throw new Error("storage down"); }, set: async () => { throw new Error("storage down"); } };
  const svc = createActionStatsService({ storage: broken, now, resolveContext: async () => { throw new Error("boom"); }, check: async () => listBody() });
  assert.equal((await svc.recordEvent({ eventId: "z", action: "BLOCK", timestamp: iso(NOW) })).errorCode, "ACTION_STATS_FAILED");
  assert.equal((await svc.refresh({ force: true })).errorCode, "ACTION_STATS_FAILED");
  const next = createActionStatsService({ storage: fakeStorage().api, now, resolveContext: async () => ({ eligible: true, viewerKey: KEY }), check: async () => { throw new Error("x"); } });
  assert.equal((await next.refresh({ force: true })).errorCode, "ACTION_STATS_FAILED");
}

console.log("PASS: action-stats (record/event parsing, dedupe by event id across channel+relay, today/cumulative, retention caps, privacy of stored fields, view states, service race/failure/throttle)");
process.exit(0);
