// '일치 비율' 하나로 통일(2026-10-16): 문서 구간 일치(WINDOW_HASH) 탐지마다 '입력 중 문서와 같은 글자' 비율을 붙인다.
// 계산은 화면(이벤트 상세 '보호 문서 일치 구간')과 같은 원본(match-ratio.mjs ← 화면 src/utils/matchRatio.ts)·같은 본문(match-evidence.mjs comparisonBodies)이라
// 목록·상세 머리 숫자와 상세 본문 대조 숫자가 같다. Detection의 해시 근거 비율(score)은 그대로 두고 이름만 화면에서 구분한다.
//
// 결과(탐지의 same_text): READY {same_chars, input_chars, differences} · PENDING(아직 계산 전, 목록은 기다리지 않음) ·
//   UNAVAILABLE {reason}(본문 없음·서버 확인과 어긋남·계산 한도 초과). 비율 = same_chars ÷ input_chars(공백 뺀 글자, 가림 한 덩어리 = 한 글자)
// 캐시: 이벤트 + 비교 문서들의 지금 판(documents.version)으로 열쇠를 만든다. 판정 기록·보존본은 바뀌지 않고, 보존본이 없는 옛 기록은
//   문서 판이 바뀌면 다시 계산한다. 목록 요청은 계산을 기다리지 않고(계산 중 표시) 뒤에서 한 건씩 계산한다 — 다음 자동 갱신(10초)에 채워진다.
//   상세(이벤트 한 건) 요청은 그 자리에서 계산한다. 메모리에만 둔다(재시작하면 다시 계산).
import { computeMatchRatio, matchRatioSummary } from './match-ratio.mjs';

const CACHE_LIMIT = 20_000;   // 이벤트 수(운영 10/16 약 600건)보다 넉넉한 상한. 넘으면 오래된 것부터 버린다

const windowDocs = (event) => [...new Set((event?.detections ?? []).filter((d) => d?.detector === 'WINDOW_HASH' && d.matched_document_id).map((d) => d.matched_document_id))];

export function createSameTextService(eventStore, { log = console } = {}) {
  const supported = typeof eventStore?.getComparisonBodies === 'function' && typeof eventStore?.documentVersions === 'function';
  const cache = new Map();   // key → Map(document_id → summary)
  const queue = new Map();   // key → event
  let running = false;

  const keyOf = (event, versions) => `${event.event_id}|${windowDocs(event).map((id) => `${id}@${versions.get(id) ?? '-'}`).join(',')}`;
  const remember = (key, value) => {
    cache.delete(key);
    cache.set(key, value);
    while (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
  };

  async function compute(event) {
    const results = new Map();
    for (const body of await eventStore.getComparisonBodies(event)) {
      try { results.set(body.document_id, matchRatioSummary(computeMatchRatio(body.input, body.document, body.comparison))); }
      catch (error) { results.set(body.document_id, { state: 'UNAVAILABLE', reason: '계산 오류' }); log.error?.('same_text compute failed:', error?.message ?? error); }
    }
    return results;
  }

  async function drain() {
    if (running) return;
    running = true;
    try {
      while (queue.size) {
        const [key, event] = queue.entries().next().value;
        queue.delete(key);
        try { remember(key, await compute(event)); }
        catch (error) { log.error?.('same_text background failed:', error?.message ?? error); remember(key, new Map()); }
      }
    } finally { running = false; }
  }

  const attach = (event, results, pending) => ({
    ...event,
    detections: event.detections.map((detection) => detection?.detector !== 'WINDOW_HASH' ? detection : {
      ...detection,
      same_text: pending ? { state: 'PENDING' } : results?.get(detection.matched_document_id) ?? { state: 'UNAVAILABLE', reason: '대조할 본문 없음' },
    }),
  });

  /** events: 응답에 실을 이벤트들. wait=false(목록)면 캐시에 없는 것은 PENDING으로 두고 뒤에서 계산 */
  async function annotate(events, { wait = false } = {}) {
    if (!supported) return events;
    // 목록 묶음: 질문 아래 붙은 파일 이벤트(attached_files)도 같은 탐지 칸이 있으면 함께
    const members = events.flatMap((event) => [event, ...(Array.isArray(event?.attached_files) ? event.attached_files : [])]);
    const targets = members.filter((event) => event?.request_id && Array.isArray(event.detections) && windowDocs(event).length);
    if (!targets.length) return events;
    const versions = await eventStore.documentVersions([...new Set(targets.flatMap(windowDocs))]);
    const out = new Map();
    for (const event of targets) {
      const key = keyOf(event, versions);
      if (cache.has(key)) { out.set(event.event_id, attach(event, cache.get(key), false)); continue; }
      if (wait) {
        const results = await compute(event);
        remember(key, results);
        out.set(event.event_id, attach(event, results, false));
      } else {
        queue.set(key, event);
        out.set(event.event_id, attach(event, null, true));
      }
    }
    if (queue.size) void drain();
    const replace = (event) => out.get(event?.event_id) ?? event;
    return events.map((event) => {
      const next = replace(event);
      return Array.isArray(next?.attached_files) ? { ...next, attached_files: next.attached_files.map(replace) } : next;
    });
  }

  return { annotate, supported, cacheSize: () => cache.size, pending: () => queue.size };
}
