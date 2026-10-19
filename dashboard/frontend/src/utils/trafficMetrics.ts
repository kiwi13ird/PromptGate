// 트래픽 및 성능 추가 지표(재설계 3c, 설계 5.9.1 권고 ①②③). 서버 변경 없이 화면이 이미 받는 응답으로만 계산한다.
//  ① 처리 시간 분포: 기간 이벤트 목록(trafficService.getSnapshot이 추이 검증용으로 읽는 readPeriodEvents)의 processingMs·contentType
//     + GET /api/gateway-settings의 timeout.prompt.seconds·timeout.file.seconds(구간 끝 '~설정'·'넘음')
//  ② 검사 못 한 요청: 같은 목록의 degraded·reasonCode·detectionOutcome(보안 현황 ②와 같은 분류) × 처리 시간 추이와 같은 시간 구간
//  ③ 요청 수 띠: 처리 시간 추이와 같은 구간의 이벤트 수(normalizeEventSeries 구간 total = timeseries request_count, 서비스가 이미 대조함)
import type { SecurityEvent } from '@/src/types/event';
import type { EventTimeBucket } from './eventSeries';
import { uninspectedKind, type UninspectedKey } from './overviewMetrics';

/** 설정 대기 시간 앞까지의 고정 경계(ms). 설정보다 작은 것만 쓴다 */
const EDGES_MS = [10, 30, 100, 300, 1000];
const edgeLabel = (ms: number) => (ms < 100 ? `~${ms}ms` : `~${ms / 1000}초`);
const secondsLabel = (seconds: number) => `~${seconds.toLocaleString('ko-KR', { maximumFractionDigits: 2 })}초`;
/** 표본이 이보다 적으면 '표본이 적음'(지금 트래픽 화면 P95 규칙과 같음).
 * 근거: 가장 가까운 순위 P95는 ceil(n × 0.95)번째 값이라 n이 19 이하이면 n번째 = 가장 긴 값이 된다(20건부터 처음으로 가장 긴 값과 갈림) */
export const FEW_SAMPLES = 20;

export interface LatencyBin { key: string; label: string; count: number; over: boolean; limit: boolean }
export interface LatencyDistribution { samples: number; bins: LatencyBin[]; overCount: number; maxMs?: number; limitSeconds?: number;
  /** 이 종류(프롬프트·파일)만의 느린 5%(P95). 합친 P95는 파일 값에 끌려가 프롬프트 지연이 안 보여 따로 적는다(2026-10-15 감사 11번) */
  p95Ms?: number }

/** 처리 시간 구간별 건수. limitSeconds(설정 대기 시간)가 있으면 마지막 두 칸이 '~설정'·'넘음', 없으면 '~1초'·'1초 넘음' */
export function latencyDistribution(events: readonly SecurityEvent[], kind: 'prompt' | 'file', limitSeconds?: number): LatencyDistribution {
  const values = events.filter((event) => (event.contentType ?? 'prompt') === kind && event.processingMs !== undefined && Number.isFinite(event.processingMs) && event.processingMs >= 0).map((event) => event.processingMs as number);
  const limitMs = limitSeconds !== undefined ? limitSeconds * 1000 : undefined;
  const edges = limitMs !== undefined ? [...EDGES_MS.filter((edge) => edge < limitMs), limitMs] : EDGES_MS;
  const bins: LatencyBin[] = edges.map((edge, index) => ({
    key: `le-${edge}`,
    label: limitMs !== undefined && index === edges.length - 1 ? secondsLabel(limitSeconds as number) : edgeLabel(edge),
    count: 0,
    over: false,
    limit: index === edges.length - 1,
  }));
  bins.push({ key: 'over', label: limitMs !== undefined ? '넘음' : '1초 넘음', count: 0, over: true, limit: false });
  for (const value of values) {
    const at = edges.findIndex((edge) => value <= edge);
    bins[at < 0 ? bins.length - 1 : at].count += 1;
  }
  const ordered = [...values].sort((a, b) => a - b);
  return { samples: values.length, bins, overCount: bins[bins.length - 1].count, maxMs: values.length ? Math.max(...values) : undefined, limitSeconds,
    ...(ordered.length ? { p95Ms: ordered[Math.ceil(ordered.length * 0.95) - 1] } : {}) };
}

export interface UninspectedBucket { key: string; start: number; total: number }
export interface UninspectedSeries { buckets: UninspectedBucket[]; byKind: Record<UninspectedKey, number>; total: number }

/** 검사 못 한 요청을 처리 시간 추이와 같은 구간에 나눠 센다(구간 밖 기록은 세지 않음 — 추이와 같은 규칙) */
export function uninspectedSeries(events: readonly SecurityEvent[], buckets: readonly EventTimeBucket[]): UninspectedSeries {
  const counts = buckets.map((bucket) => ({ key: bucket.bucket, start: bucket.start, total: 0 }));
  const byKind: Record<UninspectedKey, number> = { 'no-response': 0, uninspectable: 0, 'too-large': 0 };
  let total = 0;
  for (const event of events) {
    const kind = uninspectedKind(event);
    if (!kind) continue;
    const at = Date.parse(event.occurredAt);
    const index = buckets.findIndex((bucket) => at >= bucket.start && at < bucket.end);
    if (index < 0) continue;
    counts[index].total += 1;
    byKind[kind] += 1;
    total += 1;
  }
  return { buckets: counts, byKind, total };
}

// ── 지표 정리(2026-10-14 피드백 "산정 기준이 모호"): 화면에 분모·표본 수를 직접 적기 위한 계산. 모두 위와 같은 기간 이벤트 목록에서 센다.

/** 처리 시간 기록으로 쓰는 값: 있고, 유한하고, 0 이상(latencyDistribution·normalizeEventSeries와 같은 규칙) */
const hasProcessing = (event: SecurityEvent) => event.processingMs !== undefined && Number.isFinite(event.processingMs) && event.processingMs >= 0;

export interface LatencySamples { events: number; samples: number; prompt: number; file: number }

/** 기간 이벤트 수와 그중 처리 시간 기록 수(프롬프트·파일 따로). 처리 시간 분포·시간대별 처리 시간의 표본 수와 같다 */
export function latencySamples(events: readonly SecurityEvent[]): LatencySamples {
  const measured = events.filter(hasProcessing);
  const file = measured.filter((event) => event.contentType === 'file').length;
  return { events: events.length, samples: measured.length, prompt: measured.length - file, file };
}

/** 시간 구간마다 처리 시간 기록 수(처리 시간 추이의 평균·P95가 이 건수로 계산됨). 구간 밖 기록은 세지 않음 */
export function bucketSamples(events: readonly SecurityEvent[], buckets: readonly EventTimeBucket[]): number[] {
  const counts = buckets.map(() => 0);
  for (const event of events) {
    if (!hasProcessing(event)) continue;
    const at = Date.parse(event.occurredAt);
    const index = buckets.findIndex((bucket) => at >= bucket.start && at < bucket.end);
    if (index >= 0) counts[index] += 1;
  }
  return counts;
}

/** P95가 가장 큰 구간(같으면 앞 구간). 처리 시간 기록이 없으면 없음 */
export function slowestBucket<T extends { p95LatencyMs?: number }>(buckets: readonly T[]): T | undefined {
  let found: T | undefined;
  for (const bucket of buckets) if (bucket.p95LatencyMs !== undefined && (found === undefined || bucket.p95LatencyMs > (found.p95LatencyMs as number))) found = bucket;
  return found;
}

/** 초당 요청 수 → 집계 구간(초) 동안의 요청 수. 서버가 '구간 요청 수 ÷ 구간 초'로 보낸 값을 되돌린다(Gateway는 소수 셋째 자리 반올림 → 60초면 오차 0.03건 이내) */
export function requestsInWindow(perSecond: number | undefined, windowSeconds: number | undefined): number | undefined {
  if (perSecond === undefined || windowSeconds === undefined || !Number.isFinite(perSecond) || perSecond < 0) return undefined;
  return Math.round(perSecond * windowSeconds);
}

/** 막대가 많을 때 눈금 글자를 n개마다 하나만(좁은 화면에서 겹치지 않게) */
export function sparseLabels(labels: readonly string[], keep = 8) {
  const step = Math.max(1, Math.ceil(labels.length / keep));
  const last = labels.length - 1;
  // 2026-10-16 화면 점검: 마지막 눈금이 바로 앞 눈금과 반 칸 간격도 안 되면(30일 × 390px에서 '10.15'·'10.16' 겹침) 앞 눈금을 비운다
  const previous = last - (last % step === 0 ? step : last % step);
  return labels.map((label, index) => (index === last || (index % step === 0 && !(index === previous && (last - previous) * 2 < step)) ? label : ''));
}

/** 처리 시간 축 단위: 가장 큰 값이 1초 미만이면 ms(설계 5.9 "눈금 0.0085초 → 10 ms") */
export function latencyAxisUnit(maxMs: number | undefined): 'ms' | '초' {
  return maxMs !== undefined && maxMs < 1000 ? 'ms' : '초';
}
