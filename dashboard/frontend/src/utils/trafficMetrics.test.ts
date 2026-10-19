import { describe, expect, it } from 'vitest';
import type { SecurityEvent } from '@/src/types/event';
import type { EventTimeBucket } from './eventSeries';
import { FEW_SAMPLES, bucketSamples, latencyAxisUnit, latencyDistribution, latencySamples, requestsInWindow, slowestBucket, sparseLabels, uninspectedSeries } from './trafficMetrics';
import { normalizeEventSeries } from './eventSeries';

// 재설계 3c(설계 5.9.1 권고 ①②③): 서버 변경 없이 기존 응답으로 계산하는 트래픽 지표
const base: SecurityEvent = { eventId: 'e', occurredAt: '2026-10-13T01:30:00Z', clientId: 'c', targetLlm: 'ChatGPT', detectionOutcome: 'MATCH', finalAction: 'ALLOW', status: 'NEW', detections: [], adminNotes: [], timeline: [] };
const ev = (extra: Partial<SecurityEvent>): SecurityEvent => ({ ...base, ...extra });

describe('① 처리 시간 분포', () => {
  it('splits prompts and files into the same 7 bins ending at the wait setting, and counts values over it', () => {
    const events = [5, 10, 25, 90, 250, 900, 2500, 3500].map((processingMs, index) => ev({ eventId: `p${index}`, processingMs, contentType: 'prompt' }));
    events.push(ev({ eventId: 'f1', processingMs: 9000, contentType: 'file' }), ev({ eventId: 'x', contentType: 'prompt' }));
    const prompt = latencyDistribution(events, 'prompt', 3);
    expect(prompt.bins.map((bin) => bin.label)).toEqual(['~10ms', '~30ms', '~0.1초', '~0.3초', '~1초', '~3초', '넘음']);
    expect(prompt.bins.map((bin) => bin.count)).toEqual([2, 1, 1, 1, 1, 1, 1]);   // 10ms는 '~10ms'(이하)
    expect(prompt.samples).toBe(8);                                                 // 처리 시간 없는 기록은 세지 않음
    expect(prompt.overCount).toBe(1);
    expect(prompt.bins.find((bin) => bin.limit)?.label).toBe('~3초');
    const file = latencyDistribution(events, 'file', 10);
    expect(file.bins.at(-2)?.label).toBe('~10초');
    expect(file.bins.at(-2)?.count).toBe(1);
  });
  it('drops fixed edges at or above a short setting and falls back to 1 second without settings', () => {
    expect(latencyDistribution([], 'prompt', 0.25).bins.map((bin) => bin.label)).toEqual(['~10ms', '~30ms', '~0.1초', '~0.25초', '넘음']);
    expect(latencyDistribution([], 'prompt').bins.map((bin) => bin.label)).toEqual(['~10ms', '~30ms', '~0.1초', '~0.3초', '~1초', '1초 넘음']);
  });
  it('uses ms on the axis only below one second', () => {
    expect(latencyAxisUnit(850)).toBe('ms');
    expect(latencyAxisUnit(1500)).toBe('초');
    expect(latencyAxisUnit(undefined)).toBe('초');
  });
});

describe('② 검사 못 한 요청(시간별)', () => {
  const bucket = (hour: number): EventTimeBucket => {
    const start = Date.parse(`2026-10-13T0${hour}:00:00Z`);
    return { bucket: `b${hour}`, timestamp: new Date(start).toISOString(), start, end: start + 3_600_000, partial: false, total: 0, block: 0, mask: 0, allow: 0 };
  };
  it('counts uninspected events into the trend buckets by reason, excluding access blocks and events outside the buckets', () => {
    const result = uninspectedSeries([
      ev({ degraded: true }), ev({ occurredAt: '2026-10-13T02:10:00Z', reasonCode: 'file_uninspectable_image' }),
      ev({ occurredAt: '2026-10-13T02:20:00Z', reasonCode: 'file_too_large', finalAction: 'BLOCK' }), ev({ reasonCode: 'client_blocked', degraded: true }),
      ev({ occurredAt: '2026-10-12T20:00:00Z', degraded: true }), ev({}),
    ], [bucket(1), bucket(2)]);
    expect(result.buckets.map((item) => item.total)).toEqual([1, 2]);
    expect(result.byKind).toEqual({ 'no-response': 1, uninspectable: 1, 'too-large': 1 });
    expect(result.total).toBe(3);
  });
  it('thins axis labels so they do not overlap on a narrow screen', () => {
    const labels = sparseLabels(Array.from({ length: 24 }, (_, hour) => `${hour}시`), 8);
    expect(labels.filter(Boolean)).toEqual(['0시', '3시', '6시', '9시', '12시', '15시', '18시', '21시', '23시']);
  });
});

// 2026-10-14 지표 정리: 화면에 적는 분모·표본 수가 그림의 표본 수와 같은지
describe('표본 수·분모(지표 정리)', () => {
  const events = [
    ev({ eventId: 'p1', occurredAt: '2026-10-13T01:10:00Z', processingMs: 12, contentType: 'prompt' }),
    ev({ eventId: 'p2', occurredAt: '2026-10-13T01:20:00Z', processingMs: 1720 }),                 // contentType 없음 = 프롬프트(분포와 같은 규칙)
    ev({ eventId: 'f1', occurredAt: '2026-10-13T02:05:00Z', processingMs: 300, contentType: 'file' }),
    ev({ eventId: 'x1', occurredAt: '2026-10-13T02:06:00Z' }),                                        // 처리 시간 없음(옛 기록)
    ev({ eventId: 'x2', occurredAt: '2026-10-13T02:07:00Z', processingMs: -1 }),                      // 잘못된 값
  ];
  it('counts events and processing-time records the same way as the distribution and the trend buckets', () => {
    const totals = latencySamples(events);
    expect(totals).toEqual({ events: 5, samples: 3, prompt: 2, file: 1 });
    expect(totals.prompt).toBe(latencyDistribution(events, 'prompt', 3).samples);
    expect(totals.file).toBe(latencyDistribution(events, 'file', 10).samples);
    const series = normalizeEventSeries(events, '24H', Date.parse('2026-10-13T03:00:00Z'));
    const perBucket = bucketSamples(events, series.buckets);
    expect(perBucket.reduce((sum, count) => sum + count, 0)).toBe(totals.samples);   // 막대 툴팁 기록 수의 합 = 묶음 머리의 처리 시간 기록 수
    const hour1 = series.buckets.findIndex((bucket) => bucket.start === Date.parse('2026-10-13T01:00:00Z'));
    expect(perBucket[hour1]).toBe(2);
    expect(slowestBucket(series.buckets)?.start).toBe(Date.parse('2026-10-13T01:00:00Z'));   // P95 1.72초인 구간
    expect(slowestBucket(series.buckets)?.p95LatencyMs).toBe(1720);
    expect(slowestBucket([{ p95LatencyMs: undefined }])).toBeUndefined();
  });
  it('turns the per-second rate back into the count of the window and keeps the P95 = maximum boundary at 20', () => {
    expect(requestsInWindow(0.417, 60)).toBe(25);      // Gateway가 25 ÷ 60 = 0.41666…을 셋째 자리로 반올림해 보냄
    expect(requestsInWindow(0.2, 300)).toBe(60);
    expect(requestsInWindow(undefined, 60)).toBeUndefined();
    expect(requestsInWindow(0.5, undefined)).toBeUndefined();
    // 가장 가까운 순위 P95 = ceil(n × 0.95)번째: 19건까지는 가장 긴 값, 20건부터 처음으로 다름
    const rank = (n: number) => Math.ceil(n * 0.95);
    expect(rank(FEW_SAMPLES - 1)).toBe(FEW_SAMPLES - 1);
    expect(rank(FEW_SAMPLES)).toBe(FEW_SAMPLES - 1);
  });
});
