import { describe, expect, it } from 'vitest';
import { formatLatency, formatTrafficRate, gatewayHealthExplanation, trafficSourceLabel, trafficSourceDescription, trafficTimeLabels } from './trafficPresentation';

describe('truthful traffic presentation', () => {
  it('includes dates for a 24-hour chart crossing a Korean midnight', () => {
    const labels = trafficTimeLabels(['2026-10-05T14:45:00Z', '2026-10-05T15:15:00Z'], '24H');
    expect(labels[0]).toContain('05.'); expect(labels[1]).toContain('06.');
    expect(labels[0]).toContain('23:45'); expect(labels[1]).toContain('00:15');
  });
  it('keeps same-day labels compact and handles absent or invalid chart dates honestly', () => {
    expect(trafficTimeLabels(['2026-10-05T01:00:00Z'], '24H')).toEqual(['10:00']);
    expect(trafficTimeLabels([], '24H')).toEqual([]);
    expect(trafficTimeLabels(['invalid'], '30D')).toEqual(['시각 미기록']);
    expect(trafficTimeLabels(['2026-10-05T01:00:00Z'], '30D')[0]).toContain('05.');
  });
  it('explains cumulative errors without claiming an ongoing outage',()=>{
    const result=gatewayHealthExplanation({metricSource:'GATEWAY_LIVE',gatewayStatus:'DEGRADED',gatewayErrorRequests:9,degradedRate:0});
    expect(result.label).toBe('오류 기록 있음');expect(result.detail).toContain('오류 9건');expect(result.detail).toContain('지속된다는 뜻은 아닙니다');expect(result.detail).not.toContain('장애 기록');
  });
  it('preserves a warning without inventing its cause',()=>{
    const result=gatewayHealthExplanation({metricSource:'GATEWAY_LIVE',gatewayStatus:'DEGRADED'});
    expect(result.label).toBe('상태 확인 필요');expect(result.detail).toContain('판정 근거는 제공되지');
  });
  it('does not hide degraded telemetry just because completed requests are zero',()=>expect(gatewayHealthExplanation({metricSource:'GATEWAY_LIVE',gatewayStatus:'DEGRADED',gatewayCompletedRequests:0,degradedRate:.01}).label).toBe('오류 기록 있음'));
  it('does not infer live health from stored events',()=>expect(gatewayHealthExplanation({metricSource:'STORED_EVENTS',gatewayStatus:'HEALTHY'}).label).toBe('확인 불가'));
  it('keeps unmeasured and unknown health distinct from healthy',()=>{
    expect(gatewayHealthExplanation({metricSource:'GATEWAY_LIVE',gatewayStatus:'UNKNOWN',gatewayCompletedRequests:0}).label).toBe('요청 대기');
    expect(gatewayHealthExplanation({metricSource:'GATEWAY_LIVE',gatewayStatus:'UNKNOWN'}).label).toBe('확인 불가');
    expect(gatewayHealthExplanation({metricSource:'GATEWAY_LIVE',gatewayStatus:'HEALTHY',gatewayCompletedRequests:1}).label).toBe('정상');
  });
  it('does not round nonzero rates to zero or near complete rates to complete',()=>{
    expect(formatTrafficRate(.0001)).toBe('0.1% 미만');expect(formatTrafficRate(.9999)).toBe('99.9% 초과');expect(formatTrafficRate(0)).toBe('0.0%');expect(formatTrafficRate(1)).toBe('100.0%');expect(formatTrafficRate(NaN)).toBe('미제공');
  });
  it('never interprets absent provenance as live telemetry', () => {
    expect(trafficSourceLabel({ gatewayStatus: 'UNKNOWN' })).toBe('지표 출처 미확인');
    expect(trafficSourceDescription({ gatewayStatus: 'UNKNOWN' })).toContain('단정하지 않습니다');
  });
  it('distinguishes stale telemetry from stored events', () => {
    const summary = { gatewayStatus: 'UNKNOWN', metricSource: 'STORED_EVENTS', gatewayMetricsStatus: 'STALE', eventCount: 5 } as const;
    expect(trafficSourceLabel(summary)).toBe('저장 이벤트 집계');
    expect(trafficSourceDescription(summary)).toContain('30초 이상 지연');   // 2026-10-15: 시스템 상태·연결 IP 표와 같은 30초 기준
    expect(trafficSourceDescription(summary)).toContain('5건');
  });
  it('formats latency for people without inventing unavailable values', () => {
    expect(formatLatency(8079.224)).toBe('8.08초');
    expect(formatLatency(270.123)).toBe('0.27초');
    expect(formatLatency()).toBe('확인 불가');
    expect(formatLatency(0)).toBe('0초');
    expect(formatLatency(0.3)).toBe('0.01초 미만');
  });
  it('does not equate actual HTTP traffic with human questions or users', () => {
    const description = trafficSourceDescription({ gatewayStatus: 'UNKNOWN', metricSource: 'GATEWAY_LIVE' });
    expect(description).toContain('HTTP');
    expect(description).toContain('질문 수·사용자 수와 같지 않습니다');
    expect(description).toContain('저장 보안 이벤트');
  });
});
