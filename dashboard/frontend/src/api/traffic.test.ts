import { describe, expect, it } from 'vitest';
import { mapTrafficClientsDto, mapTrafficSnapshotDto } from './mappers';
import { parseApiResponse, trafficClientsSchema, trafficSnapshotSchema } from './schemas';

const payload = {
  summary: {
    active_clients: 3,
    concurrent_requests: 7,
    requests_per_sec: 12.5,
    average_latency_ms: 90,
    p95_latency_ms: 140,
    timeout_rate: 0.01,
    degraded_rate: 0.02,
    gateway_status: 'HEALTHY' as const,
  },
  time_series: [{
    timestamp: '2026-09-18T12:00:00+09:00', request_count: 10,
    allow_count: 8, mask_count: 1, block_count: 1,
    average_latency_ms: 90, p95_latency_ms: 140,
  }],
};

describe('traffic telemetry contract', () => {
  it('maps live counters and no longer carries the recent request list', () => {
    const parsed = parseApiResponse(trafficSnapshotSchema, payload);
    const mapped = mapTrafficSnapshotDto(parsed, '24H');
    expect(mapped.summary.concurrentRequests).toBe(7);
    expect('recent' in mapped).toBe(false);
  });
  it('carries the backend reason when live latency from a legacy Gateway is withheld', () => {
    const live = { ...payload, summary: { ...payload.summary, metric_source: 'GATEWAY_LIVE' as const, average_latency_ms: undefined, p95_latency_ms: undefined } };
    const withheld = mapTrafficSnapshotDto(parseApiResponse(trafficSnapshotSchema, { ...live, summary: { ...live.summary, latency_unavailable_reason: 'LEGACY_GATEWAY' } }), '24H');
    expect(withheld.summary).toMatchObject({ metricSource: 'GATEWAY_LIVE', latencyUnavailableReason: 'LEGACY_GATEWAY', averageLatencyMs: undefined, p95LatencyMs: undefined });
    // 이전 백엔드는 칸을 보내지 않는다 → 이유 없음(지금처럼 표시)
    expect(mapTrafficSnapshotDto(parseApiResponse(trafficSnapshotSchema, payload), '24H').summary.latencyUnavailableReason).toBeUndefined();
    expect(() => parseApiResponse(trafficSnapshotSchema, { ...live, summary: { ...live.summary, latency_unavailable_reason: 'SOMETHING_ELSE' } }))
      .toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });
  it('preserves actual process counters separately from selected-period events', () => {
    const parsed = parseApiResponse(trafficSnapshotSchema, { ...payload, summary: { ...payload.summary,
      metric_source: 'GATEWAY_LIVE', gateway_total_requests: 100, gateway_completed_requests: 90,
      gateway_error_requests: 2, gateway_window_seconds: 60, latency_sample_count: 90 } });
    expect(mapTrafficSnapshotDto(parsed, '30D').summary).toMatchObject({
      gatewayTotalRequests: 100, gatewayCompletedRequests: 90, gatewayErrorRequests: 2,
      gatewayWindowSeconds: 60, latencySampleCount: 90,
    });
  });
});

// 연결 중인 IP(2026-10-12): GET /api/traffic/clients. IP는 문서용 대역만 쓴다
const clientsPayload = {
  received_at: '2026-10-12T02:00:00.000Z',
  stale: false,
  window_seconds: 300,
  clients: [
    { ip: '203.0.113.5', client_id: 'chrome-00000000-0000-4000-8000-000000000001', connections: 2, inflight: 1, waiting: 2, requests_5m: 7,
      targets: { Claude: 2, ChatGPT: 5, Gemini: 0 }, first_seen_at: '2026-10-12T01:00:00.000Z', last_seen_at: '2026-10-12T01:59:58.000Z' },
    { ip: '2001:db8::1', client_id: null, connections: 0, inflight: 0, requests_5m: 0,
      targets: {}, first_seen_at: '2026-10-12T01:40:00+00:00', last_seen_at: '2026-10-12T01:52:00+00:00' },
  ],
};

describe('connected client IP contract', () => {
  it('maps clients in server order, sorts targets by count and drops zero counts', () => {
    const mapped = mapTrafficClientsDto(parseApiResponse(trafficClientsSchema, clientsPayload));
    expect(mapped).toMatchObject({ receivedAt: '2026-10-12T02:00:00.000Z', stale: false, windowSeconds: 300 });
    expect(mapped.clients.map(client => client.ip)).toEqual(['203.0.113.5', '2001:db8::1']);
    expect(mapped.clients[0]).toMatchObject({ clientId: 'chrome-00000000-0000-4000-8000-000000000001', connections: 2, inflight: 1, waiting: 2, requests5m: 7,
      targets: [{ llm: 'ChatGPT', count: 5 }, { llm: 'Claude', count: 2 }] });
    expect(mapped.clients[1]).toMatchObject({ clientId: undefined, connections: 0, targets: [] });
  });

  it('treats a missing waiting (old backend or gateway) as 0 and keeps a sent value', () => {
    // clientsPayload의 둘째 항목은 waiting 칸이 없다
    expect('waiting' in clientsPayload.clients[1]).toBe(false);
    const mapped = mapTrafficClientsDto(parseApiResponse(trafficClientsSchema, clientsPayload));
    expect(mapped.clients.map(client => client.waiting)).toEqual([2, 0]);
    // DTO를 직접 넘겨도(waiting 없음) 0
    expect(mapTrafficClientsDto({ ...clientsPayload, clients: [{ ...clientsPayload.clients[1], targets: {} }] }).clients[0].waiting).toBe(0);
  });

  it('accepts a backend that has not received metrics yet', () => {
    const mapped = mapTrafficClientsDto(parseApiResponse(trafficClientsSchema, { received_at: null, stale: true, window_seconds: 300, clients: [] }));
    expect(mapped).toEqual({ receivedAt: undefined, stale: true, windowSeconds: 300, clients: [] });
  });

  it('rejects values outside the contract', () => {
    const client = clientsPayload.clients[0];
    for (const bad of [
      { ...clientsPayload, stale: undefined },
      { ...clientsPayload, received_at: 'yesterday' },
      { ...clientsPayload, clients: [{ ...client, connections: -1 }] },
      { ...clientsPayload, clients: [{ ...client, requests_5m: 1.5 }] },
      { ...clientsPayload, clients: [{ ...client, waiting: -1 }] },
      { ...clientsPayload, clients: [{ ...client, waiting: 1.5 }] },
      { ...clientsPayload, clients: [{ ...client, waiting: '2' }] },
      { ...clientsPayload, clients: [{ ...client, waiting: null }] },
      { ...clientsPayload, clients: [{ ...client, ip: 'x'.repeat(46) }] },
      { ...clientsPayload, clients: [{ ...client, client_id: 'c'.repeat(81) }] },
      { ...clientsPayload, clients: [{ ...client, targets: { Claude: -1 } }] },
      { ...clientsPayload, clients: Array.from({ length: 201 }, () => client) },
    ]) expect(() => parseApiResponse(trafficClientsSchema, bad)).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });
});
