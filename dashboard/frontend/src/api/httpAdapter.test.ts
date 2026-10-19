import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpGatewayApi } from './httpAdapter';

const eventDto = {
  event_id: 'EVT-12345678',
  occurred_at: '2026-08-16T10:00:00Z',
  client_id: 'CLT-1001',
  action: 'BLOCK',
  severity: 'CRITICAL',
  status: 'NEW',
  admin_notes: [],
  timeline: [],
  detections: [
    {
      detector: 'SHA256',
      match_type: 'EXACT_DOCUMENT',
      outbound_document_name: 'fixture.pdf',
      matched_document_id: 'DOC-1',
      action: 'BLOCK',
    },
  ],
  target_llm: 'ChatGPT',
  processing_ms: 10,
};
const filters = {
  query: '',
  period: '7D',
  finalAction: 'ALL',
  recommendedAction: 'ALL',
  detector: 'ALL',
  matchType: 'ALL',
  scoreKind: 'ALL',
  degraded: 'ALL',
  detectionOutcome: 'ALL',
  degradedReason: 'ALL',
  failurePolicy: 'ALL',
  documentId: '',
  severity: 'ALL',
  status: 'ALL',
  targetLlm: 'ALL',
  sort: 'OCCURRED_AT_DESC',
  page: 1,
  pageSize: 20,
} as const;
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
afterEach(() => vi.unstubAllGlobals());

describe('real HTTP adapter', () => {
  const trafficFetch = (failure?: string, status = 503) => vi.fn(async (url: string | URL) => {
    const path = new URL(String(url)).pathname;
    if (path.endsWith(failure ?? '!never')) return json({}, status);
    if (path.endsWith('/summary')) return json({ metric_source: 'STORED_EVENTS', gateway_status: 'UNKNOWN' });
    return json([]);
  });
  // 성능 측정 기록(/performance-runs)은 2026-10-13 화면에서 빼 읽지 않는다 - 부분 실패는 시간별 추이로 확인
  it('keeps successful traffic sections when the time series query fails', async () => {
    vi.stubGlobal('fetch', trafficFetch('/timeseries'));
    const result = await httpGatewayApi.getTrafficSnapshot('24H');
    expect(result.summary.metric_source).toBe('STORED_EVENTS');
    expect(result.unavailable_sections).toEqual(['timeseries']);
  });
  it('does not invent live metrics when the summary alone fails', async () => {
    vi.stubGlobal('fetch', trafficFetch('/summary'));
    const result = await httpGatewayApi.getTrafficSnapshot('24H');
    expect(result.summary).toEqual({});
    expect(result.unavailable_sections).toEqual(['summary']);
  });
  it('treats an authentication failure as an error, not partial success', async () => {
    vi.stubGlobal('fetch', trafficFetch('/timeseries', 401));
    await expect(httpGatewayApi.getTrafficSnapshot('24H')).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });
  it('does not fall back to demo traffic when the Backend is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await expect(httpGatewayApi.getTrafficSnapshot('24H')).rejects.toBeTruthy();
  });
  // 연결 중인 IP(2026-10-12): 최근 요청 목록은 더 이상 읽지 않고, 연결 IP는 따로 읽는다
  it('no longer requests the recent request list or performance runs', async () => {
    const fetch = trafficFetch();
    vi.stubGlobal('fetch', fetch);
    await httpGatewayApi.getTrafficSnapshot('24H');
    const paths = fetch.mock.calls.map(([url]) => new URL(String(url)).pathname);
    expect(paths.sort()).toEqual(['/api/traffic/summary', '/api/traffic/timeseries']);
  });
  it('reads connected client IPs from /api/traffic/clients and validates them', async () => {
    const fetch = vi.fn(async (_url: string | URL) => json({ received_at: null, stale: true, window_seconds: 300, clients: [] }));
    vi.stubGlobal('fetch', fetch);
    await expect(httpGatewayApi.getTrafficClients()).resolves.toEqual({ received_at: null, stale: true, window_seconds: 300, clients: [] });
    expect(new URL(String(fetch.mock.calls[0][0])).pathname).toBe('/api/traffic/clients');
    fetch.mockResolvedValueOnce(json({ received_at: null, stale: 'no', window_seconds: 300, clients: [] }));
    await expect(httpGatewayApi.getTrafficClients()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
  it('validates V4 event DTOs', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(
          json({
            items: [eventDto],
            total: 1,
            page: 1,
            page_size: 20,
            total_pages: 1,
          }),
        )
        .mockResolvedValueOnce(json(eventDto)),
    );
    await expect(httpGatewayApi.getEvents(filters)).resolves.toMatchObject({
      total: 1,
    });
    await expect(
      httpGatewayApi.getEvent('EVT-12345678'),
    ).resolves.toMatchObject({ severity: 'CRITICAL' });
  });
  it('rejects an invalid event schema', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        json({
          items: [{ event_id: 'broken' }],
          total: 1,
          page: 1,
          page_size: 20,
          total_pages: 1,
        }),
      ),
    );
    await expect(httpGatewayApi.getEvents(filters)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
    });
  });
  it('maps event detail 404 to null', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(null, { status: 404 })),
    );
    await expect(httpGatewayApi.getEvent('EVT-NOTFOUND')).resolves.toBeNull();
  });
  it('uploads multipart document data', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      json({
        document_id: 'DOC-12345678',
        document_name: 'fixture.txt',
        registered_at: '2026-08-16T10:00:00Z',
        status: 'ACTIVE',
        processing_status: 'READY',
        file_type: 'text/plain',
        file_size: 7,
        exact_fingerprint_status: 'READY',
        similarity_fingerprint_status: 'READY',
        chunk_index_status: 'READY',
        chunk_count: 1,
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    await httpGatewayApi.registerDocument(
      new File(['fixture'], 'fixture.txt', { type: 'text/plain' }),
    );
    expect((fetchMock.mock.calls[0][1] as RequestInit).body).toBeInstanceOf(
      FormData,
    );
  });
  it('sends explicit desired state and policy concurrency versions', async () => {
    const document = {
      document_id: 'DOC-12345678',
      document_name: 'fixture.txt',
      registered_at: '2026-08-16T10:00:00Z',
      status: 'INACTIVE',
      processing_status: 'READY',
      file_type: 'text/plain',
      file_size: 7,
      exact_fingerprint_status: 'READY',
      similarity_fingerprint_status: 'READY',
      chunk_index_status: 'READY',
      chunk_count: 1,
    };
    const policy = {
      policy_id: 'POL-001',
      detector: 'DOCUMENT',
      detection_target: 'EXACT_DOCUMENT',
      action: 'BLOCK',
      version: 3,
      enabled: false,
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(document))
      .mockResolvedValueOnce(json({ ...policy, enabled: true }))
      .mockResolvedValueOnce(json(policy));
    vi.stubGlobal('fetch', fetchMock);

    await httpGatewayApi.changeDocumentStatus('DOC-12345678', 'INACTIVE');
    await httpGatewayApi.updatePolicy('POL-001', 'BLOCK', 3);
    await httpGatewayApi.changePolicyStatus('POL-001', false, 3);

    expect(String(fetchMock.mock.calls[0][0])).toContain(
      '/api/documents/DOC-12345678/status',
    );
    expect(JSON.parse(fetchMock.mock.calls[0][1].body as string)).toEqual({
      status: 'INACTIVE',
    });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body as string)).toEqual({
      action: 'BLOCK',
      expected_version: 3,
    });
    expect(String(fetchMock.mock.calls[2][0])).toContain(
      '/api/policies/POL-001/status',
    );
    expect(JSON.parse(fetchMock.mock.calls[2][1].body as string)).toEqual({
      enabled: false,
      expected_version: 3,
    });
  });
});
