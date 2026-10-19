import { afterEach, describe, expect, it, vi } from 'vitest';
import { gatewayStateText } from '@/src/services/gatewaySettingsService';
import { httpGatewayApi } from './httpAdapter';
import { httpClient } from './httpClient';
import { gatewaySettingsResponseSchema, type GatewaySettingsResponse, type GatewaySettingsValues } from './gatewaySettingsSchemas';

// 실제 HTTP 어댑터: Gateway 처리 설정 GET·PUT(명세 §3.1·§3.2)과 문서 등록 업로드 제한 시간(§6). 값은 모두 가짜.
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const values: GatewaySettingsValues = {
  timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'block', seconds: 2 } },
  uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
  notify_on_allow: false,
};
const body: GatewaySettingsResponse = {
  settings: { ...values, version: 3, revision: REV, updated_at: '2026-10-10T05:12:00.000Z', updated_by: 'local-admin', source: 'STORED' },
  defaults: values,
  gateway: {
    state: 'APPLIED', metrics_status: 'FRESH', reported_at: '2026-10-10T05:12:08.120Z', applied_version: 3, applied_revision: REV,
    applied_source: 'DASHBOARD', applied_at: '2026-10-10T05:12:07.900000+00:00', first_seen_at: '2026-10-10T05:12:08.120Z', rejected: null, effective: values,
  },
};
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('gateway settings over HTTP', () => {
  it('reads the settings with the session cookie', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(body));
    vi.stubGlobal('fetch', fetchMock);
    await expect(httpGatewayApi.getGatewaySettings()).resolves.toEqual(body);
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(new URL(String(url)).pathname).toBe('/api/gateway-settings');
    expect(init).toMatchObject({ method: 'GET', credentials: 'include' });
  });

  it('sends exactly expected_version and the three setting groups with PUT', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ...body, settings: { ...body.settings, version: 4 } }));
    vi.stubGlobal('fetch', fetchMock);
    const saved = await httpGatewayApi.saveGatewaySettings({ expected_version: 3, ...values, timeout: { ...values.timeout, file: { action: 'forward', seconds: 0.125 } } });
    expect(saved.settings.version).toBe(4);
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(new URL(String(url)).pathname).toBe('/api/gateway-settings');
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(String(init.body))).toEqual({
      expected_version: 3,
      timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'forward', seconds: 0.125 } },
      uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
      notify_on_allow: false,
    });
  });

  it('does not send a body with fields outside the contract', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(httpGatewayApi.saveGatewaySettings({ expected_version: 3, ...values, extra: true } as never)).rejects.toMatchObject({ code: 'VALIDATION' });
    await expect(httpGatewayApi.saveGatewaySettings({ expected_version: 3, ...values, timeout: { ...values.timeout, prompt: { action: 'forward', seconds: 0.04 } } })).rejects.toMatchObject({ code: 'VALIDATION' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [409, 'CONFLICT'],
    [503, 'SERVER'],
    [422, 'VALIDATION'],
    [400, 'VALIDATION'],
  ])('maps PUT %s to %s', async (status, code) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: { code: 'X' } }, status)));
    await expect(httpGatewayApi.saveGatewaySettings({ expected_version: 3, ...values })).rejects.toMatchObject({ code, status });
  });

  it('rejects a response that does not match the settings document', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ ...body, settings: { ...body.settings, unknown_field: 1 } })));
    await expect(httpGatewayApi.getGatewaySettings()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ ...body, gateway: { ...body.gateway, state: 'SOMETHING' } })));
    await expect(httpGatewayApi.getGatewaySettings()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
});

// 실제 대시보드 백엔드(dash-work app.mjs, 임시 JSON 저장소·가짜 값)가 돌려준 본문 그대로(2026-10-10 리뷰 반영).
// 백엔드는 Gateway 보고를 관대하게 받는다: 거부 문서 번호 null(rejected.version), Gateway 시각 null(applied_at)도 그대로 돌려준다
const CAPTURED_REV1 = 'c661d638-232d-4ca8-a9b8-2eac9a338c96';
const captured = {
  // Gateway가 디스크 사본(CACHE)으로 v1을 적용, applied_at 없음 → APPLIED
  appliedWithoutGatewayClock: {"settings":{"version":1,"revision":"c661d638-232d-4ca8-a9b8-2eac9a338c96","updated_at":"2026-10-10T06:25:01.912Z","updated_by":"local-admin","timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":3}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false,"source":"STORED"},"defaults":{"timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":2}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false},"gateway":{"state":"APPLIED","metrics_status":"FRESH","reported_at":"2026-10-10T06:25:01.916Z","applied_version":1,"applied_revision":"c661d638-232d-4ca8-a9b8-2eac9a338c96","applied_source":"CACHE","applied_at":null,"first_seen_at":"2026-10-10T06:25:01.916Z","rejected":null,"effective":{"timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":3}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false}}},
  // Gateway가 v1을 거부, 거부 문서 번호 null → REJECTED
  rejectedWithoutVersion: {"settings":{"version":1,"revision":"c661d638-232d-4ca8-a9b8-2eac9a338c96","updated_at":"2026-10-10T06:25:01.912Z","updated_by":"local-admin","timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":3}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false,"source":"STORED"},"defaults":{"timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":2}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false},"gateway":{"state":"REJECTED","metrics_status":"FRESH","reported_at":"2026-10-10T06:25:01.919Z","applied_version":0,"applied_revision":null,"applied_source":"ENV_DEFAULT","applied_at":"2026-10-10T05:12:07.900Z","first_seen_at":"2026-10-10T06:25:01.919Z","rejected":{"version":null,"revision":"c661d638-232d-4ca8-a9b8-2eac9a338c96","field":"version"},"effective":{"timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":2}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false}}},
  // 그 상태에서 PUT(expected_version 1) → v2 저장, 응답 gateway.rejected.version은 여전히 null
  savedWhileRejectedWithoutVersion: {"settings":{"version":2,"revision":"53c67346-362d-4f2e-a0a6-f9f586e1c8c0","updated_at":"2026-10-10T06:25:01.923Z","updated_by":"local-admin","timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":2}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false,"source":"STORED"},"defaults":{"timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":2}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false},"gateway":{"state":"PENDING","metrics_status":"FRESH","reported_at":"2026-10-10T06:25:01.919Z","applied_version":0,"applied_revision":null,"applied_source":"ENV_DEFAULT","applied_at":"2026-10-10T05:12:07.900Z","first_seen_at":"2026-10-10T06:25:01.919Z","rejected":{"version":null,"revision":"c661d638-232d-4ca8-a9b8-2eac9a338c96","field":"version"},"effective":{"timeout":{"prompt":{"action":"forward","seconds":0.5},"file":{"action":"block","seconds":2}},"uninspectable":{"image":"allow","scanned_pdf":"block","other":"block"},"notify_on_allow":false}}},
};

describe('gateway settings bodies captured from the dashboard backend', () => {
  it('reads every GET body, including a rejection reported without a version', async () => {
    for (const captureBody of [captured.appliedWithoutGatewayClock, captured.rejectedWithoutVersion]) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(captureBody)));
      await expect(httpGatewayApi.getGatewaySettings()).resolves.toEqual(captureBody);
    }
  });

  it('reads the PUT response of a save made while that rejection is reported', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(captured.savedWhileRejectedWithoutVersion)));
    const saved = await httpGatewayApi.saveGatewaySettings({ expected_version: 1, ...values });   // 저장은 이미 끝났으므로 '저장 실패'가 아니어야 한다
    expect(saved.settings.version).toBe(2);
    expect(saved.gateway.rejected).toEqual({ version: null, revision: CAPTURED_REV1, field: 'version' });
  });

  it('writes the status line of those bodies without a repeated or missing word', () => {
    expect(gatewayStateText(gatewaySettingsResponseSchema.parse(captured.appliedWithoutGatewayClock).gateway))
      .toEqual({ tone: 'ok', text: 'Gateway 반영 v1 · 확인 15:25:01' });   // Gateway 시각이 없으면 그 부분을 뺀다
    expect(gatewayStateText(gatewaySettingsResponseSchema.parse(captured.rejectedWithoutVersion).gateway))
      .toEqual({ tone: 'warn', text: 'Gateway가 이 설정을 거부함 · 거부한 칸 version' });
  });
});

describe('upload timeout', () => {
  const hanging = () => vi.fn((_url: URL, options: RequestInit) => new Promise((_resolve, reject) =>
    options.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))));

  it('gives protected-document registration 120 seconds', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', hanging());
    let settled = false;
    const pending = httpGatewayApi.registerDocument(new File(['fake'], 'fake.pdf', { type: 'application/pdf' }))
      .finally(() => { settled = true; });
    const result = expect(pending).rejects.toMatchObject({ code: 'TIMEOUT' });
    await vi.advanceTimersByTimeAsync(10_001);
    expect(settled).toBe(false);   // 일반 요청 제한(10초)으로 끊지 않는다
    await vi.advanceTimersByTimeAsync(110_000);
    await result;
  });

  it('keeps 10 seconds for other requests, including other form posts', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', hanging());
    const get = expect(httpClient.get('/api/events')).rejects.toMatchObject({ code: 'TIMEOUT' });
    const form = expect(httpClient.postForm('/api/other', new FormData())).rejects.toMatchObject({ code: 'TIMEOUT' });
    await vi.advanceTimersByTimeAsync(10_001);
    await get;
    await form;
  });
});
