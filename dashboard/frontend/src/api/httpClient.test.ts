import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpClient, setUnauthorizedHandler } from './httpClient';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  setUnauthorizedHandler(undefined);
});

describe('HTTP client hardening', () => {
  it('sends multipart data without setting the Content-Type boundary', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ ok: true }), { status: 200 }),
      );
    vi.stubGlobal('fetch', fetchMock);
    const body = new FormData();
    body.append('file', new File(['safe fixture'], 'fixture.txt'));
    await httpClient.postForm('/api/documents', body);
    const options = fetchMock.mock.calls[0][1] as RequestInit;
    expect(options.body).toBe(body);
    expect(options.headers).toBeUndefined();
  });
  it('invokes the unauthorized hook once for 401', async () => {
    const unauthorized = vi.fn();
    setUnauthorizedHandler(unauthorized);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(null, { status: 401 })),
    );
    await expect(httpClient.get('/api/events')).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
      status: 401,
    });
    expect(unauthorized).toHaveBeenCalledOnce();
  });
  it.each([413, 415])(
    'maps actionable request status %s to a validation error without fallback',
    async (status) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(new Response(null, { status })),
      );
      await expect(httpClient.get('/api/events')).rejects.toMatchObject({
        code: 'VALIDATION',
        status,
      });
    },
  );
  it('normalizes a timed out request', async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url, options: RequestInit) =>
          new Promise((_resolve, reject) =>
            options.signal?.addEventListener('abort', () =>
              reject(new DOMException('aborted', 'AbortError')),
            ),
          ),
      ),
    );
    const pending = expect(httpClient.get('/api/events')).rejects.toMatchObject(
      { code: 'TIMEOUT' },
    );
    await vi.advanceTimersByTimeAsync(10_001);
    await pending;
  });
});
