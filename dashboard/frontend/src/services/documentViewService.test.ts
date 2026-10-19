import { afterEach, describe, expect, it, vi } from 'vitest';
import { documentViewProblem, documentViewService } from './documentViewService';

// 재설계 3h: 본문 보기 서버 경로 3개 호출(계약 = backend/README.md 5절). 값은 모두 가짜.
const VIEW = {
  view_id: 'Qm9yZWQ0Ny1leGFtcGxlMQ', view_ref: '3F9A2C1B', document_id: '13_파트너사협상자료', document_name: '13_파트너사협상자료.docx', version: '3', format: 'docx', size: 48213,
  status: 'ACTIVE', index_status: 'READY', mode: 'original', issued_at: '2026-10-13T04:10:00.000Z', expires_at: '2026-10-13T12:10:00.000Z',
};
const json = (status: number, body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
afterEach(() => vi.unstubAllGlobals());

describe('document view service', () => {
  it('starts a view with the session cookie and no HTTP cache, and reads the issued view', async () => {
    const fetch = vi.fn().mockResolvedValue(json(201, VIEW));
    vi.stubGlobal('fetch', fetch);
    await expect(documentViewService.startView('13_파트너사협상자료', 'text')).resolves.toMatchObject({ view_ref: '3F9A2C1B', format: 'docx', size: 48213 });
    const [url, init] = fetch.mock.calls[0];
    expect(String(url)).toMatch(/\/api\/documents\/13_%ED%8C%8C%ED%8A%B8%EB%84%88%EC%82%AC%ED%98%91%EC%83%81%EC%9E%90%EB%A3%8C\/views$/);
    expect(init).toMatchObject({ method: 'POST', credentials: 'include', cache: 'no-store', body: '{"mode":"text"}' });
  });

  it('reads an unknown format as null instead of failing the whole view', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(201, { ...VIEW, format: null })));
    await expect(documentViewService.startView('legacy', 'original')).resolves.toMatchObject({ format: null });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(201, { ...VIEW, view_ref: 'not-hex' })));
    await expect(documentViewService.startView('legacy', 'original')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });

  it.each([
    [403, 'AUDIT_REQUIRED', 'audit-required'],
    [403, 'VIEW_FORBIDDEN', 'view-expired'],
    [409, 'DOCUMENT_VERSION_CHANGED', 'version-changed'],
    [413, 'PAYLOAD_TOO_LARGE', 'too-large'],
    [404, 'NOT_FOUND', 'not-found'],
    [401, 'UNAUTHORIZED', 'unauthorized'],
  ])('maps %s %s to "%s" from the server error code', async (status, code, problem) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(status, { error: { code, message: 'private detail' } })));
    const error = await documentViewService.getOriginal('doc', VIEW.view_id).catch((caught: unknown) => caught);
    expect(documentViewProblem(error)).toBe(problem);
    expect(String((error as Error).message)).not.toContain('private detail');
  });

  it('returns the original bytes and version without parsing them', async () => {
    const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]);
    const fetch = vi.fn().mockResolvedValue(new Response(bytes, { status: 200, headers: { 'Content-Type': 'application/pdf', 'X-Document-Version': '3' } }));
    vi.stubGlobal('fetch', fetch);
    const original = await documentViewService.getOriginal('doc/#1', VIEW.view_id);
    expect(new Uint8Array(original.data)).toEqual(bytes);
    expect(original.version).toBe('3');
    expect(String(fetch.mock.calls[0][0])).toMatch(/\/api\/documents\/doc%2F%231\/original\?view=Qm9yZWQ0Ny1leGFtcGxlMQ$/);
  });

  it('reads a text page in the evidence page shape', async () => {
    const page = { status: 'AVAILABLE', side: 'document', document_id: 'doc', char_start: 1800, char_end: 2000, total_chars: 2000, page_size: 1800, segments: [{ text: '본문', matched: false, redacted: false }], content_source: 'CURRENT_PROTECTED_DOCUMENT' };
    const fetch = vi.fn().mockResolvedValue(json(200, { document_id: 'doc', version: '3', index_status: 'PROCESSING', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', redaction: 'APPLIED', page }));
    vi.stubGlobal('fetch', fetch);
    await expect(documentViewService.getTextPage('doc', VIEW.view_id, 1800.7)).resolves.toMatchObject({ index_status: 'PROCESSING', page: { char_start: 1800 } });
    expect(String(fetch.mock.calls[0][0])).toMatch(/\/text\?view=Qm9yZWQ0Ny1leGFtcGxlMQ&offset=1800$/);
  });
});
