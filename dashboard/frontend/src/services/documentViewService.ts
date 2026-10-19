// 보호 문서 본문 보기(재설계 3h, 설계안 6.4) — 대시보드 백엔드 새 경로 3개를 부른다.
// 계약: docs/design/dashboard-redesign-2026-10-13/backend/README.md 2·5절
//   POST /api/documents/:id/views             열람 시작(감사 DOCUMENT_VIEW 1건 → 열람 번호)
//   GET  /api/documents/:id/original?view=     원본 바이트(그리기용. 내려받기 download=1은 2026-10-13 화면·서버에서 뺐다 — 서버 404)
//   GET  /api/documents/:id/text?view=&offset= 탐지 기준 텍스트 1,800자 쪽(근거 화면과 같은 가림)
// 원본 바이트는 react-query 캐시에 넣지 않는다(부르는 쪽이 상태로만 들고 닫으면 버림). 브라우저 저장소·HTTP 캐시도 쓰지 않는다(cache: 'no-store').
import { z } from 'zod';
import { env } from '@/src/config/env';
import { ApiError, normalizeApiError, type ApiErrorCode } from '@/src/api/errors';
import { parseApiResponse } from '@/src/api/schemas';
import { evidencePageSchema } from '@/src/services/evidenceService';

/** 등록 상한과 같은 20 MiB. 이보다 큰 원본은 서버가 413을 준다 → 처음부터 텍스트 보기 */
export const DOCUMENT_VIEW_LIMIT_BYTES = 20 * 1024 * 1024;
/** 원본 받기 제한 시간: 등록 업로드 제한(env.uploadTimeoutMs 기본 120초, 20 MiB를 1.5 Mbps로 보내는 시간)과 같게 둔다 */
const ORIGINAL_TIMEOUT_MS = 120_000;

export const DOCUMENT_VIEW_FORMATS = ['pdf', 'docx', 'xlsx', 'hwp', 'hwpx'] as const;
export type DocumentViewFormat = (typeof DOCUMENT_VIEW_FORMATS)[number];
export type DocumentViewMode = 'original' | 'text';

export const documentViewSchema = z.object({
  view_id: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  view_ref: z.string().regex(/^[0-9A-F]{8}$/),
  document_id: z.string().min(1),
  document_name: z.string(),
  version: z.string(),
  format: z.enum(DOCUMENT_VIEW_FORMATS).nullable().catch(null),
  size: z.number().int().nonnegative(),
  status: z.enum(['ACTIVE', 'INACTIVE']),
  index_status: z.enum(['READY', 'PROCESSING', 'FAILED']),
  mode: z.enum(['original', 'text']),
  issued_at: z.iso.datetime({ offset: true }),
  expires_at: z.iso.datetime({ offset: true }),
});
export type DocumentView = z.infer<typeof documentViewSchema>;

export const documentTextSchema = z.object({
  document_id: z.string(),
  version: z.string(),
  index_status: z.enum(['READY', 'PROCESSING', 'FAILED']),
  coordinate_system: z.literal('NORMALIZED_UNICODE_CODE_POINTS'),
  redaction: z.enum(['APPLIED', 'OFF']),
  page: evidencePageSchema,
});
export type DocumentTextPage = z.infer<typeof documentTextSchema>;

export interface DocumentOriginal {
  data: ArrayBuffer;
  version: string | null;
}

/** 본문 보기 호출의 오류: 서버 오류 코드(AUDIT_REQUIRED·VIEW_FORBIDDEN·DOCUMENT_VERSION_CHANGED 등)를 함께 든다 */
export class DocumentViewError extends ApiError {
  // 서버 코드 칸은 2026-10-15부터 공용 ApiError.serverCode(같은 이름·같은 뜻)를 쓴다
  constructor(code: ApiErrorCode, status: number, serverCode?: string) {
    super('요청을 처리하지 못했습니다.', code, status, serverCode || undefined);
    this.name = 'DocumentViewError';
  }
}

const codeForStatus = (status: number): ApiErrorCode =>
  status === 401 ? 'UNAUTHORIZED' : status === 403 ? 'FORBIDDEN' : status === 404 ? 'NOT_FOUND' : status === 409 ? 'CONFLICT'
    : status === 429 ? 'RATE_LIMITED' : [400, 413, 415, 422].includes(status) ? 'VALIDATION' : status >= 500 ? 'SERVER' : 'UNKNOWN';

async function serverErrorCode(response: Response) {
  try {
    const code = ((await response.json()) as { error?: { code?: unknown } })?.error?.code;
    return typeof code === 'string' && /^[A-Z_]{1,64}$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

// 공용 httpClient와 같은 방식(쿠키 포함·제한 시간)이지만 바이트 응답과 서버 오류 코드를 읽는다.
// 공용 파일(첫 화면 묶음)을 키우지 않으려고 이 지연 묶음 안에 따로 둔다.
// 401이면 이 화면은 '로그인이 만료됨'만 알리고, 로그인 화면 이동은 같은 화면의 10초 갱신(공용 httpClient)이 맡는다.
async function call(method: 'GET' | 'POST', path: string, options: { body?: Record<string, unknown>; signal?: AbortSignal; timeoutMs?: number } = {}) {
  const timeout = new AbortController();
  const timer = window.setTimeout(() => timeout.abort(), options.timeoutMs ?? env.httpTimeoutMs);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout.signal]) : timeout.signal;
  try {
    const response = await fetch(new URL(path, new URL(env.apiBaseUrl, window.location.origin)), {
      method,
      credentials: 'include',
      cache: 'no-store',
      headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal,
    });
    if (!response.ok) throw new DocumentViewError(codeForStatus(response.status), response.status, await serverErrorCode(response));
    return response;
  } catch (error) {
    if (timeout.signal.aborted && !options.signal?.aborted) throw new ApiError('서버 응답 시간이 초과되었습니다. 다시 시도해주세요.', 'TIMEOUT');
    throw normalizeApiError(error);
  } finally {
    window.clearTimeout(timer);
  }
}

async function callJson(method: 'GET' | 'POST', path: string, options: { body?: Record<string, unknown>; signal?: AbortSignal } = {}) {
  const response = await call(method, path, options);
  try {
    return (await response.json()) as unknown;
  } catch (error) {
    throw normalizeApiError(error);
  }
}

// 본문은 받는 동안에도 제한 시간이 걸리도록 call 안의 신호를 쓰지 않고 따로 잰다
async function callBinary(path: string, signal?: AbortSignal) {
  const timeout = new AbortController();
  const timer = window.setTimeout(() => timeout.abort(), ORIGINAL_TIMEOUT_MS);
  const both = signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal;
  try {
    const response = await call('GET', path, { signal: both, timeoutMs: ORIGINAL_TIMEOUT_MS });
    return { data: await response.arrayBuffer(), headers: response.headers };
  } catch (error) {
    if (timeout.signal.aborted && !signal?.aborted) throw new ApiError('서버 응답 시간이 초과되었습니다. 다시 시도해주세요.', 'TIMEOUT');
    throw normalizeApiError(error);
  } finally {
    window.clearTimeout(timer);
  }
}

/** 열람 오류를 화면 문구 종류로 나눈다(backend/README.md 5절 표) */
export type DocumentViewProblem =
  | 'unauthorized'
  | 'audit-required'
  | 'view-expired'
  | 'version-changed'
  | 'not-found'
  | 'too-large'
  | 'network'
  | 'other';

export function documentViewProblem(error: unknown): DocumentViewProblem {
  if (!(error instanceof ApiError)) return 'other';
  const serverCode = error instanceof DocumentViewError ? error.serverCode : undefined;
  if (error.status === 401) return 'unauthorized';
  if (serverCode === 'AUDIT_REQUIRED') return 'audit-required';
  if (serverCode === 'VIEW_FORBIDDEN') return 'view-expired';
  if (error.status === 409 || serverCode === 'DOCUMENT_VERSION_CHANGED') return 'version-changed';
  if (error.status === 404) return 'not-found';
  if (error.status === 413) return 'too-large';
  if (error.code === 'NETWORK' || error.code === 'TIMEOUT') return 'network';
  return 'other';
}

export const DOCUMENT_VIEW_PROBLEM_TEXT: Readonly<Record<DocumentViewProblem, string>> = {
  unauthorized: '로그인이 만료됨 · 다시 로그인하세요',
  'audit-required': '열람 기록을 남기지 못해 열 수 없음',
  'view-expired': '열람 시간이 끝남 · 다시 열기',
  'version-changed': '새 판이 등록됨 · 다시 열기',
  'not-found': '문서를 찾을 수 없음(삭제됐거나 본문 보기가 꺼져 있음)',
  'too-large': '원본이 20MB를 넘음 · 텍스트로 보기',
  network: '서버에 연결하지 못함',
  other: '본문을 불러오지 못함',
};

const documentPath = (documentId: string, kind: 'views' | 'original' | 'text') => `/api/documents/${encodeURIComponent(documentId)}/${kind}`;

export const documentViewService = {
  /** 열람 시작: 열 때마다 서버가 감사 기록 1건을 남기고 열람 번호를 준다(재시도·새로고침으로 다시 부르지 않게 부르는 쪽이 조절) */
  async startView(documentId: string, mode: DocumentViewMode, signal?: AbortSignal): Promise<DocumentView> {
    return parseApiResponse(documentViewSchema, await callJson('POST', documentPath(documentId, 'views'), { body: { mode }, signal }));
  },
  async getOriginal(documentId: string, viewId: string, signal?: AbortSignal): Promise<DocumentOriginal> {
    const response = await callBinary(`${documentPath(documentId, 'original')}?view=${encodeURIComponent(viewId)}`, signal);
    return { data: response.data, version: response.headers.get('X-Document-Version') };
  },
  async getTextPage(documentId: string, viewId: string, offset: number, signal?: AbortSignal): Promise<DocumentTextPage> {
    return parseApiResponse(documentTextSchema, await callJson('GET', `${documentPath(documentId, 'text')}?view=${encodeURIComponent(viewId)}&offset=${Math.max(0, Math.floor(offset))}`, { signal }));
  },
};
