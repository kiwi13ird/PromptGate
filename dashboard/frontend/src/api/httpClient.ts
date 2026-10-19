import { env } from '@/src/config/env';
import { ApiError, normalizeApiError } from './errors';

type UnauthorizedHandler = () => void;
let onUnauthorized: UnauthorizedHandler | undefined;

export function setUnauthorizedHandler(handler?: UnauthorizedHandler) {
  onUnauthorized = handler;
}

function codeForStatus(status: number) {
  if (status === 401) return 'UNAUTHORIZED' as const;
  if (status === 403) return 'FORBIDDEN' as const;
  if (status === 404) return 'NOT_FOUND' as const;
  if (status === 409) return 'CONFLICT' as const;
  if (status === 429) return 'RATE_LIMITED' as const;
  if (status === 400 || status === 413 || status === 415 || status === 422)
    return 'VALIDATION' as const;
  if (status >= 500) return 'SERVER' as const;
  return 'UNKNOWN' as const;
}

type RequestBody = Record<string, unknown> | FormData;

// 오류 응답 본문의 서버 코드만 읽는다(2026-10-15). JSON이 아니거나 비었거나 모양이 다르면 undefined → 기존 동작 그대로.
// 대시보드 서버는 {"error":{"code"}}, Detection을 그대로 넘긴 본문은 {"detail":{"code"}}일 수 있다. 메시지(영어)는 읽지 않는다
const SERVER_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
async function readServerCode(response: Response): Promise<string | undefined> {
  try {
    if (typeof response.text !== 'function') return undefined;
    const text = await response.text();
    if (!text) return undefined;
    const body = JSON.parse(text) as { error?: { code?: unknown }; detail?: { code?: unknown } } | null;
    const code = body?.error?.code ?? body?.detail?.code;
    return typeof code === 'string' && SERVER_CODE.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

async function request<T>(
  method: string,
  path: string,
  options: { body?: RequestBody; signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<T> {
  const timeout = new AbortController();
  const timer = window.setTimeout(() => timeout.abort(), options.timeoutMs ?? env.httpTimeoutMs);
  const signal = options.signal
    ? AbortSignal.any([options.signal, timeout.signal])
    : timeout.signal;
  try {
    const apiBaseUrl = new URL(env.apiBaseUrl, window.location.origin);
    const response = await fetch(new URL(path, apiBaseUrl), {
      method,
      credentials: 'include',
      headers:
        options.body === undefined || options.body instanceof FormData
          ? undefined
          : { 'Content-Type': 'application/json' },
      body:
        options.body === undefined
          ? undefined
          : options.body instanceof FormData
            ? options.body
            : JSON.stringify(options.body),
      signal,
    });
    if (!response.ok) {
      if (response.status === 401) onUnauthorized?.();
      throw new ApiError(
        '요청을 처리하지 못했습니다.',
        codeForStatus(response.status),
        response.status,
        await readServerCode(response),
      );
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  } catch (error) {
    if (timeout.signal.aborted && !options.signal?.aborted)
      throw new ApiError(
        '서버 응답 시간이 초과되었습니다. 다시 시도해주세요.',
        'TIMEOUT',
      );
    throw normalizeApiError(error);
  } finally {
    window.clearTimeout(timer);
  }
}

export const httpClient = {
  get: <T>(path: string, signal?: AbortSignal) =>
    request<T>('GET', path, { signal }),
  post: <T>(
    path: string,
    body?: Record<string, unknown>,
    signal?: AbortSignal,
  ) => request<T>('POST', path, { body, signal }),
  // 파일 업로드는 전송 시간이 길어 제한 시간을 따로 받는다(보호 문서 등록 = env.uploadTimeoutMs)
  postForm: <T>(
    path: string,
    body: FormData,
    signal?: AbortSignal,
    timeoutMs?: number,
  ) => request<T>('POST', path, { body, signal, timeoutMs }),
  patch: <T>(
    path: string,
    body?: Record<string, unknown>,
    signal?: AbortSignal,
  ) => request<T>('PATCH', path, { body, signal }),
  put: <T>(
    path: string,
    body?: Record<string, unknown>,
    signal?: AbortSignal,
  ) => request<T>('PUT', path, { body, signal }),
  delete: <T>(path: string, signal?: AbortSignal) =>
    request<T>('DELETE', path, { signal }),
};
