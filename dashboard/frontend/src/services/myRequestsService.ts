import { z } from 'zod';
import { env } from '@/src/config/env';
import { ApiError, normalizeApiError } from '@/src/api/errors';
import { parseApiResponse } from '@/src/api/schemas';
import { fileComparisonSchema } from '@/src/services/evidenceService';

// 내 요청 기록 (2026-10-09). 관리자 로그인 없이, 확장 프로그램이 이 브라우저에만 가진 열람 키로 본인 요청만 연다.
// 키는 주소·저장소에 남기지 않고 요청 헤더로만 보낸다. 서버에는 키의 지문(SHA-256)만 있다.
export const EXTENSION_ID = 'mdeejegfkckeeolcgbkkblnccealmgan';
const VIEWER_KEY = /^[A-Za-z0-9_-]{43}$/;

export type ViewerKeyResult =
  | { status: 'READY'; viewerKey: string; identityEnabled: boolean }
  | { status: 'NO_EXTENSION' }
  | { status: 'NOT_READY' };

interface ChromeRuntimeLike {
  sendMessage?: (extensionId: string, message: unknown, callback: (response: unknown) => void) => void;
  lastError?: unknown;
}

// 확장 프로그램의 manifest(externally_connectable)에 이 대시보드 주소가 있을 때만 chrome.runtime이 페이지에 보인다
export function askViewerKey(timeoutMs = 3000): Promise<ViewerKeyResult> {
  const runtime = (globalThis as { chrome?: { runtime?: ChromeRuntimeLike } }).chrome?.runtime;
  const send = runtime?.sendMessage;
  if (!runtime || typeof send !== 'function') return Promise.resolve({ status: 'NO_EXTENSION' });
  return new Promise((resolve) => {
    let done = false;
    const finish = (result: ViewerKeyResult) => { if (!done) { done = true; window.clearTimeout(timer); resolve(result); } };
    const timer = window.setTimeout(() => finish({ status: 'NO_EXTENSION' }), timeoutMs);
    try {
      send.call(runtime, EXTENSION_ID, { type: 'GET_VIEWER_KEY' }, (response) => {
        const failed = runtime.lastError;
        const reply = response as { ok?: unknown; viewerKey?: unknown; identityEnabled?: unknown } | undefined;
        if (failed || !reply) return finish({ status: 'NO_EXTENSION' });
        if (reply.ok !== true || typeof reply.viewerKey !== 'string' || !VIEWER_KEY.test(reply.viewerKey)) return finish({ status: 'NOT_READY' });
        finish({ status: 'READY', viewerKey: reply.viewerKey, identityEnabled: reply.identityEnabled === true });
      });
    } catch {
      finish({ status: 'NO_EXTENSION' });
    }
  });
}

const action = z.enum(['ALLOW', 'MASK', 'BLOCK']);
const ownItemBase = z.object({
  event_id: z.string(),
  occurred_at: z.string(),
  target_llm: z.string().nullish(),
  content_type: z.string().nullish(),
  final_action: action,
  group_final_action: action.optional(),
  protected_document: z.boolean(),
  entity_counts: z.array(z.object({ entity_type: z.string(), count: z.number().int().nonnegative() })),
  // 차단·검사 불가 사유(2026-10-10): 검사 불가·상한 초과·응답 없음·마스킹 불가만. 개인정보·보호 문서는 칩으로 이미 보인다
  reason_code: z.string().optional(),
  // 접속 차단 안내(2026-10-12): reason_code가 client_blocked인 건에만. 규칙의 사유 코드(고정 6종)와, 관리자가 공개를 고른 경우의 메모(user_memo).
  // 둘 다 없으면(옛 서버 · 규칙에 사유 없음) 사유 줄 없이 기본 이름표만 보인다
  reasons: z.array(z.string().min(1).max(40)).max(20).optional(),
  block_reasons: z.array(z.string().min(1).max(40)).max(20).optional(),   // 서버 이름(10/12) - reasons와 같은 뜻
  user_memo: z.string().max(1000).nullish(),
  // 요청 ID(2026-10-12): 사용자가 관리자에게 문의할 때 알려 줄 번호. 옛 서버는 보내지 않는다(없으면 화면에서 줄을 숨긴다).
  // null이 와도 목록 전체가 깨지지 않게 nullish로 받는다
  request_id: z.string().nullish(),
});
export const ownRequestSchema = ownItemBase.extend({ attached_files: z.array(ownItemBase).optional() });
// limit·truncated(2026-10-16): 최근 100건 상한과 넘쳤는지. 옛 서버는 보내지 않는다
export const ownRequestListSchema = z.object({ items: z.array(ownRequestSchema), window_days: z.number().int().positive(),
  limit: z.number().int().positive().optional(), truncated: z.boolean().optional() });
export const OWN_REQUEST_LIMIT = 100;
export const ownEvidenceSchema = z.object({
  event_id: z.string(),
  status: z.enum(['AVAILABLE', 'NOT_RECORDED', 'TOO_LARGE']),
  redaction: z.enum(['APPLIED', 'OFF']),
  content_type: z.string().nullish(),
  final_action: action.nullish(),
  protected_document: z.boolean().optional(),
  filename: z.string().optional(),
  file_comparison: fileComparisonSchema.optional(),
  prompt_comparison: fileComparisonSchema.optional(),
  reason_code: z.string().optional(),
  reasons: z.array(z.string().min(1).max(40)).max(20).optional(),   // 접속 차단 안내(위 목록 항목과 같다)
  block_reasons: z.array(z.string().min(1).max(40)).max(20).optional(),
  user_memo: z.string().max(1000).nullish(),
  request_id: z.string().nullish(),   // 요청 ID(위 목록 항목과 같다)
});
export type OwnRequest = z.infer<typeof ownRequestSchema>;
export type OwnRequestFile = z.infer<typeof ownItemBase>;
export type OwnEvidence = z.infer<typeof ownEvidenceSchema>;

async function viewerGet(path: string, viewerKey: string, signal?: AbortSignal): Promise<unknown> {
  const timeout = new AbortController();
  const timer = window.setTimeout(() => timeout.abort(), env.httpTimeoutMs);
  try {
    const base = new URL(env.apiBaseUrl, window.location.origin);
    const response = await fetch(new URL(path, base), {
      method: 'GET',
      credentials: 'omit',   // 관리자 세션 쿠키는 쓰지 않는다
      cache: 'no-store',
      headers: { 'X-Viewer-Key': viewerKey },
      signal: signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal,
    });
    if (!response.ok)
      throw new ApiError('요청을 처리하지 못했습니다.', response.status === 401 ? 'UNAUTHORIZED' : response.status === 404 ? 'NOT_FOUND'
        : response.status >= 500 ? 'SERVER' : 'UNKNOWN', response.status);
    return await response.json();
  } catch (error) {
    if (timeout.signal.aborted && !signal?.aborted) throw new ApiError('서버 응답 시간이 초과되었습니다.', 'TIMEOUT');
    throw normalizeApiError(error);
  } finally {
    window.clearTimeout(timer);
  }
}

export const myRequestsService = {
  async list(viewerKey: string, signal?: AbortSignal) {
    return parseApiResponse(ownRequestListSchema, await viewerGet('/api/my/requests', viewerKey, signal));
  },
  async evidence(viewerKey: string, eventId: string, signal?: AbortSignal) {
    const evidence = parseApiResponse(ownEvidenceSchema,
      await viewerGet(`/api/my/requests/${encodeURIComponent(eventId)}/evidence`, viewerKey, signal));
    if (evidence.event_id !== eventId) throw new ApiError('요청한 기록과 응답이 일치하지 않습니다.', 'INVALID_RESPONSE');
    return evidence;
  },
};
