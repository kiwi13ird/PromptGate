import { env } from '@/src/config/env';
import { ApiError, normalizeApiError } from '@/src/api/errors';
import { parseApiResponse } from '@/src/api/schemas';
import { ownEvidenceSchema, ownRequestListSchema, type ViewerKeyResult } from '../services/myRequestsService';
import { PROTECTION_REQUIRED_MESSAGE, readViewerGate, setBlockedStatus } from './extensionGate';

// 확장 프로그램 번들 전용 대체 모듈(vite.extension.config.ts·vitest.extension.config.ts의 alias로
// '@/src/services/myRequestsService'를 바꿔 끼운다). 원본 서비스 파일은 고치지 않는다.
// 스키마·타입은 원본을 그대로 다시 내보내고, 열람 키 획득과 요청 경로만 바꾼다.
// 요청은 확장 프로그램 PAC가 Gateway로 보내는 llm-gateway.local로만 간다 - 관리자 대시보드 서버에 직접 붙지 않는다.
export * from '../services/myRequestsService';

// Gateway가 /__llmsgw/my/* 만 대시보드 /api/my/* 로 중계한다. 주소는 고정이다(보호 상태 확인이 이 호스트의 PAC 경로를 보장한다)
export const GATEWAY_MY_BASE = 'http://llm-gateway.local/__llmsgw/my/';
// Gateway 중계의 응답 상한(16 MiB)과 같다
export const MAX_RESPONSE_CHARS = 16 * 1024 * 1024;
// 기록 번호: Gateway 중계의 정규식(gateway_my_requests_relay._EVIDENCE_ROUTE)과 같다.
// '.'으로 시작할 수 없어 '.'·'..' 경로 조각이 생기지 않는다('..'이면 주소가 중계 밖 /__llmsgw/my/evidence로 바뀐다)
export const EVENT_ID_PATTERN = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const GATEWAY_MY_REQUESTS = `${GATEWAY_MY_BASE}requests`;
const GATEWAY_MY_EVIDENCE = /^http:\/\/llm-gateway\.local\/__llmsgw\/my\/requests\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\/evidence$/;

// 실제로 부르는 주소는 중계가 받는 두 가지(목록·근거)뿐이다. 그 밖의 llm-gateway.local 경로로는 열람 키를 보내지 않는다
export function isGatewayRelayUrl(href: string): boolean {
  return href === GATEWAY_MY_REQUESTS || GATEWAY_MY_EVIDENCE.test(href);
}

// 페이지가 처음 열릴 때: 보호 상태가 확인돼야 키를 넘긴다. 확인 실패는 안내 화면으로 바뀐다(extensionGate의 상태)
export async function askViewerKey(): Promise<ViewerKeyResult> {
  const gate = await readViewerGate();
  if (gate.status === 'READY') return { status: 'READY', viewerKey: gate.viewerKey, identityEnabled: gate.identityEnabled };
  if (gate.status !== 'NOT_READY') setBlockedStatus(gate.status);
  return { status: 'NOT_READY' };
}

// 요청 직전마다 다시 확인한다: 열려 있는 동안 보호를 끄거나 다른 프록시로 바뀌면 키를 보내지 않는다
async function keyForRequest(viewerKey: string): Promise<string> {
  const gate = await readViewerGate();
  if (gate.status === 'READY') {
    if (gate.viewerKey !== viewerKey) throw new ApiError('열람 키가 바뀌었습니다. 페이지를 새로 고친 후 다시 시도하십시오.', 'UNAUTHORIZED');
    return gate.viewerKey;
  }
  if (gate.status === 'NOT_READY') throw new ApiError('확장 프로그램 준비 중입니다.', 'UNAUTHORIZED');
  setBlockedStatus(gate.status);
  throw new ApiError(PROTECTION_REQUIRED_MESSAGE, 'FORBIDDEN');
}

async function readJson(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_CHARS) throw new ApiError('응답이 너무 커서 표시할 수 없습니다.', 'INVALID_RESPONSE');
  const text = await response.text();
  if (text.length > MAX_RESPONSE_CHARS) throw new ApiError('응답이 너무 커서 표시할 수 없습니다.', 'INVALID_RESPONSE');
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError('응답 형식이 올바르지 않습니다.', 'INVALID_RESPONSE');
  }
}

async function viewerGet(relativePath: string, viewerKey: string, signal?: AbortSignal): Promise<unknown> {
  const url = new URL(relativePath, GATEWAY_MY_BASE);
  if (!isGatewayRelayUrl(url.href)) throw new ApiError('요청 주소가 올바르지 않습니다.', 'VALIDATION');
  const key = await keyForRequest(viewerKey);
  if (signal?.aborted) throw new ApiError('요청이 취소되었습니다.', 'UNKNOWN');
  const timeout = new AbortController();
  const timer = window.setTimeout(() => timeout.abort(), env.httpTimeoutMs);
  try {
    const response = await fetch(url, {
      method: 'GET',
      credentials: 'omit',          // 쿠키·인증 정보를 쓰지 않는다
      cache: 'no-store',
      redirect: 'error',            // 다른 곳으로 넘겨 키 머리가 따라가지 않게 한다(중계는 넘기지 않는다)
      referrerPolicy: 'no-referrer',
      headers: { 'X-Viewer-Key': key },   // 키는 주소가 아니라 머리로만
      signal: signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal,
    });
    if (!response.ok)
      throw new ApiError('요청을 처리하지 못했습니다.', response.status === 401 ? 'UNAUTHORIZED' : response.status === 404 ? 'NOT_FOUND'
        : response.status >= 500 ? 'SERVER' : 'UNKNOWN', response.status);
    return await readJson(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (timeout.signal.aborted && !signal?.aborted) throw new ApiError('서버 응답 시간이 초과되었습니다.', 'TIMEOUT');
    throw normalizeApiError(error);   // 보호 꺼짐·Gateway 연결 실패는 fetch TypeError(NETWORK)로만 보인다
  } finally {
    window.clearTimeout(timer);
  }
}

export const myRequestsService = {
  async list(viewerKey: string, signal?: AbortSignal) {
    return parseApiResponse(ownRequestListSchema, await viewerGet('requests', viewerKey, signal));
  },
  async evidence(viewerKey: string, eventId: string, signal?: AbortSignal) {
    // 보호 상태 확인·요청 전에 거른다(대시보드·Gateway가 잘못된 번호를 줘도 중계 밖 경로로 키가 가지 않게)
    if (!EVENT_ID_PATTERN.test(eventId)) throw new ApiError('기록 번호가 올바르지 않습니다.', 'VALIDATION');
    const evidence = parseApiResponse(ownEvidenceSchema,
      await viewerGet(`requests/${encodeURIComponent(eventId)}/evidence`, viewerKey, signal));
    if (evidence.event_id !== eventId) throw new ApiError('요청한 기록과 응답이 일치하지 않습니다.', 'INVALID_RESPONSE');
    return evidence;
  },
};
