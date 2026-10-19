export type ApiErrorCode =
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'VALIDATION'
  | 'RATE_LIMITED'
  | 'TIMEOUT'
  | 'NETWORK'
  | 'INVALID_RESPONSE'
  | 'SERVER'
  | 'UNKNOWN';

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status?: number;
  /** 서버 오류 본문의 코드(`{"error":{"code":…}}`). 없으면 undefined — 기존 화면은 code·status만 본다(2026-10-15 정책 화면) */
  declare readonly serverCode?: string;   // declare: 값이 없을 때 칸 자체를 만들지 않는다(기존 오류 객체 모양 그대로)

  constructor(
    message: string,
    code: ApiErrorCode = 'UNKNOWN',
    status?: number,
    serverCode?: string,
  ) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    if (serverCode !== undefined) this.serverCode = serverCode;
  }
}

export function normalizeApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  if (error instanceof TypeError)
    return new ApiError('네트워크 연결을 확인해주세요.', 'NETWORK');
  if (error instanceof DOMException && error.name === 'AbortError')
    return new ApiError('요청이 취소되었습니다.', 'UNKNOWN');
  return new ApiError('작업을 완료하지 못했습니다. 다시 시도해주세요.');
}
