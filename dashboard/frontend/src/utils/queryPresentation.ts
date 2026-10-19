import { ApiError } from '@/src/api/errors';

// Do not keep showing protected records after authentication or authorization fails.
export function canRetainQueryData(error: unknown) {
  return !(error instanceof ApiError && ['UNAUTHORIZED', 'FORBIDDEN'].includes(error.code));
}
