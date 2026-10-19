import { describe, expect, it } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { canRetainQueryData } from './queryPresentation';

describe('cached data after request errors', () => {
  it('permits a labeled last successful result on temporary network failures', () => {
    expect(canRetainQueryData(new ApiError('offline', 'NETWORK'))).toBe(true);
    expect(canRetainQueryData(new ApiError('slow', 'TIMEOUT'))).toBe(true);
    expect(canRetainQueryData(undefined)).toBe(true);
  });
  it('does not display protected cached records after an authorization failure', () => {
    expect(canRetainQueryData(new ApiError('expired', 'UNAUTHORIZED', 401))).toBe(false);
    expect(canRetainQueryData(new ApiError('denied', 'FORBIDDEN', 403))).toBe(false);
  });
});
