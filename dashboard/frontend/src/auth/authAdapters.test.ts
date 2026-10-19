import { afterEach, describe, expect, it, vi } from 'vitest';
import { authAdapter as mockAuth } from './mockAuthAdapter';
import { authAdapter as realAuth } from './realAuthAdapter';

afterEach(() => vi.unstubAllGlobals());

describe('auth adapter separation', () => {
  it('keeps demo credentials in the mock adapter only', () => {
    expect(mockAuth.demoCredentials).not.toBeNull();
    expect(realAuth.demoCredentials).toBeNull();
  });
  it('bootstraps a real cookie session from the backend', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            id: 'admin-007',
            email: 'admin@example.invalid',
            display_name: 'Admin',
            role: 'ADMIN',
          }),
          { status: 200 },
        ),
      ),
    );
    await expect(realAuth.getSession()).resolves.toMatchObject({
      id: 'admin-007',
      displayName: 'Admin',
    });
  });
  it('rejects a missing real session on 401', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(null, { status: 401 })),
    );
    await expect(realAuth.getSession()).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
    });
  });
});
