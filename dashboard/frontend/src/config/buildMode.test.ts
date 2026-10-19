import { describe, expect, it } from 'vitest';
import { resolveBuildMode } from './buildMode';

describe('explicit build mode selection', () => {
  it('selects only mock adapters for demo mode', () => {
    expect(resolveBuildMode('demo', { VITE_API_MODE: 'mock' })).toMatchObject({
      gatewayAdapter: 'src/api/mockAdapter.ts',
      authAdapter: 'src/auth/mockAuthAdapter.ts',
    });
  });

  it('selects only HTTP adapters for configured real mode', () => {
    expect(
      resolveBuildMode('production', {
        VITE_API_MODE: 'real',
        VITE_API_BASE_URL: 'https://api.example.invalid',
      }),
    ).toMatchObject({
      gatewayAdapter: 'src/api/httpAdapter.ts',
      authAdapter: 'src/auth/realAuthAdapter.ts',
    });
  });

  it('fails safely when mode or real API URL is missing', () => {
    expect(() => resolveBuildMode('production', {})).toThrow(/VITE_API_MODE/);
    expect(() =>
      resolveBuildMode('production', { VITE_API_MODE: 'real' }),
    ).toThrow(/VITE_API_BASE_URL/);
  });
});
