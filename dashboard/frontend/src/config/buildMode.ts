export interface BuildModeSettings {
  gatewayAdapter: 'src/api/mockAdapter.ts' | 'src/api/httpAdapter.ts';
  authAdapter: 'src/auth/mockAuthAdapter.ts' | 'src/auth/realAuthAdapter.ts';
  uiMode: 'src/config/uiMode.mock.ts' | 'src/config/uiMode.real.ts';
}

export function resolveBuildMode(
  mode: string,
  environment: Record<string, string>,
): BuildModeSettings {
  const apiMode = environment.VITE_API_MODE;
  if (apiMode !== 'mock' && apiMode !== 'real') {
    throw new Error(
      `VITE_API_MODE must be explicitly set to "mock" or "real" for mode "${mode}".`,
    );
  }
  if (apiMode === 'real' && !environment.VITE_API_BASE_URL) {
    throw new Error(
      'VITE_API_BASE_URL is required for a real production build.',
    );
  }
  return apiMode === 'real'
    ? {
        gatewayAdapter: 'src/api/httpAdapter.ts',
        authAdapter: 'src/auth/realAuthAdapter.ts',
        uiMode: 'src/config/uiMode.real.ts',
      }
    : {
        gatewayAdapter: 'src/api/mockAdapter.ts',
        authAdapter: 'src/auth/mockAuthAdapter.ts',
        uiMode: 'src/config/uiMode.mock.ts',
      };
}
