export type ApiMode = 'mock' | 'real';

const rawMode = import.meta.env.VITE_API_MODE;

if (rawMode !== 'mock' && rawMode !== 'real')
  throw new Error(
    'VITE_API_MODE must be explicitly configured as mock or real.',
  );
if (rawMode === 'real' && !import.meta.env.VITE_API_BASE_URL)
  throw new Error('VITE_API_BASE_URL is required in real mode.');

export const env = {
  apiMode: rawMode as ApiMode,
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL ?? '',
  httpTimeoutMs: Number(import.meta.env.VITE_HTTP_TIMEOUT_MS || 10_000),
  // 보호 문서 등록(최대 20 MiB)만: 1.5 Mbps 업로드로 112초 → 기본 120초
  uploadTimeoutMs: Number(import.meta.env.VITE_UPLOAD_TIMEOUT_MS || 120_000),
  debugToolsEnabled:
    import.meta.env.DEV || import.meta.env.VITE_ENABLE_DEBUG_TOOLS === 'true',
};
