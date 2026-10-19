import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@runtime/gateway-api': path.resolve(root, 'src/api/mockAdapter.ts'),
      '@runtime/auth-adapter': path.resolve(
        root,
        'src/auth/mockAuthAdapter.ts',
      ),
      '@runtime/ui-mode': path.resolve(root, 'src/config/uiMode.mock.ts'),
      '@': root,
    },
  },
  test: {
    // Synthetic fixtures are available only to isolated unit tests, not runtime builds.
    env: {
      VITE_API_MODE: 'mock',
      VITE_API_BASE_URL: '/',
      VITE_HTTP_TIMEOUT_MS: '10000',
      VITE_ENABLE_DEBUG_TOOLS: 'false',
    },
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    restoreMocks: true,
    exclude: [
      'e2e/**',
      'e2e-real/**',
      'server/test/**',
      'node_modules/**',
      'dist*/**',
    ],
  },
});
