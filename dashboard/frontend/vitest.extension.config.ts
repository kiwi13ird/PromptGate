import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, mergeConfig } from 'vitest/config';
import base from './vitest.config.ts';

// 확장 프로그램 '내 요청 기록' 번들과 같은 바꿔 끼우기(alias)로 MyRequestsPage·보호 상태 확인을 시험한다.
//   npm run test:extension
const root = path.dirname(fileURLToPath(import.meta.url));
export default mergeConfig(base, defineConfig({
  cacheDir: process.env.MYREQ_EXT_CACHE_DIR || path.resolve(root, 'node_modules/.vite-extension'),
  resolve: {
    alias: [{ find: /^@\/src\/services\/myRequestsService$/, replacement: path.resolve(root, 'src/standalone/myRequestsService.extension.ts') }],
  },
  test: {
    // 이름을 .ext-test로: 기본 npm test(vitest.config.ts, alias 없음)에는 잡히지 않게
    include: ['src/standalone/**/*.ext-test.{ts,tsx}'],
  },
}));
