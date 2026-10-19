import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanExtensionFiles } from './scripts/check-extension-csp.mjs';

// 확장 프로그램(1.4.3) 안에 넣는 '내 요청 기록' 정적 번들. 보통은 npm run build:extension(scripts/build-extension.mjs)으로 만든다.
// 결과: <outDir>/myrequests.html + assets/* (상대 경로, 인라인 스크립트 없음)
//   → 확장 프로그램 myrequests/ 폴더(팝업 '로그 확인'이 chrome.runtime.getURL('myrequests/myrequests.html')로 연다)
// 원본 대시보드 소스는 고치지 않는다: 서비스 모듈만 alias로 바꿔 끼운다(src/standalone/myRequestsService.extension.ts).
const configDirectory = path.dirname(fileURLToPath(import.meta.url));
const standaloneRoot = path.resolve(configDirectory, 'src/standalone');
export const DEFAULT_EXTENSION_OUT_DIR = path.resolve(configDirectory, '../llm-security-gateway-extension-handoff-v1.4.0/extension/myrequests');
const outDir = path.resolve(process.env.MYREQ_EXT_OUT_DIR || DEFAULT_EXTENSION_OUT_DIR);
// 확장 프로그램 PAC가 이 호스트를 Gateway로 보낸다(manifest host_permissions에 이미 있음). Gateway가 /__llmsgw/my/*만 대시보드로 중계
const GATEWAY_MY_BASE = 'http://llm-gateway.local/__llmsgw/my/';
// Pretendard 글꼴(2 MB, 번들의 80%)은 기본으로 빼고 시스템 글꼴(맑은 고딕 등)을 쓴다. MYREQ_EXT_KEEP_FONT=1이면 넣는다
const keepFont = process.env.MYREQ_EXT_KEEP_FONT === '1';

// emptyOutDir가 폴더를 비우므로, 확장 프로그램의 myrequests 폴더 이외의 곳을 지우지 않게 막는다
if (path.basename(outDir) !== 'myrequests') throw new Error(`내 요청 기록 번들 출력 폴더 이름은 myrequests여야 합니다: ${outDir}`);

function dropPretendardFace(): Plugin {
  let dropped = false;
  return {
    name: 'drop-pretendard-face',
    enforce: 'pre',
    transform(code, id) {
      if (keepFont || !id.split('?')[0].endsWith('product-polish.css')) return null;
      const next = code.replace(/@font-face\s*\{[^}]*PretendardVariable\.woff2[^}]*\}/, '');
      dropped ||= next !== code;
      return { code: next, map: null };
    },
    generateBundle: {
      order: 'post',
      handler(_options, bundle) {
        if (keepFont) return;
        const fonts = Object.keys(bundle).filter(file => /\.(woff2?|ttf|otf)$/i.test(file));
        if (fonts.length) this.error(`글꼴을 빼도록 설정했지만 번들에 글꼴이 있습니다: ${fonts.join(', ')}`);
        if (!dropped) this.warn('product-polish.css에서 Pretendard @font-face를 찾지 못했습니다(글꼴 미포함은 확인됨).');
      },
    },
  };
}

// zod 4는 스키마를 만들 때 eval 가능 여부를 new Function("")으로 떠 보고(allowsEval), 빠른 경로를 Function 생성자로 만든다(Doc.compile).
// 진입점 첫 import의 z.config({ jitless: true })로 둘 다 실행되지 않지만, 번들에 Function 생성자 자체가 남지 않도록 빌드 때 지운다.
// zod가 바뀌어 대상 코드를 못 찾으면 빌드를 멈춘다(조용히 넘어가지 않게).
function zodWithoutFunctionConstructor(): Plugin {
  const patches = [
    {
      file: /[\\/]zod[\\/]v4[\\/]core[\\/]util\.js$/,
      find: /try\s*\{\s*const F = Function;\s*new F\(""\);\s*return true;\s*\}\s*catch\s*\(_\)\s*\{\s*return false;\s*\}/,
      replace: 'return false;',
    },
    {
      file: /[\\/]zod[\\/]v4[\\/]core[\\/]doc\.js$/,
      find: /compile\(\)\s*\{\s*const F = Function;[\s\S]*?return factory\(\.\.\.Object\.values\(this\.closed\)\);\s*\}/,
      replace: 'compile() { throw new Error("zod JIT is disabled in the extension bundle (MV3 CSP)"); }',
    },
  ];
  const seen = new Set<number>();
  return {
    name: 'zod-without-function-constructor',
    enforce: 'pre',
    transform(code, id) {
      const index = patches.findIndex(patch => patch.file.test(id.split('?')[0]));
      if (index < 0) return null;
      const { find, replace } = patches[index];
      if (!find.test(code)) this.error(`zod 패치 대상 코드를 찾지 못했습니다: ${id}`);
      seen.add(index);
      return { code: code.replace(find, replace), map: null };
    },
    buildEnd(error) {
      if (!error && !seen.has(0)) this.error('zod v4 core/util.js(allowsEval)를 번들에서 찾지 못했습니다.');
    },
  };
}

// MV3 확장 페이지 CSP(script-src 'self')를 깨는 산출물이면 빌드를 실패시킨다(규칙: scripts/check-extension-csp.mjs)
function mv3CspGuard(): Plugin {
  return {
    name: 'mv3-csp-guard',
    enforce: 'post',
    transformIndexHtml(html) {
      return html.replaceAll(' crossorigin', '');   // 같은 출처(chrome-extension://) 파일이라 필요 없다
    },
    generateBundle(_options, bundle) {
      const problems: string[] = [];
      const files: { path: string; text?: string }[] = [];
      for (const item of Object.values(bundle)) {
        if (item.type === 'chunk') {
          files.push({ path: item.fileName, text: item.code });
          const modules = Object.keys(item.modules).map(id => path.relative(configDirectory, id).split(path.sep).join('/'));
          const mocks = modules.filter(id => /(^|\/)(mocks|__mocks__|fixtures|__fixtures__|samples)(\/|$)|\.(test|spec|ext-test)\.|(^|\/)(mockAdapter|mockClient|mockAuthAdapter)\.|uiMode\.mock/.test(id));
          if (mocks.length) problems.push(`${item.fileName}: 목·시험 모듈 포함 ${mocks.join(', ')}`);
        } else {
          files.push({ path: item.fileName, text: typeof item.source === 'string' ? item.source : /\.(html|js|css|svg|json)$/i.test(item.fileName) ? new TextDecoder().decode(item.source) : undefined });
        }
      }
      problems.push(...scanExtensionFiles(files));
      if (problems.length) this.error(`MV3 CSP 점검 실패\n${problems.join('\n')}`);
    },
  };
}

export default defineConfig({
  root: standaloneRoot,
  base: './',
  publicDir: false,
  envDir: standaloneRoot,   // .env* 없음 → 대시보드용 .env.production.local(VITE_API_BASE_URL=/)을 읽지 않는다
  cacheDir: process.env.MYREQ_EXT_CACHE_DIR || path.resolve(configDirectory, 'node_modules/.vite-extension'),
  define: {
    'import.meta.env.VITE_API_MODE': JSON.stringify('real'),
    'import.meta.env.VITE_API_BASE_URL': JSON.stringify(GATEWAY_MY_BASE),
    'import.meta.env.VITE_HTTP_TIMEOUT_MS': JSON.stringify('10000'),
    'import.meta.env.VITE_ENABLE_DEBUG_TOOLS': JSON.stringify('false'),
  },
  plugins: [dropPretendardFace(), zodWithoutFunctionConstructor(), react(), mv3CspGuard()],
  resolve: {
    alias: [
      // 열람 키는 보호 상태 확인(GET_MODEL) 뒤에만, 요청은 Gateway(llm-gateway.local)로 - 원본 서비스 파일은 고치지 않는다
      { find: /^@\/src\/services\/myRequestsService$/, replacement: path.resolve(standaloneRoot, 'myRequestsService.extension.ts') },
      { find: '@runtime/gateway-api', replacement: path.resolve(configDirectory, 'src/api/httpAdapter.ts') },
      { find: '@runtime/auth-adapter', replacement: path.resolve(configDirectory, 'src/auth/realAuthAdapter.ts') },
      { find: '@runtime/ui-mode', replacement: path.resolve(configDirectory, 'src/config/uiMode.real.ts') },
      { find: '@', replacement: configDirectory },
    ],
  },
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: false,
    target: 'chrome116',            // manifest minimum_chrome_version
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,           // data: URI 없이 파일로
    rollupOptions: { input: { myrequests: path.resolve(standaloneRoot, 'myrequests.html') } },
  },
});
