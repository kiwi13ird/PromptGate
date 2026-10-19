// 확장 프로그램(1.4.3) '내 요청 기록' 번들을 만들어 확장 프로그램 myrequests/ 폴더에 바로 넣는다.
//   npm run build:extension
// 1) 출력 폴더(기본 ../llm-security-gateway-extension-handoff-v1.4.0/extension/myrequests, MYREQ_EXT_OUT_DIR로 변경)를 비운다
// 2) vite.extension.config.ts로 빌드한다(상대 경로, 인라인 스크립트 없음, 글꼴 제외가 기본)
// 3) 결과 폴더를 MV3 CSP 규칙(scripts/check-extension-csp.mjs)으로 다시 점검한다
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readBundleFiles, scanExtensionFiles } from './check-extension-csp.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.resolve(process.env.MYREQ_EXT_OUT_DIR || path.resolve(root, '../llm-security-gateway-extension-handoff-v1.4.0/extension/myrequests'));
const keepFont = process.env.MYREQ_EXT_KEEP_FONT === '1';

function fail(message) {
  console.error(`build:extension 실패: ${message}`);
  process.exit(1);
}

// 지우기 전에 확인: 폴더 이름이 myrequests이고, 바로 위가 MV3 확장 프로그램 폴더(manifest.json)여야 한다
if (path.basename(target) !== 'myrequests') fail(`출력 폴더 이름은 myrequests여야 합니다: ${target}`);
const manifestPath = path.join(path.dirname(target), 'manifest.json');
let manifest;
try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch { fail(`확장 프로그램 manifest.json을 읽을 수 없습니다: ${manifestPath}`); }
if (manifest?.manifest_version !== 3) fail(`MV3 확장 프로그램 폴더가 아닙니다: ${manifestPath}`);

fs.rmSync(target, { recursive: true, force: true });
const vite = path.join(root, 'node_modules', 'vite', 'bin', 'vite.js');
const built = spawnSync(process.execPath, [vite, 'build', '--config', 'vite.extension.config.ts', '--configLoader', 'native'], {
  cwd: root,
  stdio: 'inherit',
  env: { ...process.env, MYREQ_EXT_OUT_DIR: target },
});
if (built.status !== 0) fail(`vite build 종료 코드 ${built.status ?? built.signal}`);

const files = readBundleFiles(target);
const problems = scanExtensionFiles(files);
const html = files.find(file => file.path === 'myrequests.html');
if (!html) problems.push('myrequests.html이 없음');
else {
  const scripts = [...(html.text ?? '').matchAll(/<script\b[^>]*\ssrc="([^"]+)"/g)].map(match => match[1]);
  if (scripts.length !== 1 || !/^\.\/assets\/[A-Za-z0-9_.-]+\.js$/.test(scripts[0])) problems.push(`진입 스크립트가 ./assets/*.js 하나여야 함: ${scripts.join(', ')}`);
  for (const reference of [...(html.text ?? '').matchAll(/\s(?:src|href)="(\.\/[^"]+)"/g)].map(match => match[1]))
    if (!files.some(file => `./${file.path}` === reference)) problems.push(`HTML이 가리키는 파일이 없음: ${reference}`);
  if (!/http-equiv="Content-Security-Policy"[^>]*connect-src http:\/\/llm-gateway\.local[;"]/.test(html.text ?? '')) problems.push('페이지 CSP(connect-src http://llm-gateway.local)가 없음');
}
if (!keepFont && files.some(file => /\.(woff2?|ttf|otf)$/i.test(file.path))) problems.push('글꼴 파일이 포함됨(MYREQ_EXT_KEEP_FONT=1이 아님)');

const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0);
console.log(JSON.stringify({
  extensionBundle: problems.length ? 'FAIL' : 'PASS',
  outDir: target,
  font: keepFont ? 'included' : 'system fonts',
  files: files.map(({ path: file, bytes }) => ({ file, bytes })),
  totalBytes,
  problems,
}, null, 2));
if (problems.length) process.exit(1);
