// 확장 프로그램 '내 요청 기록' 번들의 MV3 CSP 정적 점검(1.4.3).
// MV3 확장 페이지는 script-src 'self'(eval·new Function·인라인 스크립트 금지)라, 이를 깨는 산출물이면 실패시킨다.
//   node scripts/check-extension-csp.mjs <번들 폴더>
// vite.extension.config.ts의 빌드 점검과 scripts/build-extension.mjs의 빌드 후 점검이 같은 규칙(scanExtensionFiles)을 쓴다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TEXT_TYPES = new Set(['.html', '.js', '.css', '.svg', '.json']);
const ALLOWED_TYPES = new Set([...TEXT_TYPES, '.woff2', '.png']);
// 상대 경로가 아닌 참조: 스킴(http:, data:, blob:, javascript: 등)·루트 절대 경로·프로토콜 상대 경로
const NON_RELATIVE = /^\s*(?:[a-z][a-z0-9+.-]*:|\/)/i;

function attr(tag, name) {
  const match = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  return match ? (match[1] ?? match[2] ?? match[3] ?? '') : null;
}

function scanHtml(file, text, problems) {
  const scripts = [...text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  if (scripts.length !== (text.match(/<script\b/gi) ?? []).length) problems.push(`${file}: 닫히지 않은 script 태그`);
  for (const [tag, , body] of scripts) {
    const src = attr(tag.slice(0, tag.indexOf('>') + 1), 'src');
    if (src === null) problems.push(`${file}: 인라인 스크립트 ${tag.slice(0, 80)}`);
    else if (NON_RELATIVE.test(src)) problems.push(`${file}: 상대 경로가 아닌 스크립트 ${src}`);
    if (body.trim()) problems.push(`${file}: 스크립트 태그 안에 코드가 있음`);
  }
  for (const tag of text.match(/<link\b[^>]*>/gi) ?? []) {
    const href = attr(tag, 'href');
    if (href !== null && NON_RELATIVE.test(href)) problems.push(`${file}: 상대 경로가 아닌 링크 ${href}`);
  }
  if (/<[a-z][^>]*\son[a-z]+\s*=/i.test(text)) problems.push(`${file}: on* 인라인 이벤트 속성`);
  if (/javascript:/i.test(text)) problems.push(`${file}: javascript: 주소`);
  if (/<(?:base|iframe|object|embed|frame)\b/i.test(text)) problems.push(`${file}: base·iframe·object·embed 태그`);
  if (/\ssrcdoc\s*=/i.test(text)) problems.push(`${file}: srcdoc 속성`);
  if (/\s(?:src|href)\s*=\s*["']?\//i.test(text)) problems.push(`${file}: 루트 절대 경로 참조`);
  for (const tag of text.match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/http-equiv\s*=\s*["']?content-security-policy/i.test(tag)) continue;
    if (/unsafe-(?:inline|eval|hashes)/i.test(attr(tag, 'content') ?? '')) problems.push(`${file}: 페이지 CSP가 unsafe-* 를 허용함`);
  }
}

function scanJs(file, text, problems) {
  const rules = [
    [/(?<![\w$.])eval\s*\(/, 'eval( 호출'],
    [/(?<![\w$.])eval(?=\s*[,;)\]}]|\s*$)/m, 'eval 별칭(간접 eval)'],
    [/\bnew\s+Function\b/, 'new Function'],
    [/(?<![\w$.])Function\s*\(/, 'Function( 생성자 호출'],
    // Function 생성자를 다른 이름에 담는 경우(let e=Function; new e(...)). Function.prototype 등 속성 접근은 허용
    [/(?<![\w$.])Function(?=\s*[,;)\]}]|\s*$)/m, 'Function 생성자 별칭'],
    [/\b(?:setTimeout|setInterval)\s*\(\s*["'`]/, '문자열 setTimeout/setInterval'],
    [/data:(?:text|application)\/(?:x-)?(?:java|ecma)script/i, 'data: 스크립트'],
    [/\bimport\s*\(\s*["'`](?:data|blob|https?):/i, '외부·data:·blob: 동적 import'],
    [/\bimportScripts\s*\(/, 'importScripts'],
    [/https?:\/\/[^\s"'`]+\.m?js["'`]/i, '외부 스크립트 주소'],
    [/[#@]\s*sourceMappingURL=/, 'sourcemap 참조'],
  ];
  for (const [rule, label] of rules) if (rule.test(text)) problems.push(`${file}: ${label}`);
}

function scanCss(file, text, problems) {
  if (/@import\b/i.test(text)) problems.push(`${file}: @import`);
  for (const [, raw] of text.matchAll(/url\(\s*([^)]*)\)/gi)) {
    const value = raw.trim().replace(/^["']|["']$/g, '');
    if (/^(?:https?:|\/\/|\/)/i.test(value)) problems.push(`${file}: 외부·루트 절대 경로 url(${value.slice(0, 60)})`);
    if (/^javascript:/i.test(value)) problems.push(`${file}: javascript: url`);
  }
  if (/expression\s*\(/i.test(text)) problems.push(`${file}: CSS expression(`);
  if (/[#@]\s*sourceMappingURL=/.test(text)) problems.push(`${file}: sourcemap 참조`);
}

// files: [{ path: '상대 경로', text?: string }] (text는 TEXT_TYPES일 때만)
export function scanExtensionFiles(files) {
  const problems = [];
  if (!files.some(file => file.path.endsWith('.html'))) problems.push('HTML 파일이 없음');
  for (const file of files) {
    const extension = path.extname(file.path).toLowerCase();
    if (file.path.endsWith('.map')) { problems.push(`${file.path}: sourcemap 파일`); continue; }
    if (!ALLOWED_TYPES.has(extension)) { problems.push(`${file.path}: 허용하지 않는 파일 형식`); continue; }
    if (!TEXT_TYPES.has(extension)) continue;
    const text = file.text ?? '';
    if (extension === '.html') scanHtml(file.path, text, problems);
    if (extension === '.js') scanJs(file.path, text, problems);
    if (extension === '.css') scanCss(file.path, text, problems);
    if (extension === '.svg' && /<script\b|\son[a-z]+\s*=|javascript:/i.test(text)) problems.push(`${file.path}: SVG 안 스크립트`);
  }
  return problems;
}

export function readBundleFiles(directory) {
  const files = [];
  const walk = (folder) => {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
      const full = path.join(folder, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      const relative = path.relative(directory, full).split(path.sep).join('/');
      const extension = path.extname(entry.name).toLowerCase();
      files.push({ path: relative, bytes: fs.statSync(full).size, text: TEXT_TYPES.has(extension) ? fs.readFileSync(full, 'utf8') : undefined });
    }
  };
  walk(directory);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = process.argv[2];
  if (!directory || !fs.existsSync(directory)) { console.error('사용법: node scripts/check-extension-csp.mjs <번들 폴더>'); process.exit(2); }
  const files = readBundleFiles(path.resolve(directory));
  const problems = scanExtensionFiles(files);
  console.log(JSON.stringify({ extensionCsp: problems.length ? 'FAIL' : 'PASS', files: files.map(({ path: file, bytes }) => ({ file, bytes })), problems }, null, 2));
  process.exit(problems.length ? 1 : 0);
}
