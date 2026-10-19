// 대시보드 서버용 같은 글자 비율 모듈 만들기(2026-10-16 '일치 비율' 통일): 화면 원본 src/utils/matchRatio.ts를 그대로 묶어
// 서버 match-ratio.mjs로 낸다(화면 대조와 서버 목록 값이 같은 코드). node scripts/build-match-ratio.mjs <출력 파일>
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { build } from 'esbuild';

const out = process.argv[2];
if (!out) { console.error('사용법: node scripts/build-match-ratio.mjs <출력 파일>'); process.exit(2); }
const sources = ['src/utils/matchRatio.ts', 'src/utils/textDiff.ts', 'src/utils/redactedText.ts'];
const stamp = sources.map((file) => `${file} md5 ${createHash('md5').update(readFileSync(file)).digest('hex').slice(0, 8)}`).join(' · ');
await build({
  entryPoints: ['src/utils/matchRatio.ts'], bundle: true, format: 'esm', platform: 'node', target: 'node22', outfile: out, logLevel: 'warning',
  banner: { js: `// 자동 생성 — 손으로 고치지 말 것. 화면(dashboard-frontend-final)의 같은 글자 비율 원본을 그대로 묶음: ${stamp}` },
});
console.log(`${out} ← ${stamp}`);
