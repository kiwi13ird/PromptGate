// 로컬 화면 확인 구성 한 번에 켜기 - kisia/project 폴더에서: node local-dashboard/start-all.mjs
// 가짜 Detection(18000) → 로컬 백엔드(9100) → 화면 개발 서버(5173). Ctrl+C 한 번이면 셋 다 꺼진다.
// 운영 서버·DB에 연결하지 않는다. 데이터는 메모리에만 있어 다시 켜면 처음 상태로 돌아간다.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.dirname(here);
const children = [];

function run(name, command, args, options = {}) {
  const child = spawn(command, args, { cwd: project, stdio: ['ignore', 'pipe', 'pipe'], ...options });
  const prefix = (chunk) => chunk.toString().split(/\r?\n/).filter(Boolean).map((line) => `[${name}] ${line}`).join('\n');
  child.stdout.on('data', (chunk) => console.log(prefix(chunk)));
  child.stderr.on('data', (chunk) => console.error(prefix(chunk)));
  child.on('exit', (code) => console.log(`[${name}] 종료 (code ${code})`));
  children.push(child);
}

run('detection', process.execPath, [path.join(here, 'fake-detection.mjs')]);
run('backend', process.execPath, [path.join(here, 'run-backend.mjs')]);
// npm은 Windows에서 셸을 거쳐야 실행된다 - 인자를 따로 넘기면 Node가 경고하므로 고정된 한 줄로 넘긴다
run('screen', 'npm --prefix dashboard-frontend-final run dev -- --host 127.0.0.1 --port 5173 --strictPort', [], { shell: true });

console.log('접속: http://localhost:5173  (아이디·비밀번호: local-dashboard/local-test-account.json)');
const stop = () => { for (const child of children) child.kill(); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
