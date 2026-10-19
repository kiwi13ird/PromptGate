// 화면 확인용 가짜 Detection 관리 API (127.0.0.1:18000). 상태는 메모리에만 - 실제 서버에 닿지 않는다.
// 응답 모양은 운영 Detection에서 읽기 전용으로 받아 본 것과 같다(dash1006/live/*.json).
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const live = (name) => JSON.parse(readFileSync(path.join(here, 'live', `${name}.json`), 'utf8'));
const now = () => new Date().toISOString();
let gpuConnected = process.env.FAKE_GPU !== 'down';
let reloadFails = process.env.FAKE_RELOAD_FAIL === '1';
// GPU 인스턴스 흉내(10/7): 켜기 → pending 4초 → running(모델 준비 6초) → 연결. 끄기 → stopping 5초 → stopped
const GPU_ID = 'i-094b015caf120ab1e';
let gpuInstance = { state: gpuConnected ? 'running' : 'stopped', at: 0 };
function advanceGpu() {
  const t = Date.now();
  if (gpuInstance.state === 'pending' && t - gpuInstance.at > 4000) gpuInstance = { state: 'running', at: t };
  if (gpuInstance.state === 'stopping' && t - gpuInstance.at > 5000) gpuInstance = { state: 'stopped', at: t };
  gpuConnected = gpuInstance.state === 'running' && t - gpuInstance.at > 6000;
}

let nextKeyword = 100;
const kw = (keyword, doc_id, status, reason, doc_hits, neg_hits) => ({
  id: nextKeyword++, keyword, doc_id, status, source: 'llm', reason, doc_hits, neg_hits,
  created_at: '2026-10-04T05:26:32Z', created_by: null,
  decided_at: status === 'approved' ? '2026-10-04T07:10:00Z' : null, decided_by: status === 'approved' ? 'local-admin' : null,
});
const keywords = [
  kw('PRJ-2026-07', '13_파트너사협상자료', 'pending', '일본 진출 프로젝트 코드', 1, 0),
  kw('Tokyo Bridge Solutions', '13_파트너사협상자료', 'pending', '협상 상대(1순위)', 1, 0),
  kw('SPK', '13_파트너사협상자료', 'pending', '협상 상대 약칭', 1, 14),
  kw('PRJ-2026-03', '01_사업전략_방향_보고서', 'approved', '리뉴얼 프로젝트 코드', 3, 0),
  kw('네오보드 3.0', '01_사업전략_방향_보고서', 'approved', '미출시 차기 버전', 4, 0),
  kw('Series B 텀시트', '05_투자유치_자료', 'pending', '투자 협의 문서명', 1, 2),
];
let nextJob = 10;
const jobs = [
  { id: 1, doc_id: '13_파트너사협상자료', doc_version: 0, status: 'done', attempts: 0, error: null, created_at: '2026-10-04T05:25:28Z', finished_at: '2026-10-04T05:26:32Z' },
  { id: 2, doc_id: '05_투자유치_자료', doc_version: 0, status: 'failed', attempts: 3, error: 'LLM response is not JSON', created_at: '2026-10-05T01:00:00Z', finished_at: '2026-10-05T01:03:00Z' },
  { id: 3, doc_id: '09_아키텍처_설계서', doc_version: 0, status: 'queued', attempts: 0, error: null, created_at: '2026-10-06T10:00:00Z', finished_at: null },
];
// 추출 흉내: GPU가 연결돼 있으면 대기 2초 → 추출 중 5초 → 완료 + 문서별 후보(가상 회사 테스트베드 표현)를 승인 대기로 추가
const CANDIDATES = {
  '13_파트너사협상자료': [['TBS 협상목표안', '협상 마지노선 문서명', 1, 0], ['간사이 파일럿', '비공개 파일럿 계획', 1, 0]],
  '01_사업전략_방향_보고서': [['PRJ-2026-05', 'AI 요약 프로젝트 코드', 2, 0], ['AI 요약 Add-on', '미출시 유료 기능', 1, 1]],
  '05_투자유치_자료': [['Series B 리드 투자사', '투자 협의 상대', 1, 0], ['프리머니 450억', '미공개 기업가치', 1, 0]],
  '09_아키텍처_설계서': [['kong-admin.neoworks.internal', '내부 관리 주소', 1, 0], ['bastion-prd-01', '운영 접속 서버', 1, 0]],
};
function advanceJobs() {
  const t = Date.now();
  for (const job of jobs) {
    if (job.status === 'queued' && gpuConnected && t - (job._at ?? 0) > 2000) Object.assign(job, { status: 'running', _at: t });
    else if (job.status === 'running' && !gpuConnected) Object.assign(job, { status: 'queued', _at: t }); // 운영과 같이 GPU가 끊기면 대기로 되돌림
    else if (job.status === 'running' && t - job._at > 5000) {
      Object.assign(job, { status: 'done', finished_at: now() });
      for (const [keyword, reason, docHits, negHits] of CANDIDATES[job.doc_id] ?? [['내부 코드명', '추출 후보', 1, 0]])
        if (!keywords.some((k) => k.doc_id === job.doc_id && k.keyword === keyword))
          keywords.push({ ...kw(keyword, job.doc_id, 'pending', reason, docHits, negHits), created_at: now() });
    }
  }
}
const publicJob = ({ _at, ...job }) => job;

const reports = live('reports').reports;
let running = null;

function reportStatus(id) {
  if (running && running.report_id === id) {
    const elapsed = (Date.now() - running.started) / 1000;
    if (elapsed > 9) {
      const done = { report_id: id, status: 'done', from: running.from, to: running.to, use_llm: running.use_llm, generated_at: now(),
        rows: 412, llm_used: running.use_llm && gpuConnected, llm_error: running.use_llm && !gpuConnected ? 'URLError' : null,
        llm_ms: running.use_llm && gpuConnected ? 6100 : null, agg_ms: 60, lines_kept: 12, lines_dropped: 0, gpu_started: false, gpu_waited_s: null,
        file: `/admin/reports/${id}/file` };
      reports.unshift(done);
      running = null;
      return done;
    }
    return { report_id: id, status: 'running', stage: elapsed < 3 ? 'aggregating' : 'writing', from: running.from, to: running.to,
      use_llm: running.use_llm, elapsed_seconds: Math.round(elapsed) };
  }
  return reports.find((report) => report.report_id === id);
}

const server = createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  const body = raw ? JSON.parse(raw) : undefined;
  const url = new URL(req.url, 'http://fake');
  const p = decodeURIComponent(url.pathname);
  const admin = req.headers['x-admin-id'] ?? null;
  const json = (status, payload) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); };
  const notFound = () => json(404, { detail: { code: 'NOT_FOUND', message: `${req.method} ${p}` } });
  console.log(req.method, p, admin ?? '');
  advanceGpu();
  advanceJobs();
  let m;

  if (req.method === 'GET' && p === '/admin/gpu')
    return json(200, { ...(gpuConnected
      ? { connected: true, models: ['qwen3-8b'], latency_ms: 6, error: null }
      : { connected: false, models: [], latency_ms: null, error: gpuInstance.state === 'running' ? 'ConnectionRefusedError' : null }),
    instance_state: gpuInstance.state, controllable: true, checked_at: now() });
  if (req.method === 'POST' && (m = /^\/admin\/gpu\/(start|stop)$/.exec(p))) {
    const action = m[1];
    if (action === 'stop' && (running || jobs.some((job) => job.status === 'running')))
      return json(409, { detail: { code: 'GPU_BUSY', message: `GPU is in use: ${running ? 'report' : 'keyword_job'}.` } });
    if (gpuInstance.state !== (action === 'start' ? 'stopped' : 'running'))
      return json(409, { detail: { code: 'GPU_STATE', message: `GPU instance is ${gpuInstance.state}.` } });
    const previous = gpuInstance.state;
    gpuInstance = { state: action === 'start' ? 'pending' : 'stopping', at: Date.now() };
    advanceGpu();
    return json(200, { instance_id: GPU_ID, previous_state: previous, instance_state: gpuInstance.state });
  }
  if (req.method === 'POST' && p === '/fake/gpu') {
    gpuInstance = { state: gpuInstance.state === 'stopped' ? 'running' : 'stopped', at: 0 };
    advanceGpu();
    return json(200, { gpuConnected, instance_state: gpuInstance.state });
  }
  if (req.method === 'POST' && p === '/fake/reload-fail') { reloadFails = !reloadFails; return json(200, { reloadFails }); }

  if (req.method === 'GET' && p === '/admin/policies') return json(200, live('policies'));
  if (req.method === 'POST' && p === '/admin/reload-signatures')
    return reloadFails ? json(500, { detail: { code: 'RELOAD_FAILED', message: 'reload failed' } }) : json(200, { status: 'ok' });

  if (req.method === 'GET' && p === '/admin/keywords') return json(200, { keywords });
  if (req.method === 'POST' && p === '/admin/keywords') {
    if (keywords.some((k) => k.doc_id === body.doc_id && k.keyword === body.keyword.trim()))
      return json(409, { detail: { code: 'KEYWORD_EXISTS', message: 'This keyword already exists for the document.' } });
    if (body.keyword.trim().length < 2) return json(400, { detail: { code: 'KEYWORD_TOO_SHORT', message: 'short' } });
    const created = { ...kw(body.keyword.trim(), body.doc_id, body.approve ? 'approved' : 'pending', null, 1, null), source: 'manual', created_by: admin };
    keywords.push(created);
    return json(201, created);
  }
  if (req.method === 'POST' && (m = /^\/admin\/keywords\/(\d+)\/approve$/.exec(p))) {
    const k = keywords.find((x) => x.id === Number(m[1]));
    if (!k) return notFound();
    if (k.status !== 'approved') Object.assign(k, { status: 'approved', decided_at: now(), decided_by: admin });
    return json(200, k);
  }
  if (req.method === 'PATCH' && (m = /^\/admin\/keywords\/(\d+)$/.exec(p))) { // 운영 keyword_store.update와 같은 규칙
    const k = keywords.find((x) => x.id === Number(m[1]));
    if (!k) return notFound();
    if (k.status !== 'pending') return json(409, { detail: { code: 'NOT_PENDING', message: 'Only pending keywords can be edited.' } });
    const text = String(body?.keyword ?? '').trim();
    if (text.length < 2 || text.length > 100 || text.includes('\n')) return json(400, { detail: { code: 'INVALID_KEYWORD', message: 'invalid' } });
    if (text === k.keyword) return json(200, k);
    if (keywords.some((x) => x.id !== k.id && x.doc_id === k.doc_id && x.keyword === text))
      return json(409, { detail: { code: 'DUPLICATE', message: 'This keyword already exists for the document.' } });
    Object.assign(k, { keyword: text, doc_hits: null, neg_hits: null });
    return json(200, k);
  }
  if (req.method === 'DELETE' && (m = /^\/admin\/keywords\/(\d+)$/.exec(p))) {
    const i = keywords.findIndex((x) => x.id === Number(m[1]));
    if (i < 0) return notFound();
    keywords.splice(i, 1);
    res.writeHead(204); return res.end();
  }
  if (req.method === 'GET' && p === '/admin/keyword-jobs') {
    const counts = { queued: 0, running: 0, done: 0, failed: 0 };
    for (const job of jobs) counts[job.status] += 1;
    return json(200, { jobs: [...jobs].sort((a, b) => b.id - a.id).map(publicJob), counts });
  }
  if (req.method === 'POST' && (m = /^\/admin\/documents\/(.+)\/extract-keywords$/.exec(p))) {
    if (m[1] === '20_장애대응보고서') return json(404, { detail: { code: 'DOC_NOT_FOUND', message: 'Document is not indexed.' } });
    const job = { id: nextJob++, doc_id: m[1], doc_version: 0, status: 'queued', attempts: 0, error: null, created_at: now(), finished_at: null, _at: Date.now() };
    jobs.push(job);
    return json(202, publicJob(job));
  }
  if (req.method === 'POST' && (m = /^\/admin\/keyword-jobs\/(\d+)\/retry$/.exec(p))) {
    const job = jobs.find((x) => x.id === Number(m[1]));
    if (!job) return notFound();
    Object.assign(job, { status: 'queued', attempts: 0, error: null, finished_at: null, _at: Date.now() });
    return json(200, publicJob(job));
  }

  if (req.method === 'GET' && p === '/admin/reports') {
    const current = running ? reportStatus(running.report_id) : null; // 끝났으면 reports에 이미 들어간다
    return json(200, { reports: [...(current?.status === 'running' ? [current] : []), ...reports] });
  }
  if (req.method === 'POST' && p === '/admin/reports') {
    if (running) return json(409, { detail: { code: 'REPORT_RUNNING', message: 'A report is already being generated.' } });
    const stamp = now().replace(/[-:]/g, '').slice(0, 15);
    running = { report_id: `report_${body.from}_${body.to}_${stamp}`, from: body.from, to: body.to, use_llm: body.use_llm ?? true, started: Date.now() };
    return json(202, reportStatus(running.report_id));
  }
  if (req.method === 'GET' && (m = /^\/admin\/reports\/([^/]+)\/file$/.exec(p))) {
    const report = reportStatus(m[1]);
    if (!report || report.status !== 'done') return notFound();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': `${url.searchParams.get('download') === '1' ? 'attachment' : 'inline'}; filename="${m[1]}.html"` });
    return res.end(`<!doctype html><meta charset="utf-8"><title>보안 리포트</title><h1>보안 리포트 ${report.from} ~ ${report.to}</h1><p>(화면 확인용 가짜 리포트)</p>`);
  }
  if (req.method === 'GET' && (m = /^\/admin\/reports\/([^/]+)$/.exec(p))) {
    const report = reportStatus(m[1]);
    return report ? json(200, report) : notFound();
  }
  return notFound();
});
server.listen(18000, '127.0.0.1', () => console.log('fake detection on http://127.0.0.1:18000'));
