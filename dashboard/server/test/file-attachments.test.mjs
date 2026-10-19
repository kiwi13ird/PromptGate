// 질문과 첨부 파일 연결 · 파일 칸별 전·후 (2026-10-09)
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { attachmentLinks, createAppServer, groupAttachments } from '../app.mjs';
import { buildFileComparison, buildMatchEvidence, parseFileSegment } from '../match-evidence.mjs';
import { canonicalEventToDto, validateCanonicalEvent } from '../validation.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-files@example.test',
  adminPassword: 'local-password-files-tests',
  ingestToken: 'local-ingest-token-files-tests',
};
const FILE_ID = '00000000ddcc81fa9d8d70a16446639a';
const ago = (seconds) => new Date(Date.now() - seconds * 1000).toISOString();
const signature = (count = 3) => ({ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'MASK', entityCounts: [{ entityType: 'KR_RRN', count }] });
const canonical = (over) => ({
  type: 'SECURITY_EVENT', eventId: 'evt-x', requestId: 'req-x', timestamp: ago(60), clientId: 'chrome-a',
  targetLlm: 'ChatGPT', contentType: 'prompt', finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [], ...over,
});
const fileEvent = (over = {}) => canonical({ eventId: 'evt-file', requestId: 'req-file', timestamp: ago(70), contentType: 'file',
  finalAction: 'MASK', detectionOutcome: 'MATCH', detections: [signature()], fileId: FILE_ID, ...over });
const promptEvent = (over = {}) => canonical({ eventId: 'evt-prompt', requestId: 'req-prompt', timestamp: ago(60), attachedFileIds: [FILE_ID], ...over });
const dto = (event) => canonicalEventToDto(validateCanonicalEvent(event));

void test('file references are accepted only where they belong', () => {
  assert.equal(dto(fileEvent()).file_id, FILE_ID);
  assert.deepEqual(dto(promptEvent({ attachedFileIds: [FILE_ID, FILE_ID, 'file-AbC_9'] })).attached_file_ids, [FILE_ID, 'file-AbC_9']);
  assert.equal(dto(promptEvent({ attachedFileIds: [] })).attached_file_ids, undefined);
  assert.equal(dto(canonical({})).file_id, undefined);
  for (const bad of [
    promptEvent({ fileId: FILE_ID }),                               // 질문에 파일 번호
    fileEvent({ attachedFileIds: [FILE_ID] }),                      // 파일에 첨부 목록
    fileEvent({ fileId: '../etc/passwd' }),                         // 번호 형식 아님
    promptEvent({ attachedFileIds: 'not-a-list' }),
    promptEvent({ attachedFileIds: Array.from({ length: 21 }, (_, i) => `f${i}`) }),
  ]) assert.throws(() => validateCanonicalEvent(bad), bad.eventId);
});

void test('a prompt groups only files with the same number from the same browser', () => {
  const file = dto(fileEvent());
  const prompt = dto(promptEvent());
  const otherBrowser = dto(promptEvent({ eventId: 'evt-other', clientId: 'chrome-b' }));
  const later = dto(fileEvent({ eventId: 'evt-later', timestamp: ago(-120) }));   // 질문보다 2분 뒤 파일
  const { attached, parents } = attachmentLinks([file, prompt, otherBrowser, later]);
  assert.deepEqual(attached.get('evt-prompt').map((e) => e.event_id), ['evt-file']);
  assert.equal(attached.has('evt-other'), false);
  assert.deepEqual(parents.get('evt-file').map((e) => e.event_id), ['evt-prompt']);
  assert.equal(parents.has('evt-later'), false);

  const grouped = groupAttachments([prompt, file, later]);
  assert.deepEqual(grouped.map((e) => e.event_id), ['evt-prompt', 'evt-later']);
  assert.equal(grouped[0].group_final_action, 'MASK');           // 질문 허용 + 파일 마스킹 → 마스킹
  assert.equal(grouped[0].final_action, 'ALLOW');                // 질문 자체 조치는 그대로
  assert.equal(grouped[0].attached_files[0].event_id, 'evt-file');
});

void test('one file attached to two prompts appears under both and not alone', () => {
  const file = dto(fileEvent());
  const first = dto(promptEvent());
  const second = dto(promptEvent({ eventId: 'evt-prompt-2', requestId: 'req-prompt-2', timestamp: ago(30) }));
  const grouped = groupAttachments([second, first, file]);
  assert.deepEqual(grouped.map((e) => [e.event_id, e.attached_files?.length]), [['evt-prompt-2', 1], ['evt-prompt', 1]]);
});

// ---------------------------------------------------------------- HTTP

async function withBackend(run) {
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-files-'));
  const server = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json') });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const ingest = async (event) => {
      const response = await fetch(`${base}/api/events/ingest`, { method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(event) });
      assert.ok([200, 201].includes(response.status), `${event.eventId}: ${response.status} ${await response.text()}`);
    };
    const get = async (pathname) => {
      const response = await fetch(`${base}${pathname}`, { headers: { Cookie: cookie } });
      assert.equal(response.status, 200, pathname);
      return response.json();
    };
    await run({ ingest, get });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

void test('the list groups only when asked and filters by the group action', async () => {
  await withBackend(async ({ ingest, get }) => {
    await ingest(fileEvent());
    await ingest(promptEvent());
    await ingest(canonical({ eventId: 'evt-alone', requestId: 'req-alone', timestamp: ago(10) }));

    const plain = await get('/api/events');
    assert.deepEqual(plain.items.map((e) => e.event_id), ['evt-alone', 'evt-prompt', 'evt-file']);
    assert.ok(plain.items.every((e) => e.attached_files === undefined));   // 기존 화면은 그대로

    const grouped = await get('/api/events?group=request');
    assert.equal(grouped.total, 2);
    const head = grouped.items.find((e) => e.event_id === 'evt-prompt');
    assert.equal(head.group_final_action, 'MASK');
    assert.equal(head.attached_files[0].event_id, 'evt-file');
    assert.equal(head.attached_files[0].detections[0].detector, 'SIGNATURE');

    assert.deepEqual((await get('/api/events?group=request&final_action=MASK')).items.map((e) => e.event_id), ['evt-prompt']);
    assert.deepEqual((await get('/api/events?group=request&final_action=ALLOW')).items.map((e) => e.event_id), ['evt-alone']);
    assert.deepEqual((await get('/api/events?group=request&detector=SIGNATURE')).items.map((e) => e.event_id), ['evt-prompt']);
    assert.deepEqual((await get('/api/events?group=request&query=req-file')).items.map((e) => e.event_id), ['evt-prompt']);
  });
});

void test('detail links a prompt to its files and a file to its prompt', async () => {
  await withBackend(async ({ ingest, get }) => {
    await ingest(fileEvent());
    await ingest(promptEvent());
    const prompt = await get('/api/events/evt-prompt');
    assert.deepEqual(prompt.attached_files, [{ event_id: 'evt-file', request_id: 'req-file', occurred_at: prompt.attached_files[0].occurred_at,
      final_action: 'MASK', content_type: 'file' }]);
    const file = await get('/api/events/evt-file');
    assert.equal(file.attached_to[0].event_id, 'evt-prompt');
    assert.equal(file.file_id, FILE_ID);
  });
});

void test('an unknown group value is rejected', async () => {
  await withBackend(async ({ get }) => {
    await assert.rejects(get('/api/events?group=everything'));
  });
});

// ---------------------------------------------------------------- 칸별 전·후

const RRN = '900101-1234567';
const row = (segment, prompt, extra = {}) => ({ request_id: `req-file#f:0:${segment}`, prompt, decided_by: 'none', ...extra });
const maskedRow = (segment, label) => {
  const prompt = `${label} ${RRN}`;
  const start = label.length + 1;
  return row(segment, prompt, { decided_by: 'signature', pii_hits: 'KR_RRN:1', block_order: undefined,
    masked_text: `${label} [KR_RRN]`, findings: [{ entity_type: 'KR_RRN', start, end: start + RRN.length, replacement: '[KR_RRN]' }] });
};

void test('segment ids become document positions', () => {
  assert.deepEqual(parseFileSegment('r#f:0:docx:body:p3'), { id: 'body:p3', format: 'docx', area: 'body', para: 3 });
  assert.deepEqual(parseFileSegment('r#f:0:docx:body:t1:r2:c1:p0'),
    { id: 'body:t1:r2:c1:p0', format: 'docx', area: 'body', para: 0, table: 1, row: 2, col: 1, nested: false });
  assert.equal(parseFileSegment('r#f:0:docx:body:t1:r0:c0:t0:r1:c2:p0').nested, true);
  assert.equal(parseFileSegment('r#f:0:docx:header0:p0').area, 'header0');
  assert.deepEqual(parseFileSegment('r#f:0:xlsx:s1:r3:c2'), { id: 's1:r3:c2', format: 'xlsx', area: 'sheet', sheet: 1, row: 3, col: 2 });
  assert.equal(parseFileSegment('req-without-segment'), null);
  assert.equal(parseFileSegment('r#f:0:pdf:page1'), null);
});

void test('file comparison carries before, after and positions', () => {
  process.env.EVIDENCE_SHOW_RAW = '1';
  try {
    const event = { request_id: 'req-file' };
    const result = buildFileComparison(event, [
      row('docx:header0:p0', '경영지원실 대외비'),
      row('docx:body:p0', '신규 입사자 등록 요청서', { block_order: 0 }),
      maskedRow('docx:body:t0:r1:c1:p0', '주민등록번호'),
      row('docx:body:t0:r1:c0:p0', '주민등록번호', { block_order: 1 }),
      { request_id: 'other-request#f:0:docx:body:p9', prompt: '다른 요청', decided_by: 'none' },  // 다른 요청 번호는 섞지 않는다
    ]);
    assert.equal(result.status, 'AVAILABLE');
    assert.equal(result.format, 'docx');
    assert.equal(result.after_recorded, true);
    assert.equal(result.ordered, true);
    assert.equal(result.segments.length, 4);
    const cell = result.segments.find((s) => s.id === 'body:t0:r1:c1:p0');
    assert.equal(cell.after, '주민등록번호 [KR_RRN]');
    assert.equal(cell.before.slice(cell.spans[0].start, cell.spans[0].end), RRN);
    assert.equal(cell.spans[0].entity_type, 'KR_RRN');
  } finally {
    delete process.env.EVIDENCE_SHOW_RAW;
  }
});

void test('the file comparison shows the original even when other evidence is redacted', () => {
  // 운영 기본(EVIDENCE_SHOW_RAW 없음)에서도 칸별 전·후는 원문 그대로, 가린 값은 위치(하이라이트)로만
  const result = buildFileComparison({ request_id: 'req-file' }, [maskedRow('docx:body:t0:r1:c1:p0', '주민등록번호')]);
  const [cell] = result.segments;
  assert.equal(cell.before.slice(cell.spans[0].start, cell.spans[0].end), RRN);
  assert.ok(!cell.before.includes('█'));
});

void test('records from before 10/9 show the original only', () => {
  const result = buildFileComparison({ request_id: 'req-file' }, [row('xlsx:s0:r0:c0', '이름'), row('xlsx:s0:r1:c0', '홍길동', { decided_by: 'signature', pii_hits: 'KR_RRN:1' })]);
  assert.equal(result.after_recorded, false);
  assert.equal(result.format, 'xlsx');
  assert.ok(result.segments.every((s) => s.after === undefined && s.spans.length === 0));
});

void test('bad spans are dropped and oversized files are refused', () => {
  const bad = maskedRow('docx:body:p1', '번호');
  bad.findings = [{ entity_type: 'KR_RRN', start: 3, end: 999 }, { entity_type: 'KR_RRN', start: 'x', end: 2 }];
  assert.deepEqual(buildFileComparison({ request_id: 'req-file' }, [bad]).segments[0].spans, []);
  assert.equal(buildFileComparison({ request_id: 'req-file' }, Array.from({ length: 3001 }, (_, i) => row(`docx:body:p${i}`, 'x'))).status, 'TOO_LARGE');
  assert.equal(buildFileComparison({ request_id: 'req-file' }, [row('docx:body:p0', null)]).status, 'TOO_LARGE');
  assert.equal(buildFileComparison({ request_id: 'req-file' }, []).status, 'NOT_RECORDED');
});

void test('evidence includes the file comparison only for file events', () => {
  const decision = { request_id: 'req-file', decided_by: 'signature', prompt: `주민등록번호 ${RRN}`, prompt_kept: true, content_type: 'file' };
  const segments = [maskedRow('docx:body:t0:r1:c1:p0', '주민등록번호')];
  const fileEvt = { event_id: 'evt-file', request_id: 'req-file', occurred_at: ago(5), content_type: 'file', final_action: 'MASK',
    detection_outcome: 'MATCH', detections: [{ detector: 'SIGNATURE', entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }] };
  assert.equal(buildMatchEvidence(fileEvt, [decision], [], undefined, undefined, segments).file_comparison.status, 'AVAILABLE');
  const promptEvt = { ...fileEvt, content_type: 'prompt' };
  assert.equal(buildMatchEvidence(promptEvt, [{ ...decision, content_type: 'prompt' }], [], undefined, undefined, segments).file_comparison, undefined);
});
