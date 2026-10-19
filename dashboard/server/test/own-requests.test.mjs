// 내 요청 기록 - 확장 프로그램 열람 키로 본인 요청만 (2026-10-09)
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { createAppServer, ownRequests } from '../app.mjs';
import { buildOwnEvidence } from '../match-evidence.mjs';
import { canonicalEventToDto, validateCanonicalEvent } from '../validation.mjs';

const CONFIG = {
  allowedOrigin: 'http://127.0.0.1:4173',
  adminEmail: 'local-admin-own@example.test',
  adminPassword: 'local-password-own-tests',
  ingestToken: 'local-ingest-token-own-tests',
};
const KEY_A = 'A'.repeat(20) + 'b-_' + '9'.repeat(20);
const KEY_B = 'B'.repeat(43);
const sha = (value) => createHash('sha256').update(value).digest('hex');
const HASH_A = sha(KEY_A);
const HASH_B = sha(KEY_B);
const FILE_ID = '00000000ddcc81fa9d8d70a16446639a';
const ago = (seconds) => new Date(Date.now() - seconds * 1000).toISOString();
const signature = (count = 1, entityType = 'KR_RRN') => ({ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'MASK', entityCounts: [{ entityType, count }] });
const canonical = (over) => ({
  type: 'SECURITY_EVENT', eventId: 'evt-x', requestId: 'req-x', timestamp: ago(60), clientId: 'chrome-a',
  targetLlm: 'ChatGPT', contentType: 'prompt', finalAction: 'ALLOW', detectionOutcome: 'NO_MATCH', detections: [], viewerKeyHash: HASH_A, ...over,
});
const masked = (over) => canonical({ finalAction: 'MASK', detectionOutcome: 'MATCH', detections: [signature()], ...over });
const dto = (event) => canonicalEventToDto(validateCanonicalEvent(event));
const RRN = '900101-1234567';

afterEach(() => { delete process.env.EVIDENCE_SHOW_RAW; });

void test('the event keeps only a well-formed key digest', () => {
  assert.equal(dto(masked({})).viewer_key_hash, HASH_A);
  assert.equal(dto(masked({ viewerKeyHash: undefined })).viewer_key_hash, undefined);
  for (const bad of [KEY_A, HASH_A.toUpperCase(), HASH_A.slice(1), `${HASH_A}0`, 42])
    assert.throws(() => validateCanonicalEvent(masked({ viewerKeyHash: bad })), String(bad));
});

void test('the list holds only this browser, the last 7 days, and masked or blocked requests', () => {
  const events = [
    dto(masked({ eventId: 'evt-mine', requestId: 'req-mine', timestamp: ago(60) })),
    dto(masked({ eventId: 'evt-other-browser', requestId: 'req-other-browser', viewerKeyHash: HASH_B })),
    dto(masked({ eventId: 'evt-no-key', requestId: 'req-no-key', viewerKeyHash: undefined })),
    dto(masked({ eventId: 'evt-old', requestId: 'req-old', timestamp: ago(8 * 24 * 3600) })),
    dto(canonical({ eventId: 'evt-allowed', requestId: 'req-allowed' })),
    dto(canonical({ eventId: 'evt-blocked', requestId: 'req-blocked', timestamp: ago(30), finalAction: 'BLOCK', detectionOutcome: 'MATCH',
      detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE', action: 'BLOCK', matchedDocumentId: 'doc-13', score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } }] })),
  ];
  const { items, window_days } = ownRequests(events, HASH_A);
  assert.equal(window_days, 7);
  assert.deepEqual(items.map((item) => item.event_id), ['evt-blocked', 'evt-mine']);   // 최근 순
  assert.deepEqual(items[1].entity_counts, [{ entity_type: 'KR_RRN', count: 1 }]);
  assert.equal(items[0].protected_document, true);
  // 요청 ID는 본인 건의 것만 싣는다(2026-10-12, 관리자 '요청 ID로 기록 조회'용). 빠진 건(다른 브라우저·키 없음·7일 지남·허용)의 요청 ID는 없다
  assert.deepEqual(items.map((item) => item.request_id), ['req-blocked', 'req-mine']);
  for (const other of ['req-other-browser', 'req-no-key', 'req-old', 'req-allowed'])
    assert.equal(JSON.stringify(items).includes(other), false, other);
  // 브라우저 번호·문서 번호·지문·탐지 내용은 여전히 내보내지 않는다
  for (const field of ['client_id', 'viewer_key_hash', 'detections', 'matched_document_id'])
    assert.equal(JSON.stringify(items).includes(`"${field}"`), false, field);
  assert.equal(JSON.stringify(items).includes('doc-13'), false);
});

void test('a prompt that is allowed but carries a masked file shows as one masked request', () => {
  const events = [
    dto(canonical({ eventId: 'evt-file', requestId: 'req-file', timestamp: ago(70), contentType: 'file', finalAction: 'MASK',
      detectionOutcome: 'MATCH', detections: [signature(4, 'KR_BANK_ACCOUNT')], fileId: FILE_ID })),
    dto(canonical({ eventId: 'evt-prompt', requestId: 'req-prompt', timestamp: ago(60), attachedFileIds: [FILE_ID] })),
  ];
  const { items } = ownRequests(events, HASH_A);
  assert.deepEqual(items.map((item) => item.event_id), ['evt-prompt']);
  assert.equal(items[0].final_action, 'ALLOW');
  assert.equal(items[0].group_final_action, 'MASK');
  assert.deepEqual(items[0].attached_files.map((file) => [file.event_id, file.final_action]), [['evt-file', 'MASK']]);
  assert.deepEqual(items[0].attached_files[0].entity_counts, [{ entity_type: 'KR_BANK_ACCOUNT', count: 4 }]);
});

const promptText = `고객 주민번호 ${RRN} 확인해줘`;
const promptStart = Array.from(promptText).indexOf('9');
const promptDecision = {
  request_id: 'req-x', decided_by: 'signature', prompt: promptText, masked_text: '고객 주민번호 [KR_RRN] 확인해줘',
  findings: [{ entity_type: 'KR_RRN', start: promptStart, end: promptStart + RRN.length, replacement: '[KR_RRN]', policy_action: 'mask' }],
};

void test('a masked prompt comes back as one before/after block', () => {
  const evidence = buildOwnEvidence(dto(masked({})), promptDecision, null);
  assert.equal(evidence.status, 'AVAILABLE');
  assert.equal(evidence.redaction, 'OFF');
  const [segment] = evidence.prompt_comparison.segments;
  assert.equal(evidence.prompt_comparison.after_recorded, true);
  assert.equal(segment.after, '고객 주민번호 [KR_RRN] 확인해줘');
  // 운영 기본(EVIDENCE_SHOW_RAW 없음)에서도 원문 그대로, 가린 값은 위치(하이라이트)로만
  assert.equal(segment.before, promptText);
  assert.equal(segment.before.slice(segment.spans[0].start, segment.spans[0].end), RRN);
  assert.deepEqual(segment.spans, [{ start: promptStart, end: promptStart + RRN.length, entity_type: 'KR_RRN', replacement: '[KR_RRN]' }]);
});

void test('a protected-document block says only that it was blocked', () => {
  const event = dto(canonical({ finalAction: 'BLOCK', detectionOutcome: 'MATCH',
    detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE', action: 'BLOCK', matchedDocumentId: 'doc-13', score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } }] }));
  const decision = { ...promptDecision, decided_by: 'windowhash', doc_id: 'doc-13', filename: '13_파트너사협상자료.docx' };
  const evidence = buildOwnEvidence(event, decision, null);
  assert.deepEqual(evidence, { event_id: 'evt-x', status: 'AVAILABLE', redaction: 'OFF', content_type: 'prompt', final_action: 'BLOCK', protected_document: true });
});

void test('records that do not belong to the request or are too long are not shown', () => {
  assert.equal(buildOwnEvidence(dto(masked({})), null, null).status, 'NOT_RECORDED');
  assert.equal(buildOwnEvidence(dto(masked({})), { ...promptDecision, request_id: 'req-other' }, null).status, 'NOT_RECORDED');
  assert.equal(buildOwnEvidence(dto(masked({})), { ...promptDecision, prompt: null }, null).status, 'TOO_LARGE');
});

void test('a file shows its cells, or the whole text when there are no cells', () => {
  const event = dto(canonical({ eventId: 'evt-file', requestId: 'req-file', contentType: 'file', finalAction: 'MASK', detectionOutcome: 'MATCH',
    detections: [signature()], fileId: FILE_ID }));
  const cell = { request_id: 'req-file#f:0:docx:body:p0', decided_by: 'signature', block_order: 0, prompt: promptText,
    masked_text: promptDecision.masked_text, findings: JSON.stringify(promptDecision.findings) };
  const whole = { request_id: 'req-file', decided_by: 'signature', filename: '요청서.docx', prompt: null };
  const withCells = buildOwnEvidence(event, whole, [cell]);
  assert.equal(withCells.status, 'AVAILABLE');
  assert.equal(withCells.filename, '요청서.docx');
  assert.equal(withCells.file_comparison.format, 'docx');
  assert.equal(withCells.file_comparison.segments[0].after, promptDecision.masked_text);
  assert.equal(withCells.prompt_comparison, undefined);
  // 다른 요청의 칸은 섞지 않는다(전체 글자도 길어 기록이 없으면 보여 줄 것이 없다)
  const foreign = buildOwnEvidence(event, whole, [{ ...cell, request_id: 'req-filex#f:0:docx:body:p0' }]);
  assert.equal(foreign.status, 'TOO_LARGE');
  assert.equal(foreign.file_comparison, undefined);
  // PDF·TXT처럼 칸이 없으면 전체 글자를 한 칸으로
  const pdf = buildOwnEvidence(event, { ...promptDecision, request_id: 'req-file', filename: '자료.pdf' }, []);
  assert.equal(pdf.status, 'AVAILABLE');
  assert.equal(pdf.prompt_comparison.segments[0].after, promptDecision.masked_text);
});

async function withBackend(run) {
  const root = await mkdtemp(path.join(tmpdir(), 'own-requests-'));
  const server = createAppServer({ ...CONFIG, storePath: path.join(root, 'events.json') });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const ingest = async (event) => {
      const response = await fetch(`${base}/api/events/ingest`, { method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${CONFIG.ingestToken}` }, body: JSON.stringify(event) });
      assert.ok([200, 201].includes(response.status), `ingest ${response.status}`);
    };
    const call = (pathname, key, method = 'GET') => fetch(`${base}${pathname}`, { method, headers: key ? { 'X-Viewer-Key': key } : {} });
    await run({ ingest, call, base });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
}

void test('the API opens only with the key and only the requests it sent', async () => {
  await withBackend(async ({ ingest, call }) => {
    await ingest(masked({ eventId: 'evt-a', requestId: 'req-a' }));
    await ingest(masked({ eventId: 'evt-b', requestId: 'req-b', viewerKeyHash: HASH_B }));

    for (const key of [undefined, 'short', `${KEY_A}x`, HASH_A]) {
      const response = await call('/api/my/requests', key);
      assert.equal(response.status, 401, String(key));
      assert.equal((await response.json()).error.code, 'VIEWER_KEY_REQUIRED');
    }
    assert.equal((await call('/api/my/requests', KEY_A, 'POST')).status, 405);

    const list = await call('/api/my/requests', KEY_A);
    assert.equal(list.status, 200);
    assert.equal(list.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await list.json()).items.map((item) => item.event_id), ['evt-a']);
    assert.deepEqual((await (await call('/api/my/requests', KEY_B)).json()).items.map((item) => item.event_id), ['evt-b']);

    const own = await call('/api/my/requests/evt-a/evidence', KEY_A);
    assert.equal(own.status, 200);
    assert.equal((await own.json()).event_id, 'evt-a');
    for (const [pathname, key] of [
      ['/api/my/requests/evt-b/evidence', KEY_A],     // 다른 브라우저의 요청
      ['/api/my/requests/evt-none/evidence', KEY_A],  // 없는 요청 - 있는지 없는지 구분하지 않는다
      ['/api/my/requests/%E0%A4%A/evidence', KEY_A],  // 잘못된 주소
      ['/api/my/requests/evt-a', KEY_A],
    ]) assert.equal((await call(pathname, key)).status, 404, pathname);
    assert.equal((await call('/api/my/requests/evt-a/evidence')).status, 401);
    // 관리자 화면은 그대로 로그인이 필요하다
    assert.equal((await call('/api/events', KEY_A)).status, 401);
  });
});

// 2026-10-10 차단·가림 사유: 정해진 목록만, 차단·가림 건에만(검사 없이 전송된 허용 건은 본인 화면에 싣지 않는다)
void test('blocked or masked requests carry only the listed reason codes', () => {
  const unavailable = (eventId, reasonCode, over = {}) => canonical({ eventId, requestId: `req-${eventId}`, contentType: 'file',
    finalAction: 'BLOCK', detectionOutcome: 'UNAVAILABLE', reasonCode, enforcement: { applied: true, httpStatus: 403 }, ...over });
  const degraded = (failurePolicy) => ({ degraded: true, degradedReason: 'TIMEOUT', failurePolicy });
  const listed = [
    'file_uninspectable_image', 'file_uninspectable_scanned_pdf', 'file_uninspectable_other', 'file_too_large',
    'detection_timeout', 'detection_unreachable', 'detection_error', 'detection_parse_error',
    'mask_application_failed', 'file_masking_failed',
  ];
  const events = [
    ...listed.map((code) => dto(unavailable(`evt-${code}`, code))),
    dto(unavailable('evt-partial-mask', 'detection_timeout', { finalAction: 'MASK', enforcement: { applied: true }, ...degraded('FAIL_OPEN') })),
    dto(masked({ eventId: 'evt-pii', requestId: 'req-pii', reasonCode: 'pii' })),
    dto(unavailable('evt-doc', 'doc_excerpt', { detectionOutcome: 'MATCH',
      detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', scoreKind: 'COVERAGE', action: 'BLOCK', matchedDocumentId: 'doc-13', score: 0.9, documentSpan: { charStart: 0, charEnd: 10 } }] })),
    dto(unavailable('evt-unknown', 'internal_debug_code')),
    dto(unavailable('evt-allowed-image', 'file_uninspectable_image', { finalAction: 'ALLOW', enforcement: undefined })),
    dto(unavailable('evt-allowed-large', 'file_too_large', { finalAction: 'ALLOW', enforcement: undefined })),
    dto(unavailable('evt-allowed-timeout', 'detection_timeout', { contentType: 'prompt', finalAction: 'ALLOW', enforcement: undefined, ...degraded('FAIL_OPEN') })),
  ];
  const { items } = ownRequests(events, HASH_A);
  const reasons = Object.fromEntries(items.map((item) => [item.event_id, item.reason_code]));
  for (const code of listed) assert.equal(reasons[`evt-${code}`], code, code);
  assert.equal(reasons['evt-file_too_large'], 'file_too_large');
  assert.equal(reasons['evt-partial-mask'], 'detection_timeout');
  for (const id of ['evt-pii', 'evt-doc', 'evt-unknown']) {
    assert.ok(id in reasons, id);
    assert.equal(reasons[id], undefined, id);
    assert.equal('reason_code' in items.find((item) => item.event_id === id), false, id);
  }
  for (const id of ['evt-allowed-image', 'evt-allowed-large', 'evt-allowed-timeout']) assert.equal(id in reasons, false, id);

  // 질문이 막혀 묶음으로 보일 때도, 함께 붙은 허용(검사 없이 전송) 파일에는 사유를 싣지 않는다
  const grouped = ownRequests([
    dto(unavailable('evt-file-allowed', 'file_uninspectable_image', { finalAction: 'ALLOW', enforcement: undefined, fileId: FILE_ID, timestamp: ago(70) })),
    dto(unavailable('evt-question', 'detection_timeout', { contentType: 'prompt', attachedFileIds: [FILE_ID], enforcement: { applied: true, httpStatus: 503 }, ...degraded('FAIL_CLOSED') })),
  ], HASH_A).items;
  assert.deepEqual(grouped.map((item) => [item.event_id, item.reason_code]), [['evt-question', 'detection_timeout']]);
  assert.deepEqual(grouped[0].attached_files.map((file) => [file.event_id, file.final_action, 'reason_code' in file]), [['evt-file-allowed', 'ALLOW', false]]);

  // 근거 기본 응답에도 같은 규칙
  assert.equal(buildOwnEvidence(dto(unavailable('evt-large', 'file_too_large')), null, null).reason_code, 'file_too_large');
  assert.deepEqual(buildOwnEvidence(dto(unavailable('evt-large', 'file_too_large')), null, null), {
    event_id: 'evt-large', status: 'NOT_RECORDED', redaction: 'OFF', content_type: 'file', final_action: 'BLOCK', reason_code: 'file_too_large',
  });
  assert.equal('reason_code' in buildOwnEvidence(dto(unavailable('evt-allowed', 'file_too_large', { finalAction: 'ALLOW', enforcement: undefined })), null, null), false);
  assert.equal('reason_code' in buildOwnEvidence(dto(masked({ reasonCode: 'pii' })), promptDecision, null), false);
});

// 2026-10-12 접속 차단 사유: client_blocked는 규칙의 사유 코드(+ 공개를 고른 메모), client_id_missing은 고정 사유 코드만
void test('access-block records carry the rule reasons and only a visible memo; a missing id carries the fixed code', () => {
  const RULE_ID = 'abcdef12-0000-4000-8000-000000000abc';
  const OTHER_RULE_ID = 'abcdef12-0000-4000-8000-000000000def';
  const accessBlock = (eventId, over = {}) => canonical({ eventId, requestId: `req-${eventId}`, finalAction: 'BLOCK', detectionOutcome: 'UNAVAILABLE',
    reasonCode: 'client_blocked', accessRuleId: RULE_ID, enforcement: { applied: true, httpStatus: 403 }, ...over });
  const rules = new Map([
    [RULE_ID, { id: RULE_ID, client_id: 'chrome-a', reasons: ['INVESTIGATION', 'ADMIN_REQUEST'], memo: '보안팀에 문의', show_memo_to_user: true, created_by: 'local-admin' }],
    [OTHER_RULE_ID, { id: OTHER_RULE_ID, client_id: 'chrome-a', reasons: ['LEAVE'], memo: '관리자 전용 메모', show_memo_to_user: false, created_by: 'local-admin' }],
  ]);
  const looked = [];
  const ruleFor = (event) => { looked.push(event.event_id); return rules.get(event.access_rule_id) ?? null; };
  const events = [
    dto(accessBlock('evt-shown', { timestamp: ago(10) })),
    dto(accessBlock('evt-hidden', { timestamp: ago(20), accessRuleId: OTHER_RULE_ID })),
    dto(accessBlock('evt-gone', { timestamp: ago(30), accessRuleId: 'abcdef12-0000-4000-8000-000000000999' })),
    dto(accessBlock('evt-missing-id', { timestamp: ago(40), clientId: 'unknown-203.0.113.9', reasonCode: 'client_id_missing', accessRuleId: undefined })),
    dto(accessBlock('evt-allowed', { timestamp: ago(50), finalAction: 'ALLOW', enforcement: undefined })),
  ];
  const { items } = ownRequests(events, HASH_A, Date.now(), ruleFor);
  assert.deepEqual(items.map((item) => item.event_id), ['evt-shown', 'evt-hidden', 'evt-gone', 'evt-missing-id']);   // 허용 건은 목록에 없다
  const byId = Object.fromEntries(items.map((item) => [item.event_id, item]));
  assert.deepEqual([byId['evt-shown'].reason_code, byId['evt-shown'].block_reasons, byId['evt-shown'].user_memo], ['client_blocked', ['INVESTIGATION', 'ADMIN_REQUEST'], '보안팀에 문의']);
  assert.deepEqual([byId['evt-hidden'].reason_code, byId['evt-hidden'].block_reasons, 'user_memo' in byId['evt-hidden']], ['client_blocked', ['LEAVE'], false]);
  assert.deepEqual([byId['evt-gone'].reason_code, 'block_reasons' in byId['evt-gone'], 'user_memo' in byId['evt-gone']], ['client_blocked', false, false]);
  assert.deepEqual([byId['evt-missing-id'].reason_code, 'block_reasons' in byId['evt-missing-id'], 'user_memo' in byId['evt-missing-id']], ['client_id_missing', false, false]);
  assert.ok(!looked.includes('evt-missing-id') && !looked.includes('evt-allowed'));   // 고정 사유·허용 건은 규칙을 찾지도 않는다
  const text = JSON.stringify(items);
  for (const secret of ['관리자 전용 메모', 'local-admin', RULE_ID, OTHER_RULE_ID, 'access_rule_id', '"client_id"', 'show_memo_to_user']) assert.ok(!text.includes(secret), secret);
  // 규칙 조회를 넘기지 않으면(옛 호출) 사유 코드만
  const plain = ownRequests(events, HASH_A).items.find((item) => item.event_id === 'evt-shown');
  assert.deepEqual([plain.reason_code, 'block_reasons' in plain, 'user_memo' in plain], ['client_blocked', false, false]);
});

// 2026-10-12 요청 ID: 관리자 이벤트 상세의 '요청 ID'와 같은 값. 본인 건에만, 붙은 파일에도 각자의 것, 요청 ID가 없던 옛 기록은 이벤트 ID로
void test('each own request and each attached file carries its own request id, an old record falls back to the event id, and other browsers stay out', () => {
  const events = [
    dto(canonical({ eventId: 'evt-file', requestId: 'req-file', timestamp: ago(70), contentType: 'file', finalAction: 'MASK',
      detectionOutcome: 'MATCH', detections: [signature(2, 'KR_BANK_ACCOUNT')], fileId: FILE_ID })),
    // 같은 확장 ID·같은 파일 번호라도 다른 브라우저(열람 키)의 파일은 이 질문에 붙지 않는다
    dto(canonical({ eventId: 'evt-file-other', requestId: 'req-file-other', timestamp: ago(65), contentType: 'file', finalAction: 'MASK',
      detectionOutcome: 'MATCH', detections: [signature()], fileId: FILE_ID, viewerKeyHash: HASH_B })),
    dto(canonical({ eventId: 'evt-prompt', requestId: 'req-prompt', timestamp: ago(60), attachedFileIds: [FILE_ID] })),
    dto(masked({ eventId: 'evt-legacy', requestId: undefined, timestamp: ago(50) })),
    dto(masked({ eventId: 'evt-other', requestId: 'req-other', viewerKeyHash: HASH_B, timestamp: ago(40) })),
  ];
  assert.equal('request_id' in events[3], false);   // 옛 기록: 요청 ID 없음
  const mine = ownRequests(events, HASH_A).items;
  assert.deepEqual(mine.map((item) => [item.event_id, item.request_id]), [['evt-legacy', 'evt-legacy'], ['evt-prompt', 'req-prompt']]);
  const prompt = mine.find((item) => item.event_id === 'evt-prompt');
  assert.deepEqual(prompt.attached_files.map((file) => [file.event_id, file.request_id]), [['evt-file', 'req-file']]);
  const mineText = JSON.stringify(mine);
  for (const other of ['req-file-other', 'evt-file-other', 'req-other', 'evt-other']) assert.equal(mineText.includes(other), false, other);

  const theirs = ownRequests(events, HASH_B).items;
  assert.deepEqual(theirs.map((item) => [item.event_id, item.request_id]), [['evt-other', 'req-other'], ['evt-file-other', 'req-file-other']]);
  const theirsText = JSON.stringify(theirs);
  for (const own of ['req-file"', 'req-prompt', 'evt-legacy', 'evt-prompt']) assert.equal(theirsText.includes(own), false, own);
});

void test('the API puts the same request id in the list, in attached files and in the evidence, only for the key that sent it, and the admin finds it by that id', async () => {
  await withBackend(async ({ ingest, call, base }) => {
    await ingest(canonical({ eventId: 'evt-a-file', requestId: 'req-a-file', timestamp: ago(70), contentType: 'file', finalAction: 'MASK',
      detectionOutcome: 'MATCH', detections: [signature()], fileId: FILE_ID }));
    await ingest(canonical({ eventId: 'evt-a-prompt', requestId: 'req-a-prompt', timestamp: ago(60), attachedFileIds: [FILE_ID] }));
    await ingest(masked({ eventId: 'evt-a-legacy', requestId: undefined, timestamp: ago(50) }));
    await ingest(canonical({ eventId: 'evt-a-access', requestId: 'req-a-access', timestamp: ago(45), clientId: 'unknown-203.0.113.9', finalAction: 'BLOCK',
      detectionOutcome: 'UNAVAILABLE', reasonCode: 'client_id_missing', enforcement: { applied: true, httpStatus: 403 } }));
    await ingest(masked({ eventId: 'evt-b', requestId: 'req-b-secret', viewerKeyHash: HASH_B, timestamp: ago(40) }));

    const listA = await (await call('/api/my/requests', KEY_A)).json();
    assert.deepEqual(listA.items.map((item) => [item.event_id, item.request_id]),
      [['evt-a-access', 'req-a-access'], ['evt-a-legacy', 'evt-a-legacy'], ['evt-a-prompt', 'req-a-prompt']]);
    assert.deepEqual(listA.items[2].attached_files.map((file) => [file.event_id, file.request_id]), [['evt-a-file', 'req-a-file']]);
    assert.equal(JSON.stringify(listA).includes('req-b-secret'), false);
    const listB = await (await call('/api/my/requests', KEY_B)).json();
    assert.deepEqual(listB.items.map((item) => [item.event_id, item.request_id]), [['evt-b', 'req-b-secret']]);
    for (const own of ['req-a-prompt', 'req-a-file', 'req-a-access', 'evt-a-legacy']) assert.equal(JSON.stringify(listB).includes(own), false, own);

    // 근거 응답: 목록과 같은 값(붙은 파일·옛 기록·접속 차단 사유가 붙는 건 포함)
    for (const [eventId, requestId] of [['evt-a-prompt', 'req-a-prompt'], ['evt-a-file', 'req-a-file'], ['evt-a-legacy', 'evt-a-legacy'], ['evt-a-access', 'req-a-access']]) {
      const response = await call(`/api/my/requests/${eventId}/evidence`, KEY_A);
      assert.equal(response.status, 200, eventId);
      const body = await response.json();
      assert.deepEqual([body.event_id, body.request_id], [eventId, requestId], eventId);
    }
    const access = await (await call('/api/my/requests/evt-a-access/evidence', KEY_A)).json();
    assert.deepEqual([access.reason_code, access.request_id], ['client_id_missing', 'req-a-access']);
    // 남의 건은 열리지 않고(없는 건과 같은 404), 응답에 그 요청 ID도 없다
    const foreign = await call('/api/my/requests/evt-b/evidence', KEY_A);
    assert.equal(foreign.status, 404);
    assert.equal((await foreign.text()).includes('req-b-secret'), false);
    assert.equal((await call('/api/my/requests/evt-b/evidence')).status, 401);
    assert.equal((await (await call('/api/my/requests/evt-b/evidence', KEY_B)).json()).request_id, 'req-b-secret');

    // 관리자: 이벤트 상세의 '요청 ID'와 같은 값이고 '요청 ID로 기록 조회'로 그 건이 찾힌다. 요청 ID가 없던 옛 기록은 '이벤트 ID'로 찾는다
    const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: CONFIG.adminEmail, password: CONFIG.adminPassword }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const admin = async (pathname) => (await fetch(`${base}${pathname}`, { headers: { Cookie: cookie } })).json();
    for (const [eventId, requestId] of [['evt-a-prompt', 'req-a-prompt'], ['evt-a-file', 'req-a-file'], ['evt-a-access', 'req-a-access']]) {
      assert.equal((await admin(`/api/events/${eventId}`)).request_id, requestId, eventId);
      const found = await admin(`/api/events/lookup?kind=request&value=${encodeURIComponent(requestId)}`);
      assert.deepEqual([found.status, found.items.map((item) => item.event_id)], ['FOUND', [eventId]], requestId);
    }
    assert.equal('request_id' in (await admin('/api/events/evt-a-legacy')), false);
    const legacy = await admin('/api/events/lookup?kind=event&value=evt-a-legacy');
    assert.deepEqual([legacy.status, legacy.items.map((item) => item.event_id)], ['FOUND', ['evt-a-legacy']]);
  });
});
