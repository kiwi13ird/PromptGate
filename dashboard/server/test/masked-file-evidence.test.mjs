// PDF·HWP·HWPX 마스킹 전·후 근거 (2026-10-11, PDF·HWP 마스킹 명세 §3.7·§4.6). 값은 모두 가짜
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildFileComparison, buildOwnEvidence, isRecheckRequestId, parseFileSegment } from '../match-evidence.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

const RRN = '900101-1234567';
const MAIL = 'fake.person@example.test';
const span = (text, value) => {
  const chars = Array.from(text);
  const start = Array.from(text.slice(0, text.indexOf(value))).length;
  return { start, end: start + Array.from(value).length, total: chars.length };
};
const finding = (text, value, entity, policy, replacement = null) => {
  const { start, end } = span(text, value);
  return { entity_type: entity, start, end, score: 0.9, policy_action: policy, replacement };
};
const row = (requestId, prompt, extra = {}) => ({ request_id: requestId, prompt, decided_by: 'none', ...extra });

void test('parses PDF pages, HWP and HWPX cells and the Claude file number', () => {
  assert.deepEqual(parseFileSegment('r#f:0:pdf:body:p3'), { id: 'body:p3', format: 'pdf', area: 'body', para: 3 });
  assert.deepEqual(parseFileSegment('r#f:0:hwp:body:t0:r1:c2:p0'),
    { id: 'body:t0:r1:c2:p0', format: 'hwp', area: 'body', para: 0, table: 0, row: 1, col: 2, nested: false });
  assert.equal(parseFileSegment('r#f:0:hwpx:body:t0:r0:c1:t0:r2:c0:p1').nested, true);
  assert.equal(parseFileSegment('r#f:0:hwpx:header0:p1').area, 'header0');
  assert.deepEqual(parseFileSegment('r#file:1#f:0:docx:body:p0'), { id: 'file1:body:p0', file: 1, format: 'docx', area: 'body', para: 0 });
  assert.deepEqual(parseFileSegment('r#file:0#f:0:pdf:body:p2'), { id: 'file0:body:p2', file: 0, format: 'pdf', area: 'body', para: 2 });
  // 부가 글자(요약 정보·수식·필드 명령 등)는 검사만 한 칸 - 그리지 않는다
  for (const id of ['r#f:0:hwp:side:summary0', 'r#f:0:hwpx:side:eq3', 'r#file:2#f:0:hwp:side:field1']) assert.equal(parseFileSegment(id), null);
  // 가린 파일 재검사·모르는 형식·칸 번호 뒤 꼬리
  for (const id of ['r#verify', 'r#nows#verify', 'r#file:0#verify', 'r#file:0#nows#verify', 'r#f:0:pdf:body:p0#verify', 'r#f:0:pptx:body:p0']) {
    assert.equal(parseFileSegment(id), null, id);
  }
  assert.equal(isRecheckRequestId('r#nows#verify'), true);
  assert.equal(isRecheckRequestId('r#file:1#verify'), true);
  assert.equal(isRecheckRequestId('r#f:0:pdf:body:p0'), false);
});

void test('builds the PDF page comparison from Detection page rows and leaves out re-check rows', () => {
  const masked = `신청인 주민등록번호 ${RRN}\n연락 메일 ${MAIL}\n`;
  const rows = [
    row('req-pdf#f:0:pdf:body:p0', '가짜 신청서 표지\n', { block_order: 0 }),
    row('req-pdf#f:0:pdf:body:p2', masked, { block_order: 2, decided_by: 'signature', pii_hits: 'KR_RRN:1,EMAIL_ADDRESS:1',
      masked_text: masked.replace(RRN, '[KR_RRN]'),
      findings: JSON.stringify([finding(masked, RRN, 'KR_RRN', 'mask_full', '[KR_RRN]'), finding(masked, MAIL, 'EMAIL_ADDRESS', 'allow')]) }),
    // Gateway 재검사(공백 그대로·공백 뺀 글자) - 같은 파일을 한 번 더 검사한 행이라 칸이 아니다
    row('req-pdf#verify', '가짜 신청서 표지\n신청인 주민등록번호 \n', { decided_by: 'none' }),
    row('req-pdf#nows#verify', '가짜신청서표지신청인주민등록번호', { decided_by: 'none' }),
  ];
  const result = buildFileComparison({ request_id: 'req-pdf' }, rows);
  assert.equal(result.status, 'AVAILABLE');
  assert.equal(result.format, 'pdf');
  assert.equal(result.after_recorded, true);
  assert.equal(result.ordered, true);
  assert.equal('files' in result, false);   // ChatGPT: 파일 번호 없음
  assert.deepEqual(result.segments.map((s) => [s.id, s.para, s.block_order]), [['body:p0', 0, 0], ['body:p2', 2, 2]]);
  const pageTwo = result.segments[1];
  assert.equal(pageTwo.before, masked);   // 칸 비교는 원문 그대로, 가린 값은 위치로만
  assert.deepEqual(pageTwo.spans, [
    { ...(({ start, end }) => ({ start, end }))(span(masked, RRN)), entity_type: 'KR_RRN', replacement: '[KR_RRN]' },   // 바꾼 값: 정책 값 없이 대체 글자만
    { ...(({ start, end }) => ({ start, end }))(span(masked, MAIL)), entity_type: 'EMAIL_ADDRESS', policy_action: 'allow' },
  ]);
  // 모르는 모양의 정책 값은 싣지 않는다
  const odd = buildFileComparison({ request_id: 'req-pdf' }, [row('req-pdf#f:0:pdf:body:p0', RRN, {
    findings: [{ entity_type: 'KR_RRN', start: 0, end: RRN.length, policy_action: 'ALLOW<script>', replacement: null }] })]);
  assert.equal('policy_action' in odd.segments[0].spans[0], false);
});

void test('re-check rows do not count toward the segment limit', () => {
  const pages = Array.from({ length: 3000 }, (_, n) => row(`req-big#f:0:pdf:body:p${n}`, 'x', { block_order: n }));
  const withRechecks = buildFileComparison({ request_id: 'req-big' }, [...pages, row('req-big#verify', 'x'), row('req-big#nows#verify', 'x')]);
  assert.equal(withRechecks.status, 'AVAILABLE');
  assert.equal(withRechecks.segments.length, 3000);
  assert.equal(buildFileComparison({ request_id: 'req-big' }, [...pages, row('req-big#f:0:pdf:body:p3000', 'x')]).status, 'TOO_LARGE');
  assert.equal(buildFileComparison({ request_id: 'req-big' }, [row('req-big#verify', 'x')]).status, 'NOT_RECORDED');
});

void test('groups Claude files by number with their format and name', () => {
  const rows = [
    row('req-c#file:0#f:0:docx:body:p0', '가짜 계약서 첫 문단', { filename: '가짜 계약서.docx', block_order: 0 }),
    row('req-c#file:1#f:0:pdf:body:p0', '가짜 명세 1쪽', { filename: '가짜 명세.pdf', block_order: 0 }),
    row('req-c#file:1#f:0:pdf:body:p1', '가짜 명세 2쪽', { filename: '가짜 명세.pdf', block_order: 1 }),
    row('req-c#file:2#f:0:hwp:body:p0', '가짜 한글 문단', { block_order: 0 }),
    row('req-c#file:1#verify', '가짜 명세 1쪽'),
    row('req-c#file:1#nows#verify', '가짜명세1쪽'),
    row('req-c#file:0', '파일 전체 글자'),                         // 파일 전체 검사 행은 칸이 아니다
    row('req-c#x#f:0:docx:body:p9', '요청 번호 바로 뒤가 아닌 칸'),
    row('req-c#file:12345#f:0:docx:body:p8', '파일 번호가 너무 긴 칸'),
  ];
  const result = buildFileComparison({ request_id: 'req-c' }, rows);
  assert.equal(result.status, 'AVAILABLE');
  assert.equal(result.format, 'docx');   // 첫 칸 형식(칸마다 format이 따로 있다)
  assert.deepEqual(result.segments.map((s) => [s.id, s.file, s.format]),
    [['file0:body:p0', 0, 'docx'], ['file1:body:p0', 1, 'pdf'], ['file1:body:p1', 1, 'pdf'], ['file2:body:p0', 2, 'hwp']]);
  assert.deepEqual(result.files, [
    { file: 0, format: 'docx', filename: '가짜 계약서.docx' },
    { file: 1, format: 'pdf', filename: '가짜 명세.pdf' },
    { file: 2, format: 'hwp' },
  ]);
});

void test('own evidence draws HWP cells as the document structure', () => {
  const cell = `주민등록번호 ${RRN}`;
  const event = { event_id: 'evt-hwp', request_id: 'req-hwp', content_type: 'file', final_action: 'MASK',
    detections: [{ detector: 'SIGNATURE', entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }] };
  const whole = { request_id: 'req-hwp', decided_by: 'signature', content_type: 'file', filename: '가짜 양식.hwp', prompt: `가짜 양식\n${cell}` };
  const evidence = buildOwnEvidence(event, whole, [
    row('req-hwp#f:0:hwp:body:p0', '가짜 양식', { block_order: 0 }),
    row('req-hwp#f:0:hwp:body:t0:r0:c1:p0', cell, { block_order: 1, decided_by: 'signature', masked_text: `주민등록번호 900101-*******`,
      findings: [finding(cell, RRN, 'KR_RRN', 'mask_partial', '900101-*******')] }),
    row('req-hwp#f:0:hwp:side:summary0', '가짜 제목'),
    row('req-hwp#verify', `가짜 양식\n주민등록번호 900101-*******`),
  ]);
  assert.equal(evidence.status, 'AVAILABLE');
  assert.equal(evidence.filename, '가짜 양식.hwp');
  assert.equal(evidence.file_comparison.format, 'hwp');
  assert.deepEqual(evidence.file_comparison.segments.map((s) => s.id), ['body:p0', 'body:t0:r0:c1:p0']);
  assert.equal(evidence.file_comparison.segments[1].spans[0].replacement, '900101-*******');
  assert.equal('policy_action' in evidence.file_comparison.segments[1].spans[0], false);
});

void test('PostgreSQL file segment query leaves out re-check rows and reads the file name', async () => {
  const seen = [];
  const pool = {
    async query(sql, parameters) {
      seen.push({ sql, parameters });
      if (/request_id LIKE \$1/.test(sql)) return { rows: [
        row('req_pdf#f:0:pdf:body:p0', '가짜 1쪽', { filename: '가짜.pdf', block_order: 0 }),
        row('req_pdf#verify', '가짜 1쪽'),   // SQL이 빼더라도 조립 쪽도 한 번 더 거른다
      ] };
      return { rows: [{ request_id: 'req_pdf', decided_by: 'signature', content_type: 'file', filename: '가짜.pdf', prompt: '가짜 1쪽' }] };
    },
  };
  const store = new PostgresEventStore({ pool });
  const event = { event_id: 'evt-pdf', request_id: 'req_pdf', content_type: 'file', final_action: 'MASK',
    detections: [{ detector: 'SIGNATURE', entity_counts: [] }] };
  const evidence = await store.getOwnEvidence(event);
  const segmentQuery = seen.find((call) => /request_id LIKE \$1/.test(call.sql));
  assert.ok(segmentQuery);
  assert.match(segmentQuery.sql, /AND request_id NOT LIKE '%#verify'/);
  assert.match(segmentQuery.sql, /\bfilename\b/);
  assert.equal(segmentQuery.parameters[0], 'req\\_pdf#%');   // LIKE 특수 문자는 그대로 이스케이프
  assert.deepEqual(evidence.file_comparison.segments.map((s) => s.id), ['body:p0']);
  assert.equal(evidence.file_comparison.format, 'pdf');
});
