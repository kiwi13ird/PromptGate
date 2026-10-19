// 관리자 근거: Gateway 마스킹 본문이 없는 질문 마스킹(Claude 새 화면)은 Detection 판정 기록으로 전·후를 보인다 (2026-10-12). 값은 모두 가짜
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { buildMatchEvidence, buildOwnEvidence, redactEvidence } from '../match-evidence.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

const PHONE = '010-9876-5432';
const PROMPT = `고객 연락처 ${PHONE}로 안내해줘`;
const MASKED = '고객 연락처 [KR_PHONE_NUMBER]로 안내해줘';
const start = Array.from(PROMPT.slice(0, PROMPT.indexOf(PHONE))).length;
const end = start + Array.from(PHONE).length;
const FINDINGS = [{ entity_type: 'KR_PHONE_NUMBER', start, end, replacement: '[KR_PHONE_NUMBER]', policy_action: 'mask_full' }];

const event = (over = {}) => ({
  event_id: 'evt-claude', request_id: 'req-claude', occurred_at: '2026-10-12T00:00:00Z', detection_outcome: 'MATCH',
  content_type: 'prompt', final_action: 'MASK', enforcement: { applied: true },
  detections: [{ detector: 'SIGNATURE', entity_counts: [{ entity_type: 'KR_PHONE_NUMBER', count: 1 }] }], ...over,
});
const decision = (over = {}) => ({ request_id: 'req-claude', decided_by: 'signature', prompt: PROMPT, prompt_kept: true,
  masked_text: MASKED, findings: FINDINGS, pii_hits: 'KR_PHONE_NUMBER:1', ...over });
const gateway = { status: 'REQUEST_REWRITTEN', beforePreview: redactEvidence(PROMPT), afterPreview: MASKED,
  beforeChars: Array.from(PROMPT).length, afterChars: Array.from(MASKED).length, previewTruncated: false,
  outboundTextSha256: 'a'.repeat(64), spans: [{ start, end, entityType: 'KR_PHONE_NUMBER' }] };

afterEach(() => { delete process.env.EVIDENCE_SHOW_RAW; });

void test('a prompt mask without a Gateway body shows the recorded original and masked text', () => {
  const evidence = buildMatchEvidence(event(), [decision()]);
  assert.equal(evidence.status, 'AVAILABLE');
  assert.equal(evidence.mask_comparison.status, 'NOT_RECORDED');   // Gateway 본문은 여전히 없음
  const comparison = evidence.prompt_comparison;
  assert.equal(comparison.status, 'AVAILABLE');
  assert.equal(comparison.after_recorded, true);
  const [segment] = comparison.segments;
  // 운영 기본(EVIDENCE_SHOW_RAW 없음)에서도 원문 그대로 - 가림(█)이 아니라 하이라이트 위치로 표시
  assert.equal(evidence.redaction, 'APPLIED');
  assert.equal(segment.before, PROMPT);
  assert.equal(segment.before.includes('█'), false);
  assert.equal(segment.after, MASKED);
  assert.deepEqual(segment.spans, [{ start, end, entity_type: 'KR_PHONE_NUMBER', replacement: '[KR_PHONE_NUMBER]' }]);
  assert.equal(Array.from(segment.before).slice(segment.spans[0].start, segment.spans[0].end).join(''), PHONE);
  assert.equal(segment.decided_by, 'signature');
});

void test('it is the same comparison the own-request page builds', () => {
  const admin = buildMatchEvidence(event(), [decision()]).prompt_comparison;
  const own = buildOwnEvidence(event(), decision(), null).prompt_comparison;
  assert.deepEqual(admin, own);
  // 같은 결과: EVIDENCE_SHOW_RAW와 무관, 적중 위치가 JSON 문자열로 와도 같다
  process.env.EVIDENCE_SHOW_RAW = '1';
  assert.deepEqual(buildMatchEvidence(event(), [decision({ findings: JSON.stringify(FINDINGS) })]).prompt_comparison, own);
});

void test('a Gateway masked body keeps the current behaviour and adds no second comparison', () => {
  const evidence = buildMatchEvidence(event(), [decision()], [], undefined, gateway);
  assert.equal(evidence.mask_comparison.status, 'REQUEST_REWRITTEN');
  // 2026-10-17: Gateway 본문이 있는 질문도 같은 입력이면 원문(가린 값은 spans 위치 하이라이트), 가림(█)이 아님
  assert.equal(evidence.mask_comparison.before_preview, PROMPT);
  assert.equal(evidence.mask_comparison.before_raw, true);
  assert.equal(evidence.mask_comparison.after_preview, MASKED);
  assert.equal('prompt_comparison' in evidence, false);
});

void test('no recorded masked text, a block, a file or a document match leave the response as before', () => {
  const nothing = (value) => assert.equal('prompt_comparison' in value, false);
  // 옛 기록: 대체본(masked_text)이 없으면 지금처럼 '기록 없음'
  const old = buildMatchEvidence(event(), [decision({ masked_text: null, findings: null })]);
  assert.equal(old.mask_comparison.status, 'NOT_RECORDED');
  nothing(old);
  // 원문이 너무 길어 조회되지 않은 기록
  nothing(buildMatchEvidence(event(), [decision({ prompt: null })]));
  // 차단·허용: 보낸 것이 없거나 바꾼 것이 없다
  nothing(buildMatchEvidence(event({ final_action: 'BLOCK' }), [decision()]));
  nothing(buildMatchEvidence(event({ final_action: 'ALLOW' }), [decision()]));
  // 파일: 칸 기록으로만 그린다
  const file = buildMatchEvidence(event({ content_type: 'file' }), [decision()], [], undefined, undefined, []);
  nothing(file);
  assert.equal(file.file_comparison.status, 'NOT_RECORDED');
  // 보호 문서 일치: 마스킹 비교 없음
  const hash = buildMatchEvidence(event({ final_action: 'BLOCK', detections: [{ detector: 'WINDOW_HASH', matched_document_id: 'doc-1', score: 0.9,
    input_location: { char_start: 0, char_end: 5 }, matched_location: { char_start: 0, char_end: 5 } }] }),
  [decision({ decided_by: 'windowhash', doc_id: 'doc-1', input_span: '0-5', doc_span: '0-5' })], [{ doc_id: 'doc-1', filename: '가짜.docx', normalized_text: PROMPT }]);
  nothing(hash);
  assert.equal('mask_comparison' in hash, false);
});

void test('a broken findings record drops only the comparison, not the whole evidence', () => {
  const evidence = buildMatchEvidence(event(), [decision({ findings: '{깨진 기록' })]);
  assert.equal(evidence.status, 'AVAILABLE');
  assert.equal(evidence.mask_comparison.status, 'NOT_RECORDED');
  assert.equal('prompt_comparison' in evidence, false);
  // 범위를 벗어난 위치는 걸러지고, 전·후 글은 그대로 나온다
  const outside = buildMatchEvidence(event(), [decision({ findings: [{ entity_type: 'KR_PHONE_NUMBER', start: 3, end: 999 }] })]);
  assert.deepEqual(outside.prompt_comparison.segments[0].spans, []);
});

void test('the admin evidence query reads the recorded findings and masked text', async () => {
  const seen = [];
  const pool = {
    async query(sql, parameters) {
      seen.push({ sql, parameters });
      if (/FROM decisions WHERE request_id = \$1/.test(sql)) return { rows: [decision()] };
      if (/FROM dashboard_security_events/.test(sql)) return { rows: [{ gateway_evidence: null }] };
      return { rows: [] };
    },
  };
  const evidence = await new PostgresEventStore({ pool }).getEvidence(event());
  const query = seen.find((call) => /FROM decisions WHERE request_id = \$1/.test(call.sql));
  assert.ok(query);
  assert.match(query.sql, /\bfindings\b/);
  assert.match(query.sql, /length\(masked_text\) <= \$2 THEN masked_text ELSE NULL END AS masked_text/);
  assert.equal(evidence.prompt_comparison.segments[0].after, MASKED);
  assert.equal(evidence.prompt_comparison.segments[0].before, PROMPT);
});
