// 원문 보기(개인정보 가림 끄기) - EVIDENCE_SHOW_RAW=1일 때만 가림을 끄고, 기본은 지금처럼 가린다.
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { buildMatchEvidence, redactEvidence } from '../match-evidence.mjs';

const DOC_TEXT = '파트너 협상 담당자 김민수 과장의 직통 연락처는 010-1234-5678이며 회신은 반드시 이 번호로 받는다. TBS 협상목표안은 수수료 22%와 최소보장 JPY 90,000,000이다. 일정은 10월 계약.';
const PROMPT = '요약해줘: 파트너 협상 담당자 김민수 과장의 직통 연락처는 010-1234-5678이며 회신은 반드시 이 번호로 받는다. TBS 협상목표안은 수수료 22%와 최소보장 JPY 90,000,000이다.';
const start = PROMPT.indexOf('파트너');
const end = Array.from(PROMPT).length;
const docEnd = Array.from(DOC_TEXT).indexOf('일') - 1;

const hashEvent = {
  event_id: 'evt-hash', request_id: 'req-hash', occurred_at: '2026-10-07T00:00:00Z', detection_outcome: 'MATCH', final_action: 'BLOCK',
  detections: [{ detector: 'WINDOW_HASH', matched_document_id: 'doc-13', score: 0.9,
    input_location: { char_start: start, char_end: end }, matched_location: { char_start: 0, char_end: docEnd } }],
};
const hashDecision = {
  request_id: 'req-hash', decided_by: 'windowhash', doc_id: 'doc-13', input_span: `${start}-${end}`, doc_span: `0-${docEnd}`,
  prompt: PROMPT, prompt_kept: true, prompt_chars: end, reason: '연락처 010-1234-5678 포함 구간 일치 (확인된 창 구간 덮임 100.0%)',
};
const documents = [{ doc_id: 'doc-13', filename: '13_파트너사협상자료.docx', normalized_text: DOC_TEXT, normalized_chars: Array.from(DOC_TEXT).length }];

const MASK_PROMPT = '고객 연락처 010-9876-5432로 안내해줘';
const maskEvent = {
  event_id: 'evt-mask', request_id: 'req-mask', occurred_at: '2026-10-07T00:00:00Z', detection_outcome: 'MATCH', final_action: 'MASK',
  enforcement: { applied: true },
  detections: [{ detector: 'SIGNATURE', entity_counts: [{ entity_type: 'KR_PHONE_NUMBER', count: 1 }] }],
};
const maskDecision = { request_id: 'req-mask', decided_by: 'signature', prompt: MASK_PROMPT, prompt_kept: true, pii_hits: 'KR_PHONE_NUMBER:1' };
const gatewayEvidence = { status: 'REQUEST_REWRITTEN', beforePreview: redactEvidence(MASK_PROMPT), afterPreview: '고객 연락처 [KR_PHONE_NUMBER]로 안내해줘',
  beforeChars: Array.from(MASK_PROMPT).length, afterChars: 26, previewTruncated: false, outboundTextSha256: 'a'.repeat(64),
  spans: [{ start: 7, end: 20, entityType: 'KR_PHONE_NUMBER' }] };

afterEach(() => { delete process.env.EVIDENCE_SHOW_RAW; });

const pageText = (evidence) => evidence.page.segments.map((s) => s.text).join('');

void test('default keeps redaction in every displayed text', () => {
  const evidence = buildMatchEvidence(hashEvent, [hashDecision], documents, { side: 'input', offset: 0, documentId: 'doc-13' });
  assert.equal(evidence.redaction, 'APPLIED');
  assert.equal(evidence.comparisons[0].status, 'AVAILABLE');
  assert.ok(!pageText(evidence).includes('010-1234-5678'));
  assert.ok(pageText(evidence).includes('█'));
  assert.ok(!evidence.metadata.detection_reason.includes('010-1234-5678'));
  assert.ok(evidence.comparisons[0].matching_passages.every((p) => !p.input_text.includes('010-1234-5678')));
  // 2026-10-17: 질문 마스킹 전·후의 '전'은 같은 입력일 때 EVIDENCE_SHOW_RAW 없이도 원문(가린 값은 위치 하이라이트)
  const masked = buildMatchEvidence(maskEvent, [maskDecision], [], undefined, gatewayEvidence);
  assert.equal(masked.mask_comparison.before_preview, MASK_PROMPT);
  assert.equal(masked.mask_comparison.before_raw, true);
});

void test('EVIDENCE_SHOW_RAW=1 shows the original input, document and reason', () => {
  process.env.EVIDENCE_SHOW_RAW = '1';
  const input = buildMatchEvidence(hashEvent, [hashDecision], documents, { side: 'input', offset: 0, documentId: 'doc-13' });
  assert.equal(input.redaction, 'OFF');
  assert.equal(pageText(input), PROMPT);
  assert.ok(input.page.segments.every((s) => s.redacted === false));
  assert.ok(input.metadata.detection_reason.includes('010-1234-5678'));
  assert.ok(input.comparisons[0].matching_passages.some((p) => p.input_text.includes('010-1234-5678')));
  const doc = buildMatchEvidence(hashEvent, [hashDecision], documents, { side: 'document', offset: 0, documentId: 'doc-13' });
  assert.equal(pageText(doc), DOC_TEXT);
});

void test('raw mask before-text is restored only when the stored preview comes from the same input', () => {
  for (const flag of [undefined, '1']) {
    if (flag) process.env.EVIDENCE_SHOW_RAW = flag; else delete process.env.EVIDENCE_SHOW_RAW;
    checkSameInputOnly();
  }
});

function checkSameInputOnly() {
  const same = buildMatchEvidence(maskEvent, [maskDecision], [], undefined, gatewayEvidence);
  assert.equal(same.mask_comparison.before_preview, MASK_PROMPT);
  assert.equal(same.mask_comparison.after_preview, gatewayEvidence.afterPreview);
  const other = buildMatchEvidence(maskEvent, [{ ...maskDecision, prompt: '고객 연락처 010-1111-2222로 안내해줘!' }], [], undefined,
    { ...gatewayEvidence, beforePreview: redactEvidence('다른 입력 010-3333-4444') });
  assert.equal(other.mask_comparison.before_preview, redactEvidence('다른 입력 010-3333-4444'));
  assert.equal(other.mask_comparison.before_raw, false);   // 같은 입력이 아니면 가린 채 그대로 + 원문 표시 아님
  assert.equal(same.mask_comparison.before_raw, true);
  // Gateway가 탐지 구간(여기서는 숫자 일부)까지 가린 미리보기도, 가리지 않은 자리가 모두 같으면 원문으로 되돌린다
  const wider = buildMatchEvidence(maskEvent, [maskDecision], [], undefined,
    { ...gatewayEvidence, beforePreview: MASK_PROMPT.replace(/[0-9-]+/, (m) => '█'.repeat(m.length)).replace('안내', '██') });
  assert.equal(wider.mask_comparison.before_preview, MASK_PROMPT);
  assert.equal(wider.mask_comparison.before_raw, true);
  // 가리지 않은 자리가 하나라도 다르면 되돌리지 않는다
  const differs = buildMatchEvidence(maskEvent, [maskDecision], [], undefined,
    { ...gatewayEvidence, beforePreview: MASK_PROMPT.replace(/[0-9-]+/, (m) => '█'.repeat(m.length)).replace('안내', '안녕') });
  assert.equal(differs.mask_comparison.before_raw, false);
  // 판정 기록의 원문이 없거나 길면(prompt 없음) 되돌리지 않는다
  const none = buildMatchEvidence(maskEvent, [{ ...maskDecision, prompt: null }], [], undefined, gatewayEvidence);
  assert.equal(none.mask_comparison.before_preview, redactEvidence(MASK_PROMPT));
  assert.equal(none.mask_comparison.before_raw, false);
}
