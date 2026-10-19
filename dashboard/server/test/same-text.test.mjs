// '일치 비율' 하나로 통일(2026-10-16): 문서 구간 일치 탐지의 same_text = 입력 중 보호 문서와 같은 글자 비율.
// 화면 근거와 같은 본문(가림 적용 + 가림 구간)·같은 계산 원본(match-ratio.mjs)인지, 목록은 기다리지 않고 상세는 그 자리에서 계산하는지 본다.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildMatchEvidence, comparisonBodies, documentPage, maskedBody } from '../match-evidence.mjs';
import { computeMatchRatio, formatSameRatio, ratioOf } from '../match-ratio.mjs';
import { createSameTextService } from '../same-text.mjs';

const DOC_TEXT = ['머리말은 입력에 없다.', '파트너 협상 담당자 김민수 과장의 직통 연락처는 010-1234-5678이며 회신은 반드시 이 번호로 받는다.',
  'TBS 협상목표안은 수수료 22%와 최소보장 JPY 90,000,000이다.', '일정은 10월 계약.'].join('\n');
const PROMPT = ['요약해줘:', '파트너 협상 담당자 김민수 과장의 직통 연락처는 010-1234-5678이며 회신은 반드시 이 번호로 받는다.',
  'TBS 협상목표안은 수수료 25%와 최소보장 JPY 90,000,000이다.'].join('\n');
const length = (text) => Array.from(text).length;
const docStart = Array.from(DOC_TEXT).indexOf('파');
const event = (id = 'evt-hash', extra = {}) => ({
  event_id: id, request_id: `req-${id}`, occurred_at: '2026-10-16T00:00:00Z', detection_outcome: 'MATCH', final_action: 'BLOCK',
  detections: [{ detector: 'WINDOW_HASH', matched_document_id: 'doc-13', score: 0.748,
    input_location: { char_start: 10, char_end: length(PROMPT) }, matched_location: { char_start: docStart, char_end: length(DOC_TEXT) } }],
  ...extra,
});
const decision = (id = 'evt-hash') => ({ request_id: `req-${id}`, decided_by: 'windowhash', doc_id: 'doc-13', input_span: `10-${length(PROMPT)}`,
  doc_span: `${docStart}-${length(DOC_TEXT)}`, prompt: PROMPT, prompt_kept: true, prompt_chars: length(PROMPT), reason: '구간 일치 (확인된 창 구간 덮임 74.8%)' });
const documents = [{ doc_id: 'doc-13', filename: '13_파트너사협상자료.docx', version: 1, normalized_text: DOC_TEXT, normalized_chars: length(DOC_TEXT) }];

test('본문은 화면 근거 쪽 응답(documentPage)과 같은 가림 글·가림 구간', () => {
  const body = maskedBody(PROMPT);
  const page = documentPage(PROMPT, undefined, { side: 'input', offset: 0 }, 'RETAINED_INPUT');
  assert.equal(body.text, page.segments.map((segment) => segment.text).join(''));
  let at = 0;
  const runs = [];
  for (const segment of page.segments) { const size = length(segment.text); if (segment.redacted) runs.push({ start: at, end: at + size }); at += size; }
  assert.deepEqual(body.runs, runs);
  assert.ok(body.text.includes('█'), '전화번호는 가림');
});

test('비교 본문 → 같은 글자 비율(서버 확인 문장과 맞음): 질문 줄과 바뀐 숫자만 다름', () => {
  const [body] = comparisonBodies(event(), [decision()], documents);
  assert.equal(body.document_id, 'doc-13');
  const result = computeMatchRatio(body.input, body.document, body.comparison);
  assert.equal(result.state, 'READY');
  assert.equal(result.differences, 2);
  assert.ok(result.ratio > 0.9 && result.ratio < 1);
  assert.equal(formatSameRatio(ratioOf(result.diff.aChars - result.diff.aChangedChars, result.diff.aChars)), formatSameRatio(result.ratio));
  // 근거 응답의 비교와 같은 것(일치 문장 예시 포함)을 쓴다
  assert.deepEqual(body.comparison, buildMatchEvidence(event(), [decision()], documents).comparisons[0]);
});

test('본문이 없거나 기록이 둘이면 비교 본문 없음', () => {
  assert.deepEqual(comparisonBodies(event(), [{ ...decision(), prompt: undefined }], documents), []);
  assert.deepEqual(comparisonBodies(event(), [decision(), decision()], documents), []);
});

function fakeStore() {
  const calls = { bodies: 0, versions: 0 };
  let version = '1';
  return {
    calls,
    setVersion(value) { version = value; },
    async documentVersions(ids) { calls.versions += 1; return new Map(ids.map((id) => [id, version])); },
    async getComparisonBodies(item) { calls.bodies += 1; return comparisonBodies(item, [decision(item.event_id)], documents); },
  };
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

test('목록은 기다리지 않고(계산 중) 뒤에서 계산해 다음 조회에 싣는다 · 판이 바뀌면 다시 계산', async () => {
  const store = fakeStore();
  const service = createSameTextService(store);
  const plain = { event_id: 'evt-sig', request_id: 'req-sig', detections: [{ detector: 'SIGNATURE' }] };
  const first = await service.annotate([event('a'), plain]);
  assert.deepEqual(first[0].detections[0].same_text, { state: 'PENDING' });
  assert.equal(first[1], plain, '문서 구간 일치가 아닌 이벤트는 그대로');
  await settle();
  const second = await service.annotate([event('a')]);
  const ready = second[0].detections[0].same_text;
  assert.equal(ready.state, 'READY');
  assert.equal(ready.differences, 2);
  assert.ok(ready.same_chars < ready.input_chars);
  assert.equal(second[0].detections[0].score, 0.748, 'Detection 해시 근거 비율(score)은 그대로');
  assert.equal(store.calls.bodies, 1);
  store.setVersion('2');
  assert.equal((await service.annotate([event('a')]))[0].detections[0].same_text.state, 'PENDING');
  await settle();
  assert.equal(store.calls.bodies, 2);
});

test('상세(한 건)는 그 자리에서 계산하고, 목록 묶음의 첨부 파일 이벤트에도 싣는다', async () => {
  const service = createSameTextService(fakeStore());
  const [detail] = await service.annotate([event('b')], { wait: true });
  assert.equal(detail.detections[0].same_text.state, 'READY');
  const grouped = { event_id: 'evt-q', request_id: 'req-q', detections: [], attached_files: [event('c')] };
  const [listed] = await service.annotate([grouped], { wait: true });
  assert.equal(listed.attached_files[0].detections[0].same_text.state, 'READY');
});

test('대조할 본문이 없으면 UNAVAILABLE, 본문 조회를 못 하는 저장소면 응답을 바꾸지 않는다', async () => {
  const empty = { ...fakeStore(), async getComparisonBodies() { return []; } };
  const [none] = await createSameTextService(empty).annotate([event('d')], { wait: true });
  assert.deepEqual(none.detections[0].same_text, { state: 'UNAVAILABLE', reason: '대조할 본문 없음' });
  const original = event('e');
  const [same] = await createSameTextService({}).annotate([original]);
  assert.equal(same, original);
});
