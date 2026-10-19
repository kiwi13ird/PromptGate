import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  canonicalEventToDto,
  validateCanonicalEvent,
  ValidationError,
} from '../validation.mjs';

const projectRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
);

function eventWithDetection(detection) {
  return {
    type: 'SECURITY_EVENT',
    eventId: `evt-${detection.detector.toLowerCase()}`,
    timestamp: '2026-09-20T17:10:00+09:00',
    clientId: 'client-local-test',
    targetLlm: 'ChatGPT',
    detectionOutcome: 'MATCH',
    finalAction: 'BLOCK',
    detections: [detection],
  };
}

const detectorCases = [
  {
    detector: 'SHA256',
    matchType: 'EXACT_DOCUMENT',
    outboundDocumentName: 'local-test.pdf',
    matchedDocumentId: 'DOC-LOCAL-001',
    action: 'BLOCK',
  },
  {
    detector: 'WINDOW_HASH',
    matchType: 'TEXT_FRAGMENT',
    score: 0.82,
    scoreKind: 'COVERAGE',
    matchedDocumentId: 'DOC-LOCAL-001',
    documentSpan: { charStart: 10, charEnd: 40 },
    action: 'BLOCK',
  },
  {
    detector: 'MINHASH',
    matchType: 'SIMILAR_DOCUMENT',
    similarity: 0.97,
    threshold: 0.8,
    outboundDocumentName: 'local-test-v2.pdf',
    matchedDocumentId: 'DOC-LOCAL-001',
    action: 'BLOCK',
  },
  {
    detector: 'SIGNATURE',
    matchType: 'SIGNATURE_RULE',
    category: 'LOCAL_TEST_RULE',
    ruleId: 'SIG-LOCAL-001',
    confidence: 0.91,
    action: 'BLOCK',
  },
];

for (const detection of detectorCases) {
  void test(`${detection.detector} accepts only its canonical match and score shape`, () => {
    const canonical = validateCanonicalEvent(eventWithDetection(detection));
    const dto = canonicalEventToDto(canonical);
    assert.equal(dto.detections[0].detector, detection.detector);
    assert.equal(dto.detections[0].match_type, detection.matchType);
  });
}

void test('mismatched detector score semantics are rejected', () => {
  assert.throws(
    () =>
      validateCanonicalEvent(
        eventWithDetection({
          detector: 'MINHASH',
          matchType: 'SIMILAR_DOCUMENT',
          score: 0.97,
          scoreKind: 'COVERAGE',
          outboundDocumentName: 'local-test-v2.pdf',
          matchedDocumentId: 'DOC-LOCAL-001',
          action: 'BLOCK',
        }),
      ),
    (error) =>
      error instanceof ValidationError &&
      error.path === 'body.detections[0].score',
  );
});

void test('SIGNATURE accepts metadata-only entity counts from the live detector', () => {
  const canonical = validateCanonicalEvent(
    eventWithDetection({
      detector: 'SIGNATURE',
      matchType: 'SIGNATURE_RULE',
      entityCounts: [
        { entityType: 'KR_PHONE_NUMBER', count: 1 },
        { entityType: 'EMAIL_ADDRESS', count: 2 },
      ],
      action: 'BLOCK',
    }),
  );
  const dto = canonicalEventToDto(canonical);
  assert.deepEqual(dto.detections[0].entity_counts, [
    { entity_type: 'KR_PHONE_NUMBER', count: 1 },
    { entity_type: 'EMAIL_ADDRESS', count: 2 },
  ]);
  assert.equal(dto.detections[0].category, undefined);
  assert.equal(dto.detections[0].rule_id, undefined);
});

void test('SHA256 cannot be represented as a text fragment', () => {
  assert.throws(
    () =>
      validateCanonicalEvent(
        eventWithDetection({
          detector: 'SHA256',
          matchType: 'TEXT_FRAGMENT',
          outboundDocumentName: 'local-test.pdf',
          matchedDocumentId: 'DOC-LOCAL-001',
          action: 'BLOCK',
        }),
      ),
    (error) =>
      error instanceof ValidationError &&
      error.path === 'body.detections[0].matchType',
  );
});

const invalidDetectorCases = [
  {
    name: 'SHA256 does not allow ALLOW',
    detection: {
      detector: 'SHA256',
      matchType: 'EXACT_DOCUMENT',
      outboundDocumentName: 'local-test.pdf',
      matchedDocumentId: 'DOC-LOCAL-001',
      action: 'ALLOW',
    },
    path: 'body.detections[0].action',
  },
  {
    name: 'WINDOW_HASH rejects score greater than one',
    detection: {
      detector: 'WINDOW_HASH',
      matchType: 'TEXT_FRAGMENT',
      score: 1.01,
      scoreKind: 'COVERAGE',
      matchedDocumentId: 'DOC-LOCAL-001',
      documentSpan: { charStart: 10, charEnd: 40 },
      action: 'BLOCK',
    },
    path: 'body.detections[0].score',
  },
  {
    name: 'WINDOW_HASH rejects an inverted character span',
    detection: {
      detector: 'WINDOW_HASH',
      matchType: 'TEXT_FRAGMENT',
      score: 0.8,
      scoreKind: 'COVERAGE',
      matchedDocumentId: 'DOC-LOCAL-001',
      documentSpan: { charStart: 40, charEnd: 10 },
      action: 'BLOCK',
    },
    path: 'body.detections[0].documentSpan.charEnd',
  },
  {
    name: 'MINHASH rejects similarity below threshold',
    detection: {
      detector: 'MINHASH',
      matchType: 'SIMILAR_DOCUMENT',
      similarity: 0.79,
      threshold: 0.8,
      outboundDocumentName: 'local-test-v2.pdf',
      matchedDocumentId: 'DOC-LOCAL-001',
      action: 'BLOCK',
    },
    path: 'body.detections[0].similarity',
  },
  {
    name: 'SIGNATURE rejects a document similarity match type',
    detection: {
      detector: 'SIGNATURE',
      matchType: 'SIMILAR_DOCUMENT',
      category: 'LOCAL_TEST_RULE',
      ruleId: 'SIG-LOCAL-001',
      action: 'BLOCK',
    },
    path: 'body.detections[0].matchType',
  },
];

for (const invalidCase of invalidDetectorCases) {
  void test(invalidCase.name, () => {
    assert.throws(
      () => validateCanonicalEvent(eventWithDetection(invalidCase.detection)),
      (error) =>
        error instanceof ValidationError && error.path === invalidCase.path,
    );
  });
}

void test('MATCH requires a detection while NO_MATCH may preserve an empty ALLOW result', () => {
  const base = {
    type: 'SECURITY_EVENT',
    eventId: 'evt-outcome-test',
    timestamp: '2026-09-20T17:10:00+09:00',
    clientId: 'client-local-test',
    targetLlm: 'ChatGPT',
    finalAction: 'ALLOW',
    detections: [],
  };
  assert.throws(
    () => validateCanonicalEvent({ ...base, detectionOutcome: 'MATCH' }),
    (error) =>
      error instanceof ValidationError && error.path === 'body.detections',
  );
  const noMatch = canonicalEventToDto(
    validateCanonicalEvent({ ...base, detectionOutcome: 'NO_MATCH' }),
  );
  assert.equal(noMatch.detection_outcome, 'NO_MATCH');
  assert.equal(noMatch.final_action, 'ALLOW');
  assert.deepEqual(noMatch.detections, []);
});

void test('UNAVAILABLE keeps fail-open/fail-closed metadata and rejects it without degraded=true', () => {
  const base = {
    type: 'SECURITY_EVENT',
    eventId: 'evt-unavailable-test',
    timestamp: '2026-09-20T17:10:00Z',
    clientId: 'client-local-test',
    targetLlm: 'Claude',
    detectionOutcome: 'UNAVAILABLE',
    finalAction: 'ALLOW',
    detections: [],
    degradedReason: 'TIMEOUT',
    failurePolicy: 'FAIL_OPEN',
  };
  assert.throws(
    () => validateCanonicalEvent({ ...base, degraded: false }),
    (error) =>
      error instanceof ValidationError && error.path === 'body.degradedReason',
  );
  const unavailable = canonicalEventToDto(
    validateCanonicalEvent({ ...base, degraded: true }),
  );
  assert.equal(unavailable.detection_outcome, 'UNAVAILABLE');
  assert.equal(unavailable.failure_policy, 'FAIL_OPEN');
  assert.equal(unavailable.degraded_reason, 'TIMEOUT');
});

void test('recommended action, Gateway final action and HTTP enforcement remain distinct', () => {
  const event = eventWithDetection({
    detector: 'SIGNATURE',
    matchType: 'SIGNATURE_RULE',
    category: 'LOCAL_TEST_RULE',
    ruleId: 'SIG-LOCAL-001',
    action: 'BLOCK',
    recommendedAction: 'BLOCK',
  });
  event.recommendedAction = 'BLOCK';
  event.finalAction = 'ALLOW';
  event.enforcement = { applied: true, httpStatus: 200 };
  const dto = canonicalEventToDto(validateCanonicalEvent(event));
  assert.equal(dto.recommended_action, 'BLOCK');
  assert.equal(dto.final_action, 'ALLOW');
  assert.deepEqual(dto.enforcement, { applied: true, http_status: 200 });
});

void test('timestamps require a timezone and accept both Z and explicit offsets', () => {
  const detection = detectorCases[1];
  assert.doesNotThrow(() =>
    validateCanonicalEvent({
      ...eventWithDetection(detection),
      timestamp: '2026-09-20T10:00:00Z',
    }),
  );
  assert.doesNotThrow(() =>
    validateCanonicalEvent({
      ...eventWithDetection(detection),
      timestamp: '2026-09-20T19:00:00+09:00',
    }),
  );
  assert.throws(
    () =>
      validateCanonicalEvent({
        ...eventWithDetection(detection),
        timestamp: '2026-09-20T19:00:00',
      }),
    (error) =>
      error instanceof ValidationError && error.path === 'body.timestamp',
  );
});

for (const fixtureName of [
  'window-hash-block.json',
  'no-match-allow.json',
  'detection-unavailable-fail-open.json',
  'detection-unavailable-fail-closed.json',
]) {
  void test(`${fixtureName} remains a valid canonical local contract fixture`, async () => {
    const fixture = JSON.parse(
      await readFile(
        path.join(projectRoot, 'fixtures', 'events', fixtureName),
        'utf8',
      ),
    );
    assert.doesNotThrow(() => validateCanonicalEvent(fixture));
  });
}

// 2026-10-10 Gateway 처리 설정 묶음이 보내는 이벤트(명세 §4.7 7모양) - 스키마 변경 없이 받아야 한다
void test('uninspectable, too-large and delayed file events are accepted unchanged', () => {
  const base = {
    type: 'SECURITY_EVENT',
    requestId: 'req-local-bundle',
    timestamp: '2026-10-10T14:12:00+09:00',
    clientId: 'client-local-test',
    targetLlm: 'ChatGPT',
    contentType: 'file',
    detectionOutcome: 'UNAVAILABLE',
    detections: [],
  };
  const shapes = [
    { finalAction: 'BLOCK', degraded: false, reasonCode: 'file_uninspectable_image', enforcement: { applied: true, httpStatus: 403 }, fileId: 'file-local-1' },
    { finalAction: 'ALLOW', degraded: false, reasonCode: 'file_uninspectable_scanned_pdf' },
    { finalAction: 'BLOCK', degraded: false, reasonCode: 'file_too_large', enforcement: { applied: true, httpStatus: 403 } },
    { finalAction: 'ALLOW', degraded: false, reasonCode: 'file_too_large' },
    { finalAction: 'BLOCK', degraded: true, degradedReason: 'TIMEOUT', failurePolicy: 'FAIL_CLOSED', reasonCode: 'detection_timeout', enforcement: { applied: true, httpStatus: 503 } },
    { finalAction: 'ALLOW', degraded: true, degradedReason: 'UNREACHABLE', failurePolicy: 'FAIL_OPEN', reasonCode: 'detection_unreachable' },
    { finalAction: 'MASK', degraded: true, degradedReason: 'TIMEOUT', failurePolicy: 'FAIL_OPEN', reasonCode: 'detection_timeout', enforcement: { applied: true } },
  ];
  shapes.forEach((shape, index) => {
    const event = validateCanonicalEvent({ ...base, eventId: `evt-local-bundle-${index}`, ...shape });
    const dto = canonicalEventToDto(event);
    assert.equal(dto.final_action, shape.finalAction);
    assert.equal(dto.detection_outcome, 'UNAVAILABLE');
    assert.equal(dto.reason_code, shape.reasonCode);
    assert.equal(dto.degraded, shape.degraded);
    assert.deepEqual(dto.detections, []);
  });
  for (const reasonCode of ['file_uninspectable_other', 'mask_application_failed', 'file_masking_failed', 'x'.repeat(100)])
    assert.doesNotThrow(() => validateCanonicalEvent({ ...base, eventId: 'evt-local-bundle-code', finalAction: 'BLOCK', reasonCode }));
  assert.throws(
    () => validateCanonicalEvent({ ...base, eventId: 'evt-local-bundle-long', finalAction: 'BLOCK', reasonCode: 'x'.repeat(101) }),
    (error) => error instanceof ValidationError && error.path === 'body.reasonCode',
  );
  // 확장 프로그램 전용 칸(notify)은 대시보드 사본에 실리면 안 된다
  assert.throws(
    () => validateCanonicalEvent({ ...base, eventId: 'evt-local-bundle-notify', finalAction: 'ALLOW', reasonCode: 'file_too_large', notify: true }),
    (error) => error instanceof ValidationError && error.path === 'body.notify',
  );
});
