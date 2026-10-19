import { describe, expect, it } from 'vitest';
import type { SecurityEvent } from '@/src/types/event';
import type { ConfidentialDocument } from '@/src/types/policy';
import { actionReasons, protectionCoverage, representativeReason, settingSummary, uninspectedKind, uninspectedRequests } from './overviewMetrics';

// 재설계 3b(설계 5.1.1 권고 ①②③): 서버 변경 없이 기존 응답으로 계산하는 지표
const base: SecurityEvent = { eventId: 'e', occurredAt: '2026-10-13T00:00:00Z', clientId: 'c', targetLlm: 'ChatGPT', detectionOutcome: 'MATCH', finalAction: 'BLOCK', status: 'NEW', detections: [], adminNotes: [], timeline: [] };
const ev = (extra: Partial<SecurityEvent>): SecurityEvent => ({ ...base, ...extra });
const sig = (...types: string[]) => [{ detector: 'SIGNATURE' as const, matchType: 'SIGNATURE_RULE' as const, scoreKind: 'CONFIDENCE' as const, entityCounts: types.map((entityType) => ({ entityType, count: 1 })) }];
const doc = { detector: 'WINDOW_HASH' as const, matchType: 'TEXT_FRAGMENT' as const, score: 1, scoreKind: 'COVERAGE' as const, matchedDocumentId: 'd1', documentSpan: { charStart: 0, charEnd: 1, endExclusive: true as const } };

describe('① 차단·마스킹 사유(이벤트마다 대표 사유 1개)', () => {
  it('follows the design order: access → no response → uninspectable → mask failed → document → keyword → credential → pii', () => {
    expect(representativeReason(ev({ reasonCode: 'client_blocked', degraded: true }))).toBe('access');
    expect(representativeReason(ev({ degraded: true, detections: [doc] }))).toBe('no-response');
    expect(representativeReason(ev({ reasonCode: 'detection_timeout' }))).toBe('no-response');
    expect(representativeReason(ev({ reasonCode: 'file_too_large', detectionOutcome: 'UNAVAILABLE' }))).toBe('uninspectable');
    expect(representativeReason(ev({ reasonCode: 'mask_application_failed', detections: [doc] }))).toBe('mask-failed');
    expect(representativeReason(ev({ detections: [doc, ...sig('DOC_KEYWORD')] }))).toBe('document');
    expect(representativeReason(ev({ detections: sig('KR_PHONE_NUMBER', 'DOC_KEYWORD') }))).toBe('keyword');
    expect(representativeReason(ev({ detections: sig('KR_RRN', 'GITHUB_TOKEN') }))).toBe('credential');
    expect(representativeReason(ev({ detections: sig('EMAIL') }))).toBe('pii');
    expect(representativeReason(ev({}))).toBe('other');
  });
  it('counts block and mask separately, skips allow, sorts by total', () => {
    const rows = actionReasons([
      ev({ detections: sig('EMAIL') }), ev({ finalAction: 'MASK', detections: sig('EMAIL') }), ev({ finalAction: 'MASK', detections: sig('EMAIL') }),
      ev({ detections: [doc] }), ev({ finalAction: 'ALLOW', detections: [doc] }), ev({ reasonCode: 'client_id_missing' }),
    ]);
    expect(rows.map((row) => [row.label, row.block, row.mask, row.to])).toEqual([
      ['개인정보', 1, 2, '/policies'], ['접속 차단', 1, 0, '/policies/access'], ['보호 문서 일치', 1, 0, '/documents'],
    ]);
  });
});

describe('② 검사 없이 처리된 요청', () => {
  it('excludes access blocks and splits allow from block by reason', () => {
    expect(uninspectedKind(ev({ reasonCode: 'client_blocked', detectionOutcome: 'UNAVAILABLE' }))).toBeUndefined();
    expect(uninspectedKind(ev({ detectionOutcome: 'NO_MATCH' }))).toBeUndefined();
    const result = uninspectedRequests([
      ev({ degraded: true, finalAction: 'ALLOW' }), ev({ detectionOutcome: 'UNAVAILABLE', finalAction: 'ALLOW' }), ev({ degraded: true }),
      ev({ reasonCode: 'file_uninspectable_image', finalAction: 'ALLOW' }), ev({ reasonCode: 'file_too_large' }), ev({ reasonCode: 'client_blocked' }),
    ]);
    expect(result.allow).toBe(3);
    expect(result.block).toBe(2);
    expect(result.rows.map((row) => [row.label, row.allow, row.block])).toEqual([['보안 검사 응답 없음', 2, 1], ['검사할 수 없는 파일', 1, 0], ['파일이 커서 검사 못 함', 0, 1]]);
  });
  it('summarises the current Gateway setting in one line', () => {
    expect(settingSummary({ timeout: { prompt: { action: 'forward', seconds: 3 }, file: { action: 'block', seconds: 10 } }, uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' }, notify_on_allow: true }))
      .toEqual({ timeout: '프롬프트 허용 · 파일 차단', uninspectable: '이미지 허용 · 스캔 PDF 차단 · 그 밖 차단' });
  });
});

describe('③ 보호 범위', () => {
  const document = (id: string, extra: Partial<ConfidentialDocument> = {}): ConfidentialDocument => ({ documentId: id, documentName: id, registeredAt: '2026-10-01T00:00:00Z', status: 'ACTIVE', processingStatus: 'READY', fileType: 'DOCX', exactFingerprintStatus: 'NOT_AVAILABLE', similarityFingerprintStatus: 'NOT_AVAILABLE', chunkIndexStatus: 'READY', chunkCount: 1, activeDetectors: ['WINDOW_HASH'], ...extra });
  it('merges document and index status like the documents page badge, and counts pending keywords and failed extractions per document', () => {
    const coverage = protectionCoverage(
      [document('a'), document('b'), document('c', { chunkIndexStatus: 'PROCESSING' }), document('d', { processingStatus: 'FAILED' }), document('e', { status: 'INACTIVE' })],
      [{ id: 1, keyword: 'k', doc_id: 'a', status: 'pending', source: 'llm' }, { id: 2, keyword: 'k2', doc_id: 'a', status: 'approved', source: 'llm' }],
      [{ id: 1, doc_id: 'a', status: 'failed' }, { id: 2, doc_id: 'a', status: 'done' }, { id: 3, doc_id: 'b', status: 'failed' }],
    );
    expect(coverage.total).toBe(5);
    expect(coverage.counts).toEqual({ protected: 2, analyzing: 1, failed: 1, stopped: 1, check: 0 });
    expect(coverage.pendingKeywords).toBe(1);
    expect(coverage.failedExtractions).toBe(1);   // 문서 a는 최근 작업이 완료라 빼고 b만
    expect(protectionCoverage([]).pendingKeywords).toBeUndefined();
  });
});
