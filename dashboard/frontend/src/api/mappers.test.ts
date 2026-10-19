import { describe, expect, it } from 'vitest';
import { mapSecurityEventDto } from './mappers';

describe('mapSecurityEventDto', () => {
  it('maps V4 evidence and incident metadata without raw content', () => {
    const event = mapSecurityEventDto({
      event_id: 'EVT-9700B002',
      occurred_at: '2026-08-16T17:25:31+09:00',
      client_id: 'CLT-1001',
      action: 'BLOCK',
      severity: 'HIGH',
      status: 'INVESTIGATING',
      assignee: 'security.lead',
      admin_notes: [],
      timeline: [],
      target_llm: 'ChatGPT',
      processing_ms: 12.7,
      detections: [
        {
          detector: 'MINHASH',
          match_type: 'SIMILAR_DOCUMENT',
          similarity: 0.97,
          threshold: 0.8,
          outbound_document_name: 'revision.pdf',
          matched_document_id: 'DOC-SEMICON-001',
          matched_document_name: '반도체공정.pdf',
          action: 'BLOCK',
        },
      ],
    });
    expect(event).toMatchObject({
      eventId: 'EVT-9700B002',
      severity: 'HIGH',
      status: 'INVESTIGATING',
      assignee: 'security.lead',
    });
    expect(event.detections[0]).toMatchObject({
      detector: 'MINHASH',
      matchType: 'SIMILAR_DOCUMENT',
      similarity: 0.97,
      matchedDocumentId: 'DOC-SEMICON-001',
    });
  });

  it('preserves WindowHash coverage, char span and Gateway enforcement', () => {
    const event = mapSecurityEventDto({
      event_id: 'EVT-WINDOW-001',
      request_id: 'REQ-WINDOW-001',
      occurred_at: '2026-09-16T10:00:00+09:00',
      client_id: 'chrome-client-001',
      action: 'BLOCK',
      severity: 'HIGH',
      status: 'NEW',
      admin_notes: [],
      timeline: [],
      target_llm: 'ChatGPT',
      degraded: false,
      enforcement: { applied: true, http_status: 403 },
      detections: [
        {
          detector: 'WINDOW_HASH',
          match_type: 'TEXT_FRAGMENT',
          score: 1,
          score_kind: 'COVERAGE',
          threshold: null,
          matched_document_id: '01_사업전략_방향_보고서',
          matched_location: { char_start: 763, char_end: 1504 },
          action: 'BLOCK',
        },
      ],
    });
    expect(event).toMatchObject({
      eventId: 'EVT-WINDOW-001',
      requestId: 'REQ-WINDOW-001',
      enforcement: { applied: true, httpStatus: 403 },
      degraded: false,
    });
    expect(event.detections[0]).toMatchObject({
      detector: 'WINDOW_HASH',
      matchType: 'TEXT_FRAGMENT',
      score: 1,
      scoreKind: 'COVERAGE',
      documentSpan: {
        charStart: 763,
        charEnd: 1504,
        endExclusive: true,
      },
    });
  });
});
