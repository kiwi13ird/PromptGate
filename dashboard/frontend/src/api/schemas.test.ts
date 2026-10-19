import { describe, expect, it } from 'vitest';
import { auditLogSchema, pageSchema, parseApiResponse, policySchema, securityEventSchema } from './schemas';
import { mapAuditLogDto, mapPolicyDto } from './mappers';

const eventWith = (detection: Record<string, unknown>) => ({
  event_id: 'EVT-12345678',
  occurred_at: '2026-08-16T10:00:00Z',
  client_id: 'CLT-1001',
  action: 'BLOCK',
  severity: 'HIGH',
  status: 'NEW',
  admin_notes: [],
  timeline: [],
  detections: [detection],
  target_llm: 'ChatGPT',
  processing_ms: 8.2,
});

describe('runtime API schema', () => {
  it.each([
    ['MASK_FULL', 'MASK'], ['MASK_PARTIAL', 'MASK'],
    ['BLOCK_NOTIFY', 'BLOCK'], ['ALLOW_NOTIFY', 'ALLOW'], ['MASK', 'MASK'],
  ])('accepts Detection policy action %s and preserves its variant', (variant, family) => {
    const policy = mapPolicyDto(parseApiResponse(policySchema, {
      policy_id: 'POLICY-PII-MASK', detector: 'SIGNATURE', detection_target: 'PII',
      action: variant, recommended_action: variant, enforcement_action: variant,
      target_llms: ['ChatGPT', 'Gemini', 'Claude'], priority: 100,
      updated_by: 'bootstrap', updated_at: '2026-09-29T09:39:04.144699Z',
      version: 1, enabled: true,
    }));
    expect(policy).toMatchObject({action:family, recommendedAction:family, enforcementAction:family, actionVariant:variant});
  });

  it('does not treat unknown policy actions as an allowed action', () => {
    expect(() => parseApiResponse(policySchema, {
      policy_id: 'POL-INVALID', detector: 'SIGNATURE', detection_target: 'PII',
      action: 'NEW_UNKNOWN_ACTION', version: 1, enabled: true,
    })).toThrowError(expect.objectContaining({code:'INVALID_RESPONSE'}));
  });

  it('keeps login activity without changes and preserves event change details', () => {
    const row = {
      audit_id: 'AUD-LOGIN', occurred_at: '2026-10-01T14:16:39.531Z',
      admin_id: 'local-admin', action: 'ADMIN_LOGIN', target_type: 'ADMIN',
      target_id: 'local-admin', result: 'SUCCESS', changes: null,
    };
    const page = parseApiResponse(pageSchema(auditLogSchema), {
      items: [row, {...row, audit_id:'AUD-EVENT', action:'EVENT_STATUS_CHANGED',
        target_type:'EVENT', target_id:'evt-test',
        changes:{previous_incident_status:'NEW',new_incident_status:'INVESTIGATING'}}],
      total:2, page:1, page_size:9, total_pages:1,
    });
    const logs = page.items.map(mapAuditLogDto);
    expect(logs[0]).toMatchObject({action:'ADMIN_LOGIN',changes:undefined});
    expect(logs[1].changes).toMatchObject({previousIncidentStatus:'NEW',newIncidentStatus:'INVESTIGATING'});
  });

  it('accepts a valid event with per-detection action', () => {
    const parsed = parseApiResponse(securityEventSchema, {
      event_id: 'EVT-12345678',
      occurred_at: '2026-08-16T10:00:00Z',
      client_id: 'CLT-1001',
      action: 'MASK',
      severity: 'MEDIUM',
      status: 'NEW',
      admin_notes: [],
      timeline: [],
      detections: [
        {
          detector: 'SIGNATURE',
          match_type: 'SIGNATURE_RULE',
          category: 'API_KEY',
          rule_id: 'SIG-003',
          policy_version: 'v3',
          action: 'MASK',
        },
      ],
      target_llm: 'ChatGPT',
      processing_ms: 8.2,
    });
    expect(parsed.detections[0].action).toBe('MASK');
  });
  it('normalizes invalid payloads without exposing raw JSON', () => {
    expect(() =>
      parseApiResponse(securityEventSchema, { event_id: 'EVT-BROKEN' }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });

  it('enforces exact-document invariants', () => {
    expect(() =>
      parseApiResponse(
        securityEventSchema,
        eventWith({
          detector: 'SHA256',
          match_type: 'EXACT_DOCUMENT',
          similarity: 0.99,
          outbound_document_name: 'outbound.pdf',
          matched_document_id: 'DOC-1',
          action: 'BLOCK',
        }),
      ),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });

  it('rejects triggered MinHash findings below threshold', () => {
    expect(() =>
      parseApiResponse(
        securityEventSchema,
        eventWith({
          detector: 'MINHASH',
          match_type: 'SIMILAR_DOCUMENT',
          similarity: 0.79,
          threshold: 0.8,
          outbound_document_name: 'revision.pdf',
          matched_document_id: 'DOC-1',
          action: 'BLOCK',
        }),
      ),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });

  it('requires chunk and a page or section for text fragments', () => {
    expect(() =>
      parseApiResponse(
        securityEventSchema,
        eventWith({
          detector: 'MINHASH',
          match_type: 'TEXT_FRAGMENT',
          similarity: 0.86,
          threshold: 0.8,
          matched_document_id: 'DOC-1',
          matched_chunk_id: 'CHUNK-012',
          action: 'BLOCK',
        }),
      ),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });

  it('accepts WindowHash coverage with only a document id and character span', () => {
    const parsed = parseApiResponse(
      securityEventSchema,
      {
        ...eventWith({
          detector: 'WINDOW_HASH',
          match_type: 'TEXT_FRAGMENT',
          score: 1,
          score_kind: 'COVERAGE',
          threshold: null,
          matched_document_id: '01_사업전략_방향_보고서',
          matched_location: { char_start: 763, char_end: 1504 },
          action: 'BLOCK',
        }),
        request_id: 'REQ-001',
        enforcement: { applied: true, http_status: 403 },
        degraded: false,
      },
    );
    expect(parsed.detections[0]).toMatchObject({
      detector: 'WINDOW_HASH',
      score_kind: 'COVERAGE',
      matched_location: { char_start: 763, char_end: 1504 },
    });
    expect(parsed.enforcement).toEqual({ applied: true, http_status: 403 });
  });

  it('rejects an invalid WindowHash character span', () => {
    expect(() =>
      parseApiResponse(
        securityEventSchema,
        eventWith({
          detector: 'WINDOW_HASH',
          match_type: 'TEXT_FRAGMENT',
          score: 1,
          score_kind: 'COVERAGE',
          matched_document_id: 'DOC-1',
          matched_location: { char_start: 1504, char_end: 763 },
          action: 'BLOCK',
        }),
      ),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });

  it('uses one-based pagination with one page for empty results', () => {
    const schema = pageSchema(securityEventSchema);
    expect(
      parseApiResponse(schema, {
        items: [],
        total: 0,
        page: 1,
        page_size: 20,
        total_pages: 1,
      }),
    ).toMatchObject({ total: 0, page: 1, total_pages: 1 });
    expect(() =>
      parseApiResponse(schema, {
        items: [],
        total: 0,
        page: 1,
        page_size: 20,
        total_pages: 0,
      }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_RESPONSE' }));
  });
});
