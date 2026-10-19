import { describe, expect, it } from 'vitest';
import type { SecurityEventDto } from '@/src/api/dto';
import type { EventFilters } from '@/src/types/event';
import {
  filterAndPaginateEventDtos,
  filterEventDtos,
  paginateDtos,
} from './eventQuery';

const now = Date.parse('2026-08-16T12:00:00Z');
const base = {
  user_id: undefined,
  tenant_id: undefined,
  assignee: undefined,
  admin_notes: [],
  timeline: [],
  target_llm: 'ChatGPT' as const,
  processing_ms: 15,
};
const rows: SecurityEventDto[] = [
  {
    ...base,
    event_id: 'EVT-AAAAAAAA',
    occurred_at: '2026-08-16T11:00:00Z',
    client_id: 'CLT-1001',
    action: 'BLOCK',
    severity: 'CRITICAL',
    status: 'NEW',
    detections: [
      {
        detector: 'SHA256',
        match_type: 'EXACT_DOCUMENT',
        outbound_document_name: 'source.pdf',
        matched_document_id: 'DOC-1',
        action: 'BLOCK',
      },
    ],
  },
  {
    ...base,
    event_id: 'EVT-BBBBBBBB',
    occurred_at: '2026-08-15T10:00:00Z',
    client_id: 'CLT-1002',
    action: 'MASK',
    severity: 'LOW',
    status: 'RESOLVED',
    detections: [
      {
        detector: 'SIGNATURE',
        match_type: 'SIGNATURE_RULE',
        category: 'API_KEY',
        rule_id: 'SIG-003',
        action: 'MASK',
      },
    ],
  },
  {
    ...base,
    event_id: 'EVT-CCCCCCCC',
    occurred_at: '2026-08-13T10:00:00Z',
    client_id: 'CLT-1001',
    action: 'BLOCK',
    severity: 'HIGH',
    status: 'INVESTIGATING',
    detections: [
      {
        detector: 'WINDOW_HASH',
        match_type: 'TEXT_FRAGMENT',
        score: 0.86,
        score_kind: 'COVERAGE',
        threshold: 0.8,
        matched_document_id: 'DOC-1',
        matched_location: { char_start: 20, char_end: 120 },
        action: 'BLOCK',
      },
    ],
  },
];
const filters: EventFilters = {
  query: 'CLT-1001',
  period: '7D',
  finalAction: 'BLOCK',
  recommendedAction: 'ALL',
  detector: 'ALL',
  matchType: 'ALL',
  scoreKind: 'ALL',
  degraded: 'ALL',
  detectionOutcome: 'ALL',
  degradedReason: 'ALL',
  failurePolicy: 'ALL',
  documentId: '',
  severity: 'ALL',
  status: 'ALL',
  targetLlm: 'ALL',
  sort: 'SEVERITY_DESC',
  page: 1,
  pageSize: 1,
};

describe('event filtering and pagination', () => {
  it('filters and sorts by server-provided severity', () =>
    expect(
      filterEventDtos(rows, filters, now).map((row) => row.event_id),
    ).toEqual(['EVT-AAAAAAAA', 'EVT-CCCCCCCC']));
  it('paginates with total count', () =>
    expect(filterAndPaginateEventDtos(rows, filters, now)).toMatchObject({
      total: 2,
      page_size: 1,
      total_pages: 2,
    }));
  it('clamps pages beyond the end', () =>
    expect(paginateDtos(rows, 99, 2).page).toBe(2));
});
