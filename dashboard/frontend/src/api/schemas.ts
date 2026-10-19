import { z } from 'zod';
import { ApiError } from './errors';

const securityActionSchema = z.enum(['ALLOW', 'BLOCK', 'MASK']);
const policyActionSchema = z.enum([
  'ALLOW', 'BLOCK', 'MASK', 'ALLOW_NOTIFY', 'ALLOW_DEGRADED',
  'BLOCK_NOTIFY', 'MASK_FULL', 'MASK_PARTIAL',
]);
function policyActionFamily(action: z.infer<typeof policyActionSchema>) {
  if (action === 'MASK_FULL' || action === 'MASK_PARTIAL') return 'MASK' as const;
  if (action === 'BLOCK_NOTIFY') return 'BLOCK' as const;
  if (action === 'ALLOW_NOTIFY' || action === 'ALLOW_DEGRADED') return 'ALLOW' as const;
  return action;
}
// 정책 전용 4종(2026-10-15): 옛 값은 읽을 때만 바꾼다(MASK→MASK_FULL, *_NOTIFY·ALLOW_DEGRADED→ALLOW/BLOCK). 접힌 3종(action)은 배지 색에만 쓴다
const POLICY_ACTION_4 = ['ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL'] as const;
function policyAction4(action: z.infer<typeof policyActionSchema>): (typeof POLICY_ACTION_4)[number] {
  if (action === 'MASK') return 'MASK_FULL';
  if (action === 'ALLOW_NOTIFY' || action === 'ALLOW_DEGRADED') return 'ALLOW';
  if (action === 'BLOCK_NOTIFY') return 'BLOCK';
  return action;
}
const incidentStatusSchema = z.enum(['NEW', 'INVESTIGATING', 'RESOLVED']);
const matchedDocumentFields = {
  matched_document_id: z.string().min(1),
  matched_document_name: z.string().min(1).optional(),
};
const sha256DetectionSchema = z.object({
  detector: z.literal('SHA256'),
  match_type: z.literal('EXACT_DOCUMENT'),
  outbound_document_name: z.string().min(1),
  ...matchedDocumentFields,
  action: z.literal('BLOCK'),
  recommended_action: z.literal('BLOCK').optional(),
}).strict();
const similarDocumentDetectionSchema = z
  .object({
    detector: z.literal('MINHASH'),
    match_type: z.literal('SIMILAR_DOCUMENT'),
    similarity: z.number().min(0).max(1),
    threshold: z.number().min(0).max(1),
    outbound_document_name: z.string().min(1),
    ...matchedDocumentFields,
    action: securityActionSchema,
    recommended_action: securityActionSchema.optional(),
  })
  .refine((value) => value.similarity >= value.threshold, {
    path: ['similarity'],
    message: 'Triggered similarity must meet the threshold.',
  });
const signatureDetectionSchema = z
  .object({
    detector: z.literal('SIGNATURE'),
    match_type: z.literal('SIGNATURE_RULE'),
    category: z.string().min(1).optional(),
    rule_id: z.string().min(1).optional(),
    policy_id: z.string().min(1).optional(),
    policy_version: z
      .string()
      .regex(/^v\d+$/)
      .optional(),
    action: securityActionSchema,
    recommended_action: securityActionSchema.optional(),
    confidence: z.number().min(0).max(1).optional(),
    entity_count: z.number().int().positive().optional(),
    entity_counts: z
      .array(
        z.object({
          entity_type: z.string().min(1),
          count: z.number().int().positive(),
        }),
      )
      .min(1)
      .optional(),
  })
  .refine(
    (value) =>
      (value.category !== undefined && value.rule_id !== undefined) ||
      value.entity_counts !== undefined,
    { message: 'Signature evidence is required.' },
  );
const characterSpanSchema = z
  .object({
    char_start: z.number().int().nonnegative(),
    char_end: z.number().int().positive(),
  })
  .refine((value) => value.char_end > value.char_start, {
    path: ['char_end'],
    message: 'char_end must be greater than char_start.',
  });
const windowHashDetectionSchema = z.object({
  detector: z.literal('WINDOW_HASH'),
  match_type: z.literal('TEXT_FRAGMENT'),
  score: z.number().min(0).max(1),
  score_kind: z.literal('COVERAGE'),
  threshold: z.number().min(0).max(1).nullable().optional(),
  ...matchedDocumentFields,
  input_location: characterSpanSchema.optional(),
  matched_location: characterSpanSchema,
  action: securityActionSchema,
  recommended_action: securityActionSchema.optional(),
  // 2026-10-16 '일치 비율' 통일: 대시보드 서버가 붙이는 입력 중 문서와 같은 글자 비율(same-text.mjs). 옛 서버는 없음
  same_text: z.object({
    state: z.enum(['READY', 'PENDING', 'UNAVAILABLE']),
    same_chars: z.number().int().nonnegative().optional(),
    input_chars: z.number().int().nonnegative().optional(),
    differences: z.number().int().nonnegative().optional(),
    reason: z.string().max(200).optional(),
  }).refine((value) => value.state !== 'READY' || (value.same_chars !== undefined && value.input_chars !== undefined && value.same_chars <= value.input_chars), { message: 'READY needs same_chars <= input_chars' }).optional(),
});
const incidentNoteSchema = z.object({
  note_id: z.string().min(1),
  author: z.string().min(1),
  created_at: z.iso.datetime({ offset: true }),
  content: z.string().min(1).max(2000),
});
const timelineItemSchema = z.object({
  timeline_id: z.string().min(1),
  occurred_at: z.iso.datetime({ offset: true }),
  actor: z.string().min(1),
  type: z.enum([
    'DETECTED',
    'STATUS_CHANGED',
    'ASSIGNEE_CHANGED',
    'NOTE_ADDED',
  ]),
  summary: z.string().min(1),
});

// 질문에 붙은 파일(목록은 전체 이벤트, 상세는 요약) - 필요한 칸만 받는다 (2026-10-09)
const attachedEventSchema = z.object({
  event_id: z.string().min(1),
  request_id: z.string().min(1).optional(),
  occurred_at: z.iso.datetime({ offset: true }),
  action: securityActionSchema.optional(),
  final_action: securityActionSchema.optional(),
  content_type: z.enum(['prompt', 'file']).optional(),
  detection_outcome: z.enum(['MATCH', 'NO_MATCH', 'UNAVAILABLE']).optional(),
  detections: z.array(z.union([sha256DetectionSchema, similarDocumentDetectionSchema, windowHashDetectionSchema, signatureDetectionSchema])).optional(),
  enforcement: z.object({ applied: z.boolean(), http_status: z.number().int().min(100).max(599).optional() }).optional(),
  reason_code: z.string().min(1).optional(),
  degraded: z.boolean().optional(),
});

export const securityEventSchema = z.object({
  event_id: z.string().min(1),
  occurred_at: z.iso.datetime({ offset: true }),
  client_id: z.string().min(1),
  user_id: z.string().min(1).optional(),
  tenant_id: z.string().min(1).optional(),
  action: securityActionSchema,
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  status: incidentStatusSchema,
  assignee: z.string().min(1).optional(),
  admin_notes: z.array(incidentNoteSchema),
  timeline: z.array(timelineItemSchema),
  detections: z
    .array(
      z.union([
        sha256DetectionSchema,
        similarDocumentDetectionSchema,
        windowHashDetectionSchema,
        signatureDetectionSchema,
      ]),
    ),
  target_llm: z.enum(['ChatGPT', 'Gemini', 'Claude']),
  processing_ms: z.number().nonnegative().optional(),
  request_id: z.string().min(1).optional(),
  enforcement: z
    .object({
      applied: z.boolean(),
      http_status: z.number().int().min(100).max(599).optional(),
    })
    .optional(),
  degraded: z.boolean().optional(),
  detection_outcome: z.enum(['MATCH', 'NO_MATCH', 'UNAVAILABLE']).optional(),
  recommended_action: securityActionSchema.optional(),
  final_action: securityActionSchema.optional(),
  host: z.string().min(1).optional(),
  endpoint: z.string().min(1).optional(),
  content_type: z.enum(['prompt', 'file']).optional(),
  degraded_reason: z
    .enum(['TIMEOUT', 'UNREACHABLE', 'PARSE_ERROR', 'OTHER'])
    .optional(),
  failure_policy: z.enum(['FAIL_OPEN', 'FAIL_CLOSED']).optional(),
  detector_version: z.string().min(1).optional(),
  ruleset_version: z.string().min(1).optional(),
  model_version: z.string().min(1).optional(),
  reason_code: z.string().min(1).optional(),
  policy_version: z.string().min(1).optional(),
  access_rule_id: z.string().min(1).max(64).optional(),
  file_id: z.string().min(1).optional(),
  attached_file_ids: z.array(z.string().min(1)).optional(),
  group_final_action: securityActionSchema.optional(),
  attached_files: z.array(attachedEventSchema).optional(),
  attached_to: z.array(attachedEventSchema).optional(),
});

export const pageSchema = <T extends z.ZodType>(item: T) =>
  z
    .object({
      items: z.array(item),
      total: z.number().int().nonnegative(),
      page: z.number().int().positive(),
      page_size: z.number().int().positive(),
      total_pages: z.number().int().positive(),
      excluded_test: z.number().int().nonnegative().optional(),
      view_totals: z.object({ counted: z.number().int().nonnegative(), access: z.number().int().nonnegative(), all: z.number().int().nonnegative() }).optional(),
    })
    .superRefine((value, context) => {
      const expectedTotalPages = Math.max(
        1,
        Math.ceil(value.total / value.page_size),
      );
      if (value.total_pages !== expectedTotalPages)
        context.addIssue({
          code: 'custom',
          path: ['total_pages'],
          message: 'total_pages is inconsistent with total and page_size.',
        });
      if (value.page > value.total_pages)
        context.addIssue({
          code: 'custom',
          path: ['page'],
          message: 'page cannot exceed total_pages.',
        });
      if (value.total === 0 && (value.page !== 1 || value.items.length !== 0))
        context.addIssue({
          code: 'custom',
          path: ['total'],
          message: 'Empty results must use page=1 and contain no items.',
        });
    });
const trendPointSchema = z.object({
  bucket: z.string().min(1),
  total: z.number().int().nonnegative(),
  block: z.number().int().nonnegative(),
  mask: z.number().int().nonnegative(),
  allow: z.number().int().nonnegative().optional(),
});
const actionCountsSchema = z.object({ key: z.string().min(1), block: z.number().int().nonnegative(), mask: z.number().int().nonnegative(), allow: z.number().int().nonnegative() });
export const dashboardStatsSchema = z.object({
  total: z.number().int().nonnegative(),
  block: z.number().int().nonnegative(),
  mask: z.number().int().nonnegative(),
  allow: z.number().int().nonnegative().optional(),
  degraded: z.number().int().nonnegative().optional(),
  enforcement_rate: z.number().min(0).max(1).optional(),
  action_mismatch: z.number().int().nonnegative().optional(),
  new_events: z.number().int().nonnegative(),
  average_processing_ms: z.number().nonnegative(),
  detection_status: z.enum(['HEALTHY', 'DEGRADED', 'UNKNOWN']).optional(),
  gateway_status: z.enum(['HEALTHY', 'DEGRADED', 'UNKNOWN']).optional(),
  gateway_metrics_status: z.enum(['FRESH', 'STALE', 'NOT_RECEIVED']).optional(),
  gateway_completed_requests: z.number().int().nonnegative().optional(),
  last_success_at: z.iso.datetime({ offset: true }).optional(),
  trend: z.array(trendPointSchema),
  recent: z.array(securityEventSchema),
  // 보안 현황 그래프(2026-10-10)
  insights: z.object({
    entity_counts: z.array(z.object({ key: z.string().min(1), count: z.number().int().nonnegative() })),
    documents: z.array(z.object({ key: z.string().min(1), count: z.number().int().nonnegative(), blocked: z.number().int().nonnegative().optional(), name: z.string().optional() })),
    llm_actions: z.array(actionCountsSchema),
    content_actions: z.array(actionCountsSchema),
    heatmap: z.array(z.array(z.number().int().nonnegative()).length(24)).length(7),
    category_counts: z.array(z.object({ key: z.enum(['PII', 'CREDENTIAL', 'KEYWORD']), events: z.number().int().nonnegative(), values: z.number().int().nonnegative() })).optional(),
    entity_event_counts: z.array(z.object({ key: z.string().min(1), count: z.number().int().nonnegative() })).optional(),
  }).optional(),
  // 집계 기준(2026-10-15). 옛 서버는 없음
  counting: z.object({
    unit: z.literal('REQUEST'),
    records: z.number().int().nonnegative(),
    list_total: z.number().int().nonnegative(),
    access_blocked: z.number().int().nonnegative(),
    resend_file: z.number().int().nonnegative().optional(),
    resend_prompt: z.number().int().nonnegative().optional(),
    resend_folded: z.number().int().nonnegative(),
    sensitive: z.number().int().nonnegative(),
    last_degraded_at: z.iso.datetime({ offset: true }).optional(),
  }).optional(),
});

const fingerprintStatusSchema = z.enum([
  'PROCESSING',
  'READY',
  'NOT_AVAILABLE',
  'FAILED',
]);
export const documentSchema = z.object({
  document_id: z.string().min(1),
  document_name: z.string().min(1),
  registered_at: z.iso.datetime({ offset: true }),
  status: z.enum(['ACTIVE', 'INACTIVE']),
  processing_status: z.enum(['PROCESSING', 'READY', 'FAILED']),
  file_type: z.string().min(1),
  file_size: z.number().int().nonnegative().optional(),
  exact_fingerprint_status: fingerprintStatusSchema,
  similarity_fingerprint_status: fingerprintStatusSchema,
  chunk_index_status: fingerprintStatusSchema,
  chunk_count: z.number().int().nonnegative(),
  version: z.string().min(1).optional(),
  classification: z
    .enum(['INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'])
    .optional(),
  owner: z.string().min(1).optional(),
  active_detectors: z
    .array(z.enum(['SHA256', 'WINDOW_HASH', 'MINHASH', 'SIGNATURE']))
    .optional(),
  exact_detection_count: z.number().int().nonnegative().optional(),
  modified_partial_detection_count: z.number().int().nonnegative().optional(),
  last_detected_at: z.iso.datetime({ offset: true }).optional(),
});
export const policyVersionSchema = z.object({
  version: z.number().int().positive(),
  action: policyActionSchema,
  created_at: z.iso.datetime({ offset: true }),
  changed_by: z.string().min(1),
  enabled: z.boolean(),
}).transform((version) => ({
  ...version,
  action: policyActionFamily(version.action),
  action_variant: version.action,
  policy_action: policyAction4(version.action),
}));
export const policySchema = z.object({
  policy_id: z.string().min(1),
  detector: z.enum(['SHA256', 'WINDOW_HASH', 'MINHASH', 'SIGNATURE', 'DOCUMENT']),
  detection_target: z.string().min(1),
  action: policyActionSchema,
  recommended_action: policyActionSchema.optional(),
  enforcement_action: policyActionSchema.optional(),
  target_llms: z
    .array(z.enum(['ChatGPT', 'Gemini', 'Claude']))
    .optional(),
  document_classification: z
    .enum(['INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'])
    .optional(),
  failure_policy: z.enum(['FAIL_OPEN', 'FAIL_CLOSED']).optional(),
  priority: z.number().int().nonnegative().optional(),
  updated_by: z.string().min(1).optional(),
  updated_at: z.iso.datetime({ offset: true }).optional(),
  version: z.number().int().positive(),
  enabled: z.boolean(),
  versions: z.array(policyVersionSchema).optional(),
}).transform((policy) => ({
  ...policy,
  action: policyActionFamily(policy.action),
  recommended_action: policy.recommended_action
    ? policyActionFamily(policy.recommended_action) : undefined,
  enforcement_action: policy.enforcement_action
    ? policyActionFamily(policy.enforcement_action) : undefined,
  action_variant: policy.enforcement_action ?? policy.action,
  policy_action: policyAction4(policy.action),
  final_policy_action: policyAction4(policy.enforcement_action ?? policy.action),
  recommended_policy_action: policy.recommended_action ? policyAction4(policy.recommended_action) : undefined,
}));
// GET /api/policies/capabilities(대시보드 서버 policy-capabilities.mjs, 2026-10-14.2). 서버가 검토한 설정 목록이며 실행 중 규칙이 아니다.
// allowed_actions는 4종만 받는다(모르는 조치·빈 목록이면 응답 전체를 거절 → 화면은 변경 기능을 끈다). 문서에 없는 칸(warnings 등)은 받아 둔다
export const policyCapabilitiesSchema = z.object({
  catalog_version: z.string().min(1),
  catalog_source: z.string().optional(),
  runtime_verified: z.boolean(),
  actions: z.array(z.object({ code: z.string().min(1), label: z.string().optional() })).optional(),
  targets: z.array(z.object({
    code: z.string().regex(/^[A-Z][A-Z0-9_]{1,47}$/),
    label: z.string().min(1),
    category: z.string().min(1),
    target_type: z.string().min(1),
    can_create: z.boolean(),
    allowed_actions: z.array(z.enum(POLICY_ACTION_4)).min(1),
    partial_masking: z.string().nullish().transform((value) => value ?? undefined),
    requires_context: z.boolean().optional(),
    runtime_availability: z.string().optional(),
  })).min(1),
  full_masking: z.string().optional(),
  creates_recognizer: z.boolean().optional(),
  warnings: z.array(z.string()).optional(),
});
export const auditLogSchema = z.object({
  audit_id: z.string().min(1),
  occurred_at: z.iso.datetime({ offset: true }),
  admin_id: z.string().min(1),
  action: z.enum([
    'ADMIN_LOGIN',
    'ADMIN_LOGOUT',
    'POLICY_CREATE',
    'POLICY_UPDATE',
    'POLICY_ENABLE',
    'POLICY_DISABLE',
    'DOCUMENT_REGISTER',
    'DOCUMENT_ENABLE',
    'DOCUMENT_DISABLE',
    'EVENT_ASSIGNED',
    'EVENT_STATUS_CHANGED',
    'EVENT_NOTE_ADDED',
    'REPORT_CREATE',
    'KEYWORD_CREATE',
    'KEYWORD_APPROVE',
    'KEYWORD_REJECT',
    'KEYWORD_UPDATE',
    'KEYWORD_EXTRACT_REQUEST',
    'GPU_START',
    'GPU_STOP',
    'GATEWAY_SETTINGS_UPDATE',
    'ACCESS_RULE_ADD',
    'ACCESS_RULE_REMOVE',
    'ACCESS_MODE_UPDATE',
    'CLIENT_ALIAS_UPDATE',
    // 보호 문서 본문 보기(2026-10-13): 열 때마다·내려받을 때마다 1건(DB 제약 002와 같은 이름)
    'DOCUMENT_VIEW',
    'DOCUMENT_DOWNLOAD',
  ]),
  target_type: z.enum(['ADMIN', 'POLICY', 'DOCUMENT', 'EVENT', 'REPORT', 'KEYWORD', 'GPU', 'GATEWAY']),
  target_id: z.string().min(1),
  result: z.enum(['SUCCESS', 'FAILURE']),
  changes: z
    .object({
      previous_version: z.number().int().positive().optional(),
      new_version: z.number().int().positive().optional(),
      // 정책 조치는 색 계열(previous_action·new_action)과 4종 이름(previous_policy_action·new_policy_action)을 함께 둔다(2026-10-15 감사 로그 부분/전체 구분)
      previous_action: policyActionSchema.optional(),
      new_action: policyActionSchema.optional(),
      previous_status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
      new_status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
      previous_incident_status: incidentStatusSchema.optional(),
      new_incident_status: incidentStatusSchema.optional(),
      previous_assignee: z.string().optional(),
      new_assignee: z.string().optional(),
      note_added: z.boolean().optional(),
      previous_value: z.string().optional(),
      new_value: z.string().optional(),
      keyword: z.string().optional(),
      doc_id: z.string().optional(),
      status: z.string().optional(),
      applied: z.boolean().optional(),
      from: z.string().optional(),
      to: z.string().optional(),
      use_llm: z.boolean().optional(),
      job_id: z.number().int().optional(),
      retry_of_job_id: z.number().int().optional(),   // 키워드 추출 재시도(2026-10-15)
      previous_instance_state: z.string().optional(),
      new_instance_state: z.string().optional(),
      // 문서 열람·내려받기(2026-10-13): 판(문자열, 옛 문서 기록의 숫자도 받음)·형식·보기 방식·열람 번호. 모양이 다르면 그 칸만 버린다(줄 전체를 못 읽게 하지 않음)
      version: z.unknown().transform((value) => (typeof value === 'string' || typeof value === 'number' ? String(value) : undefined)).optional(),
      format: z.unknown().transform((value) => (typeof value === 'string' ? value : undefined)).optional(),
      mode: z.unknown().transform((value) => (value === 'original' || value === 'text' || value === 'download' ? value : undefined)).optional(),
      view_ref: z.unknown().transform((value) => (typeof value === 'string' ? value : undefined)).optional(),
    })
    .transform(({ previous_action, new_action, ...changes }) => ({
      ...changes,
      ...(previous_action ? { previous_action: policyActionFamily(previous_action), previous_policy_action: policyAction4(previous_action) } : {}),
      ...(new_action ? { new_action: policyActionFamily(new_action), new_policy_action: policyAction4(new_action) } : {}),
    }))
    .nullish()
    .transform((changes) => changes ?? undefined),
});
// 감사 로그는 줄마다 읽는다(2026-10-10): 바뀐 값(changes)만 형식이 다르면 그 부분만 빼고 보여 주고,
// 작업 이름처럼 화면이 모르는 값이 있는 줄은 빼고 건수만 알린다. 한 줄 때문에 페이지 전체가 실패하지 않게
const auditLogWithoutChanges = auditLogSchema.extend({ changes: z.unknown().transform(() => undefined) });
export function readAuditRows<T>(page: { items: unknown[]; total: number; page: number; page_size: number; total_pages: number }) {
  const items: T[] = [];
  let skipped = 0;
  let partial = 0;
  for (const row of page.items) {
    const full = auditLogSchema.safeParse(row);
    if (full.success) { items.push(full.data as T); continue; }
    const withoutChanges = auditLogWithoutChanges.safeParse(row);
    if (withoutChanges.success) { items.push({ ...withoutChanges.data, changes_unreadable: true } as T); partial += 1; continue; }
    skipped += 1;
  }
  return { ...page, items, ...(skipped ? { skipped } : {}), ...(partial ? { partial } : {}) };
}

export const adminUserSchema = z.object({
  id: z.string().min(1),
  email: z.email(),
  display_name: z.string().min(1),
  role: z.string().min(1),
});

export const trafficSummarySchema = z.object({
  metric_source: z.enum(['GATEWAY_LIVE', 'STORED_EVENTS']).optional(),
  gateway_metrics_status: z.enum(['FRESH', 'STALE', 'NOT_RECEIVED']).optional(),
  gateway_metrics_received_at: z.iso.datetime({ offset: true }).optional(),
  gateway_metrics_age_sec: z.number().nonnegative().optional(),
  gateway_total_requests: z.number().int().nonnegative().optional(),
  gateway_completed_requests: z.number().int().nonnegative().optional(),
  gateway_error_requests: z.number().int().nonnegative().optional(),
  gateway_window_seconds: z.number().int().positive().optional(),
  client_identity_incomplete: z.boolean().optional(),
  event_count: z.number().int().nonnegative().optional(),
  latency_sample_count: z.number().int().nonnegative().optional(),
  active_clients: z.number().int().nonnegative().optional(),
  concurrent_requests: z.number().int().nonnegative().optional(),
  requests_per_sec: z.number().nonnegative().optional(),
  average_latency_ms: z.number().nonnegative().optional(),
  p95_latency_ms: z.number().nonnegative().optional(),
  latency_unavailable_reason: z.enum(['LEGACY_GATEWAY']).optional(),
  timeout_rate: z.number().min(0).max(1).optional(),
  degraded_rate: z.number().min(0).max(1).optional(),
  gateway_status: z.enum(['HEALTHY', 'DEGRADED', 'UNKNOWN']).optional(),
  // 2026-10-15 숫자 감사: 접속 차단 분리·검사 요청 분모·연결 오류 기준(옛 서버·옛 Gateway는 없음)
  access_blocked: z.number().int().nonnegative().optional(),
  gateway_inspected_requests: z.number().int().nonnegative().optional(),
  gateway_error_basis: z.enum(['GATEWAY_ERRORS', 'ALL_DISCONNECTS']).optional(),
  gateway_client_cancelled_requests: z.number().int().nonnegative().optional(),
  gateway_status_reason: z.string().max(200).optional(),
});
export const trafficTimeBucketSchema = z.object({
  timestamp: z.iso.datetime({ offset: true }),
  request_count: z.number().int().nonnegative(),
  allow_count: z.number().int().nonnegative(),
  mask_count: z.number().int().nonnegative(),
  block_count: z.number().int().nonnegative(),
  average_latency_ms: z.number().nonnegative().optional(),
  p95_latency_ms: z.number().nonnegative().optional(),
}).refine(point => point.request_count === point.allow_count + point.mask_count + point.block_count, {
  message: 'Traffic bucket action totals do not match request_count.',
});
// 연결 중인 IP(2026-10-12): GET /api/traffic/clients. Gateway가 보낸 지표의 clients를 백엔드가 그대로 돌려준다
export const trafficClientSchema = z.object({
  ip: z.string().min(1).max(45),
  client_id: z.string().max(80).nullable(),
  connections: z.number().int().nonnegative(),
  inflight: z.number().int().nonnegative(),
  waiting: z.number().int().nonnegative().default(0),   // 대기 연결(2026-10-12). 칸이 없으면 0
  requests_5m: z.number().int().nonnegative(),
  targets: z.record(z.string().min(1), z.number().int().nonnegative()),
  first_seen_at: z.iso.datetime({ offset: true }),
  last_seen_at: z.iso.datetime({ offset: true }),
});
export const trafficClientsSchema = z.object({
  received_at: z.iso.datetime({ offset: true }).nullable(),
  stale: z.boolean(),
  window_seconds: z.number().int().positive(),
  clients: z.array(trafficClientSchema).max(200),
});
export const trafficSnapshotSchema = z.object({
  unavailable_sections: z.array(z.string()).optional(),
  summary: trafficSummarySchema,
  time_series: z.array(trafficTimeBucketSchema),
});

export function parseApiResponse<T>(schema: z.ZodType<T>, payload: unknown): T {
  const parsed = schema.safeParse(payload);
  if (!parsed.success)
    throw new ApiError(
      '서버 응답 형식이 올바르지 않습니다.',
      'INVALID_RESPONSE',
    );
  return parsed.data;
}
