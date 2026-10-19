import type {
  AdminUserDto,
  AttachedEventDto,
  AuditLogDto,
  ConfidentialDocumentDto,
  DashboardStatsDto,
  DetectionDto,
  DetectionPolicyDto,
  PageDto,
  PolicyCapabilitiesDto,
  PolicyVersionDto,
  SecurityEventDto,
  TrafficClientsDto,
  TrafficSnapshotDto,
} from './dto';
import type { AdminUser } from '@/src/types/auth';
import type { AuditLog } from '@/src/types/audit';
import type {
  AttachedEvent,
  DashboardStats,
  Detection,
  PaginatedResult,
  SecurityEvent,
} from '@/src/types/event';
import type { ConfidentialDocument, DetectionPolicy, PolicyCapabilities, PolicyVersion } from '@/src/types/policy';
import { toPolicyAction } from '@/src/utils/policyActions';
import type { TrafficClients, TrafficSnapshot } from '@/src/types/traffic';

export function mapDetectionDto(item: DetectionDto): Detection {
  if (item.detector === 'SHA256')
    return {
      detector: 'SHA256',
      matchType: item.match_type,
      outboundDocumentName: item.outbound_document_name,
      matchedDocumentId: item.matched_document_id,
      matchedDocumentName: item.matched_document_name,
      recommendedAction: item.recommended_action,
    };
  if (item.detector === 'MINHASH' && item.match_type === 'SIMILAR_DOCUMENT')
    return {
      detector: 'MINHASH',
      matchType: item.match_type,
      similarity: item.similarity,
      threshold: item.threshold,
      outboundDocumentName: item.outbound_document_name,
      matchedDocumentId: item.matched_document_id,
      matchedDocumentName: item.matched_document_name,
      recommendedAction: item.recommended_action,
    };
  if (item.detector === 'WINDOW_HASH')
    return {
      detector: 'WINDOW_HASH',
      matchType: item.match_type,
      score: item.score,
      scoreKind: item.score_kind,
      threshold: item.threshold ?? undefined,
      matchedDocumentId: item.matched_document_id,
      matchedDocumentName: item.matched_document_name,
      inputSpan: item.input_location
        ? {
            charStart: item.input_location.char_start,
            charEnd: item.input_location.char_end,
            endExclusive: true,
          }
        : undefined,
      documentSpan: {
        charStart: item.matched_location.char_start,
        charEnd: item.matched_location.char_end,
        endExclusive: true,
      },
      recommendedAction: item.recommended_action,
      sameText: item.same_text ? {
        state: item.same_text.state,
        sameChars: item.same_text.same_chars,
        inputChars: item.same_text.input_chars,
        differences: item.same_text.differences,
        reason: item.same_text.reason,
      } : undefined,
    };
  return {
    detector: 'SIGNATURE',
    matchType: item.match_type,
    category: item.category,
    ruleId: item.rule_id,
    policyId: item.policy_id,
    policyVersion: item.policy_version,
    confidence: item.confidence,
    scoreKind: 'CONFIDENCE',
    entityCount: item.entity_count,
    entityCounts: item.entity_counts?.map((entity) => ({
      entityType: entity.entity_type,
      count: entity.count,
    })),
    recommendedAction: item.recommended_action,
  };
}

// 질문에 붙은 파일 - 목록은 전체 이벤트, 상세는 요약이라 있는 칸만 옮긴다 (2026-10-09)
function mapAttachedEventDto(raw: AttachedEventDto): AttachedEvent {
  return {
    eventId: raw.event_id,
    requestId: raw.request_id,
    occurredAt: raw.occurred_at,
    finalAction: raw.final_action ?? raw.action ?? 'ALLOW',
    contentType: raw.content_type,
    detectionOutcome: raw.detection_outcome,
    detections: (raw.detections ?? []).map(mapDetectionDto),
    enforcement: raw.enforcement ? { applied: raw.enforcement.applied, httpStatus: raw.enforcement.http_status } : undefined,
    ...(raw.reason_code ? { reasonCode: raw.reason_code } : {}),
    ...(raw.degraded !== undefined ? { degraded: raw.degraded } : {}),
  };
}

export function mapSecurityEventDto(raw: SecurityEventDto): SecurityEvent {
  const detections: Detection[] = raw.detections.map(mapDetectionDto);
  return {
    ...(raw.file_id ? { fileId: raw.file_id } : {}),
    ...(raw.attached_file_ids ? { attachedFileIds: raw.attached_file_ids } : {}),
    ...(raw.group_final_action ? { groupFinalAction: raw.group_final_action } : {}),
    ...(raw.attached_files ? { attachedFiles: raw.attached_files.map(mapAttachedEventDto) } : {}),
    ...(raw.attached_to ? { attachedTo: raw.attached_to.map(mapAttachedEventDto) } : {}),
    eventId: raw.event_id,
    requestId: raw.request_id,
    occurredAt: raw.occurred_at,
    clientId: raw.client_id,
    userId: raw.user_id,
    tenantId: raw.tenant_id,
    detectionOutcome:
      raw.detection_outcome ?? (raw.detections.length ? 'MATCH' : 'UNAVAILABLE'),
    recommendedAction:
      raw.recommended_action ?? raw.detections[0]?.recommended_action,
    finalAction: raw.final_action ?? raw.action,
    severity: raw.severity,
    status: raw.status,
    assignee: raw.assignee,
    adminNotes: raw.admin_notes.map((note) => ({
      noteId: note.note_id,
      author: note.author,
      createdAt: note.created_at,
      content: note.content,
    })),
    timeline: raw.timeline.map((item) => ({
      timelineId: item.timeline_id,
      occurredAt: item.occurred_at,
      actor: item.actor,
      type: item.type,
      summary: item.summary,
    })),
    detections,
    targetLlm: raw.target_llm,
    host: raw.host,
    endpoint: raw.endpoint,
    contentType: raw.content_type,
    processingMs: raw.processing_ms,
    enforcement: raw.enforcement
      ? {
          applied: raw.enforcement.applied,
          httpStatus: raw.enforcement.http_status,
        }
      : undefined,
    degraded: raw.degraded,
    degradedReason: raw.degraded_reason,
    failurePolicy: raw.failure_policy,
    detectorVersion: raw.detector_version,
    rulesetVersion: raw.ruleset_version,
    modelVersion: raw.model_version,
    reasonCode: raw.reason_code,
    policyVersion: raw.policy_version,
    ...(raw.access_rule_id ? { accessRuleId: raw.access_rule_id } : {}),
  };
}

export const mapDocumentDto = (
  raw: ConfidentialDocumentDto,
): ConfidentialDocument => ({
  documentId: raw.document_id,
  documentName: raw.document_name,
  registeredAt: raw.registered_at,
  status: raw.status,
  processingStatus: raw.processing_status,
  fileType: raw.file_type,
  fileSize: raw.file_size,
  exactFingerprintStatus: raw.exact_fingerprint_status,
  similarityFingerprintStatus: raw.similarity_fingerprint_status,
  chunkIndexStatus: raw.chunk_index_status,
  chunkCount: raw.chunk_count,
  version: raw.version,
  classification: raw.classification,
  owner: raw.owner,
  activeDetectors: raw.active_detectors ?? [],
  exactDetectionCount: raw.exact_detection_count,
  modifiedPartialDetectionCount: raw.modified_partial_detection_count,
  lastDetectedAt: raw.last_detected_at,
});
export const mapPolicyVersionDto = (raw: PolicyVersionDto): PolicyVersion => ({
  version: raw.version,
  action: raw.action,
  actionVariant: raw.action_variant,
  policyAction: raw.policy_action ?? toPolicyAction(raw.action_variant) ?? toPolicyAction(raw.action) ?? 'MASK_FULL',
  createdAt: raw.created_at,
  changedBy: raw.changed_by,
  enabled: raw.enabled,
});
export const mapPolicyDto = (raw: DetectionPolicyDto): DetectionPolicy => ({
  policyId: raw.policy_id,
  detector: raw.detector,
  detectionTarget: raw.detection_target,
  action: raw.action,
  actionVariant: raw.action_variant,
  recommendedAction: raw.recommended_action,
  enforcementAction: raw.enforcement_action,
  // 응답 스키마가 채운 4종. 예시 연결(모의 DTO)처럼 없으면 원값(action_variant) → 색 계열 순으로 바꾼다
  policyAction: raw.policy_action ?? toPolicyAction(raw.action_variant) ?? toPolicyAction(raw.action) ?? 'MASK_FULL',
  finalPolicyAction: raw.final_policy_action ?? toPolicyAction(raw.action_variant) ?? toPolicyAction(raw.enforcement_action ?? raw.action) ?? 'MASK_FULL',
  recommendedPolicyAction: raw.recommended_policy_action ?? toPolicyAction(raw.recommended_action),
  targetLlms: raw.target_llms ?? [],
  documentClassification: raw.document_classification,
  failurePolicy: raw.failure_policy,
  priority: raw.priority,
  updatedBy: raw.updated_by,
  updatedAt: raw.updated_at,
  version: raw.version,
  enabled: raw.enabled,
  versions: (raw.versions ?? []).map(mapPolicyVersionDto),
});
export const mapPolicyCapabilitiesDto = (raw: PolicyCapabilitiesDto): PolicyCapabilities => ({
  catalogVersion: raw.catalog_version,
  catalogSource: raw.catalog_source,
  runtimeVerified: raw.runtime_verified,
  targets: raw.targets.map((target) => ({
    code: target.code,
    label: target.label,
    category: target.category,
    targetType: target.target_type,
    canCreate: target.can_create,
    allowedActions: [...target.allowed_actions],
    partialMasking: target.partial_masking ?? undefined,
    requiresContext: target.requires_context === true,
    runtimeAvailability: target.runtime_availability,
  })),
  fullMasking: raw.full_masking,
  createsRecognizer: raw.creates_recognizer,
  warnings: raw.warnings ?? [],
});
export const mapAuditLogDto = (raw: AuditLogDto): AuditLog => ({
  auditId: raw.audit_id,
  occurredAt: raw.occurred_at,
  adminId: raw.admin_id,
  action: raw.action,
  targetType: raw.target_type,
  targetId: raw.target_id,
  changes: raw.changes
    ? {
        previousVersion: raw.changes.previous_version,
        newVersion: raw.changes.new_version,
        previousAction: raw.changes.previous_action,
        newAction: raw.changes.new_action,
        previousPolicyAction: raw.changes.previous_policy_action,
        newPolicyAction: raw.changes.new_policy_action,
        previousStatus: raw.changes.previous_status,
        newStatus: raw.changes.new_status,
        previousIncidentStatus: raw.changes.previous_incident_status,
        newIncidentStatus: raw.changes.new_incident_status,
        previousAssignee: raw.changes.previous_assignee,
        newAssignee: raw.changes.new_assignee,
        noteAdded: raw.changes.note_added,
        previousValue: raw.changes.previous_value,
        newValue: raw.changes.new_value,
        keyword: raw.changes.keyword,
        documentId: raw.changes.doc_id,
        recordedStatus: raw.changes.status,
        detectionApplied: raw.changes.applied,
        reportFrom: raw.changes.from,
        reportTo: raw.changes.to,
        useLlm: raw.changes.use_llm,
        jobId: raw.changes.job_id,
        retryOfJobId: raw.changes.retry_of_job_id,
        previousGpuState: raw.changes.previous_instance_state,
        newGpuState: raw.changes.new_instance_state,
        documentVersion: raw.changes.version,
        documentFormat: raw.changes.format,
        viewMode: raw.changes.mode,
        viewRef: raw.changes.view_ref,
      }
    : undefined,
  ...(raw.changes_unreadable ? { changesUnreadable: true } : {}),
  result: raw.result,
});
export const mapAdminUserDto = (raw: AdminUserDto): AdminUser => ({
  id: raw.id,
  email: raw.email,
  displayName: raw.display_name,
  role: raw.role,
});
export const mapPageDto = <TDto, TDomain>(
  raw: PageDto<TDto>,
  mapper: (value: TDto) => TDomain,
): PaginatedResult<TDomain> => ({
  items: raw.items.map(mapper),
  total: raw.total,
  page: raw.page,
  pageSize: raw.page_size,
  totalPages: raw.total_pages,
  ...(raw.excluded_test !== undefined ? { excludedTest: raw.excluded_test } : {}),
  ...(raw.view_totals ? { viewTotals: { counted: raw.view_totals.counted, access: raw.view_totals.access, all: raw.view_totals.all } } : {}),
  ...(raw.skipped ? { skipped: raw.skipped } : {}),
  ...(raw.partial ? { partial: raw.partial } : {}),
});
export const mapDashboardStatsDto = (
  raw: DashboardStatsDto,
): DashboardStats => ({
  total: raw.total,
  block: raw.block,
  mask: raw.mask,
  allow: raw.allow,
  degraded: raw.degraded,
  enforcementRate: raw.enforcement_rate,
  actionMismatch: raw.action_mismatch,
  newEvents: raw.new_events,
  averageProcessingMs: raw.average_processing_ms,
  detectionStatus: raw.detection_status ?? 'UNKNOWN',
  gatewayStatus: raw.gateway_status ?? 'UNKNOWN',
  ...(raw.gateway_metrics_status ? { gatewayMetricsStatus: raw.gateway_metrics_status } : {}),
  ...(raw.gateway_completed_requests !== undefined ? { gatewayCompletedRequests: raw.gateway_completed_requests } : {}),
  lastSuccessAt: raw.last_success_at,
  trend: raw.trend.map((point) => ({ ...point })),
  recent: raw.recent.map(mapSecurityEventDto).sort((a, b) => Date.parse(b.occurredAt) - Date.parse(a.occurredAt)),
  ...(raw.insights ? { insights: { entityCounts: raw.insights.entity_counts, documents: raw.insights.documents,
    llmActions: raw.insights.llm_actions, contentActions: raw.insights.content_actions, heatmap: raw.insights.heatmap,
    ...(raw.insights.category_counts ? { categoryCounts: raw.insights.category_counts } : {}),
    ...(raw.insights.entity_event_counts ? { entityEventCounts: raw.insights.entity_event_counts } : {}) } } : {}),
  ...(raw.counting ? { counting: { unit: raw.counting.unit, records: raw.counting.records, listTotal: raw.counting.list_total,
    accessBlocked: raw.counting.access_blocked, resendFolded: raw.counting.resend_folded,
    ...(raw.counting.resend_file !== undefined ? { resendFile: raw.counting.resend_file } : {}),
    ...(raw.counting.resend_prompt !== undefined ? { resendPrompt: raw.counting.resend_prompt } : {}), sensitive: raw.counting.sensitive,
    ...(raw.counting.last_degraded_at ? { lastDegradedAt: raw.counting.last_degraded_at } : {}) } } : {}),
});

// 연결 중인 IP(2026-10-12). 순서는 서버가 준 대로(마지막 활동이 최근인 순)
export const mapTrafficClientsDto = (raw: TrafficClientsDto): TrafficClients => ({
  receivedAt: raw.received_at ?? undefined,
  stale: raw.stale,
  windowSeconds: raw.window_seconds,
  clients: raw.clients.map((client) => ({
    ip: client.ip,
    clientId: client.client_id || undefined,
    connections: client.connections,
    inflight: client.inflight,
    waiting: client.waiting ?? 0,
    requests5m: client.requests_5m,
    targets: Object.entries(client.targets)
      .filter(([, count]) => count > 0)
      .map(([llm, count]) => ({ llm, count }))
      .sort((a, b) => b.count - a.count || a.llm.localeCompare(b.llm)),
    firstSeenAt: client.first_seen_at,
    lastSeenAt: client.last_seen_at,
  })),
});

export const mapTrafficSnapshotDto = (
  raw: TrafficSnapshotDto,
  period: TrafficSnapshot['period'],
): TrafficSnapshot => ({
  unavailableSections: raw.unavailable_sections,
  period,
  summary: {
    metricSource: raw.summary.metric_source,
    gatewayMetricsStatus: raw.summary.gateway_metrics_status,
    gatewayMetricsReceivedAt: raw.summary.gateway_metrics_received_at,
    gatewayMetricsAgeSec: raw.summary.gateway_metrics_age_sec,
    gatewayTotalRequests: raw.summary.gateway_total_requests,
    gatewayCompletedRequests: raw.summary.gateway_completed_requests,
    gatewayErrorRequests: raw.summary.gateway_error_requests,
    gatewayWindowSeconds: raw.summary.gateway_window_seconds,
    clientIdentityIncomplete: raw.summary.client_identity_incomplete,
    eventCount: raw.summary.event_count,
    latencySampleCount: raw.summary.latency_sample_count,
    activeClients: raw.summary.active_clients,
    concurrentRequests: raw.summary.concurrent_requests,
    requestsPerSec: raw.summary.requests_per_sec,
    averageLatencyMs: raw.summary.average_latency_ms,
    p95LatencyMs: raw.summary.p95_latency_ms,
    latencyUnavailableReason: raw.summary.latency_unavailable_reason,
    timeoutRate: raw.summary.timeout_rate,
    degradedRate: raw.summary.degraded_rate,
    gatewayStatus: raw.summary.gateway_status ?? 'UNKNOWN',
    ...(raw.summary.access_blocked !== undefined ? { accessBlocked: raw.summary.access_blocked } : {}),
    ...(raw.summary.gateway_inspected_requests !== undefined ? { gatewayInspectedRequests: raw.summary.gateway_inspected_requests } : {}),
    ...(raw.summary.gateway_error_basis ? { gatewayErrorBasis: raw.summary.gateway_error_basis } : {}),
    ...(raw.summary.gateway_client_cancelled_requests !== undefined ? { gatewayClientCancelledRequests: raw.summary.gateway_client_cancelled_requests } : {}),
    ...(raw.summary.gateway_status_reason ? { gatewayStatusReason: raw.summary.gateway_status_reason } : {}),
  },
  timeSeries: raw.time_series.map((point) => ({
    timestamp: point.timestamp,
    requestCount: point.request_count,
    allowCount: point.allow_count,
    maskCount: point.mask_count,
    blockCount: point.block_count,
    averageLatencyMs: point.average_latency_ms,
    p95LatencyMs: point.p95_latency_ms,
  })),
});
