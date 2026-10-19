export type SecurityActionDto = 'ALLOW' | 'BLOCK' | 'MASK';
/** 정책 전용 처리 방식 4종(이벤트의 SecurityActionDto와 따로) */
export type PolicyActionDto = 'ALLOW' | 'BLOCK' | 'MASK_PARTIAL' | 'MASK_FULL';
export type TargetLlmDto =
  | 'ChatGPT'
  | 'Gemini'
  | 'Claude';
export type SeverityDto = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatusDto = 'NEW' | 'INVESTIGATING' | 'RESOLVED';

export interface Sha256DetectionDto {
  detector: 'SHA256';
  match_type: 'EXACT_DOCUMENT';
  outbound_document_name: string;
  matched_document_id: string;
  matched_document_name?: string;
  action: 'BLOCK';
  recommended_action?: 'BLOCK';
}

export interface SimilarDocumentDetectionDto {
  detector: 'MINHASH';
  match_type: 'SIMILAR_DOCUMENT';
  similarity: number;
  threshold: number;
  outbound_document_name: string;
  matched_document_id: string;
  matched_document_name?: string;
  action: SecurityActionDto;
  recommended_action?: SecurityActionDto;
}

export type MinHashDetectionDto = SimilarDocumentDetectionDto;

export interface SignatureDetectionDto {
  detector: 'SIGNATURE';
  match_type: 'SIGNATURE_RULE';
  category?: string;
  rule_id?: string;
  policy_id?: string;
  policy_version?: string;
  action: SecurityActionDto;
  recommended_action?: SecurityActionDto;
  confidence?: number;
  entity_count?: number;
  entity_counts?: Array<{
    entity_type: string;
    count: number;
  }>;
}

export interface WindowHashDetectionDto {
  detector: 'WINDOW_HASH';
  match_type: 'TEXT_FRAGMENT';
  score: number;
  score_kind: 'COVERAGE';
  threshold?: number | null;
  matched_document_id: string;
  matched_document_name?: string;
  input_location?: {
    char_start: number;
    char_end: number;
  };
  matched_location: {
    char_start: number;
    char_end: number;
  };
  action: SecurityActionDto;
  recommended_action?: SecurityActionDto;
  same_text?: { state: 'READY' | 'PENDING' | 'UNAVAILABLE'; same_chars?: number; input_chars?: number; differences?: number; reason?: string };
}

export type DetectionDto =
  | Sha256DetectionDto
  | MinHashDetectionDto
  | WindowHashDetectionDto
  | SignatureDetectionDto;

export interface IncidentNoteDto {
  note_id: string;
  author: string;
  created_at: string;
  content: string;
}
export interface IncidentTimelineItemDto {
  timeline_id: string;
  occurred_at: string;
  actor: string;
  type: 'DETECTED' | 'STATUS_CHANGED' | 'ASSIGNEE_CHANGED' | 'NOTE_ADDED';
  summary: string;
}

export interface AttachedEventDto {
  event_id: string;
  request_id?: string;
  occurred_at: string;
  action?: SecurityActionDto;
  final_action?: SecurityActionDto;
  content_type?: 'prompt' | 'file';
  detection_outcome?: 'MATCH' | 'NO_MATCH' | 'UNAVAILABLE';
  detections?: DetectionDto[];
  enforcement?: { applied: boolean; http_status?: number };
  reason_code?: string;
  degraded?: boolean;
}

export interface SecurityEventDto {
  event_id: string;
  request_id?: string;
  occurred_at: string;
  client_id: string;
  user_id?: string;
  tenant_id?: string;
  action: SecurityActionDto;
  final_action?: SecurityActionDto;
  recommended_action?: SecurityActionDto;
  detection_outcome?: 'MATCH' | 'NO_MATCH' | 'UNAVAILABLE';
  severity?: SeverityDto;
  status: IncidentStatusDto;
  assignee?: string;
  admin_notes: IncidentNoteDto[];
  timeline: IncidentTimelineItemDto[];
  detections: DetectionDto[];
  target_llm: TargetLlmDto;
  host?: string;
  endpoint?: string;
  content_type?: 'prompt' | 'file';
  processing_ms?: number;
  enforcement?: {
    applied: boolean;
    http_status?: number;
  };
  degraded?: boolean;
  degraded_reason?: 'TIMEOUT' | 'UNREACHABLE' | 'PARSE_ERROR' | 'OTHER';
  failure_policy?: 'FAIL_OPEN' | 'FAIL_CLOSED';
  detector_version?: string;
  ruleset_version?: string;
  model_version?: string;
  reason_code?: string;
  policy_version?: string;
  /** 접속 차단(관리자) 이벤트의 규칙 번호(2026-10-12) */
  access_rule_id?: string;
  // 질문과 첨부 파일 연결 (2026-10-09)
  file_id?: string;
  attached_file_ids?: string[];
  group_final_action?: SecurityActionDto;
  attached_files?: AttachedEventDto[];
  attached_to?: AttachedEventDto[];
}

export interface PageDto<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  excluded_test?: number;
  view_totals?: { counted: number; access: number; all: number };
  skipped?: number;
  partial?: number;
}
export interface TrendPointDto {
  bucket: string;
  total: number;
  block: number;
  mask: number;
  allow?: number;
}
export interface DashboardStatsDto {
  total: number;
  block: number;
  mask: number;
  allow?: number;
  degraded?: number;
  enforcement_rate?: number;
  action_mismatch?: number;
  new_events: number;
  average_processing_ms: number;
  detection_status?: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN';
  gateway_status?: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN';
  gateway_metrics_status?: 'FRESH' | 'STALE' | 'NOT_RECEIVED';
  gateway_completed_requests?: number;
  last_success_at?: string;
  trend: TrendPointDto[];
  recent: SecurityEventDto[];
  insights?: {
    entity_counts: Array<{ key: string; count: number }>;
    documents: Array<{ key: string; count: number; blocked?: number; name?: string }>;
    llm_actions: Array<{ key: string; block: number; mask: number; allow: number }>;
    content_actions: Array<{ key: string; block: number; mask: number; allow: number }>;
    heatmap: number[][];
    category_counts?: Array<{ key: 'PII' | 'CREDENTIAL' | 'KEYWORD'; events: number; values: number }>;
    entity_event_counts?: Array<{ key: string; count: number }>;
  };
  counting?: {
    unit: 'REQUEST';
    records: number;
    list_total: number;
    access_blocked: number;
    resend_file?: number;     // 2026-10-16 공통 규칙: 10/11 전 파일 재전송
    resend_prompt?: number;   // 2026-10-16 공통 규칙: 4.348초 안 같은 질문 재시도
    resend_folded: number;
    sensitive: number;
    last_degraded_at?: string;
  };
}

export type DocumentStatusDto = 'ACTIVE' | 'INACTIVE';
export type ProcessingStatusDto = 'PROCESSING' | 'READY' | 'FAILED';
export type FingerprintStatusDto =
  | 'PROCESSING'
  | 'READY'
  | 'NOT_AVAILABLE'
  | 'FAILED';
export interface ConfidentialDocumentDto {
  document_id: string;
  document_name: string;
  registered_at: string;
  status: DocumentStatusDto;
  processing_status: ProcessingStatusDto;
  file_type: string;
  file_size?: number;
  exact_fingerprint_status: FingerprintStatusDto;
  similarity_fingerprint_status: FingerprintStatusDto;
  chunk_index_status: FingerprintStatusDto;
  chunk_count: number;
  version?: string;
  classification?: 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  owner?: string;
  active_detectors?: Array<'SHA256' | 'WINDOW_HASH' | 'MINHASH' | 'SIGNATURE'>;
  exact_detection_count?: number;
  modified_partial_detection_count?: number;
  last_detected_at?: string;
}

export interface PolicyVersionDto {
  version: number;
  action: SecurityActionDto;
  action_variant?: string;
  /** 4종(응답 스키마가 채움. 없으면 action_variant·action에서 바꿈) */
  policy_action?: PolicyActionDto;
  created_at: string;
  changed_by: string;
  enabled: boolean;
}
export interface DetectionPolicyDto {
  policy_id: string;
  detector: 'SHA256' | 'WINDOW_HASH' | 'MINHASH' | 'SIGNATURE' | 'DOCUMENT';
  detection_target: string;
  action: SecurityActionDto;
  action_variant?: string;
  recommended_action?: SecurityActionDto;
  enforcement_action?: SecurityActionDto;
  policy_action?: PolicyActionDto;
  final_policy_action?: PolicyActionDto;
  recommended_policy_action?: PolicyActionDto;
  target_llms?: TargetLlmDto[];
  document_classification?: 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  failure_policy?: 'FAIL_OPEN' | 'FAIL_CLOSED';
  priority?: number;
  updated_by?: string;
  updated_at?: string;
  version: number;
  enabled: boolean;
  versions?: PolicyVersionDto[];
}

export interface PolicyCapabilityTargetDto {
  code: string;
  label: string;
  category: string;
  target_type: string;
  can_create: boolean;
  allowed_actions: PolicyActionDto[];
  partial_masking?: string;
  requires_context?: boolean;
  runtime_availability?: string;
}
export interface PolicyCapabilitiesDto {
  catalog_version: string;
  catalog_source?: string;
  runtime_verified: boolean;
  actions?: Array<{ code: string; label?: string }>;
  targets: PolicyCapabilityTargetDto[];
  full_masking?: string;
  creates_recognizer?: boolean;
  warnings?: string[];
}

export type AuditActionDto =
  | 'ADMIN_LOGIN'
  | 'ADMIN_LOGOUT'
  | 'POLICY_CREATE'
  | 'POLICY_UPDATE'
  | 'POLICY_ENABLE'
  | 'POLICY_DISABLE'
  | 'DOCUMENT_REGISTER'
  | 'DOCUMENT_ENABLE'
  | 'DOCUMENT_DISABLE'
  | 'EVENT_ASSIGNED'
  | 'EVENT_STATUS_CHANGED'
  | 'EVENT_NOTE_ADDED'
  | 'REPORT_CREATE'
  | 'KEYWORD_CREATE'
  | 'KEYWORD_APPROVE'
  | 'KEYWORD_REJECT'
  | 'KEYWORD_UPDATE'
  | 'KEYWORD_EXTRACT_REQUEST'
  | 'GPU_START'
  | 'GPU_STOP'
  | 'GATEWAY_SETTINGS_UPDATE'
  | 'ACCESS_RULE_ADD'
  | 'ACCESS_RULE_REMOVE'
  | 'ACCESS_MODE_UPDATE'
  | 'CLIENT_ALIAS_UPDATE'
  | 'DOCUMENT_VIEW'
  | 'DOCUMENT_DOWNLOAD';
export interface AuditChangesDto {
  previous_version?: number;
  new_version?: number;
  previous_action?: SecurityActionDto;
  new_action?: SecurityActionDto;
  previous_policy_action?: PolicyActionDto;
  new_policy_action?: PolicyActionDto;
  previous_status?: DocumentStatusDto;
  new_status?: DocumentStatusDto;
  previous_incident_status?: IncidentStatusDto;
  new_incident_status?: IncidentStatusDto;
  previous_assignee?: string;
  new_assignee?: string;
  note_added?: boolean;
  previous_value?: string;
  new_value?: string;
  // 리포트·키워드 작업(2026-10) - 백엔드 detectionOps 블록이 남기는 값
  keyword?: string;
  doc_id?: string;
  status?: string;
  applied?: boolean;
  from?: string;
  to?: string;
  use_llm?: boolean;
  job_id?: number;
  retry_of_job_id?: number;
  // GPU 켜기·끄기(2026-10-07) - EC2 상태 이름
  previous_instance_state?: string;
  new_instance_state?: string;
  // 문서 열람·내려받기(2026-10-13)
  version?: string;
  format?: string;
  mode?: 'original' | 'text' | 'download';
  view_ref?: string;
}
export interface AuditLogDto {
  audit_id: string;
  occurred_at: string;
  admin_id: string;
  action: AuditActionDto;
  target_type: 'ADMIN' | 'POLICY' | 'DOCUMENT' | 'EVENT' | 'REPORT' | 'KEYWORD' | 'GPU' | 'GATEWAY';
  target_id: string;
  changes?: AuditChangesDto;
  changes_unreadable?: boolean;   // 바뀐 값이 기록됐지만 화면이 형식을 읽지 못함
  result: 'SUCCESS' | 'FAILURE';
}

export interface AdminUserDto {
  id: string;
  email: string;
  display_name: string;
  role: string;
}

export interface TrafficSummaryDto {
  access_blocked?: number;
  gateway_inspected_requests?: number;
  gateway_error_basis?: 'GATEWAY_ERRORS' | 'ALL_DISCONNECTS';
  gateway_client_cancelled_requests?: number;
  gateway_status_reason?: string;
  metric_source?: 'GATEWAY_LIVE' | 'STORED_EVENTS';
  gateway_metrics_status?: 'FRESH' | 'STALE' | 'NOT_RECEIVED';
  gateway_metrics_received_at?: string;
  gateway_metrics_age_sec?: number;
  gateway_total_requests?: number;
  gateway_completed_requests?: number;
  gateway_error_requests?: number;
  gateway_window_seconds?: number;
  client_identity_incomplete?: boolean;
  event_count?: number;
  latency_sample_count?: number;
  active_clients?: number;
  concurrent_requests?: number;
  requests_per_sec?: number;
  average_latency_ms?: number;
  p95_latency_ms?: number;
  latency_unavailable_reason?: 'LEGACY_GATEWAY';
  timeout_rate?: number;
  degraded_rate?: number;
  gateway_status?: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN';
}
export interface TrafficTimeBucketDto {
  timestamp: string;
  request_count: number;
  allow_count: number;
  mask_count: number;
  block_count: number;
  average_latency_ms?: number;
  p95_latency_ms?: number;
}
// 연결 중인 IP(2026-10-12): GET /api/traffic/clients
export interface TrafficClientDto {
  ip: string;
  client_id: string | null;
  connections: number;
  inflight: number;
  /** 30초 넘게 응답을 받는 중인 요청 수. 옛 백엔드·Gateway는 보내지 않음(0으로 본다) */
  waiting?: number;
  requests_5m: number;
  targets: Record<string, number>;
  first_seen_at: string;
  last_seen_at: string;
}
export interface TrafficClientsDto {
  received_at: string | null;
  stale: boolean;
  window_seconds: number;
  clients: TrafficClientDto[];
}
export interface TrafficSnapshotDto {
  unavailable_sections?: string[];
  summary: TrafficSummaryDto;
  time_series: TrafficTimeBucketDto[];
}
