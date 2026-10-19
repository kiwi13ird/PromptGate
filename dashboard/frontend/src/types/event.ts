export type SecurityAction = 'ALLOW' | 'BLOCK' | 'MASK';
export type DetectorType =
  | 'SHA256'
  | 'MINHASH'
  | 'WINDOW_HASH'
  | 'SIGNATURE';
export type MatchType =
  | 'EXACT_DOCUMENT'
  | 'SIMILAR_DOCUMENT'
  | 'TEXT_FRAGMENT'
  | 'SIGNATURE_RULE';
export type ScoreKind = 'COVERAGE' | 'SIMILARITY' | 'CONFIDENCE';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED';
export type TargetLlm =
  | 'ChatGPT'
  | 'Gemini'
  | 'Claude';
export type ContentType = 'prompt' | 'file';
export type DetectionOutcome = 'MATCH' | 'NO_MATCH' | 'UNAVAILABLE';
export type FailurePolicy = 'FAIL_OPEN' | 'FAIL_CLOSED';
export type DegradedReason = 'TIMEOUT' | 'UNREACHABLE' | 'PARSE_ERROR' | 'OTHER';
export type OverviewPeriod = '24H' | '7D' | '30D';
export type EventSort =
  | 'OCCURRED_AT_DESC'
  | 'OCCURRED_AT_ASC'
  | 'SEVERITY_DESC';

export interface SafeMatchEvidence {
  outboundDocumentName?: string;
  matchedDocumentId: string;
  matchedDocumentName?: string;
  matchedChunkId?: string;
  page?: number;
  section?: string;
}

export interface CharacterSpan {
  charStart: number;
  charEnd: number;
  endExclusive: true;
}

export interface Sha256Detection extends SafeMatchEvidence {
  detector: 'SHA256';
  matchType: 'EXACT_DOCUMENT';
  recommendedAction?: 'BLOCK';
}

export interface SimilarDocumentDetection extends SafeMatchEvidence {
  detector: 'MINHASH';
  matchType: 'SIMILAR_DOCUMENT';
  outboundDocumentName: string;
  similarity: number;
  threshold: number;
  recommendedAction?: SecurityAction;
}

export interface SignatureDetection {
  detector: 'SIGNATURE';
  matchType: 'SIGNATURE_RULE';
  category?: string;
  ruleId?: string;
  policyId?: string;
  policyVersion?: string;
  confidence?: number;
  scoreKind: 'CONFIDENCE';
  entityCount?: number;
  entityCounts?: Array<{
    entityType: string;
    count: number;
  }>;
  recommendedAction?: SecurityAction;
}

export interface WindowHashDetection {
  detector: 'WINDOW_HASH';
  matchType: 'TEXT_FRAGMENT';
  score: number;
  scoreKind: 'COVERAGE';
  threshold?: number;
  matchedDocumentId: string;
  matchedDocumentName?: string;
  inputSpan?: CharacterSpan;
  documentSpan: CharacterSpan;
  recommendedAction?: SecurityAction;
  /** 입력 중 보호 문서와 같은 글자 비율(대시보드 서버 계산, 이벤트 상세 대조와 같은 원본). score는 Detection 해시 근거 비율 */
  sameText?: { state: 'READY' | 'PENDING' | 'UNAVAILABLE'; sameChars?: number; inputChars?: number; differences?: number; reason?: string };
}

export type MinHashDetection = SimilarDocumentDetection;
export type Detection =
  | Sha256Detection
  | MinHashDetection
  | WindowHashDetection
  | SignatureDetection;

export interface EnforcementResult {
  applied: boolean;
  httpStatus?: number;
}

export interface IncidentNote {
  noteId: string;
  author: string;
  createdAt: string;
  content: string;
}

export interface IncidentTimelineItem {
  timelineId: string;
  occurredAt: string;
  actor: string;
  type: 'DETECTED' | 'STATUS_CHANGED' | 'ASSIGNEE_CHANGED' | 'NOTE_ADDED';
  summary: string;
}

export interface AttachedEvent {
  eventId: string;
  requestId?: string;
  occurredAt: string;
  finalAction: SecurityAction;
  contentType?: ContentType;
  detectionOutcome?: DetectionOutcome;
  detections: Detection[];
  enforcement?: EnforcementResult;
  /** 목록 묶음의 첨부 파일 사유(2026-10-15, 보안 현황 사유·검사 못 한 요청 계산용). 상세 요약에는 없음 */
  reasonCode?: string;
  degraded?: boolean;
}

export interface SecurityEvent {
  eventId: string;
  requestId?: string;
  occurredAt: string;
  clientId: string;
  userId?: string;
  tenantId?: string;
  detectionOutcome: DetectionOutcome;
  recommendedAction?: SecurityAction;
  finalAction: SecurityAction;
  severity?: Severity;
  status: IncidentStatus;
  assignee?: string;
  adminNotes: IncidentNote[];
  timeline: IncidentTimelineItem[];
  detections: Detection[];
  targetLlm: TargetLlm;
  host?: string;
  endpoint?: string;
  contentType?: ContentType;
  processingMs?: number;
  enforcement?: EnforcementResult;
  degraded?: boolean;
  degradedReason?: DegradedReason;
  failurePolicy?: FailurePolicy;
  detectorVersion?: string;
  rulesetVersion?: string;
  modelVersion?: string;
  reasonCode?: string;
  policyVersion?: string;
  /** 접속 차단(관리자)으로 막힌 요청의 규칙 번호. 차단 번호는 앞 8자 */
  accessRuleId?: string;
  fileId?: string;
  attachedFileIds?: string[];
  groupFinalAction?: SecurityAction;
  attachedFiles?: AttachedEvent[];
  attachedTo?: AttachedEvent[];
}

export interface EventFilters {
  query: string;
  period: OverviewPeriod;
  finalAction: SecurityAction | 'ALL';
  recommendedAction: SecurityAction | 'ALL';
  detector: DetectorType | 'ALL';
  matchType: MatchType | 'ALL';
  scoreKind: ScoreKind | 'ALL';
  degraded: 'ALL' | 'YES' | 'NO';
  detectionOutcome: DetectionOutcome | 'ALL';
  degradedReason: DegradedReason | 'ALL';
  failurePolicy: FailurePolicy | 'ALL';
  documentId: string;
  severity: Severity | 'ALL';
  status: IncidentStatus | 'ALL';
  targetLlm: TargetLlm | 'ALL';
  sort: EventSort;
  page: number;
  pageSize: number;
  // 'request': 프롬프트와 첨부 파일을 한 줄로 묶는다. 보안 이벤트 목록 화면만 쓰고, 차트·집계용 조회는 묶지 않는다
  group?: 'request';
  // 시험·데모 기록 포함(기본은 제외, 2026-10-10)
  includeTest?: boolean;
  // 탐지 정보 종류: 개인정보·자격증명·기밀 키워드(2026-10-10)
  entityCategory?: 'ALL' | 'PII' | 'CREDENTIAL' | 'KEYWORD';
  // 집계와 같은 기록만(2026-10-15): counted = 접속 차단·재전송 제외(보안 현황), inspected = 접속 차단 제외(트래픽 저장 기록).
  // 2026-10-16 목록 화면 보기: counted = 보안 이벤트(기본, 카드와 같은 기록) · access = 접속 차단 기록 · 없음 = 전체 기록
  scope?: 'counted' | 'inspected' | 'access';
}

/** 보안 이벤트 목록 보기별 건수(같은 조회 조건, 2026-10-16). 새 서버가 counted·access로 물을 때만 준다 */
export interface EventViewTotals {
  counted: number;
  access: number;
  all: number;
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
  excludedTest?: number;   // 같은 조건에서 빠진 시험·데모 기록 수
  viewTotals?: EventViewTotals;   // 보안 이벤트 목록 보기별 건수(2026-10-16)
  skipped?: number;   // 형식을 읽지 못해 표시하지 않은 줄 수(감사 로그)
  partial?: number;   // 바뀐 값만 읽지 못한 줄 수(감사 로그)
}

export interface TrendPoint {
  bucket: string;
  total: number;
  block: number;
  mask: number;
  allow?: number;
}

export interface CountPoint {
  key: string;
  count: number;
  blocked?: number;
}

// 보안 현황 그래프용 집계(2026-10-10)
export interface ActionCounts {
  key: string;
  block: number;
  mask: number;
  allow: number;
}

export interface OverviewInsights {
  entityCounts: CountPoint[];   // 탐지된 값의 개수
  documents: Array<CountPoint & { name?: string }>;
  llmActions: ActionCounts[];
  contentActions: ActionCounts[];
  heatmap: number[][];   // [요일 0=일요일][시 0~23], 한국 시간, 차단·마스킹만
  categoryCounts?: Array<{ key: 'PII' | 'CREDENTIAL' | 'KEYWORD'; events: number; values: number }>;   // 정책 분류별 적중
  entityEventCounts?: CountPoint[];   // 유형별로 그 유형이 나온 이벤트 수
}

export interface DashboardStats {
  total: number;
  block: number;
  mask: number;
  allow?: number;
  degraded?: number;
  enforcementRate?: number;
  actionMismatch?: number;
  newEvents: number;
  averageProcessingMs: number;
  detectionStatus: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN';
  gatewayStatus: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN';
  // Gateway 실시간 지표 수신 상태(최근 2분)와 완료 요청 수 — 보안 현황 Gateway 표시용(2026-10-10)
  gatewayMetricsStatus?: 'FRESH' | 'STALE' | 'NOT_RECEIVED';
  gatewayCompletedRequests?: number;
  lastSuccessAt?: string;
  trend: TrendPoint[];
  recent: SecurityEvent[];
  insights?: OverviewInsights;
  visualization?: import('@/src/utils/eventSeries').EventSeries;
  /** 추이 검증용으로 읽은 기간 이벤트 목록(시험·데모 제외). 보안 현황 추가 지표 계산용(재설계 3b). 못 읽으면 없음.
   * counting이 있으면(새 서버) 카드와 같은 기록: 요청 단위 묶음(첨부 파일은 attachedFiles), 접속 차단·재전송 제외 */
  periodEvents?: SecurityEvent[];
  /** 집계 기준(2026-10-15 숫자 감사). 옛 서버는 없음 → 화면은 옛 방식(기록 단위·접속 차단 포함)으로 계산 */
  counting?: DashboardCounting;
}

export interface DashboardCounting {
  /** 카드·추이·최근 이벤트의 단위: 요청(첨부 파일은 프롬프트에 묶음 = 보안 이벤트 목록과 같은 묶음) */
  unit: 'REQUEST';
  /** 묶기 전 기록 수(프롬프트·파일 각각, 그래프의 단위) */
  records: number;
  /** 같은 기간 보안 이벤트 목록 건수(접속 차단·재전송 포함) */
  listTotal: number;
  /** 카드에서 뺀 접속 차단 기록 */
  accessBlocked: number;
  /** 접은 10/11 전 파일 재전송 기록(리포트와 같은 규칙) */
  resendFolded: number;
  resendFile?: number;     // 10/11 전 파일 재전송(2026-10-16, 새 서버)
  resendPrompt?: number;   // 4.348초 안 같은 질문 재시도(2026-10-16, 새 서버)
  /** 민감정보·기밀이 실제로 검출돼 차단·마스킹한 요청 */
  sensitive: number;
  /** 기간 중 마지막 Detection 오류(검사 응답 없음) 기록 시각 */
  lastDegradedAt?: string;
}
