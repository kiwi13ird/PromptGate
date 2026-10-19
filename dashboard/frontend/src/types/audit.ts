import type { IncidentStatus, OverviewPeriod, SecurityAction } from './event';
import type { DocumentStatus, PolicyAction } from './policy';

export type AuditAction =
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
export type AuditResult = 'SUCCESS' | 'FAILURE';

export interface AuditChanges {
  previousVersion?: number;
  newVersion?: number;
  previousAction?: SecurityAction;
  newAction?: SecurityAction;
  /** 정책 처리 방식 4종(부분·전체 마스킹 구분, 2026-10-15). 있으면 '최종 조치' 줄이 이 값을 쓴다 */
  previousPolicyAction?: PolicyAction;
  newPolicyAction?: PolicyAction;
  previousStatus?: DocumentStatus;
  newStatus?: DocumentStatus;
  previousIncidentStatus?: IncidentStatus;
  newIncidentStatus?: IncidentStatus;
  previousAssignee?: string;
  newAssignee?: string;
  noteAdded?: boolean;
  previousValue?: string;
  newValue?: string;
  keyword?: string;
  documentId?: string;
  recordedStatus?: string;
  detectionApplied?: boolean;
  reportFrom?: string;
  reportTo?: string;
  useLlm?: boolean;
  jobId?: number;
  /** 키워드 추출 재시도(2026-10-15): 다시 돌린 실패 작업 번호 */
  retryOfJobId?: number;
  previousGpuState?: string;
  newGpuState?: string;
  /** 문서 열람·내려받기(2026-10-13): 판·형식·보기 방식·열람 번호(워터마크 번호) */
  documentVersion?: string;
  documentFormat?: string;
  viewMode?: 'original' | 'text' | 'download';
  viewRef?: string;
}

export interface AuditLog {
  auditId: string;
  occurredAt: string;
  adminId: string;
  action: AuditAction;
  targetType: 'ADMIN' | 'POLICY' | 'DOCUMENT' | 'EVENT' | 'REPORT' | 'KEYWORD' | 'GPU' | 'GATEWAY';
  targetId: string;
  changes?: AuditChanges;
  changesUnreadable?: boolean;
  result: AuditResult;
}

export interface AuditFilters {
  period: OverviewPeriod;
  action: AuditAction | 'ALL';
  result: AuditResult | 'ALL';
  admin: string;
  page: number;
  pageSize: number;
}
