import type { SecurityAction } from './event';

export type DocumentStatus = 'ACTIVE' | 'INACTIVE';
export type ProcessingStatus = 'PROCESSING' | 'READY' | 'FAILED';
export type FingerprintStatus =
  | 'PROCESSING'
  | 'READY'
  | 'NOT_AVAILABLE'
  | 'FAILED';

export interface ConfidentialDocument {
  documentId: string;
  documentName: string;
  registeredAt: string;
  status: DocumentStatus;
  processingStatus: ProcessingStatus;
  fileType: string;
  fileSize?: number;
  exactFingerprintStatus: FingerprintStatus;
  similarityFingerprintStatus: FingerprintStatus;
  chunkIndexStatus: FingerprintStatus;
  chunkCount: number;
  version?: string;
  classification?: 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  owner?: string;
  activeDetectors: Array<'SHA256' | 'WINDOW_HASH' | 'MINHASH' | 'SIGNATURE'>;
  exactDetectionCount?: number;
  modifiedPartialDetectionCount?: number;
  lastDetectedAt?: string;
}

/**
 * 정책 전용 처리 방식 4종(2026-10-14 정책 API). 이벤트·통계의 SecurityAction(ALLOW/MASK/BLOCK)과 따로 둔다.
 * 옛 값(ALLOW_NOTIFY·BLOCK_NOTIFY·MASK)은 읽을 때만 바꾼다(utils/policyActions.ts toPolicyAction).
 */
export type PolicyAction = 'ALLOW' | 'BLOCK' | 'MASK_PARTIAL' | 'MASK_FULL';

/** GET /api/policies/capabilities 의 대상 1개(서버가 검토한 설정 목록, 실행 중 규칙을 읽은 값 아님) */
export interface PolicyCapabilityTarget {
  code: string;
  label: string;
  /** PII · CREDENTIAL */
  category: string;
  /** CATEGORY(분류 전체) · ENTITY_TYPE(개별 항목) */
  targetType: string;
  canCreate: boolean;
  allowedActions: PolicyAction[];
  partialMasking?: string;
  requiresContext: boolean;
  runtimeAvailability?: string;
}

export interface PolicyCapabilities {
  catalogVersion: string;
  catalogSource?: string;
  runtimeVerified: boolean;
  targets: PolicyCapabilityTarget[];
  /** ENTITY_PLACEHOLDER = [EMAIL_ADDRESS] 같은 항목 표시로 교체 */
  fullMasking?: string;
  createsRecognizer?: boolean;
  warnings: string[];
}

export interface PolicyVersion {
  version: number;
  action: SecurityAction;
  actionVariant?: string;
  /** 4종 처리 방식(옛 값은 변환) */
  policyAction: PolicyAction;
  createdAt: string;
  changedBy: string;
  enabled: boolean;
}

export interface DetectionPolicy {
  policyId: string;
  detector: 'SHA256' | 'WINDOW_HASH' | 'MINHASH' | 'SIGNATURE' | 'DOCUMENT';
  detectionTarget: string;
  /** 색 계열(허용·마스킹·차단). 선택·비교·전송에는 policyAction을 쓴다 */
  action: SecurityAction;
  actionVariant?: string;
  recommendedAction?: SecurityAction;
  enforcementAction?: SecurityAction;
  /** 설정된 처리 방식 4종(수정 비교·전송 기준) */
  policyAction: PolicyAction;
  /** 최종 집행 처리 방식 4종(enforcement_action ?? action) */
  finalPolicyAction: PolicyAction;
  recommendedPolicyAction?: PolicyAction;
  targetLlms: string[];
  documentClassification?: 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  failurePolicy?: 'FAIL_OPEN' | 'FAIL_CLOSED';
  priority?: number;
  updatedBy?: string;
  updatedAt?: string;
  version: number;
  enabled: boolean;
  versions: PolicyVersion[];
}
