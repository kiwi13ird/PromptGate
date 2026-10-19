import type { DocumentStatus, PolicyAction } from '@/src/types/policy';
import type {
  AuditLogDto,
  ConfidentialDocumentDto,
  DashboardStatsDto,
  DetectionPolicyDto,
  PageDto,
  PolicyCapabilitiesDto,
  PolicyVersionDto,
  SecurityEventDto,
  TrafficClientsDto,
  TrafficSnapshotDto,
} from './dto';
import type { AuditFilters } from '@/src/types/audit';
import type {
  GatewaySettingsResponse,
  GatewaySettingsSaveBody,
} from './gatewaySettingsSchemas';
import type {
  AccessModeBody,
  AccessRuleCreateBody,
  AccessWriteResult,
  ClientAliasesResponse,
  GatewayAccessResponse,
} from './gatewayAccessSchemas';
import type {
  EventFilters,
  IncidentStatus,
  OverviewPeriod,
  SecurityAction,
} from '@/src/types/event';

export interface GatewayApi {
  getDashboardStats(
    period: OverviewPeriod,
    signal?: AbortSignal,
  ): Promise<DashboardStatsDto>;
  getTrafficSnapshot(
    period: OverviewPeriod,
    signal?: AbortSignal,
  ): Promise<TrafficSnapshotDto>;
  getTrafficClients(signal?: AbortSignal): Promise<TrafficClientsDto>;
  getEvents(
    filters: EventFilters,
    signal?: AbortSignal,
  ): Promise<PageDto<SecurityEventDto>>;
  getEvent(
    eventId: string,
    signal?: AbortSignal,
  ): Promise<SecurityEventDto | null>;
  updateEventStatus(
    eventId: string,
    status: IncidentStatus,
    signal?: AbortSignal,
  ): Promise<SecurityEventDto>;
  assignEvent(
    eventId: string,
    assignee: string,
    signal?: AbortSignal,
  ): Promise<SecurityEventDto>;
  addEventNote(
    eventId: string,
    content: string,
    signal?: AbortSignal,
  ): Promise<SecurityEventDto>;
  getDocuments(signal?: AbortSignal): Promise<ConfidentialDocumentDto[]>;
  registerDocument(
    file: File,
    signal?: AbortSignal,
  ): Promise<ConfidentialDocumentDto>;
  changeDocumentStatus(
    documentId: string,
    status: DocumentStatus,
    signal?: AbortSignal,
  ): Promise<ConfidentialDocumentDto>;
  getPolicies(signal?: AbortSignal): Promise<DetectionPolicyDto[]>;
  /** 지원 대상·처리 방식 목록(대시보드 서버 설정 목록, Detection 호출 없음) */
  getPolicyCapabilities(signal?: AbortSignal): Promise<PolicyCapabilitiesDto>;
  getPolicyHistory(
    policyId: string,
    signal?: AbortSignal,
  ): Promise<PolicyVersionDto[]>;
  createPolicy(
    detectionTarget: string,
    action: PolicyAction,
    signal?: AbortSignal,
  ): Promise<DetectionPolicyDto>;
  updatePolicy(
    policyId: string,
    action: PolicyAction,
    expectedVersion: number,
    signal?: AbortSignal,
  ): Promise<DetectionPolicyDto>;
  changePolicyStatus(
    policyId: string,
    enabled: boolean,
    expectedVersion: number,
    signal?: AbortSignal,
  ): Promise<DetectionPolicyDto>;
  getAuditLogs(
    filters: AuditFilters,
    signal?: AbortSignal,
  ): Promise<PageDto<AuditLogDto>>;
  getGatewaySettings(signal?: AbortSignal): Promise<GatewaySettingsResponse>;
  saveGatewaySettings(
    body: GatewaySettingsSaveBody,
    signal?: AbortSignal,
  ): Promise<GatewaySettingsResponse>;
  // 접속 차단(2026-10-12)
  getGatewayAccess(signal?: AbortSignal): Promise<GatewayAccessResponse>;
  addAccessRule(body: AccessRuleCreateBody, signal?: AbortSignal): Promise<AccessWriteResult>;
  removeAccessRule(ruleId: string, expectedVersion: number, signal?: AbortSignal): Promise<AccessWriteResult>;
  setAccessMode(body: AccessModeBody, signal?: AbortSignal): Promise<AccessWriteResult>;
  getClientAliases(signal?: AbortSignal): Promise<ClientAliasesResponse>;
  setClientAlias(clientId: string, alias: string, signal?: AbortSignal): Promise<void>;
}
