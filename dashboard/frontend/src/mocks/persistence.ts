import type {
  AuditLogDto,
  ConfidentialDocumentDto,
  DetectionPolicyDto,
  SecurityEventDto,
} from '@/src/api/dto';
import type { AccessRule } from '@/src/api/gatewayAccessSchemas';
import type { GatewaySettingsValues } from '@/src/api/gatewaySettingsSchemas';
import { initialEventDtos } from './events';
import {
  initialAuditLogDtos,
  initialDocumentDtos,
  initialPolicyDtos,
} from './seed';

export interface PersistedMockState {
  events: SecurityEventDto[];
  documents: ConfidentialDocumentDto[];
  policies: DetectionPolicyDto[];
  auditLogs: AuditLogDto[];
  // Gateway 처리 설정(2026-10-10): 저장할 때마다 한 행 추가. 이전 데모 저장본에는 없다
  gatewaySettings?: MockGatewaySettingsRow[];
  // 접속 차단(2026-10-12): 저장할 때마다 한 행 추가(덧붙이기 전용), 별칭은 확장 ID별 한 칸. 이전 데모 저장본에는 없다
  gatewayAccess?: MockGatewayAccessRow[];
  clientAliases?: Record<string, string>;
}
export interface MockGatewayAccessRow {
  version: number;
  revision: string;
  require_client_id: boolean;
  rules: AccessRule[];
  updated_by: string;
  updated_at: string;
}
export interface MockGatewaySettingsRow {
  version: number;
  revision: string;
  settings: GatewaySettingsValues;
  updated_by: string;
  updated_at: string;
}
const storageKey = 'llm-security-gateway-demo-metadata-v5';

const cloneSeed = (): PersistedMockState => ({
  events: structuredClone(initialEventDtos),
  documents: structuredClone(initialDocumentDtos),
  policies: structuredClone(initialPolicyDtos),
  auditLogs: structuredClone(initialAuditLogDtos),
  gatewaySettings: [],
  gatewayAccess: [],
  clientAliases: {},
});

export function getMockState(): PersistedMockState {
  try {
    const raw = localStorage.getItem(storageKey);
    return raw ? (JSON.parse(raw) as PersistedMockState) : cloneSeed();
  } catch {
    return cloneSeed();
  }
}

export function saveMockState(state: PersistedMockState) {
  localStorage.setItem(storageKey, JSON.stringify(state));
}
export function updateMockState(updater: (state: PersistedMockState) => void) {
  const state = getMockState();
  updater(state);
  saveMockState(state);
  return state;
}
