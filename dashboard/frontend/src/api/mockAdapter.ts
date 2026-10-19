import type { GatewayApi } from './gatewayApi';
import type {
  AuditChangesDto,
  AuditLogDto,
  ConfidentialDocumentDto,
  DetectionPolicyDto,
  PolicyActionDto,
  SecurityEventDto,
  TrafficClientsDto,
  TrafficSnapshotDto,
} from './dto';
import { ApiError } from './errors';
import { getMockScenario, mockRequest } from './mockClient';
import {
  filterAndPaginateEventDtos,
  filterEventDtos,
  paginateDtos,
  periodThreshold,
} from '@/src/mocks/eventQuery';
import {
  getMockState,
  updateMockState,
  type MockGatewayAccessRow,
  type MockGatewaySettingsRow,
} from '@/src/mocks/persistence';
import { generateResourceId } from '@/src/utils/ids';
import { POLICY_CAPABILITY_TARGETS, policyCapabilitiesDto } from '@/src/mocks/policyCapabilities.fixture';
import { summarizeGatewaySettings } from '@/src/utils/gatewaySettingsText';
import {
  gatewaySettingsValuesSchema,
  type GatewaySettingsResponse,
  type GatewaySettingsValues,
} from './gatewaySettingsSchemas';
import {
  ALIAS_MAX,
  accessModeBodySchema,
  accessRuleCreateBodySchema,
  blockReasonText,
  type AccessRule,
  type GatewayAccessResponse,
} from './gatewayAccessSchemas';

const mockAdminId = 'admin-001';

// Gateway 처리 설정 기본값(명세 §1.1) - 저장된 설정이 없을 때 데모 Gateway가 쓰는 환경변수 기본값
const gatewaySettingsDefaults: GatewaySettingsValues = {
  timeout: {
    prompt: { action: 'forward', seconds: 0.5 },
    file: { action: 'block', seconds: 2 },
  },
  uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
  notify_on_allow: false,
};
// 데모 Gateway는 저장 뒤 이 시간이 지나야 새 설정을 반영했다고 보고한다(실제는 다음 지표 전송, 최대 약 11초)
export const MOCK_GATEWAY_APPLY_MS = 2_500;

function mockRevision() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function gatewaySettingsSnapshot(
  rows: MockGatewaySettingsRow[],
  now = Date.now(),
): GatewaySettingsResponse {
  const current = rows.at(-1);
  const applied = [...rows]
    .reverse()
    .find((row) => now - Date.parse(row.updated_at) >= MOCK_GATEWAY_APPLY_MS);
  const appliedAt = (row: MockGatewaySettingsRow) =>
    new Date(Date.parse(row.updated_at) + MOCK_GATEWAY_APPLY_MS).toISOString();
  return {
    settings: current
      ? {
          ...structuredClone(current.settings),
          version: current.version,
          revision: current.revision,
          updated_at: current.updated_at,
          updated_by: current.updated_by,
          source: 'STORED',
        }
      : {
          ...structuredClone(gatewaySettingsDefaults),
          version: 0,
          revision: null,
          updated_at: null,
          updated_by: null,
          source: 'DEFAULT',
        },
    defaults: structuredClone(gatewaySettingsDefaults),
    gateway: {
      state: !current || applied?.revision === current.revision ? 'APPLIED' : 'PENDING',
      metrics_status: 'FRESH',
      reported_at: new Date(now).toISOString(),
      applied_version: applied?.version ?? 0,
      applied_revision: applied?.revision ?? null,
      applied_source: applied ? 'DASHBOARD' : 'ENV_DEFAULT',
      applied_at: applied ? appliedAt(applied) : new Date(now - 60_000).toISOString(),
      first_seen_at: applied ? appliedAt(applied) : null,
      rejected: null,
      effective: structuredClone(applied?.settings ?? gatewaySettingsDefaults),
    },
  };
}

// 접속 차단(2026-10-12) 데모 Gateway: 저장 뒤 MOCK_GATEWAY_APPLY_MS가 지나야 새 목록을 반영했다고 보고한다
const ruleActiveAt = (rule: AccessRule, now: number) =>
  !rule.removed_at && (!rule.expires_at || Date.parse(rule.expires_at) > now);

function gatewayAccessSnapshot(rows: MockGatewayAccessRow[], now = Date.now()): GatewayAccessResponse {
  const current = rows.at(-1);
  const applied = [...rows].reverse().find((row) => now - Date.parse(row.updated_at) >= MOCK_GATEWAY_APPLY_MS);
  return {
    version: current?.version ?? 0,
    revision: current?.revision ?? null,
    require_client_id: current?.require_client_id ?? false,
    rules: (current?.rules ?? []).map((rule) => ({ ...structuredClone(rule), active: ruleActiveAt(rule, now) })),
    ...(current ? { updated_at: current.updated_at, updated_by: current.updated_by } : {}),
    applied: {
      version: applied?.version ?? null,
      revision: applied?.revision ?? null,
      source: applied ? 'DASHBOARD' : 'NONE',
      applied_at: applied ? new Date(Date.parse(applied.updated_at) + MOCK_GATEWAY_APPLY_MS).toISOString() : null,
      rejected: null,
      active_rules: (applied?.rules ?? []).filter((rule) => ruleActiveAt(rule, now)).length,
      require_client_id: applied?.require_client_id ?? false,
      denied_5m: 0,
      received_at: new Date(now).toISOString(),
    },
  };
}

const accessConflict = () => new ApiError('다른 관리자가 먼저 바꿨습니다.', 'CONFLICT', 409);
const DURATION_MS = { '1h': 3_600_000, '1d': 86_400_000 } as const;
const modeText = (on: boolean) => (on ? '켜짐' : '꺼짐');

/** 접속 차단 문서를 한 행 덧붙인다(번호 확인 → 변경 → 새 번호·revision). 감사 기록은 호출한 쪽이 남긴다 */
function appendAccessRow(
  expectedVersion: number,
  change: (latest: MockGatewayAccessRow | undefined) => { rules: AccessRule[]; require_client_id: boolean },
) {
  let previous: MockGatewayAccessRow | undefined;
  let saved: MockGatewayAccessRow | undefined;
  updateMockState((state) => {
    const rows = (state.gatewayAccess ??= []);
    const latest = rows.at(-1);
    if ((latest?.version ?? 0) !== expectedVersion) throw accessConflict();
    previous = latest;
    saved = {
      version: expectedVersion + 1,
      revision: mockRevision(),
      ...change(latest),
      updated_by: mockAdminId,
      updated_at: new Date().toISOString(),
    };
    rows.push(saved);
  });
  if (!saved) throw new ApiError('목록을 저장하지 못했습니다.');
  return { previous, saved };
}

function demoTrafficSnapshot(): TrafficSnapshotDto {
  const now = Date.now();
  const timeSeries = Array.from({ length: 12 }, (_, index) => ({
    timestamp: new Date(now - (11 - index) * 5 * 60_000).toISOString(),
    request_count: 74 + index * 5,
    allow_count: 58 + index * 4,
    mask_count: 4 + (index % 3),
    block_count: 12 + (index % 4),
    average_latency_ms: 102 + index * 3,
    p95_latency_ms: 178 + index * 6,
  }));
  return {
    summary: {
      active_clients: 17,
      concurrent_requests: 24,
      requests_per_sec: 32.5,
      average_latency_ms: 128,
      p95_latency_ms: 241,
      timeout_rate: 0.012,
      degraded_rate: 0.008,
      gateway_status: 'HEALTHY',
    },
    time_series: timeSeries,
  };
}

// 연결 중인 IP(2026-10-12) 데모 값. IP는 문서용 대역(203.0.113.x · 198.51.100.x · 2001:db8::)만 쓴다
function demoTrafficClients(): TrafficClientsDto {
  const now = Date.now();
  const ago = (seconds: number) => new Date(now - seconds * 1000).toISOString();
  return {
    received_at: ago(4),
    stale: false,
    window_seconds: 300,
    clients: [
      { ip: '203.0.113.24', client_id: 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39', connections: 3, inflight: 1, waiting: 2, requests_5m: 14, targets: { ChatGPT: 9, Claude: 5 }, first_seen_at: ago(3_480), last_seen_at: ago(6) },
      { ip: '2001:db8::7a', client_id: 'chrome-9b1e4d7c-2a6f-4c3b-8e05-7f2d9a6c4b18', connections: 2, inflight: 0, waiting: 0, requests_5m: 6, targets: { Gemini: 6 }, first_seen_at: ago(1_260), last_seen_at: ago(41) },
      { ip: '198.51.100.17', client_id: null, connections: 1, inflight: 0, waiting: 1, requests_5m: 2, targets: { Claude: 2 }, first_seen_at: ago(720), last_seen_at: ago(95) },
      { ip: '203.0.113.88', client_id: 'chrome-6c2d8e1f-4b7a-4d9e-a3c6-1e8f5b2d7a04', connections: 0, inflight: 0, waiting: 0, requests_5m: 0, targets: {}, first_seen_at: ago(2_100), last_seen_at: ago(430) },
    ],
  };
}

// ── 정책 예시 연결 도우미(2026-10-15). 운영 서버 validatePolicyAction과 같은 코드·순서
const LEGACY_POLICY_ACTION: Readonly<Record<string, PolicyActionDto>> = { MASK: 'MASK_FULL', ALLOW_NOTIFY: 'ALLOW', BLOCK_NOTIFY: 'BLOCK' };
const POLICY_ACTION_CODES: readonly string[] = ['ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL'];
function mockValidatePolicy(target: unknown, action: unknown, creating: boolean): { target: string; action: PolicyActionDto } {
  const fail = (code: string, message: string): never => { throw new ApiError(message, 'VALIDATION', 422, code); };
  if (typeof target !== 'string') return fail('UNSUPPORTED_POLICY_TARGET', 'Select a supported detection target.');
  const selected = POLICY_CAPABILITY_TARGETS.find((item) => item.code === target.trim().toUpperCase());
  if (!selected) return fail('UNSUPPORTED_POLICY_TARGET', 'Policy target is not in the reviewed configuration catalog.');
  if (creating && !selected.can_create) return fail('CATEGORY_POLICY_CREATE_UNSUPPORTED', 'Category creation is not supported; edit an existing category policy.');
  if (typeof action !== 'string') return fail('UNSUPPORTED_POLICY_ACTION', 'Select a supported policy action.');
  const input = action.trim().toUpperCase();
  const normalized = LEGACY_POLICY_ACTION[input] ?? input;
  if (!POLICY_ACTION_CODES.includes(normalized)) return fail('UNSUPPORTED_POLICY_ACTION', 'Select one of the four policy actions.');
  if (!selected.allowed_actions.includes(normalized as PolicyActionDto)) return fail('CREDENTIAL_PARTIAL_MASK_FORBIDDEN', 'Credentials require full masking or blocking when masked; partial masking is forbidden.');
  return { target: selected.code, action: normalized as PolicyActionDto };
}
const actionFamily = (action: PolicyActionDto): DetectionPolicyDto['action'] => (action === 'MASK_FULL' || action === 'MASK_PARTIAL' ? 'MASK' : action);
const mockPolicyActionFields = (action: PolicyActionDto) => ({
  action: actionFamily(action), action_variant: action, policy_action: action, final_policy_action: action,
  recommended_action: actionFamily(action), enforcement_action: actionFamily(action), recommended_policy_action: action,
});
const mockPolicyVersionAction = (action: PolicyActionDto) => ({ action: actionFamily(action), action_variant: action, policy_action: action });
function mockStoredPolicyAction(policy: DetectionPolicyDto): PolicyActionDto {
  if (policy.policy_action) return policy.policy_action;
  const raw = (policy.action_variant ?? policy.action).toUpperCase();
  return LEGACY_POLICY_ACTION[raw] ?? (POLICY_ACTION_CODES.includes(raw) ? raw as PolicyActionDto : 'MASK_FULL');
}

function addAudit(
  action: AuditLogDto['action'],
  targetType: AuditLogDto['target_type'],
  targetId: string,
  changes?: AuditChangesDto,
) {
  updateMockState((state) =>
    state.auditLogs.unshift({
      audit_id: generateResourceId('AUD'),
      occurred_at: new Date().toISOString(),
      admin_id: mockAdminId,
      action,
      target_type: targetType,
      target_id: targetId,
      changes,
      result: 'SUCCESS',
    }),
  );
}

function mutateEvent(
  eventId: string,
  mutate: (event: SecurityEventDto) => void,
) {
  let changed: SecurityEventDto | undefined;
  updateMockState((state) => {
    const event = state.events.find(
      (item) => item.event_id.toLowerCase() === eventId.toLowerCase(),
    );
    if (!event)
      throw new ApiError('이벤트를 찾을 수 없습니다.', 'NOT_FOUND', 404);
    mutate(event);
    changed = structuredClone(event);
  });
  if (!changed)
    throw new ApiError('이벤트를 찾을 수 없습니다.', 'NOT_FOUND', 404);
  return changed;
}

export const mockGatewayApi: GatewayApi = {
  getDashboardStats: (period, signal) =>
    mockRequest(() => {
      const filters = {
        query: '',
        period,
        finalAction: 'ALL',
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
        sort: 'OCCURRED_AT_DESC',
        page: 1,
        pageSize: 100,
      } as const;
      const rows =
        getMockScenario() === 'empty-events'
          ? []
          : filterEventDtos(getMockState().events, filters);
      const bucketCount = period === '24H' ? 12 : period === '7D' ? 7 : 10;
      const duration =
        period === '24H'
          ? 24 * 3600000
          : period === '7D'
            ? 7 * 86400000
            : 30 * 86400000;
      const bucketMs = duration / bucketCount;
      const start = Date.now() - duration;
      return {
        total: rows.length,
        block: rows.filter(
          (event) => (event.final_action ?? event.action) === 'BLOCK',
        ).length,
        mask: rows.filter(
          (event) => (event.final_action ?? event.action) === 'MASK',
        ).length,
        allow: rows.filter(
          (event) => (event.final_action ?? event.action) === 'ALLOW',
        ).length,
        degraded: rows.filter((event) => event.degraded).length,
        enforcement_rate: rows.length
          ? rows.filter((event) => event.enforcement?.applied).length /
            rows.length
          : 0,
        action_mismatch: rows.filter((event) => {
          const recommended =
            event.recommended_action ??
            event.detections[0]?.recommended_action ??
            event.detections[0]?.action;
          return Boolean(
            recommended && recommended !== (event.final_action ?? event.action),
          );
        }).length,
        new_events: rows.filter((event) => event.status === 'NEW').length,
        average_processing_ms: rows.length
          ? Number(
              (
                rows.reduce(
                  (sum, event) => sum + (event.processing_ms ?? 0),
                  0,
                ) /
                rows.length
              ).toFixed(1),
            )
          : 0,
        detection_status: rows.some((event) => event.degraded)
          ? 'DEGRADED'
          : 'HEALTHY',
        gateway_status: 'HEALTHY',
        last_success_at: rows.find((event) => !event.degraded)?.occurred_at,
        trend: Array.from({ length: bucketCount }, (_, index) => {
          const from = start + index * bucketMs;
          const to = from + bucketMs;
          const bucketRows = rows.filter(
            (event) =>
              Date.parse(event.occurred_at) >= from &&
              Date.parse(event.occurred_at) < to,
          );
          const date = new Date(from);
          return {
            bucket:
              period === '24H'
                ? `${String(date.getHours()).padStart(2, '0')}:00`
                : `${date.getMonth() + 1}/${date.getDate()}`,
            total: bucketRows.length,
            block: bucketRows.filter(
              (event) => (event.final_action ?? event.action) === 'BLOCK',
            ).length,
            mask: bucketRows.filter(
              (event) => (event.final_action ?? event.action) === 'MASK',
            ).length,
            allow: bucketRows.filter(
              (event) => (event.final_action ?? event.action) === 'ALLOW',
            ).length,
          };
        }),
        recent: rows.slice(0, 7),
      };
    }, signal),
  getTrafficSnapshot: (_period, signal) =>
    mockRequest(
      () =>
        getMockScenario() === 'empty-traffic'
          ? {
              summary: { gateway_status: 'UNKNOWN' },
              time_series: [],
            }
          : demoTrafficSnapshot(),
      signal,
    ),
  getTrafficClients: (signal) =>
    mockRequest(
      () =>
        getMockScenario() === 'empty-traffic'
          ? { received_at: null, stale: true, window_seconds: 300, clients: [] }
          : demoTrafficClients(),
      signal,
    ),
  getEvents: (filters, signal) =>
    mockRequest(
      () =>
        getMockScenario() === 'empty-events'
          ? paginateDtos([], filters.page, filters.pageSize)
          : filterAndPaginateEventDtos(getMockState().events, filters),
      signal,
    ),
  getEvent: (eventId, signal) =>
    mockRequest(
      () =>
        getMockState().events.find(
          (event) => event.event_id.toLowerCase() === eventId.toLowerCase(),
        ) ?? null,
      signal,
    ),
  updateEventStatus: (eventId, status, signal) =>
    mockRequest(() => {
      let previous = 'NEW' as SecurityEventDto['status'];
      const changed = mutateEvent(eventId, (event) => {
        previous = event.status;
        event.status = status;
        event.timeline.unshift({
          timeline_id: generateResourceId('TL'),
          occurred_at: new Date().toISOString(),
          actor: mockAdminId,
          type: 'STATUS_CHANGED',
          summary: `상태를 ${status}로 변경했습니다.`,
        });
      });
      addAudit('EVENT_STATUS_CHANGED', 'EVENT', eventId, {
        previous_incident_status: previous,
        new_incident_status: status,
      });
      return changed;
    }, signal),
  assignEvent: (eventId, assignee, signal) =>
    mockRequest(() => {
      const normalized = assignee.trim();
      if (!normalized)
        throw new ApiError('담당자를 입력해주세요.', 'VALIDATION', 422);
      let previous: string | undefined;
      const changed = mutateEvent(eventId, (event) => {
        previous = event.assignee;
        event.assignee = normalized;
        event.timeline.unshift({
          timeline_id: generateResourceId('TL'),
          occurred_at: new Date().toISOString(),
          actor: mockAdminId,
          type: 'ASSIGNEE_CHANGED',
          summary: `담당자를 ${normalized}(으)로 지정했습니다.`,
        });
      });
      addAudit('EVENT_ASSIGNED', 'EVENT', eventId, {
        previous_assignee: previous,
        new_assignee: normalized,
      });
      return changed;
    }, signal),
  addEventNote: (eventId, content, signal) =>
    mockRequest(() => {
      const normalized = content.trim();
      if (!normalized || normalized.length > 2000)
        throw new ApiError(
          '1~2,000자의 관리자 메모를 입력해주세요.',
          'VALIDATION',
          422,
        );
      const changed = mutateEvent(eventId, (event) => {
        const occurredAt = new Date().toISOString();
        event.admin_notes.unshift({
          note_id: generateResourceId('NOTE'),
          author: mockAdminId,
          created_at: occurredAt,
          content: normalized,
        });
        event.timeline.unshift({
          timeline_id: generateResourceId('TL'),
          occurred_at: occurredAt,
          actor: mockAdminId,
          type: 'NOTE_ADDED',
          summary: '관리자 메모를 추가했습니다.',
        });
      });
      addAudit('EVENT_NOTE_ADDED', 'EVENT', eventId, { note_added: true });
      return changed;
    }, signal),
  getDocuments: (signal) => mockRequest(() => getMockState().documents, signal),
  registerDocument: (file, signal) =>
    mockRequest(() => {
      if (!file.name.trim() || file.size <= 0 || file.size > 20 * 1024 * 1024)
        throw new ApiError('유효한 파일을 선택해주세요.', 'VALIDATION', 422);
      const document = {
        document_id: generateResourceId('DOC'),
        document_name: file.name.slice(0, 120),
        registered_at: new Date().toISOString(),
        status: 'ACTIVE' as const,
        processing_status: 'READY' as const,
        file_type: file.type || 'application/octet-stream',
        file_size: file.size,
        exact_fingerprint_status: 'READY' as const,
        similarity_fingerprint_status: 'READY' as const,
        chunk_index_status: 'READY' as const,
        chunk_count: Math.max(1, Math.ceil(file.size / 180000)),
      };
      updateMockState((state) => state.documents.unshift(document));
      addAudit('DOCUMENT_REGISTER', 'DOCUMENT', document.document_id, {
        new_status: 'ACTIVE',
      });
      return document;
    }, signal),
  changeDocumentStatus: (documentId, status, signal) =>
    mockRequest(() => {
      let changed: ConfidentialDocumentDto | undefined;
      let previous: ConfidentialDocumentDto['status'] | undefined;
      updateMockState((state) => {
        const document = state.documents.find(
          (item) => item.document_id === documentId,
        );
        if (!document)
          throw new ApiError('문서를 찾을 수 없습니다.', 'NOT_FOUND', 404);
        previous = document.status;
        document.status = status;
        changed = { ...document };
      });
      if (!changed)
        throw new ApiError('문서를 찾을 수 없습니다.', 'NOT_FOUND', 404);
      if (previous !== changed.status)
        addAudit(
          changed.status === 'ACTIVE' ? 'DOCUMENT_ENABLE' : 'DOCUMENT_DISABLE',
          'DOCUMENT',
          documentId,
          {
            previous_status: previous,
            new_status: changed.status,
          },
        );
      return changed;
    }, signal),
  getPolicies: (signal) => mockRequest(() => getMockState().policies, signal),
  getPolicyHistory: (policyId, signal) =>
    mockRequest(() => {
      const policy = getMockState().policies.find(
        (item) => item.policy_id === policyId,
      );
      if (!policy)
        throw new ApiError('Policy를 찾을 수 없습니다.', 'NOT_FOUND', 404);
      return policy.versions ?? [];
    }, signal),
  // 정책(2026-10-15): 운영 대시보드 서버의 검증 순서를 흉내 낸다 — 지원 목록(422) → 분류 생성 불가(422) → 처리 방식(422) → 중복(409 CONFLICT) · 버전(409 VERSION_CONFLICT)
  getPolicyCapabilities: (signal) => mockRequest(() => policyCapabilitiesDto(), signal),
  createPolicy: (detectionTarget, action, signal) =>
    mockRequest(() => {
      const checked = mockValidatePolicy(detectionTarget, action, true);
      let created: DetectionPolicyDto | undefined;
      updateMockState((state) => {
        if (state.policies.some((policy) => policy.detection_target.toUpperCase() === checked.target))
          throw new ApiError(
            '동일한 Detection Target의 Policy가 이미 있습니다.',
            'CONFLICT',
            409,
            'CONFLICT',
          );
        const maxId = Math.max(
          ...state.policies.map((policy) =>
            /^POL-\d+$/.test(policy.policy_id)
              ? Number(policy.policy_id.slice(4))
              : 0,
          ),
          0,
        );
        const now = new Date().toISOString();
        created = {
          policy_id: `POL-${String(maxId + 1).padStart(3, '0')}`,
          detector: 'SIGNATURE' as const,
          detection_target: checked.target,
          ...mockPolicyActionFields(checked.action),
          version: 1,
          enabled: true,
          versions: [
            {
              version: 1,
              ...mockPolicyVersionAction(checked.action),
              created_at: now,
              changed_by: mockAdminId,
              enabled: true,
            },
          ],
        };
        state.policies.unshift(created);
      });
      if (!created) throw new ApiError('Policy 생성에 실패했습니다.');
      addAudit('POLICY_CREATE', 'POLICY', created.policy_id, {
        new_version: 1,
        new_action: actionFamily(checked.action),
        new_policy_action: checked.action,
      });
      return created;
    }, signal),
  updatePolicy: (policyId, action, expectedVersion, signal) =>
    mockRequest(() => {
      let changed: DetectionPolicyDto | undefined;
      let previous = 0;
      let previousAction: PolicyActionDto = 'MASK_FULL';
      updateMockState((state) => {
        const policy = state.policies.find(
          (item) => item.policy_id === policyId,
        );
        if (!policy)
          throw new ApiError('Policy를 찾을 수 없습니다.', 'NOT_FOUND', 404, 'NOT_FOUND');
        const checked = mockValidatePolicy(policy.detection_target, action, false);
        if (policy.version !== expectedVersion)
          throw new ApiError(
            '다른 관리자가 정책을 변경했습니다. 새로고침 후 다시 시도해주세요.',
            'CONFLICT',
            409,
            'VERSION_CONFLICT',
          );
        previous = policy.version;
        previousAction = mockStoredPolicyAction(policy);
        Object.assign(policy, mockPolicyActionFields(checked.action));
        policy.version += 1;
        policy.versions = [
          ...(policy.versions ?? []),
          {
            version: policy.version,
            ...mockPolicyVersionAction(checked.action),
            created_at: new Date().toISOString(),
            changed_by: mockAdminId,
            enabled: policy.enabled,
          },
        ];
        changed = { ...policy };
      });
      if (!changed)
        throw new ApiError('Policy를 찾을 수 없습니다.', 'NOT_FOUND', 404, 'NOT_FOUND');
      const next = mockStoredPolicyAction(changed);
      addAudit('POLICY_UPDATE', 'POLICY', policyId, {
        previous_version: previous,
        new_version: changed.version,
        previous_action: actionFamily(previousAction),
        new_action: actionFamily(next),
        previous_policy_action: previousAction,
        new_policy_action: next,
      });
      return changed;
    }, signal),
  // 상태 변경도 Detection처럼 버전을 1 올리고 이력을 남긴다(조치 변경과 같은 줄 형식 → 화면이 앞뒤를 비교해 구분)
  changePolicyStatus: (policyId, enabled, expectedVersion, signal) =>
    mockRequest(() => {
      let changed: DetectionPolicyDto | undefined;
      let previousEnabled: boolean | undefined;
      let previousVersion = 0;
      if (typeof enabled !== 'boolean')
        throw new ApiError('enabled must be a boolean.', 'VALIDATION', 422, 'INVALID_POLICY_STATUS');
      updateMockState((state) => {
        const policy = state.policies.find(
          (item) => item.policy_id === policyId,
        );
        if (!policy)
          throw new ApiError('Policy를 찾을 수 없습니다.', 'NOT_FOUND', 404, 'NOT_FOUND');
        if (policy.version !== expectedVersion)
          throw new ApiError(
            '다른 관리자가 정책을 변경했습니다. 새로고침 후 다시 시도해주세요.',
            'CONFLICT',
            409,
            'VERSION_CONFLICT',
          );
        previousEnabled = policy.enabled;
        previousVersion = policy.version;
        if (policy.enabled !== enabled) {
          policy.enabled = enabled;
          policy.version += 1;
          policy.versions = [
            ...(policy.versions ?? []),
            {
              version: policy.version,
              ...mockPolicyVersionAction(mockStoredPolicyAction(policy)),
              created_at: new Date().toISOString(),
              changed_by: mockAdminId,
              enabled,
            },
          ];
        }
        changed = { ...policy };
      });
      if (!changed)
        throw new ApiError('Policy를 찾을 수 없습니다.', 'NOT_FOUND', 404, 'NOT_FOUND');
      if (previousEnabled !== changed.enabled)
        addAudit(
          changed.enabled ? 'POLICY_ENABLE' : 'POLICY_DISABLE',
          'POLICY',
          policyId,
          { previous_version: previousVersion, new_version: changed.version },
        );
      return changed;
    }, signal),
  getAuditLogs: (filters, signal) =>
    mockRequest(() => {
      if (getMockScenario() === 'empty-audit')
        return paginateDtos([], filters.page, filters.pageSize);
      const query = filters.admin.toLowerCase().trim();
      const rows = getMockState()
        .auditLogs.filter(
          (log) =>
            Date.parse(log.occurred_at) >= periodThreshold(filters.period) &&
            (filters.action === 'ALL' || log.action === filters.action) &&
            (filters.result === 'ALL' || log.result === filters.result) &&
            (!query || log.admin_id.toLowerCase().includes(query)),
        )
        .sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at));
      return paginateDtos(rows, filters.page, filters.pageSize);
    }, signal),
  getGatewaySettings: (signal) =>
    mockRequest(
      () => gatewaySettingsSnapshot(getMockState().gatewaySettings ?? []),
      signal,
    ),
  saveGatewaySettings: (body, signal) =>
    mockRequest(() => {
      // 백엔드와 같은 순서: 칸 목록(400) → 값 범위(422) → 번호 충돌(409)
      const keys = Object.keys(body).sort().join(',');
      if (keys !== 'expected_version,notify_on_allow,timeout,uninspectable')
        throw new ApiError('설정 칸이 올바르지 않습니다.', 'VALIDATION', 400);
      const { expected_version: expectedVersion, ...values } = body;
      const parsed = gatewaySettingsValuesSchema.safeParse(values);
      if (!parsed.success || !Number.isInteger(expectedVersion) || expectedVersion < 0)
        throw new ApiError('허용 범위를 벗어난 값입니다.', 'VALIDATION', 422);
      let previous: MockGatewaySettingsRow | undefined;
      let saved: MockGatewaySettingsRow | undefined;
      updateMockState((state) => {
        const rows = (state.gatewaySettings ??= []);
        const latest = rows.at(-1);
        if ((latest?.version ?? 0) !== expectedVersion)
          throw new ApiError(
            '다른 관리자가 먼저 바꿨습니다.',
            'CONFLICT',
            409,
          );
        previous = latest;
        saved = {
          version: expectedVersion + 1,
          revision: mockRevision(),
          settings: parsed.data,
          updated_by: mockAdminId,
          updated_at: new Date().toISOString(),
        };
        rows.push(saved);
      });
      if (!saved) throw new ApiError('설정을 저장하지 못했습니다.');
      addAudit('GATEWAY_SETTINGS_UPDATE', 'GATEWAY', 'gateway-settings', {
        ...(previous ? { previous_version: previous.version } : {}),
        new_version: saved.version,
        previous_value: summarizeGatewaySettings(
          previous?.settings ?? gatewaySettingsDefaults,
          !previous,
        ),
        new_value: summarizeGatewaySettings(saved.settings),
      });
      return gatewaySettingsSnapshot(getMockState().gatewaySettings ?? []);
    }, signal),
  getGatewayAccess: (signal) =>
    mockRequest(() => gatewayAccessSnapshot(getMockState().gatewayAccess ?? []), signal),
  addAccessRule: (body, signal) =>
    mockRequest(() => {
      // 백엔드와 같은 순서: 입력 형식(422) → 번호 충돌(409) → 같은 ID에 이미 차단 중(409)
      const parsed = accessRuleCreateBodySchema.safeParse(body);
      if (!parsed.success) throw new ApiError('허용 범위를 벗어난 값입니다.', 'VALIDATION', 422);
      const input = parsed.data;
      const now = Date.now();
      const rule: AccessRule = {
        id: mockRevision(),
        client_id: input.client_id,
        reasons: input.reasons,
        memo: input.memo?.trim() || null,
        ...(input.show_memo_to_user && input.memo?.trim() ? { show_memo_to_user: true } : {}),
        expires_at: input.duration === 'permanent' ? null : new Date(now + DURATION_MS[input.duration]).toISOString(),
        created_by: mockAdminId,
        created_at: new Date(now).toISOString(),
        removed_by: null,
        removed_at: null,
      };
      const { previous, saved } = appendAccessRow(input.expected_version, (latest) => {
        if ((latest?.rules ?? []).some((item) => item.client_id === input.client_id && ruleActiveAt(item, now))) throw accessConflict();
        return { rules: [...(latest?.rules ?? []), rule], require_client_id: latest?.require_client_id ?? false };
      });
      const until = rule.expires_at ? `${rule.expires_at}까지` : '영구';
      addAudit('ACCESS_RULE_ADD', 'GATEWAY', rule.id, {
        ...(previous ? { previous_version: previous.version } : {}),
        new_version: saved.version,
        new_value: `차단 · 확장 프로그램 ${rule.client_id} · ${until} · 사유 ${rule.reasons.map(blockReasonText).join(', ')}${rule.memo ? ` · 메모 ${rule.memo}` : ''}`,
      });
      return { version: saved.version };
    }, signal),
  removeAccessRule: (ruleId, expectedVersion, signal) =>
    mockRequest(() => {
      if (!Number.isInteger(expectedVersion) || expectedVersion < 0) throw new ApiError('허용 범위를 벗어난 값입니다.', 'VALIDATION', 422);
      const now = Date.now();
      let removed: AccessRule | undefined;
      const { previous, saved } = appendAccessRow(expectedVersion, (latest) => {
        const target = latest?.rules.find((item) => item.id === ruleId);
        if (!target) throw new ApiError('규칙을 찾을 수 없습니다.', 'NOT_FOUND', 404);
        if (!ruleActiveAt(target, now)) throw new ApiError('이미 만료되었거나 해제된 규칙입니다.', 'NOT_FOUND', 404);
        const done: AccessRule = { ...target, removed_by: mockAdminId, removed_at: new Date(now).toISOString() };
        removed = done;
        return { rules: (latest?.rules ?? []).map((item) => (item.id === ruleId ? done : item)), require_client_id: latest?.require_client_id ?? false };
      });
      addAudit('ACCESS_RULE_REMOVE', 'GATEWAY', ruleId, {
        ...(previous ? { previous_version: previous.version } : {}),
        new_version: saved.version,
        previous_value: `차단 · 확장 프로그램 ${removed?.client_id ?? ''}`,
      });
      return { version: saved.version };
    }, signal),
  setAccessMode: (body, signal) =>
    mockRequest(() => {
      const parsed = accessModeBodySchema.safeParse(body);
      if (!parsed.success) throw new ApiError('허용 범위를 벗어난 값입니다.', 'VALIDATION', 422);
      const { previous, saved } = appendAccessRow(parsed.data.expected_version, (latest) => ({
        rules: latest?.rules ?? [],
        require_client_id: parsed.data.require_client_id,
      }));
      addAudit('ACCESS_MODE_UPDATE', 'GATEWAY', 'gateway-access', {
        ...(previous ? { previous_version: previous.version } : {}),
        new_version: saved.version,
        previous_value: modeText(previous?.require_client_id ?? false),
        new_value: modeText(saved.require_client_id),
      });
      return { version: saved.version };
    }, signal),
  getClientAliases: (signal) =>
    mockRequest(
      () => ({ items: Object.entries(getMockState().clientAliases ?? {}).map(([client_id, alias]) => ({ client_id, alias })) }),
      signal,
    ),
  setClientAlias: (clientId, alias, signal) =>
    mockRequest(() => {
      const next = alias.trim();
      if (!clientId || next.length > ALIAS_MAX) throw new ApiError('허용 범위를 벗어난 값입니다.', 'VALIDATION', 422);
      let before = '';
      updateMockState((state) => {
        const aliases = (state.clientAliases ??= {});
        before = aliases[clientId] ?? '';
        if (next) aliases[clientId] = next;
        else delete aliases[clientId];
      });
      addAudit('CLIENT_ALIAS_UPDATE', 'GATEWAY', clientId, { previous_value: before, new_value: next });
    }, signal),
};

export const gatewayApi = mockGatewayApi;
