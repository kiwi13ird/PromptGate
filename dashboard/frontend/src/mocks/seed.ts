import type {
  AuditActionDto,
  AuditLogDto,
  ConfidentialDocumentDto,
  DetectionPolicyDto,
  PolicyVersionDto,
  SecurityActionDto,
} from '@/src/api/dto';

export const initialDocumentDtos: ConfidentialDocumentDto[] = [
  {
    document_id: 'DOC-SEMICON-001',
    document_name: '반도체공정.pdf',
    registered_at: new Date(Date.now() - 22 * 86400000).toISOString(),
    status: 'ACTIVE',
    processing_status: 'READY',
    file_type: 'application/pdf',
    file_size: 6842000,
    exact_fingerprint_status: 'READY',
    similarity_fingerprint_status: 'READY',
    chunk_index_status: 'READY',
    chunk_count: 42,
    version: 'v3.2',
    classification: 'RESTRICTED',
    owner: '개발본부',
    active_detectors: ['SHA256', 'WINDOW_HASH', 'MINHASH'],
    exact_detection_count: 14,
    modified_partial_detection_count: 9,
    last_detected_at: new Date(Date.now() - 18 * 60000).toISOString(),
  },
  {
    document_id: 'DOC-A23F19B2',
    document_name: '설계검토서.pdf',
    registered_at: new Date(Date.now() - 18 * 86400000).toISOString(),
    status: 'ACTIVE',
    processing_status: 'READY',
    file_type: 'application/pdf',
    file_size: 4287000,
    exact_fingerprint_status: 'READY',
    similarity_fingerprint_status: 'READY',
    chunk_index_status: 'READY',
    chunk_count: 31,
    version: 'v2.0',
    classification: 'CONFIDENTIAL',
    owner: '제품개발팀',
    active_detectors: ['SHA256', 'WINDOW_HASH', 'MINHASH'],
    exact_detection_count: 7,
    modified_partial_detection_count: 12,
    last_detected_at: new Date(Date.now() - 104 * 60000).toISOString(),
  },
  {
    document_id: 'DOC-C904E71A',
    document_name: '사업계획.xlsx',
    registered_at: new Date(Date.now() - 12 * 86400000).toISOString(),
    status: 'ACTIVE',
    processing_status: 'READY',
    file_type:
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    file_size: 1963000,
    exact_fingerprint_status: 'READY',
    similarity_fingerprint_status: 'READY',
    chunk_index_status: 'READY',
    chunk_count: 18,
    version: 'v1.6',
    classification: 'RESTRICTED',
    owner: '경영기획실',
    active_detectors: ['SHA256', 'WINDOW_HASH', 'MINHASH'],
    exact_detection_count: 4,
    modified_partial_detection_count: 6,
    last_detected_at: new Date(Date.now() - 6 * 3600000).toISOString(),
  },
  {
    document_id: 'DOC-7BD213F0',
    document_name: '제품로드맵.docx',
    registered_at: new Date(Date.now() - 8 * 86400000).toISOString(),
    status: 'INACTIVE',
    processing_status: 'READY',
    file_type:
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    file_size: 2814000,
    exact_fingerprint_status: 'READY',
    similarity_fingerprint_status: 'READY',
    chunk_index_status: 'READY',
    chunk_count: 24,
    version: 'v4.1',
    classification: 'CONFIDENTIAL',
    owner: '전략기획팀',
    active_detectors: ['WINDOW_HASH'],
    exact_detection_count: 2,
    modified_partial_detection_count: 3,
    last_detected_at: new Date(Date.now() - 4 * 86400000).toISOString(),
  },
];

function history(
  currentVersion: number,
  currentAction: SecurityActionDto,
  enabled: boolean,
): PolicyVersionDto[] {
  return Array.from({ length: currentVersion }, (_, index) => ({
    version: index + 1,
    action:
      index + 1 === currentVersion
        ? currentAction
        : index % 2
          ? 'BLOCK'
          : 'MASK',
    created_at: new Date(
      Date.now() - (currentVersion - index) * 6 * 86400000,
    ).toISOString(),
    changed_by: index === 0 ? 'security.lead' : 'admin-001',
    enabled: index + 1 === currentVersion ? enabled : true,
  }));
}

const policy = (
  id: string,
  detector: DetectionPolicyDto['detector'],
  target: string,
  action: SecurityActionDto,
  version: number,
  enabled: boolean,
): DetectionPolicyDto => ({
  policy_id: id,
  detector,
  detection_target: target,
  action,
  version,
  enabled,
  versions: history(version, action, enabled),
});
export const initialPolicyDtos: DetectionPolicyDto[] = [
  {
    ...policy('POL-DOC-001', 'SHA256', 'EXACT_DOCUMENT', 'BLOCK', 2, true),
    recommended_action: 'BLOCK',
    enforcement_action: 'BLOCK',
    target_llms: ['ChatGPT', 'Gemini', 'Claude'],
    document_classification: 'RESTRICTED',
    failure_policy: 'FAIL_CLOSED',
    priority: 10,
    updated_by: 'security.lead',
    updated_at: new Date(Date.now() - 2 * 86400000).toISOString(),
  },
  {
    ...policy('POL-DOC-002', 'MINHASH', 'SIMILAR_DOCUMENT', 'BLOCK', 3, true),
    recommended_action: 'BLOCK',
    enforcement_action: 'BLOCK',
    target_llms: ['ChatGPT', 'Gemini', 'Claude'],
    document_classification: 'CONFIDENTIAL',
    failure_policy: 'FAIL_CLOSED',
    priority: 20,
    updated_by: 'admin-001',
    updated_at: new Date(Date.now() - 3 * 86400000).toISOString(),
  },
  {
    ...policy('POL-DOC-003', 'WINDOW_HASH', 'TEXT_FRAGMENT', 'BLOCK', 2, true),
    recommended_action: 'BLOCK',
    enforcement_action: 'BLOCK',
    target_llms: ['ChatGPT', 'Gemini', 'Claude'],
    document_classification: 'CONFIDENTIAL',
    failure_policy: 'FAIL_OPEN',
    priority: 30,
    updated_by: 'security.lead',
    updated_at: new Date(Date.now() - 4 * 86400000).toISOString(),
  },
  {
    ...policy('POL-001', 'SIGNATURE', 'API_KEY', 'MASK', 3, true),
    recommended_action: 'MASK',
    enforcement_action: 'MASK',
    target_llms: ['ChatGPT', 'Gemini', 'Claude'],
    failure_policy: 'FAIL_CLOSED',
    priority: 40,
    updated_by: 'security.lead',
    updated_at: new Date(Date.now() - 5 * 86400000).toISOString(),
  },
  policy('POL-002', 'SIGNATURE', 'PASSWORD', 'BLOCK', 2, true),
  policy('POL-003', 'SIGNATURE', 'ACCESS_TOKEN', 'MASK', 4, true),
  policy('POL-004', 'SIGNATURE', 'PRIVATE_KEY', 'BLOCK', 2, true),
  policy('POL-005', 'SIGNATURE', 'CONNECTION_STRING', 'MASK', 1, false),
  policy('POL-006', 'SIGNATURE', 'EMAIL_ADDRESS', 'MASK', 2, true),
];

const actions: AuditActionDto[] = [
  'POLICY_UPDATE',
  'DOCUMENT_REGISTER',
  'EVENT_STATUS_CHANGED',
  'POLICY_ENABLE',
  'DOCUMENT_DISABLE',
  'EVENT_ASSIGNED',
  'POLICY_CREATE',
  'EVENT_NOTE_ADDED',
  'DOCUMENT_ENABLE',
  'POLICY_DISABLE',
];
export const initialAuditLogDtos: AuditLogDto[] = Array.from(
  { length: 36 },
  (_, index): AuditLogDto => {
    const action = actions[index % actions.length];
    const isPolicy = action.startsWith('POLICY');
    const isEvent = action.startsWith('EVENT');
    const previous = action === 'POLICY_UPDATE' ? 2 + (index % 3) : undefined;
    return {
      audit_id: `AUD-${String(9100 + index)}`,
      occurred_at: new Date(
        Date.now() - index * 4.1 * 60 * 60_000,
      ).toISOString(),
      admin_id: index % 5 === 0 ? 'security.lead' : 'admin-001',
      action,
      target_type: isPolicy ? 'POLICY' : isEvent ? 'EVENT' : 'DOCUMENT',
      target_id: isPolicy
        ? `POL-${String((index % 6) + 1).padStart(3, '0')}`
        : isEvent
          ? ['EVT-1000A001', 'EVT-9700B002', 'EVT-8600C003'][index % 3]
          : ['DOC-SEMICON-001', 'DOC-A23F19B2', 'DOC-C904E71A'][index % 3],
      changes: previous
        ? {
            previous_version: previous,
            new_version: previous + 1,
            previous_action: 'MASK',
            new_action: 'BLOCK',
          }
        : action === 'DOCUMENT_DISABLE'
          ? { previous_status: 'ACTIVE', new_status: 'INACTIVE' }
          : action === 'DOCUMENT_ENABLE' || action === 'DOCUMENT_REGISTER'
            ? { new_status: 'ACTIVE' }
            : action === 'EVENT_STATUS_CHANGED'
              ? {
                  previous_incident_status: 'NEW',
                  new_incident_status: 'INVESTIGATING',
                }
              : action === 'EVENT_ASSIGNED'
                ? { new_assignee: 'security.lead' }
                : action === 'EVENT_NOTE_ADDED'
                  ? { note_added: true }
                  : undefined,
      result: index === 17 ? 'FAILURE' : 'SUCCESS',
    };
  },
);
