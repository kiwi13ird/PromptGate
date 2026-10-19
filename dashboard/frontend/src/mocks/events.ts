import type {
  DetectionDto,
  IncidentStatusDto,
  SecurityActionDto,
  SecurityEventDto,
  SeverityDto,
  TargetLlmDto,
} from '@/src/api/dto';

const nowMinus = (minutes: number) =>
  new Date(Date.now() - minutes * 60_000).toISOString();
const detectedTimeline = (eventId: string, occurredAt: string) => [
  {
    timeline_id: `TL-${eventId}-01`,
    occurred_at: occurredAt,
    actor: 'Security Gateway',
    type: 'DETECTED' as const,
    summary: '보안 게이트웨이가 요청을 탐지하고 최종 조치를 적용했습니다.',
  },
];

const exactOccurredAt = nowMinus(18);
const similarOccurredAt = nowMinus(43);
const fragmentOccurredAt = nowMinus(76);

export const flagshipEventDtos: SecurityEventDto[] = [
  {
    event_id: 'EVT-1000A001',
    occurred_at: exactOccurredAt,
    client_id: 'CLT-RND-001',
    user_id: 'USR-0041',
    tenant_id: 'TNT-001',
    action: 'BLOCK',
    final_action: 'BLOCK',
    recommended_action: 'BLOCK',
    detection_outcome: 'MATCH',
    severity: 'CRITICAL',
    status: 'NEW',
    admin_notes: [],
    timeline: detectedTimeline('EVT-1000A001', exactOccurredAt),
    detections: [
      {
        detector: 'WINDOW_HASH',
        match_type: 'TEXT_FRAGMENT',
        score: 1,
        score_kind: 'COVERAGE',
        threshold: 0.8,
        matched_document_id: '01_사업전략_방향_보고서',
        matched_document_name: '01_사업전략_방향_보고서.pdf',
        input_location: { char_start: 0, char_end: 743 },
        matched_location: { char_start: 763, char_end: 1504 },
        action: 'BLOCK',
        recommended_action: 'BLOCK',
      },
    ],
    target_llm: 'ChatGPT',
    processing_ms: 11.8,
    request_id: 'REQ-CHATGPT-1000A001',
    host: 'chatgpt.com',
    endpoint: '/backend-api/f/conversation',
    content_type: 'prompt',
    enforcement: { applied: true, http_status: 403 },
    degraded: false,
    detector_version: 'window-hash-1.4.0',
    ruleset_version: 'gateway-policy-7',
  },
  {
    event_id: 'EVT-9700B002',
    occurred_at: similarOccurredAt,
    client_id: 'CLT-ENG-014',
    user_id: 'USR-0184',
    tenant_id: 'TNT-001',
    action: 'BLOCK',
    final_action: 'BLOCK',
    recommended_action: 'BLOCK',
    detection_outcome: 'MATCH',
    severity: 'HIGH',
    status: 'INVESTIGATING',
    assignee: 'security.lead',
    admin_notes: [],
    timeline: [
      ...detectedTimeline('EVT-9700B002', similarOccurredAt),
      {
        timeline_id: 'TL-EVT-9700B002-02',
        occurred_at: nowMinus(34),
        actor: 'security.lead',
        type: 'STATUS_CHANGED',
        summary: '상태를 조사 중으로 변경했습니다.',
      },
    ],
    detections: [
      {
        detector: 'MINHASH',
        match_type: 'SIMILAR_DOCUMENT',
        similarity: 0.97,
        threshold: 0.8,
        outbound_document_name: '반도체공정_v2.pdf',
        matched_document_id: 'DOC-SEMICON-001',
        matched_document_name: '반도체공정.pdf',
        action: 'BLOCK',
        recommended_action: 'BLOCK',
      },
    ],
    target_llm: 'ChatGPT',
    processing_ms: 19.4,
    request_id: 'REQ-CHATGPT-9700B002',
    host: 'chatgpt.com',
    endpoint: '/backend-api/f/conversation',
    content_type: 'file',
    enforcement: { applied: true, http_status: 403 },
    degraded: false,
    detector_version: 'minhash-demo-1.0',
    ruleset_version: 'gateway-policy-7',
  },
  {
    event_id: 'EVT-8600C003',
    occurred_at: fragmentOccurredAt,
    client_id: 'CLT-QA-009',
    user_id: 'USR-0312',
    tenant_id: 'TNT-001',
    action: 'BLOCK',
    final_action: 'BLOCK',
    recommended_action: 'BLOCK',
    detection_outcome: 'MATCH',
    severity: 'HIGH',
    status: 'NEW',
    admin_notes: [],
    timeline: detectedTimeline('EVT-8600C003', fragmentOccurredAt),
    detections: [
      {
        detector: 'WINDOW_HASH',
        match_type: 'TEXT_FRAGMENT',
        score: 0.86,
        score_kind: 'COVERAGE',
        threshold: 0.8,
        matched_document_id: 'DOC-SEMICON-001',
        matched_document_name: '반도체공정.pdf',
        input_location: { char_start: 0, char_end: 326 },
        matched_location: { char_start: 2410, char_end: 2690 },
        action: 'BLOCK',
        recommended_action: 'BLOCK',
      },
    ],
    target_llm: 'ChatGPT',
    processing_ms: 16.7,
    request_id: 'REQ-CHATGPT-8600C003',
    host: 'chatgpt.com',
    endpoint: '/backend-api/f/conversation',
    content_type: 'prompt',
    enforcement: { applied: true, http_status: 403 },
    degraded: false,
    detector_version: 'window-hash-1.4.0',
    ruleset_version: 'gateway-policy-7',
  },
];

const operationalEventDtos: SecurityEventDto[] = [
  {
    event_id: 'EVT-PASS0001',
    request_id: 'REQ-CHATGPT-PASS0001',
    occurred_at: nowMinus(9),
    client_id: 'CLT-WEB-001',
    user_id: 'USR-0041',
    tenant_id: 'TNT-001',
    action: 'ALLOW',
    final_action: 'ALLOW',
    recommended_action: 'ALLOW',
    detection_outcome: 'NO_MATCH',
    severity: 'LOW',
    status: 'RESOLVED',
    admin_notes: [],
    timeline: detectedTimeline('EVT-PASS0001', nowMinus(9)),
    detections: [],
    target_llm: 'ChatGPT',
    host: 'chatgpt.com',
    endpoint: '/backend-api/f/conversation',
    content_type: 'prompt',
    processing_ms: 8.2,
    enforcement: { applied: true, http_status: 200 },
    degraded: false,
    detector_version: 'detector-orchestrator-2.1.0',
    ruleset_version: 'gateway-policy-7',
  },
  {
    event_id: 'EVT-OPEN0001',
    request_id: 'REQ-GEMINI-OPEN0001',
    occurred_at: nowMinus(27),
    client_id: 'CLT-WEB-006',
    tenant_id: 'TNT-001',
    action: 'ALLOW',
    final_action: 'ALLOW',
    detection_outcome: 'UNAVAILABLE',
    severity: 'HIGH',
    status: 'NEW',
    admin_notes: [],
    timeline: detectedTimeline('EVT-OPEN0001', nowMinus(27)),
    detections: [],
    target_llm: 'Gemini',
    host: 'gemini.google.com',
    endpoint: '/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate',
    content_type: 'prompt',
    processing_ms: 3002,
    enforcement: { applied: true, http_status: 200 },
    degraded: true,
    degraded_reason: 'TIMEOUT',
    failure_policy: 'FAIL_OPEN',
    detector_version: 'detector-orchestrator-2.1.0',
    ruleset_version: 'gateway-policy-7',
  },
  {
    event_id: 'EVT-CLOSE001',
    request_id: 'REQ-CLAUDE-CLOSE001',
    occurred_at: nowMinus(51),
    client_id: 'CLT-WEB-012',
    tenant_id: 'TNT-001',
    action: 'BLOCK',
    final_action: 'BLOCK',
    detection_outcome: 'UNAVAILABLE',
    severity: 'CRITICAL',
    status: 'NEW',
    admin_notes: [],
    timeline: detectedTimeline('EVT-CLOSE001', nowMinus(51)),
    detections: [],
    target_llm: 'Claude',
    host: 'claude.ai',
    endpoint: '/api/organizations/demo/chat_conversations/demo/completion',
    content_type: 'prompt',
    processing_ms: 3001,
    enforcement: { applied: true, http_status: 503 },
    degraded: true,
    degraded_reason: 'TIMEOUT',
    failure_policy: 'FAIL_CLOSED',
    detector_version: 'detector-orchestrator-2.1.0',
    ruleset_version: 'gateway-policy-8',
  },
  {
    event_id: 'EVT-OVRD0001',
    request_id: 'REQ-OPENAI-OVRD0001',
    occurred_at: nowMinus(64),
    client_id: 'CLT-API-004',
    tenant_id: 'TNT-001',
    action: 'BLOCK',
    final_action: 'BLOCK',
    recommended_action: 'MASK',
    detection_outcome: 'MATCH',
    severity: 'HIGH',
    status: 'INVESTIGATING',
    assignee: 'security.lead',
    admin_notes: [],
    timeline: detectedTimeline('EVT-OVRD0001', nowMinus(64)),
    detections: [
      {
        detector: 'SIGNATURE',
        match_type: 'SIGNATURE_RULE',
        category: 'PHONE_NUMBER',
        rule_id: 'SIG-014',
        policy_id: 'POL-PII-02',
        policy_version: 'v4',
        confidence: 0.99,
        entity_count: 1,
        action: 'MASK',
        recommended_action: 'MASK',
      },
    ],
    target_llm: 'Claude',
    host: 'claude.ai',
    endpoint: '/api/organizations/.../chat_conversations',
    content_type: 'prompt',
    processing_ms: 14.9,
    enforcement: { applied: true, http_status: 403 },
    degraded: false,
    detector_version: 'signature-3.0.1',
    ruleset_version: 'gateway-policy-8',
  },
];

const multiOccurredAt = nowMinus(104);
const multiDetectionEventDto: SecurityEventDto = {
  event_id: 'EVT-MULTI004',
  occurred_at: multiOccurredAt,
  client_id: 'CLT-OPS-017',
  user_id: 'USR-0204',
  tenant_id: 'TNT-001',
  action: 'BLOCK',
  severity: 'HIGH',
  status: 'NEW',
  admin_notes: [],
  timeline: detectedTimeline('EVT-MULTI004', multiOccurredAt),
  detections: [
    {
      detector: 'MINHASH',
      match_type: 'SIMILAR_DOCUMENT',
      similarity: 0.91,
      threshold: 0.8,
      outbound_document_name: '설계검토서_요약.pdf',
      matched_document_id: 'DOC-A23F19B2',
      matched_document_name: '설계검토서.pdf',
      action: 'BLOCK',
    },
    {
      detector: 'SIGNATURE',
      match_type: 'SIGNATURE_RULE',
      category: 'EMAIL_ADDRESS',
      rule_id: 'SIG-006',
      policy_id: 'POL-006',
      policy_version: 'v2',
      action: 'MASK',
    },
  ],
  target_llm: 'Gemini',
  processing_ms: 21.3,
};

const llms: TargetLlmDto[] = ['ChatGPT', 'Gemini', 'Claude'];
const categories = [
  'API_KEY',
  'PASSWORD',
  'ACCESS_TOKEN',
  'PRIVATE_KEY',
  'CONNECTION_STRING',
  'EMAIL_ADDRESS',
];
const documents = [
  ['DOC-SEMICON-001', '반도체공정.pdf'],
  ['DOC-A23F19B2', '설계검토서.pdf'],
  ['DOC-C904E71A', '사업계획.xlsx'],
  ['DOC-7BD213F0', '제품로드맵.docx'],
] as const;
const severities: SeverityDto[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const statuses: IncidentStatusDto[] = ['NEW', 'INVESTIGATING', 'RESOLVED'];

const generatedEventDtos: SecurityEventDto[] = Array.from(
  { length: 51 },
  (_, index) => {
    const occurredAt = nowMinus(115 + index * 185);
    const flavor = index % 5;
    let detections: DetectionDto[];
    if (flavor === 0) {
      const [documentId, documentName] = documents[index % documents.length];
      detections = [
        {
          detector: 'SHA256',
          match_type: 'EXACT_DOCUMENT',
          outbound_document_name: documentName,
          matched_document_id: documentId,
          matched_document_name: documentName,
          action: 'BLOCK',
        },
      ];
    } else if (flavor === 1 || flavor === 2) {
      const [documentId, documentName] = documents[index % documents.length];
      const isFragment = flavor === 2;
      detections = isFragment
        ? [
            {
              detector: 'WINDOW_HASH',
              match_type: 'TEXT_FRAGMENT',
              score: 0.82 + (index % 9) / 100,
              score_kind: 'COVERAGE',
              threshold: 0.8,
              matched_document_id: documentId,
              matched_document_name: documentName,
              input_location: { char_start: 0, char_end: 180 + index },
              matched_location: {
                char_start: 400 + index * 7,
                char_end: 580 + index * 8,
              },
              action: index % 4 === 0 ? 'MASK' : 'BLOCK',
            },
          ]
        : [
            {
              detector: 'MINHASH',
              match_type: 'SIMILAR_DOCUMENT',
              similarity: 0.9 + (index % 8) / 100,
              threshold: 0.8,
              outbound_document_name: `수정본_${index + 1}.docx`,
              matched_document_id: documentId,
              matched_document_name: documentName,
              action: index % 4 === 0 ? 'MASK' : 'BLOCK',
            },
          ];
    } else {
      const category = categories[index % categories.length];
      const action: SecurityActionDto = ['PASSWORD', 'PRIVATE_KEY'].includes(
        category,
      )
        ? 'BLOCK'
        : 'MASK';
      detections = [
        {
          detector: 'SIGNATURE',
          match_type: 'SIGNATURE_RULE',
          category,
          rule_id: `SIG-${String((index % 12) + 1).padStart(3, '0')}`,
          policy_id: `POL-${String((index % 6) + 1).padStart(3, '0')}`,
          policy_version: `v${2 + (index % 4)}`,
          confidence: 0.92 + (index % 7) / 100,
          entity_count: 1 + (index % 3),
          action,
        },
      ];
    }
    const action: SecurityActionDto = detections.some(
      (detection) => detection.action === 'BLOCK',
    )
      ? 'BLOCK'
      : 'MASK';
    const status = statuses[index % statuses.length];
    return {
      event_id: `EVT-${(0xa11ce100 + index * 0x1f35b).toString(16).toUpperCase()}`,
      occurred_at: occurredAt,
      client_id: `CLT-${String(1001 + (index % 14)).padStart(4, '0')}`,
      ...(index % 4
        ? {
            user_id: `USR-${String(41 + ((index * 47) % 860)).padStart(4, '0')}`,
          }
        : {}),
      ...(index % 5 === 0
        ? { tenant_id: `TNT-${String((index % 3) + 1).padStart(3, '0')}` }
        : {}),
      action,
      severity:
        action === 'BLOCK'
          ? severities[2 + (index % 2)]
          : severities[index % 3],
      status,
      ...(status === 'INVESTIGATING'
        ? { assignee: index % 2 ? 'security.lead' : 'admin-001' }
        : {}),
      admin_notes: [],
      timeline: detectedTimeline(`EVT-GEN-${index}`, occurredAt),
      detections,
      target_llm: llms[index % llms.length],
      processing_ms: Number((7.1 + ((index * 13) % 97) / 4).toFixed(1)),
    };
  },
);

export const initialEventDtos: SecurityEventDto[] = [
  ...operationalEventDtos,
  ...flagshipEventDtos,
  multiDetectionEventDto,
  ...generatedEventDtos,
];
