import { redactEvidence } from './match-evidence.mjs';

const ACTIONS = new Set(['ALLOW', 'BLOCK', 'MASK']);
const ACTION_INPUTS = new Set([...ACTIONS, 'ALLOW_DEGRADED']);
const TARGET_LLMS = new Set(['ChatGPT', 'Gemini', 'Claude']);
const SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const OUTCOMES = new Set(['MATCH', 'NO_MATCH', 'UNAVAILABLE']);
const DEGRADED_REASONS = new Set([
  'TIMEOUT',
  'UNREACHABLE',
  'PARSE_ERROR',
  'OTHER',
]);
const FAILURE_POLICIES = new Set(['FAIL_OPEN', 'FAIL_CLOSED']);

const EVENT_FIELDS = new Set([
  'type',
  'eventId',
  'requestId',
  'timestamp',
  'clientId',
  'userId',
  'tenantId',
  'targetLlm',
  'contentType',
  'host',
  'endpoint',
  'detectionOutcome',
  'recommendedAction',
  'finalAction',
  'severity',
  'enforcement',
  'maskEvidence',
  'processingMs',
  'degraded',
  'degradedReason',
  'failurePolicy',
  'detectorVersion',
  'rulesetVersion',
  'modelVersion',
  'reasonCode',
  'policyVersion',
  'detections',
  // 2026-10-09 질문과 첨부 파일 연결: 파일 이벤트의 파일 번호, 질문 이벤트에 붙은 파일 번호들(번호만, 내용 없음)
  'fileId',
  'attachedFileIds',
  // 2026-10-09 내 요청 기록: 요청을 보낸 브라우저의 열람 키 지문(SHA-256). 키 값은 받지 않는다
  'viewerKeyHash',
  // 2026-10-12 접속 차단: 차단한 규칙 번호(reasonCode가 client_blocked일 때만)
  'accessRuleId',
]);
const ACCESS_RULE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FILE_REF = /^[A-Za-z0-9_-]{1,100}$/;

function fileRef(value, path) {
  if (typeof value !== 'string' || !FILE_REF.test(value)) fail('must be a file reference', path);
  return value;
}

function fileRefs(value, path) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 20) fail('must be an array of at most 20 file references', path);
  return [...new Set(value.map((item, index) => fileRef(item, `${path}.${index}`)))];
}

const DETECTION_FIELDS = {
  SHA256: new Set([
    'detector',
    'matchType',
    'outboundDocumentName',
    'matchedDocumentId',
    'matchedDocumentName',
    'action',
    'recommendedAction',
  ]),
  WINDOW_HASH: new Set([
    'detector',
    'matchType',
    'score',
    'scoreKind',
    'threshold',
    'matchedDocumentId',
    'matchedDocumentName',
    'inputSpan',
    'documentSpan',
    'action',
    'recommendedAction',
  ]),
  MINHASH: new Set([
    'detector',
    'matchType',
    'similarity',
    'threshold',
    'outboundDocumentName',
    'matchedDocumentId',
    'matchedDocumentName',
    'action',
    'recommendedAction',
  ]),
  SIGNATURE: new Set([
    'detector',
    'matchType',
    'category',
    'ruleId',
    'policyId',
    'policyVersion',
    'action',
    'recommendedAction',
    'confidence',
    'entityCount',
    'entityCounts',
  ]),
};

export class ValidationError extends Error {
  constructor(message, path = 'body') {
    super(message);
    this.name = 'ValidationError';
    this.path = path;
  }
}

function fail(message, path) {
  throw new ValidationError(message, path);
}

function isObject(value) {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function object(value, path) {
  if (!isObject(value)) fail('must be an object', path);
  return value;
}

function rejectUnknown(value, allowed, path) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail('contains an unsupported field', `${path}.${key}`);
  }
}

function string(value, path, { optional = false, max = 500 } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'string' || value.trim().length === 0)
    fail('must be a non-empty string', path);
  if (value.length > max) fail(`must be at most ${max} characters`, path);
  return value;
}

function enumValue(value, values, path, { optional = false } = {}) {
  if (value === undefined && optional) return undefined;
  if (!values.has(value)) fail('contains an unsupported value', path);
  return value;
}

function actionValue(value, path, { optional = false } = {}) {
  const action = enumValue(value, ACTION_INPUTS, path, { optional });
  return action === 'ALLOW_DEGRADED' ? 'ALLOW' : action;
}

function boolean(value, path, { optional = false } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'boolean') fail('must be a boolean', path);
  return value;
}

function number(
  value,
  path,
  { optional = false, nullable = false, min = 0, max = Number.MAX_SAFE_INTEGER, integer = false } = {},
) {
  if (value === undefined && optional) return undefined;
  if (value === null && nullable) return null;
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    value < min ||
    value > max ||
    (integer && !Number.isInteger(value))
  )
    fail('contains an invalid number', path);
  return value;
}

function isoTimestamp(value, path) {
  string(value, path, { max: 50 });
  if (
    !/(?:Z|[+-]\d{2}:\d{2})$/.test(value) ||
    Number.isNaN(Date.parse(value))
  )
    fail('must be an ISO-8601 timestamp with timezone', path);
  return value;
}

function span(value, path) {
  const raw = object(value, path);
  rejectUnknown(raw, new Set(['charStart', 'charEnd', 'endExclusive']), path);
  const charStart = number(raw.charStart, `${path}.charStart`, {
    integer: true,
  });
  const charEnd = number(raw.charEnd, `${path}.charEnd`, {
    integer: true,
    min: 1,
  });
  if (charEnd <= charStart)
    fail('charEnd must be greater than charStart', `${path}.charEnd`);
  if (raw.endExclusive !== undefined && raw.endExclusive !== true)
    fail('must be true when supplied', `${path}.endExclusive`);
  return { charStart, charEnd, endExclusive: true };
}

function optionalString(value, path, max = 500) {
  return string(value, path, { optional: true, max });
}

function detectionBase(raw, path) {
  return {
    action: actionValue(raw.action, `${path}.action`),
    recommendedAction: actionValue(
      raw.recommendedAction,
      `${path}.recommendedAction`,
      { optional: true },
    ),
  };
}

function validateSha256(raw, path) {
  rejectUnknown(raw, DETECTION_FIELDS.SHA256, path);
  if (raw.matchType !== 'EXACT_DOCUMENT')
    fail('SHA256 requires EXACT_DOCUMENT', `${path}.matchType`);
  if (raw.action !== 'BLOCK')
    fail('SHA256 exact matches require BLOCK', `${path}.action`);
  if (raw.recommendedAction !== undefined && raw.recommendedAction !== 'BLOCK')
    fail('SHA256 recommendation must be BLOCK', `${path}.recommendedAction`);
  return {
    detector: 'SHA256',
    matchType: 'EXACT_DOCUMENT',
    outboundDocumentName: string(
      raw.outboundDocumentName,
      `${path}.outboundDocumentName`,
    ),
    matchedDocumentId: string(
      raw.matchedDocumentId,
      `${path}.matchedDocumentId`,
    ),
    matchedDocumentName: optionalString(
      raw.matchedDocumentName,
      `${path}.matchedDocumentName`,
    ),
    ...detectionBase(raw, path),
  };
}

function validateWindowHash(raw, path) {
  rejectUnknown(raw, DETECTION_FIELDS.WINDOW_HASH, path);
  if (raw.matchType !== 'TEXT_FRAGMENT')
    fail('WINDOW_HASH requires TEXT_FRAGMENT', `${path}.matchType`);
  if (raw.scoreKind !== 'COVERAGE')
    fail('WINDOW_HASH requires COVERAGE', `${path}.scoreKind`);
  return {
    detector: 'WINDOW_HASH',
    matchType: 'TEXT_FRAGMENT',
    score: number(raw.score, `${path}.score`, { max: 1 }),
    scoreKind: 'COVERAGE',
    threshold: number(raw.threshold, `${path}.threshold`, {
      optional: true,
      nullable: true,
      max: 1,
    }),
    matchedDocumentId: string(
      raw.matchedDocumentId,
      `${path}.matchedDocumentId`,
    ),
    matchedDocumentName: optionalString(
      raw.matchedDocumentName,
      `${path}.matchedDocumentName`,
    ),
    inputSpan:
      raw.inputSpan === undefined
        ? undefined
        : span(raw.inputSpan, `${path}.inputSpan`),
    documentSpan: span(raw.documentSpan, `${path}.documentSpan`),
    ...detectionBase(raw, path),
  };
}

function validateMinHash(raw, path) {
  rejectUnknown(raw, DETECTION_FIELDS.MINHASH, path);
  if (raw.matchType !== 'SIMILAR_DOCUMENT')
    fail('MINHASH requires SIMILAR_DOCUMENT', `${path}.matchType`);
  const similarity = number(raw.similarity, `${path}.similarity`, { max: 1 });
  const threshold = number(raw.threshold, `${path}.threshold`, { max: 1 });
  if (similarity < threshold)
    fail('triggered similarity must meet the threshold', `${path}.similarity`);
  return {
    detector: 'MINHASH',
    matchType: 'SIMILAR_DOCUMENT',
    similarity,
    threshold,
    outboundDocumentName: string(
      raw.outboundDocumentName,
      `${path}.outboundDocumentName`,
    ),
    matchedDocumentId: string(
      raw.matchedDocumentId,
      `${path}.matchedDocumentId`,
    ),
    matchedDocumentName: optionalString(
      raw.matchedDocumentName,
      `${path}.matchedDocumentName`,
    ),
    ...detectionBase(raw, path),
  };
}

function validateSignature(raw, path) {
  rejectUnknown(raw, DETECTION_FIELDS.SIGNATURE, path);
  if (raw.matchType !== 'SIGNATURE_RULE')
    fail('SIGNATURE requires SIGNATURE_RULE', `${path}.matchType`);
  const policyVersion = optionalString(
    raw.policyVersion,
    `${path}.policyVersion`,
    30,
  );
  if (policyVersion !== undefined && !/^v\d+$/.test(policyVersion))
    fail('must use the v<number> format', `${path}.policyVersion`);
  const category = optionalString(raw.category, `${path}.category`, 100);
  const ruleId = optionalString(raw.ruleId, `${path}.ruleId`, 200);
  if ((category === undefined) !== (ruleId === undefined))
    fail('category and ruleId must be supplied together', `${path}.ruleId`);
  let entityCounts;
  if (raw.entityCounts !== undefined) {
    if (!Array.isArray(raw.entityCounts) || raw.entityCounts.length === 0)
      fail('must be a non-empty array', `${path}.entityCounts`);
    if (raw.entityCounts.length > 50)
      fail('must contain at most 50 entries', `${path}.entityCounts`);
    entityCounts = raw.entityCounts.map((value, index) => {
      const itemPath = `${path}.entityCounts[${index}]`;
      const item = object(value, itemPath);
      rejectUnknown(item, new Set(['entityType', 'count']), itemPath);
      return {
        entityType: string(item.entityType, `${itemPath}.entityType`, { max: 100 }),
        count: number(item.count, `${itemPath}.count`, {
          integer: true,
          min: 1,
        }),
      };
    });
    if (new Set(entityCounts.map((item) => item.entityType)).size !== entityCounts.length)
      fail('must not contain duplicate entity types', `${path}.entityCounts`);
  }
  if (ruleId === undefined && entityCounts === undefined)
    fail('requires rule metadata or entityCounts', path);
  return {
    detector: 'SIGNATURE',
    matchType: 'SIGNATURE_RULE',
    category,
    ruleId,
    policyId: optionalString(raw.policyId, `${path}.policyId`, 200),
    policyVersion,
    confidence: number(raw.confidence, `${path}.confidence`, {
      optional: true,
      max: 1,
    }),
    entityCount: number(raw.entityCount, `${path}.entityCount`, {
      optional: true,
      integer: true,
      min: 1,
    }),
    entityCounts,
    ...detectionBase(raw, path),
  };
}

function validateDetection(value, index) {
  const path = `body.detections[${index}]`;
  const raw = object(value, path);
  const detector = enumValue(
    raw.detector,
    new Set(Object.keys(DETECTION_FIELDS)),
    `${path}.detector`,
  );
  if (detector === 'SHA256') return validateSha256(raw, path);
  if (detector === 'WINDOW_HASH') return validateWindowHash(raw, path);
  if (detector === 'MINHASH') return validateMinHash(raw, path);
  return validateSignature(raw, path);
}

function validateEnforcement(value) {
  if (value === undefined) return undefined;
  const raw = object(value, 'body.enforcement');
  rejectUnknown(raw, new Set(['applied', 'httpStatus']), 'body.enforcement');
  return {
    applied: boolean(raw.applied, 'body.enforcement.applied'),
    httpStatus: number(raw.httpStatus, 'body.enforcement.httpStatus', {
      optional: true,
      integer: true,
      min: 100,
      max: 599,
    }),
  };
}

function validateMaskEvidence(value) {
  if (value === undefined) return undefined;
  const raw = object(value, 'body.maskEvidence');
  rejectUnknown(raw, new Set(['status','representation','beforePreview','afterPreview','beforeChars','afterChars','previewTruncated','outboundTextSha256','spans']), 'body.maskEvidence');
  if (raw.status !== 'REQUEST_REWRITTEN') fail('must be REQUEST_REWRITTEN', 'body.maskEvidence.status');
  if (!/^[a-f0-9]{64}$/.test(raw.outboundTextSha256??'')) fail('invalid digest','body.maskEvidence.outboundTextSha256');
  if (!Array.isArray(raw.spans) || raw.spans.length>100) fail('invalid spans','body.maskEvidence.spans');
  const beforeChars=number(raw.beforeChars,'body.maskEvidence.beforeChars',{integer:true,min:0,max:2_000_000});
  const afterChars=number(raw.afterChars,'body.maskEvidence.afterChars',{integer:true,min:0,max:2_000_000});
  return {status:raw.status,
    representation:enumValue(raw.representation,new Set(['JSON_TEXT','GEMINI_FORM_TEXT']),'body.maskEvidence.representation'),
    beforePreview:redactEvidence(string(raw.beforePreview,'body.maskEvidence.beforePreview',{max:8000})),
    afterPreview:redactEvidence(string(raw.afterPreview,'body.maskEvidence.afterPreview',{max:8000})),
    beforeChars,afterChars,previewTruncated:boolean(raw.previewTruncated,'body.maskEvidence.previewTruncated'),
    outboundTextSha256:raw.outboundTextSha256,
    spans:raw.spans.map((value,index)=>{const path=`body.maskEvidence.spans.${index}`;const item=object(value,path);
      rejectUnknown(item,new Set(['start','end','entityType']),path);
      const start=number(item.start,`${path}.start`,{integer:true,min:0,max:beforeChars});
      const end=number(item.end,`${path}.end`,{integer:true,min:1,max:beforeChars});
      if(end<=start)fail('invalid range',path);
      return {start,end,entityType:string(item.entityType,`${path}.entityType`,{max:100})};}),
  };
}

export function validateCanonicalEvent(value) {
  const raw = object(value, 'body');
  rejectUnknown(raw, EVENT_FIELDS, 'body');
  if (raw.maskEvidence !== undefined && (raw.finalAction!=='MASK'||raw.enforcement?.applied!==true||raw.contentType!=='prompt'))
    fail('mask evidence requires an applied prompt MASK','body.maskEvidence');
  if (raw.type !== undefined && raw.type !== 'SECURITY_EVENT')
    fail('must be SECURITY_EVENT', 'body.type');
  if (!Array.isArray(raw.detections))
    fail('must be an array', 'body.detections');
  if (raw.detections.length > 20)
    fail('must contain at most 20 detections', 'body.detections');

  const detectionOutcome = enumValue(
    raw.detectionOutcome,
    OUTCOMES,
    'body.detectionOutcome',
    { optional: true },
  );
  if (detectionOutcome === 'MATCH' && raw.detections.length === 0)
    fail('MATCH requires at least one detection', 'body.detections');

  const event = {
    type: 'SECURITY_EVENT',
    eventId: string(raw.eventId, 'body.eventId', { max: 200 }),
    requestId: optionalString(raw.requestId, 'body.requestId', 200),
    timestamp: isoTimestamp(raw.timestamp, 'body.timestamp'),
    clientId: string(raw.clientId, 'body.clientId', { max: 200 }),
    userId: optionalString(raw.userId, 'body.userId', 200),
    tenantId: optionalString(raw.tenantId, 'body.tenantId', 200),
    targetLlm: enumValue(raw.targetLlm, TARGET_LLMS, 'body.targetLlm'),
    contentType: enumValue(
      raw.contentType,
      new Set(['prompt', 'file']),
      'body.contentType',
      { optional: true },
    ),
    host: optionalString(raw.host, 'body.host', 300),
    endpoint: optionalString(raw.endpoint, 'body.endpoint', 500),
    detectionOutcome,
    recommendedAction: actionValue(
      raw.recommendedAction,
      'body.recommendedAction',
      { optional: true },
    ),
    finalAction: actionValue(raw.finalAction, 'body.finalAction'),
    severity: enumValue(raw.severity, SEVERITIES, 'body.severity', {
      optional: true,
    }),
    enforcement: validateEnforcement(raw.enforcement),
    maskEvidence: validateMaskEvidence(raw.maskEvidence),
    processingMs: number(raw.processingMs, 'body.processingMs', {
      optional: true,
    }),
    degraded:
      raw.finalAction === 'ALLOW_DEGRADED' ||
      raw.recommendedAction === 'ALLOW_DEGRADED'
        ? true
        : boolean(raw.degraded, 'body.degraded', { optional: true }),
    degradedReason: enumValue(
      raw.degradedReason,
      DEGRADED_REASONS,
      'body.degradedReason',
      { optional: true },
    ),
    failurePolicy: enumValue(
      raw.failurePolicy,
      FAILURE_POLICIES,
      'body.failurePolicy',
      { optional: true },
    ),
    detectorVersion: optionalString(
      raw.detectorVersion,
      'body.detectorVersion',
      100,
    ),
    rulesetVersion: optionalString(
      raw.rulesetVersion,
      'body.rulesetVersion',
      100,
    ),
    modelVersion: optionalString(raw.modelVersion, 'body.modelVersion', 100),
    reasonCode: optionalString(raw.reasonCode, 'body.reasonCode', 100),
    policyVersion: optionalString(raw.policyVersion, 'body.policyVersion', 100),
    fileId: raw.fileId === undefined ? undefined : fileRef(raw.fileId, 'body.fileId'),
    attachedFileIds: fileRefs(raw.attachedFileIds, 'body.attachedFileIds'),
    viewerKeyHash: raw.viewerKeyHash === undefined ? undefined
      : /^[0-9a-f]{64}$/.test(String(raw.viewerKeyHash)) ? raw.viewerKeyHash : fail('must be a SHA-256 hex digest', 'body.viewerKeyHash'),
    accessRuleId: raw.accessRuleId === undefined ? undefined
      : typeof raw.accessRuleId === 'string' && ACCESS_RULE_ID.test(raw.accessRuleId) ? raw.accessRuleId : fail('must be a lowercase UUID', 'body.accessRuleId'),
    detections: raw.detections.map(validateDetection),
  };
  if (event.accessRuleId !== undefined && event.reasonCode !== 'client_blocked')
    fail('requires reasonCode=client_blocked', 'body.accessRuleId');
  if (event.fileId !== undefined && event.contentType !== 'file')
    fail('requires contentType=file', 'body.fileId');
  if (event.attachedFileIds !== undefined && event.contentType === 'file')
    fail('requires a prompt event', 'body.attachedFileIds');

  if (event.degradedReason !== undefined && event.degraded !== true)
    fail('requires degraded=true', 'body.degradedReason');
  if (event.failurePolicy !== undefined && event.degraded !== true)
    fail('requires degraded=true', 'body.failurePolicy');
  return event;
}

function compact(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => item !== undefined),
  );
}

function detectionToDto(detection) {
  const common = compact({
    detector: detection.detector,
    match_type: detection.matchType,
    action: detection.action,
    recommended_action: detection.recommendedAction,
  });
  if (detection.detector === 'SHA256')
    return compact({
      ...common,
      outbound_document_name: detection.outboundDocumentName,
      matched_document_id: detection.matchedDocumentId,
      matched_document_name: detection.matchedDocumentName,
    });
  if (detection.detector === 'MINHASH')
    return compact({
      ...common,
      similarity: detection.similarity,
      threshold: detection.threshold,
      outbound_document_name: detection.outboundDocumentName,
      matched_document_id: detection.matchedDocumentId,
      matched_document_name: detection.matchedDocumentName,
    });
  if (detection.detector === 'SIGNATURE')
    return compact({
      ...common,
      category: detection.category,
      rule_id: detection.ruleId,
      policy_id: detection.policyId,
      policy_version: detection.policyVersion,
      confidence: detection.confidence,
      entity_count: detection.entityCount,
      entity_counts: detection.entityCounts?.map((item) => ({
        entity_type: item.entityType,
        count: item.count,
      })),
    });
  return compact({
    ...common,
    score: detection.score,
    score_kind: detection.scoreKind,
    threshold: detection.threshold,
    matched_document_id: detection.matchedDocumentId,
    matched_document_name: detection.matchedDocumentName,
    input_location: detection.inputSpan
      ? {
          char_start: detection.inputSpan.charStart,
          char_end: detection.inputSpan.charEnd,
        }
      : undefined,
    matched_location: {
      char_start: detection.documentSpan.charStart,
      char_end: detection.documentSpan.charEnd,
    },
  });
}

export function canonicalEventToDto(event) {
  return compact({
    event_id: event.eventId,
    request_id: event.requestId,
    occurred_at: event.timestamp,
    client_id: event.clientId,
    user_id: event.userId,
    tenant_id: event.tenantId,
    action: event.finalAction,
    final_action: event.finalAction,
    recommended_action: event.recommendedAction,
    detection_outcome: event.detectionOutcome,
    severity: event.severity,
    status: 'NEW',
    admin_notes: [],
    timeline: [],
    detections: event.detections.map(detectionToDto),
    target_llm: event.targetLlm,
    host: event.host,
    endpoint: event.endpoint,
    content_type: event.contentType,
    processing_ms: event.processingMs,
    enforcement: event.enforcement
      ? compact({
          applied: event.enforcement.applied,
          http_status: event.enforcement.httpStatus,
        })
      : undefined,
    degraded: event.degraded,
    degraded_reason: event.degradedReason,
    failure_policy: event.failurePolicy,
    detector_version: event.detectorVersion,
    ruleset_version: event.rulesetVersion,
    model_version: event.modelVersion,
    reason_code: event.reasonCode,
    policy_version: event.policyVersion,
    file_id: event.fileId,
    attached_file_ids: event.attachedFileIds?.length ? event.attachedFileIds : undefined,
    viewer_key_hash: event.viewerKeyHash,
    access_rule_id: event.accessRuleId,
  });
}
