// 보안 현황 추가 지표(재설계 3b, 설계 5.1.1 권고 ①②③). 서버 변경 없이 화면이 이미 받는 응답으로만 계산한다.
//  ① 차단·마스킹 사유: 기간 이벤트 목록(dashboardService.getStats가 추이 검증용으로 읽는 readPeriodEvents) — 이벤트마다 대표 사유 1개
//  ② 검사 없이 처리된 요청: 같은 목록 + inspectionFailure()와 같은 분류(reasonLabels.ts) + GET /api/gateway-settings(지금 설정 1줄)
//  ③ 보호 범위: GET /api/documents(documentProtectionStage = 보호 문서 화면과 같은 규칙) + GET /api/keywords + GET /api/keyword-jobs
import type { ConfidentialDocument } from '@/src/types/policy';
import type { AttachedEvent, SecurityEvent } from '@/src/types/event';
import type { DocumentKeyword, KeywordJob } from '@/src/services/detectionOpsService';
import type { GatewaySettingsValues } from '@/src/api/gatewaySettingsSchemas';
import { documentProtectionStage } from './documentPresentation';
import { entityCategory } from './entityCategory';
import { isAccessBlockReason, isNoResponseReason, isUninspectedReason } from './reasonLabels';
import { isDemoDocument } from '@/src/utils/demoDocuments';

export type ReasonKey = 'access' | 'no-response' | 'uninspectable' | 'mask-failed' | 'document' | 'keyword' | 'credential' | 'pii' | 'other';

/** 대표 사유 순서(설계 5.1.1 ① 계산): 접속 차단 → 응답 없음 → 검사 불가 파일 → 마스킹 불가 → 보호 문서 일치 → 기밀 키워드 → 자격증명 → 개인정보 */
export const REASON_ORDER: readonly ReasonKey[] = ['access', 'no-response', 'uninspectable', 'mask-failed', 'document', 'keyword', 'credential', 'pii', 'other'];
export const REASON_INFO: Readonly<Record<ReasonKey, { label: string; to: string; setting: string }>> = {
  access: { label: '접속 차단', to: '/policies/access', setting: '접속 차단' },
  'no-response': { label: '보안 검사 응답 없음', to: '/policies/gateway', setting: 'Gateway 처리' },
  uninspectable: { label: '검사할 수 없는 파일', to: '/policies/gateway', setting: 'Gateway 처리' },
  'mask-failed': { label: '마스킹할 수 없음', to: '/policies/gateway', setting: 'Gateway 처리' },
  document: { label: '보호 문서 일치', to: '/documents', setting: '보호 문서' },
  keyword: { label: '기밀 키워드', to: '/policies/keywords', setting: '문서별 키워드' },
  credential: { label: '자격증명', to: '/policies', setting: '탐지 정책' },
  pii: { label: '개인정보', to: '/policies', setting: '탐지 정책' },
  other: { label: '사유 미기록', to: '/events', setting: '보안 이벤트' },
};
const MASK_FAILED = new Set(['mask_application_failed', 'file_masking_failed']);

/** 사유를 고를 때 보는 칸(목록 행과 묶음의 첨부 파일이 같이 쓴다) */
type ReasonSource = Pick<SecurityEvent, 'reasonCode' | 'degraded' | 'detections' | 'finalAction'> & { detectionOutcome?: SecurityEvent['detectionOutcome'] };

function entityTypes(event: ReasonSource) {
  return event.detections.flatMap((detection) => detection.detector === 'SIGNATURE' ? (detection.entityCounts ?? []).filter((entity) => entity.count > 0).map((entity) => entity.entityType) : []);
}

/** 요청 1건의 구성(2026-10-15): 목록 묶음이면 질문 + 첨부 파일, 아니면 그 기록 하나 */
export function requestMembers(event: SecurityEvent): ReasonSource[] {
  return [event, ...(event.attachedFiles ?? []).map((file: AttachedEvent) => ({
    reasonCode: file.reasonCode, degraded: file.degraded, detectionOutcome: file.detectionOutcome, detections: file.detections, finalAction: file.finalAction,
  }))];
}
const requestAction = (event: SecurityEvent) => event.groupFinalAction ?? event.finalAction;

/** 이벤트 1건의 대표 사유(차단·마스킹 이벤트에 쓴다) */
export function representativeReason(event: ReasonSource): ReasonKey {
  const code = event.reasonCode;
  if (isAccessBlockReason(code)) return 'access';
  if (event.degraded || isNoResponseReason(code) || (event.detectionOutcome === 'UNAVAILABLE' && !isUninspectedReason(code))) return 'no-response';
  if (isUninspectedReason(code)) return 'uninspectable';
  if (code && MASK_FAILED.has(code)) return 'mask-failed';
  if (event.detections.some((detection) => 'matchedDocumentId' in detection && detection.matchedDocumentId)) return 'document';
  const types = entityTypes(event).map(entityCategory);
  if (types.includes('KEYWORD')) return 'keyword';
  if (types.includes('CREDENTIAL')) return 'credential';
  if (types.includes('PII') || event.detections.some((detection) => detection.detector === 'SIGNATURE')) return 'pii';
  // 검출 목록이 비어도 사유 코드가 있으면 그것으로(감사 11번): 보호 문서 일치·개인정보
  if (code === 'doc_excerpt') return 'document';
  if (code === 'pii') return 'pii';
  return 'other';
}

/** 요청(목록 묶음)의 대표 사유: 묶음 조치를 낸 구성(질문 먼저)의 사유 */
function requestReason(event: SecurityEvent): ReasonKey {
  const action = requestAction(event);
  return representativeReason(requestMembers(event).find((member) => member.finalAction === action) ?? event);
}

export interface ReasonRow { key: ReasonKey; label: string; to: string; block: number; mask: number }

/** ① 차단·마스킹 사유: 많은 순(같으면 대표 사유 순서), 0건 줄은 뺀다. 행의 조치 = 묶음 조치(카드와 같은 단위) */
export function actionReasons(events: readonly SecurityEvent[]): ReasonRow[] {
  const rows = new Map<ReasonKey, ReasonRow>();
  for (const event of events) {
    const action = requestAction(event);
    if (action === 'ALLOW') continue;
    const key = requestReason(event);
    const row = rows.get(key) ?? { key, label: REASON_INFO[key].label, to: REASON_INFO[key].to, block: 0, mask: 0 };
    if (action === 'BLOCK') row.block += 1;
    else row.mask += 1;
    rows.set(key, row);
  }
  return [...rows.values()].sort((a, b) => (b.block + b.mask) - (a.block + a.mask) || REASON_ORDER.indexOf(a.key) - REASON_ORDER.indexOf(b.key));
}

export type UninspectedKey = 'no-response' | 'uninspectable' | 'too-large';
export const UNINSPECTED_LABEL: Readonly<Record<UninspectedKey, string>> = {
  'no-response': '보안 검사 응답 없음',
  uninspectable: '검사할 수 없는 파일',
  'too-large': '파일이 커서 검사 못 함',
};
export interface Uninspected { allow: number; block: number; rows: Array<{ key: UninspectedKey; label: string; allow: number; block: number }> }

/** 이벤트가 검사 없이 처리됐는지와 그 사유. 접속 차단은 검사 대상이 아니라 뺀다(설계 5.1.1 ② 계산) */
export function uninspectedKind(event: Pick<SecurityEvent, 'reasonCode' | 'degraded'> & { detectionOutcome?: SecurityEvent['detectionOutcome'] }): UninspectedKey | undefined {
  const code = event.reasonCode;
  if (isAccessBlockReason(code)) return undefined;
  if (code === 'file_too_large') return 'too-large';
  if (isUninspectedReason(code)) return 'uninspectable';
  if (event.degraded || event.detectionOutcome === 'UNAVAILABLE' || isNoResponseReason(code)) return 'no-response';
  return undefined;
}

/** ② 검사 없이 처리된 요청: 허용과 그 밖(차단·마스킹)을 따로 센다. 요청 단위 묶음이면 질문·첨부 파일 중 처음 검사 못 한 것의 사유·조치로 1건 */
export function uninspectedRequests(events: readonly SecurityEvent[]): Uninspected {
  const keys: UninspectedKey[] = ['no-response', 'uninspectable', 'too-large'];
  const rows = keys.map((key) => ({ key, label: UNINSPECTED_LABEL[key], allow: 0, block: 0 }));
  for (const event of events) {
    const member = requestMembers(event).find((item) => uninspectedKind(item));
    const kind = member && uninspectedKind(member);
    if (!member || !kind) continue;
    const row = rows[keys.indexOf(kind)];
    if (member.finalAction === 'ALLOW') row.allow += 1;
    else row.block += 1;
  }
  return { allow: rows.reduce((sum, row) => sum + row.allow, 0), block: rows.reduce((sum, row) => sum + row.block, 0), rows };
}

/** ② 분모: 접속 차단을 뺀 행 수(분자와 같은 기준, 감사 7번). 새 서버 목록은 이미 접속 차단이 빠져 있다 */
export function inspectableCount(events: readonly SecurityEvent[]) {
  return events.filter((event) => !isAccessBlockReason(event.reasonCode)).length;
}

/** ② 지금 설정 1줄: "응답 없음 → 프롬프트 전달 · 파일 차단 / 검사할 수 없는 파일 → 이미지 허용 · 스캔 PDF 차단 · 그 밖 차단" */
export function settingSummary(values: GatewaySettingsValues) {
  const timeout = (action: 'block' | 'forward') => (action === 'forward' ? '허용' : '차단');
  const file = (action: 'block' | 'allow') => (action === 'allow' ? '허용' : '차단');
  return {
    timeout: `프롬프트 ${timeout(values.timeout.prompt.action)} · 파일 ${timeout(values.timeout.file.action)}`,
    uninspectable: `이미지 ${file(values.uninspectable.image)} · 스캔 PDF ${file(values.uninspectable.scanned_pdf)} · 그 밖 ${file(values.uninspectable.other)}`,
  };
}

export type CoverageKey = 'protected' | 'analyzing' | 'failed' | 'stopped' | 'check';
export const COVERAGE_LABEL: Readonly<Record<CoverageKey, string>> = { protected: '보호 중', analyzing: '분석 중', failed: '분석 실패', stopped: '보호 중지', check: '확인 필요' };   // 2026-10-16: 문서 배지와 같은 말
const STAGE_TO_COVERAGE: Readonly<Record<string, CoverageKey>> = { '보호 중': 'protected', '분석 중': 'analyzing', '분석 실패': 'failed', '보호 중지': 'stopped', '준비 확인 필요': 'check' };

/** ③ 보호 범위: 문서 상태 합치기(보호 문서 화면 배지와 같은 규칙) + 승인 대기 키워드 수 + 최근 추출이 실패한 문서 수 */
export function protectionCoverage(all: readonly ConfidentialDocument[], keywords?: readonly DocumentKeyword[], jobs?: readonly KeywordJob[]) {
  // 2026-10-16 공통 규칙: 문서 수에서 시연 문서(DEMO_) 제외
  const documents = all.filter((document) => !isDemoDocument(document.documentId));
  const counts: Record<CoverageKey, number> = { protected: 0, analyzing: 0, failed: 0, stopped: 0, check: 0 };
  for (const document of documents) counts[STAGE_TO_COVERAGE[documentProtectionStage(document).label] ?? 'check'] += 1;
  return {
    total: documents.length,
    demoExcluded: all.length - documents.length,
    counts,
    pendingKeywords: keywords ? keywords.filter((keyword) => keyword.status === 'pending').length : undefined,
    failedExtractions: jobs ? failedExtractionDocuments(documents, jobs).length : undefined,
  };
}

/** 키워드 추출 실패 문서(2026-10-15 감사 8번 — 보안 현황·문서별 키워드 단추·실패 목록이 같이 쓴다):
 * 지금 등록된 문서 중 마지막(번호가 가장 큰) 추출 작업이 실패인 문서. 옛 실패 작업이 남아 있어도 다시 추출해 성공했으면 세지 않는다 */
export function failedExtractionDocuments(documents: readonly Pick<ConfidentialDocument, 'documentId'>[], jobs: readonly KeywordJob[]) {
  const registered = new Set(documents.map((document) => document.documentId));
  const latest = new Map<string, KeywordJob>();
  for (const job of [...jobs].sort((a, b) => b.id - a.id)) if (!latest.has(job.doc_id)) latest.set(job.doc_id, job);
  return [...latest.values()].filter((job) => job.status === 'failed' && registered.has(job.doc_id)).map((job) => job.doc_id);
}
