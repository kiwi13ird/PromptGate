// 접속 차단(2026-10-12) - 확장 프로그램 ID 차단·해제, 사유 선택, 별칭, '확장 ID 없는 접속 차단' 방식.
// 계약: /api/gateway-access(문서 번호 expected_version으로 저장) · /api/client-aliases. 응답은 어댑터가 zod로 확인한다.
import { gatewayApi } from '@/src/api';
import { ApiError } from '@/src/api/errors';
import {
  ACCESS_REPORT_INVALID,
  ALIAS_MAX,
  BLOCK_REASON_CODES,
  CLIENT_ID_PATTERN,
  MEMO_MAX,
  blockReasonText,
  isBlockableClientId,
  isPlaceholderClientId,
  type AccessApplied,
  type AccessRule,
  type AccessWriteResult,
  type BlockDuration,
  type BlockReasonCode,
  type ClientAliasesResponse,
  type GatewayAccessResponse,
} from '@/src/api/gatewayAccessSchemas';
import { formatClock, formatSavedAt } from '@/src/services/gatewaySettingsService';
import type { TrafficClient } from '@/src/types/traffic';
import { safeMessage } from '@/src/utils/feedback';
import { formatCount } from '@/src/utils/format';

export {
  ALIAS_MAX,
  BLOCK_DURATION_CODES,
  BLOCK_DURATION_OPTIONS,
  BLOCK_REASON_CODES,
  BLOCK_REASON_OPTIONS,
  MEMO_MAX,
  accessRuleCreateBodySchema,
  blockReasonText,
  clientAliasesResponseSchema,
  gatewayAccessResponseSchema,
  isBlockableClientId,
  isPlaceholderClientId,
} from '@/src/api/gatewayAccessSchemas';
export type {
  AccessApplied,
  AccessRule,
  BlockDuration,
  BlockReasonCode,
  ClientAliasesResponse,
  GatewayAccessResponse,
} from '@/src/api/gatewayAccessSchemas';

export const gatewayAccessKeys = {
  all: ['gateway-access'] as const,
  detail: () => ['gateway-access', 'detail'] as const,
  aliases: () => ['gateway-access', 'aliases'] as const,
};

export const gatewayAccessService = {
  get(signal?: AbortSignal): Promise<GatewayAccessResponse> {
    return gatewayApi.getGatewayAccess(signal);
  },
  /** expectedVersion: 화면이 본 문서 번호. 그사이 다른 저장이 있으면 서버가 409로 거부한다 */
  addRule(
    input: { clientId: string; reasons: BlockReasonCode[]; memo: string; duration: BlockDuration; showMemoToUser?: boolean },
    expectedVersion: number,
    signal?: AbortSignal,
  ): Promise<AccessWriteResult> {
    const memo = input.memo.trim();
    return gatewayApi.addAccessRule(
      {
        client_id: input.clientId,
        reasons: input.reasons,
        ...(memo ? { memo } : {}),
        // 메모가 있고 관리자가 고른 경우에만 보낸다(기본 false는 보내지 않는다)
        ...(memo && input.showMemoToUser ? { show_memo_to_user: true } : {}),
        duration: input.duration,
        expected_version: expectedVersion,
      },
      signal,
    );
  },
  removeRule(ruleId: string, expectedVersion: number, signal?: AbortSignal): Promise<AccessWriteResult> {
    return gatewayApi.removeAccessRule(ruleId, expectedVersion, signal);
  },
  setMode(requireClientId: boolean, expectedVersion: number, signal?: AbortSignal): Promise<AccessWriteResult> {
    return gatewayApi.setAccessMode({ require_client_id: requireClientId, expected_version: expectedVersion }, signal);
  },
};

export const clientAliasService = {
  list(signal?: AbortSignal): Promise<ClientAliasesResponse> {
    return gatewayApi.getClientAliases(signal);
  },
  /** 빈 별칭은 지운다 */
  set(clientId: string, alias: string, signal?: AbortSignal): Promise<void> {
    return gatewayApi.setClientAlias(clientId, alias.trim(), signal);
  },
};

// ───── 규칙 상태 ─────

export type AccessRuleStatus = 'ACTIVE' | 'EXPIRED' | 'REMOVED';

/** 해제됐으면 REMOVED, 만료 시각이 지났거나 서버가 active=false로 보냈으면 EXPIRED(만료는 화면 시계로도 따라간다) */
export function ruleStatus(rule: AccessRule, now: number): AccessRuleStatus {
  if (rule.removed_at) return 'REMOVED';
  if (rule.expires_at && Date.parse(rule.expires_at) <= now) return 'EXPIRED';
  if (rule.active === false) return 'EXPIRED';
  return 'ACTIVE';
}
export const ruleIsActive = (rule: AccessRule, now: number) => ruleStatus(rule, now) === 'ACTIVE';

/** 이 확장 ID에 지금 걸려 있는 차단 규칙 */
export function findActiveRule(rules: readonly AccessRule[], clientId: string | null | undefined, now: number): AccessRule | undefined {
  if (!clientId) return undefined;
  return rules.find(rule => rule.client_id === clientId && ruleIsActive(rule, now));
}

/** 남은 시간 글자: 59분 · 2시간 5분 · 1일 3시간 */
export function formatRemaining(milliseconds: number): string {
  if (milliseconds < 60_000) return '1분 미만';
  const minutes = Math.ceil(milliseconds / 60_000);
  if (minutes < 60) return `${minutes}분`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return minutes % 60 ? `${hours}시간 ${minutes % 60}분` : `${hours}시간`;
  return hours % 24 ? `${Math.floor(hours / 24)}일 ${hours % 24}시간` : `${Math.floor(hours / 24)}일`;
}

/** 연결 IP 표 배지: 영구 또는 '남은 시간 …' */
export function remainingBadgeText(rule: AccessRule, now: number): string {
  if (!rule.expires_at) return '영구';
  return `남은 시간 ${formatRemaining(Date.parse(rule.expires_at) - now)}`;
}

/** 규칙 표 '기간' 칸 */
export function ruleDurationText(rule: AccessRule, now: number): string {
  switch (ruleStatus(rule, now)) {
    case 'ACTIVE': return remainingBadgeText(rule, now);
    case 'EXPIRED': return `만료됨 · ${formatSavedAt(rule.expires_at)}`;
    case 'REMOVED': return `해제됨 · ${formatSavedAt(rule.removed_at)}`;
  }
}

/** 차단 번호: 규칙 번호 앞 8자(사용자 안내 화면과 같다) */
export const blockNumber = (ruleId: string) => ruleId.slice(0, 8);

// ───── 입력 확인 ─────

export interface BlockInput {
  clientId: string;
  reasons: readonly string[];
  memo: string;
  showMemoToUser?: boolean;
}

/** 차단 입력 확인. 문제가 없으면 null, 있으면 화면에 보일 문구 하나 */
export function validateBlockInput(input: BlockInput, rules: readonly AccessRule[] = [], now = Date.now()): string | null {
  const clientId = input.clientId.trim();
  if (!clientId) return '차단할 확장 프로그램 ID를 입력하세요.';
  if (!CLIENT_ID_PATTERN.test(clientId)) return '확장 프로그램 ID 형식이 올바르지 않습니다.';
  if (isPlaceholderClientId(clientId)) return '사용자를 구분할 수 없는 ID(unknown-·legacy-)는 차단할 수 없습니다.';
  if (findActiveRule(rules, clientId, now)) return '이미 차단 중인 확장 프로그램 ID입니다.';
  if (!input.reasons.length) return '사유를 하나 이상 선택하세요.';
  const memo = input.memo.trim();
  if (input.reasons.includes('OTHER') && !memo) return '사유 ‘기타’를 고르면 메모를 입력해야 합니다.';
  if (input.memo.length > MEMO_MAX) return `메모는 ${MEMO_MAX}자까지 입력할 수 있습니다.`;
  if (input.showMemoToUser && !memo) return '메모를 입력해야 사용자에게 보일 수 있습니다.';
  return null;
}

/** 차단된 사용자에게 보이는 내용(대화상자 미리보기 · Gateway 차단 화면과 같은 문구): 사유 줄 + 공개를 고른 메모 */
export function userVisibleBlock(reasons: readonly string[], memo: string, showMemoToUser: boolean): { reasonLine: string; memoLine: string | null } {
  const text = reasons.map(blockReasonText).join(' · ');
  const note = memo.trim();
  return { reasonLine: `사유: ${text || '선택 전'}`, memoLine: showMemoToUser && note ? `관리자 안내: ${note}` : null };
}

/** 선택한 사유를 고정 순서(BLOCK_REASON_CODES)로 */
export const orderReasons = (selected: ReadonlySet<string>): BlockReasonCode[] =>
  BLOCK_REASON_CODES.filter(code => selected.has(code));

/** 주소의 reason 값(쉼표로 여러 개 가능)에서 아는 사유 코드만 고정 순서로. 모르는 값은 버린다 */
export const parseReasonParam = (value: string | null | undefined): BlockReasonCode[] =>
  orderReasons(new Set((value ?? '').split(',').map(code => code.trim())));

export const validateAlias = (alias: string): string | null =>
  alias.trim().length > ALIAS_MAX ? `별칭은 ${ALIAS_MAX}자까지 입력할 수 있습니다.` : null;

// ───── 별칭 ─────

export const aliasMapOf = (response: ClientAliasesResponse | undefined): ReadonlyMap<string, string> =>
  new Map((response?.items ?? []).map(item => [item.client_id, item.alias]));

// ───── 연결 IP ─────

/** 지금 연결 중인 IP 수와 그중 확장 프로그램 ID가 없는 IP 수(‘확장 ID 없는 접속 차단’을 켜면 막힐 대상) */
export function countConnectedClients(clients: readonly TrafficClient[]): { connected: number; withoutId: number } {
  const connected = clients.filter(client => client.connections > 0);
  return { connected: connected.length, withoutId: connected.filter(client => !client.clientId).length };
}

/** '확장 ID 없는 접속 차단' 확인창 문구. stale이면 연결 IP 수가 실제와 다를 수 있다고 덧붙인다 */
export function modeConfirmText(turnOn: boolean, counts: { connected: number; withoutId: number } | null, stale = false): string[] {
  if (!turnOn) return ['끄면 확장 프로그램 ID가 없는 접속도 다시 허용됩니다.'];
  const lines = ['켜면 확장 프로그램 ID 없이 들어오는 요청을 Gateway가 막습니다. 확장 프로그램을 끄거나 식별 헤더를 쓰지 않는 사용자도 막힙니다.'];
  lines.push(counts
    ? `지금 연결 중인 IP ${formatCount(counts.connected)}개 중 ${formatCount(counts.withoutId)}개가 확장 프로그램 ID 없이 접속 중입니다.${counts.withoutId ? ' 켜면 이 접속이 막힙니다.' : ''}${stale ? ' (Gateway 지표가 오래되어 실제와 다를 수 있습니다.)' : ''}`
    : '연결 중인 IP 수를 불러오지 못했습니다.');
  return lines;
}

// ───── Gateway 반영 상태 ─────

export type AccessApplyState = 'APPLIED' | 'PENDING' | 'REJECTED' | 'NOT_REPORTING' | 'REPORT_INVALID';
export type AccessApplyTone = 'ok' | 'pending' | 'warn';
/** Gateway 보고가 이 시간 넘게 갱신되지 않으면 ‘보고 없음’(연결 IP 표의 지표 지연 기준과 같은 30초) */
export const ACCESS_REPORT_STALE_MS = 30_000;

const REJECTED_FIELD_TEXT: Record<string, string> = {
  version: '문서 번호', revision: '문서 revision', updated_at: '갱신 시각', require_client_id: '확장 ID 없는 접속 차단', rules: '차단 목록',
};
const RULE_PART_TEXT: Record<string, string> = { id: '차단 번호', client_id: '확장 프로그램 ID', expires_at: '만료 시각', reasons: '사유', user_memo: '사용자 안내 메모' };
/** Gateway가 거부한 칸 경로(rules.3.client_id 등)의 이름. 모르는 경로는 그대로 */
export function accessFieldText(field: string): string {
  const rule = /^rules\.(\d+)\.([a-z_]+)$/.exec(field);
  if (rule) return `차단 목록 ${Number(rule[1]) + 1}번째 ${RULE_PART_TEXT[rule[2]] ?? rule[2]}`;
  return REJECTED_FIELD_TEXT[field] ?? field;
}

/** Gateway가 이 문서(번호+revision)를 반영했는지. 저장된 목록이 없으면(번호 0) 어떤 보고든 반영으로 본다 */
export function isDocumentApplied(document: GatewayAccessResponse): boolean {
  const applied = document.applied;
  if (!applied || applied === ACCESS_REPORT_INVALID) return false;
  if (document.version === 0) return true;
  return applied.version === document.version && applied.revision === document.revision;
}

/** 저장한 번호(savedVersion) 이상을 Gateway가 보고했는지 - 저장 직후 ‘반영 대기 → 반영됨’ 표시 */
export function isVersionApplied(document: GatewayAccessResponse | undefined, savedVersion: number): boolean {
  const applied = document?.applied;
  return Boolean(applied && applied !== ACCESS_REPORT_INVALID && applied.version !== null && applied.version >= savedVersion);
}

/** ‘접속 차단’ 탭 상태 줄: 반영됨 · 반영 대기 · 거부됨 · 보고 없음 */
export function accessApplyStatus(document: GatewayAccessResponse, now: number): { state: AccessApplyState; tone: AccessApplyTone; text: string } {
  const applied = document.applied;
  if (applied === ACCESS_REPORT_INVALID)
    return { state: 'REPORT_INVALID', tone: 'warn', text: 'Gateway 보고 형식 오류 · 반영 여부 확인 불가' };
  if (!applied)
    return { state: 'NOT_REPORTING', tone: 'warn', text: 'Gateway 보고 없음 · 접속 차단을 지원하지 않는 판이거나 첫 보고 전(최대 10초)' };
  const receivedAt = Date.parse(applied.received_at);
  if (Number.isFinite(receivedAt) && now - receivedAt > ACCESS_REPORT_STALE_MS)
    return { state: 'NOT_REPORTING', tone: 'warn', text: `Gateway 보고 없음 · 마지막 보고 ${formatClock(applied.received_at)}` };
  if (isDocumentApplied(document)) {
    const head = document.version === 0 ? 'Gateway 반영 · 저장된 목록 없음' : `Gateway 반영 v${applied.version}`;
    return { state: 'APPLIED', tone: 'ok', text: `${head} · 적용 중 차단 ${formatCount(applied.active_rules)}개 · 최근 5분 막은 요청 ${formatCount(applied.denied_5m)}건(화면 로딩 포함) · 확인 ${formatClock(applied.received_at)}` };
  }
  if (applied.rejected)
    return { state: 'REJECTED', tone: 'warn', text: `Gateway가 이 목록을 거부함 · 거부한 칸 ${accessFieldText(applied.rejected)}` };
  const current = applied.version === null ? ' · Gateway 현재 목록 없음' : ` · Gateway 현재 v${applied.version}`;
  return { state: 'PENDING', tone: 'pending', text: `Gateway 반영 대기 중${current}` };
}

/** ‘접속 차단’ 탭 첫 줄: 저장된 목록 */
export function accessSavedText(document: GatewayAccessResponse, now: number): string {
  if (document.version === 0) return '저장된 목록 없음 · 아무도 차단하지 않음';
  const active = document.rules.filter(rule => ruleIsActive(rule, now)).length;
  const who = document.updated_by ? ` · ${document.updated_by}` : '';
  const when = document.updated_at ? ` · ${formatSavedAt(document.updated_at)}` : '';
  return `저장 v${document.version}${when}${who} · 적용 중 차단 ${formatCount(active)}개 · 확장 ID 없는 접속 차단 ${document.require_client_id ? '켜짐' : '꺼짐'}`;
}

// ───── 오류 문구 ─────

export const ACCESS_CONFLICT_MESSAGE = '다른 관리자가 먼저 바꿨습니다. 최신 목록을 확인하세요.';
export const ACCESS_DUPLICATE_MESSAGE = '이미 차단 중인 확장 프로그램 ID입니다.';
export const ACCESS_NOT_READY_MESSAGE = '대시보드 서버가 아직 접속 차단을 지원하지 않습니다(서버 반영 전).';
export const ACCESS_UNAVAILABLE_MESSAGE = '접속 차단 목록을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.';

export const isAccessConflict = (error: unknown) => error instanceof ApiError && error.code === 'CONFLICT';
export const isAccessNotReady = (error: unknown) => error instanceof ApiError && error.status === 404;

/** 저장·조회 실패 문구. 서버 오류 코드를 그대로 보이지 않는다 */
export function accessErrorMessage(error: unknown): string {
  if (isAccessConflict(error)) return ACCESS_CONFLICT_MESSAGE;
  if (isAccessNotReady(error)) return ACCESS_NOT_READY_MESSAGE;
  if (error instanceof ApiError && error.status === 503) return ACCESS_UNAVAILABLE_MESSAGE;
  if (error instanceof ApiError && error.code === 'VALIDATION') return '저장할 수 없는 값입니다. 입력 값을 확인하세요.';
  return safeMessage(error);
}

export { formatSavedAt };
