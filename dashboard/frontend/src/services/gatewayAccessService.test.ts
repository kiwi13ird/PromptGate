import { describe, expect, it } from 'vitest';
import {
  ACCESS_REPORT_STALE_MS,
  BLOCK_DURATION_OPTIONS,
  BLOCK_REASON_OPTIONS,
  accessApplyStatus,
  accessErrorMessage,
  accessFieldText,
  accessRuleCreateBodySchema,
  accessSavedText,
  aliasMapOf,
  blockNumber,
  blockReasonText,
  clientAliasesResponseSchema,
  countConnectedClients,
  findActiveRule,
  formatRemaining,
  gatewayAccessResponseSchema,
  isBlockableClientId,
  isDocumentApplied,
  isVersionApplied,
  modeConfirmText,
  orderReasons,
  parseReasonParam,
  remainingBadgeText,
  ruleDurationText,
  ruleIsActive,
  ruleStatus,
  validateAlias,
  validateBlockInput,
  type AccessRule,
  type GatewayAccessResponse,
} from './gatewayAccessService';
import { ApiError } from '@/src/api/errors';
import type { TrafficClient } from '@/src/types/traffic';

// 접속 차단(2026-10-12) 순수 함수·계약 확인. 확장 ID·IP·시각은 모두 가짜.
const NOW = Date.parse('2026-10-12T05:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';
const ID_B = 'chrome-9b1e4d7c-2a6f-4c3b-8e05-7f2d9a6c4b18';

const rule = (over: Partial<AccessRule> = {}): AccessRule => ({
  id: '1a2b3c4d-0000-4000-8000-000000000001', client_id: ID_A, reasons: ['INVESTIGATION'], memo: null,
  expires_at: iso(NOW + 2 * 3_600_000 + 5 * 60_000), created_by: 'local-admin', created_at: iso(NOW - 60_000),
  removed_by: null, removed_at: null, active: true, ...over,
});
const doc = (over: Partial<GatewayAccessResponse> = {}): GatewayAccessResponse => ({
  version: 5, revision: REV, require_client_id: false, rules: [rule()],
  applied: { version: 5, revision: REV, source: 'DASHBOARD', applied_at: iso(NOW - 3_000), rejected: null, active_rules: 1, require_client_id: false, denied_5m: 3, received_at: iso(NOW - 4_000) },
  ...over,
});
const client = (over: Partial<TrafficClient> = {}): TrafficClient => ({
  ip: '203.0.113.5', clientId: ID_A, connections: 1, inflight: 0, waiting: 0, requests5m: 1, targets: [], firstSeenAt: iso(NOW - 1000), lastSeenAt: iso(NOW - 500), ...over,
});

describe('which client ids can be blocked', () => {
  it.each([
    [ID_A, true],
    ['chrome-1', true],
    ['A', true],
    ['a.b_c:d@e-f', true],
    ['unknown-client', false],
    ['Unknown-Client', false],
    ['legacy-gateway', false],
    ['LEGACY-x', false],
    ['', false],
    [' chrome-1', false],
    ['chrome 1', false],
    ['-chrome', false],
    ['a'.repeat(80), true],
    ['a'.repeat(81), false],
    [undefined, false],
    [null, false],
  ])('%s -> %s', (value, expected) => {
    expect(isBlockableClientId(value as string | null | undefined)).toBe(expected);
  });
});

describe('block form validation', () => {
  const ok = { clientId: ID_A, reasons: ['INVESTIGATION'], memo: '' };
  it('accepts a valid input', () => {
    expect(validateBlockInput(ok)).toBeNull();
    expect(validateBlockInput({ ...ok, reasons: ['LEAVE', 'OTHER'], memo: '  사유  ' })).toBeNull();
  });
  it('requires at least one reason', () => {
    expect(validateBlockInput({ ...ok, reasons: [] })).toBe('사유를 하나 이상 선택하세요.');
  });
  it('requires a memo when 기타 is chosen, even if the memo is only spaces', () => {
    expect(validateBlockInput({ ...ok, reasons: ['OTHER'], memo: '' })).toBe('사유 ‘기타’를 고르면 메모를 입력해야 합니다.');
    expect(validateBlockInput({ ...ok, reasons: ['OTHER'], memo: '   ' })).toBe('사유 ‘기타’를 고르면 메모를 입력해야 합니다.');
    expect(validateBlockInput({ ...ok, reasons: ['OTHER', 'LEAVE'], memo: '메모' })).toBeNull();
    expect(validateBlockInput({ ...ok, reasons: ['LEAVE'], memo: '' })).toBeNull();
  });
  it('limits the memo to 200 characters', () => {
    expect(validateBlockInput({ ...ok, memo: 'a'.repeat(200) })).toBeNull();
    expect(validateBlockInput({ ...ok, memo: 'a'.repeat(201) })).toBe('메모는 200자까지 입력할 수 있습니다.');
  });
  it('checks the id: empty, shape, placeholder', () => {
    expect(validateBlockInput({ ...ok, clientId: '' })).toBe('차단할 확장 프로그램 ID를 입력하세요.');
    expect(validateBlockInput({ ...ok, clientId: '  ' })).toBe('차단할 확장 프로그램 ID를 입력하세요.');
    expect(validateBlockInput({ ...ok, clientId: 'chrome 1' })).toBe('확장 프로그램 ID 형식이 올바르지 않습니다.');
    expect(validateBlockInput({ ...ok, clientId: 'unknown-client' })).toBe('사용자를 구분할 수 없는 ID(unknown-·legacy-)는 차단할 수 없습니다.');
    expect(validateBlockInput({ ...ok, clientId: 'legacy-gateway' })).toMatch(/차단할 수 없습니다/);
  });
  it('refuses an id that already has an active rule, but not an expired or removed one', () => {
    expect(validateBlockInput(ok, [rule()], NOW)).toBe('이미 차단 중인 확장 프로그램 ID입니다.');
    expect(validateBlockInput(ok, [rule({ expires_at: iso(NOW - 1) })], NOW)).toBeNull();
    expect(validateBlockInput(ok, [rule({ removed_at: iso(NOW - 5), removed_by: 'x' })], NOW)).toBeNull();
    expect(validateBlockInput(ok, [rule({ client_id: ID_B })], NOW)).toBeNull();
  });
  it('orders the chosen reasons by the fixed code list, not by click order', () => {
    expect(orderReasons(new Set(['OTHER', 'LEAVE', 'LEAK_DOC_REPEAT']))).toEqual(['LEAK_DOC_REPEAT', 'LEAVE', 'OTHER']);
    expect(orderReasons(new Set(['nope']))).toEqual([]);
  });
  it('reads the reason of a report link: known codes only, fixed order, no duplicates', () => {
    expect(parseReasonParam('LEAK_DOC_REPEAT')).toEqual(['LEAK_DOC_REPEAT']);
    expect(parseReasonParam('PII_REPEAT,LEAK_DOC_REPEAT,PII_REPEAT')).toEqual(['LEAK_DOC_REPEAT', 'PII_REPEAT']);
    expect(parseReasonParam(' PII_REPEAT , nope ,')).toEqual(['PII_REPEAT']);
    expect(parseReasonParam('leak_doc_repeat')).toEqual([]);   // 코드는 대소문자를 구분한다
    expect(parseReasonParam('')).toEqual([]);
    expect(parseReasonParam(null)).toEqual([]);
    expect(parseReasonParam(undefined)).toEqual([]);
  });
  it('validates the alias length after trimming', () => {
    expect(validateAlias('a'.repeat(40))).toBeNull();
    expect(validateAlias(`  ${'a'.repeat(40)}  `)).toBeNull();
    expect(validateAlias('a'.repeat(41))).toBe('별칭은 40자까지 입력할 수 있습니다.');
    expect(validateAlias('')).toBeNull();
  });
});

describe('preset labels', () => {
  it('uses the stable codes and Korean labels from the spec', () => {
    expect(BLOCK_REASON_OPTIONS.map(option => [option.code, option.label])).toEqual([
      ['LEAK_DOC_REPEAT', '기밀 문서 반복 유출 시도'],
      ['PII_REPEAT', '개인정보 반복 입력'],
      ['INVESTIGATION', '보안 조사 중'],
      ['LEAVE', '퇴사·휴직 예정'],
      ['ADMIN_REQUEST', '관리자 요청'],
      ['OTHER', '기타'],
    ]);
    expect(BLOCK_DURATION_OPTIONS.map(option => [option.code, option.label])).toEqual([['1h', '1시간'], ['1d', '1일'], ['permanent', '영구']]);
    expect(blockReasonText('LEAVE')).toBe('퇴사·휴직 예정');
    expect(blockReasonText('FUTURE_CODE')).toBe('FUTURE_CODE');
  });
});

describe('rule status and time text', () => {
  it('tells active, expired and removed rules apart, following the screen clock for expiry', () => {
    expect(ruleStatus(rule(), NOW)).toBe('ACTIVE');
    expect(ruleStatus(rule({ expires_at: null }), NOW)).toBe('ACTIVE');
    expect(ruleStatus(rule({ expires_at: iso(NOW) }), NOW)).toBe('EXPIRED');   // 만료 시각 정각부터 만료
    expect(ruleStatus(rule({ expires_at: iso(NOW + 1) }), NOW)).toBe('ACTIVE');
    expect(ruleStatus(rule({ removed_at: iso(NOW - 10), removed_by: 'a' }), NOW)).toBe('REMOVED');
    expect(ruleStatus(rule({ expires_at: iso(NOW - 10), removed_at: iso(NOW - 10) }), NOW)).toBe('REMOVED');
    expect(ruleStatus(rule({ active: false }), NOW)).toBe('EXPIRED');
    expect(ruleIsActive(rule({ active: undefined }), NOW)).toBe(true);
  });
  it('finds the active rule of a client id', () => {
    const rules = [rule({ id: 'x', client_id: ID_B, expires_at: iso(NOW - 1) }), rule()];
    expect(findActiveRule(rules, ID_A, NOW)?.id).toBe(rule().id);
    expect(findActiveRule(rules, ID_B, NOW)).toBeUndefined();
    expect(findActiveRule(rules, undefined, NOW)).toBeUndefined();
    expect(findActiveRule(rules, null, NOW)).toBeUndefined();
  });
  it.each([
    [30_000, '1분 미만'],
    [60_000, '1분'],
    [61_000, '2분'],
    [59 * 60_000, '59분'],
    [59 * 60_000 + 59_000, '1시간'],
    [3_600_000, '1시간'],
    [2 * 3_600_000 + 5 * 60_000, '2시간 5분'],
    [23 * 3_600_000 + 59 * 60_000, '23시간 59분'],
    [24 * 3_600_000, '1일'],
    [27 * 3_600_000, '1일 3시간'],
  ])('formats %i ms as %s', (ms, text) => {
    expect(formatRemaining(ms)).toBe(text);
  });
  it('writes the badge and the duration cell', () => {
    expect(remainingBadgeText(rule(), NOW)).toBe('남은 시간 2시간 5분');
    expect(remainingBadgeText(rule({ expires_at: null }), NOW)).toBe('영구');
    expect(ruleDurationText(rule(), NOW)).toBe('남은 시간 2시간 5분');
    expect(ruleDurationText(rule({ expires_at: null }), NOW)).toBe('영구');
    expect(ruleDurationText(rule({ expires_at: '2026-10-12T04:00:00.000Z' }), NOW)).toBe('만료됨 · 2026-10-12 13:00');
    expect(ruleDurationText(rule({ removed_at: '2026-10-12T04:30:00.000Z', removed_by: 'a' }), NOW)).toBe('해제됨 · 2026-10-12 13:30');
  });
  it('shows the first 8 characters of the rule id as the block number', () => {
    expect(blockNumber('1a2b3c4d-0000-4000-8000-000000000001')).toBe('1a2b3c4d');
  });
});

describe('gateway apply status', () => {
  it('APPLIED when version and revision match', () => {
    const status = accessApplyStatus(doc(), NOW);
    expect(status).toMatchObject({ state: 'APPLIED', tone: 'ok' });
    expect(status.text).toBe('Gateway 반영 v5 · 적용 중 차단 1개 · 최근 5분 막은 요청 3건(화면 로딩 포함) · 확인 13:59:56');
  });
  it('PENDING while the gateway reports an older version, or the same version with another revision', () => {
    const older = doc({ applied: { ...doc().applied as object, version: 4 } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(older, NOW)).toEqual({ state: 'PENDING', tone: 'pending', text: 'Gateway 반영 대기 중 · Gateway 현재 v4' });
    const other = doc({ applied: { ...doc().applied as object, revision: '00000000-0000-4000-8000-000000000000' } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(other, NOW).state).toBe('PENDING');
    const none = doc({ applied: { ...doc().applied as object, version: null, revision: null, source: 'NONE' } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(none, NOW).text).toBe('Gateway 반영 대기 중 · Gateway 현재 목록 없음');
  });
  it('REJECTED when the gateway reports a rejected field and has not applied this document', () => {
    const rejected = doc({ applied: { ...doc().applied as object, version: 4, rejected: 'rules.2.client_id' } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(rejected, NOW)).toEqual({ state: 'REJECTED', tone: 'warn', text: 'Gateway가 이 목록을 거부함 · 거부한 칸 차단 목록 3번째 확장 프로그램 ID' });
    // 이미 이 문서를 반영했다면 지난 거부 기록은 무시
    const applied = doc({ applied: { ...doc().applied as object, rejected: 'rules.0.id' } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(applied, NOW).state).toBe('APPLIED');
  });
  it('NOT_REPORTING without a report, and when the last report is older than 30 seconds', () => {
    expect(accessApplyStatus(doc({ applied: null }), NOW)).toMatchObject({ state: 'NOT_REPORTING', tone: 'warn' });
    expect(accessApplyStatus(doc({ applied: undefined }), NOW).state).toBe('NOT_REPORTING');
    const old = doc({ applied: { ...doc().applied as object, received_at: iso(NOW - ACCESS_REPORT_STALE_MS - 1000) } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(old, NOW)).toMatchObject({ state: 'NOT_REPORTING', text: 'Gateway 보고 없음 · 마지막 보고 13:59:29' });
    const edge = doc({ applied: { ...doc().applied as object, received_at: iso(NOW - ACCESS_REPORT_STALE_MS) } as GatewayAccessResponse['applied'] });
    expect(accessApplyStatus(edge, NOW).state).toBe('APPLIED');
  });
  it('REPORT_INVALID for a malformed report block', () => {
    expect(accessApplyStatus(doc({ applied: 'INVALID' }), NOW)).toEqual({ state: 'REPORT_INVALID', tone: 'warn', text: 'Gateway 보고 형식 오류 · 반영 여부 확인 불가' });
  });
  it('treats a gateway report as applied when nothing is stored (version 0)', () => {
    const empty = doc({ version: 0, revision: null, rules: [], applied: { version: null, revision: null, source: 'NONE', applied_at: null, rejected: null, active_rules: 0, require_client_id: false, denied_5m: 0, received_at: iso(NOW - 1000) } });
    expect(isDocumentApplied(empty)).toBe(true);
    expect(accessApplyStatus(empty, NOW).text).toBe('Gateway 반영 · 저장된 목록 없음 · 적용 중 차단 0개 · 최근 5분 막은 요청 0건(화면 로딩 포함) · 확인 13:59:59');
  });
  it('isVersionApplied: reported version >= saved version, never for a missing or null version', () => {
    expect(isVersionApplied(doc(), 5)).toBe(true);
    expect(isVersionApplied(doc(), 4)).toBe(true);
    expect(isVersionApplied(doc(), 6)).toBe(false);
    expect(isVersionApplied(undefined, 1)).toBe(false);
    expect(isVersionApplied(doc({ applied: null }), 1)).toBe(false);
    expect(isVersionApplied(doc({ applied: 'INVALID' }), 1)).toBe(false);
    expect(isVersionApplied(doc({ applied: { ...doc().applied as object, version: null } as GatewayAccessResponse['applied'] }), 0)).toBe(false);
  });
  it('writes the saved line', () => {
    expect(accessSavedText(doc(), NOW)).toBe('저장 v5 · 적용 중 차단 1개 · 확장 ID 없는 접속 차단 꺼짐');
    expect(accessSavedText(doc({ updated_at: '2026-10-12T04:59:00.000Z', updated_by: 'local-admin', require_client_id: true }), NOW))
      .toBe('저장 v5 · 2026-10-12 13:59 · local-admin · 적용 중 차단 1개 · 확장 ID 없는 접속 차단 켜짐');
    expect(accessSavedText(doc({ version: 0, revision: null, rules: [] }), NOW)).toBe('저장된 목록 없음 · 아무도 차단하지 않음');
    expect(accessSavedText(doc({ rules: [rule({ expires_at: iso(NOW - 1) })] }), NOW)).toContain('적용 중 차단 0개');
  });
  it('names the rejected field', () => {
    expect(accessFieldText('rules.0.expires_at')).toBe('차단 목록 1번째 만료 시각');
    expect(accessFieldText('rules.10.id')).toBe('차단 목록 11번째 차단 번호');
    expect(accessFieldText('require_client_id')).toBe('확장 ID 없는 접속 차단');
    expect(accessFieldText('something_new')).toBe('something_new');
  });
});

describe('connected clients and the mode confirmation', () => {
  it('counts only connected IPs and those among them without an extension id', () => {
    const list = [client(), client({ clientId: undefined }), client({ clientId: undefined, connections: 0 }), client({ clientId: ID_B, connections: 0 }), client({ clientId: undefined, connections: 3 })];
    expect(countConnectedClients(list)).toEqual({ connected: 3, withoutId: 2 });
    expect(countConnectedClients([])).toEqual({ connected: 0, withoutId: 0 });
  });
  it('writes the confirmation lines for turning on, with and without the counts', () => {
    expect(modeConfirmText(true, { connected: 12, withoutId: 3 })[1]).toBe('지금 연결 중인 IP 12개 중 3개가 확장 프로그램 ID 없이 접속 중입니다. 켜면 이 접속이 막힙니다.');
    expect(modeConfirmText(true, { connected: 4, withoutId: 0 })[1]).toBe('지금 연결 중인 IP 4개 중 0개가 확장 프로그램 ID 없이 접속 중입니다.');
    expect(modeConfirmText(true, null)[1]).toBe('연결 중인 IP 수를 불러오지 못했습니다.');
    expect(modeConfirmText(true, { connected: 2, withoutId: 1 }, true)[1]).toContain('Gateway 지표가 오래되어');
    expect(modeConfirmText(false, { connected: 2, withoutId: 1 })).toEqual(['끄면 확장 프로그램 ID가 없는 접속도 다시 허용됩니다.']);
  });
  it('maps api errors to plain messages without codes', () => {
    expect(accessErrorMessage(new ApiError('x', 'CONFLICT', 409))).toBe('다른 관리자가 먼저 바꿨습니다. 최신 목록을 확인하세요.');
    expect(accessErrorMessage(new ApiError('x', 'NOT_FOUND', 404))).toBe('대시보드 서버가 아직 접속 차단을 지원하지 않습니다(서버 반영 전).');
    expect(accessErrorMessage(new ApiError('x', 'SERVER', 503))).toBe('접속 차단 목록을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.');
    expect(accessErrorMessage(new ApiError('x', 'VALIDATION', 422))).toBe('저장할 수 없는 값입니다. 입력 값을 확인하세요.');
    expect(accessErrorMessage(new Error('boom'))).toBe('잠시 후 다시 시도해주세요.');
  });
});

describe('contract schemas', () => {
  const body = { client_id: ID_A, reasons: ['INVESTIGATION'], memo: '메모', duration: '1d', expected_version: 5 };
  it('accepts the dashboard document with the applied report', () => {
    const parsed = gatewayAccessResponseSchema.safeParse({
      version: 5, revision: REV, require_client_id: true, updated_at: '2026-10-12T04:59:00.000Z', updated_by: 'local-admin',
      rules: [rule(), rule({ id: '1a2b3c4d-0000-4000-8000-000000000002', client_id: ID_B, memo: '메모', expires_at: null, removed_by: 'a', removed_at: iso(NOW) })],
      applied: { version: 5, revision: REV, source: 'CACHE', applied_at: '2026-10-12T04:59:58.000000+00:00', rejected: null, active_rules: 1, require_client_id: true, denied_5m: 0, received_at: iso(NOW) },
    });
    expect(parsed.success).toBe(true);
  });
  it('accepts an empty store (version 0, null revision) and a missing or null applied report', () => {
    expect(gatewayAccessResponseSchema.safeParse({ version: 0, revision: null, require_client_id: false, rules: [] }).success).toBe(true);
    const parsed = gatewayAccessResponseSchema.parse({ version: 0, revision: null, require_client_id: false, rules: [], applied: null });
    expect(parsed.applied).toBeNull();
  });
  it('turns a malformed applied report into INVALID instead of failing the whole document', () => {
    const parsed = gatewayAccessResponseSchema.parse({ version: 5, revision: REV, require_client_id: false, rules: [], applied: { version: 'x' } });
    expect(parsed.applied).toBe('INVALID');
  });
  it('rejects a document with a bad rule or revision', () => {
    const base = { version: 5, revision: REV, require_client_id: false, rules: [rule()] };
    expect(gatewayAccessResponseSchema.safeParse({ ...base, rules: [rule({ client_id: 'bad id' })] }).success).toBe(false);
    expect(gatewayAccessResponseSchema.safeParse({ ...base, rules: [rule({ id: 'not-a-uuid' })] }).success).toBe(false);
    expect(gatewayAccessResponseSchema.safeParse({ ...base, rules: [rule({ expires_at: 'tomorrow' })] }).success).toBe(false);
    expect(gatewayAccessResponseSchema.safeParse({ ...base, revision: 'x' }).success).toBe(false);
    expect(gatewayAccessResponseSchema.safeParse({ ...base, version: -1 }).success).toBe(false);
    expect(gatewayAccessResponseSchema.safeParse({ ...base, require_client_id: 'yes' }).success).toBe(false);
  });
  it('checks the create body: reasons, OTHER needs memo, placeholder ids, extra fields, duplicates', () => {
    expect(accessRuleCreateBodySchema.safeParse(body).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, memo: undefined }).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, reasons: [] }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, reasons: ['OTHER'], memo: undefined }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, reasons: ['OTHER'], memo: '  ' }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, reasons: ['OTHER'], memo: '기타 사유' }).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, reasons: ['NOPE'] }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, reasons: ['LEAVE', 'LEAVE'] }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, client_id: 'unknown-client' }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, duration: '2d' }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, memo: 'a'.repeat(201) }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, expected_version: -1 }).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse({ ...body, note: 'x' }).success).toBe(false);
  });
  it('reads the alias list into a map', () => {
    const parsed = clientAliasesResponseSchema.parse({ items: [{ client_id: ID_A, alias: '홍길동 PC' }] });
    expect(aliasMapOf(parsed).get(ID_A)).toBe('홍길동 PC');
    expect(aliasMapOf(undefined).size).toBe(0);
    expect(clientAliasesResponseSchema.safeParse({ items: [{ client_id: ID_A, alias: '' }] }).success).toBe(false);
  });
});
