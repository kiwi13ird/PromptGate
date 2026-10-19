import { describe, expect, it, vi } from 'vitest';
import { gatewayApi } from '@/src/api';
import { mockGatewayApi } from '@/src/api/mockAdapter';
import {
  accessFieldText,
  accessRuleCreateBodySchema,
  gatewayAccessResponseSchema,
  gatewayAccessService,
  userVisibleBlock,
  validateBlockInput,
} from './gatewayAccessService';

// 접속 차단 사유·메모 공개(2026-10-12) 계약. 확장 ID·시각은 모두 가짜.
const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';
const REV = '6f1c2a0e-4f7b-4d55-9f43-2f7d5f7f9b10';
const RULE = '1a2b3c4d-0000-4000-8000-000000000001';
const body = (over: Record<string, unknown> = {}) => ({ client_id: ID_A, reasons: ['INVESTIGATION'], duration: '1d', expected_version: 0, ...over });

describe('create body: show_memo_to_user', () => {
  it('is optional (default off) and accepted with a memo', () => {
    expect(accessRuleCreateBodySchema.safeParse(body()).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse(body({ memo: '메모' })).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse(body({ memo: '메모', show_memo_to_user: false })).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse(body({ memo: '메모', show_memo_to_user: true })).success).toBe(true);
    expect(accessRuleCreateBodySchema.safeParse(body({ show_memo_to_user: false })).success).toBe(true);
  });

  it('requires a non-blank memo when true, and a boolean', () => {
    for (const bad of [{ show_memo_to_user: true }, { memo: '', show_memo_to_user: true }, { memo: '   ', show_memo_to_user: true }])
      expect(accessRuleCreateBodySchema.safeParse(body(bad)).success, JSON.stringify(bad)).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse(body({ memo: '메모', show_memo_to_user: 'true' })).success).toBe(false);
    expect(accessRuleCreateBodySchema.safeParse(body({ memo: '메모', show_memo_to_user: 1 })).success).toBe(false);
  });

  it('still rejects other unknown keys', () => {
    expect(accessRuleCreateBodySchema.safeParse(body({ user_memo: '메모' })).success).toBe(false);
  });
});

describe('document: rules with or without show_memo_to_user', () => {
  const rule = (over: Record<string, unknown> = {}) => ({
    id: RULE, client_id: ID_A, reasons: ['INVESTIGATION'], memo: '메모', expires_at: null, created_by: 'local-admin',
    created_at: '2026-10-12T05:00:00.000Z', removed_by: null, removed_at: null, active: true, ...over,
  });
  const doc = (rules: unknown[]) => ({ version: 1, revision: REV, require_client_id: false, rules });

  it('accepts the old shape (no field) and the new one', () => {
    const parsed = gatewayAccessResponseSchema.parse(doc([rule(), rule({ id: '2b3c4d5e-0000-4000-8000-000000000002', show_memo_to_user: true }), rule({ id: '3c4d5e6f-0000-4000-8000-000000000003', show_memo_to_user: false })]));
    expect(parsed.rules.map(item => item.show_memo_to_user)).toEqual([undefined, true, false]);
  });

  it('rejects a non-boolean field', () => {
    expect(gatewayAccessResponseSchema.safeParse(doc([rule({ show_memo_to_user: 'yes' })])).success).toBe(false);
  });
});

describe('addRule', () => {
  const spyApi = () => vi.spyOn(gatewayApi, 'addAccessRule').mockResolvedValue({ version: 1 });
  const input = { clientId: ID_A, reasons: ['INVESTIGATION' as const], memo: '  메모  ', duration: '1d' as const };

  it('sends show_memo_to_user: true only with a memo and the flag', async () => {
    const api = spyApi();
    await gatewayAccessService.addRule({ ...input, showMemoToUser: true }, 3);
    expect(api.mock.calls[0][0]).toEqual({ client_id: ID_A, reasons: ['INVESTIGATION'], memo: '메모', show_memo_to_user: true, duration: '1d', expected_version: 3 });
  });

  it.each([
    ['flag off', { ...input, showMemoToUser: false }],
    ['flag absent', input],
    ['flag on but memo blank', { ...input, memo: '   ', showMemoToUser: true }],
  ])('omits the key when %s', async (_name, value) => {
    const api = spyApi();
    await gatewayAccessService.addRule(value, 3);
    expect(Object.keys(api.mock.calls[0][0])).not.toContain('show_memo_to_user');
  });
});

describe('demo adapter keeps the flag on the stored rule', () => {
  it('stores show_memo_to_user only for a non-blank memo and returns it in the document', async () => {
    await mockGatewayApi.addAccessRule({ client_id: ID_A, reasons: ['INVESTIGATION'], memo: '메모', show_memo_to_user: true, duration: '1d', expected_version: 0 });
    await mockGatewayApi.addAccessRule({ client_id: 'chrome-1', reasons: ['LEAVE'], memo: '비공개', duration: '1d', expected_version: 1 });
    await expect(mockGatewayApi.addAccessRule({ client_id: 'chrome-2', reasons: ['LEAVE'], show_memo_to_user: true, duration: '1d', expected_version: 2 } as never))
      .rejects.toMatchObject({ code: 'VALIDATION', status: 422 });   // 메모 없이 공개는 거부
    const saved = await mockGatewayApi.getGatewayAccess();
    expect(gatewayAccessResponseSchema.safeParse(saved).success).toBe(true);
    expect(saved.rules.map(item => item.show_memo_to_user)).toEqual([true, undefined]);
  });
});

describe('validateBlockInput with showMemoToUser', () => {
  const ok = { clientId: ID_A, reasons: ['INVESTIGATION'], memo: '메모' };
  it('needs a memo to show it', () => {
    expect(validateBlockInput({ ...ok, showMemoToUser: true })).toBeNull();
    expect(validateBlockInput({ ...ok, memo: '  ', showMemoToUser: true })).toBe('메모를 입력해야 사용자에게 보일 수 있습니다.');
    expect(validateBlockInput({ ...ok, memo: '  ', showMemoToUser: false })).toBeNull();
  });
});

describe('userVisibleBlock', () => {
  it('writes the reason line like the Gateway block page', () => {
    expect(userVisibleBlock(['INVESTIGATION', 'ADMIN_REQUEST'], '', false)).toEqual({ reasonLine: '사유: 보안 조사 중 · 관리자 요청', memoLine: null });
    expect(userVisibleBlock([], '', false).reasonLine).toBe('사유: 선택 전');
  });
  it('adds the memo line only when shown and non-blank', () => {
    expect(userVisibleBlock(['OTHER'], ' 현장 확인 ', true).memoLine).toBe('관리자 안내: 현장 확인');
    expect(userVisibleBlock(['OTHER'], '현장 확인', false).memoLine).toBeNull();
    expect(userVisibleBlock(['OTHER'], '   ', true).memoLine).toBeNull();
  });
});

describe('Gateway rejection paths for the new fields', () => {
  it('names reasons and user_memo', () => {
    expect(accessFieldText('rules.0.reasons')).toBe('차단 목록 1번째 사유');
    expect(accessFieldText('rules.2.user_memo')).toBe('차단 목록 3번째 사용자 안내 메모');
  });
});
