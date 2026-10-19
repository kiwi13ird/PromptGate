// 분리 보호(설계 5절 시험 12): 정책 4종은 이벤트·통계의 3종(SecurityAction·uiMode.supportedActions)을 바꾸지 않는다.
// 새 정책 화면 부품은 인라인 style을 쓰지 않는다(CSS 클래스만 — 확장 CSP와 같은 규칙).
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, expectTypeOf, it, vi } from 'vitest';
import { uiMode as realUiMode } from '@/src/config/uiMode.real';
import { uiMode as mockUiMode } from '@/src/config/uiMode.mock';
import type { SecurityAction } from '@/src/types/event';
import type { PolicyAction } from '@/src/types/policy';
import { uiLabel } from '@/src/utils/labels';
import { POLICY_ACTIONS } from '@/src/utils/policyActions';
import { mountPolicies, ready, stubPolicyServices } from '@/src/test/policyPage';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
afterEach(() => vi.restoreAllMocks());

describe('event actions stay three, policy actions are four', () => {
  it('keeps SecurityAction and uiMode.supportedActions unchanged', () => {
    expectTypeOf<SecurityAction>().toEqualTypeOf<'ALLOW' | 'BLOCK' | 'MASK'>();
    expectTypeOf<PolicyAction>().toEqualTypeOf<'ALLOW' | 'BLOCK' | 'MASK_PARTIAL' | 'MASK_FULL'>();
    expect(realUiMode.supportedActions).toEqual(['ALLOW', 'MASK', 'BLOCK']);
    expect(mockUiMode.supportedActions).toEqual(['ALLOW', 'MASK', 'BLOCK']);
    expect(POLICY_ACTIONS).toEqual(['ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL']);
    expect([uiLabel('MASK'), uiLabel('ALLOW'), uiLabel('BLOCK')]).toEqual(['마스킹', '허용', '차단']);   // 이벤트 이름표 그대로
    const eventSchemaSource = readFileSync(path.resolve(process.cwd(), 'src/api/schemas.ts'), 'utf8');
    expect(eventSchemaSource).toContain("const securityActionSchema = z.enum(['ALLOW', 'BLOCK', 'MASK']);");
  });
});

describe('no inline style in the policy screen', () => {
  it('source files have no style= attribute', () => {
    for (const file of ['pages/PolicyManagementPage.tsx']) {
      const source = readFileSync(path.resolve(process.cwd(), 'src', file), 'utf8');
      expect(source, file).not.toMatch(/\sstyle=\{/);
    }
  });
  it('rendered groups, choices and the allow confirm have no [style]', async () => {
    stubPolicyServices();
    mountPolicies();
    await ready();
    expect(document.querySelectorAll('.pg-polt [style]')).toHaveLength(0);
    fireEvent.change(screen.getByRole('combobox', { name: '이메일 처리 방식' }), { target: { value: 'ALLOW' } });
    const confirm = await screen.findByRole('dialog', { name: '허용 · 이메일' });
    expect(within(confirm).getByRole('button', { name: '허용' })).toBeInTheDocument();
    expect(document.querySelectorAll('.pg-polt [style]')).toHaveLength(0);
  });
});
