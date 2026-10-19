// 변경 이력 서랍(설계 3.3, 시험 10) + 감사 로그 부분/전체 마스킹 구분(결정 5).
import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuditChangeDetails } from '@/src/components/AuditChangeDetails';
import { policyService } from '@/src/services/policyService';
import { historyFixture } from '@/src/test/policyFixtures';
import { itemRow, mountPolicies, ready, stubPolicyServices } from '@/src/test/policyPage';
import { policyChangeText } from '@/src/utils/policyActions';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
afterEach(() => vi.restoreAllMocks());

describe('policy version history', () => {
  it('has a change column comparing each version with the previous one, in four-way names', async () => {
    stubPolicyServices();
    vi.spyOn(policyService, 'getPolicyHistory').mockResolvedValue(historyFixture());
    mountPolicies();
    await ready();
    fireEvent.click(within(itemRow('이메일')).getByRole('button', { name: /더보기$/ }));
    fireEvent.click(await screen.findByRole('menuitem', { name: '변경 이력' }));
    const drawer = await screen.findByRole('dialog', { name: '정책 버전 이력' });
    const table = await within(drawer).findByRole('table', { name: '버전 이력' });
    expect(within(table).getAllByRole('columnheader').map((head) => head.textContent)).toEqual(['시간 · 버전', '변경자', '변경 내용', '변경 후 처리 방식', '활성 상태']);
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((item) => within(item).getAllByRole('cell')[2].textContent)).toEqual(['비활성화', '처리 방식 전체 마스킹 → 부분 마스킹', '최초 생성']);
    expect(rows.map((item) => within(item).getAllByRole('cell')[3].textContent)).toEqual(['부분 마스킹', '부분 마스킹', '전체 마스킹']);   // 옛 값 MASK도 전체 마스킹
    expect(rows.map((item) => within(item).getAllByRole('cell')[4].textContent)).toEqual(['비활성', '활성', '활성']);
    expect(rows[2]).toHaveTextContent('bootstrap');
  });

  it('describes combined and missing changes', () => {
    expect(policyChangeText({ version: 5, policyAction: 'BLOCK', enabled: true }, { policyAction: 'ALLOW', enabled: false })).toBe('처리 방식 허용 → 차단 · 활성화');
    expect(policyChangeText({ version: 5, policyAction: 'BLOCK', enabled: true })).toBe('이전 버전 미기록');
    expect(policyChangeText({ version: 1, policyAction: 'BLOCK', enabled: true })).toBe('최초 생성');
  });
});

describe('audit log tells partial and full masking apart', () => {
  it('uses four-way names when recorded, and the old family name otherwise', () => {
    const { unmount } = render(<AuditChangeDetails action="POLICY_UPDATE" changes={{ previousVersion: 1, newVersion: 2, previousAction: 'MASK', newAction: 'MASK', previousPolicyAction: 'MASK_FULL', newPolicyAction: 'MASK_PARTIAL' }} />);
    expect(screen.getByText('변경 전: 전체 마스킹')).toBeInTheDocument();
    expect(screen.getByText('변경 후: 부분 마스킹')).toBeInTheDocument();
    unmount();
    render(<AuditChangeDetails action="POLICY_UPDATE" changes={{ previousAction: 'MASK', newAction: 'BLOCK' }} />);
    expect(screen.getByText('변경 전: 마스킹')).toBeInTheDocument();
    expect(screen.getByText('변경 후: 차단')).toBeInTheDocument();
  });
});
