// 분류 기본 처리의 활성 상태 변경(설계 3.2, 시험 8 → 2026-10-16 분류 머리 ⋯ 메뉴): 끌 때 실제로 넘어가는 곳을 확인창에 적고 expected_version을 보낸다.
// 항목 토글은 확인창 없이 바로 바뀌고(policyToggle.test.tsx), 꺼진 항목이 실제로 받는 처리는 줄의 title에 적는다.
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { policyService } from '@/src/services/policyService';
import { notifySuccess } from '@/src/utils/feedback';
import { policiesFixture, policyDto, serverError } from '@/src/test/policyFixtures';
import { itemRow, mountPolicies, ready, stubPolicyServices } from '@/src/test/policyPage';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
afterEach(() => vi.restoreAllMocks());

async function openCategoryStatus(category: '개인정보' | '자격증명', menu: '비활성화' | '활성화') {
  await ready();
  const head = screen.getByRole('heading', { name: category }).closest('header')!;
  fireEvent.click(within(head).getByRole('button', { name: /더보기$/ }));
  fireEvent.click(await screen.findByRole('menuitem', { name: menu }));
  return screen.findByRole('dialog', { name: new RegExp(`^${menu} · `) });
}

describe('category default handling on/off follows Detection fallback', () => {
  it('turning the category off says unhandled items fall back to the default block (danger) and sends expected_version', async () => {
    stubPolicyServices();
    const toggle = vi.spyOn(policyService, 'changePolicyStatus').mockResolvedValue({ ...policiesFixture()[0], enabled: false, version: 2 });
    mountPolicies();
    const dialog = await openCategoryStatus('개인정보', '비활성화');
    expect(dialog).toHaveAccessibleName('비활성화 · 개인정보 전체');
    expect(dialog).toHaveTextContent('이 정책을 끄면 항목별 정책이 없는 개인정보 항목은 기본 처리(차단)로 넘어갑니다.');
    expect(dialog).not.toHaveTextContent('더 이상 탐지·조치하지 않습니다');   // 옛 문구(틀린 설명)
    expect(within(dialog).getByRole('button', { name: '비활성화' }).className).toMatch(/danger/);
    fireEvent.click(within(dialog).getByRole('button', { name: '비활성화' }));
    await waitFor(() => expect(toggle).toHaveBeenCalledWith('POLICY-PII-MASK', false, 1));
    await waitFor(() => expect(notifySuccess).toHaveBeenCalledWith('개인정보 전체 정책을 비활성화했습니다.'));
  });

  it('a switched-off category shows block as its default, and items say what they get now', async () => {
    stubPolicyServices({ policies: policiesFixture([policyDto('POLICY-PASSWORD-1', 'PASSWORD', 'BLOCK', 1, false)]).map((policy) => policy.policyId === 'POLICY-CREDENTIAL-MASK' ? { ...policy, enabled: false } : policy) });
    mountPolicies();
    await ready();
    expect(screen.getByText('차단 · 자격증명 정책 꺼짐')).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: '자격증명 기본 처리' })).toBeNull();
    expect(within(itemRow('비밀번호')).getByText('기본 처리 따름')).toHaveAttribute('title', '지금 처리: 기본 처리(차단)');
    expect(within(itemRow('이메일')).getByRole('switch')).toHaveAttribute('aria-checked', 'true');
  });

  it('turning a category on says it handles again, and an error shows no success', async () => {
    stubPolicyServices({ policies: policiesFixture().map((policy) => policy.policyId === 'POLICY-CREDENTIAL-MASK' ? { ...policy, enabled: false } : policy) });
    const toggle = vi.spyOn(policyService, 'changePolicyStatus').mockRejectedValue(serverError(503, 'POLICY_UPSTREAM_UNAVAILABLE'));
    mountPolicies();
    const dialog = await openCategoryStatus('자격증명', '활성화');
    expect(dialog).toHaveTextContent('이 정책으로 다시 처리합니다.');
    fireEvent.click(within(dialog).getByRole('button', { name: '활성화' }));
    await waitFor(() => expect(toggle).toHaveBeenCalledWith('POLICY-CREDENTIAL-MASK', true, 1));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('탐지 서버에 연결하지 못했습니다(3초 안에 응답 없음 포함). 변경이 적용됐는지 목록에서 확인한 뒤 다시 시도하세요.');
    expect(notifySuccess).not.toHaveBeenCalled();
  });

  it('a toggle error shows in that item row only', async () => {
    stubPolicyServices();
    vi.spyOn(policyService, 'changePolicyStatus').mockRejectedValue(serverError(503, 'POLICY_UPSTREAM_UNAVAILABLE'));
    mountPolicies();
    await ready();
    fireEvent.click(within(itemRow('이메일')).getByRole('switch'));
    expect(await within(itemRow('이메일')).findByRole('alert')).toHaveTextContent('탐지 서버에 연결하지 못했습니다');
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(notifySuccess).not.toHaveBeenCalled();
  });
});
