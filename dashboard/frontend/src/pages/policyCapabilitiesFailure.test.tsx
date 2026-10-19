// 처리 방식 목록(capabilities) 조회 실패·로딩 중(설계 3.5, 시험 9 → 2026-10-16 토글 화면): 토글·처리 방식 선택·활성 변경을 끄고 이유를 적는다.
// 항목 이름은 운영 Detection에서 확인해 둔 목록으로 보이고, 이력 보기는 된다. [다시 시도]로 복구.
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { policyService } from '@/src/services/policyService';
import { capabilitiesFixture, historyFixture, serverError } from '@/src/test/policyFixtures';
import { itemRow, mountPolicies, stubPolicyServices } from '@/src/test/policyPage';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
afterEach(() => vi.restoreAllMocks());

const REASON = '처리 방식 목록을 불러오지 못해 정책 변경을 쉬고 있습니다.';

describe('policy changes pause without the capabilities list', () => {
  it('disables toggles, choices and status change with the reason, keeps history readable, and recovers on retry', async () => {
    const { getCapabilities } = stubPolicyServices({ capabilities: serverError(503, 'POLICY_UPSTREAM_UNAVAILABLE') });
    vi.spyOn(policyService, 'getPolicyHistory').mockResolvedValue(historyFixture());
    mountPolicies();
    const band = await screen.findByText(/처리 방식 목록을 불러오지 못해 정책 변경을 쉬고 있습니다 ·/);
    expect(band).toHaveAttribute('role', 'status');
    await screen.findByText('POLICY-PII-MASK');
    const switches = screen.getAllByRole('switch');
    expect(switches).toHaveLength(11);   // 저장된 항목 목록(개인정보 8 · 자격증명 3)으로 이름은 보인다
    for (const item of switches) {
      expect(item).toBeDisabled();
      expect(item).toHaveAttribute('title', REASON);
    }
    for (const select of screen.getAllByRole('combobox')) {
      expect(select).toBeDisabled();
      expect(select).toHaveAttribute('title', REASON);
    }
    expect(screen.getByText('처리 방식 목록을 불러오지 못해 운영 Detection에서 확인해 둔 항목으로 표시')).toBeInTheDocument();
    const head = screen.getByRole('heading', { name: '개인정보' }).closest('header')!;
    fireEvent.click(within(head).getByRole('button', { name: /더보기$/ }));
    expect(await screen.findByRole('menuitem', { name: '비활성화' })).toHaveAttribute('aria-disabled', 'true');
    fireEvent.keyDown(screen.getByRole('menuitem', { name: '비활성화' }), { key: 'Escape' });
    fireEvent.click(within(itemRow('이메일')).getByRole('button', { name: /더보기$/ }));
    fireEvent.click(await screen.findByRole('menuitem', { name: '변경 이력' }));   // 읽기는 된다
    const drawer = await screen.findByRole('dialog', { name: '정책 버전 이력' });
    expect(await within(drawer).findByText('최초 생성')).toBeInTheDocument();
    fireEvent.keyDown(drawer, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    getCapabilities.mockResolvedValue(capabilitiesFixture());
    fireEvent.click(within(band).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(within(itemRow('주민등록번호')).getByRole('switch')).toBeEnabled());
    expect(screen.queryByText(/정책 변경을 쉬고 있습니다/)).toBeNull();
    expect(screen.getByRole('combobox', { name: '개인정보 기본 처리' })).toBeEnabled();
  });

  it('while the list is loading the toggles stay off and say why', async () => {
    stubPolicyServices();
    vi.spyOn(policyService, 'getCapabilities').mockReturnValue(new Promise(() => {}));
    mountPolicies();
    await screen.findByText('POLICY-PII-MASK');
    expect(within(itemRow('주민등록번호')).getByRole('switch')).toBeDisabled();
    expect(within(itemRow('주민등록번호')).getByRole('switch')).toHaveAttribute('title', '처리 방식 목록을 불러오는 중입니다.');
    expect(screen.queryByText(/정책 변경을 쉬고 있습니다/)).toBeNull();
  });

  it('a malformed list (schema rejected) also pauses changes', async () => {
    stubPolicyServices({ capabilities: new ApiError('서버 응답 형식이 올바르지 않습니다.', 'INVALID_RESPONSE') });
    mountPolicies();
    expect(await screen.findByText(/정책 변경을 쉬고 있습니다 ·/)).toBeInTheDocument();
    expect(within(itemRow('이메일')).getByRole('switch')).toBeDisabled();
  });
});
