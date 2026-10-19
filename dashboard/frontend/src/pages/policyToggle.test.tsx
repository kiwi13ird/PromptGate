// 탐지 정책 분류별 항목 토글(2026-10-16, 기존 정책 생성 2단계·수정 대화상자 대체):
//   개인정보 8 · 자격증명 3 항목이 화면에 바로 보이고, 토글 켬 = 정책 없으면 생성(POST)/있으면 활성(PATCH status),
//   끔 = 비활성(PATCH status, expected_version), 처리 방식 변경 = PATCH(expected_version). 허용은 확인창 1회. 오류는 그 줄에 한 줄.
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { policyService } from '@/src/services/policyService';
import { notifyError, notifySuccess } from '@/src/utils/feedback';
import { policiesFixture, policyDto, serverError } from '@/src/test/policyFixtures';
import { itemRow, mountPolicies, ready, stubPolicyServices } from '@/src/test/policyPage';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('@/src/utils/feedback', async original => ({ ...await original<typeof import('@/src/utils/feedback')>(), notifyError: vi.fn(), notifySuccess: vi.fn() }));
afterEach(() => vi.restoreAllMocks());

const options = (select: HTMLElement) => [...(select as HTMLSelectElement).options].filter((option) => !option.disabled).map((option) => option.value);

describe('policy screen shows category groups with item toggles', () => {
  it('lists 8 personal-information and 3 credential items with their state, without a create dialog', async () => {
    stubPolicyServices({ policies: policiesFixture([policyDto('POLICY-KR_RRN-1', 'kr_rrn', 'BLOCK', 3, false)]) });
    mountPolicies();
    await ready();
    expect(screen.queryByRole('button', { name: '정책 생성' })).toBeNull();
    const pii = screen.getByRole('list', { name: '개인정보 항목' });
    const credential = screen.getByRole('list', { name: '자격증명 항목' });
    expect(within(pii).getAllByRole('switch')).toHaveLength(8);
    expect(within(credential).getAllByRole('switch').map((item) => item.getAttribute('aria-label'))).toEqual(['GitHub 토큰 따로 처리', 'API 키 따로 처리', '비밀번호 따로 처리']);
    expect(screen.getAllByText('이름표 필요')).toHaveLength(6);
    // 이메일: 항목 정책 켜짐(부분 마스킹) → 처리 방식 선택 + 규칙 + 적용 중
    const email = itemRow('이메일');
    expect(within(email).getByRole('switch')).toHaveAttribute('aria-checked', 'true');
    expect(within(email).getByRole('combobox', { name: '이메일 처리 방식' })).toHaveValue('MASK_PARTIAL');
    expect(email).toHaveTextContent('부분 마스킹 규칙 · 아이디 일부 가림, 도메인 유지');
    expect(within(email).getByText('적용 중')).toBeInTheDocument();
    // 주민등록번호: 정책은 있지만 꺼짐(대소문자 무시) → 선택 없음, 분류 기본 처리를 따른다
    const rrn = itemRow('주민등록번호');
    expect(within(rrn).getByRole('switch')).toHaveAttribute('aria-checked', 'false');
    expect(within(rrn).queryByRole('combobox')).toBeNull();
    expect(within(rrn).getByText('기본 처리 따름')).toHaveAttribute('title', '지금 처리: 개인정보 기본 처리(전체 마스킹)');
    expect(within(rrn).getByText('꺼짐')).toBeInTheDocument();
    // 분류 머리: 기본 처리 = 분류 정책 처리 방식(수정 가능), 자격증명은 부분 마스킹 없음
    expect(screen.getByRole('combobox', { name: '개인정보 기본 처리' })).toHaveValue('MASK_FULL');
    expect(options(screen.getByRole('combobox', { name: '개인정보 기본 처리' }))).toEqual(['ALLOW', 'BLOCK', 'MASK_PARTIAL', 'MASK_FULL']);
    expect(options(screen.getByRole('combobox', { name: '자격증명 기본 처리' }))).toEqual(['ALLOW', 'BLOCK', 'MASK_FULL']);
    expect(screen.getByText('POLICY-PII-MASK').closest('section')).toHaveTextContent('개인정보8개 항목');
  });

  it('turning an item on creates its policy with the handling it gets now, then shows the action choice', async () => {
    stubPolicyServices();
    const create = vi.spyOn(policyService, 'createPolicy').mockResolvedValue(policiesFixture()[2]);
    mountPolicies();
    await ready();
    fireEvent.click(within(itemRow('전화번호')).getByRole('switch'));
    await waitFor(() => expect(create).toHaveBeenCalledWith('KR_PHONE_NUMBER', 'MASK_FULL'));
    await waitFor(() => expect(notifySuccess).toHaveBeenCalledWith('전화번호 정책을 만들었습니다 · 부분 마스킹'));
  });

  it('a credential item never starts as partial masking, and its choices have no partial masking', async () => {
    stubPolicyServices({ policies: policiesFixture([policyDto('POLICY-PASSWORD-1', 'PASSWORD', 'BLOCK', 1)]) });
    const create = vi.spyOn(policyService, 'createPolicy').mockResolvedValue(policiesFixture()[2]);
    mountPolicies();
    await ready();
    expect(options(within(itemRow('비밀번호')).getByRole('combobox'))).toEqual(['ALLOW', 'BLOCK', 'MASK_FULL']);
    fireEvent.click(within(itemRow('API 키')).getByRole('switch'));
    await waitFor(() => expect(create).toHaveBeenCalledWith('GENERIC_API_KEY', 'MASK_FULL'));
  });

  it('with the category off, a new item policy starts as block (the default it gets now)', async () => {
    stubPolicyServices({ policies: policiesFixture().map((policy) => policy.policyId === 'POLICY-PII-MASK' ? { ...policy, enabled: false } : policy) });
    const create = vi.spyOn(policyService, 'createPolicy').mockResolvedValue(policiesFixture()[2]);
    mountPolicies();
    await ready();
    expect(screen.getByText('차단 · 개인정보 정책 꺼짐')).toBeInTheDocument();
    expect(within(itemRow('주소')).getByText('기본 처리 따름')).toHaveAttribute('title', '지금 처리: 기본 처리(차단)');
    fireEvent.click(within(itemRow('주소')).getByRole('switch'));
    await waitFor(() => expect(create).toHaveBeenCalledWith('KR_ADDRESS', 'BLOCK'));
  });

  it('when the category allows, turning an item on asks once (허용 · 대상) before creating', async () => {
    stubPolicyServices({ policies: policiesFixture().map((policy) => policy.policyId === 'POLICY-CREDENTIAL-MASK' ? { ...policy, policyAction: 'ALLOW' as const, finalPolicyAction: 'ALLOW' as const, action: 'ALLOW' as const } : policy) });
    const create = vi.spyOn(policyService, 'createPolicy').mockResolvedValue(policiesFixture()[2]);
    mountPolicies();
    await ready();
    fireEvent.click(within(itemRow('비밀번호')).getByRole('switch'));
    const confirm = await screen.findByRole('dialog', { name: '허용 · 비밀번호' });
    expect(create).not.toHaveBeenCalled();
    expect(confirm).toHaveTextContent('마스킹·차단 없이 그대로 전달');
    fireEvent.click(within(confirm).getByRole('button', { name: '허용' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith('PASSWORD', 'ALLOW'));
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('turning off / on an existing item changes only its status with expected_version (no dialog)', async () => {
    stubPolicyServices({ policies: policiesFixture([policyDto('POLICY-KR_RRN-1', 'KR_RRN', 'BLOCK', 3, false)]) });
    const toggle = vi.spyOn(policyService, 'changePolicyStatus').mockResolvedValue({ ...policiesFixture()[2], enabled: false, version: 3 });
    const create = vi.spyOn(policyService, 'createPolicy');
    mountPolicies();
    await ready();
    fireEvent.click(within(itemRow('이메일')).getByRole('switch'));
    await waitFor(() => expect(toggle).toHaveBeenCalledWith('POLICY-EMAIL_ADDRESS-1', false, 2));
    await waitFor(() => expect(notifySuccess).toHaveBeenCalledWith('이메일 정책을 비활성화했습니다.'));
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.click(within(itemRow('주민등록번호')).getByRole('switch'));
    await waitFor(() => expect(toggle).toHaveBeenCalledWith('POLICY-KR_RRN-1', true, 3));
    expect(create).not.toHaveBeenCalled();
  });

  it('changing the action sends PATCH with expected_version; partial ↔ full works directly', async () => {
    stubPolicyServices();
    const update = vi.spyOn(policyService, 'updatePolicy').mockResolvedValue({ ...policiesFixture()[2], version: 3 });
    mountPolicies();
    await ready();
    fireEvent.change(within(itemRow('이메일')).getByRole('combobox'), { target: { value: 'MASK_FULL' } });
    await waitFor(() => expect(update).toHaveBeenCalledWith('POLICY-EMAIL_ADDRESS-1', 'MASK_FULL', 2));
    await waitFor(() => expect(notifySuccess).toHaveBeenCalledWith('이메일 정책을 v3으로 바꿨습니다 · 부분 마스킹'));
    fireEvent.change(screen.getByRole('combobox', { name: '개인정보 기본 처리' }), { target: { value: 'BLOCK' } });
    await waitFor(() => expect(update).toHaveBeenCalledWith('POLICY-PII-MASK', 'BLOCK', 1));
  });

  it('choosing allow asks once (허용 · 대상) with the warning, then updates', async () => {
    stubPolicyServices();
    const update = vi.spyOn(policyService, 'updatePolicy').mockResolvedValue({ ...policiesFixture()[2], version: 3 });
    mountPolicies();
    await ready();
    fireEvent.change(within(itemRow('이메일')).getByRole('combobox'), { target: { value: 'ALLOW' } });
    const confirm = await screen.findByRole('dialog', { name: '허용 · 이메일' });
    expect(confirm).toHaveTextContent('부분 마스킹 → 허용으로 바꾼 v3을 만듭니다.');
    expect(confirm).toHaveTextContent('분류 전체 정책이 마스킹이어도 이 항목은 예외가 됩니다.');
    expect(update).not.toHaveBeenCalled();
    fireEvent.click(within(confirm).getByRole('button', { name: '허용' }));
    await waitFor(() => expect(update).toHaveBeenCalledWith('POLICY-EMAIL_ADDRESS-1', 'ALLOW', 2));
  });

  it('409 VERSION_CONFLICT: one line in that row, reloads the list, no toast and no retry', async () => {
    const { getPolicies } = stubPolicyServices();
    const update = vi.spyOn(policyService, 'updatePolicy').mockRejectedValue(serverError(409, 'VERSION_CONFLICT'));
    mountPolicies();
    await ready();
    const before = getPolicies.mock.calls.length;
    fireEvent.change(within(itemRow('이메일')).getByRole('combobox'), { target: { value: 'BLOCK' } });
    expect(await within(itemRow('이메일')).findByRole('alert')).toHaveTextContent('다른 관리자가 먼저 바꿨습니다. 최신 정책을 다시 불러왔으니 내용을 확인한 뒤 다시 변경하세요.');
    await waitFor(() => expect(getPolicies.mock.calls.length).toBeGreaterThan(before));
    expect(update).toHaveBeenCalledTimes(1);
    expect(notifyError).not.toHaveBeenCalled();
    expect(notifySuccess).not.toHaveBeenCalled();
    expect(screen.queryByText(/VERSION_CONFLICT/)).toBeNull();
  });

  it('create 409 CONFLICT and 422 UNSUPPORTED_POLICY_TARGET show the coded line and reload what is needed', async () => {
    const { getPolicies, getCapabilities } = stubPolicyServices();
    const create = vi.spyOn(policyService, 'createPolicy').mockRejectedValue(serverError(409, 'CONFLICT'));
    mountPolicies();
    await ready();
    const policyCalls = getPolicies.mock.calls.length;
    fireEvent.click(within(itemRow('우편번호')).getByRole('switch'));
    expect(await within(itemRow('우편번호')).findByRole('alert')).toHaveTextContent('이 탐지 대상에는 이미 정책이 있습니다. 목록에서 수정하세요.');
    await waitFor(() => expect(getPolicies.mock.calls.length).toBeGreaterThan(policyCalls));
    create.mockRejectedValue(serverError(422, 'UNSUPPORTED_POLICY_TARGET'));
    const capabilityCalls = getCapabilities.mock.calls.length;
    fireEvent.click(within(itemRow('주소')).getByRole('switch'));
    expect(await within(itemRow('주소')).findByRole('alert')).toHaveTextContent('지원 목록에 없는 탐지 대상입니다. 처리 방식 목록을 다시 불러옵니다.');
    await waitFor(() => expect(getCapabilities.mock.calls.length).toBeGreaterThan(capabilityCalls));
    expect(within(itemRow('우편번호')).queryByRole('alert')).toBeNull();   // 오류는 마지막 줄 하나만
  });

  it('a policy outside the reviewed list stays visible but cannot be changed', async () => {
    stubPolicyServices({ policies: policiesFixture([policyDto('POLICY-PASSPORT', 'PASSPORT', 'BLOCK', 1)]) });
    mountPolicies();
    await ready();
    const others = screen.getByRole('list', { name: '그 밖의 정책' });
    expect(others).toHaveTextContent('POLICY-PASSPORT');
    expect(within(others).queryByRole('switch')).toBeNull();
    expect(within(others).queryByRole('combobox')).toBeNull();
  });
});
