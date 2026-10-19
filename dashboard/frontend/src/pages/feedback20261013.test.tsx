// 2026-10-13 사용자 피드백 7건 중 새로 생긴 화면 동작: ⑥ 탐지 정책 펼침의 '탐지 항목'(운영 Detection 인식기 기준), ① Gateway 처리 '기타 형식' 설명.
// 나머지(②③④⑤⑦)는 기존 시험을 새 동작으로 고쳤다(gatewayAccess·trafficClientsAccess·workbenchV3·detectionOps·documentViewer 등).
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { dashboardService } from '@/src/services/dashboardService';
import { policyService } from '@/src/services/policyService';
import { ApiError } from '@/src/api/errors';
import { capabilitiesFixture, policiesFixture, policyDto } from '@/src/test/policyFixtures';
import type { DashboardStats } from '@/src/types/event';
import { CATEGORY_ENTITIES, DETECTION_ENTITIES_CHECKED_AT, policyEntities } from '@/src/utils/detectionEntities';
import { uiLabel } from '@/src/utils/labels';
import { PolicyManagementPage } from './PolicyManagementPage';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
afterEach(() => vi.restoreAllMocks());

const wrap = (node: React.ReactNode, path = '/policies') => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[path]}>{node}</MemoryRouter></QueryClientProvider>);
const policy = (id: string, target: string) => ({ policyId: id, detector: 'SIGNATURE', detectionTarget: target, action: 'MASK', targetLlms: ['ChatGPT'], version: 1, enabled: true });
const summary = { insights: { entityCounts: [], documents: [], llmActions: [], contentActions: [], heatmap: [], categoryCounts: [], entityEventCounts: [] } } as unknown as DashboardStats;

describe('detection items behind each policy (운영 Detection 2026-10-13 확인)', () => {
  it('lists exactly the entities the running Detection emits for each category, with Korean names', () => {
    expect(CATEGORY_ENTITIES.PII.map(entity => entity.type)).toEqual(['KR_RRN', 'KR_FOREIGN_REGISTRATION_NUMBER', 'KR_PHONE_NUMBER', 'EMAIL_ADDRESS', 'KR_DATE_OF_BIRTH', 'KR_BANK_ACCOUNT', 'KR_ADDRESS', 'KR_POSTAL_CODE']);
    expect(CATEGORY_ENTITIES.CREDENTIAL.map(entity => entity.type)).toEqual(['PASSWORD', 'GENERIC_API_KEY', 'GITHUB_TOKEN']);
    for (const entity of [...CATEGORY_ENTITIES.PII, ...CATEGORY_ENTITIES.CREDENTIAL]) expect(uiLabel(entity.type)).toMatch(/[가-힣]/);
    // 운영에 없는 유형(AWS 액세스 키·개인 키)은 목록에 넣지 않는다
    expect([...CATEGORY_ENTITIES.PII, ...CATEGORY_ENTITIES.CREDENTIAL].map(entity => entity.type)).not.toEqual(expect.arrayContaining(['AWS_ACCESS_KEY']));
    expect(DETECTION_ENTITIES_CHECKED_AT).toBe('2026-10-13');
  });

  it('maps a policy target to its items: category, single entity, keyword, or unknown', () => {
    expect(policyEntities('pii')).toEqual({ kind: 'category', entities: CATEGORY_ENTITIES.PII });
    expect(policyEntities('KR_RRN')).toEqual({ kind: 'entity', entities: [{ type: 'KR_RRN' }] });
    expect(policyEntities('DOC_KEYWORD')).toEqual({ kind: 'keyword' });
    expect(policyEntities('KEYWORD')).toEqual({ kind: 'keyword' });
    expect(policyEntities('PASSPORT')).toEqual({ kind: 'unknown' });
  });

  // 2026-10-16: 정책 펼침의 '탐지 항목' → 화면 자체가 분류별 항목 목록(토글). 목록을 못 불러오면 이 정적 목록으로 이름만 보인다
  it('shows the stored items by category when the capabilities list is missing, and says where keywords and document matches go', async () => {
    vi.spyOn(policyService, 'getCapabilities').mockRejectedValue(new ApiError('offline', 'NETWORK'));
    vi.spyOn(dashboardService, 'getSummary').mockResolvedValue(summary);
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy('POLICY-PII-MASK', 'PII'), policy('POLICY-CREDENTIAL-MASK', 'CREDENTIAL'), policy('POLICY-NONE', 'PASSPORT')] as never);
    wrap(<PolicyManagementPage />);
    await screen.findByText('POLICY-PII-MASK');
    const label = (item: HTMLElement) => item.querySelector('.pg-polt-label')?.textContent;
    const pii = await screen.findByRole('list', { name: '개인정보 항목' });
    expect(within(pii).getAllByRole('listitem').map(label)).toEqual(['주민등록번호', '외국인등록번호', '전화번호', '이메일', '생년월일', '계좌번호', '주소', '우편번호']);
    const credential = screen.getByRole('list', { name: '자격증명 항목' });
    expect(within(credential).getAllByRole('listitem').map(label)).toEqual(['비밀번호', 'API 키', 'GitHub 토큰']);
    expect(screen.getAllByText('이름표 필요')).toHaveLength(6);
    expect(screen.getByText('처리 방식 목록을 불러오지 못해 운영 Detection에서 확인해 둔 항목으로 표시')).toBeInTheDocument();
    expect(screen.getByText('* 이름표 필요: ‘비밀번호:’처럼 값 앞에 이름표가 있을 때만 잡습니다. 생년월일은 값 앞뒤 30자 안에 ‘생년월일’·‘생일’·‘출생일’ 같은 말이 있을 때만 잡습니다.')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: '그 밖의 정책' })).toHaveTextContent('POLICY-NONE');
    expect(screen.getByText(/기밀 키워드·문서 일치는 이 정책과 관계없이 차단됩니다/)).toBeInTheDocument();
  });

  // 2026-10-15 처리 방식 목록(capabilities) 기준 → 2026-10-16 항목 줄: 같은 출처의 항목·이름표 필요·부분 마스킹 규칙, 출처 문구는 '실행 중 규칙 실시간 확인 아님'
  it('lists items from the capabilities list with partial masking rules and an honest source line', async () => {
    vi.spyOn(dashboardService, 'getSummary').mockResolvedValue(summary);
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue(policiesFixture([policyDto('POLICY-NONE', 'PASSPORT', 'BLOCK', 1)]));
    vi.spyOn(policyService, 'getCapabilities').mockResolvedValue(capabilitiesFixture());
    wrap(<PolicyManagementPage />);
    const source = await screen.findByText('항목은 설정 목록 기준(실행 중 규칙 실시간 확인 아님)');
    expect(source).toHaveAttribute('title', 'runtime_verified: false · 목록 버전 2026-10-14.2');
    const label = (item: HTMLElement) => item.querySelector('.pg-polt-label')?.textContent;
    expect(within(screen.getByRole('list', { name: '개인정보 항목' })).getAllByRole('listitem').map(label)).toEqual(['주민등록번호', '외국인등록번호', '전화번호', '이메일', '생년월일', '계좌번호', '주소', '우편번호']);
    expect(within(screen.getByRole('list', { name: '자격증명 항목' })).getAllByRole('listitem').map(label)).toEqual(['GitHub 토큰', 'API 키', '비밀번호']);
    expect(screen.getByText('부분 마스킹 규칙 · 아이디 일부 가림, 도메인 유지')).toBeInTheDocument();   // 켜진 부분 마스킹 항목만
    expect(screen.getAllByText(/부분 마스킹 규칙/)).toHaveLength(1);
    expect(screen.getByRole('list', { name: '그 밖의 정책' })).toHaveTextContent('POLICY-NONE');
    expect(screen.getByText('처리 방식 목록에 없는 대상 · 바꿀 수 없음')).toBeInTheDocument();
    expect(screen.queryByText('처리 방식 목록을 불러오지 못해 운영 Detection에서 확인해 둔 항목으로 표시')).toBeNull();
  });

  it('opens with the policy named in the address highlighted', async () => {
    vi.spyOn(dashboardService, 'getSummary').mockResolvedValue(summary);
    vi.spyOn(policyService, 'getPolicies').mockResolvedValue([policy('POLICY-PII-MASK', 'PII'), policy('POLICY-CREDENTIAL-MASK', 'CREDENTIAL')] as never);
    wrap(<PolicyManagementPage />, '/policies?policyId=POLICY-CREDENTIAL-MASK');
    await screen.findByText('POLICY-CREDENTIAL-MASK');
    expect(screen.getByRole('heading', { name: '자격증명' }).closest('header')).toHaveAttribute('aria-current', 'true');
    expect(screen.getByRole('heading', { name: '개인정보' }).closest('header')).not.toHaveAttribute('aria-current');
  });
});
