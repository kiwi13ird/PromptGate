// 탐지 정책 화면 시험 공통(2026-10-15): 실제 응답 모양의 고정 값으로 목록·선택지·요약을 채워 화면을 띄운다.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, vi } from 'vitest';
import { PolicyManagementPage } from '@/src/pages/PolicyManagementPage';
import { dashboardService } from '@/src/services/dashboardService';
import { policyService } from '@/src/services/policyService';
import type { DashboardStats } from '@/src/types/event';
import { capabilitiesFixture, policiesFixture } from './policyFixtures';

export const emptySummary = { insights: { entityCounts: [], documents: [], llmActions: [], contentActions: [], heatmap: [], categoryCounts: [], entityEventCounts: [] } } as unknown as DashboardStats;

export function stubPolicyServices({ policies = policiesFixture(), capabilities = capabilitiesFixture() }: { policies?: ReturnType<typeof policiesFixture>; capabilities?: ReturnType<typeof capabilitiesFixture> | Error } = {}) {
  vi.spyOn(dashboardService, 'getSummary').mockResolvedValue(emptySummary);
  const getPolicies = vi.spyOn(policyService, 'getPolicies').mockResolvedValue(policies);
  const getCapabilities = capabilities instanceof Error
    ? vi.spyOn(policyService, 'getCapabilities').mockRejectedValue(capabilities)
    : vi.spyOn(policyService, 'getCapabilities').mockResolvedValue(capabilities);
  return { getPolicies, getCapabilities };
}

export function mountPolicies(path = '/policies') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><PolicyManagementPage /></MemoryRouter></QueryClientProvider>);
  return { client, ...view };
}

/** 목록·선택지를 다 받아 항목 토글이 켜질 때까지(2026-10-16 분류별 항목 토글 화면) */
export async function ready() {
  await screen.findByText('POLICY-PII-MASK');
  await waitFor(() => expect(screen.getByRole('switch', { name: '주민등록번호 따로 처리' })).toBeEnabled());
}

/** 항목 줄(이름으로) */
export const itemRow = (name: string) => screen.getByRole('switch', { name: `${name} 따로 처리` }).closest('li') as HTMLElement;
