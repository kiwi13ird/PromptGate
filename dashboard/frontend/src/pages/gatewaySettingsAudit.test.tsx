import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { GatewaySettingsValues } from '@/src/api/gatewaySettingsSchemas';
import { mockGatewayApi } from '@/src/api/mockAdapter';
import { readAuditRows } from '@/src/api/schemas';
import { uiLabel } from '@/src/utils/labels';
import { AuditLogsPage } from './AuditLogsPage';

// 감사 로그의 Gateway 처리 설정 변경 줄(2026-10-10, 명세 §2.5·§10). 값은 모두 가짜.
const defaults: GatewaySettingsValues = {
  timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'block', seconds: 2 } },
  uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' },
  notify_on_allow: false,
};
const DEFAULT_SUMMARY = '질문 지연 시 원본 전송(0.5초) · 파일 지연 시 차단(2초) · 이미지 허용 · 스캔 PDF 차단 · 기타 형식 차단 · 허용 알림 끔';

describe('gateway settings audit rows', () => {
  it('reads a first save without previous_version as a full row', () => {
    const page = readAuditRows({ items: [{
      audit_id: 'AUD-1', occurred_at: '2026-10-10T05:12:00.000Z', admin_id: 'local-admin', action: 'GATEWAY_SETTINGS_UPDATE',
      target_type: 'GATEWAY', target_id: 'gateway-settings', result: 'SUCCESS',
      changes: { new_version: 1, previous_value: `기본값 · ${DEFAULT_SUMMARY}`, new_value: DEFAULT_SUMMARY.replace('스캔 PDF 차단', '스캔 PDF 허용') },
    }], total: 1, page: 1, page_size: 10, total_pages: 1 });
    expect(page.items).toHaveLength(1);
    expect(page).not.toHaveProperty('skipped');
    expect(page).not.toHaveProperty('partial');
    expect(uiLabel('GATEWAY_SETTINGS_UPDATE')).toBe('Gateway 처리 설정 변경');
    expect(uiLabel('GATEWAY')).toBe('Gateway');
  });

  it('lists the change with a link to the settings tab and shows before and after', async () => {
    await mockGatewayApi.saveGatewaySettings({ expected_version: 0, ...defaults, notify_on_allow: true });
    await mockGatewayApi.saveGatewaySettings({ expected_version: 1, ...defaults, notify_on_allow: true, uninspectable: { ...defaults.uninspectable, image: 'block' } });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><AuditLogsPage /></MemoryRouter></QueryClientProvider>);
    expect(screen.getByRole('option', { name: 'Gateway 처리 설정 변경' })).toHaveValue('GATEWAY_SETTINGS_UPDATE');
    fireEvent.change(screen.getByLabelText('작업 유형'), { target: { value: 'GATEWAY_SETTINGS_UPDATE' } });
    const links = await screen.findAllByRole('link', { name: 'gateway-settings' });
    expect(links).toHaveLength(2);
    for (const link of links) expect(link).toHaveAttribute('href', '/policies/gateway');
    const rows = links.map(link => link.closest('tr')!);
    for (const row of rows) {
      expect(within(row).getByText('Gateway 처리 설정 변경')).toBeInTheDocument();
      expect(within(row).getByText('Gateway')).toBeInTheDocument();
    }
    // 최신 줄(v2)
    fireEvent.click(within(rows[0]).getByRole('button', { name: /상세 열기/ }));
    let details = await screen.findByRole('region', { name: '기록된 변경 전후' });
    expect(within(details).getByText('설정 버전')).toBeInTheDocument();
    expect(within(details).getByText('변경 전: v1')).toBeInTheDocument();
    expect(within(details).getByText('변경 후: v2')).toBeInTheDocument();
    expect(within(details).getByText(`변경 후: ${DEFAULT_SUMMARY.replace('이미지 허용', '이미지 차단').replace('허용 알림 끔', '허용 알림 켬')}`)).toBeInTheDocument();
    // 첫 저장 줄: 이전 번호 없음 → 기본값. 재설계 3g: 변경 내용은 서랍(모달) — 닫고 다음 줄을 연다
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    fireEvent.click(within(rows[1]).getByRole('button', { name: /상세 열기/ }));
    details = await screen.findByRole('region', { name: '기록된 변경 전후' });
    expect(within(details).getByText('변경 전: 기본값')).toBeInTheDocument();
    expect(within(details).getByText('변경 후: v1')).toBeInTheDocument();
    expect(within(details).getByText('처리 설정')).toBeInTheDocument();
    expect(within(details).getByText(`변경 전: 기본값 · ${DEFAULT_SUMMARY}`)).toBeInTheDocument();
    expect(within(details).queryByText('정책 버전')).not.toBeInTheDocument();
    expect(within(details).queryByText(/당시 미기록/)).not.toBeInTheDocument();
  });
});
