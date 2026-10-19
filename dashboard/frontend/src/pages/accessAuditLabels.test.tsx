// 접속 차단의 이름표·감사 로그(2026-10-12): 사유 코드, 감사 작업 4개, 감사 로그 연결·변경 전후, 검사 안 함 표시. 값은 모두 가짜.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { mockGatewayApi } from '@/src/api/mockAdapter';
import { auditLogSchema, readAuditRows, securityEventSchema } from '@/src/api/schemas';
import { mapSecurityEventDto } from '@/src/api/mappers';
import { inspectionFailure, missingDetectionTitle } from '@/src/utils/eventPresentation';
import { eventStory } from '@/src/utils/eventStory';
import { uiLabel } from '@/src/utils/labels';
import { hasReasonLabel, isAccessBlockReason, isNoResponseReason, isUninspectedReason, reasonLabel } from '@/src/utils/reasonLabels';
import type { SecurityEvent } from '@/src/types/event';
import { AuditLogsPage } from './AuditLogsPage';

const ID_A = 'chrome-3f6a2c1e-8b4d-4e2a-9c71-5d0e7b1a2f39';
const RULE = '1a2b3c4d-0000-4000-8000-000000000001';

describe('access block labels', () => {
  it('labels the two reason codes', () => {
    expect(reasonLabel('client_blocked')).toBe('접속 차단(관리자)');
    expect(reasonLabel('client_id_missing')).toBe('접속 차단(확장 ID 없음)');
    expect(hasReasonLabel('client_blocked')).toBe(true);
    expect(hasReasonLabel('client_id_missing')).toBe(true);
    expect(isAccessBlockReason('client_blocked')).toBe(true);
    expect(isAccessBlockReason('client_id_missing')).toBe(true);
    for (const other of ['file_too_large', 'detection_timeout', 'pii', undefined, null, 'toString']) expect(isAccessBlockReason(other)).toBe(false);
    // 검사 못 한 파일·검사 응답 없음과는 따로 센다
    expect(isUninspectedReason('client_blocked') || isNoResponseReason('client_blocked')).toBe(false);
  });

  it('labels the four audit actions', () => {
    expect(uiLabel('ACCESS_RULE_ADD')).toBe('접속 차단 등록');
    expect(uiLabel('ACCESS_RULE_REMOVE')).toBe('접속 차단 해제');
    expect(uiLabel('ACCESS_MODE_UPDATE')).toBe('확장 ID 없는 접속 차단 변경');
    expect(uiLabel('CLIENT_ALIAS_UPDATE')).toBe('확장 ID 별칭 변경');
  });

  it('the audit schema accepts the four actions and still refuses an unknown one', () => {
    const row = (action: string) => ({ audit_id: 'AUD-1', occurred_at: '2026-10-12T05:00:00.000Z', admin_id: 'local-admin', action, target_type: 'GATEWAY', target_id: RULE, result: 'SUCCESS' });
    for (const action of ['ACCESS_RULE_ADD', 'ACCESS_RULE_REMOVE', 'ACCESS_MODE_UPDATE', 'CLIENT_ALIAS_UPDATE', 'GATEWAY_SETTINGS_UPDATE'])
      expect(auditLogSchema.safeParse(row(action)).success).toBe(true);
    expect(auditLogSchema.safeParse(row('ACCESS_SOMETHING')).success).toBe(false);
    // 화면이 모르는 작업은 줄을 빼고 건수만 알린다(이전 화면 동작 유지)
    const read = readAuditRows({ items: [row('ACCESS_RULE_ADD'), row('ACCESS_SOMETHING')], total: 2, page: 1, page_size: 10, total_pages: 1 });
    expect(read.items).toHaveLength(1);
    expect(read.skipped).toBe(1);
  });

  it('reads accessRuleId from an event and maps it', () => {
    const raw = {
      event_id: 'evt-1', occurred_at: '2026-10-12T05:00:00.000Z', client_id: ID_A, action: 'BLOCK', final_action: 'BLOCK', status: 'NEW',
      admin_notes: [], timeline: [], detections: [], target_llm: 'ChatGPT', detection_outcome: 'UNAVAILABLE', content_type: 'prompt',
      reason_code: 'client_blocked', access_rule_id: RULE,
    };
    const parsed = securityEventSchema.parse(raw);
    expect(mapSecurityEventDto(parsed as never).accessRuleId).toBe(RULE);
    const { access_rule_id: _omitted, ...without } = raw;
    expect(mapSecurityEventDto(securityEventSchema.parse(without) as never)).not.toHaveProperty('accessRuleId');
  });
});

describe('access block in the event presentation', () => {
  const event: SecurityEvent = {
    eventId: 'evt-1', occurredAt: '2026-10-12T05:00:00Z', clientId: ID_A, targetLlm: 'ChatGPT', detectionOutcome: 'UNAVAILABLE', finalAction: 'BLOCK',
    status: 'NEW', adminNotes: [], timeline: [], detections: [], degraded: false, reasonCode: 'client_blocked',
  };
  it('is not a detection failure: no fail policy, no cause, no "unsafe" wording', () => {
    expect(inspectionFailure(event)).toEqual({ action: '접속 차단', detail: '접속 차단(관리자)', accessBlock: true });
    expect(inspectionFailure({ ...event, reasonCode: 'client_id_missing' })).toEqual({ action: '접속 차단', detail: '접속 차단(확장 ID 없음)', accessBlock: true });
    expect(eventStory(event).reason).toBe('관리자 설정에 따라 접속 단계에서 차단했습니다. 내용은 검사하지 않았습니다.');
    expect(missingDetectionTitle('UNAVAILABLE', 'client_blocked')).toBe('검사 안 함 · 접속 차단');
  });
  it('leaves the other unavailable cases as they were', () => {
    expect(inspectionFailure({ ...event, reasonCode: undefined })).toEqual({ action: '검사 불가 · 차단', detail: '원인 미기록 · 장애 정책 미기록' });
    expect(inspectionFailure({ ...event, reasonCode: 'file_too_large' })).toEqual({ action: '검사 불가 · 차단', detail: '파일이 커서 검사하지 못함' });
    expect(eventStory({ ...event, reasonCode: undefined }).reason).toBe('탐지 결과를 확인할 수 없습니다.');
    expect(missingDetectionTitle('UNAVAILABLE')).toBe('탐지 결과 확인 불가');
    expect(missingDetectionTitle('UNAVAILABLE', 'detection_timeout')).toBe('탐지 결과 확인 불가');
    expect(missingDetectionTitle('NO_MATCH')).toBe('일치한 문서·민감정보 없음');
  });
  it('a degraded detection keeps its failure wording even if a stale access code were present', () => {
    expect(inspectionFailure({ ...event, degraded: true, degradedReason: 'TIMEOUT', failurePolicy: 'FAIL_CLOSED' })?.detail).toBe('시간 초과 · 장애 시 차단');
  });
});

describe('audit log page: access actions', () => {
  const mount = () => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuditLogsPage /></MemoryRouter></QueryClientProvider>);

  it('offers the four actions in the filter', () => {
    mount();
    for (const [value, label] of [['ACCESS_RULE_ADD', '접속 차단 등록'], ['ACCESS_RULE_REMOVE', '접속 차단 해제'], ['ACCESS_MODE_UPDATE', '확장 ID 없는 접속 차단 변경'], ['CLIENT_ALIAS_UPDATE', '확장 ID 별칭 변경']])
      expect(screen.getByRole('option', { name: label })).toHaveValue(value);
  });

  it('links the rows to the access tab (not the settings tab) and shows before and after', async () => {
    await mockGatewayApi.addAccessRule({ client_id: ID_A, reasons: ['INVESTIGATION'], memo: '메모', duration: '1d', expected_version: 0 });
    await mockGatewayApi.setAccessMode({ require_client_id: true, expected_version: 1 });
    await mockGatewayApi.setClientAlias(ID_A, '홍길동 PC');
    await mockGatewayApi.setClientAlias(ID_A, '김철수 PC');
    await mockGatewayApi.saveGatewaySettings({ expected_version: 0, timeout: { prompt: { action: 'forward', seconds: 0.5 }, file: { action: 'block', seconds: 2 } }, uninspectable: { image: 'allow', scanned_pdf: 'block', other: 'block' }, notify_on_allow: true });
    mount();

    // 접속 차단 등록
    fireEvent.change(screen.getByLabelText('작업 유형'), { target: { value: 'ACCESS_RULE_ADD' } });
    const addLink = await screen.findByRole('link', { name: /^[0-9a-f-]{36}$/ });
    expect(addLink).toHaveAttribute('href', '/policies/access');
    const addRow = addLink.closest('tr') as HTMLElement;
    expect(within(addRow).getByText('접속 차단 등록')).toBeInTheDocument();
    expect(within(addRow).getByText('Gateway')).toBeInTheDocument();
    fireEvent.click(within(addRow).getByRole('button', { name: /상세 열기/ }));
    let details = await screen.findByRole('region', { name: '기록된 변경 전후' });
    expect(within(details).getByText('접속 차단 버전')).toBeInTheDocument();
    expect(within(details).getByText('변경 전: 없음')).toBeInTheDocument();   // 첫 저장은 이전 번호가 없다
    expect(within(details).getByText('변경 후: v1')).toBeInTheDocument();
    expect(within(details).getByText('차단 목록')).toBeInTheDocument();
    expect(within(details).getByText(new RegExp(`변경 후: 차단 · 확장 프로그램 ${ID_A}`))).toBeInTheDocument();
    expect(within(details).queryByText('정책 버전')).toBeNull();

    // 확장 ID 없는 접속 차단 변경
    fireEvent.change(screen.getByLabelText('작업 유형'), { target: { value: 'ACCESS_MODE_UPDATE' } });
    const modeLink = await screen.findByRole('link', { name: 'gateway-access' });
    expect(modeLink).toHaveAttribute('href', '/policies/access');
    fireEvent.click(within(modeLink.closest('tr') as HTMLElement).getByRole('button', { name: /상세 열기/ }));
    details = await screen.findByRole('region', { name: '기록된 변경 전후' });
    expect(within(details).getByText('변경 전: v1')).toBeInTheDocument();
    expect(within(details).getByText('변경 후: v2')).toBeInTheDocument();
    expect(within(details).getByText('확장 ID 없는 접속 차단')).toBeInTheDocument();
    expect(within(details).getByText('변경 전: 꺼짐')).toBeInTheDocument();
    expect(within(details).getByText('변경 후: 켜짐')).toBeInTheDocument();

    // 별칭 변경: 대상은 확장 ID, 전·후는 별칭
    fireEvent.change(screen.getByLabelText('작업 유형'), { target: { value: 'CLIENT_ALIAS_UPDATE' } });
    const aliasLinks = await screen.findAllByRole('link', { name: ID_A });
    expect(aliasLinks).toHaveLength(2);
    for (const link of aliasLinks) expect(link).toHaveAttribute('href', '/policies/access');
    fireEvent.click(within(aliasLinks[0].closest('tr') as HTMLElement).getByRole('button', { name: /상세 열기/ }));
    details = await screen.findByRole('region', { name: '기록된 변경 전후' });
    expect(within(details).getByText('별칭')).toBeInTheDocument();
    expect(within(details).getByText('변경 전: 홍길동 PC')).toBeInTheDocument();
    expect(within(details).getByText('변경 후: 김철수 PC')).toBeInTheDocument();

    // Gateway 처리 설정 변경은 그대로 설정 탭으로
    fireEvent.change(screen.getByLabelText('작업 유형'), { target: { value: 'GATEWAY_SETTINGS_UPDATE' } });
    expect(await screen.findByRole('link', { name: 'gateway-settings' })).toHaveAttribute('href', '/policies/gateway');
  });
});
