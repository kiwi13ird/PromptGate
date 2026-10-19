import { describe, expect, it } from 'vitest';
import { mockGatewayApi } from './mockAdapter';

describe('mock mutations', () => {
  it('creates a new policy version rather than overwriting the version number', async () => {
    const updated = await mockGatewayApi.updatePolicy('POL-002', 'MASK_FULL', 2);
    expect(updated.version).toBe(3);
    expect(updated.action).toBe('MASK');
    expect(updated.policy_action).toBe('MASK_FULL');
    const history = await mockGatewayApi.getPolicyHistory('POL-002');
    expect(history.map((entry) => entry.version)).toEqual([1, 2, 3]);
    const logs = await mockGatewayApi.getAuditLogs({
      period: '7D',
      action: 'POLICY_UPDATE',
      result: 'ALL',
      admin: '',
      page: 1,
      pageSize: 50,
    });
    expect(logs.items[0].changes).toMatchObject({
      previous_version: 2,
      new_version: 3,
      previous_action: 'BLOCK',
      new_action: 'MASK',
    });
  });
  it('registers metadata and applies an idempotent desired document status', async () => {
    const file = new File(['not persisted'], 'sample-upload.txt', {
      type: 'text/plain',
    });
    const created = await mockGatewayApi.registerDocument(file);
    const changed = await mockGatewayApi.changeDocumentStatus(
      created.document_id,
      'INACTIVE',
    );
    expect(changed.status).toBe('INACTIVE');
    await expect(
      mockGatewayApi.changeDocumentStatus(created.document_id, 'INACTIVE'),
    ).resolves.toMatchObject({ status: 'INACTIVE' });
    expect(
      localStorage.getItem('llm-security-gateway-demo-metadata-v5'),
    ).not.toContain('not persisted');
  });
  it('persists incident workflow metadata and writes content-free audit metadata', async () => {
    const assigned = await mockGatewayApi.assignEvent(
      'EVT-1000A001',
      'security.lead',
    );
    expect(assigned.assignee).toBe('security.lead');
    const updated = await mockGatewayApi.updateEventStatus(
      'EVT-1000A001',
      'INVESTIGATING',
    );
    expect(updated.status).toBe('INVESTIGATING');
    const noted = await mockGatewayApi.addEventNote(
      'EVT-1000A001',
      '시연용 조사 메모',
    );
    expect(noted.admin_notes[0].content).toBe('시연용 조사 메모');
    const audits = await mockGatewayApi.getAuditLogs({
      period: '7D',
      action: 'EVENT_NOTE_ADDED',
      result: 'ALL',
      admin: '',
      page: 1,
      pageSize: 50,
    });
    expect(audits.items[0].changes).toEqual({ note_added: true });
    expect(JSON.stringify(audits.items[0])).not.toContain('시연용 조사 메모');
  });
  it('rejects duplicate policy targets', async () => {
    // 2026-10-15: 지원 목록에 있는 대상만 409까지 간다(API_KEY는 목록 밖 → 422, 아래 시험). 예시 정책 POL-006이 EMAIL_ADDRESS
    await expect(
      mockGatewayApi.createPolicy('EMAIL_ADDRESS', 'BLOCK'),
    ).rejects.toMatchObject({ code: 'CONFLICT', status: 409, serverCode: 'CONFLICT' });
  });
  it('rejects stale policy mutation versions', async () => {
    await expect(
      mockGatewayApi.updatePolicy('POL-002', 'MASK_FULL', 1),
    ).rejects.toMatchObject({ code: 'CONFLICT', status: 409, serverCode: 'VERSION_CONFLICT' });
  });
});
