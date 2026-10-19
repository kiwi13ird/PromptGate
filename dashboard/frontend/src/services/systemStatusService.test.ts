import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpClient } from '@/src/api/httpClient';
import { systemStatusWire } from '@/src/mocks/systemStatus';
import { systemStatusSchema, systemStatusService } from './systemStatusService';

afterEach(() => vi.restoreAllMocks());

describe('system status service', () => {
  it('reads GET /api/system/status without query parameters and parses the contract shape', async () => {
    const get = vi.spyOn(httpClient, 'get').mockResolvedValue(systemStatusWire());
    const status = await systemStatusService.getStatus();
    expect(get.mock.calls[0][0]).toBe('/api/system/status');
    expect(status.components).toHaveLength(9);
    expect(status.components[0]).toMatchObject({ key: 'dashboard', label: '대시보드', status: 'ok' });
    expect(status.instances.items[0]).toMatchObject({ role: 'gateway', instance_id: 'i-00000000000000001', state: 'running' });
    expect(status.rds_instance).toMatchObject({ identifier: 'sample-db', status: 'available' });
  });

  it('maps an unknown component status to unknown instead of failing the whole page', () => {
    const wire = systemStatusWire() as { components: Record<string, unknown>[] };
    wire.components[0].status = 'degraded-somehow';
    expect(systemStatusSchema.parse(wire).components[0].status).toBe('unknown');
  });

  it('accepts the unavailable fallbacks the dashboard backend sends when Detection does not answer', () => {
    const wire = {
      ...systemStatusWire(),
      instances: { ok: false, error: 'unavailable', items: [] },
      rds_instance: { ok: false, error: 'unavailable', items: [] },
    };
    const parsed = systemStatusSchema.parse(wire);
    expect(parsed.instances).toEqual({ ok: false, error: 'unavailable', status_checks: undefined, items: [] });
    expect(parsed.rds_instance).toMatchObject({ ok: false, error: 'unavailable' });
  });

  it('treats missing optional fields as empty without inventing values', () => {
    const wire = {
      checked_at: '2026-10-12T03:00:00Z',
      components: [{ key: 'redis', label: 'Redis', status: 'ok', summary: '정상' }],
      instances: { ok: true, error: null },
      rds_instance: { ok: true },
    };
    const parsed = systemStatusSchema.parse(wire);
    expect(parsed.components[0].details).toEqual({});
    expect(parsed.components[0].checked_at).toBeUndefined();
    expect(parsed.instances.items).toEqual([]);
    expect(parsed.rds_instance.identifier).toBeUndefined();
  });

  it('rejects a response without the required top-level parts', async () => {
    vi.spyOn(httpClient, 'get').mockResolvedValue({ checked_at: '2026-10-12T03:00:00Z', components: [] });
    await expect(systemStatusService.getStatus()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });

  it('drops fields outside the contract so nothing unexpected reaches the screen', () => {
    const wire = systemStatusWire() as { rds_instance: Record<string, unknown> };
    wire.rds_instance.host = 'private-host.example.internal';
    expect(systemStatusSchema.parse(wire).rds_instance).not.toHaveProperty('host');
  });
});
