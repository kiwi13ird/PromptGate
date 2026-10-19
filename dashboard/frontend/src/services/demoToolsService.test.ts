import { describe, expect, it, vi } from 'vitest';
import { httpClient } from '@/src/api/httpClient';
import { demoToolsService } from './demoToolsService';
describe('lookup action validation', () => {
  it('rejects unknown actions rather than rendering them as allowed', async () => {
    vi.spyOn(httpClient, 'get').mockResolvedValue({ status: 'FOUND', count: 1, checked_at: '2026-10-04T00:00:00Z', items: [{ event_id: 'evt-a', request_id: 'req-a', client_id: 'client-a', occurred_at: '2026-10-04T00:00:00Z', final_action: 'UNKNOWN', target_llm: 'ChatGPT' }] });
    await expect(demoToolsService.lookup('request', 'req-a')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
});
