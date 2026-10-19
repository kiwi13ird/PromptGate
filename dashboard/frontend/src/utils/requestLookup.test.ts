import { describe, expect, it } from 'vitest';
import { eventListReturnPath, lookupMatches } from './requestLookup';
import type { LookupResult } from '@/src/services/demoToolsService';
const item = { event_id: 'evt-a', request_id: 'req-a', client_id: 'client-a', occurred_at: '2026-10-04T00:00:00Z', final_action: 'BLOCK' as const, target_llm: 'ChatGPT' };
const result: LookupResult = { status: 'FOUND', count: 1, checked_at: item.occurred_at, items: [item] };
describe('exact request lookup and local return navigation', () => {
  it('accepts only the correct identifier for each lookup kind', () => {
    expect(lookupMatches(result, 'request', 'req-a')).toBe(true);
    expect(lookupMatches(result, 'client', 'client-a')).toBe(true);
    expect(lookupMatches(result, 'event', 'evt-a')).toBe(true);
    expect(lookupMatches(result, 'request', 'other')).toBe(false);
  });
  it('rejects an entire mixed response instead of offering unrelated events', () => {
    expect(lookupMatches({ ...result, status: 'AMBIGUOUS', count: 2, items: [item, { ...item, request_id: 'other' }] }, 'request', 'req-a')).toBe(false);
  });
  it('keeps multiple client results valid but rejects records before observation began', () => {
    expect(lookupMatches({ ...result, count: 2, items: [item, { ...item, event_id: 'evt-b' }] }, 'client', 'client-a', '2026-10-03T23:59:59Z')).toBe(true);
    expect(lookupMatches(result, 'client', 'client-a', '2026-10-04T00:00:01Z')).toBe(false);
    expect(lookupMatches(result, 'client', 'client-a', 'invalid')).toBe(false);
  });
  it('rejects inconsistent counts and invalid event timestamps', () => {
    expect(lookupMatches({ ...result, count: 0 }, 'request', 'req-a')).toBe(false);
    expect(lookupMatches({ ...result, items: [{ ...item, occurred_at: 'bad' }] }, 'request', 'req-a')).toBe(false);
    expect(lookupMatches({ ...result, status: 'WAITING' }, 'request', 'req-a')).toBe(false);
    expect(lookupMatches({ ...result, status: 'WAITING', count: 0, items: [] }, 'request', 'req-a')).toBe(true);
  });
  it('retains list filters but never accepts an external or unrelated return destination', () => {
    expect(eventListReturnPath({ eventListReturn: '/events?period=30D&page=2&llm=Gemini' })).toBe('/events?period=30D&page=2&llm=Gemini');
    for (const value of ['https://evil.example', '//evil.example', '/events/evt-a', '/login', '/events#x']) expect(eventListReturnPath({ eventListReturn: value })).toBe('/events');
    expect(eventListReturnPath(null)).toBe('/events');
  });
});
