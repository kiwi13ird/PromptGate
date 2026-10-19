import type { LookupKind, LookupResult } from '@/src/services/demoToolsService';

// Never label an unrelated or out-of-window record as this user's request.
export function lookupMatches(result: LookupResult, kind: LookupKind, value: string, since?: string) {
  if (result.status === 'WAITING') return result.count === 0 && result.items.length === 0;
  if (!result.items.length || result.count < result.items.length) return false;
  if (result.status === 'AMBIGUOUS' && result.count < 2) return false;
  const field = { request: 'request_id', client: 'client_id', event: 'event_id' } as const;
  const sinceMs = since ? Date.parse(since) : undefined;
  if (sinceMs !== undefined && !Number.isFinite(sinceMs)) return false;
  return result.items.every(item => item[field[kind]] === value
    && Number.isFinite(Date.parse(item.occurred_at))
    && (sinceMs === undefined || Date.parse(item.occurred_at) >= sinceMs));
}

export function eventListReturnPath(state: unknown) {
  if (!state || typeof state !== 'object' || !('eventListReturn' in state)) return '/events';
  const value = state.eventListReturn;
  if (typeof value !== 'string' || value.length > 4096 || !/^\/events(?:\?[^#]*)?$/.test(value)) return '/events';
  return value;
}
