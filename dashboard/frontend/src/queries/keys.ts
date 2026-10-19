import type { AuditFilters } from '@/src/types/audit';
import type { EventFilters, OverviewPeriod } from '@/src/types/event';

export const eventKeys = {
  all: ['events'] as const,
  lists: () => [...eventKeys.all, 'list'] as const,
  list: (filters: EventFilters) => [...eventKeys.lists(), filters] as const,
  details: () => [...eventKeys.all, 'detail'] as const,
  detail: (eventId: string) => [...eventKeys.details(), eventId] as const,
};
export const dashboardKeys = {
  all: ['dashboard'] as const,
  stats: (period: OverviewPeriod) => ['dashboard', 'stats', period] as const,
  summary: (period: OverviewPeriod) => ['dashboard', 'summary', period] as const,
};
export const trafficKeys = {
  all: ['traffic'] as const,
  snapshot: (period: OverviewPeriod) => ['traffic', 'snapshot', period] as const,
  clients: () => ['traffic', 'clients'] as const,
};
export const documentKeys = {
  all: ['documents'] as const,
  list: () => ['documents', 'list'] as const,
};
export const policyKeys = {
  all: ['policies'] as const,
  list: () => ['policies', 'list'] as const,
  capabilities: () => ['policies', 'capabilities'] as const,
  history: (policyId: string) => ['policies', 'history', policyId] as const,
};
export const auditKeys = {
  all: ['audit-logs'] as const,
  list: (filters: AuditFilters) => ['audit-logs', 'list', filters] as const,
};
