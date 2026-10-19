export const endpoints = {
  auth: {
    login: '/api/auth/login',
    logout: '/api/auth/logout',
    session: '/api/auth/session',
  },
  dashboard: { stats: '/api/dashboard/stats' },
  traffic: {
    summary: '/api/traffic/summary',
    timeseries: '/api/traffic/timeseries',
    clients: '/api/traffic/clients',
  },
  events: {
    ingest: '/api/events/ingest',
    list: '/api/events',
    detail: (eventId: string) => `/api/events/${encodeURIComponent(eventId)}`,
    status: (eventId: string) =>
      `/api/events/${encodeURIComponent(eventId)}/status`,
    assignee: (eventId: string) =>
      `/api/events/${encodeURIComponent(eventId)}/assignee`,
    notes: (eventId: string) =>
      `/api/events/${encodeURIComponent(eventId)}/notes`,
  },
  documents: {
    list: '/api/documents',
    create: '/api/documents',
    status: (documentId: string) =>
      `/api/documents/${encodeURIComponent(documentId)}/status`,
  },
  policies: {
    list: '/api/policies',
    capabilities: '/api/policies/capabilities',
    create: '/api/policies',
    detail: (policyId: string) =>
      `/api/policies/${encodeURIComponent(policyId)}`,
    status: (policyId: string) =>
      `/api/policies/${encodeURIComponent(policyId)}/status`,
    versions: (policyId: string) =>
      `/api/policies/${encodeURIComponent(policyId)}/versions`,
  },
  auditLogs: { list: '/api/audit-logs' },
  // Gateway 처리 설정(2026-10-10): GET 조회 · PUT 저장(expected_version)
  gatewaySettings: '/api/gateway-settings',
  // 접속 차단(2026-10-12): 목록·방식은 문서 번호(expected_version)로 저장, 별칭은 확장 ID별
  gatewayAccess: {
    document: '/api/gateway-access',
    rules: '/api/gateway-access/rules',
    rule: (ruleId: string) => `/api/gateway-access/rules/${encodeURIComponent(ruleId)}`,
    mode: '/api/gateway-access/mode',
  },
  clientAliases: {
    list: '/api/client-aliases',
    item: (clientId: string) => `/api/client-aliases/${encodeURIComponent(clientId)}`,
  },
} as const;
