import { z } from 'zod';
import type { GatewayApi } from './gatewayApi';
import type {
  AuditLogDto,
  ConfidentialDocumentDto,
  DashboardStatsDto,
  DetectionPolicyDto,
  PageDto,
  PolicyCapabilitiesDto,
  PolicyVersionDto,
  SecurityEventDto,
  TrafficClientsDto,
  TrafficSnapshotDto,
} from './dto';
import { endpoints } from './endpoints';
import { httpClient } from './httpClient';
import { ApiError } from './errors';
import { env } from '@/src/config/env';
import {
  gatewaySettingsResponseSchema,
  gatewaySettingsSaveBodySchema,
} from './gatewaySettingsSchemas';
import {
  accessModeBodySchema,
  accessRuleCreateBodySchema,
  clientAliasBodySchema,
  clientAliasesResponseSchema,
  gatewayAccessResponseSchema,
  type AccessWriteResult,
} from './gatewayAccessSchemas';
import {
  readAuditRows,
  dashboardStatsSchema,
  documentSchema,
  pageSchema,
  parseApiResponse,
  policyCapabilitiesSchema,
  policySchema,
  policyVersionSchema,
  securityEventSchema,
  trafficSummarySchema,
  trafficTimeBucketSchema,
  trafficClientsSchema,
} from './schemas';

// 접속 차단 쓰기 응답: 새 문서 번호가 정수로 있으면 읽고, 본문이 없거나 다른 모양이면 null(호출한 쪽이 expected_version + 1로 본다)
const writeResult = (payload: unknown): AccessWriteResult => {
  const version = typeof payload === 'object' && payload !== null ? (payload as { version?: unknown }).version : undefined;
  return { version: typeof version === 'number' && Number.isInteger(version) && version >= 0 ? version : null };
};

function withQuery(path: string, values: Record<string, string | number>) {
  const query = new URLSearchParams(
    Object.entries(values)
      .filter(([, value]) => value !== '' && value !== 'ALL')
      .map(([key, value]) => [key, String(value)]),
  );
  return `${path}?${query.toString()}`;
}

export const httpGatewayApi: GatewayApi = {
  getDashboardStats: async (period, signal) =>
    parseApiResponse<DashboardStatsDto>(
      dashboardStatsSchema,
      await httpClient.get<unknown>(
        withQuery(endpoints.dashboard.stats, { period }),
        signal,
      ),
    ),
  getTrafficSnapshot: async (period, signal) => {
    const sections = ['summary', 'timeseries'];
    const results = await Promise.allSettled([
      httpClient.get<unknown>(withQuery(endpoints.traffic.summary, { period }), signal).then(value => parseApiResponse(trafficSummarySchema, value)),
      httpClient.get<unknown>(withQuery(endpoints.traffic.timeseries, { period }), signal).then(value => parseApiResponse(z.array(trafficTimeBucketSchema), value)),
    ]);
    // Authentication and cancellation must not be downgraded to partial success.
    const forbidden = results.find(result => result.status === 'rejected' && result.reason instanceof ApiError && ['UNAUTHORIZED', 'FORBIDDEN'].includes(result.reason.code));
    if (forbidden?.status === 'rejected') throw forbidden.reason;
    if (signal?.aborted) throw new ApiError('요청이 취소되었습니다.');
    if (results.every(result => result.status === 'rejected')) throw (results[0] as PromiseRejectedResult).reason;
    const [summary, timeSeries] = results;
    return {
      unavailable_sections: results.flatMap((result, index) => result.status === 'rejected' ? [sections[index]] : []),
      summary: summary.status === 'fulfilled' ? summary.value : {},
      time_series: timeSeries.status === 'fulfilled' ? timeSeries.value : [],
    } satisfies TrafficSnapshotDto;
  },
  getTrafficClients: async (signal) =>
    parseApiResponse<TrafficClientsDto>(
      trafficClientsSchema,
      await httpClient.get<unknown>(endpoints.traffic.clients, signal),
    ),
  getEvents: async (filters, signal) =>
    parseApiResponse<PageDto<SecurityEventDto>>(
      pageSchema(securityEventSchema),
      await httpClient.get<unknown>(
        withQuery(endpoints.events.list, {
          query: filters.query,
          period: filters.period,
          final_action: filters.finalAction,
          recommended_action: filters.recommendedAction,
          detector: filters.detector,
          match_type: filters.matchType,
          score_kind: filters.scoreKind,
          degraded: filters.degraded,
          detection_outcome: filters.detectionOutcome,
          degraded_reason: filters.degradedReason,
          failure_policy: filters.failurePolicy,
          document_id: filters.documentId,
          severity: filters.severity,
          status: filters.status,
          target_llm: filters.targetLlm,
          sort: filters.sort,
          page: filters.page,
          page_size: filters.pageSize,
          ...(filters.group ? { group: filters.group } : {}),   // 목록 화면만 묶음 — 차트는 이벤트 단위로 센다
          ...(filters.includeTest ? { include_test: 1 } : {}),   // 시험·데모 기록은 기본 제외
          ...(filters.entityCategory && filters.entityCategory !== 'ALL' ? { entity_category: filters.entityCategory } : {}),
          ...(filters.scope ? { scope: filters.scope } : {}),   // 집계와 같은 기록만(보안 현황·트래픽 계산용, 2026-10-15)
        }),
        signal,
      ),
    ),
  getEvent: async (eventId, signal) => {
    try {
      return parseApiResponse<SecurityEventDto>(
        securityEventSchema,
        await httpClient.get<unknown>(endpoints.events.detail(eventId), signal),
      );
    } catch (error) {
      if (
        typeof error === 'object' &&
        error &&
        'status' in error &&
        error.status === 404
      )
        return null;
      throw error;
    }
  },
  updateEventStatus: async (eventId, status, signal) =>
    parseApiResponse<SecurityEventDto>(
      securityEventSchema,
      await httpClient.patch<unknown>(
        endpoints.events.status(eventId),
        { status },
        signal,
      ),
    ),
  assignEvent: async (eventId, assignee, signal) =>
    parseApiResponse<SecurityEventDto>(
      securityEventSchema,
      await httpClient.patch<unknown>(
        endpoints.events.assignee(eventId),
        { assignee },
        signal,
      ),
    ),
  addEventNote: async (eventId, content, signal) =>
    parseApiResponse<SecurityEventDto>(
      securityEventSchema,
      await httpClient.post<unknown>(
        endpoints.events.notes(eventId),
        { content },
        signal,
      ),
    ),
  getDocuments: async (signal) =>
    parseApiResponse<ConfidentialDocumentDto[]>(
      z.array(documentSchema),
      await httpClient.get<unknown>(endpoints.documents.list, signal),
    ),
  registerDocument: async (file, signal) => {
    const body = new FormData();
    body.append('file', file, file.name);
    return parseApiResponse<ConfidentialDocumentDto>(
      documentSchema,
      await httpClient.postForm<unknown>(
        endpoints.documents.create,
        body,
        signal,
        env.uploadTimeoutMs,
      ),
    );
  },
  changeDocumentStatus: async (documentId, status, signal) =>
    parseApiResponse<ConfidentialDocumentDto>(
      documentSchema,
      await httpClient.patch<unknown>(
        endpoints.documents.status(documentId),
        { status },
        signal,
      ),
    ),
  getPolicies: async (signal) =>
    parseApiResponse<DetectionPolicyDto[]>(
      z.array(policySchema),
      await httpClient.get<unknown>(endpoints.policies.list, signal),
    ),
  getPolicyCapabilities: async (signal) =>
    parseApiResponse<PolicyCapabilitiesDto>(
      policyCapabilitiesSchema,
      await httpClient.get<unknown>(endpoints.policies.capabilities, signal),
    ),
  getPolicyHistory: async (policyId, signal) =>
    parseApiResponse<PolicyVersionDto[]>(
      z.array(policyVersionSchema),
      await httpClient.get<unknown>(
        endpoints.policies.versions(policyId),
        signal,
      ),
    ),
  createPolicy: async (detectionTarget, action, signal) =>
    parseApiResponse<DetectionPolicyDto>(
      policySchema,
      await httpClient.post<unknown>(
        endpoints.policies.create,
        { detection_target: detectionTarget, action },
        signal,
      ),
    ),
  updatePolicy: async (policyId, action, expectedVersion, signal) =>
    parseApiResponse<DetectionPolicyDto>(
      policySchema,
      await httpClient.patch<unknown>(
        endpoints.policies.detail(policyId),
        { action, expected_version: expectedVersion },
        signal,
      ),
    ),
  changePolicyStatus: async (policyId, enabled, expectedVersion, signal) =>
    parseApiResponse<DetectionPolicyDto>(
      policySchema,
      await httpClient.patch<unknown>(
        endpoints.policies.status(policyId),
        { enabled, expected_version: expectedVersion },
        signal,
      ),
    ),
  getAuditLogs: async (filters, signal) =>
    readAuditRows<AuditLogDto>(parseApiResponse(
      pageSchema(z.unknown()),
      await httpClient.get<unknown>(
        withQuery(endpoints.auditLogs.list, {
          period: filters.period,
          action: filters.action,
          result: filters.result,
          admin: filters.admin,
          page: filters.page,
          page_size: filters.pageSize,
        }),
        signal,
      ),
    )),
  getGatewaySettings: async (signal) =>
    parseApiResponse(
      gatewaySettingsResponseSchema,
      await httpClient.get<unknown>(endpoints.gatewaySettings, signal),
    ),
  saveGatewaySettings: async (body, signal) => {
    // 계약 밖 칸이 섞인 본문은 보내지 않는다(서버도 400으로 거부)
    const checked = gatewaySettingsSaveBodySchema.safeParse(body);
    if (!checked.success)
      throw new ApiError('저장할 수 없는 값입니다.', 'VALIDATION');
    return parseApiResponse(
      gatewaySettingsResponseSchema,
      await httpClient.put<unknown>(endpoints.gatewaySettings, checked.data, signal),
    );
  },
  getGatewayAccess: async (signal) =>
    parseApiResponse(
      gatewayAccessResponseSchema,
      await httpClient.get<unknown>(endpoints.gatewayAccess.document, signal),
    ),
  addAccessRule: async (body, signal) => {
    const checked = accessRuleCreateBodySchema.safeParse(body);
    if (!checked.success)
      throw new ApiError('저장할 수 없는 값입니다.', 'VALIDATION');
    return writeResult(await httpClient.post<unknown>(endpoints.gatewayAccess.rules, checked.data, signal));
  },
  removeAccessRule: async (ruleId, expectedVersion, signal) => {
    if (!Number.isInteger(expectedVersion) || expectedVersion < 0)
      throw new ApiError('저장할 수 없는 값입니다.', 'VALIDATION');
    return writeResult(await httpClient.delete<unknown>(
      `${endpoints.gatewayAccess.rule(ruleId)}?expected_version=${expectedVersion}`,
      signal,
    ));
  },
  setAccessMode: async (body, signal) => {
    const checked = accessModeBodySchema.safeParse(body);
    if (!checked.success)
      throw new ApiError('저장할 수 없는 값입니다.', 'VALIDATION');
    return writeResult(await httpClient.put<unknown>(endpoints.gatewayAccess.mode, checked.data, signal));
  },
  getClientAliases: async (signal) =>
    parseApiResponse(
      clientAliasesResponseSchema,
      await httpClient.get<unknown>(endpoints.clientAliases.list, signal),
    ),
  setClientAlias: async (clientId, alias, signal) => {
    const checked = clientAliasBodySchema.safeParse({ alias });
    if (!checked.success || !clientId)
      throw new ApiError('저장할 수 없는 값입니다.', 'VALIDATION');
    await httpClient.put<unknown>(endpoints.clientAliases.item(clientId), checked.data, signal);
  },
};

export const gatewayApi = httpGatewayApi;
