// 시스템 상태 화면(2026-10-12) - 대시보드 백엔드 GET /api/system/status 호출.
// detectionOpsService와 같이 httpClient를 직접 쓴다(gatewayApi 인터페이스·mock adapter는 건드리지 않는다).
// 계약: components[]는 백엔드가 구성 요소별로 판정한 상태, instances·rds_instance는 Detection이 AWS에서 읽은 값 그대로.
// 시크릿·DSN·RDS 호스트 주소는 계약상 내려오지 않으며, 화면도 받은 칸만 그대로 보여 준다.
import { z } from 'zod';
import { httpClient } from '@/src/api/httpClient';
import { parseApiResponse } from '@/src/api/schemas';

export const SYSTEM_STATUS_PATH = '/api/system/status';

// 알 수 없는 상태 값이 와도 화면 전체가 실패하지 않도록 '확인 불가'로 받는다
export const componentStatusSchema = z.enum(['ok', 'slow', 'down', 'unknown']).catch('unknown');
export type ComponentStatus = z.infer<typeof componentStatusSchema>;

const optionalText = z.string().nullish();

export const systemComponentSchema = z.object({
  key: z.string().min(1),
  label: z.string(),
  status: componentStatusSchema,
  summary: z.string(),
  // 값 모양이 달라져도 다른 칸이 막히지 않도록 칸별 값은 그대로 받고 표시할 때 문자열로 바꾼다
  details: z.record(z.string(), z.unknown()).nullish().transform(value => value ?? {}),
  checked_at: optionalText,
});
export type SystemComponent = z.infer<typeof systemComponentSchema>;

export const systemInstanceSchema = z.object({
  role: z.string(),
  instance_id: z.string(),
  name: optionalText,
  state: z.string(),
  system_status: optionalText,
  instance_status: optionalText,
});
export type SystemInstance = z.infer<typeof systemInstanceSchema>;

// error: null | 'permission_missing' | 'unavailable'. 상태 점검 권한만 없으면 error는 null이고 status_checks만 'permission_missing'
export const systemInstancesSchema = z.object({
  ok: z.boolean(),
  error: optionalText,
  status_checks: optionalText,
  items: z.array(systemInstanceSchema).nullish().transform(value => value ?? []),
});
export type SystemInstances = z.infer<typeof systemInstancesSchema>;

// error: null | 'permission_missing' | 'unavailable' | 'not_configured'
export const systemRdsSchema = z.object({
  ok: z.boolean(),
  error: optionalText,
  identifier: optionalText,
  status: optionalText,
  engine: optionalText,
});
export type SystemRds = z.infer<typeof systemRdsSchema>;

export const systemStatusSchema = z.object({
  checked_at: z.string(),
  components: z.array(systemComponentSchema),
  instances: systemInstancesSchema,
  rds_instance: systemRdsSchema,
});
export type SystemStatus = z.infer<typeof systemStatusSchema>;

export const systemStatusKeys = {
  status: () => ['system-status', 'status'] as const,
};

export const systemStatusService = {
  async getStatus(signal?: AbortSignal): Promise<SystemStatus> {
    return parseApiResponse(systemStatusSchema, await httpClient.get<unknown>(SYSTEM_STATUS_PATH, signal));
  },
};
