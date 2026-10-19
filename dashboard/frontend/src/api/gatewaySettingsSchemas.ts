import { z } from 'zod';

// Gateway 처리 설정(2026-10-10) 계약 - 명세 §1.1(설정 문서) · §3.1(GET 응답) · §3.2(PUT 본문).
// 설정 값은 칸이 정확히 같아야 한다(모르는 칸·빠진 칸 거부). Gateway 상태 칸은 보고에 따라 비어 있을 수 있어 null을 받는다.
export const WAIT_SECONDS_MIN = 0.05;
export const WAIT_SECONDS_MAX = 30;
export const REVISION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const SETTINGS_FIELD_PATTERN = /^[a-z_.]{1,100}$/;

const revision = z.string().regex(REVISION_PATTERN);
// 소수 자리 규칙 없음(0.125 허용). z.number()는 NaN·Infinity를 받지 않는다
const waitSeconds = z.number().min(WAIT_SECONDS_MIN).max(WAIT_SECONDS_MAX);
const timeoutRule = z.strictObject({ action: z.enum(['block', 'forward']), seconds: waitSeconds });
const uninspectableAction = z.enum(['block', 'allow']);

export const gatewaySettingsValuesSchema = z.strictObject({
  timeout: z.strictObject({ prompt: timeoutRule, file: timeoutRule }),
  uninspectable: z.strictObject({ image: uninspectableAction, scanned_pdf: uninspectableAction, other: uninspectableAction }),
  notify_on_allow: z.boolean(),
});

const storedDocument = z.strictObject({
  ...gatewaySettingsValuesSchema.shape,
  version: z.number().int().min(1),
  revision,
  updated_at: z.iso.datetime({ offset: true }).max(50),
  updated_by: z.string().min(1).max(200),
  source: z.literal('STORED'),
});
// 저장된 설정이 없으면 기본값 + version 0
const defaultDocument = z.strictObject({
  ...gatewaySettingsValuesSchema.shape,
  version: z.literal(0),
  revision: z.null(),
  updated_at: z.null(),
  updated_by: z.null(),
  source: z.literal('DEFAULT'),
});
export const gatewaySettingsDocumentSchema = z.discriminatedUnion('source', [storedDocument, defaultDocument]);

export const gatewayApplyStateSchema = z.enum(['NOT_REPORTING', 'LEGACY_GATEWAY', 'REPORT_INVALID', 'APPLIED', 'REJECTED', 'PENDING']);
export const gatewayApplyStatusSchema = z.object({
  state: gatewayApplyStateSchema,
  metrics_status: z.enum(['FRESH', 'STALE', 'NOT_RECEIVED']).nullish(),
  reported_at: z.iso.datetime({ offset: true }).nullish(),
  applied_version: z.number().int().nonnegative().nullish(),
  applied_revision: revision.nullish(),
  applied_source: z.enum(['ENV_DEFAULT', 'CACHE', 'DASHBOARD']).nullish(),
  applied_at: z.string().max(50).nullish(),   // Gateway 시계
  first_seen_at: z.iso.datetime({ offset: true }).nullish(),   // 대시보드가 처음 받은 시각
  rejected: z.object({
    version: z.number().int().nonnegative().nullable(),   // 백엔드가 받는 Gateway 보고 그대로(번호 없는 거부도 온다)
    revision: revision.nullable(),
    field: z.string().regex(SETTINGS_FIELD_PATTERN),
  }).nullish(),
  effective: gatewaySettingsValuesSchema.nullish(),
});

export const gatewaySettingsResponseSchema = z.object({
  settings: gatewaySettingsDocumentSchema,
  defaults: gatewaySettingsValuesSchema,
  gateway: gatewayApplyStatusSchema,
});

export const gatewaySettingsSaveBodySchema = z.strictObject({
  expected_version: z.number().int().nonnegative(),
  ...gatewaySettingsValuesSchema.shape,
});

export type GatewaySettingsValues = z.infer<typeof gatewaySettingsValuesSchema>;
export type GatewaySettingsDocument = z.infer<typeof gatewaySettingsDocumentSchema>;
export type GatewayApplyState = z.infer<typeof gatewayApplyStateSchema>;
export type GatewayApplyStatus = z.infer<typeof gatewayApplyStatusSchema>;
export type GatewaySettingsResponse = z.infer<typeof gatewaySettingsResponseSchema>;
export type GatewaySettingsSaveBody = z.infer<typeof gatewaySettingsSaveBodySchema>;
