import { z } from 'zod';

// 접속 차단(2026-10-12) 계약 - 대시보드 서버의 /api/gateway-access · /api/client-aliases.
// Gateway로는 id·client_id·expires_at과 사유 코드(reasons)가 간다. 메모는 관리자가 '사용자에게 메모도 보이기'를 고른 규칙만
// user_memo로 간다(그 밖의 메모는 관리자만 본다). 별칭은 Gateway로 가지 않는다.
export const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$/;
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const ALIAS_MAX = 40;
export const MEMO_MAX = 200;

// 사유 코드는 고정(화면 글자는 서비스의 BLOCK_REASON_OPTIONS). 순서대로 보낸다
export const BLOCK_REASON_CODES = ['LEAK_DOC_REPEAT', 'PII_REPEAT', 'INVESTIGATION', 'LEAVE', 'ADMIN_REQUEST', 'OTHER'] as const;
export const BLOCK_DURATION_CODES = ['1h', '1d', 'permanent'] as const;
export type BlockReasonCode = (typeof BLOCK_REASON_CODES)[number];
export type BlockDuration = (typeof BLOCK_DURATION_CODES)[number];

// 화면에 보이는 글자(코드는 위에서 고정)
export const BLOCK_REASON_OPTIONS: ReadonlyArray<{ code: BlockReasonCode; label: string }> = [
  { code: 'LEAK_DOC_REPEAT', label: '기밀 문서 반복 유출 시도' },
  { code: 'PII_REPEAT', label: '개인정보 반복 입력' },
  { code: 'INVESTIGATION', label: '보안 조사 중' },
  { code: 'LEAVE', label: '퇴사·휴직 예정' },
  { code: 'ADMIN_REQUEST', label: '관리자 요청' },
  { code: 'OTHER', label: '기타' },
];
export const BLOCK_DURATION_OPTIONS: ReadonlyArray<{ code: BlockDuration; label: string }> = [
  { code: '1h', label: '1시간' },
  { code: '1d', label: '1일' },
  { code: 'permanent', label: '영구' },
];
/** 사유 코드의 글자. 모르는 코드는 그대로 */
export const blockReasonText = (code: string) => BLOCK_REASON_OPTIONS.find(option => option.code === code)?.label ?? code;

/** 이벤트에 남는 자리표시 ID(unknown-client · legacy-gateway)는 사람을 가리지 못해 차단 대상이 아니다 */
export const isPlaceholderClientId = (value: string) => /^(unknown|legacy)-/i.test(value);
/** 차단할 수 있는 확장 프로그램 ID: 형식이 맞고 자리표시 ID가 아님 */
export const isBlockableClientId = (value: string | null | undefined): value is string =>
  typeof value === 'string' && CLIENT_ID_PATTERN.test(value) && !isPlaceholderClientId(value);

const isoTime = z.iso.datetime({ offset: true }).max(50);
const uuid = z.string().regex(UUID_PATTERN);

export const accessRuleSchema = z.object({
  id: uuid,
  client_id: z.string().regex(CLIENT_ID_PATTERN),
  reasons: z.array(z.string().min(1).max(40)).max(20),
  memo: z.string().max(1000).nullish(),
  show_memo_to_user: z.boolean().optional(),   // 메모를 차단된 사용자에게도 보임(없으면 꺼짐)
  expires_at: isoTime.nullable(),
  created_by: z.string().min(1).max(200),
  created_at: isoTime,
  removed_by: z.string().max(200).nullish(),
  removed_at: isoTime.nullish(),
  active: z.boolean().optional(),
});

// Gateway가 지표에 실어 보낸 마지막 반영 보고(access_applied) + 대시보드가 받은 시각
export const accessAppliedSchema = z.object({
  version: z.number().int().nonnegative().nullable(),
  revision: z.string().max(100).nullable(),
  source: z.enum(['NONE', 'CACHE', 'DASHBOARD']),
  applied_at: z.string().max(50).nullish(),   // Gateway 시계
  rejected: z.string().max(200).nullish(),   // 거부한 칸 경로(rules.3.client_id 등)
  active_rules: z.number().int().nonnegative(),
  require_client_id: z.boolean(),
  denied_5m: z.number().int().nonnegative(),
  received_at: isoTime,
});
export const ACCESS_REPORT_INVALID = 'INVALID' as const;
// 보고 칸 하나가 계약과 달라도 규칙 목록은 보여 준다: 모양이 틀리면 '보고 형식 오류'로 따로 표시
const appliedField = z.unknown().transform(value => {
  if (value === null || value === undefined) return null;
  const parsed = accessAppliedSchema.safeParse(value);
  return parsed.success ? parsed.data : ACCESS_REPORT_INVALID;
});

export const gatewayAccessResponseSchema = z.object({
  version: z.number().int().nonnegative(),   // 저장된 목록이 없으면 0
  revision: uuid.nullable(),
  require_client_id: z.boolean(),
  rules: z.array(accessRuleSchema),   // 만료·해제된 기록 포함 전체
  applied: appliedField.optional(),
  updated_at: isoTime.nullish(),
  updated_by: z.string().max(200).nullish(),
});

export const clientAliasesResponseSchema = z.object({
  items: z.array(z.object({ client_id: z.string().min(1).max(200), alias: z.string().min(1).max(200) })),
});

export const accessRuleCreateBodySchema = z.strictObject({
  client_id: z.string().regex(CLIENT_ID_PATTERN).refine(value => !isPlaceholderClientId(value)),
  reasons: z.array(z.enum(BLOCK_REASON_CODES)).min(1).refine(list => new Set(list).size === list.length),
  memo: z.string().max(MEMO_MAX).optional(),
  show_memo_to_user: z.boolean().optional(),   // 기본 false. true면 메모가 있어야 한다
  duration: z.enum(BLOCK_DURATION_CODES),
  expected_version: z.number().int().nonnegative(),
}).superRefine((body, context) => {
  // 사유 '기타'는 메모가 있어야 한다
  if (body.reasons.includes('OTHER') && !body.memo?.trim())
    context.addIssue({ code: 'custom', path: ['memo'], message: 'OTHER requires a memo.' });
  // 메모를 사용자에게 보이려면 메모가 있어야 한다
  if (body.show_memo_to_user === true && !body.memo?.trim())
    context.addIssue({ code: 'custom', path: ['show_memo_to_user'], message: 'show_memo_to_user requires a memo.' });
});
export const accessModeBodySchema = z.strictObject({
  require_client_id: z.boolean(),
  expected_version: z.number().int().nonnegative(),
});
export const clientAliasBodySchema = z.strictObject({ alias: z.string().max(ALIAS_MAX) });

export type AccessRule = z.infer<typeof accessRuleSchema>;
export type AccessApplied = z.infer<typeof accessAppliedSchema>;
export type GatewayAccessResponse = z.infer<typeof gatewayAccessResponseSchema>;
export type ClientAliasesResponse = z.infer<typeof clientAliasesResponseSchema>;
export type AccessRuleCreateBody = z.infer<typeof accessRuleCreateBodySchema>;
export type AccessModeBody = z.infer<typeof accessModeBodySchema>;
/** 쓰기 요청의 결과: 새 문서 번호를 응답에서 읽을 수 있으면 그 값, 아니면 null(요청의 expected_version + 1로 본다) */
export interface AccessWriteResult { version: number | null }
