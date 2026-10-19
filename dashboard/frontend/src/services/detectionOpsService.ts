// 리포트 · 문서별 키워드(HITL) · GPU 연결 상태 - 대시보드 백엔드가 Detection 관리 API로 넘기는 경로.
// evidenceService와 같이 httpClient를 직접 쓴다(기존 gatewayApi 인터페이스·mock adapter는 건드리지 않는다).
// 계약: docs/handoff/dashboard-backend-2026-10-04/README.md §2 + GET /api/system/gpu · POST /api/system/gpu/{start,stop}
import { z } from 'zod';
import { env } from '@/src/config/env';
import { ApiError } from '@/src/api/errors';
import { httpClient } from '@/src/api/httpClient';
import { parseApiResponse } from '@/src/api/schemas';

const optionalText = z.string().nullable().optional();
const optionalCount = z.number().int().nonnegative().nullable().optional();

export const keywordSchema = z.object({
  id: z.number().int().positive(),
  keyword: z.string(),
  doc_id: z.string(),
  status: z.enum(['pending', 'approved']),
  source: z.string(),
  reason: optionalText,
  doc_hits: optionalCount,
  neg_hits: optionalCount,
  created_at: optionalText,
  created_by: optionalText,
  decided_at: optionalText,
  decided_by: optionalText,
  // 선정 이유 보강(2026-10-13): 본문에서 그대로 잘라 온 근거 문장(줄바꿈으로 이음) · 자동 검사 결과(+ LLM의 고유/일반 참고 판정)
  evidence: optionalText,
  reason_version: optionalText,
  reason_check: z.object({
    ok: z.boolean().optional(),
    source: z.string().optional(),
    foreign_tokens: z.array(z.string()).optional(),
    error: z.string().optional(),
    specificity: z.string().nullable().optional(),
    kind: z.string().nullable().optional(),
    // 2026-10-16 Detection 계약(docs/handoff/detection-keyword-logic-2026-10-16/CONTRACT.md): 지금 보호 중인 문서 중 이 키워드가 든
    // 문서 수(자기 문서 포함) · 2개 이상이면 참 · 센 시각. 셈 전·옛 Detection은 없다(그때는 specificity만 본다, doc_hits로 대신하지 않음)
    doc_count: z.number().int().nonnegative().optional(),
    common_in_docs: z.boolean().optional(),
    doc_count_at: z.string().optional(),
  }).nullable().optional(),
});
export type DocumentKeyword = z.infer<typeof keywordSchema>;

/** '일반 표현' 표시(계약 2절): LLM 참고 판정 '일반' 또는 2개 이상 보호 문서에 나옴. 문턱은 Detection이 정한다(common_in_docs) */
export function keywordGenerality(keyword: Pick<DocumentKeyword, 'reason_check'>) {
  const check = keyword.reason_check;
  const llm = check?.specificity === '일반';
  const common = check?.common_in_docs === true;
  return { generic: llm || common, llm, common, kind: check?.kind ?? null, docCount: common ? check?.doc_count ?? null : null };
}

/** 일반 표현 안내 문구: '일반 표현일 수 있음 · 문서 n개에 나옴'(계약 문구) / LLM 판정만이면 종류를 괄호로 */
export function keywordGeneralityText(keyword: Pick<DocumentKeyword, 'reason_check'>) {
  const info = keywordGenerality(keyword);
  if (!info.generic) return null;
  const head = info.llm ? `일반 표현일 수 있음${info.kind ? `(${info.kind})` : ''}` : '일반 표현일 수 있음';
  return info.common && info.docCount !== null ? `${head} · 문서 ${info.docCount.toLocaleString('ko-KR')}개에 나옴` : head;
}

const keywordListSchema = z.object({ keywords: z.array(keywordSchema) });
// 승인 · 승인 상태로 직접 추가: 백엔드가 바로 탐지 재로딩까지 부르고 결과를 applied로 알린다
const keywordChangeSchema = keywordSchema.extend({
  applied: z.boolean().optional(),
  apply_error: z.string().optional(),
});
const keywordRejectSchema = z.object({
  id: z.number().int().positive(),
  rejected: z.literal(true),
  applied: z.boolean(),
  apply_error: z.string().optional(),
});
export type KeywordChange = { applied?: boolean; apply_error?: string };

export const keywordJobSchema = z.object({
  id: z.number().int().positive(),
  doc_id: z.string(),
  doc_version: z.number().int().nullable().optional(),
  status: z.enum(['queued', 'running', 'done', 'failed']),
  attempts: z.number().int().nonnegative().optional(),
  error: optionalText,
  created_at: optionalText,
  finished_at: optionalText,
});
export type KeywordJob = z.infer<typeof keywordJobSchema>;
const keywordJobListSchema = z.object({
  jobs: z.array(keywordJobSchema),
  counts: z.object({
    queued: z.number().int().nonnegative(),
    running: z.number().int().nonnegative(),
    done: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
  }),
});
export type KeywordJobList = z.infer<typeof keywordJobListSchema>;

// 2026-10-12 설계 v2 새 상태 칸은 전부 선택이고, 칸 하나의 모양이 달라도 목록 전체를 못 읽게 하지 않는다(그 칸만 없는 것으로 본다).
// 옛 보고서(10/1~10/11)와 옛 Detection에는 이 칸들이 없다.
const lenient = <T extends z.ZodType>(schema: T) => schema.nullish().catch(undefined);
const reportIncidentsSchema = z.object({
  total: z.number().int().nonnegative(),
  by_grade: z.record(z.string(), z.number().int().nonnegative()).optional(),
});

export const reportSchema = z.object({
  report_id: z.string(),
  status: z.enum(['running', 'done', 'failed']),
  stage: optionalText,
  from: optionalText,
  to: optionalText,
  /** 비교 기간(같은 길이 직전). 비교할 수 없으면 null */
  compare_from: lenient(z.string()),
  compare_to: lenient(z.string()),
  elapsed_seconds: z.number().nonnegative().optional(),
  generated_at: optionalText,
  /** 검사 건수(이벤트 기준). 옛 보고서에는 없고 rows(판정 기록 행)만 있다 */
  items: lenient(z.number().int().nonnegative()),
  rows: z.number().int().nonnegative().nullable().optional(),
  /** 사건 수(전체)와 등급별 수. 옛 보고서에는 없음 */
  incidents: lenient(reportIncidentsSchema),
  users_high: lenient(z.number().int().nonnegative()),
  error: optionalText,
});
export type Report = z.infer<typeof reportSchema>;
const reportListSchema = z.object({ reports: z.array(reportSchema), content_trend_enabled: lenient(z.boolean()) });
/** contentTrendEnabled: 탐지 서버의 전역 내용 경향 스위치. 옛 탐지 서버는 칸이 없어 null */
export type ReportList = { reports: Report[]; contentTrendEnabled: boolean | null };
export type CreateReportOptions = {
  /** 내용 경향 포함 여부. 안 보내면 서버의 전역 스위치를 따른다(옛 탐지 서버를 위해 칸 자체를 뺀다) */
  contentTrend?: boolean;
};

export const gpuStatusSchema = z.object({
  connected: z.boolean(),
  models: z.array(z.string()),
  latency_ms: z.number().nonnegative().nullable(),
  error: z.string().nullable(),
  checked_at: z.string(),
  // 켜기·끄기(10/7): EC2 상태(pending·running·stopping·stopped …). 조회 실패면 null, 이전 Detection이면 없음
  instance_state: z.string().nullable().optional(),
  controllable: z.boolean().optional(),
});
export type GpuStatus = z.infer<typeof gpuStatusSchema>;
const gpuControlSchema = z.object({ instance_id: z.string(), previous_state: z.string(), instance_state: z.string() });
export type GpuControlResult = z.infer<typeof gpuControlSchema>;

export const detectionOpsKeys = {
  keywords: () => ['detection-ops', 'keywords'] as const,
  keywordJobs: () => ['detection-ops', 'keyword-jobs'] as const,
  reports: () => ['detection-ops', 'reports'] as const,
  gpu: () => ['detection-ops', 'gpu'] as const,
};

const id = (value: string | number) => encodeURIComponent(String(value));

/** 리포트 파일은 새 탭·내려받기로만 연다 - nginx가 iframe을 막고, 백엔드가 sandbox CSP를 붙인다. */
export function reportFileUrl(reportId: string, download = false) {
  const base = new URL(env.apiBaseUrl, window.location.origin);
  return new URL(`/api/reports/${id(reportId)}/file${download ? '?download=1' : ''}`, base).toString();
}

export const detectionOpsService = {
  async getKeywords(signal?: AbortSignal): Promise<DocumentKeyword[]> {
    return parseApiResponse(keywordListSchema, await httpClient.get<unknown>('/api/keywords', signal)).keywords;
  },
  async addKeyword(keyword: string, docId: string, approve: boolean): Promise<DocumentKeyword & KeywordChange> {
    return parseApiResponse(keywordChangeSchema, await httpClient.post<unknown>('/api/keywords', { keyword, doc_id: docId, approve }));
  },
  /** 승인 대기 키워드의 표현만 고친다(탐지 미반영 상태라 재로딩 없음). 승인된 키워드는 409. */
  async updateKeyword(keywordId: number, keyword: string): Promise<DocumentKeyword> {
    return parseApiResponse(keywordSchema, await httpClient.patch<unknown>(`/api/keywords/${id(keywordId)}`, { keyword }));
  },
  async approveKeyword(keywordId: number): Promise<DocumentKeyword & KeywordChange> {
    return parseApiResponse(keywordChangeSchema, await httpClient.post<unknown>(`/api/keywords/${id(keywordId)}/approve`));
  },
  async rejectKeyword(keywordId: number): Promise<KeywordChange> {
    return parseApiResponse(keywordRejectSchema, await httpClient.post<unknown>(`/api/keywords/${id(keywordId)}/reject`));
  },
  async getKeywordJobs(signal?: AbortSignal): Promise<KeywordJobList> {
    return parseApiResponse(keywordJobListSchema, await httpClient.get<unknown>('/api/keyword-jobs', signal));
  },
  async requestExtraction(docId: string): Promise<KeywordJob> {
    return parseApiResponse(keywordJobSchema, await httpClient.post<unknown>(`/api/documents/${id(docId)}/extract-keywords`));
  },
  async retryJob(jobId: number): Promise<KeywordJob> {
    return parseApiResponse(keywordJobSchema, await httpClient.post<unknown>(`/api/keyword-jobs/${id(jobId)}/retry`));
  },
  async getReports(signal?: AbortSignal): Promise<ReportList> {
    const list = parseApiResponse(reportListSchema, await httpClient.get<unknown>('/api/reports', signal));
    return { reports: list.reports, contentTrendEnabled: list.content_trend_enabled ?? null };
  },
  async createReport(from: string, to: string, useLlm: boolean, options: CreateReportOptions = {}): Promise<Report> {
    const body = { from, to, use_llm: useLlm, ...(options.contentTrend === undefined ? {} : { content_trend: options.contentTrend }) };
    return parseApiResponse(reportSchema, await httpClient.post<unknown>('/api/reports', body));
  },
  async getGpuStatus(signal?: AbortSignal): Promise<GpuStatus> {
    return parseApiResponse(gpuStatusSchema, await httpClient.get<unknown>('/api/system/gpu', signal));
  },
  /** 켜기는 꺼진 상태에서만, 끄기는 켜진 상태에서만. 끄기는 리포트 생성·키워드 추출 중이면 409. */
  async controlGpu(action: 'start' | 'stop'): Promise<GpuControlResult> {
    return parseApiResponse(gpuControlSchema, await httpClient.post<unknown>(`/api/system/gpu/${action}`));
  },
};

/** 백엔드 오류 코드가 화면 문구를 정하지 않도록, 상태별로 이 화면에 맞는 안내만 고른다. */
export function detectionOpsMessage(error: unknown, context: 'report' | 'extract' | 'keyword' | 'edit' | 'gpu-start' | 'gpu-stop'): string {
  if (!(error instanceof ApiError)) return '잠시 후 다시 시도해주세요.';
  if (error.code === 'CONFLICT' && context === 'gpu-stop') return '리포트 생성이나 키워드 추출이 GPU를 쓰는 중이거나, GPU 상태가 바뀌는 중입니다. 끝난 뒤 다시 시도해주세요.';
  if (error.code === 'CONFLICT' && context === 'gpu-start') return 'GPU가 이미 켜져 있거나 상태가 바뀌는 중입니다. 잠시 후 상태를 확인해주세요.';
  if (error.code === 'FORBIDDEN' && context.startsWith('gpu')) return '탐지 서버에 GPU 켜기·끄기 권한이 없습니다. Detection IAM 역할 정책을 확인해주세요.';
  if (error.code === 'SERVER' && error.status === 502 && context.startsWith('gpu')) return 'AWS에 GPU 켜기·끄기를 요청하지 못했습니다. 잠시 후 다시 시도해주세요.';
  if (error.code === 'CONFLICT' && context === 'edit') return '이 문서에 같은 키워드가 이미 있거나, 그사이 승인된 키워드입니다. 목록을 새로고침해 주세요.';
  if (error.code === 'NOT_FOUND' && context === 'edit') return '이미 삭제된 키워드입니다. 목록을 새로고침해 주세요.';
  if (error.code === 'VALIDATION' && context === 'edit') return '키워드는 한 줄, 2~100자로 입력해주세요.';
  if (error.code === 'CONFLICT' && context === 'report') return '이미 만들고 있는 리포트가 있습니다. 끝난 뒤 다시 요청해주세요.';
  if (error.code === 'NOT_FOUND' && context === 'extract') return '색인이 끝나지 않은 문서입니다. 색인 완료 후 다시 요청해주세요.';
  if (error.code === 'VALIDATION' && context === 'report') return '기간을 확인해주세요. 시작일은 오늘 이전, 종료일은 시작일 이후, 최대 366일입니다.';
  if (error.code === 'CONFLICT' && context === 'keyword') return '이 문서에 이미 등록된 키워드입니다.';
  if (error.code === 'VALIDATION' && context === 'keyword') return '키워드는 한 줄, 2~100자로 입력해주세요.';
  if (error.code === 'SERVER' && error.status === 503) return '탐지 서버에 연결할 수 없습니다. 잠시 후 다시 시도해주세요.';
  if (error.code === 'UNAUTHORIZED') return '로그인이 만료되었습니다. 다시 로그인해주세요.';
  if (error.code === 'NETWORK') return '서버에 연결할 수 없습니다. 네트워크나 프록시 설정을 확인해주세요.';
  if (error.code === 'TIMEOUT') return '서버 응답 시간이 초과되었습니다. 다시 시도해주세요.';
  return '잠시 후 다시 시도해주세요.';
}
