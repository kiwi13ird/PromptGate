// Gateway 처리 설정(2026-10-10) - 검사 지연 시 처리 · 검사할 수 없는 파일 처리 · 허용 알림.
// 계약: 명세 §1.1(설정 문서) · §3.1(GET /api/gateway-settings) · §3.2(PUT, expected_version). 응답은 어댑터가 zod로 확인한다.
import { gatewayApi } from '@/src/api';
import { ApiError } from '@/src/api/errors';
import type {
  GatewayApplyStatus,
  GatewaySettingsDocument,
  GatewaySettingsResponse,
  GatewaySettingsValues,
} from '@/src/api/gatewaySettingsSchemas';
import { WAIT_SECONDS_MAX, WAIT_SECONDS_MIN } from '@/src/api/gatewaySettingsSchemas';
import { safeMessage } from '@/src/utils/feedback';
import { formatSeconds, settingsFieldText } from '@/src/utils/gatewaySettingsText';

export {
  gatewayApplyStateSchema,
  gatewayApplyStatusSchema,
  gatewaySettingsDocumentSchema,
  gatewaySettingsResponseSchema,
  gatewaySettingsSaveBodySchema,
  gatewaySettingsValuesSchema,
  WAIT_SECONDS_MAX,
  WAIT_SECONDS_MIN,
} from '@/src/api/gatewaySettingsSchemas';
export type {
  GatewayApplyState,
  GatewayApplyStatus,
  GatewaySettingsDocument,
  GatewaySettingsResponse,
  GatewaySettingsSaveBody,
  GatewaySettingsValues,
} from '@/src/api/gatewaySettingsSchemas';

export const gatewaySettingsKeys = {
  all: ['gateway-settings'] as const,
  detail: () => ['gateway-settings', 'detail'] as const,
};

export const gatewaySettingsService = {
  get(signal?: AbortSignal): Promise<GatewaySettingsResponse> {
    return gatewayApi.getGatewaySettings(signal);
  },
  /** expectedVersion: 편집을 시작한 설정 번호. 그사이 다른 저장이 있으면 서버가 409로 거부한다. */
  save(values: GatewaySettingsValues, expectedVersion: number, signal?: AbortSignal): Promise<GatewaySettingsResponse> {
    return gatewayApi.saveGatewaySettings(
      {
        expected_version: expectedVersion,
        timeout: values.timeout,
        uninspectable: values.uninspectable,
        notify_on_allow: values.notify_on_allow,
      },
      signal,
    );
  },
};

export const SETTINGS_CONFLICT_MESSAGE = '다른 관리자가 먼저 바꿨습니다. 최신 값을 확인하세요.';
export const SETTINGS_UNAVAILABLE_MESSAGE = '설정을 아직 불러오지 못했습니다. 잠시 후 다시 시도하세요.';

export const isSettingsConflict = (error: unknown) => error instanceof ApiError && error.code === 'CONFLICT';
export const isSettingsUnavailable = (error: unknown) => error instanceof ApiError && error.status === 503;

/** 저장·조회 실패 문구. 서버 오류 코드를 그대로 보이지 않는다. */
export function gatewaySettingsErrorMessage(error: unknown): string {
  if (isSettingsConflict(error)) return SETTINGS_CONFLICT_MESSAGE;
  if (isSettingsUnavailable(error)) return SETTINGS_UNAVAILABLE_MESSAGE;
  if (error instanceof ApiError && error.code === 'VALIDATION') return '저장할 수 없는 값입니다. 입력 값을 확인하세요.';
  return safeMessage(error);
}

/** 조회 실패 문구: 서버가 설정을 아직 못 읽었으면(503) 명세 문구, 그 밖은 공통 안내 */
export function gatewaySettingsLoadMessage(error: unknown): string {
  if (isSettingsUnavailable(error)) return SETTINGS_UNAVAILABLE_MESSAGE;
  return `설정을 불러오지 못했습니다. ${safeMessage(error)}`;
}

const seoulParts = (value: string) => {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).formatToParts(new Date(value));
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find(item => item.type === type)?.value ?? '';
  return { date: `${part('year')}-${part('month')}-${part('day')}`, minute: `${part('hour')}:${part('minute')}`, second: `${part('hour')}:${part('minute')}:${part('second')}` };
};
const validTime = (value?: string | null): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));
/** 2026-10-10 14:12 (한국 시각) */
export const formatSavedAt = (value?: string | null) => (validTime(value) ? `${seoulParts(value).date} ${seoulParts(value).minute}` : '시각 미기록');
/** 14:12:07 (한국 시각) */
export const formatClock = (value?: string | null) => (validTime(value) ? seoulParts(value).second : '시각 미기록');

/** 상태 줄 첫째 줄: 저장된 설정 */
export function savedSettingsText(settings: GatewaySettingsDocument): string {
  if (settings.source === 'DEFAULT') return '저장된 설정 없음 · 기본값으로 동작';
  return `저장 v${settings.version} · ${formatSavedAt(settings.updated_at)} · ${settings.updated_by}`;
}

export type GatewayStateTone = 'ok' | 'pending' | 'warn';

/** 상태 줄 둘째 줄: Gateway 반영 상태(명세 §3.1 여섯 가지) */
export function gatewayStateText(gateway: GatewayApplyStatus): { tone: GatewayStateTone; text: string } {
  switch (gateway.state) {
    case 'APPLIED': {
      const checked = gateway.first_seen_at ? ` · 확인 ${formatClock(gateway.first_seen_at)}` : '';
      if (gateway.applied_source === 'ENV_DEFAULT') return { tone: 'ok', text: `Gateway 반영 · 기본값${checked}` };
      const clock = validTime(gateway.applied_at) ? ` · Gateway 시각 ${formatClock(gateway.applied_at)}` : '';   // Gateway가 시각을 보내지 않으면 뺀다
      return { tone: 'ok', text: `Gateway 반영 v${gateway.applied_version ?? '?'}${clock}${checked}` };
    }
    case 'PENDING': {
      const running = gateway.applied_source === 'ENV_DEFAULT' ? ' · Gateway 현재 기본값'
        : gateway.applied_version ? ` · Gateway 현재 v${gateway.applied_version}` : '';
      return { tone: 'pending', text: `Gateway 반영 대기 중${running}` };
    }
    case 'REJECTED':
      return { tone: 'warn', text: `Gateway가 이 설정을 거부함${gateway.rejected ? ` · 거부한 칸 ${settingsFieldText(gateway.rejected.field)}` : ''}` };
    case 'NOT_REPORTING':
      return { tone: 'warn', text: 'Gateway 응답 없음 · 마지막으로 받은 설정으로 동작 중' };
    case 'LEGACY_GATEWAY':
      return { tone: 'warn', text: 'Gateway가 설정 반영을 지원하지 않는 판(또는 첫 응답 전, 최대 10초)' };
    case 'REPORT_INVALID':
      return { tone: 'warn', text: 'Gateway 보고 형식 오류 · 반영 여부 확인 불가' };
  }
}

/** 화면 입력 칸 값(문자열)으로 바꾼 설정 */
export interface GatewaySettingsDraft {
  promptAction: 'block' | 'forward';
  promptSeconds: string;
  fileAction: 'block' | 'forward';
  fileSeconds: string;
  image: 'block' | 'allow';
  scannedPdf: 'block' | 'allow';
  other: 'block' | 'allow';
  notifyOnAllow: boolean;
}

export function toDraft(values: GatewaySettingsValues): GatewaySettingsDraft {
  return {
    promptAction: values.timeout.prompt.action,
    promptSeconds: formatSeconds(values.timeout.prompt.seconds),
    fileAction: values.timeout.file.action,
    fileSeconds: formatSeconds(values.timeout.file.seconds),
    image: values.uninspectable.image,
    scannedPdf: values.uninspectable.scanned_pdf,
    other: values.uninspectable.other,
    notifyOnAllow: values.notify_on_allow,
  };
}

/** 대기 시간 입력 확인: 0.05~30초, 소수 자리 제한 없음. 틀리면 null */
export function parseWaitSeconds(text: string): number | null {
  if (!text.trim()) return null;
  const value = Number(text);
  return Number.isFinite(value) && value >= WAIT_SECONDS_MIN && value <= WAIT_SECONDS_MAX ? value : null;
}

export function fromDraft(draft: GatewaySettingsDraft): GatewaySettingsValues | null {
  const promptSeconds = parseWaitSeconds(draft.promptSeconds);
  const fileSeconds = parseWaitSeconds(draft.fileSeconds);
  if (promptSeconds === null || fileSeconds === null) return null;
  return {
    timeout: {
      prompt: { action: draft.promptAction, seconds: promptSeconds },
      file: { action: draft.fileAction, seconds: fileSeconds },
    },
    uninspectable: { image: draft.image, scanned_pdf: draft.scannedPdf, other: draft.other },
    notify_on_allow: draft.notifyOnAllow,
  };
}
