// 시스템 상태 화면의 문구·표시 규칙. 상태 판정은 백엔드가 하고, 여기서는 받은 값을 한국어로 바꿔 보여 주기만 한다.
import type { ComponentStatus, SystemInstance, SystemInstances, SystemRds } from '@/src/services/systemStatusService';

export const REFRESH_INTERVAL_MS = 15_000;

export const STATUS_LABEL: Record<ComponentStatus, string> = {
  ok: '정상',
  slow: '느림',
  down: '끊김',
  unknown: '확인 불가',
};
export const STATUS_ORDER: ComponentStatus[] = ['ok', 'slow', 'down', 'unknown'];

export const PERMISSION_MISSING_TEXT = '권한이 없어 조회하지 못했습니다(IAM 정책 추가 필요)';
export const NO_VALUE = '–';

export function countByStatus(components: { status: ComponentStatus }[]): Record<ComponentStatus, number> {
  const counts: Record<ComponentStatus, number> = { ok: 0, slow: 0, down: 0, unknown: 0 };
  for (const component of components) counts[component.status] += 1;
  return counts;
}

const ROLE_LABEL: Record<string, string> = {
  gateway: 'Gateway',
  detection: 'Detection',
  dashboard: '대시보드',
  gpu: 'GPU',
};
export const roleLabel = (role: string) => ROLE_LABEL[role] ?? role;

// EC2 인스턴스 상태 → 표시 문구와 칩 색
const INSTANCE_STATE: Record<string, { label: string; tone: ComponentStatus }> = {
  running: { label: '실행 중', tone: 'ok' },
  pending: { label: '시작 중', tone: 'slow' },
  stopping: { label: '중지 중', tone: 'slow' },
  'shutting-down': { label: '종료 중', tone: 'slow' },
  stopped: { label: '중지됨', tone: 'down' },
  terminated: { label: '종료됨', tone: 'down' },
};
export function instanceState(instance: Pick<SystemInstance, 'role' | 'state'>): { label: string; tone: ComponentStatus } {
  const known = INSTANCE_STATE[instance.state];
  if (!known) return { label: instance.state || NO_VALUE, tone: 'unknown' };
  // GPU는 리포트·키워드 추출 때만 켜는 서버라 꺼져 있는 것이 정상 상태다
  if (instance.role === 'gpu' && instance.state === 'stopped') return { label: known.label, tone: 'unknown' };
  return known;
}

// describe_instance_status 값: system_status·instance_status
const CHECK_LABEL: Record<string, string> = {
  ok: '정상',
  impaired: '이상',
  initializing: '초기화 중',
  'insufficient-data': '데이터 부족',
  'not-applicable': '해당 없음',
};
export const checkLabel = (value?: string | null) => (value ? (CHECK_LABEL[value] ?? value) : NO_VALUE);

// RDS DBInstanceStatus → 표시 문구와 칩 색. 목록에 없는 값은 원문 그대로 '확인 불가'
const RDS_OK = new Set(['available', 'backing-up']);
const RDS_DOWN = new Set(['failed', 'stopped', 'storage-full', 'inaccessible-encryption-credentials', 'restore-error']);
const RDS_SLOW = new Set(['starting', 'stopping', 'modifying', 'rebooting', 'upgrading', 'maintenance', 'renaming', 'creating', 'storage-optimization']);
const RDS_LABEL: Record<string, string> = {
  available: '사용 가능',
  'backing-up': '백업 중',
  failed: '실패',
  stopped: '중지됨',
  stopping: '중지 중',
  starting: '시작 중',
  modifying: '변경 중',
  rebooting: '재부팅 중',
  upgrading: '업그레이드 중',
  maintenance: '점검 중',
  'storage-full': '저장 공간 부족',
};
export function rdsState(status?: string | null): { label: string; tone: ComponentStatus } {
  if (!status) return { label: NO_VALUE, tone: 'unknown' };
  const label = RDS_LABEL[status] ?? status;
  if (RDS_OK.has(status)) return { label, tone: 'ok' };
  if (RDS_DOWN.has(status) || status.startsWith('incompatible-')) return { label, tone: 'down' };
  if (RDS_SLOW.has(status) || status.startsWith('configuring-')) return { label, tone: 'slow' };
  return { label, tone: 'unknown' };
}

export type AwsNotice = { kind: 'permission' | 'error'; text: string };

/** EC2 목록 위에 보일 안내. 목록을 못 받았거나(error), 상태 점검 권한만 없을 때(status_checks). */
export function instancesNotices(instances: SystemInstances): AwsNotice[] {
  const notices: AwsNotice[] = [];
  if (instances.error === 'permission_missing') notices.push({ kind: 'permission', text: PERMISSION_MISSING_TEXT });
  else if (instances.error) notices.push({ kind: 'error', text: 'AWS에서 인스턴스 정보를 받지 못했습니다.' });
  if (instances.status_checks === 'permission_missing' && instances.error !== 'permission_missing')
    notices.push({ kind: 'permission', text: PERMISSION_MISSING_TEXT });
  return notices;
}

export function rdsNotice(rds: SystemRds): AwsNotice | null {
  if (rds.error === 'permission_missing') return { kind: 'permission', text: PERMISSION_MISSING_TEXT };
  if (rds.error === 'not_configured') return { kind: 'error', text: 'RDS 식별자가 설정되지 않아 조회하지 않았습니다.' };
  if (rds.error) return { kind: 'error', text: 'AWS에서 RDS 정보를 받지 못했습니다.' };
  return null;
}

const kstSeconds = new Intl.DateTimeFormat('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone: 'Asia/Seoul' });
const kstParts = new Intl.DateTimeFormat('ko-KR', {
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  hourCycle: 'h23', timeZone: 'Asia/Seoul',
});
/** 2026-10-12 11:59:52 KST - 브라우저마다 다른 한국어 날짜 서식 대신 고정 모양으로 */
const kstFull = {
  format(date: Date) {
    const part = Object.fromEntries(kstParts.formatToParts(date).map(({ type, value }) => [type, value]));
    return `${part.year}-${part.month}-${part.day} ${part.hour}:${part.minute}:${part.second} KST`;
  },
};
const isValidTime = (value?: string | null): value is string => Boolean(value) && Number.isFinite(Date.parse(value as string));

/** 표 칸에 보일 시각(한국 시각, 초 단위). 값이 없으면 '–' */
export const formatClock = (value?: string | null) => (isValidTime(value) ? kstSeconds.format(new Date(value)) : NO_VALUE);
/** 마우스를 올리면 보이는 정확한 시각 */
export const formatExactTime = (value?: string | null) => (isValidTime(value) ? kstFull.format(new Date(value)) : '시각 미기록');

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/;

/** 세부 정보 값을 한 줄 문구로. 시각은 한국 시각으로, 참/거짓은 예/아니오로 바꾼다. */
export function formatDetailValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return NO_VALUE;
  if (typeof value === 'boolean') return value ? '예' : '아니오';
  if (typeof value === 'number') return Number.isFinite(value) ? value.toLocaleString('ko-KR', { maximumFractionDigits: 3 }) : NO_VALUE;
  if (typeof value === 'string') return ISO_TIME.test(value) && isValidTime(value) ? kstFull.format(new Date(value)) : value;
  if (Array.isArray(value)) return value.length ? value.map(formatDetailValue).join(', ') : NO_VALUE;
  try {
    return JSON.stringify(value);
  } catch {
    return NO_VALUE;
  }
}
