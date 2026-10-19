/** 건수·개수 표기: 천 단위 쉼표(2026-10-16, 감사 1/4-13) */
export const formatCount = (value: number) => value.toLocaleString('ko-KR');

export function formatDateTime(value: string) {
  if (!Number.isFinite(Date.parse(value))) return '시각 미기록';
  return new Intl.DateTimeFormat('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone: 'Asia/Seoul',
    timeZoneName: 'short',
  }).format(new Date(value));
}

const shortParts = new Intl.DateTimeFormat('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'Asia/Seoul' });
/**
 * 표 안 짧은 시각(설계 4.5): 오늘이면 "08:53", 다른 날은 "10.12 21:04", 다른 해는 "2025.10.12 21:04"(서울 시각).
 * 연도·GMT+9 전체는 title(formatDateTime)로.
 */
export function formatShortDateTime(value: string, now: number = Date.now()) {
  if (!Number.isFinite(Date.parse(value))) return '시각 미기록';
  const parts = (at: number) => Object.fromEntries(shortParts.formatToParts(new Date(at)).map((part) => [part.type, part.value]));
  const at = parts(Date.parse(value));
  const today = parts(now);
  const time = `${at.hour}:${at.minute}`;
  if (at.year === today.year && at.month === today.month && at.day === today.day) return time;
  if (at.year === today.year) return `${at.month}.${at.day} ${time}`;
  return `${at.year}.${at.month}.${at.day} ${time}`;
}

export function formatBytes(bytes: number) {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function millisecondsToSeconds(milliseconds?: number) {
  return milliseconds !== undefined && Number.isFinite(milliseconds) && milliseconds >= 0
    ? milliseconds / 1000 : undefined;
}

export function formatDurationSeconds(seconds?: number) {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return '확인 불가';
  if (seconds > 0 && seconds < 0.01) return '0.01초 미만';
  return `${seconds.toLocaleString('ko-KR', {maximumFractionDigits:2})}초`;
}

export const formatProcessingTime = (milliseconds?: number) =>
  formatDurationSeconds(millisecondsToSeconds(milliseconds));
