// 리포트 기간 계산(2026-10-12 설계 v2/v1 3.6). 날짜는 한국 날짜 문자열(YYYY-MM-DD)만 다룬다.
// 시간대 변환은 kstDate 한 곳, 나머지는 UTC 날짜 계산이라 실행 PC의 시간대와 무관하다.

const DAY_MS = 86_400_000;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

export type PeriodPreset = 'LAST_7_DAYS' | 'LAST_30_DAYS' | 'THIS_MONTH' | 'LAST_MONTH';
export const PERIOD_PRESETS: ReadonlyArray<{ code: PeriodPreset; label: string }> = [
  { code: 'LAST_7_DAYS', label: '지난 7일' },
  { code: 'LAST_30_DAYS', label: '지난 30일' },
  { code: 'THIS_MONTH', label: '이번 달' },
  { code: 'LAST_MONTH', label: '지난달' },
];

/** 한국 시각 기준 YYYY-MM-DD. offsetDays는 오늘 기준 일수 */
export function kstDate(offsetDays = 0, now = Date.now()): string {
  const date = new Date(now + offsetDays * DAY_MS);
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit' }).format(date);
}

function parse(date: string): number | null {
  const match = DATE.exec(date);
  if (!match) return null;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const ms = Date.UTC(year, month - 1, day);
  const check = new Date(ms);
  // 2026-02-31 같은 날짜는 넘어간 날로 바뀌므로 걸러낸다
  return check.getUTCFullYear() === year && check.getUTCMonth() === month - 1 && check.getUTCDate() === day ? ms : null;
}

const format = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** 날짜에 일수를 더한다(음수 가능). 잘못된 날짜면 null */
export function shiftDate(date: string, days: number): string | null {
  const ms = parse(date);
  return ms === null ? null : format(ms + days * DAY_MS);
}

/** 시작일·종료일을 모두 포함한 일수. 날짜가 잘못됐거나 종료일이 앞서면 null */
export function periodDays(from: string, to: string): number | null {
  const [start, end] = [parse(from), parse(to)];
  if (start === null || end === null || end < start) return null;
  return Math.round((end - start) / DAY_MS) + 1;
}

/** 기간 바로 고르기. today는 한국 날짜(기본: 지금) */
export function presetPeriod(code: PeriodPreset, today = kstDate()): { from: string; to: string } {
  switch (code) {
    case 'LAST_7_DAYS':
      return { from: shiftDate(today, -6) ?? today, to: today };
    case 'LAST_30_DAYS':
      return { from: shiftDate(today, -29) ?? today, to: today };
    case 'THIS_MONTH':
      return { from: `${today.slice(0, 8)}01`, to: today };
    case 'LAST_MONTH': {
      const firstOfThis = `${today.slice(0, 8)}01`;
      const last = shiftDate(firstOfThis, -1) ?? today;
      return { from: `${last.slice(0, 8)}01`, to: last };
    }
  }
}

/** 비교 기간: 바로 앞의 같은 길이(직전 기간). Detection이 쓰는 기준과 같다 */
export function comparePeriod(from: string, to: string): { from: string; to: string } | null {
  const days = periodDays(from, to);
  if (days === null) return null;
  const end = shiftDate(from, -1);
  const start = end === null ? null : shiftDate(end, -(days - 1));
  return start && end ? { from: start, to: end } : null;
}

/** 9/19~9/30. 두 날짜가 기준 연도(기본: 종료일의 해)와 다르면 연도까지 적는다 */
export function formatPeriodRange(from: string, to: string, anchorYear = to.slice(0, 4)): string {
  const short = (date: string) => `${Number(date.slice(5, 7))}/${Number(date.slice(8, 10))}`;
  return from.slice(0, 4) === anchorYear && to.slice(0, 4) === anchorYear ? `${short(from)}~${short(to)}` : `${from}~${to}`;
}
