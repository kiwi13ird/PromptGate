import { describe, expect, it } from 'vitest';
import { comparePeriod, formatPeriodRange, kstDate, periodDays, presetPeriod, shiftDate } from './reportPeriod';

// 기간 계산은 날짜 문자열만 쓴다. 한국 날짜 경계와 달·해·윤년 경계가 틀리면 보고서 기간과 비교 기간이 하루씩 어긋난다.

describe('kstDate', () => {
  it('uses the Korean calendar day, not the UTC day', () => {
    expect(kstDate(0, Date.parse('2026-10-11T14:59:59Z'))).toBe('2026-10-11');   // 한국 23:59:59
    expect(kstDate(0, Date.parse('2026-10-11T15:00:00Z'))).toBe('2026-10-12');   // 한국 00:00:00
    expect(kstDate(-6, Date.parse('2026-10-12T00:30:00Z'))).toBe('2026-10-06');
    expect(kstDate(1, Date.parse('2026-12-31T20:00:00Z'))).toBe('2027-01-02');
  });
});

describe('shiftDate / periodDays', () => {
  it('moves across month, year and leap-day boundaries', () => {
    expect(shiftDate('2026-03-01', -1)).toBe('2026-02-28');
    expect(shiftDate('2028-03-01', -1)).toBe('2028-02-29');
    expect(shiftDate('2026-01-01', -1)).toBe('2025-12-31');
    expect(shiftDate('2026-12-31', 1)).toBe('2027-01-01');
    expect(shiftDate('2026-10-12', 0)).toBe('2026-10-12');
  });
  it('rejects dates that do not exist or are not written as YYYY-MM-DD', () => {
    for (const bad of ['', '2026-02-30', '2026-13-01', '2026-1-5', '26-10-12', '2026/10/12', '2026-10-12T00:00']) {
      expect(shiftDate(bad, 1), bad).toBeNull();
      expect(periodDays(bad, '2026-10-12'), bad).toBeNull();
    }
  });
  it('counts both ends and refuses a reversed period', () => {
    expect(periodDays('2026-10-12', '2026-10-12')).toBe(1);
    expect(periodDays('2026-10-06', '2026-10-12')).toBe(7);
    expect(periodDays('2026-02-01', '2026-03-01')).toBe(29);
    expect(periodDays('2028-02-01', '2028-03-01')).toBe(30);
    expect(periodDays('2026-10-12', '2026-10-11')).toBeNull();
  });
});

describe('presetPeriod', () => {
  it('last 7 and 30 days end today and include it', () => {
    expect(presetPeriod('LAST_7_DAYS', '2026-10-12')).toEqual({ from: '2026-10-06', to: '2026-10-12' });
    expect(presetPeriod('LAST_30_DAYS', '2026-10-12')).toEqual({ from: '2026-09-13', to: '2026-10-12' });
    expect(periodDays(...Object.values(presetPeriod('LAST_7_DAYS', '2026-10-12')) as [string, string])).toBe(7);
    expect(periodDays(...Object.values(presetPeriod('LAST_30_DAYS', '2026-10-12')) as [string, string])).toBe(30);
  });
  it('this month runs from the 1st to today, also on the 1st itself', () => {
    expect(presetPeriod('THIS_MONTH', '2026-10-12')).toEqual({ from: '2026-10-01', to: '2026-10-12' });
    expect(presetPeriod('THIS_MONTH', '2026-10-01')).toEqual({ from: '2026-10-01', to: '2026-10-01' });
  });
  it('last month covers the whole previous month, including 28/29/30/31 days and January', () => {
    expect(presetPeriod('LAST_MONTH', '2026-10-12')).toEqual({ from: '2026-09-01', to: '2026-09-30' });
    expect(presetPeriod('LAST_MONTH', '2026-03-05')).toEqual({ from: '2026-02-01', to: '2026-02-28' });
    expect(presetPeriod('LAST_MONTH', '2028-03-05')).toEqual({ from: '2028-02-01', to: '2028-02-29' });
    expect(presetPeriod('LAST_MONTH', '2026-01-15')).toEqual({ from: '2025-12-01', to: '2025-12-31' });
    expect(presetPeriod('LAST_MONTH', '2026-11-01')).toEqual({ from: '2026-10-01', to: '2026-10-31' });
  });
});

describe('comparePeriod', () => {
  it('is the same-length period right before, with no gap and no overlap', () => {
    expect(comparePeriod('2026-10-06', '2026-10-12')).toEqual({ from: '2026-09-29', to: '2026-10-05' });
    expect(comparePeriod('2026-10-01', '2026-10-12')).toEqual({ from: '2026-09-19', to: '2026-09-30' });
    expect(comparePeriod('2026-09-01', '2026-09-30')).toEqual({ from: '2026-08-02', to: '2026-08-31' });
    expect(comparePeriod('2026-10-12', '2026-10-12')).toEqual({ from: '2026-10-11', to: '2026-10-11' });
  });
  it('keeps the length across a year change and a leap day', () => {
    expect(comparePeriod('2026-01-01', '2026-01-10')).toEqual({ from: '2025-12-22', to: '2025-12-31' });
    expect(comparePeriod('2028-03-01', '2028-03-10')).toEqual({ from: '2028-02-20', to: '2028-02-29' });
    for (const [from, to] of [['2026-10-06', '2026-10-12'], ['2026-01-01', '2026-01-10'], ['2028-03-01', '2028-03-10'], ['2026-02-01', '2026-03-31']]) {
      const previous = comparePeriod(from, to)!;
      expect(periodDays(previous.from, previous.to)).toBe(periodDays(from, to));
      expect(shiftDate(previous.to, 1)).toBe(from);
    }
  });
  it('gives nothing for an unusable period', () => {
    expect(comparePeriod('', '2026-10-12')).toBeNull();
    expect(comparePeriod('2026-10-12', '2026-10-06')).toBeNull();
    expect(comparePeriod('2026-02-30', '2026-03-05')).toBeNull();
  });
});

describe('formatPeriodRange', () => {
  it('writes month/day inside the anchor year and the full date otherwise', () => {
    expect(formatPeriodRange('2026-09-19', '2026-09-30')).toBe('9/19~9/30');
    expect(formatPeriodRange('2026-09-29', '2026-10-05')).toBe('9/29~10/5');
    expect(formatPeriodRange('2025-12-22', '2025-12-31', '2026')).toBe('2025-12-22~2025-12-31');
    expect(formatPeriodRange('2025-12-22', '2026-01-02')).toBe('2025-12-22~2026-01-02');
  });
});
