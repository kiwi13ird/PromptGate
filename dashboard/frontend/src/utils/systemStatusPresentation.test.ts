import { describe, expect, it } from 'vitest';
import {
  PERMISSION_MISSING_TEXT,
  checkLabel,
  countByStatus,
  formatClock,
  formatDetailValue,
  instanceState,
  instancesNotices,
  rdsNotice,
  rdsState,
  roleLabel,
} from './systemStatusPresentation';

describe('system status presentation', () => {
  it('counts components per status', () => {
    expect(countByStatus([{ status: 'ok' }, { status: 'ok' }, { status: 'down' }, { status: 'unknown' }])).toEqual({ ok: 2, slow: 0, down: 1, unknown: 1 });
  });

  it('names the instance roles in Korean where the project already does', () => {
    expect([roleLabel('gateway'), roleLabel('detection'), roleLabel('dashboard'), roleLabel('gpu'), roleLabel('relay-x')]).toEqual(['Gateway', 'Detection', '대시보드', 'GPU', 'relay-x']);
  });

  it('colors EC2 states and treats a stopped GPU as expected rather than down', () => {
    expect(instanceState({ role: 'gateway', state: 'running' })).toEqual({ label: '실행 중', tone: 'ok' });
    expect(instanceState({ role: 'gateway', state: 'pending' }).tone).toBe('slow');
    expect(instanceState({ role: 'gateway', state: 'stopped' }).tone).toBe('down');
    expect(instanceState({ role: 'gpu', state: 'stopped' }).tone).toBe('unknown');
    expect(instanceState({ role: 'gpu', state: 'terminated' }).tone).toBe('down');
    expect(instanceState({ role: 'gateway', state: 'weird' })).toEqual({ label: 'weird', tone: 'unknown' });
  });

  it('translates status-check values and leaves missing ones as a dash', () => {
    expect(checkLabel('ok')).toBe('정상');
    expect(checkLabel('impaired')).toBe('이상');
    expect(checkLabel('insufficient-data')).toBe('데이터 부족');
    expect(checkLabel('new-value')).toBe('new-value');
    expect(checkLabel(null)).toBe('–');
    expect(checkLabel(undefined)).toBe('–');
  });

  it('maps RDS states to a tone', () => {
    expect(rdsState('available')).toEqual({ label: '사용 가능', tone: 'ok' });
    expect(rdsState('modifying').tone).toBe('slow');
    expect(rdsState('configuring-log-exports').tone).toBe('slow');
    expect(rdsState('storage-full').tone).toBe('down');
    expect(rdsState('incompatible-parameters').tone).toBe('down');
    expect(rdsState('something-new')).toEqual({ label: 'something-new', tone: 'unknown' });
    expect(rdsState(null)).toEqual({ label: '–', tone: 'unknown' });
  });

  it('picks AWS notices without inventing permission problems', () => {
    expect(instancesNotices({ ok: true, error: null, status_checks: 'ok', items: [] })).toEqual([]);
    expect(instancesNotices({ ok: true, error: null, status_checks: 'permission_missing', items: [] })).toEqual([{ kind: 'permission', text: PERMISSION_MISSING_TEXT }]);
    expect(instancesNotices({ ok: false, error: 'permission_missing', items: [] })).toEqual([{ kind: 'permission', text: PERMISSION_MISSING_TEXT }]);
    expect(instancesNotices({ ok: false, error: 'unavailable', items: [] })).toEqual([{ kind: 'error', text: 'AWS에서 인스턴스 정보를 받지 못했습니다.' }]);
    expect(rdsNotice({ ok: true, error: null })).toBeNull();
    expect(rdsNotice({ ok: false, error: 'permission_missing' })).toEqual({ kind: 'permission', text: PERMISSION_MISSING_TEXT });
    expect(rdsNotice({ ok: false, error: 'not_configured' })?.kind).toBe('error');
    expect(rdsNotice({ ok: false, error: 'unavailable' })?.text).toBe('AWS에서 RDS 정보를 받지 못했습니다.');
  });

  it('formats clock times in KST and tolerates missing values', () => {
    expect(formatClock('2026-10-12T03:00:00Z')).toBe('12:00:00');
    expect(formatClock('2026-10-12T15:30:05+00:00')).toBe('00:30:05');
    expect(formatClock(null)).toBe('–');
    expect(formatClock('not a time')).toBe('–');
  });

  it('formats detail values into plain Korean text', () => {
    expect(formatDetailValue(null)).toBe('–');
    expect(formatDetailValue('')).toBe('–');
    expect(formatDetailValue(true)).toBe('예');
    expect(formatDetailValue(false)).toBe('아니오');
    expect(formatDetailValue(1234567)).toBe('1,234,567');
    expect(formatDetailValue(0)).toBe('0');
    expect(formatDetailValue(Number.NaN)).toBe('–');
    expect(formatDetailValue('v22.13.0')).toBe('v22.13.0');
    expect(formatDetailValue(['10.0.0.1', '10.0.0.2'])).toBe('10.0.0.1, 10.0.0.2');
    expect(formatDetailValue([])).toBe('–');
    expect(formatDetailValue({ a: 1 })).toBe('{"a":1}');
    expect(formatDetailValue('2026-10-12T02:59:52Z')).toBe('2026-10-12 11:59:52 KST');
    expect(formatDetailValue('2026-10-12T15:00:00+00:00')).toBe('2026-10-13 00:00:00 KST');
    expect(formatDetailValue('2026-10-12')).toBe('2026-10-12');   // 날짜만 있는 값은 그대로
  });
});
