import { describe, expect, it } from 'vitest';
import type { SecurityEvent } from '@/src/types/event';
import { inspectionFailure } from './eventPresentation';
import { hasReasonLabel, isNoResponseReason, isUninspectedReason, reasonLabel } from './reasonLabels';

// 판정 사유 이름표(2026-10-10, 명세 §8.2) - 내 요청 기록과 관리자 화면이 같이 쓴다
describe('reason labels', () => {
  it.each([
    ['file_uninspectable_image', '검사할 수 없는 파일(이미지)'],
    ['file_uninspectable_scanned_pdf', '검사할 수 없는 파일(스캔 PDF)'],
    ['file_uninspectable_other', '검사할 수 없는 파일 형식'],
    ['file_too_large', '파일이 커서 검사하지 못함'],
    ['mask_application_failed', '마스킹할 수 없음'],
    ['file_masking_failed', '마스킹 처리 실패'],
    ['detection_timeout', '보안 검사 응답 없음'],
    ['detection_unreachable', '보안 검사 응답 없음'],
    ['detection_error', '보안 검사 응답 없음'],
    ['detection_parse_error', '보안 검사 응답 없음'],
  ])('%s', (code, label) => {
    expect(hasReasonLabel(code)).toBe(true);
    expect(reasonLabel(code)).toBe(label);
  });

  it('leaves an unknown code as it is', () => {
    for (const code of ['pii', 'doc_excerpt', 'some_new_code', 'toString', 'constructor']) {
      expect(hasReasonLabel(code)).toBe(false);
      expect(reasonLabel(code)).toBe(code);
    }
    expect(hasReasonLabel(undefined)).toBe(false);
    expect(hasReasonLabel(null)).toBe(false);
  });

  it('separates not inspected from no response', () => {
    expect(['file_uninspectable_image', 'file_uninspectable_scanned_pdf', 'file_uninspectable_other', 'file_too_large'].every(isUninspectedReason)).toBe(true);
    expect(['detection_timeout', 'detection_unreachable', 'detection_error', 'detection_parse_error'].every(isNoResponseReason)).toBe(true);
    expect(isUninspectedReason('detection_timeout')).toBe(false);
    expect(isNoResponseReason('file_too_large')).toBe(false);
    expect(isUninspectedReason('mask_application_failed') || isNoResponseReason('mask_application_failed')).toBe(false);
  });
});

describe('admin inspection failure text', () => {
  const base: SecurityEvent = { eventId: 'evt-1', occurredAt: '2026-10-10T05:00:00Z', clientId: 'test', targetLlm: 'ChatGPT', detectionOutcome: 'UNAVAILABLE', finalAction: 'BLOCK', status: 'NEW', detections: [], adminNotes: [], timeline: [], degraded: false };

  it('names the reason for a file that was not inspected instead of "원인 미기록 · 장애 정책 미기록"', () => {
    expect(inspectionFailure({ ...base, reasonCode: 'file_uninspectable_scanned_pdf' })).toEqual({ action: '검사 불가 · 차단', detail: '검사할 수 없는 파일(스캔 PDF)' });
    expect(inspectionFailure({ ...base, finalAction: 'ALLOW', reasonCode: 'file_uninspectable_image' })).toEqual({ action: '검사 불가 · 허용', detail: '검사할 수 없는 파일(이미지)' });
    expect(inspectionFailure({ ...base, finalAction: 'ALLOW', reasonCode: 'file_too_large' })).toEqual({ action: '검사 불가 · 허용', detail: '파일이 커서 검사하지 못함' });
  });

  it('keeps the recorded cause and failure policy for a degraded inspection', () => {
    expect(inspectionFailure({ ...base, degraded: true, degradedReason: 'TIMEOUT', failurePolicy: 'FAIL_CLOSED', reasonCode: 'detection_timeout' })?.detail).toBe('시간 초과 · 장애 시 차단');
    expect(inspectionFailure({ ...base, degraded: true, failurePolicy: 'FAIL_OPEN', finalAction: 'ALLOW', reasonCode: 'detection_unreachable' })?.detail).toBe('보안 검사 응답 없음 · 장애 시 허용');
    expect(inspectionFailure({ ...base })?.detail).toBe('원인 미기록 · 장애 정책 미기록');
    expect(inspectionFailure({ ...base, detectionOutcome: 'MATCH' })).toBeUndefined();
  });
});
