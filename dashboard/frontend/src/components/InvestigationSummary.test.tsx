import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { InvestigationSummary } from './InvestigationSummary';
import type { SecurityEvent } from '@/src/types/event';

const event: SecurityEvent = { eventId: 'evt-summary', occurredAt: '2026-10-05T00:00:00Z', clientId: 'client', targetLlm: 'ChatGPT', status: 'NEW', detectionOutcome: 'MATCH', finalAction: 'BLOCK', detections: [{ detector: 'WINDOW_HASH', matchType: 'TEXT_FRAGMENT', score: 0.882, scoreKind: 'COVERAGE', matchedDocumentId: 'doc/#1', matchedDocumentName: '공정 문서', documentSpan: { charStart: 10, charEnd: 50, endExclusive: true } }], adminNotes: [], timeline: [] };
const view = (value: SecurityEvent) => render(<MemoryRouter><InvestigationSummary event={value} /></MemoryRouter>);
describe('V3.1 result-first summary with no invented execution', () => {
  it('prioritizes the recorded result, reason and encoded document without fabricating a policy', () => {
    view(event);
    expect(screen.getByRole('region', { name: '사건 핵심 요약' })).toHaveAttribute('data-action', 'block');
    expect(screen.getByText('차단', { selector: '.investigation-result strong' })).toBeInTheDocument();
    expect(screen.queryByText('BLOCK')).toBeNull();   // 영문 코드는 화면에 그대로 내보내지 않는다
    expect(screen.getByText('문서 구간 검사')).toBeInTheDocument();   // 탐지 방식도 한글 이름
    expect(screen.getByRole('heading', { name: '보호 문서 구간 일치' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '공정 문서' })).toHaveAttribute('href', '/documents/doc%2F%231');
    expect(screen.getByText('집행 확인 기록 없음')).toBeInTheDocument();
    expect(screen.queryByText('전송 차단 집행 확인')).toBeNull();
    expect(screen.queryByText('기록 정책')).toBeNull();
    expect(screen.queryByText(/위험 점수|서버 정상|안전/)).toBeNull();
  });
  it('distinguishes a recorded decision from explicitly unexecuted blocking', () => {
    view({ ...event, enforcement: { applied: false } });
    expect(screen.getByText('미집행 기록')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: '사건 핵심 요약' })).toHaveAttribute('data-enforcement', 'not-applied');
    expect(screen.queryByText('전송 차단 집행 확인')).toBeNull();
  });
  it('shows confirmed block execution only when its real flag is set', () => {
    view({ ...event, enforcement: { applied: true, httpStatus: 403 } });
    expect(screen.getByText('전송 차단 집행 확인')).toBeInTheDocument();
    expect(screen.getByText('기록된 HTTP 403')).toBeInTheDocument();
  });
  it('shows actual PII types/counts and recorded policy for masking, never document similarity or receipt', () => {
    view({ ...event, finalAction: 'MASK', policyVersion: 'v2', enforcement: { applied: true }, detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', policyId: 'policy/#1', entityCounts: [{ entityType: 'KR_PHONE_NUMBER', count: 1 }] }] });
    expect(screen.getByText('마스킹', { selector: '.investigation-result strong' })).toBeInTheDocument();
    expect(screen.queryByText('MASK')).toBeNull();
    expect(screen.getByRole('heading', { name: '민감정보 패턴 탐지' })).toBeInTheDocument();
    expect(screen.getByText('전화번호 1개가 탐지된 요청입니다.')).toBeInTheDocument();
    expect(screen.getByText('마스킹 집행 확인')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'policy/#1' })).toHaveAttribute('href', '/policies?policyId=policy%2F%231');
    expect(screen.queryByText('연결 문서')).toBeNull();
    expect(screen.queryByText(/유사도|전송 성공|답변 완료/)).toBeNull();
  });
  it('never treats fail-open allowance as safe and makes the failed inspection explicit', () => {
    view({ ...event, finalAction: 'ALLOW', detectionOutcome: 'UNAVAILABLE', degraded: true, failurePolicy: 'FAIL_OPEN', detections: [] });
    const summary = screen.getByRole('region', { name: '사건 핵심 요약' });
    expect(summary).toHaveAttribute('data-inspection', 'unavailable');
    expect(within(summary).getByRole('heading', { name: '입력 검사 결과 확인 불가' })).toBeInTheDocument();
    expect(screen.getByText('검사 불가 · 허용')).toHaveClass('inspection-failure');
    expect(screen.queryByText('일치한 문서·민감정보 없음')).toBeNull();
  });
});
