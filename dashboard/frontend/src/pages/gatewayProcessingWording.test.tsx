// Gateway 처리 시간 문구(2026-10-11): processingMs는 Gateway 자체 처리분(LLM 응답 시간 제외), 이전 기록은 백엔드가 값을 빼고 보낸다
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EventDetailPage } from './EventDetailPage';
import { TrafficPerformancePage } from './TrafficPerformancePage';
import { eventService } from '@/src/services/eventService';
import { evidenceService } from '@/src/services/evidenceService';
import { trafficService } from '@/src/services/trafficService';
import type { SecurityEvent } from '@/src/types/event';
import type { TrafficSnapshot } from '@/src/types/traffic';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));

const client = () => new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
const event = (over: Partial<SecurityEvent> = {}): SecurityEvent => ({
  eventId: 'evt-gw-time', requestId: 'req-gw-time', clientId: 'chrome-gw-time', occurredAt: '2026-10-11T06:00:00Z', targetLlm: 'ChatGPT',
  finalAction: 'BLOCK', recommendedAction: 'BLOCK', detectionOutcome: 'MATCH', status: 'NEW', contentType: 'prompt',
  enforcement: { applied: true, httpStatus: 403 }, detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', scoreKind: 'CONFIDENCE', recommendedAction: 'BLOCK' }],
  adminNotes: [], timeline: [], ...over,
});
const snapshot: TrafficSnapshot = {
  period: '24H',
  summary: { metricSource: 'STORED_EVENTS', eventCount: 2, gatewayStatus: 'UNKNOWN', latencySampleCount: 1, averageLatencyMs: 120, p95LatencyMs: 120 },
  timeSeries: [{ timestamp: '2026-10-11T06:00:00Z', requestCount: 2, allowCount: 0, maskCount: 0, blockCount: 2 }],
  visualization: { asOf: Date.parse('2026-10-11T07:00:00Z'), from: Date.parse('2026-10-10T07:00:00Z'), boundaryBucket: false, issues: [], buckets: [
    { bucket: '2026-10-11T06:00:00Z', timestamp: '2026-10-11T06:00:00Z', start: Date.parse('2026-10-11T06:00:00Z'), end: Date.parse('2026-10-11T07:00:00Z'), partial: false, total: 2, block: 2, mask: 0, allow: 0 },
  ] },
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(evidenceService, 'getEventEvidence').mockResolvedValue({ status: 'NOT_RECORDED', event_id: 'evt-gw-time', source: 'RDS_DECISION_LOG', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', comparisons: [] });
});

describe('Gateway processing time wording', () => {
  it('names traffic latency as the Gateway processing time and states that LLM response time is excluded', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
    render(<QueryClientProvider client={client()}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    // 재설계 3c(설계 5.9): 지표 4칸 — P95 카드의 보조 줄에 평균(평균 카드는 따로 두지 않음)
    // 2026-10-14 지표 정리: 이름을 풀어 쓰고(용어는 괄호), 보조 줄에 표본 수('처리 시간 기록 n건'), title에 산정 기준
    // 같은 이름이 아래 '산정 기준'(접힘)의 항목 이름에도 있어 지표 묶음 안에서 찾는다
    const p95 = (await within(await screen.findByRole('region', { name: 'Gateway 지표' })).findByText('느린 5% 요청의 처리 시간 (P95)')).closest('article') as HTMLElement;
    expect(p95).toHaveTextContent('평균 0.12초 · 처리 시간 기록 1건 · 20건 미만');
    expect(p95).toHaveAttribute('title', expect.stringContaining('처리 시간 기록 1건 · 20건 미만이라 가장 긴 값과 같음'));
    expect(p95).toHaveAttribute('title', expect.stringMatching(/처리 시간 = 요청 수신부터 LLM 전달·차단까지\(LLM 응답 시간 제외\)$/));
    expect(screen.queryByText(/평균 처리시간|보안 검사만의 시간 아님|지연시간/)).toBeNull();
    expect(screen.getByRole('heading', { name: '시간대별 처리 시간' })).toBeInTheDocument();
    // 처리 시간 정의와 옛 기록 제외 안내는 시간대별 처리 시간 카드 아래 줄(옛 'LLM 응답 시간이 포함된 이전 기록은 처리 시간에서 제외합니다.' 줄임)
    expect(screen.getByText(/LLM 응답 시간 제외\) · LLM 응답 시간이 섞인 옛 기록은 뺌/)).toBeInTheDocument();
    // 저장 기록에 처리 시간이 없으면 0초로 그리지 않고 빈 상태(옛 '선택 기간에 Gateway 처리 시간 기록이 없습니다.')
    expect(screen.getByText('24시간 동안 처리 시간 기록이 없습니다.')).toBeInTheDocument();
  });

  it('shows live average and P95 as unavailable, with the reason, when the backend withholds a legacy Gateway value', async () => {
    const live: TrafficSnapshot = { ...snapshot, summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY',
      gatewayTotalRequests: 5, gatewayCompletedRequests: 5, gatewayErrorRequests: 0, gatewayWindowSeconds: 300, activeClients: 1, concurrentRequests: 0,
      requestsPerSec: 0.2, timeoutRate: 0, degradedRate: 0, latencyUnavailableReason: 'LEGACY_GATEWAY' } };
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(live);
    const view = render(<QueryClientProvider client={client()}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    // 2026-10-14: 같은 이름이 '산정 기준'(접힘)에도 있어 지표 묶음 안에서 찾는다
    const card = async (label: string) => (await within(await screen.findByRole('region', { name: 'Gateway 지표' })).findByText(label)).closest('article') as HTMLElement;
    const reason = '이전 판 Gateway(또는 첫 응답 전, 최대 10초) · LLM 응답 시간이 섞일 수 있어 표시하지 않음';
    // 재설계 3c: P95 카드 하나에 P95(값)·평균(보조 줄) — 둘 다 '확인 불가', 설명은 이유
    const article = await card('느린 5% 요청의 처리 시간 (P95)');   // 2026-10-14: 'Gateway 처리 시간 (P95)' → 풀어 쓴 이름
    expect(within(article).getAllByText('확인 불가')).toHaveLength(2);
    expect(article).toHaveAttribute('title', reason);
    expect(within(article).getByText(reason)).toBeInTheDocument();
    const kpis = within(screen.getByRole('region', { name: 'Gateway 지표' }));   // 재설계 3c: 옛 .traffic-kpis 클래스 대신 지표 묶음 이름
    expect(kpis.queryByText(/LLM 응답 시간 제외/)).toBeNull();   // KPI 설명에서 '제외'라고 하지 않는다(아래 저장 이벤트 차트 설명은 그대로)
    expect(kpis.queryByText(/측정 .*건|처리 시간 기록 .*건/)).toBeNull();
    // 다른 실시간 값은 그대로. 2026-10-14: 초당 0.2건 × 집계 300초 = '최근 5분 요청 60건'(분모를 건수로), 시간 초과는 실시간이면 '연결 시간 초과'
    // 2026-10-15 감사 5·6번: '응답 대기 중인 요청'(스트리밍·장시간 연결 포함), 최근 요청 = LLM 사이트 요청(화면 로딩 포함)
    expect(within(await card('응답 대기 중인 요청')).getByText(/최근 5분 LLM 사이트 요청 60건\(화면 로딩 포함\)/)).toBeInTheDocument();
    expect(within(await card('연결 시간 초과')).getByText('0.0%')).toBeInTheDocument();
    expect(within(await card('연결 시간 초과')).getByText('시작 이후 LLM 사이트 요청 5건 중(화면 로딩 포함)')).toBeInTheDocument();
    view.unmount();

    // 완료 0건이어도 처리 시간은 '아직 측정 없음'이 아니라 '확인 불가'(어느 기준 값인지 모름), 나머지는 그대로 '아직 측정 없음'
    vi.mocked(trafficService.getSnapshot).mockResolvedValue({ ...live, summary: { ...live.summary, gatewayStatus: 'UNKNOWN', gatewayTotalRequests: 0, gatewayCompletedRequests: 0 } });
    render(<QueryClientProvider client={client()}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    expect(within(await card('느린 5% 요청의 처리 시간 (P95)')).getAllByText('확인 불가')).toHaveLength(2);   // P95·평균
    expect(screen.getAllByText('아직 측정 없음')).toHaveLength(2);
  });

  it('keeps the live value and its scope when the reason is absent (new Gateway)', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue({ ...snapshot, summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY',
      gatewayTotalRequests: 5, gatewayCompletedRequests: 5, gatewayErrorRequests: 0, gatewayWindowSeconds: 300, latencySampleCount: 5,
      averageLatencyMs: 30, p95LatencyMs: 80, timeoutRate: 0, degradedRate: 0 } });
    render(<QueryClientProvider client={client()}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    const p95 = (await within(await screen.findByRole('region', { name: 'Gateway 지표' })).findByText('느린 5% 요청의 처리 시간 (P95)')).closest('article') as HTMLElement;
    expect(within(p95).getByText('0.08초')).toBeInTheDocument();
    expect(within(p95).getByText('0.03초')).toBeInTheDocument();   // 평균(보조 줄, 3c)
    // 2026-10-15 감사 1번: 실시간 표본 수 = 새 Gateway가 보내는 처리 시간 표본 수(서버는 이것만 latency_sample_count로 싣는다)
    expect(p95).toHaveAttribute('title', '요청 95%가 이 시간 안에 처리됨 · 표본 5건(Gateway가 검사한 요청) · 20건 미만이라 가장 긴 값과 같음 · 처리 시간 = 요청 수신부터 LLM 전달·차단까지(LLM 응답 시간 제외)');
    expect(p95).toHaveTextContent('평균 0.03초 · 표본 5건(Gateway가 검사한 요청) · 20건 미만');
    expect(screen.queryByText(/이전 판 Gateway/)).toBeNull();
  });

  it('labels the event detail value as the Gateway processing time and hides the row when the value is absent', async () => {
    const detail = (id: string) => render(<QueryClientProvider client={client()}><MemoryRouter initialEntries={[`/events/${id}`]}><Routes><Route path="/events/:eventId" element={<EventDetailPage />} /></Routes></MemoryRouter></QueryClientProvider>);
    vi.spyOn(eventService, 'getEventById').mockResolvedValue(event({ processingMs: 120 }));
    const measured = detail('evt-gw-time');
    await screen.findAllByText('evt-gw-time');
    const summary = within(measured.container.querySelector('.console-request-summary') as HTMLElement);
    const value = summary.getByText('Gateway 처리 시간').nextElementSibling as HTMLElement;
    expect(value).toHaveTextContent('0.12초');
    expect(value).toHaveAttribute('title', '요청 수신부터 LLM 전달·차단까지 · LLM 응답 시간 제외');
    expect(summary.queryByText('처리시간')).toBeNull();
    measured.unmount();

    vi.mocked(eventService.getEventById).mockResolvedValue(event({ eventId: 'evt-old-record' }));
    const legacy = detail('evt-old-record');
    await screen.findAllByText('evt-old-record');
    expect(within(legacy.container.querySelector('.console-request-summary') as HTMLElement).queryByText('Gateway 처리 시간')).toBeNull();
  });
});
