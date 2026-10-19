import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { TrafficPerformancePage } from './TrafficPerformancePage';
import { trafficService } from '@/src/services/trafficService';

describe('live telemetry during idle periods', () => {
  it('shows a connected waiting gateway without claiming zero-latency performance', async () => {
    vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue({ period: '24H',
      summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'UNKNOWN',
        gatewayTotalRequests: 0, gatewayCompletedRequests: 0, gatewayErrorRequests: 0,
        gatewayWindowSeconds: 60, activeClients: 0, concurrentRequests: 0, requestsPerSec: 0, latencySampleCount: 0 },
      timeSeries: [],
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('요청 대기')).toBeInTheDocument();
    // 2026-10-15 감사 2번: 처리 시간 표본 0건이면 P95·평균은 '기록 없음'(0초가 아님), 비율 2칸은 완료 요청이 없어 '아직 측정 없음'
    expect(screen.getAllByText('기록 없음')).toHaveLength(2);
    expect(screen.getAllByText('아직 측정 없음')).toHaveLength(2);
    expect(screen.getByText('지표 연결 정상 · 완료 요청 없음')).toBeInTheDocument();
    // 2026-10-14 지표 정리: '프로세스' → 'Gateway 시작 이후 요청', 실시간·저장 기록 구분은 묶음 머리와 산정 기준으로
    expect(screen.getByRole('status', { name: 'Gateway 상태' })).toHaveTextContent('시작 이후 LLM 사이트 요청 0건(화면 로딩 포함)');
    expect(screen.queryByText('0초')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '지금 Gateway' })).toBeInTheDocument();
    expect(screen.getByText('실시간 · Gateway 시작 이후 누적 · 위 기간 선택과 무관')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '24시간 저장 기록' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '시간대별 처리 시간' })).toBeInTheDocument();
    expect(screen.getByText(/LLM 사이트로 간 HTTP 요청 전체\(화면 로딩·이미지·폴링 포함\)라 아래 보안 이벤트 수보다 많음/)).toBeInTheDocument();
  });
});
