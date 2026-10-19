// 재설계 3c(설계 5.9·5.9.1): 상태 띠 · 지표 4칸 · 처리 시간 분포 ① · 검사 못 한 요청 ② · 요청 수 띠 ③
// 2026-10-14 지표 정리: 이름 풀어 쓰기·분모·표본 수, 요청 수 띠 삭제(툴팁으로), 처리 시간 추이 선 → 막대
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TrafficPerformancePage } from './TrafficPerformancePage';
import { trafficService } from '@/src/services/trafficService';
import { gatewaySettingsService } from '@/src/services/gatewaySettingsService';
import type { GatewaySettingsResponse } from '@/src/api/gatewaySettingsSchemas';
import type { SecurityEvent } from '@/src/types/event';
import type { TrafficSnapshot } from '@/src/types/traffic';

vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
vi.mock('recharts', () => ({ LineChart: () => null, BarChart: () => null, Bar: () => null, Line: () => null, CartesianGrid: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null }));

const start = Date.parse('2026-10-13T01:00:00Z');
const bucket = (hour: number, total: number) => ({ bucket: `b${hour}`, timestamp: new Date(start + hour * 3_600_000).toISOString(), start: start + hour * 3_600_000, end: start + (hour + 1) * 3_600_000, partial: false, total, block: 0, mask: 0, allow: total, averageLatencyMs: 20, p95LatencyMs: 40 });
const event = (id: string, extra: Partial<SecurityEvent>): SecurityEvent => ({ eventId: id, occurredAt: new Date(start + 600_000).toISOString(), clientId: 'c', targetLlm: 'ChatGPT', detectionOutcome: 'NO_MATCH', finalAction: 'ALLOW', status: 'NEW', detections: [], adminNotes: [], timeline: [], ...extra });
const snapshot: TrafficSnapshot = {
  period: '24H',
  summary: { metricSource: 'GATEWAY_LIVE', gatewayMetricsStatus: 'FRESH', gatewayStatus: 'HEALTHY', gatewayTotalRequests: 12, gatewayCompletedRequests: 12, gatewayErrorRequests: 0,
    gatewayWindowSeconds: 60, activeClients: 2, concurrentRequests: 1, requestsPerSec: 0.5, latencySampleCount: 30, averageLatencyMs: 20, p95LatencyMs: 40, timeoutRate: 0, degradedRate: 0.1 },
  timeSeries: [],
  visualization: { asOf: start + 7_200_000, from: start - 79_200_000, boundaryBucket: false, issues: [], buckets: [bucket(0, 3), bucket(1, 1)] },
  periodEvents: [
    event('a', { processingMs: 8, contentType: 'prompt' }), event('b', { processingMs: 4000, contentType: 'prompt', degraded: true }),
    event('c', { processingMs: 200, contentType: 'file', reasonCode: 'file_uninspectable_image' }), event('d', { occurredAt: new Date(start + 4_000_000).toISOString(), reasonCode: 'client_blocked', finalAction: 'BLOCK' }),
  ],
};
const values = { timeout: { prompt: { action: 'forward' as const, seconds: 3 }, file: { action: 'block' as const, seconds: 10 } }, uninspectable: { image: 'allow' as const, scanned_pdf: 'block' as const, other: 'block' as const }, notify_on_allow: true };
const settings = { settings: { ...values, version: 0, revision: null, updated_at: null, updated_by: null, source: 'DEFAULT' }, defaults: values, gateway: { state: 'APPLIED' } } as GatewaySettingsResponse;

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(trafficService, 'getSnapshot').mockResolvedValue(snapshot);
  vi.spyOn(trafficService, 'getClients').mockResolvedValue({ receivedAt: undefined, stale: false, windowSeconds: 300, clients: [] });
  vi.spyOn(gatewaySettingsService, 'get').mockResolvedValue(settings);
});

describe('traffic page metrics (3c)', () => {
  it('shows the Gateway strip, four KPIs with secondary lines, the latency distribution against the wait setting and uninspected requests', async () => {
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><TrafficPerformancePage /></MemoryRouter></QueryClientProvider>);
    const strip = await screen.findByRole('status', { name: 'Gateway 상태' });
    expect(strip).toHaveAttribute('data-level', 'ok');
    expect(strip).toHaveTextContent('Gateway 정상');
    // 2026-10-14 지표 정리: '프로세스 시작 이후 12건 · 완료 12건 · 오류 0건' → 무엇을 세는지(요청·연결 오류)를 적음
    // 2026-10-15 감사: '요청' = LLM 사이트 HTTP 요청(화면 로딩 포함)이라 이름에 밝히고, 옛 Gateway의 연결 오류는 브라우저 취소가 섞인 '연결 끊김'
    expect(strip).toHaveTextContent('시작 이후 LLM 사이트 요청 12건(화면 로딩 포함) · 완료 12건 · 연결 끊김 0건(브라우저 취소 포함)');
    // 두 묶음: 지금 Gateway(실시간, 기간과 무관) · 24시간 저장 기록(표본 수)
    expect(screen.getByRole('region', { name: '지금 Gateway' })).toHaveTextContent('실시간 · Gateway 시작 이후 누적 · 위 기간 선택과 무관');
    const stored = screen.getByRole('region', { name: '24시간 저장 기록' });
    expect(stored).toHaveTextContent('질문·파일 검사 기록(보안 이벤트) 4건 · 그중 처리 시간 기록 3건 (프롬프트 2 · 파일 1)');
    const kpis = screen.getByRole('region', { name: 'Gateway 지표' });
    expect(within(kpis).getAllByRole('article')).toHaveLength(4);
    // 옛 '보안 검사 장애 비율' → '보안 검사 응답 없음', 보조 줄 = 분모
    const degraded = within(kpis).getByText('보안 검사 응답 없음').closest('article') as HTMLElement;
    expect(degraded).toHaveClass('pg-kpi--mask');
    expect(degraded).toHaveTextContent('시작 이후 LLM 사이트 요청 12건 중(화면 로딩 포함)');   // 옛 Gateway: 검사 요청 수가 없어 전체가 분모임을 밝힘
    // 옛 '시간 초과 비율'(실시간 값은 연결 오류 중 시간 초과) → '연결 시간 초과'
    expect(within(kpis).getByText('연결 시간 초과').closest('article')).toHaveAttribute('title', expect.stringContaining("보안 검사 대기 시간 초과는 '보안 검사 응답 없음'에 셈"));
    // 옛 '연결 중 클라이언트 2 · 동시 요청 1 · 초당 0.5' → 이름이 아래 '연결 중인 IP'(열린 연결)와 겹치지 않게, 초당 → 1분 건수
    const busy = within(kpis).getByText('응답 대기 중인 요청').closest('article') as HTMLElement;   // 감사 5번: 답변 스트리밍·장시간 연결 포함
    expect(busy).toHaveTextContent('1건');
    expect(busy).toHaveTextContent('응답 대기 IP 2개 · 최근 1분 LLM 사이트 요청 30건(화면 로딩 포함)');
    // 산정 기준(접힘): 카드마다 정의
    const basis = screen.getByText('산정 기준').closest('details') as HTMLElement;
    expect(within(basis).getByText('느린 5% 요청의 처리 시간 (P95)').nextElementSibling).toHaveTextContent(/100건이면 5번째로 느린 요청의 시간/);
    // 처리 시간별 요청 수(옛 '처리 시간 분포')
    const distribution = screen.getByRole('region', { name: '처리 시간별 요청 수' });
    expect(await within(distribution).findByRole('img', { name: '프롬프트 처리 시간 분포: ~10ms 1건, ~30ms 0건, ~0.1초 0건, ~0.3초 0건, ~1초 0건, ~3초 0건, 넘음 1건' })).toBeInTheDocument();
    expect(within(distribution).getByText(/대기 시간 3초 넘음 1건 · 20건 미만/)).toBeInTheDocument();   // 옛 '대기 설정 3초 · 넘음 1건 · 표본이 적음'
    expect(within(distribution).getByRole('img', { name: /^파일 처리 시간 분포: .*~0\.3초 1건.*~10초 0건, 넘음 0건$/ })).toBeInTheDocument();
    expect(within(distribution).getByTitle('3초 넘음 · 1건')).toBeInTheDocument();       // 막대 툴팁 = 구간 범위
    expect(within(distribution).getByTitle('10ms 이하 · 1건')).toBeInTheDocument();
    // 시간대별 처리 시간: 막대(구간마다 P95), 가장 느린 시간과 그 표본 수. 두 그림의 표본 수 합 = 묶음 머리의 처리 시간 기록 수(3건)
    const trend = screen.getByRole('region', { name: '시간대별 처리 시간' });
    expect(within(trend).getByRole('img', { name: /^1시간 단위 느린 5% 처리 시간: .* 0\.04초, .* 0\.04초$/ })).toBeInTheDocument();
    expect(trend).toHaveTextContent('가장 느린 시간');
    expect(trend).toHaveTextContent('(처리 시간 기록 3건)');   // 전체가 20건 미만이면 아래 안내 한 번만(같은 말 반복 안 함)
    expect(within(trend).getByRole('note')).toHaveTextContent('처리 시간 기록이 3건뿐이라 경향을 판단하기 이릅니다');
    // 옛 요청 수 띠(③)는 없음: 요청 수는 막대 툴팁으로
    expect(screen.queryByText(/요청 수\(같은 가로축\)/)).toBeNull();
    expect(screen.queryByRole('img', { name: /^구간별 요청 수/ })).toBeNull();
    const uninspected = screen.getByRole('region', { name: '검사 못 한 요청' });
    expect(within(uninspected).getByText('보안 검사 응답 없음 1')).toHaveAttribute('data-tone', 'mask');
    expect(within(uninspected).getByText('검사할 수 없는 파일 1')).toBeInTheDocument();
    expect(within(uninspected).getByText('파일이 커서 검사 못 함 0')).toHaveAttribute('data-tone', 'neutral');
    expect(uninspected).toHaveTextContent('24시간 2건 · 막대 = 그 시간에 검사 없이 전달·차단된 요청 수');
    // 감사 8·9번: 분모도 접속 차단을 뺀 수, '해당 이벤트' 목록에 접속 차단이 섞여 나온다는 것을 적음
    expect(uninspected).toHaveTextContent('24시간 보안 이벤트 3건 중(접속 차단 제외)');
    expect(uninspected).toHaveTextContent('해당 이벤트 목록에는 접속 차단 1건도 함께 나옴');
    expect(within(uninspected).getByRole('img').getAttribute('aria-label')).toMatch(/^1시간 단위 검사 못 한 요청: .* 2건, .* 0건$/);   // 접속 차단(d)은 빼고 첫 구간 2건
    expect(within(uninspected).getByRole('link', { name: '해당 이벤트' })).toHaveAttribute('href', '/events?period=24H&detectionOutcome=UNAVAILABLE');
  });
});
