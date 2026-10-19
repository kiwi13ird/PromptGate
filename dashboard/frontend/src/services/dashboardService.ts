import { gatewayApi } from '@/src/api';
import { mapDashboardStatsDto } from '@/src/api/mappers';
import type { OverviewPeriod } from '@/src/types/event';
import { readPeriodEvents } from './eventSeriesService';
import { normalizeEventSeries, overviewIntegrityIssues } from '@/src/utils/eventSeries';
import { ApiError } from '@/src/api/errors';

export const dashboardService = {
  // 집계만(시간축 검증 없이) — 정책·키워드 화면의 적중 수용(2026-10-10)
  async getSummary(period: OverviewPeriod, signal?: AbortSignal) {
    return mapDashboardStatsDto(await gatewayApi.getDashboardStats(period, signal));
  },
  async getStats(period: OverviewPeriod, signal?: AbortSignal) {
    const stats = mapDashboardStatsDto(
      await gatewayApi.getDashboardStats(period, signal),
    );
    try {
      // 새 서버(counting 있음)는 카드와 같은 기록(요청 단위, 접속 차단·재전송 제외)으로 읽어 추이·검증·추가 지표가 카드와 같은 기준이 된다
      const events = await readPeriodEvents(period, signal, stats.counting ? 'counted' : undefined);
      const series = normalizeEventSeries(events, period, Date.now());
      stats.visualization = {...series, issues: overviewIntegrityIssues(stats, events, series)};
      // 재설계 3b: 같은 목록으로 추가 지표(사유·검사 없이 처리된 요청)를 화면에서 계산한다 — 요청을 더 하지 않는다
      stats.periodEvents = events;
    } catch (error) {
      if (signal?.aborted || (error instanceof ApiError && ['UNAUTHORIZED','FORBIDDEN'].includes(error.code))) throw error;
      stats.visualization = {buckets:[],asOf:Date.now(),from:Date.now(),boundaryBucket:false,issues:['시간축을 확인할 사건 목록을 불러오지 못했습니다. 집계값은 별도 API 응답입니다.']};
    }
    return stats;
  },
};
