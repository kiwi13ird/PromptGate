import { gatewayApi } from '@/src/api';
import { mapTrafficClientsDto, mapTrafficSnapshotDto } from '@/src/api/mappers';
import type { OverviewPeriod } from '@/src/types/event';
import { readPeriodEvents } from './eventSeriesService';
import { normalizeEventSeries } from '@/src/utils/eventSeries';
import { ApiError } from '@/src/api/errors';

export const trafficService = {
  async getSnapshot(period: OverviewPeriod, signal?: AbortSignal) {
    const snapshot = mapTrafficSnapshotDto(
      await gatewayApi.getTrafficSnapshot(period, signal),
      period,
    );
    if (!snapshot.unavailableSections?.includes('timeseries')) {
      try {
        // 새 서버(access_blocked 있음)는 저장 기록에서 접속 차단을 뺀다 — 목록도 같은 기록으로 읽는다
        const events = await readPeriodEvents(period, signal, snapshot.summary.accessBlocked !== undefined ? 'inspected' : undefined);
        const series = normalizeEventSeries(events, period, Date.now());
        const rawCount = snapshot.timeSeries.reduce((n, p) => n + p.requestCount, 0);
        if (rawCount !== events.length || (snapshot.summary.eventCount !== undefined && snapshot.summary.eventCount !== events.length)) series.issues.push('저장 이벤트 집계와 사건 목록의 조회 결과가 달라졌습니다. 새로고침해 확인하세요.');
        for (const action of ['BLOCK','MASK','ALLOW'] as const) {
          const field = action === 'BLOCK' ? 'blockCount' : action === 'MASK' ? 'maskCount' : 'allowCount';
          if (snapshot.timeSeries.reduce((n, point) => n + point[field], 0) !== events.filter(event => event.finalAction === action).length) series.issues.push('조치별 시간 구간 합계와 사건 목록이 일치하지 않습니다.');
        }
        series.issues = [...new Set(series.issues)];
        snapshot.visualization = series;
        // 재설계 3c: 같은 목록으로 처리 시간 분포·검사 못 한 요청을 화면에서 계산한다 — 요청을 더 하지 않는다
        snapshot.periodEvents = events;
      } catch (error) {
        if (signal?.aborted || (error instanceof ApiError && ['UNAUTHORIZED','FORBIDDEN'].includes(error.code))) throw error;
        snapshot.visualization = {buckets:[],asOf:Date.now(),from:Date.now(),boundaryBucket:false,issues:['시간축을 확인할 사건 목록을 불러오지 못했습니다.']};
      }
    }
    return snapshot;
  },
  // 연결 중인 IP(2026-10-12): 조회 기간과 무관한 Gateway 실시간 값
  async getClients(signal?: AbortSignal) {
    return mapTrafficClientsDto(await gatewayApi.getTrafficClients(signal));
  },
};
