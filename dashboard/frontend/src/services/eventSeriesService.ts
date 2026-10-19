import { gatewayApi } from '@/src/api';
import { mapSecurityEventDto } from '@/src/api/mappers';
import { ApiError } from '@/src/api/errors';
import type { EventFilters, OverviewPeriod } from '@/src/types/event';

/** Existing GET pagination only. A partial/truncated set must never form a chart.
 * scope(2026-10-15): 집계 API와 같은 기록만 읽는다 — 새 서버가 집계 기준을 알려 줄 때만 쓴다(옛 서버는 이 칸을 모른다).
 *  counted = 보안 현황 카드와 같은 기록(요청 단위 묶음, 접속 차단·10/11 전 재전송 제외) · inspected = 트래픽 저장 기록(기록 단위, 접속 차단 제외) */
export async function readPeriodEvents(period: OverviewPeriod, signal?: AbortSignal, scope?: 'counted' | 'inspected') {
  const filters: EventFilters = {query:'',period,finalAction:'ALL',recommendedAction:'ALL',detector:'ALL',matchType:'ALL',scoreKind:'ALL',degraded:'ALL',detectionOutcome:'ALL',degradedReason:'ALL',failurePolicy:'ALL',documentId:'',severity:'ALL',status:'ALL',targetLlm:'ALL',sort:'OCCURRED_AT_DESC',page:1,pageSize:100,
    ...(scope ? { scope } : {}), ...(scope === 'counted' ? { group: 'request' as const } : {})};
  const first = await gatewayApi.getEvents(filters, signal);
  if (first.total_pages > 100) throw new ApiError('시간축 검증에 필요한 기록이 너무 많습니다. 일부 자료로 차트를 생성하지 않습니다.', 'INVALID_RESPONSE');
  const pages = [first];
  for (let next = 2; next <= first.total_pages; next += 4) {
    const group = await Promise.all(Array.from({length:Math.min(4, first.total_pages - next + 1)}, (_, i) => gatewayApi.getEvents({...filters,page:next + i}, signal)));
    if (group.some(p => p.total !== first.total || p.total_pages !== first.total_pages)) throw new ApiError('조회 중 사건 집합이 변경됐습니다. 다시 조회하세요.', 'INVALID_RESPONSE');
    pages.push(...group);
  }
  const items = pages.flatMap(p => p.items);
  if (items.length !== first.total || new Set(items.map(e => e.event_id)).size !== items.length) throw new ApiError('전체 사건 목록을 확인하지 못했습니다.', 'INVALID_RESPONSE');
  return items.map(mapSecurityEventDto);
}
