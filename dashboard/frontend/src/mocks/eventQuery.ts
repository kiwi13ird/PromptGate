import type { PageDto, SecurityEventDto } from '@/src/api/dto';
import type { EventFilters, OverviewPeriod } from '@/src/types/event';
import { isAccessBlockReason } from '@/src/utils/reasonLabels';

// 서버 isAccessBlockEvent와 같은 판단(2026-10-16 공통 규칙: 사유 코드만). 모의 자료에는 재전송 접기가 없다
const isAccessBlockDto = (event: SecurityEventDto) => isAccessBlockReason(event.reason_code);
const inScope = (event: SecurityEventDto, scope: EventFilters['scope']) =>
  !scope ? true : scope === 'access' ? isAccessBlockDto(event) : !isAccessBlockDto(event);

export function periodThreshold(period: OverviewPeriod, now = Date.now()) {
  if (period === '7D') return now - 7 * 86400000;
  if (period === '24H') return now - 86400000;
  return now - 30 * 86400000;
}

export function filterEventDtos(
  events: SecurityEventDto[],
  filters: EventFilters,
  now = Date.now(),
) {
  const query = filters.query.toLowerCase().trim();
  const rows = events.filter((event) => {
    const finalAction = event.final_action ?? event.action;
    const recommendedAction =
      event.recommended_action ??
      event.detections[0]?.recommended_action ??
      event.detections[0]?.action;
    const scoreKinds = event.detections.map((item) => {
      if (item.detector === 'WINDOW_HASH')
        return item.score_kind;
      if (item.detector === 'SIGNATURE') return 'CONFIDENCE';
      return 'SIMILARITY';
    });
    const documentIds = event.detections.flatMap((item) =>
      'matched_document_id' in item ? [item.matched_document_id] : [],
    );
    const matchesQuery =
      !query ||
      event.event_id.toLowerCase().includes(query) ||
      event.client_id.toLowerCase().includes(query);
    return (
      Date.parse(event.occurred_at) >= periodThreshold(filters.period, now) &&
      inScope(event, filters.scope) &&
      matchesQuery &&
      (filters.finalAction === 'ALL' ||
        finalAction === filters.finalAction) &&
      (filters.recommendedAction === 'ALL' ||
        recommendedAction === filters.recommendedAction) &&
      (filters.detector === 'ALL' ||
        event.detections.some((item) => item.detector === filters.detector)) &&
      (filters.matchType === 'ALL' ||
        event.detections.some(
          (item) => item.match_type === filters.matchType,
        )) &&
      (filters.scoreKind === 'ALL' || scoreKinds.includes(filters.scoreKind)) &&
      (filters.degraded === 'ALL' ||
        (filters.degraded === 'YES' ? event.degraded : !event.degraded)) &&
      (filters.detectionOutcome === 'ALL' ||
        event.detection_outcome === filters.detectionOutcome) &&
      (filters.degradedReason === 'ALL' ||
        event.degraded_reason === filters.degradedReason) &&
      (filters.failurePolicy === 'ALL' ||
        event.failure_policy === filters.failurePolicy) &&
      (!filters.documentId || documentIds.includes(filters.documentId)) &&
      (filters.severity === 'ALL' || event.severity === filters.severity) &&
      (filters.status === 'ALL' || event.status === filters.status) &&
      (filters.targetLlm === 'ALL' || event.target_llm === filters.targetLlm)
    );
  });
  return rows.sort((a, b) => {
    if (filters.sort === 'OCCURRED_AT_ASC')
      return Date.parse(a.occurred_at) - Date.parse(b.occurred_at);
    if (filters.sort === 'SEVERITY_DESC') {
      const priority = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
      return (
        priority[b.severity ?? 'LOW'] - priority[a.severity ?? 'LOW'] ||
        Date.parse(b.occurred_at) - Date.parse(a.occurred_at)
      );
    }
    return Date.parse(b.occurred_at) - Date.parse(a.occurred_at);
  });
}

export function paginateDtos<T>(
  rows: T[],
  page: number,
  pageSize: number,
): PageDto<T> {
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  return {
    items: rows.slice((safePage - 1) * pageSize, safePage * pageSize),
    total: rows.length,
    page: safePage,
    page_size: pageSize,
    total_pages: totalPages,
  };
}

export const filterAndPaginateEventDtos = (
  events: SecurityEventDto[],
  filters: EventFilters,
  now = Date.now(),
) => {
  const page = paginateDtos(
    filterEventDtos(events, filters, now),
    filters.page,
    filters.pageSize,
  );
  // 서버처럼 counted·access로 물으면 보기별 건수를 같이 준다(2026-10-16)
  if (filters.scope !== 'counted' && filters.scope !== 'access') return page;
  const count = (scope: EventFilters['scope']) => filterEventDtos(events, { ...filters, scope }, now).length;
  return { ...page, view_totals: { counted: count('counted'), access: count('access'), all: count(undefined) } };
};
