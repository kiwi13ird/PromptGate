import { uiLabel } from '@/src/utils/labels';
import { RotateCcw, Search, SlidersHorizontal, ChevronDown } from 'lucide-react';
import { useEffect, useMemo, useState, type SyntheticEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  EmptyState,
  ErrorState,
  FilterSelect,
  LoadingSkeleton,
  PageHeader,
  Pagination,
} from '@/src/components/common';
import { EventsTable } from '@/src/components/EventsTable';
import { useClientAliases } from '@/src/hooks/useGatewayAccess';
import { AutoRefreshBar, liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { eventService } from '@/src/services/eventService';
import { eventKeys } from '@/src/queries/keys';
import type {
  EventFilters,
  EventSort,
  OverviewPeriod,
} from '@/src/types/event';
import { uiMode } from '@runtime/ui-mode';
import { EmptyPeriodHint } from '@/src/components/EmptyPeriodHint';
import { RequestFinder } from '@/src/components/RequestFinder';
import { categoryTitle } from '@/src/utils/entityCategory';

const allowedPeriods: OverviewPeriod[] = ['24H', '7D', '30D'];
const allowedActions = ['ALL', ...uiMode.supportedActions] as EventFilters['finalAction'][];
const allowedDetectors = ['ALL', ...uiMode.supportedDetectors] as EventFilters['detector'][];
const allowedMatchTypes = ['ALL', ...uiMode.supportedMatchTypes] as EventFilters['matchType'][];
const allowedScoreKinds = ['ALL', ...uiMode.supportedScoreKinds] as EventFilters['scoreKind'][];
const allowedCategories = ['ALL', 'PII', 'CREDENTIAL', 'KEYWORD'] as const;
// 일치 유형·점수 기준이 탐지 방식과 1:1이면(운영) 같은 뜻의 필터를 또 보여 주지 않는다(2026-10-10)
const showMatchFilters = uiMode.supportedMatchTypes.length !== uiMode.supportedDetectors.length || uiMode.supportedScoreKinds.length > 1;
const allowedDetectionOutcomes: EventFilters['detectionOutcome'][] = [
  'ALL',
  'MATCH',
  'NO_MATCH',
  'UNAVAILABLE',
];
const allowedFailurePolicies: EventFilters['failurePolicy'][] = [
  'ALL',
  'FAIL_OPEN',
  'FAIL_CLOSED',
];
const allowedStatuses: EventFilters['status'][] = [
  'ALL',
  'NEW',
  'INVESTIGATING',
  'RESOLVED',
];
const allowedLlms: EventFilters['targetLlm'][] = [
  'ALL',
  'ChatGPT',
  'Gemini',
  'Claude',
];
const allowedSorts: EventSort[] = [
  'OCCURRED_AT_DESC',
  'OCCURRED_AT_ASC',
];
// 목록 보기(2026-10-16): 보안 이벤트(기본) = 보안 현황 카드와 같은 기록(접속 차단 제외·10/11 전 파일 재전송 접음) ·
// 접속 차단 기록 = 내용 검사 전에 막은 접속(카드가 따로 세는 기록) · 전체 기록 = 둘 다 포함한 모든 저장 기록
const allowedViews = ['events', 'access', 'all'] as const;
type EventView = typeof allowedViews[number];
const VIEW_LABELS: Record<EventView, string> = { events: '보안 이벤트', access: '접속 차단 기록', all: '전체 기록' };
const VIEW_HINTS: Record<EventView, string> = {
  events: '보안 검사를 거친 요청 · 보안 현황 카드와 같은 기록(접속 차단 제외, 10/11 전 파일 재전송·4초 안 같은 질문 재시도는 앞 기록 1건으로 접음)',
  access: '확장 프로그램 ID가 없거나 관리자가 막은 접속을 내용 검사 전에 거부한 기록 · 보안 현황 카드에는 들지 않음',
  all: '접속 차단 기록과 접은 재전송·재시도까지 모든 저장 기록 · 보안 현황 카드 수와 다름',
};
const VIEW_SCOPES: Record<EventView, EventFilters['scope']> = { events: 'counted', access: 'access', all: undefined };
const readEnum = <T extends string>(
  value: string | null,
  allowed: T[],
  fallback: T,
) => (value && allowed.includes(value as T) ? (value as T) : fallback);

export function SecurityEventsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const hasRetiredFilters = ['severity', 'degraded', 'degradedReason'].some(key => searchParams.has(key))
    || searchParams.get('sort') === 'SEVERITY_DESC';
  useEffect(() => {
    if (!hasRetiredFilters) return;
    const next = new URLSearchParams(searchParams);
    for (const key of ['severity', 'degraded', 'degradedReason', 'page']) next.delete(key);
    if (next.get('sort') === 'SEVERITY_DESC') next.delete('sort');
    navigate({pathname:location.pathname,search:next.toString(),hash:location.hash}, {replace:true,state:location.state});
  }, [hasRetiredFilters, searchParams, navigate, location.pathname, location.hash, location.state]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [newestOnly, setNewestOnly] = useState(false);
  const queryText = searchParams.get('q') ?? '';
  const view = readEnum(searchParams.get('view'), [...allowedViews], 'events');
  const filters = useMemo<EventFilters>(
    () => ({
      query: queryText,
      period: readEnum(searchParams.get('period'), allowedPeriods, '24H'),
      finalAction: readEnum(
        searchParams.get('finalAction') ?? searchParams.get('action'),
        allowedActions,
        'ALL',
      ),
      recommendedAction: readEnum(
        searchParams.get('recommendedAction'),
        allowedActions,
        'ALL',
      ),
      detector: readEnum(searchParams.get('detector'), allowedDetectors, 'ALL'),
      // 숨긴 필터(탐지 방식과 1:1)는 주소에 남아 있어도 적용하지 않는다
      matchType: showMatchFilters ? readEnum(searchParams.get('matchType'), allowedMatchTypes, 'ALL') : 'ALL',
      scoreKind: showMatchFilters ? readEnum(searchParams.get('scoreKind'), allowedScoreKinds, 'ALL') : 'ALL',
      degraded: 'ALL',
      detectionOutcome: readEnum(
        searchParams.get('detectionOutcome'),
        allowedDetectionOutcomes,
        'ALL',
      ),
      degradedReason: 'ALL',
      failurePolicy: readEnum(
        searchParams.get('failurePolicy'),
        allowedFailurePolicies,
        'ALL',
      ),
      documentId: searchParams.get('documentId') ?? '',
      severity: 'ALL',
      status: readEnum(searchParams.get('status'), allowedStatuses, 'ALL'),
      targetLlm: readEnum(searchParams.get('llm'), allowedLlms, 'ALL'),
      sort: readEnum(
        searchParams.get('sort'),
        allowedSorts,
        'OCCURRED_AT_DESC',
      ),
      page: hasRetiredFilters ? 1 : Math.max(1, Number(searchParams.get('page')) || 1),
      pageSize: 20,
      group: 'request',   // 프롬프트 + 첨부 파일을 한 줄로 (2026-10-09)
      ...(searchParams.get('includeTest') === '1' ? { includeTest: true } : {}),   // 시험·데모 기록 포함(2026-10-10)
      ...((category) => (category === 'ALL' ? {} : { entityCategory: category }))(readEnum(searchParams.get('category'), [...allowedCategories], 'ALL')),
      ...(VIEW_SCOPES[view] ? { scope: VIEW_SCOPES[view] } : {}),
    }),
    [queryText, searchParams, hasRetiredFilters, view],
  );
  const viewHref = (next: EventView) => {
    const params = new URLSearchParams(searchParams);
    if (next === 'events') params.delete('view');
    else params.set('view', next);
    params.delete('page');
    const text = params.toString();
    return `${location.pathname}${text ? `?${text}` : ''}`;
  };
  const showTestEvents = (include: boolean) => {
    const next = new URLSearchParams(searchParams);
    if (include) next.set('includeTest', '1');
    else next.delete('includeTest');
    next.delete('page');
    setSearchParams(next);
  };
  const { aliases } = useClientAliases();   // 확장 프로그램 ID 별칭(서버가 모르면 빈 목록)
  const events = useQuery({
    ...liveQueryOptions,
    queryKey: eventKeys.list(filters),
    queryFn: ({ signal }) => eventService.getEvents(filters, signal),
  });
  const setFilter = (key: string, value: string, fallback = 'ALL') => {
    const next = new URLSearchParams(searchParams);
    if (value === fallback || !value) next.delete(key);
    else next.set(key, value);
    next.delete('page');
    setSearchParams(next);
  };
  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const field = event.currentTarget.elements.namedItem(
      'eventSearch',
    ) as HTMLInputElement | null;
    setFilter('q', field?.value.trim() ?? '', '');
  };
  const activeFilters = [
    filters.query,
    filters.period !== '24H',
    filters.finalAction !== 'ALL',
    uiMode.showRecommendedAction && filters.recommendedAction !== 'ALL',
    filters.detector !== 'ALL',
    filters.entityCategory !== undefined,
    filters.matchType !== 'ALL',
    filters.scoreKind !== 'ALL',
    filters.detectionOutcome !== 'ALL',
    uiMode.showFailurePolicy && filters.failurePolicy !== 'ALL',
    filters.documentId,
    filters.status !== 'ALL',
    filters.targetLlm !== 'ALL',
    filters.sort !== 'OCCURRED_AT_DESC',
  ].filter(Boolean).length;
  const advancedFilters = [
    filters.status !== 'ALL',
    uiMode.showRecommendedAction && filters.recommendedAction !== 'ALL',
    filters.matchType !== 'ALL', filters.scoreKind !== 'ALL',
    filters.entityCategory !== undefined,
    filters.detectionOutcome !== 'ALL',
    uiMode.showFailurePolicy && filters.failurePolicy !== 'ALL',
  ].filter(Boolean).length;
  const advancedOpen = showAdvanced || advancedFilters > 0;
  return (
    <div className="events-console" data-ui="legacy">
      <PageHeader
        eyebrow="보안 이벤트"
        title="보안 이벤트 조회"
        action={events.data && canRetainQueryData(events.error) ? <span className="console-list-count">{VIEW_LABELS[view]} <b>{events.data.total.toLocaleString('ko-KR')}</b>건
          {events.data.excludedTest ? <span className="dops-test-note"> · 시험·데모 {events.data.excludedTest.toLocaleString('ko-KR')}건 제외 <button type="button" className="dops-test-toggle" onClick={() => showTestEvents(true)}>포함해서 보기</button></span>
            : filters.includeTest ? <span className="dops-test-note"> · 시험·데모 포함 <button type="button" className="dops-test-toggle" onClick={() => showTestEvents(false)}>빼고 보기</button></span> : null}</span> : undefined}
        status={<AutoRefreshBar compact updatedAt={events.dataUpdatedAt} fetching={events.isFetching} failed={events.isError} onRefresh={() => events.refetch()} total={events.data?.total} scope={JSON.stringify({ ...filters, page: undefined })}
          recentAt={filters.page === 1 && filters.sort === 'OCCURRED_AT_DESC' ? events.data?.items.map(item => item.occurredAt) : undefined}
          countLabel={view === 'access' ? '접속 차단 기록' : '이벤트'} onNew={() => { const next=new URLSearchParams(searchParams); next.delete('page'); next.delete('sort'); setSearchParams(next); setNewestOnly(true); }} />}
      />
      {events.isError && events.data && canRetainQueryData(events.error) && <p role="status" className="console-stale-notice">갱신 실패 · 아래는 마지막 성공 조회 결과입니다.</p>}
      {newestOnly && !events.isError && filters.page === 1 && filters.sort === 'OCCURRED_AT_DESC' && events.data?.items[0] && <div className="latest-event-shortcut"><span>현재 조회 조건의 최신 사건</span><a href={`/events/${encodeURIComponent(events.data.items[0].eventId)}`}>탐지 근거와 처리 과정 보기 →</a><button type="button" aria-label="최신 사건 안내 닫기" onClick={() => setNewestOnly(false)}>닫기</button></div>}
      <nav className="events-view-tabs" aria-label="목록 보기">
        {allowedViews.map(item => {
          const count = events.data?.viewTotals?.[item === 'events' ? 'counted' : item];
          return <Link key={item} to={viewHref(item)} aria-current={view === item ? 'page' : undefined} title={VIEW_HINTS[item]}>
            {VIEW_LABELS[item]}{count !== undefined && <b>{count.toLocaleString('ko-KR')}</b>}
          </Link>;
        })}
      </nav>
      {view !== 'events' && <p className="events-view-note">{VIEW_HINTS[view]}</p>}
      <section className="panel filter-panel">
        <form className="event-search" onSubmit={submit}>
          <label htmlFor="eventSearch">문서명 / 이벤트·요청·클라이언트 ID 검색</label>
          <div>
            <Input
              key={queryText}
              id="eventSearch"
              name="eventSearch"
              defaultValue={queryText}
              placeholder="문서명 또는 이벤트·요청·클라이언트 ID"
            />
            <Button type="submit" variant="outline">
              <Search />
              검색
            </Button>
            <Button
              type="button"
              variant="outline"
              className="reset-button"
              onClick={() => setSearchParams(view === 'events' ? {} : { view })}
              disabled={!activeFilters}
            >
              <RotateCcw />
              필터 초기화{activeFilters ? ` (${activeFilters})` : ''}
            </Button>
          </div>
        </form>
        <div className="filter-toolbar">
          <span>조회 조건{activeFilters > 0 && <b>{activeFilters}개 적용</b>}</span>
          <button type="button" className="advanced-filter-toggle" aria-expanded={advancedOpen}
            aria-controls="event-filter-fields" onClick={() => setShowAdvanced(!showAdvanced)}
            disabled={advancedFilters > 0} title={advancedFilters > 0 ? '적용 중인 상세 조건은 펼쳐서 표시합니다.' : undefined}>
            <SlidersHorizontal aria-hidden="true" /> 상세 조건 <ChevronDown aria-hidden="true" />
          </button>
        </div>
        <div id="event-filter-fields" className={`filter-grid event-filter-grid${advancedOpen ? ' expanded' : ''}`}>
          <FilterSelect
            label="기간"
            value={filters.period}
            onChange={(value) => setFilter('period', value, '24H')}
          >
            <option value="24H">최근 24시간</option>
            <option value="7D">최근 7일</option>
            <option value="30D">최근 30일</option>
          </FilterSelect>
          <FilterSelect
            label="게이트웨이 최종 조치"
            value={filters.finalAction}
            onChange={(value) => setFilter('finalAction', value)}
          >
            {allowedActions.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>
          {uiMode.showRecommendedAction && <FilterSelect
            secondary
            label="탐지 권장 조치"
            value={filters.recommendedAction}
            onChange={(value) => setFilter('recommendedAction', value)}
          >
            {allowedActions.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>}
          <FilterSelect
            label="탐지 방식"
            value={filters.detector}
            onChange={(value) => setFilter('detector', value)}
          >
            {allowedDetectors.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>
          <FilterSelect
            secondary
            label="탐지 정보 종류"
            value={filters.entityCategory ?? 'ALL'}
            onChange={(value) => setFilter('category', value)}
          >
            {allowedCategories.map((value) => (
              <option key={value} value={value}>{value === 'ALL' ? '전체' : categoryTitle[value]}</option>
            ))}
          </FilterSelect>
          {showMatchFilters && <><FilterSelect
            secondary
            label="일치 유형"
            value={filters.matchType}
            onChange={(value) => setFilter('matchType', value)}
          >
            {allowedMatchTypes.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>
          <FilterSelect
            secondary
            label="점수 기준"
            value={filters.scoreKind}
            onChange={(value) => setFilter('scoreKind', value)}
          >
            {allowedScoreKinds.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect></>}
          <FilterSelect
            secondary
            label="탐지 결과"
            value={filters.detectionOutcome}
            onChange={(value) => setFilter('detectionOutcome', value)}
          >
            {allowedDetectionOutcomes.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>
          {uiMode.showFailurePolicy && <FilterSelect
            secondary
            label="장애 정책"
            value={filters.failurePolicy}
            onChange={(value) => setFilter('failurePolicy', value)}
          >
            {allowedFailurePolicies.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>}
          <label className="filter-field" htmlFor="protected-document-filter">
            <span>보호 문서 ID</span>
            <Input
              id="protected-document-filter"
              value={filters.documentId}
              placeholder="DOC-"
              onChange={(event) =>
                setFilter('documentId', event.target.value, '')
              }
            />
          </label>
          <FilterSelect
            secondary
            label="조사 상태"
            value={filters.status}
            onChange={(value) => setFilter('status', value)}
          >
            {allowedStatuses.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>
          <FilterSelect
            label="대상 LLM"
            value={filters.targetLlm}
            onChange={(value) => setFilter('llm', value)}
          >
            {allowedLlms.map((value) => (
              <option key={value} value={value}>{uiLabel(value)}</option>
            ))}
          </FilterSelect>
          <FilterSelect
            label="정렬"
            value={filters.sort}
            onChange={(value) => setFilter('sort', value, 'OCCURRED_AT_DESC')}
          >
            <option value="OCCURRED_AT_DESC">최신순</option>
            <option value="OCCURRED_AT_ASC">오래된 순</option>
          </FilterSelect>
        </div>
        <details key={location.hash} open={location.hash === '#request-finder'} className="request-finder-disclosure console-lookup"><summary><Search size={14} aria-hidden="true" />요청 ID로 기록 조회</summary><RequestFinder /></details>
      </section>
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">조회 결과</p>
            <h3>조회 결과</h3>
          </div>
          <span className="console-page-size">한 쪽에 {filters.pageSize}건</span>
        </div>
        {events.isLoading ? (
          <LoadingSkeleton />
        ) : events.isError && (!events.data || !canRetainQueryData(events.error)) ? (
          <ErrorState
            message="보안 이벤트를 불러오지 못했습니다."
            error={events.error}
            onRetry={() => events.refetch()}
          />
        ) : events.data?.items.length ? (
          <>
            <EventsTable events={events.data.items} evidenceToggle aliases={aliases} />
            <Pagination
              page={events.data.page}
              totalPages={events.data.totalPages}
              total={events.data.total}
              onPage={(page) => {
                const next = new URLSearchParams(searchParams);
                if (page === 1) next.delete('page');
                else next.set('page', String(page));
                setSearchParams(next);
              }}
            />
          </>
        ) : (
          <><EmptyState
            title={view === 'access' ? '조건에 맞는 접속 차단 기록이 없습니다.' : view === 'all' ? '조건에 맞는 기록이 없습니다.' : '조건에 맞는 보안 이벤트가 없습니다.'}
            description="필터를 초기화하거나 다른 기간을 선택해보세요."
          /><EmptyPeriodHint period={filters.period} onExpand={() => setFilter('period', '30D', '24H')} /></>
        )}
      </section>
    </div>
  );
}
