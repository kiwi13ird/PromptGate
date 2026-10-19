import { useEffect, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis } from 'recharts';
import { trafficService } from '@/src/services/trafficService';
import { gatewaySettingsKeys, gatewaySettingsService } from '@/src/services/gatewaySettingsService';
import { trafficKeys } from '@/src/queries/keys';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { PgBadge, PgEmpty, PgError, PgMiniBars, PgPageHeader, PgPeriod, PgRefresh, PgSkeleton, PgStatusStrip, PERIOD_LABELS, type StripLevel } from '@/src/components/pg';
import { CHART_TICK_FONT_SIZE, chartColor, chartColors } from '@/src/utils/chartColors';
import { TrafficClientsManager } from '@/src/components/TrafficClientsManager';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { GATEWAY_PROCESSING_UNCONFIRMED, formatLatency, formatTrafficRate, gatewayErrorText, gatewayHealthExplanation, trafficSourceLabel, trafficSourceDescription } from '@/src/utils/trafficPresentation';
import { formatDateTime } from '@/src/utils/format';
import type { OverviewPeriod } from '@/src/types/event';
import type { TrafficSnapshot } from '@/src/types/traffic';
import { bucketLabel, type EventTimeBucket } from '@/src/utils/eventSeries';
import { useOverviewPeriod } from '@/src/utils/useOverviewPeriod';
import { EmptyPeriodHint } from '@/src/components/EmptyPeriodHint';
import { FEW_SAMPLES, bucketSamples, latencyAxisUnit, latencyDistribution, latencySamples, requestsInWindow, slowestBucket, sparseLabels, uninspectedSeries, type LatencyDistribution, type LatencySamples } from '@/src/utils/trafficMetrics';
import { UNINSPECTED_LABEL, inspectableCount } from '@/src/utils/overviewMetrics';

const chart = chartColors();
const ko = (input: number) => input.toLocaleString('ko-KR', { maximumFractionDigits: 2 });
const value = (input: number | undefined, suffix = '') => (input === undefined ? '확인 불가' : `${ko(input)}${suffix}`);
const percent = formatTrafficRate;
const unitWord = (period: OverviewPeriod) => (period === '24H' ? '1시간' : '1일');
/** 작은 막대 그림 눈금: 24시간은 '13시', 7·30일은 '10.12'(한국 시간). 긴 날짜·시각은 잘려 '10. 12.'만 보였다(전체 시각은 막대 툴팁) */
const shortBucketLabel = (start: number, period: OverviewPeriod) => {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('ko-KR', { timeZone: 'Asia/Seoul', month: 'numeric', day: 'numeric', hour: 'numeric', hourCycle: 'h23' }).formatToParts(new Date(start)).map(part => [part.type, part.value]));
  return period === '24H' ? `${Number(parts.hour)}시` : `${parts.month}.${parts.day}`;
};
/** P95 이름(2026-10-14): 제목에 무엇을 재는지 풀어 쓰고 용어는 괄호로 */
const P95_LABEL = '느린 5% 요청의 처리 시간 (P95)';

// 트래픽 및 성능(재설계 3c → 2026-10-14 지표 정리). 피드백 "산정 기준이 모호, 요청 수 띠는 뭘 말하는지 안 보임"으로 화면을 두 묶음으로 나눴다:
//  ① 지금 Gateway: 상태 띠 + 지표 4칸. Gateway 실시간 값(시작 이후 누적·최근 60초)이라 위 기간 선택과 무관 — 묶음 머리에 그렇게 적고, 카드마다 분모를 보조 줄에 적는다
//  ② 선택 기간 저장 기록: 시간대별 처리 시간(막대) · 처리 시간별 요청 수 · 검사 못 한 요청. 묶음 머리에 이벤트 수·처리 시간 기록 수(두 그림의 표본 수와 같음)
// 요청 수 띠(옛 ③)는 뺐다: 같은 수는 보안 현황 이벤트 추이에 있고, 처리 시간 막대의 툴팁에 '요청 n건 · 처리 시간 기록 m건'으로 합쳤다.
// 서버·API 호출·경로는 그대로(같은 응답으로 계산, utils/trafficMetrics.ts).
export function TrafficPerformancePage() {
  const location = useLocation();
  const navigate = useNavigate();
  // 옛 '성능 검증' 탭 주소로 들어오면 주소에서 #performance만 지운다(화면은 처음부터 요청 모니터링)
  useEffect(() => {
    if (location.hash === '#performance') navigate({ pathname: location.pathname, search: location.search }, { replace: true });
  }, [location.hash, location.pathname, location.search, navigate]);
  const [period, setPeriod] = useOverviewPeriod();
  const query = useQuery({
    ...liveQueryOptions,
    queryKey: trafficKeys.snapshot(period),
    queryFn: ({ signal }) => trafficService.getSnapshot(period, signal),
  });
  // 연결 중인 IP(2026-10-12): 조회 기간과 무관, 같은 10초 자동 갱신
  const clientsQuery = useQuery({
    ...liveQueryOptions,
    queryKey: trafficKeys.clients(),
    queryFn: ({ signal }) => trafficService.getClients(signal),
  });
  // 처리 시간별 요청 수의 '~설정'·'넘음' 경계(Gateway 처리 설정의 검사 대기 시간). 자동 갱신 없이 열 때·새로고침 때만
  const settings = useQuery({ queryKey: gatewaySettingsKeys.detail(), queryFn: ({ signal }) => gatewaySettingsService.get(signal), staleTime: 60_000, retry: false });
  const control = <PgPeriod label="트래픽 조회 기간" value={period} onChange={setPeriod} />;
  if (query.isLoading)
    return <div className="pg-screen pg-tr traffic-console"><PgPageHeader title="트래픽 및 성능" period={control} /><PgSkeleton shape="kpi-table" /></div>;
  if (!query.data || !canRetainQueryData(query.error))
    return <div className="pg-screen pg-tr traffic-console"><PgPageHeader title="트래픽 및 성능" period={control} /><PgError message="트래픽 백엔드에 연결할 수 없습니다." error={query.error} onRetry={() => query.refetch()} /></div>;

  const data = query.data;
  const unavailable = data.unavailableSections ?? [];
  const sectionLabels: Record<string, string> = { summary: '요약 지표', timeseries: '시간별 추이' };
  const empty = !data.timeSeries.length && data.summary.metricSource !== 'GATEWAY_LIVE' && unavailable.length === 0;
  const storedEvents = data.summary.metricSource === 'STORED_EVENTS';
  const liveMetrics = data.summary.metricSource === 'GATEWAY_LIVE';
  const gatewayHealth = gatewayHealthExplanation(data.summary);
  const level: StripLevel = !liveMetrics ? 'unknown' : gatewayHealth.label === '정상' || gatewayHealth.label === '요청 대기' ? 'ok' : gatewayHealth.label === '확인 불가' ? 'unknown' : 'warn';
  const timeout = settings.data?.settings.timeout;
  const samples = data.periodEvents ? latencySamples(data.periodEvents) : undefined;
  return (
    <div className="pg-screen pg-tr traffic-console">
      <PgPageHeader title="트래픽 및 성능" period={control}
        refresh={<PgRefresh updatedAt={query.dataUpdatedAt} fetching={query.isFetching} failed={query.isError} onRefresh={() => { void query.refetch(); void clientsQuery.refetch(); void settings.refetch(); }} />} />
      {query.isError && <p className="pg-stale" role="status">갱신 실패 · 아래는 마지막 성공 조회 결과입니다.</p>}
      <div className="pg-tr-workspace traffic-monitor-workspace">
        <PgStatusStrip level={level} label="Gateway 상태"
          word={<><span className="pg-strip-subject">Gateway</span> {gatewayHealth.label}</>}
          facts={liveMetrics ? [
            <span key="n" title="LLM 사이트로 간 HTTP 요청 전체(화면 로딩·이미지·폴링 포함) · 질문 수가 아님">시작 이후 LLM 사이트 요청 {value(data.summary.gatewayTotalRequests)}건(화면 로딩 포함) · 완료 {value(data.summary.gatewayCompletedRequests)}건{data.summary.gatewayInspectedRequests !== undefined ? <> · 검사 요청 {value(data.summary.gatewayInspectedRequests)}건</> : null} · {gatewayErrorText(data.summary)}</span>,
            gatewayHealth.label === '요청 대기' && <span key="w">지표 연결 정상 · 완료 요청 없음</span>,
          ] : [<span key="s">{trafficSourceLabel(data.summary)} · 과거 이벤트로 현재 상태를 추정하지 않음</span>]}
          end={data.summary.gatewayMetricsReceivedAt && <time dateTime={data.summary.gatewayMetricsReceivedAt} title={formatDateTime(data.summary.gatewayMetricsReceivedAt)}>실시간 수신 {formatDateTime(data.summary.gatewayMetricsReceivedAt).replace(/^.*\.\s/, '').replace(/\sGMT.*$/, '')}</time>} />
        {!query.isError && unavailable.length === 0 && storedEvents && data.summary.eventCount === 0 && <EmptyPeriodHint period={period} onExpand={() => setPeriod('30D')} />}
        {unavailable.length > 0 && <div className="partial-data-warning" role="status"><PgError variant="inline" message={`일부 조회 실패: ${unavailable.map(section => sectionLabels[section] ?? section).join(' · ')}. 조회에 성공한 영역은 계속 표시합니다.`} /></div>}
        {empty ? <PgEmpty title="트래픽 지표가 없습니다." description="Gateway가 트래픽 데이터를 제공하면 이 화면에 표시됩니다." /> : <>
          <section className="pg-tr-group" aria-labelledby="pg-tr-now-title">
            <header className="pg-tr-group-head">
              <h2 id="pg-tr-now-title">{liveMetrics ? '지금 Gateway' : storedEvents ? `Gateway 지표 · ${PERIOD_LABELS[period]} 저장 기록` : 'Gateway 지표'}</h2>
              <span className="pg-muted">{liveMetrics ? '실시간 · Gateway 시작 이후 누적 · 위 기간 선택과 무관' : storedEvents ? '실시간 지표를 받지 못해 저장 기록으로 셈' : '지표 출처 미확인'}</span>
            </header>
            <TrafficKpis data={data} period={period} />
            <MetricBasis data={data} period={period} />
          </section>
          <section className="pg-tr-group" aria-labelledby="pg-tr-period-title">
            <header className="pg-tr-group-head">
              <h2 id="pg-tr-period-title">{PERIOD_LABELS[period]} 저장 기록</h2>
              <span className="pg-muted">{samples
                ? <>질문·파일 검사 기록(보안 이벤트) <b>{ko(samples.events)}건</b>{data.summary.accessBlocked !== undefined ? ` (접속 차단 ${ko(data.summary.accessBlocked)}건 제외)` : ''} · 그중 처리 시간 기록 <b>{ko(samples.samples)}건</b> (프롬프트 {ko(samples.prompt)} · 파일 {ko(samples.file)})</>
                : '기간 이벤트 목록을 읽지 못함'}</span>
            </header>
            <div className="pg-grid-2-1 pg-tr-charts">
              <LatencyTrendCard data={data} period={period} samples={samples} />
              <DistributionCard data={data} prompt={timeout?.prompt.seconds} file={timeout?.file.seconds} settingsFailed={settings.isError} />
            </div>
            <UninspectedCard data={data} period={period} />
          </section>
        </>}
        <TrafficClientsManager data={canRetainQueryData(clientsQuery.error) ? clientsQuery.data : undefined} loading={clientsQuery.isLoading} error={clientsQuery.error} onRetry={() => clientsQuery.refetch()} />
      </div>
    </div>
  );
}

/** 지표 카드 1칸: 이름(무엇을 재는지) → 값 → 보조 1줄(분모·기준). 설명(산정 기준)은 title과 화면 읽기 프로그램용 글로 */
function TrafficKpi({ label, metric, sub, description, tone }: { label: string; metric: string; sub?: ReactNode; description: string; tone?: 'mask' }) {
  return <article className={`pg-kpi traffic-kpi${tone ? ` pg-kpi--${tone}` : ''}`} title={description}>
    <span className="pg-kpi-label">{label}</span>
    <span className="pg-kpi-value">{metric}</span>
    {sub && <span className="pg-kpi-sub">{sub}</span>}
    <p className="sr-only">{description}</p>
  </article>;
}

/** 카드 이름·분모 문구. 실시간(Gateway 시작 이후)과 저장 기록(선택 기간)은 같은 칸이라도 세는 대상이 달라 이름을 따로 쓴다.
 * 2026-10-15 감사: 실시간 비율의 분모는 새 Gateway가 보내는 '검사 요청'(질문·파일 업로드), 옛 Gateway는 LLM 사이트 요청 전체(화면 로딩 포함)라 그렇게 적는다.
 * 저장 기록은 접속 차단(내용 검사 전 거부)을 뺀 기록(새 서버). '최근 1분 요청'은 LLM 사이트 요청(화면 로딩 포함)이라 이름에 밝힌다 */
function kpiText(data: TrafficSnapshot, period: OverviewPeriod) {
  const summary = data.summary;
  const live = summary.metricSource === 'GATEWAY_LIVE';
  const stored = summary.metricSource === 'STORED_EVENTS';
  const inspected = summary.gatewayInspectedRequests;
  const total = live ? inspected ?? summary.gatewayTotalRequests : stored ? summary.eventCount : undefined;
  const accessNote = stored && summary.accessBlocked !== undefined ? ' · 접속 차단 제외' : '';
  const denominator = live
    ? inspected !== undefined ? `시작 이후 검사한 요청 ${value(inspected)}건 중` : `시작 이후 LLM 사이트 요청 ${value(total)}건 중(화면 로딩 포함)`
    : stored ? `${PERIOD_LABELS[period]} 보안 이벤트 ${value(total)}건 중${accessNote}` : '분모 미확인';
  const liveBase = inspected !== undefined ? 'Gateway 시작 이후 검사 요청(질문·파일 업로드)' : 'Gateway 시작 이후 LLM 사이트 요청 전체(화면 로딩 포함, 옛 Gateway)';
  const window = live ? summary.gatewayWindowSeconds : stored ? 60 : undefined;
  const recent = requestsInWindow(summary.requestsPerSec, window);
  const windowText = window !== undefined && window % 60 === 0 ? `${window / 60}분` : `${window}초`;
  const recentText = recent === undefined ? `초당 ${value(summary.requestsPerSec)}건` : live ? `최근 ${windowText} LLM 사이트 요청 ${ko(recent)}건(화면 로딩 포함)` : `최근 ${windowText} 기록 ${ko(recent)}건`;
  return {
    timeoutLabel: live ? '연결 시간 초과' : stored ? '검사 대기 시간 초과' : '시간 초과 비율',
    timeoutBasis: live ? `연결이 시간 초과 오류로 끝난 요청 ÷ ${liveBase}. 보안 검사 대기 시간 초과는 '보안 검사 응답 없음'에 셈`
      : stored ? `검사 대기 시간을 넘겨 검사하지 못한 이벤트 ÷ ${PERIOD_LABELS[period]} 보안 이벤트${accessNote}` : '출처 미확인',
    degradedBasis: live ? `Detection이 대기 시간 안에 답하지 않았거나 연결되지 않은 요청 ÷ ${liveBase}`
      : stored ? `검사 응답 없음(대기 시간 초과 포함)으로 기록된 이벤트 ÷ ${PERIOD_LABELS[period]} 보안 이벤트${accessNote}` : '출처 미확인',
    denominator,
    recentText,
    clientsLabel: live ? '응답 대기 중인 요청' : '최근 5분 활동한 확장 프로그램',
    inspectedZero: live && inspected === 0,
  };
}

/** 처리 시간 표본 수 글(2026-10-15 감사 1·2번): 실시간은 새 Gateway가 보내는 표본 수(검사·판정한 요청), 옛 Gateway는 알 수 없음 */
function latencySampleText(live: boolean, count: number | undefined) {
  if (live) return count === undefined ? 'Gateway가 검사한 요청 기준 · 표본 수 알 수 없음' : `표본 ${ko(count)}건(Gateway가 검사한 요청)`;
  return `처리 시간 기록 ${count === undefined ? '건수 미확인' : `${ko(count)}건`}`;
}

function TrafficKpis({ data, period }: { data: TrafficSnapshot; period: OverviewPeriod }) {
  const summary = data.summary;
  const storedEvents = summary.metricSource === 'STORED_EVENTS';
  const liveMetrics = summary.metricSource === 'GATEWAY_LIVE';
  const text = kpiText(data, period);
  const latencyCount = summary.latencySampleCount;
  // 실시간 표본 수는 새 Gateway만 보낸다(서버가 그 값만 싣고, 옛 Gateway면 칸이 없음). 0이면 '기록 없음'(0초가 아님), 1~19건이면 '20건 미만'
  const fewSamples = latencyCount !== undefined && latencyCount > 0 && latencyCount < FEW_SAMPLES;
  const noSamples = latencyCount === 0;
  const liveUnmeasured = liveMetrics && summary.gatewayCompletedRequests === 0;
  // 백엔드가 실시간 평균·P95를 뺀 경우(이전 판 Gateway 값은 LLM 응답 시간까지 잼) — 0건 대기보다 먼저 본다
  const latencyWithheld = liveMetrics && summary.latencyUnavailableReason === 'LEGACY_GATEWAY';
  const latencyText = (ms?: number) => (latencyWithheld ? '확인 불가' : noSamples ? '기록 없음' : liveUnmeasured ? '아직 측정 없음' : formatLatency(ms));
  // 검사 요청이 0건이면 0%가 아니라 '검사 요청 없음'(분모 0, Gateway 계약 2절)
  const rateText = (rate?: number) => (liveUnmeasured ? '아직 측정 없음' : text.inspectedZero ? '검사 요청 없음' : storedEvents && summary.eventCount === 0 ? '기록 없음' : percent(rate));
  const latencyScope = liveMetrics || storedEvents ? latencySampleText(liveMetrics, latencyCount) : '출처 미확인';
  const latencyDescription = latencyWithheld ? GATEWAY_PROCESSING_UNCONFIRMED
    : `요청 95%가 이 시간 안에 처리됨 · ${latencyScope}${fewSamples ? ' · 20건 미만이라 가장 긴 값과 같음' : ''} · 처리 시간 = 요청 수신부터 LLM 전달·차단까지(LLM 응답 시간 제외)`;
  const clientsDescription = liveMetrics ? '이 순간 응답을 기다리는 요청 수(LLM 답변 스트리밍·오래 열린 연결·화면 로딩 포함)와 그 IP 수 · 최근 1분 LLM 사이트 요청 = 최근 60초에 받은 HTTP 요청 수(화면 로딩 포함, 질문 수가 아님)'
    : `최근 5분 이벤트의 확장 프로그램 ID 수${summary.clientIdentityIncomplete ? ' · ID 없는 요청 제외' : ''} · 최근 1분 기록 = 최근 60초 이벤트 수`;
  return <section className="pg-kpi-group pg-tr-kpis" aria-label="Gateway 지표">
    <TrafficKpi label={P95_LABEL} metric={latencyText(summary.p95LatencyMs)} description={latencyDescription}
      sub={<>평균 <b>{latencyText(summary.averageLatencyMs)}</b>{!latencyWithheld && (storedEvents || liveMetrics) && <> · {latencyScope}{fewSamples ? ' · 20건 미만' : ''}</>}</>} />
    <TrafficKpi label={text.timeoutLabel} metric={rateText(summary.timeoutRate)} description={text.timeoutBasis} sub={text.denominator} tone={summary.timeoutRate && summary.timeoutRate > 0 ? 'mask' : undefined} />
    <TrafficKpi label="보안 검사 응답 없음" metric={rateText(summary.degradedRate)} description={text.degradedBasis} sub={text.denominator} tone={summary.degradedRate && summary.degradedRate > 0 ? 'mask' : undefined} />
    {liveMetrics
      ? <TrafficKpi label={text.clientsLabel} metric={value(summary.concurrentRequests, '건')} description={clientsDescription}
        sub={<>응답 대기 IP <b>{value(summary.activeClients, '개')}</b> · {text.recentText}</>} />
      : <TrafficKpi label={text.clientsLabel} metric={value(summary.activeClients, '개')} description={clientsDescription}
        sub={<>{text.recentText}{summary.clientIdentityIncomplete ? ' · ID 없는 요청 제외' : ''}</>} />}
  </section>;
}

/** 지표 4칸의 산정 기준(접힘). 카드 보조 줄에 다 못 쓰는 정의를 한곳에 */
function MetricBasis({ data, period }: { data: TrafficSnapshot; period: OverviewPeriod }) {
  const summary = data.summary;
  const live = summary.metricSource === 'GATEWAY_LIVE';
  const text = kpiText(data, period);
  return <details className="pg-tr-basis" id="monitoring">
    <summary>산정 기준</summary>
    <dl>
      <div><dt>{P95_LABEL}</dt><dd>{live
        ? `Gateway가 시작된 뒤 검사·판정한 요청(최근 최대 5,000건)의 처리 시간을 짧은 순으로 놓았을 때 95% 지점. 100건이면 5번째로 느린 요청의 시간. 처리 시간 = 요청 수신부터 LLM 전달·차단까지(LLM 응답 시간 제외). ${summary.latencySampleCount === undefined ? '표본 수는 이 Gateway가 보내지 않음.' : `표본 ${ko(summary.latencySampleCount)}건(20건 미만이면 가장 긴 값과 같음, 0건이면 기록 없음).`}`
        : `${PERIOD_LABELS[period]} 보안 이벤트 중 처리 시간 기록이 있는 건의 95% 지점(20건 미만이면 가장 긴 값과 같음). 처리 시간 = 요청 수신부터 LLM 전달·차단까지(LLM 응답 시간 제외).`}</dd></div>
      <div><dt>{text.timeoutLabel}</dt><dd>{text.timeoutBasis}.</dd></div>
      <div><dt>보안 검사 응답 없음</dt><dd>{text.degradedBasis}.</dd></div>
      <div><dt>{text.clientsLabel}</dt><dd>{live ? '이 순간 응답을 기다리는 요청 수(LLM 답변 스트리밍·오래 열린 연결·화면 로딩 포함)와 그 요청을 보낸 IP 수. 최근 1분 LLM 사이트 요청 = 최근 60초에 받은 HTTP 요청 수(화면 로딩 포함).' : `최근 5분 이벤트의 확장 프로그램 ID 수(ID 없는 요청 제외). 최근 1분 기록 = 최근 60초 이벤트 수.`}</dd></div>
      <div><dt>{live ? 'LLM 사이트 요청' : '왜 저장 기록인가'}</dt><dd>{live
        ? `LLM 사이트로 간 HTTP 요청 전체(화면 로딩·이미지·폴링 포함)라 아래 보안 이벤트 수보다 많음. ${summary.gatewayInspectedRequests !== undefined ? '그중 보안 검사를 거친 요청(질문·파일 업로드)이 비율의 분모. ' : ''}Gateway를 다시 켜면 0부터 다시 셈. 30초 안에 받은 실시간 값만 씀.`
        : trafficSourceDescription(summary)}</dd></div>
    </dl>
  </details>;
}

type TrendRow = EventTimeBucket & { average?: number; p95?: number; samples?: number };

/** 시간대별 처리 시간 막대의 툴팁: 시각 · 느린 5% · 평균 · 요청 수 · 처리 시간 기록 수(옛 요청 수 띠의 값) */
function TrendTooltip({ active, payload, period }: { active?: boolean; payload?: ReadonlyArray<{ payload?: TrendRow }>; period: OverviewPeriod }) {
  const row = payload?.[0]?.payload;
  if (!active || !row) return null;
  return <div className="recharts-default-tooltip" style={{ padding: 10, background: chartColor('tooltipBackground'), border: `1px solid ${chartColor('tooltipBorder')}`, color: chartColor('tooltipText'), fontSize: 12 }}>
    <p>{bucketLabel(row.start, period, true)} · GMT+9{row.partial ? ' · 부분 구간' : ''}</p>
    <p>느린 5% (P95) <b>{formatLatency(row.p95LatencyMs)}</b> · 평균 {formatLatency(row.averageLatencyMs)}</p>
    <p>요청 {ko(row.total)}건{row.samples !== undefined && <> · 처리 시간 기록 {ko(row.samples)}건{row.samples > 0 && row.samples < FEW_SAMPLES ? ' (20건 미만 = 가장 긴 값)' : ''}</>}</p>
  </div>;
}

/** 시간대별 처리 시간: 구간마다 막대 1개 = 그 구간 느린 5%(P95). 점 몇 개뿐인 선 대신 막대(외딴 구간도 보임), 기록 없는 구간은 막대 없음(0초로 만들지 않음) */
function LatencyTrendCard({ data, period, samples }: { data: TrafficSnapshot; period: OverviewPeriod; samples?: LatencySamples }) {
  const series = data.visualization;
  const points = series?.issues.length ? [] : series?.buckets ?? [];
  const counts = data.periodEvents ? bucketSamples(data.periodEvents, points) : undefined;
  const measured = points.some(point => point.p95LatencyMs !== undefined);
  const maxMs = Math.max(0, ...points.map(point => point.p95LatencyMs ?? 0));
  const unit = measured ? latencyAxisUnit(maxMs) : '초';
  const scale = unit === 'ms' ? 1 : 1 / 1000;
  const rows: TrendRow[] = points.map((point, index) => ({ ...point, samples: counts?.[index], average: point.averageLatencyMs === undefined ? undefined : point.averageLatencyMs * scale, p95: point.p95LatencyMs === undefined ? undefined : point.p95LatencyMs * scale }));
  const slowest = slowestBucket(rows);
  const xTick = (stamp: unknown) => bucketLabel(Date.parse(String(stamp)), period);
  return <section className="pg-card pg-tr-trend" aria-labelledby="pg-tr-trend-title">
    <header className="pg-card-head">
      <h3 id="pg-tr-trend-title" className="pg-card-title">{period === '24H' ? '시간대별' : '날짜별'} 처리 시간</h3>
      <span className="pg-card-note pg-card-head-end">느린 5% (P95) · {unitWord(period)} 단위</span>
    </header>
    <div className="pg-card-body">
      {series?.issues.length ? <PgError variant="inline" message={`차트 정합성 확인 필요 · ${series.issues.join(' ')}`} /> : null}
      {data.unavailableSections?.includes('timeseries') ? <PgEmpty title="시간별 추이를 불러오지 못했습니다." /> : series?.issues.length ? null : !measured ? <PgEmpty title={`${PERIOD_LABELS[period]} 동안 처리 시간 기록이 없습니다.`} /> : <>
        <p className="pg-tr-meaning">막대 = 그 {period === '24H' ? '시간' : '날'}에 처리된 요청 중 <b>느린 5%의 처리 시간</b>. 막대가 없으면 기록 없음.</p>
        {slowest && <p className="pg-tr-headline">가장 느린 {period === '24H' ? '시간' : '날'} <b>{bucketLabel(slowest.start, period)}</b> · <b>{formatLatency(slowest.p95LatencyMs)}</b> {slowest.samples !== undefined && <span className="pg-muted">(처리 시간 기록 {ko(slowest.samples)}건{slowest.samples < FEW_SAMPLES && !(samples && samples.samples < FEW_SAMPLES) ? ' · 20건 미만이라 가장 긴 값' : ''})</span>}</p>}
        {samples && samples.samples < FEW_SAMPLES && <p className="pg-tr-few" role="note">처리 시간 기록이 {ko(samples.samples)}건뿐이라 경향을 판단하기 이릅니다(20건 미만이면 P95 = 가장 긴 값).</p>}
        <div className="pg-tr-chart traffic-chart" role="img" aria-label={`${unitWord(period)} 단위 느린 5% 처리 시간: ${rows.filter(row => row.p95LatencyMs !== undefined).map(row => `${bucketLabel(row.start, period)} ${formatLatency(row.p95LatencyMs)}`).join(', ')}`}>
          <BarChart responsive data={rows} style={{ width: '100%', height: '100%' }} margin={{ top: 8, right: 12, left: 0, bottom: 0 }} barCategoryGap="20%">
            <CartesianGrid vertical={false} stroke={chart.grid} />
            <XAxis dataKey="timestamp" tickFormatter={xTick} interval="preserveStartEnd" minTickGap={32} tick={{ fontSize: CHART_TICK_FONT_SIZE, fill: chart.axis }} axisLine={false} tickLine={false} />
            <YAxis width={52} domain={[0, 'auto']} unit={unit === 'ms' ? ' ms' : '초'} tickFormatter={amount => Number(amount).toLocaleString('ko-KR', { maximumFractionDigits: unit === 'ms' ? 0 : 2 })} tick={{ fontSize: CHART_TICK_FONT_SIZE, fill: chart.axis }} axisLine={false} tickLine={false} />
            <Tooltip cursor={{ fill: chart.cursor }} content={<TrendTooltip period={period} />} />
            <Bar dataKey="p95" name="느린 5% (P95)" fill={chart.info} maxBarSize={24} isAnimationActive={false} />
          </BarChart>
        </div>
        {series?.boundaryBucket && <p className="pg-muted">조회 시작의 부분 시간 구간도 포함합니다.</p>}
      </>}
    </div>
    <footer className="pg-card-foot"><span>처리 시간 = 요청 수신부터 LLM 전달·차단까지(LLM 응답 시간 제외) · LLM 응답 시간이 섞인 옛 기록은 뺌 · 막대에 마우스를 올리면 요청 수</span></footer>
  </section>;
}

function Distribution({ title, result, limitSeconds }: { title: string; result: LatencyDistribution; limitSeconds?: number }) {
  const limitBin = result.bins.find(bin => bin.limit);
  return <div className="pg-tr-dist">
    <p className="pg-tr-dist-head"><b>{title} {ko(result.samples)}건</b><span className="pg-muted">{result.p95Ms !== undefined ? `느린 5% ${formatLatency(result.p95Ms)} · ` : ''}{limitSeconds !== undefined ? `대기 시간 ${ko(limitSeconds)}초 넘음 ${ko(result.overCount)}건` : '대기 시간 확인 불가'}{result.samples > 0 && result.samples < FEW_SAMPLES ? ' · 20건 미만' : ''}</span></p>
    <PgMiniBars label={`${title} 처리 시간 분포`} height={72} limitAfter={limitSeconds !== undefined ? limitBin?.key : undefined} limitLabel={limitSeconds !== undefined ? `대기 ${limitSeconds}초` : undefined}
      bars={result.bins.map((bin, index) => ({ key: bin.key, label: bin.label, value: bin.count, tone: bin.over && bin.count > 0 ? 'mask' : 'info',
        title: `${bin.over ? `${result.bins[index - 1]?.label.replace('~', '') ?? ''} 넘음` : `${index > 0 ? `${result.bins[index - 1].label.replace('~', '')} 초과 ` : ''}${bin.label.replace('~', '')} 이하`} · ${ko(bin.count)}건` }))} />
  </div>;
}

/** 처리 시간별 요청 수(프롬프트·파일 따로, 같은 7구간) — 검사 대기 시간 설정을 줄일지·늘릴지 */
function DistributionCard({ data, prompt, file, settingsFailed }: { data: TrafficSnapshot; prompt?: number; file?: number; settingsFailed: boolean }) {
  const events = data.periodEvents;
  const promptResult = events && latencyDistribution(events, 'prompt', prompt);
  const fileResult = events && latencyDistribution(events, 'file', file);
  const longest = Math.max(promptResult?.maxMs ?? 0, fileResult?.maxMs ?? 0);
  return <section className="pg-card pg-tr-dist-card" aria-labelledby="pg-tr-dist-title">
    <header className="pg-card-head"><h3 id="pg-tr-dist-title" className="pg-card-title">처리 시간별 요청 수</h3><span className="pg-card-note pg-card-head-end">프롬프트·파일 따로</span></header>
    <div className="pg-card-body">
      {!events || !promptResult || !fileResult ? <PgError variant="inline" message="기간 이벤트 목록을 읽지 못해 계산하지 못함" />
        : promptResult.samples + fileResult.samples === 0 ? <PgEmpty title="처리 시간 기록이 없습니다." />
          : <>
            <p className="pg-tr-meaning">막대 = 처리 시간 구간별 요청 수(~10ms = 10ms 이하) · 주황 점선 = 검사 대기 시간 설정</p>
            <Distribution title="프롬프트" result={promptResult} limitSeconds={prompt} />
            <Distribution title="파일" result={fileResult} limitSeconds={file} />
          </>}
    </div>
    <footer className="pg-card-foot">
      <span>{longest > 0 ? `가장 긴 처리 ${formatLatency(longest)}` : '처리 시간 기록 있는 요청만'}{settingsFailed ? ' · 대기 시간 설정을 불러오지 못함' : ''}</span>
      <Link className="pg-card-head-end" to="/policies/gateway">대기 시간 설정<span aria-hidden="true"> ›</span></Link>
    </footer>
  </section>;
}

/** 검사 못 한 요청(시간대별 막대 + 사유 배지) — Detection 점검·증설이 필요한지, 몰리는 시간 */
function UninspectedCard({ data, period }: { data: TrafficSnapshot; period: OverviewPeriod }) {
  const events = data.periodEvents;
  const buckets = data.visualization?.issues.length ? [] : data.visualization?.buckets ?? [];
  const result = events && buckets.length ? uninspectedSeries(events, buckets) : undefined;
  const accessInList = data.summary.accessBlocked ?? (events ? events.length - inspectableCount(events) : 0);
  const labels = sparseLabels(buckets.map(bucket => shortBucketLabel(bucket.start, period)));
  return <section className="pg-card pg-tr-uninspected" aria-labelledby="pg-tr-uninspected-title">
    <header className="pg-card-head">
      <h3 id="pg-tr-uninspected-title" className="pg-card-title">검사 못 한 요청</h3>
      {result && <span className="pg-card-head-end pg-tr-reasons">
        {(Object.keys(result.byKind) as Array<keyof typeof result.byKind>).map(kind => <PgBadge key={kind} tone={result.byKind[kind] > 0 ? 'mask' : 'neutral'}>{UNINSPECTED_LABEL[kind]} {result.byKind[kind]}</PgBadge>)}
      </span>}
    </header>
    <div className="pg-card-body">
      {!result ? <PgError variant="inline" message="기간 이벤트 목록을 읽지 못해 계산하지 못함" />
        : result.total === 0 ? <PgEmpty title={`${PERIOD_LABELS[period]} 동안 검사 못 한 요청 없음`} />
          : <>
            <p className="pg-tr-meaning"><b>{PERIOD_LABELS[period]} {ko(result.total)}건</b> · 막대 = 그 {period === '24H' ? '시간' : '날'}에 검사 없이 전달·차단된 요청 수</p>
            <PgMiniBars label={`${unitWord(period)} 단위 검사 못 한 요청`} height={96} bars={result.buckets.map((bucket, index) => ({ key: bucket.key, label: labels[index], value: bucket.total, tone: 'mask', title: `${bucketLabel(bucket.start, period, true)} · ${ko(bucket.total)}건` }))} />
          </>}
    </div>
    <footer className="pg-card-foot">
      {/* 2026-10-15 감사 8·9번: 분모도 분자처럼 접속 차단을 뺀 수. 이벤트 목록의 '검사 결과 없음' 조건에는 접속 차단도 들어 있어 그 수를 링크 앞에 적는다 */}
      <span>{events ? `${PERIOD_LABELS[period]} 보안 이벤트 ${ko(inspectableCount(events))}건 중(접속 차단 제외)` : '저장 기록 기준'} · 위 '보안 검사 응답 없음' 비율과 기준(기간·대상)이 다름{accessInList ? ` · 해당 이벤트 목록에는 접속 차단 ${ko(accessInList)}건도 함께 나옴` : ''}</span>
      <Link className="pg-card-head-end" to={`/events?period=${period}&detectionOutcome=UNAVAILABLE`}>해당 이벤트<span aria-hidden="true"> ›</span></Link>
    </footer>
  </section>;
}
