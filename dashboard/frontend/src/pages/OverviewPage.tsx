import { useQuery } from '@tanstack/react-query';
import { Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis } from 'recharts';
import { Link, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { dashboardService } from '@/src/services/dashboardService';
import { documentService } from '@/src/services/documentService';
import { detectionOpsKeys, detectionOpsService } from '@/src/services/detectionOpsService';
import { gatewaySettingsKeys, gatewaySettingsService } from '@/src/services/gatewaySettingsService';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { PgEmpty, PgError, PgHBars, PgPageHeader, PgPeriod, PgRefresh, PgSkeleton, PgSplitBar, PERIOD_LABELS } from '@/src/components/pg';
import { KpiMetric, OverviewRecentTable, RecordStatusBar } from '@/src/components/OverviewPanels';
import { InsightsSection, percent } from '@/src/components/OverviewInsights';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { dashboardKeys, documentKeys } from '@/src/queries/keys';
import type { DashboardStats, OverviewPeriod } from '@/src/types/event';
import { uiMode } from '@runtime/ui-mode';
import { useOverviewPeriod } from '@/src/utils/useOverviewPeriod';
import { bucketLabel, integerCountAxis } from '@/src/utils/eventSeries';
import { EventBucketTooltip } from '@/src/components/EventBucketTooltip';
import { CHART_TICK_FONT_SIZE, chartColors } from '@/src/utils/chartColors';
import { actionReasons, COVERAGE_LABEL, inspectableCount, protectionCoverage, settingSummary, uninspectedRequests } from '@/src/utils/overviewMetrics';

const chart = chartColors();
const RECENT_LIMIT = 6;
const ko = (value: number) => value.toLocaleString('ko-KR');
// 접은 기록(2026-10-16 공통 규칙): 새 서버는 파일 재전송·질문 재시도를 나눠 준다. 옛 서버는 파일 재전송만 있었다
const foldedText = (counting: NonNullable<DashboardStats['counting']>) => counting.resendPrompt === undefined
  ? `10/11 전 파일 재전송 ${ko(counting.resendFolded)}건`
  : [counting.resendFile ? `10/11 전 파일 재전송 ${ko(counting.resendFile)}건` : '', counting.resendPrompt ? `같은 질문 재시도 ${ko(counting.resendPrompt)}건` : ''].filter(Boolean).join(' · ');

// 보안 현황(재설계 3b, 설계 5.1·목업 overview.html): 머리(기간·갱신) → 상태 띠 → 지표 4칸(전체 카드에 차단·마스킹·허용 비율 막대)
// → [이벤트 추이 2/3 · 최근 이벤트 1/3] → [검사 없이 처리된 요청 ② · 보호 범위 ③] → 탐지 분석([차단·마스킹 사유 ① · 정보 유형] …).
// 추가 지표 ①②③은 서버 변경 없이 기존 응답으로 계산한다(utils/overviewMetrics.ts). 선택 지표 ④⑤는 하지 않음(사용자 결정 ⑤).
export function OverviewPage() {
  const navigate = useNavigate();
  const [period, setPeriod] = useOverviewPeriod();
  const query = useQuery({
    ...liveQueryOptions,
    queryKey: dashboardKeys.stats(period),
    queryFn: ({ signal }) => dashboardService.getStats(period, signal),
  });
  // ②의 지금 설정 1줄 · ③ 보호 범위: 문서 목록 조회가 Detection 지문 조회를 함께 부르므로 10초 자동 갱신에서 빼고 열 때·새로고침 때만(설계 5.1.1 ③)
  const settings = useQuery({ queryKey: gatewaySettingsKeys.detail(), queryFn: ({ signal }) => gatewaySettingsService.get(signal), staleTime: 60_000, retry: false });
  const documents = useQuery({ queryKey: documentKeys.list(), queryFn: ({ signal }) => documentService.getDocuments(signal), staleTime: 60_000 });
  const keywords = useQuery({ queryKey: detectionOpsKeys.keywords(), queryFn: ({ signal }) => detectionOpsService.getKeywords(signal), staleTime: 60_000, retry: false });
  const jobs = useQuery({ queryKey: detectionOpsKeys.keywordJobs(), queryFn: ({ signal }) => detectionOpsService.getKeywordJobs(signal), staleTime: 60_000, retry: false });
  const refreshAll = () => Promise.all([query.refetch(), settings.refetch(), documents.refetch(), keywords.refetch(), jobs.refetch()]);

  const periodControl = <PgPeriod label="보안 현황 조회 기간" value={period} onChange={setPeriod} />;
  const refresh = <PgRefresh updatedAt={query.dataUpdatedAt} fetching={query.isFetching} failed={query.isError} onRefresh={refreshAll} total={query.data?.total} scope={period}
    recentAt={query.data?.recent.map(event => event.occurredAt)}
    onNew={query.data?.recent.length ? () => navigate(`/events/${encodeURIComponent([...query.data!.recent].sort((a, b) => Date.parse(b.occurredAt) - Date.parse(a.occurredAt))[0].eventId)}`) : undefined} />;
  const header = <PgPageHeader title="보안 현황" period={periodControl} refresh={refresh} />;
  if (query.isLoading) return <div className="pg-screen pg-ov overview-console">{header}<PgSkeleton shape="kpi-table" rows={4} /></div>;
  if (!query.data || !canRetainQueryData(query.error)) return <div className="pg-screen pg-ov overview-console">{header}<PgError message="대시보드 정보를 불러오지 못했습니다." error={query.error} onRetry={() => query.refetch()} /></div>;
  const stats = query.data;
  const series = stats.visualization;
  const countAxis = integerCountAxis(Math.max(0, ...(series?.buckets.map(point => point.total) ?? [])));
  const masks = uiMode.supportedActions.some(action => action === 'MASK');
  const allow = stats.allow ?? Math.max(0, stats.total - stats.block - stats.mask);
  const acted = stats.block + stats.mask;
  const counting = stats.counting;
  // 2026-10-15 숫자 감사: 새 서버는 카드를 요청 단위(목록과 같은 묶음)로, 접속 차단·재전송을 빼고 센다. 옛 서버는 기록 단위·접속 차단 포함
  const unitHint = counting ? ' · 요청 단위(첨부 파일은 프롬프트에 묶음, 보안 이벤트 목록과 같음) · 접속 차단 제외' : '';
  return <div className="pg-screen pg-ov overview-console">
    {header}
    {query.isError && <p role="status" className="pg-stale console-stale-notice">갱신 실패 · 아래는 마지막 성공 조회 결과입니다.</p>}
    <RecordStatusBar stats={stats} stale={query.isError} end={<Link to="/traffic">트래픽 및 성능<span aria-hidden="true"> ›</span></Link>} />
    <section className="pg-kpi-group" aria-label={`${PERIOD_LABELS[period]} 이벤트 집계`}>
      <KpiMetric label="전체 이벤트" value={stats.total} to={`/events?period=${period}`} accessibleLabel="전체 이벤트 목록 보기"
        hint={counting ? `보안 검사를 거친 요청${unitHint} · 민감정보·기밀 검출 = 보호 문서 일치 또는 개인정보·자격증명·기밀 키워드가 검출돼 차단·마스킹한 요청` : undefined}
        sub={counting ? `민감정보·기밀 검출 ${ko(counting.sensitive)}건 · ${percent(counting.sensitive, stats.total)}` : `차단·마스킹 ${ko(acted)}건 · ${percent(acted, stats.total)}`}
        bar={<PgSplitBar label="최종 조치 비율" legend={false} parts={[{ tone: 'block', value: stats.block, name: '차단' }, ...(masks ? [{ tone: 'mask' as const, value: stats.mask, name: '마스킹' }] : []), { tone: 'allow-soft', value: allow, name: '허용' }]} />} />
      <KpiMetric label="전송 차단" value={stats.block} tone="danger" to={`/events?period=${period}&finalAction=BLOCK`} accessibleLabel="전송 차단 목록 보기" hint={`최종 조치가 차단인 저장 이벤트${unitHint} · 실제 집행 증거는 상세에서 확인`}
        sub={counting ? `전체의 ${percent(stats.block, stats.total)} · 접속 차단 ${ko(counting.accessBlocked)}건 별도` : `전체의 ${percent(stats.block, stats.total)} · 목록 보기 ›`} />
      {masks && <KpiMetric label="민감정보 마스킹" value={stats.mask} tone="warning" to={`/events?period=${period}&finalAction=MASK`} accessibleLabel="민감정보 마스킹 목록 보기" hint={`최종 조치가 마스킹인 저장 이벤트${unitHint} · 처리 증거는 상세에서 확인`} sub={`전체의 ${percent(stats.mask, stats.total)} · 목록 보기 ›`} />}
      <KpiMetric label="전송 허용" value={stats.allow} tone="success" to={`/events?period=${period}&finalAction=ALLOW`} accessibleLabel="전송 허용 목록 보기" hint={`최종 조치가 허용인 저장 이벤트${unitHint} · 안전 판정과는 다릅니다`} sub={`전체의 ${percent(allow, stats.total)} · 목록 보기 ›`} />
    </section>
    {counting && <p className="pg-muted pg-ov-unit-note">
      카드 단위 = 요청(첨부 파일은 프롬프트에 묶어 1건, 보안 이벤트 목록과 같음) · 접속 차단 <Link to={`/events?period=${period}&view=access`}>{ko(counting.accessBlocked)}건</Link>은 따로 셈
      {counting.resendFolded > 0 ? ` · ${foldedText(counting)}은 앞 기록 1건으로 접음` : ''}
    </p>}

    <div className="pg-grid-2-1 pg-ov-activity">
      <section className="pg-card pg-ov-trend" aria-labelledby="pg-ov-trend-title">
        <header className="pg-card-head">
          <h2 id="pg-ov-trend-title" className="pg-card-title">이벤트 추이</h2>
          <div className="pg-card-head-end">
            {series?.buckets.length && !series.issues.length && stats.total > 0 ? <ul className="pg-legend" aria-hidden="true"><li><i className="pg-fill--block" />차단</li>{masks && <li><i className="pg-fill--mask" />마스킹</li>}<li><i className="pg-fill--allow-soft" />허용</li></ul> : null}
            <span className="pg-card-note" title="최근 24시간/7×24시간/30×24시간의 API 조회 범위 · GMT+9 날짜/시간 구간">{PERIOD_LABELS[period]} · {period === '24H' ? '시간별' : '일별'} 저장 이벤트</span>
          </div>
        </header>
        <div className="pg-card-body">
          {series?.issues.length ? <PgError variant="inline" message={`차트 정합성 확인 필요 · ${series.issues.join(' ')}`} /> : null}
          {series?.issues.length ? null : stats.total === 0 ? <PgEmpty title="해당 기간에 기록된 이벤트가 없습니다." action={period !== '30D' && <Button variant="outline" size="sm" onClick={() => setPeriod('30D')}>최근 30일 보기</Button>} /> : series?.buckets.length ? <>
            <div className="console-trend-chart pg-ov-chart"><BarChart responsive data={series.buckets} style={{ width: '100%', height: '100%' }} margin={{ top: 12, right: 8, left: -18, bottom: 0 }} barCategoryGap="28%">
              <CartesianGrid vertical={false} stroke={chart.grid} />
              <XAxis dataKey="timestamp" tickFormatter={value => bucketLabel(Date.parse(String(value)), period)} interval="preserveStartEnd" minTickGap={32} tick={{ fontSize: CHART_TICK_FONT_SIZE, fill: chart.axis }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} domain={countAxis.domain} ticks={countAxis.ticks} tick={{ fontSize: CHART_TICK_FONT_SIZE, fill: chart.axis }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: chart.cursor }} content={<EventBucketTooltip period={period} />} />
              <Bar dataKey="block" name="차단" stackId="actions" fill={chart.block} maxBarSize={24} isAnimationActive={false} />
              {masks && <Bar dataKey="mask" name="마스킹" stackId="actions" fill={chart.mask} maxBarSize={24} isAnimationActive={false} />}
              <Bar dataKey="allow" name="허용" stackId="actions" fill={chart.allow} fillOpacity={chart.allowOpacity} maxBarSize={24} isAnimationActive={false} />
            </BarChart></div>
            {series.boundaryBucket && <p className="pg-muted pg-ov-chart-note">조회 시작 시각이 날짜·시간 경계와 달라 시작의 부분 구간도 표시합니다. 해당 기록은 합계에서 제외하지 않습니다.</p>}
          </> : <PgEmpty title="집계 구간 기록이 없습니다." />}
        </div>
      </section>
      <section className="pg-card pg-ov-recent-card" aria-labelledby="pg-ov-recent-title">
        <header className="pg-card-head">
          <h2 id="pg-ov-recent-title" className="pg-card-title">최근 보안 이벤트</h2>
          <Link className="pg-card-head-end pg-card-link" to={`/events?period=${period}`}>전체 이벤트 보기<span aria-hidden="true"> ›</span></Link>
        </header>
        {stats.recent.length ? <OverviewRecentTable events={stats.recent.slice(0, RECENT_LIMIT)} /> : <PgEmpty title="조회된 이벤트가 없습니다." />}
      </section>
    </div>

    <div className="pg-grid-2">
      <UninspectedCard stats={stats} period={period} settings={settings.data?.settings} settingsFailed={settings.isError} />
      <CoverageCard documents={documents} keywords={keywords.data} jobs={jobs.data?.jobs} keywordsFailed={keywords.isError} jobsFailed={jobs.isError} />
    </div>

    {stats.insights
      ? <InsightsSection insights={stats.insights} period={period} recordUnit={Boolean(stats.counting)} lead={<ReasonsCard stats={stats} period={period} />} />
      : <div className="pg-grid-2"><ReasonsCard stats={stats} period={period} /></div>}
  </div>;
}

const notComputed = (stats: DashboardStats) => !stats.periodEvents && <PgError variant="inline" message="기간 이벤트 목록을 읽지 못해 계산하지 못함" />;

/** ① 차단·마스킹 사유(가로 누적 막대 최대 8줄, 줄을 누르면 손볼 설정 화면). 2026-10-14: 기간·합계(= 차단 + 마스킹 카드 수)를 아래 줄에 적음 */
function ReasonsCard({ stats, period }: { stats: DashboardStats; period: OverviewPeriod }) {
  const rows = stats.periodEvents ? actionReasons(stats.periodEvents) : [];
  const total = rows.reduce((sum, row) => sum + row.block + row.mask, 0);
  return <section className="pg-card pg-ov-metric" aria-labelledby="pg-ov-reasons-title">
    <header className="pg-card-head">
      <h2 id="pg-ov-reasons-title" className="pg-card-title">차단·마스킹 사유</h2>
      <ul className="pg-legend pg-card-head-end" aria-hidden="true"><li><i className="pg-fill--block" />차단</li><li><i className="pg-fill--mask" />마스킹</li></ul>
    </header>
    <div className="pg-card-body">
      {notComputed(stats) || (rows.length === 0
        ? <PgEmpty title={`${PERIOD_LABELS[period]} 동안 차단·마스킹 없음`} />
        : <PgHBars label="차단·마스킹 사유별 건수" max={8} rows={rows.map(row => ({ key: row.key, label: row.label, to: row.to, parts: [{ tone: 'block', value: row.block, name: '차단' }, { tone: 'mask', value: row.mask, name: '마스킹' }] }))} />)}
    </div>
    <footer className="pg-card-foot">{stats.periodEvents ? `${PERIOD_LABELS[period]} 차단·마스킹 ${ko(total)}건을 ${stats.counting ? '요청' : '건'}마다 대표 사유 1개로 셈(합 = ${ko(total)}건${stats.counting ? ' = 차단 + 마스킹 카드' : ''})` : '건마다 대표 사유 1개'} · 줄을 누르면 손볼 설정 화면</footer>
  </section>;
}

/** ② 검사 못 한 요청(트래픽 화면 카드와 같은 이름·같은 분류): 큰 숫자(검사 없이 허용된 건수, 0이면 정상 계열) + 사유 3줄 + 지금 설정 1줄 + Gateway 처리 링크 */
function UninspectedCard({ stats, period, settings, settingsFailed }: { stats: DashboardStats; period: OverviewPeriod; settings?: Parameters<typeof settingSummary>[0]; settingsFailed: boolean }) {
  const result = stats.periodEvents ? uninspectedRequests(stats.periodEvents) : undefined;
  const summary = settings ? settingSummary(settings) : undefined;
  return <section className="pg-card pg-ov-metric" aria-labelledby="pg-ov-uninspected-title">
    <header className="pg-card-head"><h2 id="pg-ov-uninspected-title" className="pg-card-title">검사 못 한 요청</h2><span className="pg-card-note pg-card-head-end">{PERIOD_LABELS[period]} · 접속 차단 제외</span></header>
    <div className="pg-card-body">
      {notComputed(stats) || (result && <>
        <p className={`pg-bignum pg-bignum--${result.allow > 0 ? 'mask' : 'allow'}`}><b>{ko(result.allow)}</b><span>건 검사 없이 허용 · 차단 {ko(result.block)}건 <small className="pg-bignum-of">(접속 차단을 뺀 {stats.counting ? '요청' : '보안 이벤트'} {ko(inspectableCount(stats.periodEvents ?? []))}건 중)</small></span></p>
        <dl className="pg-rows" aria-label="검사 못 한 사유별 처리">
          {result.rows.map(row => <div key={row.key}><dt>{row.label}</dt><dd className="pg-num">{row.allow + row.block === 0 ? <b>0</b> : <><span>허용 <b>{ko(row.allow)}</b></span><span>· 차단 <b>{ko(row.block)}</b></span></>}</dd></div>)}
        </dl>
      </>)}
      <p className="pg-setting-line">{summary
        ? <>지금 설정 · 응답 없음 <b>{summary.timeout}</b> · 검사할 수 없는 파일 <b>{summary.uninspectable}</b></>
        : settingsFailed ? '지금 설정을 불러오지 못함' : '지금 설정 확인 중'}</p>
    </div>
    <footer className="pg-card-foot"><span>허용은 검사 없이 LLM에 전달된 건</span><Link className="pg-card-head-end" to="/policies/gateway">Gateway 처리<span aria-hidden="true"> ›</span></Link></footer>
  </section>;
}

/** ③ 보호 범위: "4 / 5개 문서 보호 중" + 분할 막대(보호 중·분석 중·오류·중지) + 승인 대기 키워드 · 추출 실패 문서 */
function CoverageCard({ documents, keywords, jobs, keywordsFailed, jobsFailed }: {
  documents: { data?: Parameters<typeof protectionCoverage>[0]; isLoading: boolean; isError: boolean; error: unknown; refetch: () => unknown };
  keywords?: Parameters<typeof protectionCoverage>[1];
  jobs?: Parameters<typeof protectionCoverage>[2];
  keywordsFailed: boolean;
  jobsFailed: boolean;
}) {
  const coverage = documents.data ? protectionCoverage(documents.data, keywords, jobs) : undefined;
  const parts = coverage ? (['protected', 'analyzing', 'failed', 'stopped', 'check'] as const)
    .filter(key => key !== 'check' || coverage.counts.check > 0)
    .map(key => ({ tone: ({ protected: 'allow', analyzing: 'info', failed: 'block', stopped: 'neutral', check: 'mask' } as const)[key], value: coverage.counts[key], name: COVERAGE_LABEL[key] })) : [];
  return <section className="pg-card pg-ov-metric" aria-labelledby="pg-ov-coverage-title">
    <header className="pg-card-head"><h2 id="pg-ov-coverage-title" className="pg-card-title">보호 범위</h2><span className="pg-card-note pg-card-head-end">지금 상태 · 기간과 무관</span></header>
    <div className="pg-card-body">
      {documents.isLoading ? <PgSkeleton shape="table" rows={2} /> : !coverage ? <PgError variant="inline" message="문서 목록을 불러오지 못함" error={documents.error} onRetry={() => documents.refetch()} /> : <>
        <p className={`pg-bignum${coverage.counts.failed > 0 ? ' pg-bignum--block' : ''}`}><b>{ko(coverage.counts.protected)}</b><span>/ {ko(coverage.total)}개 문서 보호 중</span></p>
        <PgSplitBar label="보호 문서 상태" parts={parts} />
        <dl className="pg-rows" aria-label="키워드 처리">
          <div><dt>승인 대기 키워드</dt><dd className="pg-num">{coverage.pendingKeywords === undefined ? (keywordsFailed ? '확인 불가' : '–') : <Link to="/policies/keywords"><b>{ko(coverage.pendingKeywords)}</b><span aria-hidden="true"> ›</span></Link>}</dd></div>
          <div><dt>키워드 추출 실패 문서</dt><dd className="pg-num"><b>{coverage.failedExtractions === undefined ? (jobsFailed ? '확인 불가' : '–') : ko(coverage.failedExtractions)}</b></dd></div>
        </dl>
      </>}
    </div>
    <footer className="pg-card-foot"><span>등록 문서 {coverage ? ko(coverage.total) : '–'}개의 상태(보호 문서 화면 배지와 같은 기준{coverage?.demoExcluded ? ` · 시연 문서 ${ko(coverage.demoExcluded)}개 제외` : ''}) · 열 때·새로고침 때만 갱신</span><Link className="pg-card-head-end" to="/documents">보호 문서<span aria-hidden="true"> ›</span></Link></footer>
  </section>;
}
