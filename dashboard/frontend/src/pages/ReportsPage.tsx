import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { toast } from '@/components/ui/toast';
import { PgBadge, PgCount, PgEmpty, PgError, PgPageHeader, PgRefresh, PgRowMenu, PgSegment, PgSkeleton } from '@/src/components/pg';
import { GpuStatusBadge } from '@/src/components/GpuStatusBadge';
import {
  detectionOpsKeys,
  detectionOpsMessage,
  detectionOpsService,
  reportFileUrl,
  type Report,
} from '@/src/services/detectionOpsService';
import { formatDateTime, formatShortDateTime, formatCount } from '@/src/utils/format';
import { notifySuccess } from '@/src/utils/feedback';
import { PERIOD_PRESETS, comparePeriod, formatPeriodRange, kstDate, presetPeriod, type PeriodPreset } from '@/src/utils/reportPeriod';
import '@/src/detection-ops.css';

// 진행 단계는 집계 · 분석 · 파일 만들기로만 보여 준다(어떤 방식으로 쓰는지는 드러내지 않는다)
const STAGE_LABEL: Record<string, string> = {
  aggregating: '집계 중',
  incidents: '집계 중',
  gpu_stopping: '분석 준비 중',
  gpu_starting: '분석 준비 중',
  gpu_booting: '분석 준비 중',
  llm: '분석 중',
  writing: '분석 중', // 2026-10-11까지 쓰던 단계 이름(옛 탐지 서버)
  rendering: '파일 만드는 중',
  gpu_stopping_after: '마무리 중',
};
const MAX_DAYS = 366; // Detection reporting/jobs.py와 같은 상한
// 설계 v2 4.10·4.11: 사건 서술·표본 분류까지 LLM을 여러 번 부르므로 웜 약 2분, GPU가 꺼져 있으면 부팅(약 3분)이 더해진다
const EXPECT_LLM = 'GPU 켜짐 약 2분 · 꺼짐 약 5분';
const EXPECT_LLM_NO_TREND = 'GPU 켜짐 약 1.5분 · 꺼짐 약 5분';
const EXPECT_AGGREGATE = '집계만 1초 이내';

const expectedTime = (useLlm: boolean, contentTrend: boolean) => (!useLlm ? EXPECT_AGGREGATE : contentTrend ? EXPECT_LLM : EXPECT_LLM_NO_TREND);

function periodError(from: string, to: string): string | null {
  if (!from || !to) return '시작일과 종료일을 모두 입력해주세요.';
  if (from > kstDate()) return '시작일은 오늘 이전이어야 합니다.';
  if (to < from) return '종료일은 시작일과 같거나 뒤여야 합니다.';
  if ((Date.parse(to) - Date.parse(from)) / 86_400_000 + 1 > MAX_DAYS) return `기간은 최대 ${MAX_DAYS}일입니다.`;
  return null;
}

const count = (value: number) => value.toLocaleString('ko-KR');

function ReportStatus({ report }: { report: Report }) {
  if (report.status === 'running') {
    const label = STAGE_LABEL[report.stage ?? ''] ?? '준비 중';
    return <PgBadge tone="info">{label}{report.elapsed_seconds != null && ` · ${Math.round(report.elapsed_seconds)}초`}</PgBadge>;
  }
  if (report.status === 'failed') return <PgBadge tone="block" title={report.error ?? undefined}>실패</PgBadge>;
  return <PgBadge tone="allow">완료</PgBadge>;
}

/** 옛 보고서(items 없음)는 판정 기록 행 수를 "분석 N건"으로 보여 준다(설계 2.2 '판정 기록 957행' → '분석 957건') */
function CheckedCount({ report }: { report: Report }) {
  if (report.items != null) return <>{count(report.items)}건</>;
  if (report.rows != null) return <span title="옛 방식 집계(판정 기록 행 수)">분석 {count(report.rows)}건</span>;
  return <>–</>;
}

/** 날짜 아래 작은 글씨. 새 방식 보고서인데 비교 기간이 없으면 비교할 수 없는 기간 */
function CompareLine({ report }: { report: Report }) {
  if (report.compare_from && report.compare_to) {
    return <small className="pg-rep-compare dops-compare">비교: {formatPeriodRange(report.compare_from, report.compare_to, (report.to ?? report.compare_to).slice(0, 4))}</small>;
  }
  if (report.status === 'done' && report.items != null) return <small className="pg-rep-compare dops-compare">비교 불가</small>;
  return null;
}

// 사건 등급(설계 v2 4.5): 규칙 순위의 첫 기준
const INCIDENT_GRADE_LABEL: Record<string, string> = { '1': '기밀 차단', '2': '인증정보', '3': '검사 없이 통과', '4': '그 밖 차단', '5': '마스킹만' };
function incidentGradesTitle(byGrade: Record<string, number> | undefined): string | undefined {
  const parts = Object.entries(byGrade ?? {})
    .filter(([, total]) => total > 0)
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([grade, total]) => `${INCIDENT_GRADE_LABEL[grade] ?? `등급 ${grade}`} ${total}`);
  return parts.length ? `사건 등급별 · ${parts.join(' · ')}` : undefined;
}

/** full: 분석 문장 포함 · tables: 분석 문장 없이 표만 · no-trend: 분석 문장은 쓰되 내용 경향 제외 */
type RegenerateVariant = 'full' | 'tables' | 'no-trend';

// 리포트(재설계 3g, 설계 5.11): 머리(GPU 상태·[GPU 끄기]) → 만들기 카드(1줄 기간 세그먼트 · 시작일~종료일 / 2줄 체크 2개 /
// 3줄 참고(흐린 글자: 비교 기간·예상 시간)와 주의(⚠ 주의 계열) 구분 / [리포트 생성] 카드 오른쪽 아래) → 생성한 리포트 표
// (기간[파일명 둘째 줄] · 상태 배지 · 생성 시각 · 분석 건수 · [열기] ⋯[내려받기·다시 만들기]). 전부 '–'인 열은 숨김. 기능·API 호출은 그대로.
const REPORT_ID_PERIOD = /^report_(\d{4}-\d{2}-\d{2})_(\d{4}-\d{2}-\d{2})_/;
/** 기간(종료일 포함). 실패한 보고서는 상태에 기간이 없어 보고서 번호에서 읽는다 */
function periodOf(report: Report): { from: string | null; to: string | null } {
  if (report.from && report.to) return { from: report.from, to: report.to };
  const match = REPORT_ID_PERIOD.exec(report.report_id);
  return { from: report.from ?? match?.[1] ?? null, to: report.to ?? match?.[2] ?? null };
}

export function ReportsPage() {
  const client = useQueryClient();
  const [form, setForm] = useState({ from: kstDate(-6), to: kstDate(), useLlm: true, contentTrend: true });
  // 마지막으로 누른 바로 고르기(처음은 지난 7일). 날짜를 직접 고치면 풀린다
  const [preset, setPreset] = useState<PeriodPreset | null>('LAST_7_DAYS');
  const [formError, setFormError] = useState('');
  const [listError, setListError] = useState('');
  const [menuFor, setMenuFor] = useState<string | null>(null);
  const reports = useQuery({
    queryKey: detectionOpsKeys.reports(),
    queryFn: ({ signal }) => detectionOpsService.getReports(signal),
    // 만드는 중이면 3초마다(진행 단계 표시), 아니면 30초마다
    refetchInterval: query => (query.state.data?.reports.some(report => report.status === 'running') ? 3_000 : 30_000),
    refetchIntervalInBackground: false,
  });
  const gpu = useQuery({ queryKey: detectionOpsKeys.gpu(), queryFn: ({ signal }) => detectionOpsService.getGpuStatus(signal), refetchInterval: 30_000, retry: false });
  const reportRows = reports.data?.reports;
  // 전역 내용 경향 스위치: true 켜짐 · false 꺼짐(관리자 설정) · null 옛 탐지 서버라 모름
  const trendEnabled = reports.data ? reports.data.contentTrendEnabled : null;
  const trendOn = trendEnabled === true && form.useLlm && form.contentTrend;
  // 전역 스위치가 켜져 있을 때만 '내용 경향' 체크·안내·'내용 경향 빼고'를 보인다(꺼짐·옛 서버·목록 전이면 아예 숨김, 2026-10-13 피드백)
  const trendAvailable = trendEnabled === true;
  const trendNote = trendAvailable && !form.useLlm ? '분석 문장 포함일 때만' : null;
  const compare = comparePeriod(form.from, form.to);

  const start = (from: string, to: string, useLlm: boolean, contentTrend: boolean | null) => {
    // 칸을 안 보내는 쪽이 기본이다: 꺼진 전역 스위치·옛 탐지 서버에는 content_trend를 아예 싣지 않는다
    return contentTrend === null
      ? detectionOpsService.createReport(from, to, useLlm)
      : detectionOpsService.createReport(from, to, useLlm, { contentTrend });
  };
  const failed = (error: unknown, where: 'form' | 'list') => {
    const message = detectionOpsMessage(error, 'report');
    if (where === 'form') setFormError(message);
    else setListError(message);
    toast.add({ title: '리포트를 만들지 못했습니다.', description: message, type: 'error', priority: 'high' });
  };
  const create = useMutation({
    mutationFn: () => start(form.from, form.to, form.useLlm, form.useLlm && trendEnabled === true ? trendOn : null),
    onSuccess: async () => {
      notifySuccess('리포트 생성을 시작했습니다.', `예상 시간 · ${expectedTime(form.useLlm, trendOn)}`);
      await client.invalidateQueries({ queryKey: detectionOpsKeys.reports() });
    },
    onError: (error: unknown) => failed(error, 'form'),
  });
  // 다시 만들기: 같은 기간으로 새 생성. 생성 중이면 탐지 서버가 409로 거부하고 화면은 안내만 한다
  const regenerate = useMutation({
    mutationFn: ({ report, variant }: { report: Report; variant: RegenerateVariant }) => {
      const useLlm = variant !== 'tables';
      const { from, to } = periodOf(report);
      return start(from ?? '', to ?? '', useLlm, useLlm && trendEnabled === true ? variant === 'full' : null);
    },
    onSuccess: async (_report, { variant }) => {
      setMenuFor(null);
      setListError('');
      notifySuccess('리포트 생성을 시작했습니다.', `예상 시간 · ${expectedTime(variant !== 'tables', variant === 'full' && trendEnabled === true)}`);
      await client.invalidateQueries({ queryKey: detectionOpsKeys.reports() });
    },
    onError: (error: unknown) => failed(error, 'list'),
  });
  const running = reportRows?.find(report => report.status === 'running');

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const error = periodError(form.from, form.to);
    setFormError(error ?? '');
    if (!error && !create.isPending) create.mutate();
  };

  const done = reportRows?.filter(report => report.status === 'done') ?? [];
  // 빈 열 숨김(설계 4.5): 지금 목록의 모든 행이 값 없음이면 사건·높음 사용자 열을 그리지 않는다(옛 보고서만 있을 때)
  const showIncidents = done.some(report => report.incidents);
  const showHigh = done.some(report => report.users_high != null);
  const columns = 5 + Number(showIncidents) + Number(showHigh);

  return (
    <div className="pg-screen pg-rep dops-page">
      <PgPageHeader
        title="리포트"
        description="기간별 판정 현황 · 사건 · 사용자 위험 · 권고"
        secondary={<GpuStatusBadge />}
        refresh={<PgRefresh updatedAt={reports.dataUpdatedAt} fetching={reports.isFetching} failed={reports.isError} onRefresh={() => reports.refetch()} />}
      />
      <section className="pg-card pg-rep-make" aria-labelledby="pg-rep-make-title">
        <header className="pg-card-head">
          <h2 id="pg-rep-make-title" className="pg-card-title">새 리포트</h2>
          <span className="pg-card-note pg-card-head-end">한 번에 하나씩 생성</span>
        </header>
        <form className="dops-report-form pg-rep-form" onSubmit={submit} noValidate>
          <div className="pg-rep-line">
            <PgSegment legend="기간 바로 고르기" legendHidden name="pg-rep-preset" className="pg-rep-presets" value={preset ?? ''}
              onChange={code => { if (!code) return; setPreset(code as PeriodPreset); setForm(current => ({ ...current, ...presetPeriod(code as PeriodPreset) })); }}
              options={PERIOD_PRESETS.map(({ code, label }) => ({ value: code, label }))} />
            <span className="pg-rep-dates">
              <label className="pg-rep-date">
                <span className="sr-only">시작일</span>
                <Input type="date" aria-label="시작일" value={form.from} max={kstDate()} onChange={event => { setPreset(null); setForm(current => ({ ...current, from: event.target.value })); }} />
              </label>
              <span aria-hidden="true">~</span>
              <label className="pg-rep-date">
                <span className="sr-only">종료일</span>
                <Input type="date" aria-label="종료일" value={form.to} onChange={event => { setPreset(null); setForm(current => ({ ...current, to: event.target.value })); }} />
              </label>
            </span>
          </div>
          <div className="pg-rep-line">
            <label className="dops-inline pg-rep-check">
              <input type="checkbox" checked={form.useLlm} onChange={event => setForm(current => ({ ...current, useLlm: event.target.checked }))} />
              분석 문장 포함
            </label>
            {trendAvailable && <label className="dops-inline pg-rep-check">
              <input type="checkbox" aria-label="내용 경향 포함" aria-describedby={trendNote ? 'dops-trend-note' : undefined}
                checked={trendOn} disabled={!form.useLlm}
                onChange={event => setForm(current => ({ ...current, contentTrend: event.target.checked }))} />
              내용 경향 포함
            </label>}
          </div>
          <div className="pg-rep-notes">
            {/* 2026-10-15 감사 9·10번: 비교 가능 여부는 서버가 그 기간 기록이 있는지로 정하고, 끝날이 오늘이면 이번 기간은 지금까지만 들어간다 */}
            {compare && <p className="pg-muted">비교 기간 · {formatPeriodRange(compare.from, compare.to, form.to.slice(0, 4))} (직전 같은 길이 · 그 기간에 기록이 없으면 '비교 불가'){form.to === kstDate() ? ' · 끝날이 오늘이라 이번 기간은 지금 시각까지만 셈(비교 기간보다 짧음)' : ''}</p>}
            <p className="pg-muted">예상 시간 · {expectedTime(form.useLlm, trendOn)}</p>
            {trendNote && <p id="dops-trend-note" className="pg-rep-caution"><span aria-hidden="true">⚠ </span>내용 경향 · {trendNote}</p>}
            {form.useLlm && gpu.data && !gpu.data.connected && (
              <p className="pg-rep-caution"><span aria-hidden="true">⚠ </span>GPU 꺼짐 · 켜지 못하면 분석 문장 없이 작성</p>
            )}
          </div>
          {formError && <p className="pg-rep-error" role="alert">{formError}</p>}
          {running && (
            <p className="pg-rep-running" role="status">
              생성 중 · {running.from} ~ {running.to} · <ReportStatus report={running} />
            </p>
          )}
          <div className="pg-rep-submit">
            <Button type="submit" disabled={create.isPending || Boolean(running)}>
              <FileText />
              {create.isPending ? '요청 중…' : '리포트 생성'}
            </Button>
          </div>
        </form>
      </section>
      <section className="pg-card pg-rep-list" aria-labelledby="pg-rep-list-title">
        <header className="pg-card-head">
          <h2 id="pg-rep-list-title" className="pg-card-title">생성한 리포트</h2>
          {reportRows && <span className="pg-card-note"><PgCount total={reportRows.length} unit="개" /></span>}
          <span className="pg-card-note pg-card-head-end">열기 · ⋯ 내려받기 · 다시 만들기</span>
        </header>
        {listError && <div className="pg-card-notice"><PgError variant="inline" message={listError} /></div>}
        {reports.isLoading ? (
          <div className="pg-card-body"><PgSkeleton /></div>
        ) : reports.isError && !reports.data ? (
          <div className="pg-card-body"><PgError message="리포트 목록을 불러오지 못했습니다." error={reports.error} onRetry={() => reports.refetch()} /></div>
        ) : reportRows?.length ? (
          <Table card aria-label="생성한 리포트" className="pg-rep-table">
            <TableHeader>
              <TableRow>
                <TableHead>기간</TableHead>
                <TableHead>상태</TableHead>
                <TableHead>생성 시각</TableHead>
                <TableHead className="pg-num" title="시험 기록, 재전송, 마스킹한 파일 재검사 기록, 접속 차단(내용 검사 전 거부)은 세지 않습니다">분석</TableHead>
                {showIncidents && <TableHead className="pg-num" title="같은 사용자·같은 대상의 요청을 묶은 수">사건</TableHead>}
                {showHigh && <TableHead className="pg-num" title="위험 등급이 높음인 사용자 수">높음 사용자</TableHead>}
                <TableHead className="pg-rep-col-actions">보기</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {reportRows.flatMap(report => {
                const period = periodOf(report);
                const canRegenerate = report.status !== 'running' && Boolean(period.from && period.to);
                const menuOpen = menuFor === report.report_id;
                const name = `${period.from ?? '?'} ~ ${period.to ?? '?'}`;
                const row = (
                  <TableRow key={report.report_id} data-tone={report.status === 'failed' ? 'block' : report.status === 'running' ? 'info' : undefined}>
                    <TableCell data-card="title">
                      <span className="pg-rep-period"><span className="dops-nowrap">{period.from ?? '?'} ~</span> <span className="dops-nowrap">{period.to ?? '?'}</span></span>
                      <CompareLine report={report} />
                      <small className="pg-rep-id" title={report.report_id}>{report.report_id}</small>
                    </TableCell>
                    <TableCell data-card="badge"><ReportStatus report={report} /></TableCell>
                    <TableCell data-card="info" data-empty={report.generated_at ? undefined : ''} title={report.generated_at ? formatDateTime(report.generated_at) : undefined}>{report.generated_at ? formatShortDateTime(report.generated_at) : <span className="pg-muted">–</span>}</TableCell>
                    <TableCell data-card="info" className="pg-num"><CheckedCount report={report} /></TableCell>
                    {showIncidents && <TableCell data-card="info" data-label="사건" className="pg-num" data-empty={report.status === 'done' && report.incidents ? undefined : ''} title={report.status === 'done' ? incidentGradesTitle(report.incidents?.by_grade) : undefined}>{report.status === 'done' && report.incidents ? `${formatCount(report.incidents.total)}건` : <span className="pg-muted">–</span>}</TableCell>}
                    {showHigh && <TableCell data-card="info" data-label="높음 사용자" className="pg-num" data-empty={report.status === 'done' && report.users_high != null ? undefined : ''}>{report.status === 'done' && report.users_high != null ? `${report.users_high}명` : '–'}</TableCell>}
                    <TableCell data-card="actions" className="pg-rep-col-actions">
                      {report.status === 'done' || canRegenerate ? (
                        <span className="pg-row-actions">
                          {report.status === 'done' && <a className="pg-rep-open" href={reportFileUrl(report.report_id)} target="_blank" rel="noopener noreferrer" title="새 탭에서 보기">열기</a>}
                          <PgRowMenu label={name} items={[
                            ...(report.status === 'done' ? [{ label: '내려받기', href: reportFileUrl(report.report_id, true), download: true }] : []),
                            ...(canRegenerate ? [{ label: menuOpen ? '다시 만들기 닫기' : '다시 만들기', onSelect: () => setMenuFor(menuOpen ? null : report.report_id) }] : []),
                          ]} />
                        </span>
                      ) : <span className="pg-muted">–</span>}
                    </TableCell>
                  </TableRow>
                );
                if (!canRegenerate || !menuOpen) return [row];
                return [row, (
                  <TableRow key={`${report.report_id}-regen`} className="pg-rep-regen-row">
                    <TableCell colSpan={columns} data-card="body">
                      <span className="pg-rep-regen" role="group" aria-label={`${name} 다시 만들기 방식`}>
                        <span className="pg-muted">같은 기간으로 다시 만들기</span>
                        <Button type="button" size="sm" variant="outline" disabled={Boolean(running) || regenerate.isPending}
                          title={running ? '생성 중인 리포트가 있습니다' : undefined} onClick={() => regenerate.mutate({ report, variant: 'full' })}>분석 문장 포함</Button>
                        <Button type="button" size="sm" variant="outline" disabled={Boolean(running) || regenerate.isPending}
                          title={running ? '생성 중인 리포트가 있습니다' : undefined} onClick={() => regenerate.mutate({ report, variant: 'tables' })}>분석 문장 빼고</Button>
                        {trendAvailable && <Button type="button" size="sm" variant="outline" disabled={Boolean(running) || regenerate.isPending}
                          title={running ? '생성 중인 리포트가 있습니다' : undefined}
                          onClick={() => regenerate.mutate({ report, variant: 'no-trend' })}>내용 경향 빼고</Button>}
                      </span>
                    </TableCell>
                  </TableRow>
                )];
              })}
            </TableBody>
          </Table>
        ) : (
          <PgEmpty title="아직 만든 리포트가 없습니다." description="위에서 기간을 고르고 리포트를 생성하세요." />
        )}
      </section>
    </div>
  );
}
