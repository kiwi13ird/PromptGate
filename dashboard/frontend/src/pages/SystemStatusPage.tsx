import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PgBadge, PgDrawer, PgEmpty, PgError, PgPageHeader, PgRefresh, PgSkeleton, PgStatusStrip, type BadgeTone, type StripLevel } from '@/src/components/pg';
import {
  systemStatusKeys,
  systemStatusService,
  type ComponentStatus,
  type SystemComponent,
  type SystemInstance,
  type SystemStatus,
} from '@/src/services/systemStatusService';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import {
  NO_VALUE,
  REFRESH_INTERVAL_MS,
  STATUS_LABEL,
  STATUS_ORDER,
  checkLabel,
  countByStatus,
  formatClock,
  formatDetailValue,
  formatExactTime,
  instanceState,
  instancesNotices,
  rdsNotice,
  rdsState,
  roleLabel,
  type AwsNotice,
} from '@/src/utils/systemStatusPresentation';

// 시스템 상태(재설계 3d, 설계 5.10·목업 system.html): 머리(설명 1줄·서버 확인 시각) → 상태 띠("이상 1 · 주의 1 — Relay 끊김 · RDS 느림")
// → 확인 필요 카드(끊김·느림만, 크게) → 나머지 구성 요소 격자(3열, 확인 불가 먼저) → EC2 표(이상 먼저, 상태 점검은 배지 2개) → RDS 1줄.
// 표시 순서만 바꾼다(서버 응답 그대로). 구성 요소 세부(키·값)는 서랍(설계 4.8). 같은 '확인 시각' 반복은 머리 한 번 + 다를 때만 카드에.

const STATUS_TONE: Readonly<Record<ComponentStatus, BadgeTone>> = { ok: 'allow', slow: 'mask', down: 'block', unknown: 'neutral' };
/** 표시 순서: 끊김 → 느림 → 확인 불가 → 정상(설계 5.10 "이상 먼저 · 확인 불가 먼저") */
const SHOW_ORDER: readonly ComponentStatus[] = ['down', 'slow', 'unknown', 'ok'];
const byStatus = <T,>(items: readonly T[], status: (item: T) => ComponentStatus) =>
  items.map((item, index) => ({ item, index })).sort((a, b) => SHOW_ORDER.indexOf(status(a.item)) - SHOW_ORDER.indexOf(status(b.item)) || a.index - b.index).map(({ item }) => item);
/** 카드에 확인 시각을 따로 보이는 기준: 서버 확인 시각과 1분 넘게 다를 때 */
const STALE_CHECK_MS = 60_000;

function StatusBadge({ status, label }: { status: ComponentStatus; label?: string }) {
  return <PgBadge variant="dot" tone={STATUS_TONE[status]} data-status={status}>{label ?? STATUS_LABEL[status]}</PgBadge>;
}

function Notice({ notice }: { notice: AwsNotice }) {
  return <p className={`pg-sys-notice pg-sys-notice--${notice.kind}`} role="status">{notice.text}</p>;
}

function CheckedAt({ value, label = '' }: { value?: string | null; label?: string }) {
  if (!value) return <span className="pg-muted">{NO_VALUE}</span>;
  return <time dateTime={value} title={formatExactTime(value)}>{label}{formatClock(value)}</time>;
}

function StatusStrip({ components, checkedAt }: { components: SystemComponent[]; checkedAt: string }) {
  const counts = countByStatus(components);
  const level: StripLevel = counts.down > 0 ? 'bad' : counts.slow > 0 ? 'warn' : components.length > 0 && counts.unknown === components.length ? 'unknown' : 'ok';
  const problems = byStatus(components.filter(component => component.status === 'down' || component.status === 'slow'), component => component.status);
  const word = level === 'bad' || level === 'warn' ? [counts.down > 0 && `이상 ${counts.down}`, counts.slow > 0 && `주의 ${counts.slow}`].filter(Boolean).join(' · ') : undefined;
  return <PgStatusStrip level={level} word={word} label="상태 요약"
    facts={[problems.length ? problems.map(component => `${component.label || component.key} ${STATUS_LABEL[component.status]}`).join(' · ') : null,
      <span key="c" className="pg-sys-counts">{STATUS_ORDER.map(status => <span key={status}>{STATUS_LABEL[status]} <b>{counts[status]}</b></span>)}</span>]}
    end={<span>서버 확인 <time dateTime={checkedAt} title={formatExactTime(checkedAt)}>{formatClock(checkedAt)}</time></span>} />;
}

function ComponentCard({ component, checkedAt, big, onOpen }: { component: SystemComponent; checkedAt: string; big: boolean; onOpen: () => void }) {
  const name = component.label || component.key;
  const hasDetails = Object.keys(component.details).length > 0;
  const own = component.checked_at && Math.abs(Date.parse(component.checked_at) - Date.parse(checkedAt)) > STALE_CHECK_MS;
  return <li className={`pg-sys-item${big ? ' pg-sys-item--big' : ''}`} data-component={component.key} data-tone={STATUS_TONE[component.status]}>
    <div className="pg-sys-item-head">
      {hasDetails
        ? <button type="button" className="pg-sys-name pg-sys-open" aria-haspopup="dialog" onClick={onOpen} title="세부 정보 보기">{name}</button>
        : <span className="pg-sys-name">{name}</span>}
      <StatusBadge status={component.status} />
      {big && hasDetails && <button type="button" className="pg-sys-more" onClick={onOpen} aria-label={`${name} 세부 정보`}>세부 정보<span aria-hidden="true"> ›</span></button>}
    </div>
    <p className="pg-sys-summary">{component.summary || NO_VALUE}</p>
    {own && <p className="pg-muted"><CheckedAt value={component.checked_at} label="확인 " /></p>}
  </li>;
}

function ComponentsSection({ data }: { data: SystemStatus }) {
  // 서랍으로 연 구성 요소는 자동 갱신으로 목록이 다시 와도 유지한다(키로 기억)
  const [openKey, setOpenKey] = useState<string | null>(null);
  const opened = openKey ? data.components.find(component => component.key === openKey) : undefined;
  const problems = byStatus(data.components.filter(component => component.status === 'down' || component.status === 'slow'), component => component.status);
  const rest = byStatus(data.components.filter(component => component.status !== 'down' && component.status !== 'slow'), component => component.status);
  if (data.components.length === 0)
    return <section className="pg-card" aria-label="구성 요소 상태"><PgEmpty title="표시할 구성 요소가 없습니다." description="서버가 구성 요소 상태를 보내지 않았습니다." /></section>;
  return <>
    {problems.length > 0 && <section className="pg-sys-group" aria-labelledby="pg-sys-problem-title">
      <h2 id="pg-sys-problem-title" className="pg-sys-group-title">확인 필요</h2>
      <ul className="pg-sys-problems" aria-label="확인 필요 구성 요소">
        {problems.map(component => <ComponentCard key={component.key} component={component} checkedAt={data.checked_at} big onOpen={() => setOpenKey(component.key)} />)}
      </ul>
    </section>}
    <section className="pg-sys-group" aria-labelledby="pg-sys-rest-title">
      <h2 id="pg-sys-rest-title" className="pg-sys-group-title">{problems.length ? `나머지 구성 요소 ${rest.length}` : `구성 요소 ${rest.length}`}</h2>
      {rest.length > 0 && <ul className="pg-card pg-sys-grid" aria-label="구성 요소 상태">
        {rest.map(component => <ComponentCard key={component.key} component={component} checkedAt={data.checked_at} big={false} onOpen={() => setOpenKey(component.key)} />)}
      </ul>}
    </section>
    <PgDrawer open={Boolean(opened)} onOpenChange={open => { if (!open) setOpenKey(null); }} title={opened ? opened.label || opened.key : ''}
      description={opened ? `${STATUS_LABEL[opened.status]} · ${opened.summary || NO_VALUE}` : undefined}>
      {opened && <div role="group" aria-label={`${opened.label || opened.key} 세부 정보`}>
        <dl className="pg-sys-details">
          <div><dt>확인 시각</dt><dd><CheckedAt value={opened.checked_at} /></dd></div>
          {Object.entries(opened.details).map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{formatDetailValue(value)}</dd></div>)}
        </dl>
      </div>}
    </PgDrawer>
  </>;
}

function CheckBadges({ instance }: { instance: SystemInstance }) {
  if (!instance.system_status && !instance.instance_status) return <span className="pg-muted">점검 {NO_VALUE}</span>;
  const tone = (value?: string | null): BadgeTone => (value === 'ok' ? 'allow' : value === 'impaired' ? 'block' : value === 'initializing' ? 'info' : 'neutral');
  return <span className="pg-sys-checks">
    <PgBadge tone={tone(instance.system_status)}>시스템 {checkLabel(instance.system_status)}</PgBadge>
    <PgBadge tone={tone(instance.instance_status)}>인스턴스 {checkLabel(instance.instance_status)}</PgBadge>
  </span>;
}

function InstancesSection({ data }: { data: SystemStatus }) {
  const { instances } = data;
  const notices = instancesNotices(instances);
  const rows = byStatus(instances.items, item => {
    const state = instanceState(item).tone;
    return item.system_status === 'impaired' || item.instance_status === 'impaired' ? 'down' : state;
  });
  return <section className="pg-card pg-sys-ec2" aria-labelledby="sysst-ec2-title">
    <header className="pg-card-head"><h2 id="sysst-ec2-title" className="pg-card-title">EC2 인스턴스</h2><span className="pg-card-note pg-card-head-end">{instances.items.length}대{instances.items.length > 1 ? ' · 이상 먼저' : ''}</span></header>
    {notices.map(notice => <Notice key={notice.text} notice={notice} />)}
    {instances.items.length > 0 ? (
      <Table card aria-label="EC2 인스턴스" className="sysst-table pg-sys-ec2-table">
        <TableHeader><TableRow><TableHead>역할</TableHead><TableHead>상태</TableHead><TableHead>이름</TableHead><TableHead>인스턴스 ID</TableHead><TableHead>상태 점검</TableHead></TableRow></TableHeader>
        <TableBody>
          {rows.map(instance => {
            const state = instanceState(instance);
            return <TableRow key={`${instance.role}-${instance.instance_id}`} data-tone={STATUS_TONE[instance.system_status === 'impaired' || instance.instance_status === 'impaired' ? 'down' : state.tone]}>
              <TableCell data-card="title"><span className="pg-sys-role">{roleLabel(instance.role)}</span></TableCell>
              <TableCell data-card="badge"><StatusBadge status={state.tone} label={state.label} /></TableCell>
              <TableCell data-card="info">{instance.name || NO_VALUE}</TableCell>
              <TableCell data-card="info"><code title={instance.instance_id}>{instance.instance_id}</code></TableCell>
              <TableCell data-card="body"><CheckBadges instance={instance} /></TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    ) : notices.length === 0 ? <PgEmpty title="표시할 인스턴스가 없습니다." description="조회할 인스턴스 ID가 설정되어 있는지 확인해주세요." /> : null}
  </section>;
}

function RdsSection({ data }: { data: SystemStatus }) {
  const rds = data.rds_instance;
  const notice = rdsNotice(rds);
  const state = rdsState(rds.status);
  return <section className="pg-card pg-sys-rds" aria-labelledby="sysst-rds-title">
    <header className="pg-card-head"><h2 id="sysst-rds-title" className="pg-card-title">RDS</h2></header>
    {notice ? <Notice notice={notice} /> : (
      <p className="pg-sys-rds-line" aria-label="RDS 상태">
        <StatusBadge status={state.tone} label={state.label} />
        <b>{rds.identifier || NO_VALUE}</b>
        <span className="pg-muted">{rds.engine || NO_VALUE}</span>
      </p>
    )}
  </section>;
}

export function SystemStatusPage() {
  const query = useQuery({
    queryKey: systemStatusKeys.status(),
    queryFn: ({ signal }) => systemStatusService.getStatus(signal),
    refetchInterval: REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
  });
  const data = query.data;
  // 로그인 만료·권한 오류 뒤에는 마지막 조회 결과를 계속 보이지 않는다
  const retained = data && canRetainQueryData(query.error) ? data : undefined;
  return (
    <div className="pg-screen pg-sys">
      <PgPageHeader
        title="시스템 상태"
        description="서버·DB·서비스 상태를 15초마다 확인"
        refresh={<PgRefresh updatedAt={query.dataUpdatedAt} fetching={query.isFetching} failed={query.isError} onRefresh={() => query.refetch()} />}
      />
      {query.isLoading ? (
        <PgSkeleton shape="table" rows={5} />
      ) : !retained ? (
        <PgError message="시스템 상태를 불러오지 못했습니다." error={query.error} onRetry={() => query.refetch()} />
      ) : (
        <>
          {query.isError && <p className="pg-stale" role="status">갱신 실패 · 아래는 마지막으로 받은 상태입니다.</p>}
          <StatusStrip components={retained.components} checkedAt={retained.checked_at} />
          <ComponentsSection data={retained} />
          <InstancesSection data={retained} />
          <RdsSection data={retained} />
        </>
      )}
    </div>
  );
}
