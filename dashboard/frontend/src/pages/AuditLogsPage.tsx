import { uiLabel } from '@/src/utils/labels';
import { ChevronRight, LockKeyhole } from 'lucide-react';
import { useState, type MouseEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { auditService } from '@/src/services/auditService';
import { auditKeys } from '@/src/queries/keys';
import type { AuditAction, AuditFilters, AuditLog, AuditResult } from '@/src/types/audit';
import { formatDateTime, formatShortDateTime, formatCount } from '@/src/utils/format';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { PgBadge, PgCount, PgDrawer, PgEmpty, PgError, PgFilterBar, PgPageHeader, PgPager, PgRefresh, PgSkeleton, type PgFilterChip } from '@/src/components/pg';
import { AuditChangeDetails } from '@/src/components/AuditChangeDetails';
import { canRetainQueryData } from '@/src/utils/queryPresentation';

// 감사 로그(재설계 3g, 설계 5.12): 머리(제목 · 읽기 전용 배지) → 필터 바(기간·작업 유형 + 더보기[결과·관리자], 기본값 아닌 필터는 칩)
// → 표 5열(시각 · 관리자 · 작업[굵게] · 대상[유형 + ID] · 결과 배지) + 끝 › → 행을 누르면 서랍(변경 내용, 설계 4.8).
// 관리자 ID와 대상 ID가 같으면 대상은 "본인". 표 자리 720px 이하에서는 카드. 기능·API 호출(필터 값·쪽)은 그대로.

const actionOptions: Array<'ALL' | AuditAction> = [
  'ALL',
  'ADMIN_LOGIN',
  'ADMIN_LOGOUT',
  'POLICY_CREATE',
  'POLICY_UPDATE',
  'POLICY_ENABLE',
  'POLICY_DISABLE',
  'DOCUMENT_REGISTER',
  'DOCUMENT_DISABLE',
  'DOCUMENT_ENABLE',
  'DOCUMENT_VIEW',
  'DOCUMENT_DOWNLOAD',
  'EVENT_ASSIGNED',
  'EVENT_STATUS_CHANGED',
  'EVENT_NOTE_ADDED',
  'REPORT_CREATE',
  'KEYWORD_CREATE',
  'KEYWORD_APPROVE',
  'KEYWORD_REJECT',
  'KEYWORD_UPDATE',
  'KEYWORD_EXTRACT_REQUEST',
  'GPU_START',
  'GPU_STOP',
  'GATEWAY_SETTINGS_UPDATE',
  'ACCESS_RULE_ADD',
  'ACCESS_RULE_REMOVE',
  'ACCESS_MODE_UPDATE',
  'CLIENT_ALIAS_UPDATE',
];
const PERIOD_TEXT: Record<AuditFilters['period'], string> = { '24H': '최근 24시간', '7D': '최근 7일', '30D': '최근 30일' };
// 접속 차단 기록(대상 종류는 GATEWAY): 설정 화면이 아니라 접속 차단 탭으로 연결한다
const accessActions: ReadonlySet<string> = new Set(['ACCESS_RULE_ADD', 'ACCESS_RULE_REMOVE', 'ACCESS_MODE_UPDATE', 'CLIENT_ALIAS_UPDATE']);

function targetPath(log: AuditLog) {
  return log.targetType === 'EVENT' ? `/events/${encodeURIComponent(log.targetId)}`
    : log.targetType === 'ADMIN' ? '/audit-logs'
      : log.targetType === 'DOCUMENT' ? `/documents/${encodeURIComponent(log.targetId)}`
        : log.targetType === 'POLICY' ? `/policies?policyId=${encodeURIComponent(log.targetId)}`
          : log.targetType === 'REPORT' ? '/reports'
            : log.targetType === 'KEYWORD' ? '/policies/keywords'
              : log.targetType === 'GATEWAY' ? accessActions.has(log.action) ? '/policies/access' : '/policies/gateway'
                : '/audit-logs';
}

export function AuditLogsPage() {
  const [period, setPeriod] = useState<AuditFilters['period']>('24H');
  const [action, setAction] = useState<AuditFilters['action']>('ALL');
  const [result, setResult] = useState<'ALL' | AuditResult>('ALL');
  const [admin, setAdmin] = useState('');
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<string | null>(null);
  const filters: AuditFilters = {
    period,
    action,
    result,
    admin,
    page,
    pageSize: 9,
  };
  const logs = useQuery({
    ...liveQueryOptions,
    queryKey: auditKeys.list(filters),
    queryFn: ({ signal }) => auditService.getLogs(filters, signal),
  });
  const change = <T,>(setter: (value: T) => void, value: T) => {
    setter(value);
    setPage(1);
    setExpanded(null);
  };
  const chips: PgFilterChip[] = [
    ...(period !== '24H' ? [{ key: 'period', label: `기간: ${PERIOD_TEXT[period]}`, onRemove: () => change(setPeriod, '24H' as AuditFilters['period']) }] : []),
    ...(action !== 'ALL' ? [{ key: 'action', label: `작업: ${uiLabel(action)}`, onRemove: () => change(setAction, 'ALL' as AuditFilters['action']) }] : []),
    ...(result !== 'ALL' ? [{ key: 'result', label: `결과: ${uiLabel(result)}`, onRemove: () => change(setResult, 'ALL' as typeof result) }] : []),
    ...(admin ? [{ key: 'admin', label: `관리자: ${admin}`, onRemove: () => change(setAdmin, '') }] : []),
  ];
  const opened = logs.data?.items.find(log => log.auditId === expanded);
  const openRow = (log: AuditLog) => (event: MouseEvent<HTMLTableRowElement>) => {
    // 행 안의 링크·버튼을 누른 것은 그쪽 동작만(대상 링크로 이동 등)
    if ((event.target as HTMLElement).closest('a, button')) return;
    setExpanded(log.auditId);
  };
  return (
    <div className="pg-screen pg-audit">
      <PgPageHeader
        title="감사 로그"
        secondary={<PgBadge variant="tag" className="pg-readonly"><LockKeyhole aria-hidden="true" />읽기 전용</PgBadge>}
        refresh={<PgRefresh updatedAt={logs.dataUpdatedAt} fetching={logs.isFetching} failed={logs.isError} onRefresh={() => logs.refetch()} total={logs.data?.total} scope={JSON.stringify({ ...filters, page: undefined })} countLabel="관리자 활동" />}
      />
      {logs.isError && logs.data && canRetainQueryData(logs.error) && <p className="pg-stale" role="status">갱신 실패 · 아래는 마지막 성공 조회 결과입니다.</p>}
      <PgFilterBar
        label="감사 로그 필터"
        filters={<>
          <label className="pg-field">
            <span>기간</span>
            <select value={period} onChange={event => change(setPeriod, event.target.value as AuditFilters['period'])}>
              <option value="24H">최근 24시간</option>
              <option value="7D">최근 7일</option>
              <option value="30D">최근 30일</option>
            </select>
          </label>
          <label className="pg-field">
            <span>작업 유형</span>
            <select value={action} onChange={event => change(setAction, event.target.value as 'ALL' | AuditAction)}>
              {actionOptions.map((value) => (
                <option key={value} value={value}>{uiLabel(value)}</option>
              ))}
            </select>
          </label>
        </>}
        more={<>
          <label className="pg-field">
            <span>결과</span>
            <select value={result} onChange={event => change(setResult, event.target.value as typeof result)}>
              <option value="ALL">전체</option>
              <option value="SUCCESS">성공</option>
              <option value="FAILURE">실패</option>
            </select>
          </label>
          <label className="pg-field" htmlFor="auditAdmin">
            <span>관리자</span>
            <Input id="auditAdmin" placeholder="admin-001" value={admin} onChange={(event) => change(setAdmin, event.target.value)} />
          </label>
        </>}
        moreCount={Number(result !== 'ALL') + Number(Boolean(admin))}
        chips={chips}
        onReset={chips.length ? () => { setPeriod('24H'); setAction('ALL'); setResult('ALL'); setAdmin(''); setPage(1); setExpanded(null); } : undefined}
      />
      <section className="pg-card pg-audit-list" aria-labelledby="pg-audit-title">
        <header className="pg-card-head">
          <h2 id="pg-audit-title" className="pg-card-title">관리자 작업 기록</h2>
          {logs.data && (
            <span className="pg-card-note"><PgCount total={logs.data.total} />{logs.data.skipped || logs.data.partial
              ? <span className="pg-audit-hidden"> · {[logs.data.skipped ? `이 쪽에서 형식을 읽지 못해 숨긴 기록 ${formatCount(logs.data.skipped)}건` : '', logs.data.partial ? `이 쪽에서 바뀐 값을 읽지 못한 기록 ${formatCount(logs.data.partial)}건` : ''].filter(Boolean).join(' · ')}</span> : null}</span>
          )}
          <span className="pg-card-note pg-card-head-end">행을 누르면 변경 내용</span>
        </header>
        {logs.isLoading ? (
          <div className="pg-card-body"><PgSkeleton /></div>
        ) : logs.isError && (!logs.data || !canRetainQueryData(logs.error)) ? (
          <div className="pg-card-body"><PgError
            message="감사 로그를 불러오지 못했습니다."
            error={logs.error}
            onRetry={() => logs.refetch()}
          /></div>
        ) : logs.data?.items.length ? (
          <>
            {/* 표 → 카드(설계 4.6): 감싼 영역 720px 이하에서 카드. 제목=작업, 배지=결과, 정보=시각·관리자·대상, 조치=상세 열기 */}
            <Table card aria-label="감사 로그" className="pg-audit-table">
              <TableHeader>
                <TableRow>
                  <TableHead>발생 시각</TableHead>
                  <TableHead>관리자</TableHead>
                  <TableHead>작업</TableHead>
                  <TableHead>대상</TableHead>
                  <TableHead>결과</TableHead>
                  <TableHead><span className="sr-only">상세</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.data.items.map((log) => {
                  const self = log.adminId === log.targetId;
                  const open = expanded === log.auditId;
                  return (
                    <TableRow key={log.auditId} className={`pg-audit-row${open ? ' console-selected-row pg-row-selected' : ''}`} data-tone={log.result === 'FAILURE' ? 'block' : undefined} onClick={openRow(log)}>
                      <TableCell data-card="info" title={formatDateTime(log.occurredAt)}><time dateTime={log.occurredAt}>{formatShortDateTime(log.occurredAt)}</time></TableCell>
                      <TableCell data-card="info" className="mono" title={log.adminId}>{log.adminId}</TableCell>
                      <TableCell data-card="title"><span className="pg-audit-action">{uiLabel(log.action)}</span></TableCell>
                      <TableCell data-card="info" className="pg-audit-target">
                        <span className="pg-audit-type">{uiLabel(log.targetType)}</span>
                        {self
                          ? <span className="pg-audit-self" title={log.targetId}>본인</span>
                          : <Link className="event-link mono" title={log.targetId} to={targetPath(log)}>{log.targetId}</Link>}
                      </TableCell>
                      <TableCell data-card="badge"><PgBadge tone={log.result === 'SUCCESS' ? 'allow' : 'block'}>{uiLabel(log.result)}</PgBadge></TableCell>
                      <TableCell data-card="actions" className="pg-audit-open-cell">
                        <button
                          type="button"
                          className="pg-audit-open"
                          aria-label={`${log.auditId} 상세 ${open ? '닫기' : '열기'}`}
                          aria-haspopup="dialog"
                          aria-expanded={open}
                          onClick={() => setExpanded(open ? null : log.auditId)}
                        >
                          <ChevronRight aria-hidden="true" />
                        </button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <PgPager page={logs.data.page} totalPages={logs.data.totalPages} onPage={setPage} label="감사 로그 쪽 이동" />
          </>
        ) : (
          <PgEmpty
            title="조회된 감사 로그가 없습니다."
            description="다른 기간 또는 필터 조건을 선택해보세요."
          />
        )}
      </section>
      <PgDrawer open={Boolean(opened)} onOpenChange={next => { if (!next) setExpanded(null); }}
        title={opened ? `${uiLabel(opened.action)} · 변경 내용` : '변경 내용'}
        description={opened ? `${formatDateTime(opened.occurredAt)} · ${opened.adminId}` : undefined}>
        {opened && <>
          <dl className="pg-audit-meta">
            <div><dt>결과</dt><dd><PgBadge tone={opened.result === 'SUCCESS' ? 'allow' : 'block'}>{uiLabel(opened.result)}</PgBadge></dd></div>
            <div><dt>대상</dt><dd>{uiLabel(opened.targetType)} · <span className="mono">{opened.targetId}</span>{opened.adminId === opened.targetId ? ' (본인)' : ''}</dd></div>
            <div><dt>기록 ID</dt><dd className="mono">{opened.auditId}</dd></div>
          </dl>
          <section id={`audit-details-${opened.auditId}`} aria-label="기록된 변경 전후" className="pg-audit-changes"><AuditChangeDetails action={opened.action} changes={opened.changes} unreadable={opened.changesUnreadable} /></section>
        </>}
      </PgDrawer>
    </div>
  );
}
