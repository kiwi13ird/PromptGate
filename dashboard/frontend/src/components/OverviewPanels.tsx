import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PgBadge, PgStatusStrip, type StripLevel } from '@/src/components/pg';
import type { DashboardStats, SecurityEvent } from '@/src/types/event';
import { formatDateTime, formatShortDateTime } from '@/src/utils/format';
import { uiLabel } from '@/src/utils/labels';
import { inspectionFailure } from '@/src/utils/eventPresentation';

/**
 * 지표 카드(설계 4.3): 이름(13/600) → 숫자(32) → 보조 1줄(12) (+ 선택: 비율 막대). 색은 의미 있을 때만 —
 * 차단(danger)은 차단 계열, 마스킹(warning)은 주의 계열 + 카드 왼쪽 3px 띠. 나머지 숫자는 기본 글자색. 누르면 해당 필터 목록(지금 동작 유지).
 * 옛 클래스(console-kpi·console-tone-*)는 3단계 끝까지 함께 붙여 둔다(시험 보호, 설계 8.1).
 */
export function KpiMetric({ label, value, to, accessibleLabel, tone = 'neutral', hint, sub, unit, bar }: {
  label: string; value?: number; to: string; accessibleLabel: string;
  tone?: 'neutral' | 'danger' | 'warning' | 'success' | 'info'; hint?: string;
  /** 보조 1줄(12px) */
  sub?: ReactNode;
  /** 단위(ms·%·건) — 숫자 옆에 작게 */
  unit?: string;
  /** 카드 아래 비율 막대(전체 카드: 차단·마스킹·허용, 설계 5.1) */
  bar?: ReactNode;
}) {
  const family = tone === 'danger' ? 'block' : tone === 'warning' ? 'mask' : undefined;
  return <Link className={`pg-kpi${family ? ` pg-kpi--${family}` : ''} console-kpi console-tone-${tone}`} to={to} aria-label={accessibleLabel} title={hint}>
    <span className="pg-kpi-label">{label}</span>
    <span className="pg-kpi-value">{value === undefined ? '기록 없음' : value.toLocaleString('ko-KR')}{unit && value !== undefined && <small className="pg-kpi-unit">{unit}</small>}</span>
    {sub && <span className="pg-kpi-sub">{sub}</span>}
    {bar && <span className="pg-kpi-bar">{bar}</span>}
  </Link>;
}

// Gateway는 Gateway가 보내는 실시간 지표(최근 2분) 기준, Detection·최신 기록은 저장 이벤트 기준 (2026-10-10)
export function gatewayLiveLabel(stats: DashboardStats) {
  if (stats.gatewayMetricsStatus !== 'FRESH') return { label: '연결 확인 안 됨', dot: 'unknown' };
  if (stats.gatewayStatus === 'DEGRADED') return { label: '오류 기록 있음', dot: 'degraded' };
  if (stats.gatewayCompletedRequests === 0) return { label: '요청 대기', dot: 'healthy' };
  if (stats.gatewayStatus === 'HEALTHY') return { label: '정상', dot: 'healthy' };
  return { label: '확인 불가', dot: 'unknown' };
}

/** Detection 오류(검사 응답 없음) 기록의 마지막 시각: 서버가 알려 주거나(새 서버) 기간 이벤트 목록에서 찾는다 */
export function lastDetectionErrorAt(stats: DashboardStats): number | undefined {
  const reported = stats.counting?.lastDegradedAt;
  if (reported) return Date.parse(reported);
  const times = (stats.periodEvents ?? []).filter(event => event.degraded === true).map(event => Date.parse(event.occurredAt)).filter(Number.isFinite);
  return times.length ? Math.max(...times) : undefined;
}
/** 상태 띠의 단계는 '지금 상태'로 읽히므로 Detection 오류는 최근 24시간 기록만 주의로 본다(2026-10-15 감사 8번). 시각을 모르면 옛 규칙(기간 중 하나라도) */
export const DETECTION_RECENT_MS = 24 * 60 * 60 * 1000;
function detectionRecentError(stats: DashboardStats, now = Date.now()) {
  if (stats.detectionStatus !== 'DEGRADED') return false;
  const last = lastDetectionErrorAt(stats);
  return last === undefined || now - last <= DETECTION_RECENT_MS;
}

/** 상태 띠 단계: 오류 기록이 하나라도 있으면 주의, Gateway 연결 확인이 안 되면 주의(Detection도 모르면 확인 안 됨), 둘 다 괜찮으면 정상 */
export function overviewLevel(stats: DashboardStats, stale: boolean): { level: StripLevel; word?: string } {
  if (stale) return { level: 'unknown', word: '갱신 실패' };
  const gateway = gatewayLiveLabel(stats).dot;
  if (gateway === 'degraded' || detectionRecentError(stats)) return { level: 'warn' };
  if (gateway === 'unknown' && stats.detectionStatus === 'UNKNOWN') return { level: 'unknown', word: '확인 안 됨' };
  if (gateway === 'unknown') return { level: 'warn' };
  return { level: 'ok' };
}

/**
 * 보안 현황 상태 띠(설계 4.2·5.1): 정상·주의 + "Gateway 정상 · Detection 오류 기록 없음 · 저장 기록 기준 · 최신 기록 09:08" + 오른쪽 트래픽 링크.
 * 옛 상태 줄(console-record-status)을 대신한다. 판정 규칙(gatewayLiveLabel·detection 문구)은 그대로.
 */
export function RecordStatusBar({ stats, stale, end }: { stats: DashboardStats; stale: boolean; end?: ReactNode }) {
  const gateway = gatewayLiveLabel(stats);
  const lastError = stats.detectionStatus === 'DEGRADED' ? lastDetectionErrorAt(stats) : undefined;
  // 기간 기록이라 기간·건수·마지막 시각을 적는다(30일을 고르면 열흘 전 오류로 오늘도 '주의'가 되던 문제)
  const detection = stats.detectionStatus === 'HEALTHY' ? '오류 기록 없음'
    : stats.detectionStatus === 'DEGRADED'
      ? `기간 중 오류 ${stats.degraded !== undefined ? `${stats.degraded.toLocaleString('ko-KR')}건` : '기록 있음'}${lastError !== undefined ? ` · 마지막 ${formatShortDateTime(new Date(lastError).toISOString())}` : ''}`
      : '확인 불가';
  const { level, word } = overviewLevel(stats, stale);
  return <PgStatusStrip level={level} word={word} label="Gateway·Detection 상태" end={end} facts={[
    <span key="g" title="Gateway가 몇 초마다 보내는 실시간 지표를 최근 2분 안에 받았는지와 그 오류 건수로 판정합니다.">Gateway <b>{gateway.label}</b></span>,
    <span key="d">Detection <b>{detection}</b></span>,
    <span key="s" className="pg-strip-scope" title="선택 기간의 저장 이벤트 집계입니다. 서버의 현재 가용성이나 DB·Redis 상태를 확인한 결과는 아닙니다.">저장 기록 기준</span>,
    <span key="t">최신 기록 <time dateTime={stats.lastSuccessAt} title={stats.lastSuccessAt ? formatDateTime(stats.lastSuccessAt) : undefined}>{stats.lastSuccessAt ? formatShortDateTime(stats.lastSuccessAt) : '없음'}</time></span>,
  ]} />;
}

/** 최근 이벤트 1건의 판정 근거(제목): 검사 불가면 그 사유, 아니면 탐지 방식, 탐지 없음이면 '일치 없음' */
function eventReason(event: SecurityEvent) {
  const failure = inspectionFailure(event);
  if (failure) return failure.detail.split(' · ')[0];
  const detectors = [...new Set(event.detections.map(item => item.detector))];
  if (detectors.length) return detectors.map(detector => uiLabel(detector)).join(' · ');
  return event.detectionOutcome === 'NO_MATCH' ? '일치 없음' : '확인 불가';
}
const ACTION_TEXT = { BLOCK: '차단', MASK: '마스킹', ALLOW: '허용' } as const;
const ACTION_TONE = { BLOCK: 'block', MASK: 'mask', ALLOW: 'allow' } as const;

/**
 * 최근 이벤트(설계 4.6 '최근 이벤트' 행): 제목 = 판정 근거(상세 링크), 배지 = 조치, 정보 = LLM·문서·시각(문서가 없으면 그 칸을 숨겨 구분점이 남지 않게 LLM을 앞에).
 * 보안 현황 오른쪽 1/3 칸(표 자리 720px 이하)이라 넓은 화면에서도 짧은 목록(카드)으로 보인다. 이벤트 화면의 EventsTable은 쓰지 않는다(5.2).
 */
export function OverviewRecentTable({ events }: { events: SecurityEvent[] }) {
  return <Table card aria-label="최근 보안 이벤트" className="pg-ov-recent">
    <TableHeader>
      <TableRow><TableHead>판정 근거</TableHead><TableHead>최종 조치</TableHead><TableHead>대상 LLM</TableHead><TableHead>보호 문서</TableHead><TableHead>발생 시각</TableHead></TableRow>
    </TableHeader>
    <TableBody>{events.map(event => {
      const documents = [...new Map(event.detections.flatMap(item => 'matchedDocumentId' in item ? [[item.matchedDocumentId, item.matchedDocumentName ?? item.matchedDocumentId] as const] : [])).entries()];
      const failure = inspectionFailure(event);
      const action = event.groupFinalAction ?? event.finalAction;   // 목록 묶음이면 묶음 조치(보안 이벤트 목록과 같음)
      return <TableRow key={event.eventId} data-tone={ACTION_TONE[action]}>
        <TableCell data-card="title"><Link className="pg-ov-recent-link" to={`/events/${encodeURIComponent(event.eventId)}?view=compare`} aria-label={`${event.eventId} 상세 보기`} title={event.eventId}>{eventReason(event)}</Link></TableCell>
        <TableCell data-card="badge">{failure ? <PgBadge tone={action === 'ALLOW' ? 'mask' : ACTION_TONE[action]} title={failure.detail}>{failure.action}</PgBadge> : <PgBadge tone={ACTION_TONE[action]}>{ACTION_TEXT[action]}</PgBadge>}</TableCell>
        <TableCell data-card="info">{event.targetLlm}</TableCell>
        <TableCell data-card="info" data-empty={documents.length ? undefined : ''}>{documents.map(([id, name]) => <Link key={id} className="pg-ov-doc" to={`/documents/${encodeURIComponent(id)}`} title={name}>{name}</Link>)}</TableCell>
        <TableCell data-card="info" className="pg-num"><time dateTime={event.occurredAt} title={formatDateTime(event.occurredAt)}>{formatShortDateTime(event.occurredAt)}</time></TableCell>
      </TableRow>;
    })}</TableBody>
  </Table>;
}
