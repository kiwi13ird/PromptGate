import { useEffect, useRef, useState } from 'react';
import { RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { formatCount } from '@/src/utils/format';

// React Query pauses interval fetching in background tabs by default.
export const liveQueryOptions = {
  refetchInterval: 10_000,
  refetchIntervalInBackground: false,
  refetchOnWindowFocus: true,
} as const;

export function AutoRefreshBar({ updatedAt, fetching, failed, onRefresh, total, scope = '', countLabel = '이벤트', onNew, latestAt, compact = false, recentAt }: {
  updatedAt: number;
  fetching: boolean;
  failed?: boolean;
  onRefresh: () => unknown;
  total?: number;
  scope?: string;
  countLabel?: string;
  onNew?: () => unknown;
  latestAt?: string;
  compact?: boolean;
  /** 최신순 첫 쪽의 기록 시각들(2026-10-16, 감사 1/4-14 — 보안 현황 PgRefresh와 같은 규칙). 주면 전체 건수 차이 대신
   * '직전 조회의 가장 최근 기록보다 새 기록 수'로 센다. 굴러가는 기간에서 옛 기록이 빠지고 새 기록이 들어와 건수 차이가 0이면 알림이 빠지던 문제 */
  recentAt?: readonly string[];
}) {
  const previous = useRef<{ scope: string; total: number; latest: number } | null>(null);
  const [newCount, setNewCount] = useState(0);
  const recentKey = recentAt?.join('|');
  useEffect(() => {
    if (total === undefined) return;
    const times = recentAt?.map((value) => Date.parse(value)).filter(Number.isFinite) ?? [];
    const latest = times.length ? Math.max(...times) : 0;
    const before = previous.current;
    if (!before || before.scope !== scope) setNewCount(0);
    else if (recentAt && before.latest > 0) {
      const added = times.filter((value) => value > before.latest).length;
      if (added > 0) setNewCount((value) => value + added);
    } else if (total > before.total) setNewCount(value => value + total - before.total);
    previous.current = { scope, total, latest: recentAt ? Math.max(latest, before?.scope === scope ? before.latest : 0) : 0 };
    // recentKey로 recentAt 내용 변경을 본다(배열은 조회마다 새로 만들어짐)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [total, scope, recentKey]);
  return <div className={`auto-refresh-bar${compact ? ' console-refresh' : ''}`}>
    <span className="refresh-status" role={failed ? 'status' : undefined} title={failed ? updatedAt > 0 ? '갱신 실패 · 아래는 마지막 성공 조회 결과입니다' : '조회 실패 · 서버 연결을 확인하세요' : '10초마다 자동 갱신 · 비활성 탭에서는 일시 정지'}>
      {compact && <i className={failed ? 'is-failed' : 'is-live'} aria-hidden="true" />}
      {failed ? compact ? '갱신 실패' : updatedAt > 0 ? '갱신 실패 · 아래는 마지막 성공 조회 결과입니다' : '조회 실패 · 서버 연결을 확인하세요' : fetching ? '갱신 중' : compact ? '자동 갱신' : '10초마다 자동 갱신'}
      {updatedAt > 0 && <span className="refresh-updated"> · {compact ? '조회' : '마지막 조회'} {new Date(updatedAt).toLocaleTimeString('ko-KR', { timeZone: 'Asia/Seoul', hourCycle: 'h23' })}</span>}
    </span>
    {latestAt && !compact && <span className="latest-record-time">최신 기록 {new Date(latestAt).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', hour12: false })} · 저장 이벤트 기준</span>}
    {newCount > 0 && !failed && <button type="button" className="new-event-notice" onClick={() => { setNewCount(0); void onNew?.(); }} aria-live="polite">현재 조건에서 {countLabel} {formatCount(newCount)}건 증가 · {onNew ? '최신 기록 보기' : '확인'}</button>}
    <Button size="sm" variant="outline" disabled={fetching} onClick={() => { setNewCount(0); void onRefresh(); }}><RefreshCcw size={14} />새로고침</Button>
  </div>;
}
