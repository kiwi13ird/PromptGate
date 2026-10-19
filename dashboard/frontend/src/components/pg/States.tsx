import { useEffect, useState, type ReactNode } from 'react';
import { AlertTriangle, RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { safeMessage } from '@/src/utils/feedback';

/**
 * 빈 상태(설계 4.9): 표·목록 자리 안에 한 줄(높이 96px 이하). "최근 24시간 이벤트 없음" + 다음 행동 1개. 큰 흰 상자를 쓰지 않는다.
 * 이벤트 화면은 옛 EmptyState(common.tsx) 그대로.
 */
export function PgEmpty({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="pg-empty" role="status">
      <span className="pg-empty-title">{title}</span>
      {description && <span className="pg-empty-desc">{description}</span>}
      {action && <span className="pg-empty-action">{action}</span>}
    </div>
  );
}

/**
 * 오류(설계 4.9)
 *  page: 전체 실패 — 머리는 남기고 본문 자리에 상자 1개(이유 1줄 + 다시 시도)
 *  inline: 부분 실패 — 해당 카드 자리(또는 머리 아래)에 주의 계열 한 줄("연결 중 IP를 불러오지 못함 · 다시 시도")
 */
export function PgError({ message, error, onRetry, variant = 'page' }: {
  message: string;
  error?: unknown;
  onRetry?: () => unknown;
  variant?: 'page' | 'inline';
}) {
  const reason = error === undefined ? '' : safeMessage(error);
  if (variant === 'inline') {
    return (
      <div className="pg-error pg-error--inline" role="alert">
        <AlertTriangle aria-hidden="true" />
        <span className="pg-error-message">{message}</span>
        {reason && <span className="pg-error-reason">{reason}</span>}
        {onRetry && <button type="button" className="pg-error-retry" onClick={() => void onRetry()}>다시 시도</button>}
      </div>
    );
  }
  return (
    <div className="pg-error pg-error--page" role="alert">
      <AlertTriangle aria-hidden="true" />
      <div className="pg-error-text">
        <span className="pg-error-message">{message}</span>
        {reason && <span className="pg-error-reason">{reason}</span>}
      </div>
      {onRetry && (
        <Button variant="outline" onClick={() => void onRetry()}>
          <RefreshCcw aria-hidden="true" />
          다시 시도
        </Button>
      )}
    </div>
  );
}

/**
 * 로딩 뼈대(설계 4.9): 실제 배치 모양(지표 4칸 · 표 5줄). delayMs(기본 300ms)가 지나야 모양을 그린다 — 빠른 응답에서 깜빡이지 않게.
 * 화면 읽기 프로그램에는 처음부터 "데이터를 불러오는 중"을 알린다.
 */
export function PgSkeleton({ shape = 'table', rows = 5, delayMs = 300 }: { shape?: 'kpi' | 'table' | 'kpi-table'; rows?: number; delayMs?: number }) {
  const [visible, setVisible] = useState(delayMs <= 0);
  useEffect(() => {
    if (delayMs <= 0) return;
    const timer = setTimeout(() => setVisible(true), delayMs);
    return () => clearTimeout(timer);
  }, [delayMs]);
  return (
    <div className="pg-skeleton" role="status" aria-busy="true" aria-label="데이터를 불러오는 중" data-visible={visible ? 'true' : 'false'}>
      <span className="sr-only">데이터를 불러오는 중…</span>
      {visible && (shape === 'kpi' || shape === 'kpi-table') && (
        <div className="pg-skeleton-kpis" aria-hidden="true">{Array.from({ length: 4 }, (_, index) => <span key={index} className="pg-skeleton-block pg-skeleton-kpi" />)}</div>
      )}
      {visible && (shape === 'table' || shape === 'kpi-table') && (
        <div className="pg-skeleton-table" aria-hidden="true">
          <span className="pg-skeleton-block pg-skeleton-head" />
          {Array.from({ length: rows }, (_, index) => <span key={index} className="pg-skeleton-block pg-skeleton-row" />)}
        </div>
      )}
    </div>
  );
}
