import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  RefreshCcw,
} from 'lucide-react';
import type { ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { uiLabel } from '@/src/utils/labels';
import { safeMessage } from '@/src/utils/feedback';
import type {
  DetectorType,
  IncidentStatus,
  SecurityAction,
  TargetLlm,
} from '@/src/types/event';

export function ActionBadge({ action }: { action: SecurityAction }) {
  return (
    <span className={`badge badge-${action.toLowerCase()}`} title={uiLabel(action)}>{uiLabel(action).split(' (')[0]}</span>
  );
}
export function DetectorBadge({ detector }: { detector: DetectorType }) {
  return (
    <span className={`badge badge-${detector.toLowerCase()}`} title={detector}>{uiLabel(detector)}</span>
  );
}
export function LlmBadge({ llm }: { llm: TargetLlm }) {
  return <span className="llm-badge">{llm}</span>;
}
export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`incident-status status-${status.toLowerCase()}`}>
      <i />
      {uiLabel(status)}
    </span>
  );
}
export function StatusBadge({
  active,
  labels = ['ACTIVE', 'INACTIVE'],
}: {
  active: boolean;
  labels?: [string, string];
}) {
  return (
    <span className={`status-badge ${active ? 'on' : 'off'}`}>
      <i />
      {uiLabel(active ? labels[0] : labels[1])}
    </span>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
  status,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  action?: ReactNode;
  status?: ReactNode;
}) {
  return (
    <div className="page-header console-page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h2 title={title}>{title}</h2>
        {description && <p className="console-page-description" title={description}>{description}</p>}
      </div>
      {(action || status) && <div className="console-page-controls">{action}{status}</div>}
    </div>
  );
}

export function LoadingSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div
      className="loading-panel"
      aria-label="데이터를 불러오는 중"
      aria-busy="true"
      role="status"
    >
      <p className="loading-caption">데이터를 불러오는 중…</p>
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton className="loading-row" key={index} />
      ))}
    </div>
  );
}

export function EmptyState({
  title = '조회된 데이터가 없습니다.',
  description = '검색 조건을 변경한 뒤 다시 시도해보세요.',
}: {
  title?: string;
  description?: string;
}) {
  return (
    <div className="state-panel state-panel--empty" role="status">
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  error,
}: {
  message: string;
  onRetry?: () => void;
  error?: unknown;
}) {
  return (
    <div className="state-panel error" role="alert">
      <AlertTriangle aria-hidden="true" />
      <strong>{message}</strong>
      <p>{safeMessage(error)}</p>
      {onRetry && (
        <Button variant="outline" onClick={onRetry}>
          <RefreshCcw />
          다시 시도
        </Button>
      )}
    </div>
  );
}

export function Pagination({
  page,
  totalPages,
  total,
  onPage,
}: {
  page: number;
  totalPages: number;
  total: number;
  onPage: (page: number) => void;
}) {
  return (
    <div className="pagination">
      <span>
        총 {total.toLocaleString('ko-KR')}건 · {page.toLocaleString('ko-KR')} / {totalPages.toLocaleString('ko-KR')}쪽
      </span>
      <div>
        <Button
          variant="outline"
          size="sm"
          aria-label="이전 페이지"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          <ChevronLeft />
        </Button>
        <Button
          variant="outline"
          size="sm"
          aria-label="다음 페이지"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
        >
          <ChevronRight />
        </Button>
      </div>
    </div>
  );
}

export function FilterSelect({
  label,
  value,
  onChange,
  children,
  secondary = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
  secondary?: boolean;
}) {
  return (
    <label className={`filter-field${secondary ? ' filter-field--secondary' : ''}`}>
      <span>{label}</span>
      <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)}>
        {children}
      </select>
    </label>
  );
}
