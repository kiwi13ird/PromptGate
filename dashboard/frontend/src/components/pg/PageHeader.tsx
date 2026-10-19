import { useEffect, useRef, useState, type MouseEventHandler, type ReactNode } from 'react';
import { RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { formatCount } from '@/src/utils/format';

/**
 * 페이지 머리(설계 4.1). 이벤트 3화면(목록·상세·요청 확인)은 쓰지 않는다 — 그 화면은 옛 PageHeader(common.tsx) 그대로(설계 5.2).
 *
 *  왼쪽: 제목(h1, --pg-t-xl) + 설명 1줄(넘치면 말줄임, 전체 글은 title)
 *  오른쪽(순서 고정): 기간 → 주 행동 1개 → 보조 2개 이하 → 갱신 시각 → 새로고침
 *  탭: 제목 줄 아래 한 자리 / 상태 띠: 머리 바로 아래(있는 화면만)
 *  모바일(800px 이하): 오른쪽 묶음이 제목 아래로 내려가고 갱신 시각 글자는 숨긴다(실패 표시는 남김)
 *
 * 옛 PageHeader 호환: action → 주 행동 자리, status → 갱신 자리. eyebrow는 받기만 하고 그리지 않는다(새 머리에 없음).
 */
export function PgPageHeader({
  title,
  description,
  period,
  primary,
  secondary,
  refresh,
  tabs,
  strip,
  action,
  status,
}: {
  title: string;
  description?: string;
  /** 기간 선택(세그먼트 등) */
  period?: ReactNode;
  /** 주 행동 1개(브랜드 채움 버튼) */
  primary?: ReactNode;
  /** 보조 2개 이하(보조 버튼·상태 배지·읽기 전용 표시) */
  secondary?: ReactNode;
  /** 갱신 시각 + 새로고침(PgRefresh) */
  refresh?: ReactNode;
  /** 제목 아래 탭(PgTabs) */
  tabs?: ReactNode;
  /** 머리 아래 상태 띠(PgStatusStrip) */
  strip?: ReactNode;
  /** @deprecated 옛 PageHeader 호환 — primary와 같음 */
  action?: ReactNode;
  /** @deprecated 옛 PageHeader 호환 — refresh와 같음 */
  status?: ReactNode;
  /** @deprecated 옛 PageHeader 호환 — 그리지 않음 */
  eyebrow?: string;
}) {
  const main = primary ?? action;
  const updated = refresh ?? status;
  const hasActions = Boolean(period || main || secondary || updated);
  return (
    <header className="pg-page-header">
      <div className="pg-page-header-row">
        <div className="pg-page-heading">
          <h1 className="pg-page-title">{title}</h1>
          {description && <p className="pg-page-description" title={description}>{description}</p>}
        </div>
        {hasActions && (
          <div className="pg-page-actions">
            {period && <div className="pg-page-slot pg-page-slot--period">{period}</div>}
            {main && <div className="pg-page-slot pg-page-slot--primary">{main}</div>}
            {secondary && <div className="pg-page-slot pg-page-slot--secondary">{secondary}</div>}
            {updated && <div className="pg-page-slot pg-page-slot--refresh">{updated}</div>}
          </div>
        )}
      </div>
      {tabs && <div className="pg-page-tabs">{tabs}</div>}
      {strip}
    </header>
  );
}

const timeFormat = new Intl.DateTimeFormat('ko-KR', { timeZone: 'Asia/Seoul', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
/** "09:11:37" (서울 시각) */
export function clockText(at: number) {
  const parts = timeFormat.formatToParts(new Date(at));
  const pick = (type: Intl.DateTimeFormatPartTypes) => parts.find((part) => part.type === type)?.value ?? '00';
  return `${pick('hour')}:${pick('minute')}:${pick('second')}`;
}

/**
 * 머리 오른쪽 끝의 갱신 시각 + 새로고침 아이콘(설계 4.1·4.9). 옛 AutoRefreshBar(이벤트 화면이 씀)는 그대로 두고 따로 만든다.
 *  정상: "09:11:37 갱신" / 갱신 중: "갱신 중" / 실패: "갱신 실패 · 09:11:37 값"(주의 계열, 이전 값은 화면에 그대로)
 *  total·scope를 주면 같은 조건에서 늘어난 건수를 알린다(옛 바와 같은 동작).
 */
export function PgRefresh({ updatedAt, fetching, failed, onRefresh, total, scope = '', countLabel = '이벤트', onNew, recentAt }: {
  updatedAt: number;
  fetching: boolean;
  failed?: boolean;
  onRefresh: () => unknown;
  total?: number;
  scope?: string;
  countLabel?: string;
  onNew?: () => unknown;
  /** 최근 기록 시각들(2026-10-15 감사 14번). 주면 전체 건수 차이 대신 '직전 조회의 가장 최근 기록보다 새 기록 수'로 센다 —
   * 굴러가는 기간에서 옛 기록이 빠지고 새 기록이 들어오면 건수 차이가 0이 되어 알림이 빠지던 문제 */
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
    else if (recentAt) {
      const added = times.filter((value) => value > before.latest).length;
      if (added > 0) setNewCount((value) => value + added);
    } else if (total > before.total) setNewCount((value) => value + total - before.total);
    previous.current = { scope, total, latest: recentAt ? Math.max(latest, before?.scope === scope ? before.latest : 0) : latest };
    // recentKey로 recentAt 내용 변경을 본다(배열은 조회마다 새로 만들어짐)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [total, scope, recentKey]);
  const time = updatedAt > 0 ? clockText(updatedAt) : '';
  const text = failed ? (time ? `갱신 실패 · ${time} 값` : '조회 실패') : fetching ? '갱신 중' : time ? `${time} 갱신` : '자동 갱신';
  const hint = failed
    ? time ? '갱신 실패 · 화면은 마지막 성공 조회 결과입니다' : '조회 실패 · 서버 연결을 확인하세요'
    : '10초마다 자동 갱신 · 비활성 탭에서는 일시 정지';
  return (
    <span className="pg-refresh">
      <span className={`pg-refresh-time${failed ? ' is-failed' : ''}`} role={failed ? 'status' : undefined} title={hint}>{text}</span>
      {newCount > 0 && !failed && (
        <button type="button" className="pg-refresh-new" aria-live="polite" onClick={() => { setNewCount(0); void onNew?.(); }}>
          현재 조건에서 {countLabel} {formatCount(newCount)}건 증가 · {onNew ? '최신 기록 보기' : '확인'}
        </button>
      )}
      <Button variant="outline" size="icon" className="pg-refresh-button" aria-label="새로고침" title="새로고침" disabled={fetching}
        onClick={() => { setNewCount(0); void onRefresh(); }}>
        <RefreshCcw aria-hidden="true" />
      </Button>
    </span>
  );
}

export interface PgTabItem {
  label: string;
  href: string;
  current: boolean;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
}

/** 한 화면 안의 보기 전환 탭(머리 tabs 자리). 화면 사이 이동은 메뉴가 맡는다(정책 탭 줄은 없앰, 설계 2.1) */
export function PgTabs({ label, items, className = '' }: { label: string; items: readonly PgTabItem[]; className?: string }) {
  return (
    <nav className={`pg-tabs ${className}`.trim()} aria-label={label}>
      {items.map((item) => (
        <a key={item.href} href={item.href} aria-current={item.current ? 'page' : undefined} onClick={item.onClick}>{item.label}</a>
      ))}
    </nav>
  );
}
