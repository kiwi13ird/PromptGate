import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { ListFilter, X } from 'lucide-react';
import { Button } from '@/components/ui/button';

export interface PgFilterChip {
  key: string;
  /** "기간: 최근 7일"처럼 이름과 값 */
  label: string;
  onRemove: () => void;
}

/**
 * 필터 바 틀(설계 4.7).
 *  항상 보임: 검색 + 화면별 핵심 필터 2개 + [필터 더보기 n]
 *  나머지: 데스크톱은 바 아래 펼침 패널, 모바일(800px 이하)은 아래에서 올라오는 시트(같은 요소, CSS로 위치만 바꿈)
 *  적용 표시: 기본값이 아닌 필터만 칩(× 지우기) + [초기화]
 * 보안 이벤트 화면 필터는 지금 그대로(설계 5.2) — 이 틀을 쓰지 않는다.
 */
export function PgFilterBar({ label = '필터', search, filters, more, moreCount = 0, chips = [], onReset }: {
  label?: string;
  search?: ReactNode;
  filters?: ReactNode;
  more?: ReactNode;
  /** 더보기 안에서 기본값이 아닌 필터 수(버튼에 "필터 n") */
  moreCount?: number;
  chips?: readonly PgFilterChip[];
  onReset?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setOpen(false); toggle.current?.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);
  return (
    <div className="pg-filter-bar" role="search" aria-label={label}>
      <div className="pg-filter-row">
        {search && <div className="pg-filter-search">{search}</div>}
        {filters && <div className="pg-filter-main">{filters}</div>}
        {more && (
          <Button ref={toggle} type="button" variant="outline" className="pg-filter-more" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((value) => !value)}>
            <ListFilter aria-hidden="true" />
            필터 더보기{moreCount > 0 && <span className="pg-filter-count" aria-label={`적용 ${moreCount}개`}>{moreCount}</span>}
          </Button>
        )}
      </div>
      {more && open && (
        <>
          <button type="button" className="pg-filter-sheet-backdrop" aria-label="필터 닫기" tabIndex={-1} onClick={() => setOpen(false)} />
          <div className="pg-filter-panel" id={panelId} role="group" aria-label="필터 더보기">
            <div className="pg-filter-panel-head">
              <span className="pg-filter-panel-title">필터</span>
              <Button type="button" variant="ghost" size="icon-sm" aria-label="필터 닫기" title="필터 닫기" onClick={() => { setOpen(false); toggle.current?.focus(); }}>
                <X aria-hidden="true" />
              </Button>
            </div>
            <div className="pg-filter-panel-body">{more}</div>
          </div>
        </>
      )}
      {chips.length > 0 && (
        <div className="pg-filter-chips" aria-label="적용한 필터">
          {chips.map((chip) => (
            <span key={chip.key} className="pg-filter-chip">
              {chip.label}
              <button type="button" aria-label={`${chip.label} 지우기`} title="지우기" onClick={chip.onRemove}><X aria-hidden="true" /></button>
            </span>
          ))}
          {onReset && <Button type="button" variant="ghost" size="sm" className="pg-filter-reset" onClick={onReset}>초기화</Button>}
        </div>
      )}
    </div>
  );
}
