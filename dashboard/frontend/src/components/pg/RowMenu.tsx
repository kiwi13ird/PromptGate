import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { MoreHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';

export interface PgRowMenuItem {
  label: string;
  /** 누르면 할 일(상태를 바꾸는 조치는 지금처럼 확인창을 거친다) */
  onSelect?: () => void;
  /** 이동·내려받기 링크 */
  href?: string;
  newTab?: boolean;
  download?: boolean;
  /** 위험 조치(빨간 글자) */
  danger?: boolean;
  disabled?: boolean;
  title?: string;
}

/**
 * 행 조치 ⋯ 메뉴(설계 4.5·4.10): 행에 보이는 버튼은 2개 이하(주·위험), 나머지는 이 메뉴 안.
 * 버튼 이름은 "<대상> 더보기"(어느 행의 메뉴인지 화면 읽기 프로그램이 알 수 있게).
 * 직접 만든 펼침 목록(role=menu): 열면 첫 항목으로 포커스, ↑↓·Home·End 이동, Esc·Tab·바깥 누름이면 닫고 버튼으로 포커스.
 * (Base UI Menu는 시험 환경(jsdom)에서 열 때 멈춰 쓰지 않았다 — stage3/README.md)
 */
export function PgRowMenu({ label, items, disabled = false }: { label: string; items: readonly PgRowMenuItem[]; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLSpanElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const id = useId();
  const entries = () => [...(list.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([aria-disabled="true"])') ?? [])];
  const close = (focus = true) => { setOpen(false); if (focus) trigger.current?.focus(); };

  useEffect(() => {
    if (!open) return;
    entries()[0]?.focus();
    const outside = (event: PointerEvent | MouseEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener('pointerdown', outside);
    document.addEventListener('mousedown', outside);
    return () => { document.removeEventListener('pointerdown', outside); document.removeEventListener('mousedown', outside); };
  }, [open]);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const all = entries();
    const at = all.indexOf(document.activeElement as HTMLElement);
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    else if (event.key === 'Tab') close(false);
    else if (event.key === 'ArrowDown') { event.preventDefault(); all[(at + 1) % all.length]?.focus(); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); all[(at - 1 + all.length) % all.length]?.focus(); }
    else if (event.key === 'Home') { event.preventDefault(); all[0]?.focus(); }
    else if (event.key === 'End') { event.preventDefault(); all[all.length - 1]?.focus(); }
  };

  return (
    <span className="pg-row-menu" ref={root}>
      <Button ref={trigger} variant="ghost" size="icon-sm" className="pg-row-menu-trigger" aria-label={`${label} 더보기`} title="더보기" disabled={disabled}
        aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen((value) => !value)}>
        <MoreHorizontal aria-hidden="true" />
      </Button>
      {open && (
        <div ref={list} id={id} role="menu" aria-label={`${label} 조치`} className="pg-menu-popup" onKeyDown={onKeyDown}>
          {items.map((item) => {
            const className = `pg-menu-item${item.danger ? ' pg-menu-item--danger' : ''}`;
            return item.href ? (
              <a key={item.label} role="menuitem" tabIndex={-1} className={className} href={item.href} title={item.title}
                target={item.newTab ? '_blank' : undefined} rel={item.newTab ? 'noopener noreferrer' : undefined} download={item.download || undefined} onClick={() => setOpen(false)}>
                {item.label}
              </a>
            ) : (
              <button key={item.label} type="button" role="menuitem" tabIndex={-1} className={className} title={item.title}
                aria-disabled={item.disabled || undefined} disabled={item.disabled} onClick={() => { close(); item.onSelect?.(); }}>
                {item.label}
              </button>
            );
          })}
        </div>
      )}
    </span>
  );
}
