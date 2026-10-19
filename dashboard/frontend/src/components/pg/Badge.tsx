import type { HTMLAttributes, ReactNode } from 'react';
import { badgeTone, type BadgeTone } from './badgeTone';

/**
 * 배지 1종(설계 4.4). 높이 22 · 12px/700 · 둥근 끝 · 계열 바탕 + 계열 글자.
 *  variant: default(기본) / dot(연결 중·정상 같은 실시간 상태) / tag(회색 사각: LLM 이름·유형 이름·승인된 키워드 — 계열 색 없음)
 *  tone을 주지 않으면 value(또는 children 글자)로 계열을 정한다(badgeTone.ts 표).
 * 이벤트 3화면은 옛 배지(common.tsx ActionBadge 등) 그대로 쓴다(설계 5.2).
 */
export function PgBadge({ value, tone, variant = 'default', className = '', children, ...rest }: {
  /** 표시 글자이자 계열을 정하는 값. children을 주면 글자는 children */
  value?: string;
  tone?: BadgeTone;
  variant?: 'default' | 'dot' | 'tag';
  className?: string;
  children?: ReactNode;
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children' | 'className'>) {
  const label = children ?? value;
  const resolved = variant === 'tag' ? undefined : tone ?? badgeTone(value ?? (typeof children === 'string' ? children : undefined));
  const classes = ['pg-badge', resolved ? `pg-badge--${resolved}` : '', variant !== 'default' ? `pg-badge--${variant}` : '', className].filter(Boolean).join(' ');
  return <span {...rest} className={classes} data-tone={resolved}>{label}</span>;
}
