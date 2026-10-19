import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { BadgeTone } from './badgeTone';

/**
 * 지표 부품(재설계 3단계, 설계 5.1.1·5.9.1). 색은 상태 5계열만(차단·주의 진하게, 허용은 정상 계열 50%).
 * 막대 길이는 계산한 값이라 style(width·height)로 준다(대시보드 화면만 씀, 확장 '내 요청 기록'은 쓰지 않음 — 확장 CSP는 인라인 style 금지).
 * 모든 그림은 role="img" + 숫자를 담은 이름(aria-label)으로 화면 읽기 프로그램에 같은 정보를 준다.
 */
export type MetricTone = BadgeTone | 'allow-soft';

const fill = (tone: MetricTone) => `pg-fill--${tone}`;
const ko = (value: number) => value.toLocaleString('ko-KR');

/** 0이 아닌 값이 너무 작아 안 보이지 않게 최소 2% */
export function share(value: number, total: number) {
  if (!total || value <= 0) return 0;
  return Math.min(100, Math.max(2, (value / total) * 100));
}

/** "▲ 12 · 63%" 증감 칩. 직전 0이면 "직전 0건". 차단·마스킹 증가만 계열 색(tone), 나머지는 중립 */
export function PgDelta({ current, previous, tone = 'neutral', label }: { current: number; previous: number; tone?: BadgeTone; label?: string }) {
  const diff = current - previous;
  const text = previous === 0 ? (current === 0 ? '변화 없음' : '직전 0건') : diff === 0 ? '변화 없음' : `${diff > 0 ? '▲' : '▼'} ${ko(Math.abs(diff))} · ${Math.round((Math.abs(diff) / previous) * 100)}%`;
  const colored = diff > 0 && (tone === 'block' || tone === 'mask');
  return (
    <span className={`pg-delta${colored ? ` pg-delta--${tone}` : ''}`} title={label ?? `직전 같은 길이 기간 ${ko(previous)}건`}>
      {text}
    </span>
  );
}

export interface HBarRow {
  key: string;
  label: string;
  /** 조각(계열·값). 합이 줄의 값 */
  parts: readonly { tone: MetricTone; value: number; name: string }[];
  /** 누르면 이동할 주소(목록·설정 화면) */
  to?: string;
  /** 줄 끝 숫자 옆 작은 글자 */
  note?: string;
}

/** 누적 가로 막대 n줄: 이름 | 막대(조각) | 합. 막대 길이는 가장 큰 줄 기준 */
export function PgHBars({ rows, label, max = rows.length }: { rows: readonly HBarRow[]; label: string; max?: number }) {
  const shown = rows.slice(0, max);
  const top = Math.max(1, ...shown.map((row) => row.parts.reduce((sum, part) => sum + part.value, 0)));
  return (
    <ol className="pg-hbars" aria-label={label}>
      {shown.map((row) => {
        const total = row.parts.reduce((sum, part) => sum + part.value, 0);
        const description = `${row.label} ${row.parts.filter((part) => part.value > 0).map((part) => `${part.name} ${ko(part.value)}건`).join(', ') || '0건'}`;
        const body = (
          <>
            <span className="pg-hbar-label" title={row.label}>{row.label}</span>
            <span className="pg-hbar-track" role="img" aria-label={description}>
              {row.parts.map((part) => part.value > 0 && <span key={part.name} className={`pg-hbar-seg ${fill(part.tone)}`} style={{ width: `${share(part.value, top)}%` }} />)}
            </span>
            <span className="pg-hbar-value">{ko(total)}{row.note && <small>{row.note}</small>}</span>
          </>
        );
        return <li key={row.key}>{row.to ? <Link className="pg-hbar" to={row.to}>{body}</Link> : <span className="pg-hbar">{body}</span>}</li>;
      })}
    </ol>
  );
}

/** 분할 막대: 한 줄을 비율로 나눔 + 범례(이름·값). 값이 모두 0이면 빈 막대 */
export function PgSplitBar({ parts, label, legend = true }: { parts: readonly { tone: MetricTone; value: number; name: string }[]; label: string; legend?: boolean }) {
  const total = parts.reduce((sum, part) => sum + part.value, 0);
  return (
    <div className="pg-split">
      <span className="pg-split-track" role="img" aria-label={`${label}: ${parts.map((part) => `${part.name} ${ko(part.value)}`).join(', ')}`}>
        {parts.map((part) => part.value > 0 && <span key={part.name} className={fill(part.tone)} style={{ width: `${share(part.value, total)}%` }} />)}
      </span>
      {legend && (
        <ul className="pg-legend" aria-hidden="true">
          {parts.map((part) => <li key={part.name}><i className={fill(part.tone)} />{part.name} <b>{ko(part.value)}</b></li>)}
        </ul>
      )}
    </div>
  );
}

export interface MiniBar {
  key: string;
  /** 눈금 글자(아래) */
  label: string;
  value: number;
  tone?: MetricTone;
  /** 막대 위 숫자를 보일지 */
  showValue?: boolean;
  title?: string;
}

/**
 * 작은 막대 그림: 세로 막대 n개 + 아래 눈금. 높이 = 가장 큰 값 기준. limitAfter를 주면 그 막대 뒤에 점선(설정 대기 시간 자리).
 * 데이터가 적어도 막대 폭은 24px 이하(설계 4.9). 막대 위 숫자 자리(16px)를 위에 비워 둔다.
 */
export function PgMiniBars({ bars, label, height = 88, limitAfter, limitLabel, footer }: {
  bars: readonly MiniBar[];
  label: string;
  height?: number;
  limitAfter?: string;
  limitLabel?: string;
  footer?: ReactNode;
}) {
  const top = Math.max(1, ...bars.map((bar) => bar.value));
  const pct = (amount: number) => (amount > 0 ? Math.max(3, (amount / top) * 100) : 0);
  return (
    <figure className="pg-minibars">
      <div className="pg-minibars-plot" role="img" aria-label={`${label}: ${bars.map((bar) => `${bar.label} ${ko(bar.value)}건`).join(', ')}`} style={{ height }}>
        {bars.map((bar) => (
          <span key={bar.key} className={`pg-minibar${limitAfter === bar.key ? ' has-limit' : ''}`} title={bar.title ?? `${bar.label} ${ko(bar.value)}건`} data-limit={limitAfter === bar.key ? limitLabel : undefined}>
            <span className="pg-minibar-col">
              <span className={`pg-minibar-fill ${fill(bar.tone ?? 'neutral')}`} style={{ height: `${pct(bar.value)}%` }} />
              {bar.showValue !== false && bar.value > 0 && <span className="pg-minibar-value" style={{ bottom: `${pct(bar.value)}%` }}>{ko(bar.value)}</span>}
            </span>
          </span>
        ))}
      </div>
      <div className="pg-minibars-axis" aria-hidden="true">
        {/* 2026-10-14: 글자를 칸 가운데에 띄워 칸보다 넓어도 잘리지 않게(막대 25개 × 390px에서 '13시'가 '1'로 잘렸음). 눈금 글자는 sparseLabels로 띄엄띄엄 */}
        {bars.map((bar) => <span key={bar.key}><span className="pg-minibars-tick">{bar.label}</span></span>)}
      </div>
      {footer && <figcaption className="pg-minibars-foot">{footer}</figcaption>}
    </figure>
  );
}
