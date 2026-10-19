import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { ActionCounts, OverviewInsights, OverviewPeriod } from '@/src/types/event';
import { uiLabel } from '@/src/utils/labels';
import '@/src/overview-insights.css';
import { formatCount } from '@/src/utils/format';

// 보안 현황 그래프 (2026-10-10): 정보 유형·보호 문서 상위, 서비스·입력 형태별 조치 비율, 요일·시간대 분포
// 재설계 3b(설계 5.1): 처리 흐름 패널은 전체 지표 카드의 비율 막대로 합쳐 없앴다(같은 숫자 3번 → 1번). 그래프는 카드(pg-card) 2열로
const DAYS = [1, 2, 3, 4, 5, 6, 0];
const DAY_NAMES = ['일', '월', '화', '수', '목', '금', '토'];
// 0과 전체가 아니면 반올림해도 0%·100%로 보이지 않게 1~99%로 둔다
export const percent = (value: number, total: number) => {
  if (!total) return '—';
  if (value <= 0) return '0%';
  if (value >= total) return '100%';
  return `${Math.min(99, Math.max(1, Math.round((value / total) * 100)))}%`;
};
const totalOf = (row: ActionCounts) => row.block + row.mask + row.allow;

function Bars({ rows, tone, unit, empty }: { rows: Array<{ key: string; label: string; count: number; to?: string }>; tone: string; unit: string; empty: string }) {
  if (!rows.length) return <p className="console-empty-inline">{empty}</p>;
  const top = Math.max(1, ...rows.map(row => row.count));
  return <ol className="ov-bars">{rows.map(row => <li key={row.key}>
    {row.to ? <Link className="ov-bar-name" to={row.to} title={row.label}>{row.label}</Link> : <span className="ov-bar-name" title={row.label}>{row.label}</span>}
    <span className="ov-bar-track" aria-hidden="true"><i className={tone} style={{ width: `${(row.count / top) * 100}%` }} /></span>
    <span className="ov-bar-num">{row.count.toLocaleString('ko-KR')}<small>{unit}</small></span>
  </li>)}</ol>;
}

function Mix({ rows, label, to }: { rows: ActionCounts[]; label: (key: string) => string; to?: (key: string) => string }) {
  const visible = rows.filter(row => totalOf(row) > 0);
  if (!visible.length) return <p className="console-empty-inline">기록 없음</p>;
  return <ul className="ov-mix">{visible.map(row => {
    const size = totalOf(row);
    return <li key={row.key}>
      {to ? <Link className="ov-mix-name" to={to(row.key)}>{label(row.key)}</Link> : <span className="ov-mix-name">{label(row.key)}</span>}
      <span className="ov-stack" role="img" aria-label={`${label(row.key)} 차단 ${formatCount(row.block)}건, 마스킹 ${formatCount(row.mask)}건, 허용 ${formatCount(row.allow)}건`}>
        {row.block > 0 && <i className="ov-block" style={{ width: `${(row.block / size) * 100}%` }} />}
        {row.mask > 0 && <i className="ov-mask" style={{ width: `${(row.mask / size) * 100}%` }} />}
        {row.allow > 0 && <i className="ov-allow" style={{ width: `${(row.allow / size) * 100}%` }} />}
      </span>
      <span className="ov-mix-num">{size.toLocaleString('ko-KR')}건 · 조치 <b>{percent(row.block + row.mask, size)}</b></span>
    </li>;
  })}</ul>;
}

const Keys = () => <div className="ov-keys"><span><i className="ov-block" />차단</span><span><i className="ov-mask" />마스킹</span><span><i className="ov-allow" />허용</span></div>;

export function heatmapSummary(heatmap: number[][]) {
  let total = 0, offHours = 0, peak = { count: 0, day: 0, hour: 0 };
  heatmap.forEach((row, day) => row.forEach((count, hour) => {
    total += count;
    if (day === 0 || day === 6 || hour < 8 || hour >= 20) offHours += count;
    if (count > peak.count) peak = { count, day, hour };
  }));
  return { total, offHours, peak };
}

function Heatmap({ heatmap }: { heatmap: number[][] }) {
  const { total, offHours, peak } = heatmapSummary(heatmap);
  if (!total) return <p className="console-empty-inline">기간 안에 차단·마스킹 기록이 없습니다.</p>;
  const level = (count: number) => (count === 0 ? 0 : 1 + Math.min(3, Math.floor((count / peak.count) * 3.999)));
  return <>
    <div className="ov-heat-wrap"><div className="ov-heat" role="img" aria-label="요일과 시간대별 차단·마스킹 건수">
      {DAYS.map(day => [<span key={`d${day}`} className="ov-heat-day">{DAY_NAMES[day]}</span>,
        ...heatmap[day].map((count, hour) => <span key={`${day}-${hour}`} className={`ov-heat-cell l${level(count)}`} title={`${DAY_NAMES[day]}요일 ${hour}시 ${formatCount(count)}건`} />)])}
      <span />{Array.from({ length: 24 }, (_, hour) => <span key={`h${hour}`} className="ov-heat-hour">{hour % 3 === 0 ? hour : ''}</span>)}
    </div></div>
    <p className="ov-insight">가장 많은 시간 {DAY_NAMES[peak.day]}요일 {peak.hour}시({formatCount(peak.count)}건) · 업무 시간 밖(평일 20시~8시, 주말) {percent(offHours, total)}</p>
  </>;
}

function Card({ title, note, children, wide = false }: { title: string; note?: ReactNode; children: ReactNode; wide?: boolean }) {
  return <article className={`pg-card ov-card${wide ? ' pg-span-2' : ''}`}>
    <header className="pg-card-head"><h3 className="pg-card-title">{title}</h3>{note && <div className="pg-card-note pg-card-head-end">{note}</div>}</header>
    <div className="pg-card-body ov-card-body">{children}</div>
  </article>;
}

/**
 * 탐지 분석 카드 묶음(2열): [lead(차단·마스킹 사유) · 유출 시도 정보 유형] → [노린 보호 문서 · 서비스별] → [입력 형태별 · 요일·시간대].
 * 요일·시간대는 7일·30일에서만(24시간은 위 추이와 같은 내용이라 한 줄 안내, 설계 4.9).
 */
export function InsightsSection({ insights, period, lead, recordUnit = false }: { insights: OverviewInsights; period: OverviewPeriod; lead?: ReactNode;
  /** 새 서버(2026-10-15): 그래프는 기록 단위(프롬프트·파일 각각) · 접속 차단 제외 — 요청 단위인 위 카드와 단위가 달라 적는다 */
  recordUnit?: boolean }) {
  const unitNote = recordUnit ? <p className="ov-note">기록 단위(프롬프트·파일 각각) · 접속 차단 제외 · 재전송·재시도는 1건</p> : null;
  const types = insights.entityCounts.slice(0, 6).map(point => ({ key: point.key, label: uiLabel(point.key), count: point.count }));
  const rest = insights.entityCounts.slice(6);
  const prompt = insights.contentActions.find(row => row.key === 'prompt');
  const file = insights.contentActions.find(row => row.key === 'file');
  const rate = (row?: ActionCounts) => (row && totalOf(row) ? (row.block + row.mask) / totalOf(row) : 0);
  const ratio = rate(prompt) > 0 && rate(file) > 0 ? rate(file) / rate(prompt) : 0;
  return <section className="pg-ov-insights pg-grid-2" aria-label="탐지 분석">
    {lead}
    <Card title="유출 시도 정보 유형" note="탐지된 값 개수 · 상위 6">
      <Bars rows={types} tone="ov-mask" unit="개" empty="민감정보 탐지 기록 없음" />
      {rest.length > 0 && <p className="ov-note">그 외 {rest.map(point => `${uiLabel(point.key)} ${point.count}`).join(', ')}</p>}
    </Card>
    <Card title="노린 보호 문서" note="문서 구간 일치 건 · 상위 5">
      <Bars rows={insights.documents.map(point => ({ key: point.key, label: point.name ?? point.key, count: point.count, to: `/documents/${encodeURIComponent(point.key)}` }))} tone="ov-block" unit="건" empty="보호 문서 일치 기록 없음" />
    </Card>
    <Card title="서비스별 조치 비율" note={<Keys />}>
      <Mix rows={insights.llmActions} label={key => key} to={key => `/events?period=${period}&llm=${encodeURIComponent(key)}`} />
      {unitNote}
    </Card>
    <Card title="입력 형태별 조치 비율" note={<Keys />}>
      <Mix rows={insights.contentActions} label={key => (key === 'file' ? '파일' : '프롬프트')} />
      {ratio >= 1.2 && <p className="ov-insight">파일 업로드의 조치 비율이 프롬프트의 {ratio.toFixed(1)}배</p>}
      {unitNote}
    </Card>
    {period === '24H'
      ? <p className="pg-card pg-ov-heat-note">요일·시간대별 차단·마스킹은 7일·30일에서 표시 (24시간은 위 이벤트 추이와 같은 내용)</p>
      : <Card title="요일·시간대별 차단·마스킹" note="한국 시간 · 진할수록 많음"><Heatmap heatmap={insights.heatmap} /></Card>}
  </section>;
}
