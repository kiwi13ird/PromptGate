import type { OverviewPeriod } from '@/src/types/event';
import { PgSegment } from './Segment';

export const PERIOD_LABELS: Readonly<Record<OverviewPeriod, string>> = { '24H': '24시간', '7D': '7일', '30D': '30일' };

/** 머리 기간 선택(설계 4.1·4.7): 24시간·7일·30일 세그먼트(속은 라디오). 보안 현황·트래픽이 같이 쓴다 */
export function PgPeriod({ value, onChange, label }: { value: OverviewPeriod; onChange: (value: OverviewPeriod) => void; label: string }) {
  return (
    <PgSegment legend={label} legendHidden name={`pg-period-${label}`} className="pg-period" value={value} onChange={onChange}
      options={(Object.keys(PERIOD_LABELS) as OverviewPeriod[]).map((period) => ({ value: period, label: PERIOD_LABELS[period] }))} />
  );
}
