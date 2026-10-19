import type { EventTimeBucket } from '@/src/utils/eventSeries';
import { bucketLabel } from '@/src/utils/eventSeries';
import type { OverviewPeriod } from '@/src/types/event';
import { chartColor } from '@/src/utils/chartColors';

export function EventBucketTooltip({active,payload,period}: {active?:boolean;payload?:ReadonlyArray<{payload?:EventTimeBucket}>;period:OverviewPeriod}) {
  const point = payload?.[0]?.payload;
  if (!active || !point) return null;
  return <div className="recharts-default-tooltip" style={{padding:10,background:chartColor('tooltipBackground'),border:`1px solid ${chartColor('tooltipBorder')}`,color:chartColor('tooltipText'),fontSize:12}}>
    <p>{bucketLabel(point.start,period,true)} · GMT+9{point.partial ? ' · 부분 구간' : ''}</p>
    <p>차단 {point.block.toLocaleString('ko-KR')} · 마스킹 {point.mask.toLocaleString('ko-KR')} · 허용 {point.allow.toLocaleString('ko-KR')}</p>
    <strong>합계 {point.total.toLocaleString('ko-KR')}건</strong>
  </div>;
}
