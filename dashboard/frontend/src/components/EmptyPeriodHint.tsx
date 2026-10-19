import { Button } from '@/components/ui/button';
import type { OverviewPeriod } from '@/src/types/event';

export function EmptyPeriodHint({ period, onExpand }: { period: OverviewPeriod; onExpand: () => void }) {
  if (period === '30D') return null;
  return <div className="empty-period-hint" role="status"><span>선택 기간에 기록이 없습니다. 현재 조건을 유지하고 더 넓은 기간을 확인할 수 있습니다.</span><Button variant="outline" size="sm" onClick={onExpand}>최근 30일 보기</Button></div>;
}
