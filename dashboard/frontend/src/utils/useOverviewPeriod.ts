import { useSearchParams } from 'react-router-dom';
import type { OverviewPeriod } from '@/src/types/event';

export function useOverviewPeriod() {
  const [params, setParams] = useSearchParams();
  const raw = params.get('period');
  const period: OverviewPeriod = raw === '7D' || raw === '30D' ? raw : '24H';
  const setPeriod = (value: OverviewPeriod) => {
    const next = new URLSearchParams(params);
    if (value === '24H') next.delete('period');
    else next.set('period', value);
    setParams(next);
  };
  return [period, setPeriod] as const;
}
