import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';

/**
 * 쪽 이동(설계 4.5): 표 아래 오른쪽. 개수("128건")는 표 위 왼쪽에 따로 둔다(PgCount).
 * 한 쪽뿐이면 그리지 않는다. 버튼 이름은 옛 Pagination과 같다(이전 페이지·다음 페이지).
 */
export function PgPager({ page, totalPages, onPage, label = '쪽 이동' }: {
  page: number;
  totalPages: number;
  onPage: (page: number) => void;
  label?: string;
}) {
  if (totalPages <= 1) return null;
  return (
    <nav className="pg-pager" aria-label={label}>
      <span className="pg-pager-status" aria-live="polite">{page} / {totalPages}쪽</span>
      <Button variant="outline" size="icon-sm" aria-label="이전 페이지" title="이전 페이지" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        <ChevronLeft aria-hidden="true" />
      </Button>
      <Button variant="outline" size="icon-sm" aria-label="다음 페이지" title="다음 페이지" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
        <ChevronRight aria-hidden="true" />
      </Button>
    </nav>
  );
}

/** 표 위 왼쪽 개수("128건") */
export function PgCount({ total, unit = '건' }: { total: number; unit?: string }) {
  return <span className="pg-count">{total.toLocaleString('ko-KR')}{unit}</span>;
}
