'use client';

import * as React from 'react';

import { cn } from '@/lib/utils';

// 표 → 카드(설계 4.6, 재설계 2단계): card를 켜면 감싼 영역 폭이 720px 이하일 때 같은 <table>을 카드로 그린다
// (CSS 컨테이너 쿼리, src/styles/components.css 6절). 칸마다 data-card="title|badge|info|body|actions|hide"를 붙인다.
// CSS display를 바꿔도 표 역할이 남도록 card 표는 role(table·rowgroup·row·columnheader·cell)을 명시한다.
// card를 켜지 않은 표(이벤트 화면의 EventsTable 등)는 지금과 같은 DOM을 그린다.
const TableCardContext = React.createContext(false);

function Table({ className, card = false, ...props }: React.ComponentProps<'table'> & { card?: boolean }) {
  return (
    <TableCardContext.Provider value={card}>
      <div
        data-slot="table-container"
        className={card ? 'relative w-full overflow-x-auto pg-table-wrap' : 'relative w-full overflow-x-auto'}
      >
        <table
          data-slot="table"
          role={card ? 'table' : undefined}
          // 글자·머리 높이·굵기는 부품 값(--pg-table-*)에서 읽는다. 이벤트 3화면 안에서는 legacy-island.css가 원래 값으로 고정
          className={cn('w-full caption-bottom text-[length:var(--pg-table-text)] leading-[var(--pg-table-leading)]', card && 'pg-table', className)}
          {...props}
        />
      </div>
    </TableCardContext.Provider>
  );
}

const useCardRole = (role: string) => (React.useContext(TableCardContext) ? role : undefined);

function TableHeader({ className, ...props }: React.ComponentProps<'thead'>) {
  return (
    <thead
      data-slot="table-header"
      role={useCardRole('rowgroup')}
      className={cn('[&_tr]:border-b', className)}
      {...props}
    />
  );
}

function TableBody({ className, ...props }: React.ComponentProps<'tbody'>) {
  return (
    <tbody
      data-slot="table-body"
      role={useCardRole('rowgroup')}
      className={cn('[&_tr:last-child]:border-0', className)}
      {...props}
    />
  );
}

function TableFooter({ className, ...props }: React.ComponentProps<'tfoot'>) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn(
        'bg-muted/50 border-t font-medium [&>tr]:last:border-b-0',
        className,
      )}
      {...props}
    />
  );
}

function TableRow({ className, ...props }: React.ComponentProps<'tr'>) {
  return (
    <tr
      data-slot="table-row"
      role={useCardRole('row')}
      className={cn(
        'hover:bg-muted/50 data-[state=selected]:bg-muted border-b transition-colors has-aria-expanded:bg-muted/50',
        className,
      )}
      {...props}
    />
  );
}

function TableHead({ className, ...props }: React.ComponentProps<'th'>) {
  return (
    <th
      data-slot="table-head"
      role={useCardRole('columnheader')}
      className={cn(
        'text-foreground h-[var(--pg-table-head-h)] px-2 text-left align-middle [font-weight:var(--pg-table-head-weight)] whitespace-nowrap [&:has([role=checkbox])]:pr-0',
        className,
      )}
      {...props}
    />
  );
}

function TableCell({ className, ...props }: React.ComponentProps<'td'>) {
  return (
    <td
      data-slot="table-cell"
      role={useCardRole('cell')}
      className={cn(
        'p-2 align-middle whitespace-nowrap [&:has([role=checkbox])]:pr-0',
        className,
      )}
      {...props}
    />
  );
}

function TableCaption({
  className,
  ...props
}: React.ComponentProps<'caption'>) {
  return (
    <caption
      data-slot="table-caption"
      className={cn('text-muted-foreground mt-4 text-[length:var(--pg-table-text)] leading-[var(--pg-table-leading)]', className)}
      {...props}
    />
  );
}

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
};
