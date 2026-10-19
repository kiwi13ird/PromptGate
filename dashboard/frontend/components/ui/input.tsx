import * as React from 'react';
import { Input as InputPrimitive } from '@base-ui/react/input';

import { cn } from '@/lib/utils';

function Input({ className, type, ...props }: React.ComponentProps<'input'>) {
  return (
    <InputPrimitive
      type={type}
      data-slot="input"
      className={cn(
        // 높이·모서리·글자는 부품 값(--pg-input-*)에서 읽는다. 이벤트 3화면 안에서는 legacy-island.css가 원래 값(h-8·rounded-lg·text-base/md:text-sm)으로 고정
        'h-[var(--pg-input-h)] w-full min-w-0 rounded-[var(--pg-input-radius)] border border-input bg-transparent px-2.5 py-1 text-[length:var(--pg-input-text)] leading-[var(--pg-input-leading)] transition-colors outline-none file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-input/50 disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 md:text-[length:var(--pg-input-text-md)] md:leading-[var(--pg-input-leading-md)] dark:bg-input/30 dark:disabled:bg-input/80 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40',
        className,
      )}
      {...props}
    />
  );
}

export { Input };
