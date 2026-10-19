import { Button as ButtonPrimitive } from '@base-ui/react/button';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

// 모서리·글자·높이는 부품 값(--pg-button-*, src/styles/tokens.css)에서 읽는다. 이벤트 3화면([data-ui='legacy']) 안에서는
// legacy-island.css가 이 값을 원래 Tailwind 값(rounded-lg·text-sm·h-8 등)으로 다시 선언해 모양이 그대로다.
// 색은 옛 CSS가 걸어 둔 클래스 이름(bg-primary·border-border)을 그대로 두고 src/styles/base.css가 이벤트 범위 밖에서 덮는다.
// 위험 조치는 danger(빨간 글자 + 외곽선), 확인창의 확정 버튼은 danger-solid(빨간 채움, 설계 4.10).
const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-[var(--pg-button-radius)] border border-transparent bg-clip-padding text-[length:var(--pg-button-text)] leading-[var(--pg-button-leading)] [font-weight:var(--pg-button-weight)] whitespace-nowrap transition-all outline-none select-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 active:not-aria-[haspopup]:translate-y-px disabled:pointer-events-none disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-primary/80',
        outline:
          'border-border bg-background hover:bg-muted hover:text-foreground aria-expanded:bg-muted aria-expanded:text-foreground dark:border-input dark:bg-input/30 dark:hover:bg-input/50',
        secondary:
          'bg-secondary text-secondary-foreground hover:bg-[color-mix(in_oklch,var(--secondary),var(--foreground)_5%)] aria-expanded:bg-secondary aria-expanded:text-secondary-foreground',
        ghost:
          'hover:bg-muted hover:text-foreground aria-expanded:bg-muted aria-expanded:text-foreground dark:hover:bg-muted/50',
        destructive:
          'bg-destructive/10 text-destructive hover:bg-destructive/20 focus-visible:border-destructive/40 focus-visible:ring-destructive/20 dark:bg-destructive/20 dark:hover:bg-destructive/30 dark:focus-visible:ring-destructive/40',
        danger: 'pg-button-danger',
        'danger-solid': 'pg-button-danger-solid',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        default:
          'h-[var(--pg-button-h)] gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2',
        xs: "h-[var(--pg-button-h-xs)] gap-1 px-2 text-[length:var(--pg-button-text-xs)] leading-[var(--pg-button-leading-xs)] in-data-[slot=button-group]:rounded-lg has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-[var(--pg-button-h-sm)] gap-1 px-2.5 text-[length:var(--pg-button-text-sm)] in-data-[slot=button-group]:rounded-lg has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3.5",
        lg: 'h-[var(--pg-button-h-lg)] gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2',
        icon: 'size-[var(--pg-button-h)]',
        'icon-xs':
          "size-[var(--pg-button-h-xs)] in-data-[slot=button-group]:rounded-lg [&_svg:not([class*='size-'])]:size-3",
        'icon-sm':
          'size-[var(--pg-button-h-sm)] in-data-[slot=button-group]:rounded-lg',
        'icon-lg': 'size-[var(--pg-button-h-lg)]',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
);

function Button({
  className,
  variant = 'default',
  size = 'default',
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  );
}

export { Button, buttonVariants };
