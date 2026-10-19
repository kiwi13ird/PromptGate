// 재설계 2단계 공통 부품(클래스 접두 pg-, 스타일은 src/styles/components.css). 사용법: docs/design/dashboard-redesign-2026-10-13/stage2/README.md 3절.
// 이벤트 3화면(목록·상세·요청 확인)은 이 부품을 쓰지 않고 옛 부품(common.tsx 등)을 그대로 쓴다(설계 5.2 방법 3).
export { PgPageHeader, PgRefresh, PgTabs, clockText, type PgTabItem } from './PageHeader';
export { PgStatusStrip, STRIP_WORD, STRIP_TONE, type StripLevel } from './StatusStrip';
export { PgBadge } from './Badge';
export { badgeTone, BADGE_TONE_VALUES, type BadgeTone } from './badgeTone';
export { PgDrawer } from './Drawer';
export { PgEmpty, PgError, PgSkeleton } from './States';
export { PgPager, PgCount } from './Pager';
export { PgFilterBar, type PgFilterChip } from './FilterBar';
export { PgSegment } from './Segment';
export { PgConfirmDialog, confirmTitle } from './ConfirmDialog';
export { PgDelta, PgHBars, PgSplitBar, PgMiniBars, share, type HBarRow, type MiniBar, type MetricTone } from './Metrics';
export { PgRowMenu, type PgRowMenuItem } from './RowMenu';
export { PgPeriod, PERIOD_LABELS } from './Period';
