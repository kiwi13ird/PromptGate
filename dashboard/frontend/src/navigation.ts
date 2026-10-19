import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  Ban,
  ChartNoAxesCombined,
  FileLock,
  FileText,
  Files,
  HeartPulse,
  LayoutDashboard,
  ScrollText,
  SlidersHorizontal,
  Tags,
} from 'lucide-react';

// 관리자 메뉴 = 페이지 제목 = 브라우저 탭 제목(설계 2.1·2.2). 경로는 App.tsx 라우트 그대로(하나도 바꾸지 않음).
// 묶음은 이 데이터로만 정한다(예전 AppLayout의 links.slice(index * 3) 고정 분할을 대신함).
export const PRODUCT_NAME = 'PromptGate';
export const CONSOLE_NAME = `${PRODUCT_NAME} 관리자 콘솔`;

export interface NavItem {
  /** 링크 주소(라우트 경로) */
  to: string;
  /** 메뉴 이름 = 페이지 제목(h1) = 브라우저 탭 제목 */
  label: string;
  icon: LucideIcon;
  /** 이 항목을 현재 항목으로 표시할 하위 경로(앞부분 일치). 예: 이벤트 상세 → 보안 이벤트 */
  prefixes?: readonly string[];
}

export interface NavGroup {
  id: string;
  label: string;
  items: readonly NavItem[];
}

export const NAV_GROUPS: readonly NavGroup[] = [
  {
    id: 'status',
    label: '현황',
    items: [
      { to: '/overview', label: '보안 현황', icon: LayoutDashboard },
      { to: '/events', label: '보안 이벤트', icon: Activity, prefixes: ['/events/', '/requests/'] },
    ],
  },
  {
    id: 'assets',
    label: '보호 대상',
    items: [
      { to: '/documents', label: '보호 문서', icon: Files, prefixes: ['/documents/'] },
      { to: '/policies/keywords', label: '문서별 키워드', icon: Tags },
    ],
  },
  {
    id: 'policy',
    label: '정책·차단',
    items: [
      { to: '/policies', label: '탐지 정책', icon: FileLock },
      { to: '/policies/gateway', label: 'Gateway 처리', icon: SlidersHorizontal },
      { to: '/policies/access', label: '접속 차단', icon: Ban },
    ],
  },
  {
    id: 'operations',
    label: '운영 상태',
    items: [
      { to: '/traffic', label: '트래픽 및 성능', icon: ChartNoAxesCombined },
      { to: '/system', label: '시스템 상태', icon: HeartPulse },
    ],
  },
  {
    id: 'records',
    label: '기록',
    items: [
      { to: '/reports', label: '리포트', icon: FileText },
      { to: '/audit-logs', label: '감사 로그', icon: ScrollText },
    ],
  },
];

export const NAV_ITEMS: readonly NavItem[] = NAV_GROUPS.flatMap((group) => group.items);

/** 지금 주소에 해당하는 메뉴 항목. 정확히 같은 경로를 먼저 보고, 없으면 하위 경로(prefixes)로 찾는다 */
export function currentNavItem(pathname: string): NavItem | undefined {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  return NAV_ITEMS.find((item) => item.to === path)
    ?? NAV_ITEMS.find((item) => item.prefixes?.some((prefix) => path.startsWith(prefix)));
}

/** 이벤트 3화면(목록·상세·요청 확인): 본문은 옛 모양 그대로(설계 5.2). 바깥 뼈대만 새 모양 */
export function isLegacyFrame(pathname: string) {
  return pathname === '/events' || pathname.startsWith('/events/') || pathname.startsWith('/requests/');
}

/**
 * 화면 이름(브라우저 탭 제목에 쓰는 이름). 메뉴 화면은 메뉴 이름, 상세 화면은 상세 이름.
 * 이벤트 화면의 본문 제목('보안 이벤트 조회' 등)은 바꾸지 않고 탭 제목만 이 이름을 쓴다.
 */
export function screenTitle(pathname: string): string {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  if (path.startsWith('/events/')) return '이벤트 상세';
  if (path.startsWith('/requests/')) return '요청 확인';
  if (path.startsWith('/documents/')) return '보호 문서 상세';
  return NAV_ITEMS.find((item) => item.to === path)?.label ?? '관리자 콘솔';
}

/** 브라우저 탭 제목: "보안 현황 · PromptGate" */
export function documentTitle(title: string) {
  return `${title} · ${PRODUCT_NAME}`;
}
