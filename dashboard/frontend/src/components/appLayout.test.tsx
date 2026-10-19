import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';
import { AppLayout } from '@/src/components/AppLayout';
import { AuthProvider } from '@/src/hooks/useAuth';
import { NAV_GROUPS, NAV_ITEMS, currentNavItem, isLegacyFrame, screenTitle } from '@/src/navigation';

// 재설계 2단계 뼈대(설계 2.1·2.2·7장): 메뉴 5묶음 11항목, 경로 그대로, 현재 항목, 탭 제목, 이벤트 화면 본문 자리, 모바일 메뉴
const SESSION_KEY = 'llm-security-gateway-demo-session-v3';
const signIn = () => window.sessionStorage.setItem(SESSION_KEY, JSON.stringify({ id: 'admin-001', email: 'admin@securegate.local', displayName: 'Security Admin', role: 'Gateway Administrator' }));

// 설계 2.1 표 그대로(묶음 순서·항목 순서·경로)
const EXPECTED = [
  ['현황', [['보안 현황', '/overview'], ['보안 이벤트', '/events']]],
  ['보호 대상', [['보호 문서', '/documents'], ['문서별 키워드', '/policies/keywords']]],
  ['정책·차단', [['탐지 정책', '/policies'], ['Gateway 처리', '/policies/gateway'], ['접속 차단', '/policies/access']]],
  ['운영 상태', [['트래픽 및 성능', '/traffic'], ['시스템 상태', '/system']]],
  ['기록', [['리포트', '/reports'], ['감사 로그', '/audit-logs']]],
] as const;
// App.tsx의 관리자 라우트(경로를 하나도 바꾸지 않았는지 대조)
const APP_ROUTES = ['/overview', '/traffic', '/documents', '/events', '/policies', '/policies/keywords', '/policies/gateway', '/policies/access', '/audit-logs', '/reports', '/system'];

// AuthProvider가 세션을 읽은 뒤 뼈대를 그리므로 메뉴가 보일 때까지 기다린다
async function mount(path: string) {
  signIn();
  const view = render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<AppLayout />}>
            {[...APP_ROUTES, '/events/:id', '/requests/:id', '/documents/:id'].map((route) => (
              <Route key={route} path={route} element={<p>화면 {route}</p>} />
            ))}
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByRole('navigation', { name: '주요 메뉴' });
  return view;
}
const menu = () => screen.getByRole('navigation', { name: '주요 메뉴' });

beforeEach(() => { document.title = ''; });

describe('menu data', () => {
  it('has 5 groups and 11 items exactly as design 2.1, and every route of App.tsx', () => {
    expect(NAV_GROUPS.map((group) => [group.label, group.items.map((item) => [item.label, item.to])])).toEqual(EXPECTED);
    expect(NAV_ITEMS).toHaveLength(11);
    expect(NAV_ITEMS.map((item) => item.to).sort()).toEqual([...APP_ROUTES].sort());
  });

  it('maps every address to one current item, the tab title and the event-screen frame', () => {
    for (const item of NAV_ITEMS) {
      expect(currentNavItem(item.to)?.to).toBe(item.to);
      expect(screenTitle(item.to)).toBe(item.label);   // 메뉴 이름 = 화면 이름(탭 제목)
    }
    expect(currentNavItem('/policies/keywords')?.label).toBe('문서별 키워드');   // 하위 경로처럼 보여도 자기 항목
    expect(currentNavItem('/events/evt-1')?.label).toBe('보안 이벤트');
    expect(currentNavItem('/requests/req-1')?.label).toBe('보안 이벤트');
    expect(currentNavItem('/documents/doc%2F1')?.label).toBe('보호 문서');
    expect(currentNavItem('/overview/')?.label).toBe('보안 현황');
    expect(screenTitle('/events/evt-1')).toBe('이벤트 상세');
    expect(screenTitle('/requests/req-1')).toBe('요청 확인');
    expect(screenTitle('/documents/doc-1')).toBe('보호 문서 상세');
    expect(['/events', '/events/evt-1', '/requests/req-1'].every(isLegacyFrame)).toBe(true);
    expect(['/overview', '/documents/doc-1', '/policies', '/eventsx'].some(isLegacyFrame)).toBe(false);
  });
});

describe('AppLayout', () => {
  it('renders the 5 labelled groups, brand, admin and logout in the menu, and no desktop top bar title', async () => {
    await mount('/overview');
    expect(screen.getByText('PromptGate', { selector: '.pg-nav-brand-name' })).toBeInTheDocument();
    expect(screen.queryByText(/Security Gateway/)).toBeNull();
    for (const [group, items] of EXPECTED) {
      const region = within(menu()).getByRole('group', { name: group });
      expect(within(region).getAllByRole('link').map((link) => [link.textContent, link.getAttribute('href')])).toEqual(items);
    }
    const admin = screen.getByRole('complementary', { name: '관리자 메뉴' });
    expect(within(admin).getByText('Security Admin')).toBeInTheDocument();
    expect(within(admin).getByRole('button', { name: '로그아웃' })).toBeInTheDocument();
    // 화면 이름은 본문 제목에만(상단 띠 h1 없음)
    expect(screen.queryByRole('heading', { level: 1 })).toBeNull();
    // 모바일 상단 띠: ☰ + PromptGate(화면 이름 없음)
    const bar = screen.getByRole('button', { name: '메뉴 열기' }).closest('header') as HTMLElement;
    expect(bar.textContent).toBe('PromptGate');
  });

  it.each([
    ['/overview', '보안 현황', '보안 현황 · PromptGate'],
    ['/policies', '탐지 정책', '탐지 정책 · PromptGate'],
    ['/policies/keywords', '문서별 키워드', '문서별 키워드 · PromptGate'],
    ['/policies/gateway', 'Gateway 처리', 'Gateway 처리 · PromptGate'],
    ['/audit-logs', '감사 로그', '감사 로그 · PromptGate'],
    ['/events', '보안 이벤트', '보안 이벤트 · PromptGate'],
    ['/events/evt-1', '보안 이벤트', '이벤트 상세 · PromptGate'],
    ['/requests/req-1', '보안 이벤트', '요청 확인 · PromptGate'],
    ['/documents/doc-1', '보호 문서', '보호 문서 상세 · PromptGate'],
  ])('%s marks %s as current and sets the tab title', async (path, current, title) => {
    await mount(path);
    const links = within(menu()).getAllByRole('link');
    expect(links.filter((link) => link.getAttribute('aria-current') === 'page').map((link) => link.textContent)).toEqual([current]);
    await waitFor(() => expect(document.title).toBe(title));
  });

  it('moves to every one of the 11 screens from the menu', async () => {
    await mount('/overview');
    for (const item of NAV_ITEMS) {
      fireEvent.click(within(menu()).getByRole('link', { name: item.label }));
      expect(await screen.findByText(`화면 ${item.to}`)).toBeInTheDocument();
      expect(within(menu()).getByRole('link', { name: item.label })).toHaveAttribute('aria-current', 'page');
      await waitFor(() => expect(document.title).toBe(`${item.label} · PromptGate`));
    }
  });

  it('keeps the event screens in the legacy body frame with a hidden screen-reader heading', async () => {
    const { unmount } = await mount('/events/evt-1');
    const main = screen.getByRole('main');
    expect(main).toHaveAttribute('data-frame', 'legacy');
    expect(main).toHaveClass('content');   // 이벤트 화면 CSS가 기대는 옛 이름
    expect(screen.getByRole('heading', { level: 1, name: '이벤트 상세' })).toHaveClass('sr-only');
    unmount();
    await mount('/overview');
    expect(screen.getByRole('main')).not.toHaveAttribute('data-frame');
  });

  it('opens the mobile menu, focuses inside it, and closes with Esc returning focus to the menu button', async () => {
    await mount('/overview');
    const open = screen.getByRole('button', { name: '메뉴 열기' });
    expect(open).toHaveAttribute('aria-expanded', 'false');
    expect(open).toHaveAttribute('aria-controls', 'console-navigation');
    fireEvent.click(open);
    expect(open).toHaveAttribute('aria-expanded', 'true');
    expect(document.getElementById('console-navigation')).toHaveClass('is-open');
    const close = within(screen.getByRole('complementary', { name: '관리자 메뉴' })).getByRole('button', { name: '메뉴 닫기' });
    await waitFor(() => expect(close).toHaveFocus());
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(open).toHaveAttribute('aria-expanded', 'false');
    await waitFor(() => expect(open).toHaveFocus());
  });

  it('closes the mobile menu when a menu link is chosen', async () => {
    await mount('/overview');
    fireEvent.click(screen.getByRole('button', { name: '메뉴 열기' }));
    fireEvent.click(within(menu()).getByRole('link', { name: '감사 로그' }));
    expect(await screen.findByText('화면 /audit-logs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '메뉴 열기' })).toHaveAttribute('aria-expanded', 'false');
  });
});
