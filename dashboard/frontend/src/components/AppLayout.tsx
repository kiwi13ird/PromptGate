import { LogOut, Menu, ShieldCheck, X } from 'lucide-react';
import { Suspense, useEffect, useRef, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '@/src/hooks/useAuth';
import { useDocumentTitle } from '@/src/hooks/useDocumentTitle';
import { NAV_GROUPS, PRODUCT_NAME, currentNavItem, isLegacyFrame, screenTitle } from '@/src/navigation';

/**
 * 관리자 화면 뼈대(재설계 2단계, 설계 2.1·7장): 왼쪽 메뉴 5묶음 11항목 + 본문.
 *  - 데스크톱 상단 띠 없음(화면 이름은 본문 제목에만). 관리자 이름·로그아웃은 메뉴 아래쪽
 *  - 800px 이하: 상단 띠(☰ + PromptGate) + 메뉴는 왼쪽에서 열리는 패널
 *  - 브라우저 탭 제목 = 화면 이름 · PromptGate
 *  - 이벤트 3화면(목록·상세·요청 확인)은 본문 자리에 data-frame="legacy": 본문 폭·여백·둘레 바탕을 옛 값으로 둬
 *    본문이 화소 단위로 그대로다(src/styles/legacy-island.css, 설계 5.2). 화면 읽기용 h1은 옛 상단 띠 제목을 숨김 글자로 둔다.
 * `.console-shell`·`.content`는 화면 CSS가 기대는 옛 이름이라 남긴다(4단계 정리 전까지).
 */
export function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const current = currentNavItem(pathname);
  const legacy = isLegacyFrame(pathname);
  const title = screenTitle(pathname);
  const displayName = user?.displayName === 'Local Administrator' ? '대시보드 관리자' : user?.displayName ?? '';

  useDocumentTitle(title);
  // 주소가 바뀌면(뒤로 가기 포함) 모바일 메뉴를 닫는다
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);
  // 열면 메뉴 안(닫기 버튼)으로, 닫기·Esc로 닫으면 ☰ 버튼으로 포커스. 본문은 열린 동안 inert라 닫힌 뒤(효과 단계)에 옮긴다
  const returnFocus = useRef(false);
  useEffect(() => {
    if (!mobileOpen) {
      if (returnFocus.current) { returnFocus.current = false; menuButton.current?.focus(); }
      return;
    }
    // 다음 그리기 때 옮긴다: 열린 직후에는 메뉴 안 요소의 visibility가 아직 hidden으로 남아 focus()가 무시된다(실브라우저 실측)
    const frame = requestAnimationFrame(() => closeButton.current?.focus());
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { returnFocus.current = true; setMobileOpen(false); }
    };
    document.addEventListener('keydown', closeOnEscape);
    return () => { cancelAnimationFrame(frame); document.removeEventListener('keydown', closeOnEscape); };
  }, [mobileOpen]);
  // 창을 넓히면(800px 초과) 모바일 메뉴 상태를 풀어 본문이 inert로 남지 않게 한다
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return;
    const wide = window.matchMedia('(min-width: 801px)');
    const onChange = () => { if (wide.matches) setMobileOpen(false); };
    wide.addEventListener('change', onChange);
    return () => wide.removeEventListener('change', onChange);
  }, []);

  const closeMenu = () => { returnFocus.current = true; setMobileOpen(false); };
  const handleLogout = async () => {
    await logout();
    void navigate('/login', { replace: true });
  };
  return (
    <div className={`console-shell pg-shell${mobileOpen ? ' is-menu-open' : ''}`} data-frame={legacy ? 'legacy' : undefined}>
      {mobileOpen && <button type="button" className="pg-nav-backdrop" aria-label="메뉴 닫기" tabIndex={-1} onClick={closeMenu} />}
      <aside id="console-navigation" className={`pg-nav${mobileOpen ? ' is-open' : ''}`} aria-label="관리자 메뉴">
        <div className="pg-nav-brand">
          <ShieldCheck aria-hidden="true" />
          <div className="pg-nav-brand-text">
            <span className="pg-nav-brand-name">{PRODUCT_NAME}</span>
            <span className="pg-nav-brand-sub">관리자 콘솔</span>
          </div>
          <button ref={closeButton} type="button" className="pg-nav-close" aria-label="메뉴 닫기" title="메뉴 닫기" onClick={closeMenu}>
            <X aria-hidden="true" />
          </button>
        </div>
        <nav className="pg-nav-menu" aria-label="주요 메뉴">
          {NAV_GROUPS.map((group) => (
            <div className="pg-nav-group" key={group.id} role="group" aria-labelledby={`pg-nav-group-${group.id}`}>
              <p className="pg-nav-group-label" id={`pg-nav-group-${group.id}`}>{group.label}</p>
              <ul className="pg-nav-list">
                {group.items.map(({ to, label, icon: Icon }) => {
                  const active = current?.to === to;
                  return (
                    <li key={to}>
                      <Link to={to} className={`pg-nav-link${active ? ' is-current' : ''}`} aria-current={active ? 'page' : undefined}
                        onClick={() => setMobileOpen(false)}>
                        <Icon aria-hidden="true" />
                        <span>{label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
        <div className="pg-nav-foot">
          <span className="pg-nav-avatar" aria-hidden="true">{displayName.slice(0, 1) || '관'}</span>
          <div className="pg-nav-user">
            <span className="pg-nav-user-name" title={displayName}>{displayName}</span>
            {user?.email && <span className="pg-nav-user-email" title={user.email}>{user.email}</span>}
          </div>
          <button type="button" className="pg-nav-logout" aria-label="로그아웃" title="로그아웃" onClick={handleLogout}>
            <LogOut aria-hidden="true" />
          </button>
        </div>
      </aside>
      <div className="pg-workspace" inert={mobileOpen || undefined}>
        <header className="pg-mobile-bar">
          <button
            ref={menuButton}
            type="button"
            className="pg-mobile-menu"
            aria-label="메뉴 열기"
            aria-expanded={mobileOpen}
            aria-controls="console-navigation"
            onClick={() => setMobileOpen(true)}
          >
            <Menu aria-hidden="true" />
          </button>
          <span className="pg-mobile-brand"><ShieldCheck aria-hidden="true" />{PRODUCT_NAME}</span>
        </header>
        {legacy && <h1 className="sr-only">{title}</h1>}
        <main className="content pg-main" id="main-content" data-frame={legacy ? 'legacy' : undefined}>
          <Suspense fallback={<div className="content-loading" role="status" aria-busy="true">화면을 불러오는 중…</div>}><Outlet /></Suspense>
        </main>
      </div>
    </div>
  );
}
