import './zodCsp';   // 반드시 첫 import: 스키마 모듈보다 먼저 jitless를 켠다
// 전역 CSS를 페이지보다 먼저: 대시보드(main.tsx → 지연 로드 페이지)와 같은 순서여야
// 페이지의 detection-ops.css가 Tailwind 유틸리티(.block{display:block} 등)를 이긴다
import '@/src/styles.css';
import '@/src/design-system.css';
import '@/src/console-system.css';
import '@/src/workbench-v3.css';
import '@/src/workbench-v31.css';
import '@/src/product-polish.css';
// 디자인 값·기본 규칙·이벤트 보존(재설계 1단계). 대시보드 main.tsx와 같은 순서로 전역 CSS 다음에 둔다. 파일 CSS만 쓴다(CSP style-src 'self')
import '@/src/styles/tokens.css';
import '@/src/styles/base.css';
import '@/src/styles/legacy-island.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClientProvider } from '@tanstack/react-query';
import { ExtensionMyRequestsApp } from './ExtensionMyRequestsApp';
import { createExtensionQueryClient } from './extensionQueryClient';

// 확장 프로그램 안 '내 요청 기록' 페이지(chrome-extension://<id>/myrequests/myrequests.html).
// MyRequestsPage는 라우터·로그인·Toaster를 쓰지 않으므로 QueryClientProvider만 둔다.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={createExtensionQueryClient()}>
      <ExtensionMyRequestsApp />
    </QueryClientProvider>
  </StrictMode>,
);
