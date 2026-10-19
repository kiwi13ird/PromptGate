import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import './styles.css';
import './design-system.css';
import './console-system.css';
import './workbench-v3.css';
import './workbench-v31.css';
import './product-polish.css';
// 디자인 값(--pg-*)·옛 변수 연결 → 기본 부품 → 공통 부품(pg-*, 2단계) → 화면별 배치(pg-*, 3단계) → 이벤트 3화면 보존(옛 값 다시 선언). 전역 CSS 다음, 맨 마지막에 둔다
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';
import './styles/screens.css';
import './styles/legacy-island.css';
import { AuthProvider } from './hooks/useAuth';
import { Toaster } from '@/components/ui/toast';
import { ApiError } from './api/errors';

const shouldRetryQuery = (failureCount: number, error: unknown) => {
  if (
    error instanceof ApiError &&
    ['UNAUTHORIZED', 'FORBIDDEN', 'VALIDATION'].includes(error.code)
  )
    return false;
  return failureCount < 1;
};

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      retry: shouldRetryQuery,
      refetchOnWindowFocus: false,
    },
    mutations: { retry: false },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Toaster>
            <App />
          </Toaster>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
