import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppLayout } from '@/src/components/AppLayout';
import { useAuth } from '@/src/hooks/useAuth';

const LoginPage = lazy(() =>
  import('@/src/pages/LoginPage').then((module) => ({
    default: module.LoginPage,
  })),
);
const OverviewPage = lazy(() =>
  import('@/src/pages/OverviewPage').then((module) => ({
    default: module.OverviewPage,
  })),
);
const TrafficPerformancePage = lazy(() =>
  import('@/src/pages/TrafficPerformancePage').then((module) => ({
    default: module.TrafficPerformancePage,
  })),
);
const ProtectedDocumentsPage = lazy(() =>
  import('@/src/pages/ProtectedDocumentsPage').then((module) => ({
    default: module.ProtectedDocumentsPage,
  })),
);
const ProtectedDocumentDetailPage = lazy(() =>
  import('@/src/pages/ProtectedDocumentDetailPage').then((module) => ({
    default: module.ProtectedDocumentDetailPage,
  })),
);
const SecurityEventsPage = lazy(() =>
  import('@/src/pages/SecurityEventsPage').then((module) => ({
    default: module.SecurityEventsPage,
  })),
);
const EventDetailPage = lazy(() =>
  import('@/src/pages/EventDetailPage').then((module) => ({
    default: module.EventDetailPage,
  })),
);
const RequestReviewPage = lazy(() => import('@/src/pages/RequestReviewPage').then(module => ({ default: module.RequestReviewPage })));
const PolicyManagementPage = lazy(() =>
  import('@/src/pages/PolicyManagementPage').then((module) => ({
    default: module.PolicyManagementPage,
  })),
);
const AuditLogsPage = lazy(() =>
  import('@/src/pages/AuditLogsPage').then((module) => ({
    default: module.AuditLogsPage,
  })),
);
const DocumentKeywordsPage = lazy(() => import('@/src/pages/DocumentKeywordsPage').then(module => ({ default: module.DocumentKeywordsPage })));
// Gateway 처리 설정(2026-10-10): 탐지 정책 메뉴의 세 번째 보기
const GatewaySettingsPage = lazy(() => import('@/src/pages/GatewaySettingsPage').then(module => ({ default: module.GatewaySettingsPage })));
// 접속 차단(2026-10-12): 탐지 정책 메뉴의 네 번째 보기
const GatewayAccessPage = lazy(() => import('@/src/pages/GatewayAccessPage').then(module => ({ default: module.GatewayAccessPage })));
const ReportsPage = lazy(() => import('@/src/pages/ReportsPage').then(module => ({ default: module.ReportsPage })));
// 시스템 상태(2026-10-12): 연결된 인스턴스·DB·서비스 상태. 보고 메뉴
const SystemStatusPage = lazy(() => import('@/src/pages/SystemStatusPage').then(module => ({ default: module.SystemStatusPage })));
// 내 요청 기록(2026-10-09): 확장 프로그램 사용자용. 관리자 로그인·메뉴 밖
const MyRequestsPage = lazy(() => import('@/src/pages/MyRequestsPage').then(module => ({ default: module.MyRequestsPage })));
const NotFoundPage = lazy(() =>
  import('@/src/pages/NotFoundPage').then((module) => ({
    default: module.NotFoundPage,
  })),
);

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const location = useLocation();
  return user ? (
    children
  ) : (
    <Navigate
      to="/login"
      replace
      state={{ from: location.pathname + location.search }}
    />
  );
}

function HomeRedirect() {
  const { user } = useAuth();
  return <Navigate to={user ? '/overview' : '/login'} replace />;
}

export default function App() {
  return (
    <Suspense
      fallback={
        <output className="route-loading">화면을 불러오는 중...</output>
      }
    >
      <Routes>
        <Route path="/" element={<HomeRedirect />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/my-requests" element={<MyRequestsPage />} />
        <Route
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >
          <Route
            path="/dashboard"
            element={<Navigate to="/overview" replace />}
          />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/traffic" element={<TrafficPerformancePage />} />
          <Route path="/documents" element={<ProtectedDocumentsPage />} />
          <Route
            path="/documents/:documentId"
            element={<ProtectedDocumentDetailPage />}
          />
          <Route path="/events" element={<SecurityEventsPage />} />
          <Route path="/events/:eventId" element={<EventDetailPage />} />
          <Route path="/requests/:requestId" element={<RequestReviewPage />} />
          <Route path="/policies" element={<PolicyManagementPage />} />
          <Route path="/policies/keywords" element={<DocumentKeywordsPage />} />
          <Route path="/policies/gateway" element={<GatewaySettingsPage />} />
          <Route path="/policies/access" element={<GatewayAccessPage />} />
          <Route path="/audit-logs" element={<AuditLogsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/system" element={<SystemStatusPage />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  );
}
