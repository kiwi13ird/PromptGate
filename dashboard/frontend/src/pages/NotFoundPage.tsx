import { ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useDocumentTitle } from '@/src/hooks/useDocumentTitle';

export function NotFoundPage() {
  useDocumentTitle('페이지 없음');
  return (
    <main className="full-not-found">
      <div className="not-found-card">
        <p className="not-found-brand">Security Gateway</p>
        <p className="eyebrow">404 · 페이지 없음</p>
        <h1>요청한 페이지를 찾을 수 없습니다.</h1>
        <p>주소가 올바른지 확인하거나 보안 현황으로 돌아가세요.</p>
        <Link to="/overview">
          <ArrowLeft aria-hidden="true" /> 보안 현황으로 돌아가기
        </Link>
      </div>
    </main>
  );
}
