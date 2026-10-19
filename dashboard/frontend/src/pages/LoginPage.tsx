import { LockKeyhole, ShieldCheck } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useAuth } from '@/src/hooks/useAuth';
import { uiMode } from '@runtime/ui-mode';
import { useDocumentTitle } from '@/src/hooks/useDocumentTitle';
import { CONSOLE_NAME } from '@/src/navigation';

export function LoginPage() {
  const { user, login, demoCredentials } = useAuth();
  useDocumentTitle('관리자 로그인');
  const navigate = useNavigate();
  const location = useLocation();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const destination =
    typeof location.state === 'object' &&
    location.state &&
    'from' in location.state &&
    typeof location.state.from === 'string'
      ? location.state.from
      : '/overview';
  if (user) return <Navigate to={destination} replace />;

  const handleSubmit = async (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await login(identifier, password);
      void navigate(destination, { replace: true });
    } catch {
      setError('아이디 또는 비밀번호를 확인해주세요.');
    } finally {
      setSubmitting(false);
    }
  };
  const fillDemo = () => {
    if (!demoCredentials) return;
    setIdentifier(demoCredentials.identifier);
    setPassword(demoCredentials.password);
    setError('');
  };

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="login-title">
        <header className="login-identity"><div className="brand-mark">
          <ShieldCheck aria-hidden="true" />
        </div>
        <h1 id="login-title">{CONSOLE_NAME}</h1></header>
        <div className="login-workspace">
        <h2>관리자 로그인</h2>
        <p className="muted">보호 문서와 외부 AI 전송 기록을 확인합니다.</p>
        <form className="login-form" onSubmit={handleSubmit}>
          <label htmlFor="adminId">관리자 ID 또는 이메일</label>
          <Input
            id="adminId"
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
            autoComplete="username"
            placeholder="admin@company.com"
            required
          />
          <label htmlFor="password">비밀번호</label>
          <Input
            id="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
            autoComplete="current-password"
            placeholder="비밀번호 입력"
            required
          />
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? '인증 중...' : '로그인'}
          </Button>
        </form>
        {demoCredentials && (
          <button className="demo-fill" type="button" onClick={fillDemo}>
            데모 계정 자동 입력
          </button>
        )}
        <div className="demo-note">
          <LockKeyhole aria-hidden="true" />
          <span>
            <strong>{uiMode.authTitle}</strong>
            <br />
            {uiMode.authDescription}
          </span>
        </div>
        </div>
      </section>
    </main>
  );
}
