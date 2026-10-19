import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { authService } from '@/src/services/authService';
import { setUnauthorizedHandler } from '@/src/api/httpClient';
import type { DemoCredentials } from '@/src/auth/authAdapter';
import type { AdminUser } from '@/src/types/auth';

interface AuthContextValue {
  user: AdminUser | null;
  ready: boolean;
  demoCredentials: DemoCredentials | null;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<AdminUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const clearAuth = () => {
      queryClient.clear();
      setUser(null);
    };
    setUnauthorizedHandler(clearAuth);
    void authService
      .getSession(controller.signal)
      .then(setUser)
      .catch(clearAuth)
      .finally(() => setReady(true));
    return () => {
      controller.abort();
      setUnauthorizedHandler(undefined);
    };
  }, [queryClient]);

  const login = async (identifier: string, password: string) => {
    queryClient.clear();
    setUser(await authService.login(identifier, password));
  };
  const logout = async () => {
    try {
      await authService.logout();
    } finally {
      queryClient.clear();
      setUser(null);
    }
  };

  if (!ready)
    return (
      <output className="route-loading" aria-live="polite">
        관리자 세션을 확인하는 중...
      </output>
    );
  return (
    <AuthContext.Provider
      value={{
        user,
        ready,
        demoCredentials: authService.demoCredentials,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
