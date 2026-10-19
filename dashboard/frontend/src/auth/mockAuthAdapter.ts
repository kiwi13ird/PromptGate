import { ApiError } from '@/src/api/errors';
import type { AuthAdapter } from './authAdapter';

const sessionKey = 'llm-security-gateway-demo-session-v3';
const demoCredentials = {
  identifier: 'admin@securegate.local',
  password: 'Admin123!',
} as const;
const demoAdmin = {
  id: 'admin-001',
  email: demoCredentials.identifier,
  displayName: 'Security Admin',
  role: 'Gateway Administrator',
} as const;

export const authAdapter: AuthAdapter = {
  demoCredentials,
  async login(identifier, password) {
    if (
      (identifier !== demoCredentials.identifier &&
        identifier !== demoAdmin.id) ||
      password !== demoCredentials.password
    )
      throw new ApiError('인증에 실패했습니다.', 'UNAUTHORIZED', 401);
    sessionStorage.setItem(sessionKey, JSON.stringify(demoAdmin));
    return { ...demoAdmin };
  },
  async logout() {
    sessionStorage.removeItem(sessionKey);
  },
  async getSession() {
    try {
      const raw = sessionStorage.getItem(sessionKey);
      return raw ? (JSON.parse(raw) as typeof demoAdmin) : null;
    } catch {
      sessionStorage.removeItem(sessionKey);
      return null;
    }
  },
};
