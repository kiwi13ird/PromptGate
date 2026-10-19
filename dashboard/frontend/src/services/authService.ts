import { authAdapter } from '@runtime/auth-adapter';

export const authService = {
  demoCredentials: authAdapter.demoCredentials,
  login: (identifier: string, password: string, signal?: AbortSignal) =>
    authAdapter.login(identifier, password, signal),
  logout: (signal?: AbortSignal) => authAdapter.logout(signal),
  getSession: (signal?: AbortSignal) => authAdapter.getSession(signal),
};
