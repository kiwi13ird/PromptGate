import type { AdminUser } from '@/src/types/auth';

export interface DemoCredentials {
  identifier: string;
  password: string;
}
export interface AuthAdapter {
  readonly demoCredentials: DemoCredentials | null;
  login(
    identifier: string,
    password: string,
    signal?: AbortSignal,
  ): Promise<AdminUser>;
  logout(signal?: AbortSignal): Promise<void>;
  getSession(signal?: AbortSignal): Promise<AdminUser | null>;
}
