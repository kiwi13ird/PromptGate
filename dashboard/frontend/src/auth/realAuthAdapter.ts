import type { AuthAdapter } from './authAdapter';
import type { AdminUserDto } from '@/src/api/dto';
import { endpoints } from '@/src/api/endpoints';
import { httpClient } from '@/src/api/httpClient';
import { mapAdminUserDto } from '@/src/api/mappers';
import { adminUserSchema, parseApiResponse } from '@/src/api/schemas';

const readUser = (payload: unknown) =>
  mapAdminUserDto(parseApiResponse<AdminUserDto>(adminUserSchema, payload));

export const authAdapter: AuthAdapter = {
  demoCredentials: null,
  async login(identifier, password, signal) {
    return readUser(
      await httpClient.post<unknown>(
        endpoints.auth.login,
        { identifier, password },
        signal,
      ),
    );
  },
  async logout(signal) {
    await httpClient.post<void>(endpoints.auth.logout, undefined, signal);
  },
  async getSession(signal) {
    return readUser(
      await httpClient.get<unknown>(endpoints.auth.session, signal),
    );
  },
};
