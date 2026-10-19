import { QueryClient } from '@tanstack/react-query';
import { ApiError } from '@/src/api/errors';

// 재시도 규칙은 대시보드 main.tsx와 같되, 시간 초과(요청당 10초)는 다시 보내지 않는다 - 대시보드가 꺼졌을 때 20초 넘게 기다리지 않게.
// 보호 상태 확인 실패(FORBIDDEN)·키 문제(UNAUTHORIZED)도 다시 보내지 않는다.
export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && ['UNAUTHORIZED', 'FORBIDDEN', 'VALIDATION', 'TIMEOUT'].includes(error.code)) return false;
  return failureCount < 1;
}

export function createExtensionQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { staleTime: 15_000, retry: shouldRetryQuery, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  });
}
