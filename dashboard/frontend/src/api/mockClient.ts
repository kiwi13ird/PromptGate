import { ApiError } from './errors';
import { env } from '@/src/config/env';

export type MockScenario =
  | 'normal'
  | 'slow'
  | 'error'
  | 'empty-events'
  | 'empty-audit'
  | 'empty-traffic';

export function getMockScenario(): MockScenario {
  if (!env.debugToolsEnabled) return 'normal';
  const value = new URLSearchParams(window.location.search).get('mockScenario');
  return value === 'slow' ||
    value === 'error' ||
    value === 'empty-events' ||
    value === 'empty-audit' ||
    value === 'empty-traffic'
    ? value
    : 'normal';
}

export async function mockRequest<T>(
  factory: () => T,
  signal?: AbortSignal,
): Promise<T> {
  const scenario = getMockScenario();
  const delayMs =
    scenario === 'slow' ? 1_500 : 120 + Math.floor(Math.random() * 160);
  await new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(resolve, delayMs);
    signal?.addEventListener(
      'abort',
      () => {
        window.clearTimeout(timer);
        reject(new DOMException('Aborted', 'AbortError'));
      },
      { once: true },
    );
  });
  if (scenario === 'error')
    throw new ApiError('데모 오류가 발생했습니다.', 'SERVER', 500);
  return factory();
}
