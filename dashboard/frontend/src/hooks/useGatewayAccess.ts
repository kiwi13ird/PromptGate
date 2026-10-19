import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ApiError } from '@/src/api/errors';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import {
  aliasMapOf,
  clientAliasService,
  gatewayAccessKeys,
  gatewayAccessService,
  isVersionApplied,
} from '@/src/services/gatewayAccessService';

// 저장 직후에는 Gateway 반영을 2초마다 확인한다(반영되거나 30초가 지나면 평소 10초 주기로) - Gateway 처리 설정 화면과 같은 방식
export const ACCESS_FAST_POLL_MS = 2_000;
export const ACCESS_FAST_POLL_WINDOW_MS = 30_000;

const notDeployed = (error: unknown) => error instanceof ApiError && error.status === 404;

/**
 * 접속 차단 문서(GET /api/gateway-access). 서버가 아직 이 API를 모르면(404, 화면만 먼저 반영된 상태) 다시 묻지 않는다.
 * pendingVersion: 방금 저장한 문서 번호. Gateway가 그 번호 이상을 보고할 때까지 빠르게 확인한다.
 */
export function useGatewayAccess({ pendingVersion = null }: { pendingVersion?: number | null } = {}) {
  const startedAt = useMemo(() => Date.now(), [pendingVersion]);
  return useQuery({
    ...liveQueryOptions,
    queryKey: gatewayAccessKeys.detail(),
    queryFn: ({ signal }) => gatewayAccessService.get(signal),
    retry: false,
    refetchInterval: query => {
      if (notDeployed(query.state.error)) return false;
      if (pendingVersion !== null && Date.now() - startedAt < ACCESS_FAST_POLL_WINDOW_MS && !isVersionApplied(query.state.data, pendingVersion))
        return ACCESS_FAST_POLL_MS;
      return liveQueryOptions.refetchInterval;
    },
  });
}

const EMPTY_ALIASES: ReadonlyMap<string, string> = new Map();
/** 확장 프로그램 ID별 별칭. 서버가 아직 모르거나 실패하면 빈 목록(ID만 보인다) */
export function useClientAliases() {
  const query = useQuery({
    queryKey: gatewayAccessKeys.aliases(),
    queryFn: ({ signal }) => clientAliasService.list(signal),
    retry: false,
    staleTime: 30_000,
  });
  const aliases = useMemo(() => (query.data ? aliasMapOf(query.data) : EMPTY_ALIASES), [query.data]);
  return { aliases, query };
}
