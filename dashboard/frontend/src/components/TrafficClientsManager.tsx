import { useState, type ComponentProps } from 'react';
import { AccessBlockDialog, AccessUnblockDialog } from '@/src/components/AccessBlockDialog';
import { useClientAliasEditor } from '@/src/components/ClientAlias';
import { TrafficClientsPanel } from '@/src/components/TrafficClientsPanel';
import { useClientAliases, useGatewayAccess } from '@/src/hooks/useGatewayAccess';
import { findActiveRule, type AccessRule } from '@/src/services/gatewayAccessService';
import { uiMode } from '@runtime/ui-mode';

/**
 * 연결 중인 IP 표 + 접속 차단 관리(2026-10-12). 서버가 접속 차단 문서에 답할 때만 ‘관리’ 칸과 별칭이 붙는다
 * (화면이 서버보다 먼저 반영돼 있으면 예전 표 그대로).
 */
export function TrafficClientsManager(props: Omit<ComponentProps<typeof TrafficClientsPanel>, 'manage'>) {
  const access = useGatewayAccess();
  const { aliases } = useClientAliases();
  const aliasEditor = useClientAliasEditor(aliases);
  const [blocking, setBlocking] = useState<string | null>(null);
  const [unblocking, setUnblocking] = useState<AccessRule | null>(null);
  const now = props.now ?? Date.now();
  const doc = access.data;
  return <>
    <TrafficClientsPanel
      {...props}
      now={now}
      manage={doc ? {
        canManage: uiMode.canManagePolicies,
        aliases,
        activeRuleOf: clientId => findActiveRule(doc.rules, clientId, now),
        onBlock: setBlocking,
        onUnblock: setUnblocking,
        onEditAlias: aliasEditor.edit,
      } : undefined}
    />
    {doc && blocking && <AccessBlockDialog key={blocking} clientId={blocking} aliases={aliases} document={doc} onClose={() => setBlocking(null)} />}
    {doc && unblocking && <AccessUnblockDialog key={unblocking.id} rule={unblocking} aliases={aliases} document={doc} onClose={() => setUnblocking(null)} />}
    {aliasEditor.dialog}
  </>;
}
