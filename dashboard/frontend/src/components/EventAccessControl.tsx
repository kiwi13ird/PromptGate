import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { AccessBlockDialog } from '@/src/components/AccessBlockDialog';
import { useGatewayAccess } from '@/src/hooks/useGatewayAccess';
import { findActiveRule, isBlockableClientId, remainingBadgeText } from '@/src/services/gatewayAccessService';
import { uiMode } from '@runtime/ui-mode';
import '@/src/access-block.css';

/**
 * 보안 이벤트 상세의 ‘이 사용자 차단’(2026-10-12). 실제 확장 프로그램 ID(unknown-·legacy- 자리표시 ID 제외)가 있고
 * 서버가 접속 차단 API에 답할 때만 한 줄(요청 정보 항목)을 그린다. 이미 차단 중이면 남은 시간과 접속 차단 탭 링크.
 */
export function EventAccessControl({ clientId, aliases }: { clientId: string; aliases: ReadonlyMap<string, string> }) {
  const access = useGatewayAccess();
  const [open, setOpen] = useState(false);
  const doc = access.data;
  if (!doc || !isBlockableClientId(clientId)) return null;
  const rule = findActiveRule(doc.rules, clientId, Date.now());
  if (!rule && !uiMode.canManagePolicies) return null;
  return <div>
    <dt>접속 차단</dt>
    <dd>
      <span className="acc-event-control">
        {rule ? <>
          <span className="acc-badge">차단 중 · {remainingBadgeText(rule, Date.now())}</span>
          <Link to="/policies/access">접속 차단 보기</Link>
        </> : <Button size="sm" variant="outline" onClick={() => setOpen(true)}>이 사용자 차단</Button>}
      </span>
      {open && <AccessBlockDialog clientId={clientId} aliases={aliases} document={doc} onClose={() => setOpen(false)} />}
    </dd>
  </div>;
}
