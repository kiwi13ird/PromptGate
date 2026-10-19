import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { MyRequestsPage } from '@/src/pages/MyRequestsPage';
import { OWN_REQUEST_LIMIT } from '@/src/services/myRequestsService';
import {
  PROTECTION_REQUIRED_MESSAGE, getBlockedStatus, readViewerGate, setBlockedStatus, subscribeBlockedStatus, watchProtectionChanges,
  type GateBlockStatus,
} from './extensionGate';

// 확장 프로그램 안 '내 요청 기록'(1.4.3). 기록 화면은 대시보드의 MyRequestsPage를 그대로 쓴다(전·후 보기 동일).
// 보호 상태를 확인하지 못하면 페이지 대신 고정 문구 안내를 보인다 - 이때는 열람 키를 보내지 않는다.
const HINT: Record<GateBlockStatus, string> = {
  PROTECTION_OFF: "PromptGate 창에서 보호를 켠 뒤 '다시 확인'을 누르십시오. 기록은 보안 서버를 통해서만 불러옵니다.",
  NOT_CONFIGURED: 'PromptGate 설정에서 보안 서버 주소를 입력하고 보호를 켜십시오.',
  PROXY_CONFLICT: '연결 설정이 PromptGate와 다릅니다. 다른 확장 프로그램이나 정책이 바꿨을 수 있으니 PromptGate 창에서 상태를 확인하십시오.',
  UNAVAILABLE: 'PromptGate 상태를 확인하지 못했습니다. 확장 프로그램을 새로고침한 후 다시 시도하십시오.',
};

function ProtectionRequired({ status, checking, onRetry }: { status: GateBlockStatus; checking: boolean; onRetry: () => void }) {
  return <main id="main-content" className="dops-my">
    <header className="dops-my-head">
      <p className="dops-my-brand">PromptGate</p>
      <h1>내 요청 기록</h1>
      <p>최근 7일간 이 브라우저에서 전송된 요청 중 마스킹·차단된 요청을 최근 {OWN_REQUEST_LIMIT}건까지 표시합니다. 본인 요청만 표시됩니다.</p>
    </header>
    <div className="dops-my-panel" role="alert" data-gate={status}>
      <p><strong>{PROTECTION_REQUIRED_MESSAGE}</strong></p>
      <p>{HINT[status]}</p>
      <button type="button" onClick={onRetry} disabled={checking}>{checking ? '확인 중' : '다시 확인'}</button>
    </div>
  </main>;
}

export function ExtensionMyRequestsApp() {
  const blocked = useSyncExternalStore(subscribeBlockedStatus, getBlockedStatus);
  const [generation, setGeneration] = useState(0);
  const [checking, setChecking] = useState(false);
  const queryClient = useQueryClient();
  const latestCheck = useRef(0);

  // 마지막으로 시작한 확인 결과만 반영한다(저장소 변경이 연달아 올 때 늦게 도착한 옛 결과로 되돌아가지 않게)
  const recheck = useCallback(async () => {
    const check = ++latestCheck.current;
    const gate = await readViewerGate();
    if (check !== latestCheck.current) return;
    if (gate.status !== 'READY' && gate.status !== 'NOT_READY') { setBlockedStatus(gate.status); return; }
    if (getBlockedStatus() === null) return;
    queryClient.clear();
    setBlockedStatus(null);
    setGeneration(value => value + 1);   // 페이지를 새로 열어 키 확인부터 다시 한다
  }, [queryClient]);

  // 열린 화면에서 보호를 끄거나 프록시가 바뀌면 바로 안내로, 다시 켜지면 기록 화면으로
  useEffect(() => watchProtectionChanges(() => { void recheck(); }), [recheck]);

  const retry = useCallback(() => {
    setChecking(true);
    void recheck().finally(() => setChecking(false));
  }, [recheck]);

  if (blocked) return <ProtectionRequired status={blocked} checking={checking} onRetry={retry} />;
  return <MyRequestsPage key={generation} />;
}
