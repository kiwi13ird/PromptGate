import type { AuditAction, AuditChanges } from '@/src/types/audit';
import { uiLabel } from '@/src/utils/labels';
import { POLICY_ACTION_NAME, isPolicyAction } from '@/src/utils/policyActions';

// EC2 상태 이름 - GPU 켜기·끄기 기록에만 쓴다(일반 설정 값은 번역하지 않는다)
const GPU_STATE_TEXT: Record<string, string> = {
  pending: '켜는 중', running: '켜짐', stopping: '끄는 중', stopped: '꺼짐', 'shutting-down': '종료 중', terminated: '삭제됨',
};

const ACCESS_VALUE_LABEL: Partial<Record<AuditAction, string>> = {
  ACCESS_RULE_ADD: '차단 목록',
  ACCESS_RULE_REMOVE: '차단 목록',
  ACCESS_MODE_UPDATE: '확장 ID 없는 접속 차단',
  CLIENT_ALIAS_UPDATE: '별칭',
};

const VIEW_MODE_TEXT = { original: '원본 모양', text: '텍스트', download: '내려받기' } as const;

function display(value: string | number | boolean | undefined, kind?: string) {
  // Gateway 처리 설정 첫 저장은 이전 번호가 없다(기본값에서 바꿈, 명세 §2.5)
  if (value === undefined) return kind === 'settings-version' ? '기본값' : kind === 'access-version' ? '없음' : '당시 미기록';
  if (value === '') return kind === 'assignee' ? '미지정' : '빈 값';
  if (kind === 'version' || kind === 'settings-version' || kind === 'access-version') return `v${value}`;
  if (kind === 'gpu') return GPU_STATE_TEXT[String(value)] ?? String(value);
  if (kind === 'policy-action') return isPolicyAction(value) ? POLICY_ACTION_NAME[value] : String(value);
  return kind === 'action' || kind === 'status' ? uiLabel(String(value)) : String(value);
}

export function AuditChangeDetails({ changes, unreadable = false, action }: { changes?: AuditChanges; unreadable?: boolean; action?: AuditAction }) {
  // 바뀐 값은 기록됐지만 화면이 모르는 형식이라 뺀 줄(2026-10-10)
  if (unreadable) return <p className="workflow-empty">바뀐 값이 기록돼 있지만 화면이 읽을 수 없는 형식이라 표시하지 않았습니다.</p>;
  const gatewaySettings = action === 'GATEWAY_SETTINGS_UPDATE';
  // 접속 차단 기록(2026-10-12): 버전은 접속 차단 목록 번호, 전·후 값은 규칙·방식·별칭 요약 문장
  const accessValueLabel = action ? ACCESS_VALUE_LABEL[action] : undefined;
  const accessAction = accessValueLabel !== undefined;
  const pairs: Array<readonly [string, keyof AuditChanges, keyof AuditChanges, string]> = [
    gatewaySettings ? ['설정 버전', 'previousVersion', 'newVersion', 'settings-version']
      : accessAction ? ['접속 차단 버전', 'previousVersion', 'newVersion', 'access-version']
      : ['정책 버전', 'previousVersion', 'newVersion', 'version'],
    // 정책 조치는 4종 이름(부분·전체 마스킹 구분)이 있으면 그것을, 없으면 색 계열 이름(2026-10-15)
    changes?.previousPolicyAction !== undefined || changes?.newPolicyAction !== undefined
      ? ['최종 조치', 'previousPolicyAction', 'newPolicyAction', 'policy-action']
      : ['최종 조치', 'previousAction', 'newAction', 'action'],
    ['문서 상태', 'previousStatus', 'newStatus', 'status'],
    ['조사 상태', 'previousIncidentStatus', 'newIncidentStatus', 'status'],
    ['담당자', 'previousAssignee', 'newAssignee', 'assignee'],
    [gatewaySettings ? '처리 설정' : accessValueLabel ?? '설정 값', 'previousValue', 'newValue', 'value'],
    ['GPU 상태', 'previousGpuState', 'newGpuState', 'gpu'],
  ];
  const rows = pairs.filter(([, before, after]) => changes?.[before] !== undefined || changes?.[after] !== undefined);
  // 리포트·키워드 작업은 전·후가 아니라 그때의 값 하나를 남긴다
  const recorded: Array<readonly [string, string]> = [
    ...(changes?.keyword !== undefined ? [['키워드', changes.keyword] as const] : []),
    ...(changes?.documentId !== undefined ? [['문서', changes.documentId] as const] : []),
    ...(changes?.reportFrom !== undefined || changes?.reportTo !== undefined ? [['리포트 기간', `${changes?.reportFrom ?? '?'} ~ ${changes?.reportTo ?? '?'}`] as const] : []),
    ...(changes?.useLlm !== undefined ? [['분석 문장', changes.useLlm ? '포함' : '포함 안 함'] as const] : []),
    ...(changes?.retryOfJobId !== undefined ? [['재시도', `실패한 추출 작업 #${changes.retryOfJobId}`] as const] : []),
    ...(changes?.jobId !== undefined ? [['추출 작업', `#${changes.jobId}`] as const] : []),
    ...(changes?.recordedStatus !== undefined ? [['상태', changes.recordedStatus] as const] : []),
    ...(changes?.detectionApplied !== undefined ? [['탐지 반영', changes.detectionApplied ? '반영됨' : '반영 실패'] as const] : []),
    // 문서 열람·내려받기(2026-10-13): 열람 번호는 화면 워터마크·도구 줄의 번호와 같다(캡처가 새면 이 줄을 찾는다)
    ...(changes?.documentVersion !== undefined ? [['판', changes.documentVersion] as const] : []),
    ...(changes?.documentFormat !== undefined ? [['형식', changes.documentFormat.toUpperCase()] as const] : []),
    // 열람 기록은 열 때 1번만 남아 같은 열람 안에서 바꾼 방식은 없다(2026-10-15 감사 16번) → '처음 연 방식'
    ...(changes?.viewMode !== undefined ? [[changes.viewMode === 'download' ? '보기 방식' : '처음 연 방식', VIEW_MODE_TEXT[changes.viewMode]] as const] : []),
    ...(changes?.viewRef !== undefined ? [['열람 번호', changes.viewRef] as const] : []),
  ];
  if (!rows.length && !recorded.length && changes?.noteAdded !== true) return <p className="workflow-empty">이 작업에는 변경 전·후 값이 기록되지 않았습니다.</p>;
  return <dl className="audit-change-details">
    {rows.map(([label, before, after, kind]) => <div key={label}><dt>{label}</dt><dd><span>변경 전: {display(changes?.[before], kind)}</span><span>변경 후: {display(changes?.[after], kind)}</span></dd></div>)}
    {recorded.map(([label, value]) => <div key={label}><dt>{label}</dt><dd><span>{value}</span></dd></div>)}
    {changes?.noteAdded === true && <div><dt>관리자 메모</dt><dd>추가됨 · 내용은 해당 이벤트에서 확인하세요.</dd></div>}
  </dl>;
}
