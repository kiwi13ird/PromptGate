import { uiLabel } from '@/src/utils/labels';
import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PgBadge, PgConfirmDialog, PgDrawer, PgEmpty, PgError, PgPageHeader, PgRefresh, PgRowMenu, PgSkeleton } from '@/src/components/pg';
import { policyService } from '@/src/services/policyService';
import { dashboardService } from '@/src/services/dashboardService';
import { categoryTitle, entityCategory } from '@/src/utils/entityCategory';
import { CATEGORY_ENTITIES, entityName } from '@/src/utils/detectionEntities';
import { auditKeys, dashboardKeys, policyKeys } from '@/src/queries/keys';
import type { DetectionPolicy, PolicyAction, PolicyCapabilities, PolicyCapabilityTarget } from '@/src/types/policy';
import { formatDateTime, formatShortDateTime, formatCount } from '@/src/utils/format';
import { notifySuccess } from '@/src/utils/feedback';
import { policyErrorInfo, type PolicyErrorContext } from '@/src/utils/policyErrors';
import { POLICY_ACTIONS, POLICY_ACTION_NAME, allowWarning, findCapabilityTarget, isCategoryTarget, policyChangeText, policyTargetName, policyTone } from '@/src/utils/policyActions';
import { uiMode } from '@runtime/ui-mode';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import '@/src/styles/policy-create.css';
import '@/src/styles/policy-toggle.css';

// 탐지 정책(2026-10-16 사용자 피드백 "정책 생성 버튼으로 보는 게 아니라 개인정보·자격증명 항목이 보이고 각각 토글로"):
// 화면에 바로 '개인정보'(8항목)·'자격증명'(3항목) 두 묶음. 묶음 머리 = 분류 기본 처리(분류 정책의 처리 방식, 바로 수정),
// 항목 줄 = 이름 · 이름표 필요 · [토글: 이 항목만 따로 처리] · 켜면 처리 방식(그 항목 allowed_actions만) · 상태(적용 중/꺼짐) · ⋯(변경 이력).
//   토글 켬: 정책이 없으면 생성(POST, 처음 값 = 지금 실제로 받는 처리라 켜는 순간 동작은 같다) / 있으면 활성(PATCH status)
//   토글 끔: 비활성(PATCH status, expected_version) / 처리 방식 변경: PATCH(expected_version)
//   허용을 고르면(생성·변경 모두) 확인창 1회. 409 VERSION_CONFLICT는 최신을 다시 불러오고 그 줄에 안내. 오류 문구는 utils/policyErrors.ts
//   처리 방식 목록(capabilities)을 못 불러오면 토글·선택을 끈다(이력 보기는 됨). 서비스·스키마는 10/15 구현 그대로
const CATEGORIES = ['PII', 'CREDENTIAL'] as const;
const ACTION_TONE = { BLOCK: 'block', MASK: 'mask', ALLOW: 'allow' } as const;
const categoryName = (category: string) => categoryTitle[category as keyof typeof categoryTitle] ?? category;
const BIRTH_NOTE = '생년월일은 값 앞뒤 30자 안에 ‘생년월일’·‘생일’·‘출생일’ 같은 말이 있을 때만 잡습니다.';

/** 같은 대상의 기존 정책(대소문자 무시) */
function policyFor(policies: readonly DetectionPolicy[] | undefined, code: string) {
  const upper = code.toUpperCase();
  return policies?.find((policy) => policy.detectionTarget.trim().toUpperCase() === upper);
}

interface Item { code: string; name: string; category: string; requiresContext: boolean; target?: PolicyCapabilityTarget }

/** 묶음별 항목: 처리 방식 목록 기준. 목록이 없으면(조회 실패·로딩) 운영 Detection에서 확인해 둔 정적 목록으로 이름만 */
function itemsOf(category: string, capabilities: PolicyCapabilities | undefined): Item[] {
  if (capabilities) return capabilities.targets.filter((target) => target.category === category && !isCategoryTarget(target) && target.canCreate)
    .map((target) => ({ code: target.code, name: policyTargetName(target.code, capabilities), category, requiresContext: target.requiresContext, target }));
  return (CATEGORY_ENTITIES[category as 'PII' | 'CREDENTIAL'] ?? []).map((entity) => ({ code: entity.type, name: entityName(entity), category, requiresContext: Boolean(entity.needsLabel) }));
}

/** 항목 정책이 꺼져 있을 때 실제로 받는 처리(Detection: 항목 정책 → 분류 정책 → 맞는 활성 정책이 없으면 차단) */
function inherited(categoryPolicy: DetectionPolicy | undefined, target?: PolicyCapabilityTarget): { action: PolicyAction; text: string } {
  if (categoryPolicy?.enabled) {
    // 자격증명에 부분 마스킹이 들어와도 Detection은 전체 마스킹으로 올린다
    const action = target && !target.allowedActions.includes(categoryPolicy.policyAction) && categoryPolicy.policyAction === 'MASK_PARTIAL' ? 'MASK_FULL' : categoryPolicy.policyAction;
    return { action, text: `${categoryName(categoryPolicy.detectionTarget.toUpperCase())} 기본 처리(${POLICY_ACTION_NAME[action]})` };
  }
  return { action: 'BLOCK', text: '기본 처리(차단)' };
}

type ConfirmTarget =
  | { type: 'status'; policy: DetectionPolicy }
  | { type: 'update'; policy: DetectionPolicy; action: PolicyAction }
  | { type: 'create-allow'; target: PolicyCapabilityTarget }
  | null;

export function PolicyManagementPage() {
  const client = useQueryClient();
  // 이벤트 상세 '기록된 정책 ID' 링크(/policies?policyId=…): 그 정책의 줄(분류 머리 또는 항목)을 강조하고 한 번 보이게 한다
  const [searchParams] = useSearchParams();
  const selectedPolicyId = searchParams.get('policyId');
  const scrolledTo = useRef<string | null>(null);
  const [historyPolicy, setHistoryPolicy] = useState<DetectionPolicy | null>(null);
  const [confirm, setConfirm] = useState<ConfirmTarget>(null);
  const [confirmError, setConfirmError] = useState('');
  // 409 VERSION_CONFLICT 뒤에는 확인창 확정 버튼을 끈다(덮어쓰지 않음)
  const [conflict, setConflict] = useState(false);
  // 줄마다 오류 한 줄(탐지 대상 코드 → 문구)
  const [rowError, setRowError] = useState<{ key: string; message: string } | null>(null);
  const policies = useQuery({ ...liveQueryOptions, queryKey: policyKeys.list(), queryFn: ({ signal }) => policyService.getPolicies(signal) });
  // 지원 대상·처리 방식(서버 고정 목록, Detection 호출 없음). 재시도는 전역 기본(1회)
  const capabilities = useQuery({ queryKey: policyKeys.capabilities(), queryFn: ({ signal }) => policyService.getCapabilities(signal), staleTime: 10 * 60_000 });
  const caps = capabilities.data;
  // 최근 30일 탐지(2026-10-10): 이벤트에 정책 ID가 없어 같은 분류·유형의 탐지 건수로 보여 준다
  const hits = useQuery({ queryKey: dashboardKeys.summary('30D'), queryFn: ({ signal }) => dashboardService.getSummary('30D', signal), staleTime: 60_000 });
  const history = useQuery({
    queryKey: policyKeys.history(historyPolicy?.policyId ?? ''),
    queryFn: ({ signal }) => policyService.getPolicyHistory(historyPolicy!.policyId, signal),
    enabled: Boolean(historyPolicy),
  });
  const refresh = async () => {
    await Promise.all([client.invalidateQueries({ queryKey: policyKeys.all }), client.invalidateQueries({ queryKey: auditKeys.all })]);
  };
  const onMutationError = (context: PolicyErrorContext, key: string) => (error: unknown) => {
    const info = policyErrorInfo(error, context);
    if (confirm) setConfirmError(info.message); else setRowError({ key, message: info.message });
    if (info.versionConflict) setConflict(true);
    if (info.refetch === 'capabilities') void client.invalidateQueries({ queryKey: policyKeys.capabilities() });
    if (info.refetch === 'policies') void client.invalidateQueries({ queryKey: policyKeys.list() });
    if (info.refetch === 'policies-history') void client.invalidateQueries({ queryKey: policyKeys.all });
  };
  const targetKey = (code: string) => code.trim().toUpperCase();
  const create = useMutation({
    mutationFn: ({ target, action }: { target: PolicyCapabilityTarget; action: PolicyAction }) => policyService.createPolicy(target.code, action),
    onMutate: ({ target }) => setRowError((current) => (current?.key === targetKey(target.code) ? null : current)),
    onSuccess: async (policy, { target }) => {
      await refresh();
      setConfirm(null);
      notifySuccess(`${policyTargetName(target.code, caps)} 정책을 만들었습니다 · ${POLICY_ACTION_NAME[policy.policyAction]}`);
    },
    onError: (error, { target }) => onMutationError('create', targetKey(target.code))(error),
  });
  const update = useMutation({
    mutationFn: ({ policy, action }: { policy: DetectionPolicy; action: PolicyAction }) => policyService.updatePolicy(policy.policyId, action, policy.version),
    onMutate: ({ policy }) => setRowError((current) => (current?.key === targetKey(policy.detectionTarget) ? null : current)),
    onSuccess: async (policy, { policy: before }) => {
      await refresh();
      setConfirm(null);
      notifySuccess(`${policyTargetName(before.detectionTarget, caps)} 정책을 v${policy.version}으로 바꿨습니다 · ${POLICY_ACTION_NAME[policy.policyAction]}`);
    },
    onError: (error, { policy }) => onMutationError('update', targetKey(policy.detectionTarget))(error),
  });
  const toggle = useMutation({
    mutationFn: (policy: DetectionPolicy) => policyService.changePolicyStatus(policy.policyId, !policy.enabled, policy.version),
    onMutate: (policy) => setRowError((current) => (current?.key === targetKey(policy.detectionTarget) ? null : current)),
    onSuccess: async (policy, before) => {
      await refresh();
      setConfirm(null);
      notifySuccess(`${policyTargetName(before.detectionTarget, caps)} 정책을 ${policy.enabled ? '활성화' : '비활성화'}했습니다.`);
    },
    onError: (error, policy) => onMutationError('status', targetKey(policy.detectionTarget))(error),
  });
  useEffect(() => {
    if (!selectedPolicyId || scrolledTo.current === selectedPolicyId || !policies.data) return;
    scrolledTo.current = selectedPolicyId;
    document.querySelector('[data-selected="true"]')?.scrollIntoView?.({ block: 'center' });
  }, [selectedPolicyId, policies.data]);
  const pending = create.isPending || update.isPending || toggle.isPending;
  const pendingKey = create.isPending ? targetKey(create.variables?.target.code ?? '')
    : update.isPending ? targetKey(update.variables?.policy.detectionTarget ?? '')
    : toggle.isPending ? targetKey(toggle.variables?.detectionTarget ?? '') : null;
  // 변경은 정책 목록과 처리 방식 목록이 모두 있을 때만
  const blockedReason = policies.isError ? '최신 정책 조회가 회복되면 변경할 수 있습니다.'
    : !caps ? (capabilities.isError ? '처리 방식 목록을 불러오지 못해 정책 변경을 쉬고 있습니다.' : '처리 방식 목록을 불러오는 중입니다.')
    : undefined;
  const canManage = uiMode.canManagePolicies;
  const locked = !canManage || pending || Boolean(blockedReason);
  const startMutation = () => { setConflict(false); setConfirmError(''); };

  const changeAction = (policy: DetectionPolicy, action: PolicyAction) => {
    if (locked || action === policy.policyAction) return;
    startMutation();
    if (action === 'ALLOW') setConfirm({ type: 'update', policy, action });
    else update.mutate({ policy, action });
  };
  const switchItem = (item: Item, policy: DetectionPolicy | undefined, categoryPolicy: DetectionPolicy | undefined) => {
    if (locked) return;
    startMutation();
    if (policy) { toggle.mutate(policy); return; }
    if (!item.target) return;
    // 처음 값 = 지금 실제로 받는 처리(켜는 순간 동작은 같고, 오른쪽에서 바꾼다)
    const start = inherited(categoryPolicy, item.target).action;
    const action = item.target.allowedActions.includes(start) ? start : 'MASK_FULL';
    if (action === 'ALLOW') setConfirm({ type: 'create-allow', target: item.target });
    else create.mutate({ target: item.target, action });
  };

  const hitText = (code: string, category = false) => {
    const insights = hits.data?.insights;
    if (hits.isLoading || hits.isError || !insights) return undefined;
    if (category) {
      const found = insights.categoryCounts?.find((entry) => entry.key === code);
      return found ? { count: found.events, title: `${categoryTitle[found.key]} 분류 전체 · 탐지된 값 ${found.values.toLocaleString('ko-KR')}개 · 최근 30일 대상 탐지(정책별 판정 수 아님)` } : { count: 0, title: '최근 30일 대상 탐지' };
    }
    return { count: insights.entityEventCounts?.find((entry) => entry.key === code)?.count ?? 0, title: `${uiLabel(code)} 유형 · 최근 30일 대상 탐지(정책별 판정 수 아님)` };
  };

  // 활성 변경 확인창(분류 정책 ⋯ 메뉴): 끄면 실제로 어디로 넘어가는지
  const statusChangeText = (policy: DetectionPolicy) => {
    if (!policy.enabled) return '이 정책으로 다시 처리합니다.';
    const target = findCapabilityTarget(caps, policy.detectionTarget);
    const upper = policy.detectionTarget.toUpperCase();
    const category = target?.category ?? (upper === 'PII' || upper === 'CREDENTIAL' ? upper : entityCategory(upper));
    if (target ? isCategoryTarget(target) : upper === category) return `이 정책을 끄면 항목별 정책이 없는 ${categoryName(category)} 항목은 기본 처리(차단)로 넘어갑니다.`;
    const categoryPolicy = policyFor(policies.data, category);
    if (categoryPolicy?.enabled) return `이 정책을 끄면 ${policyTargetName(category, caps)} 정책(${POLICY_ACTION_NAME[categoryPolicy.policyAction]})으로 넘어갑니다.`;
    return '이 정책을 끄면 기본 처리(차단)로 넘어갑니다.';
  };
  const selectedPolicy = confirm && confirm.type !== 'create-allow' ? confirm.policy : null;
  const latestPolicy = policies.data?.find((policy) => policy.policyId === selectedPolicy?.policyId);
  const versionChanged = Boolean(selectedPolicy && policies.data && latestPolicy?.version !== selectedPolicy.version);
  const confirmProps = (() => {
    if (!confirm) return { action: '', change: '', reversible: '', danger: false };
    if (confirm.type === 'create-allow') return {
      action: '허용', target: policyTargetName(confirm.target.code, caps), change: allowWarning(confirm.target),
      reversible: '켠 뒤에도 처리 방식을 바꾸거나 끌 수 있습니다 · 감사 로그에 기록됩니다.', danger: true,
    };
    if (confirm.type === 'update') {
      const target = findCapabilityTarget(caps, confirm.policy.detectionTarget);
      return {
        action: '허용', target: policyTargetName(confirm.policy.detectionTarget, caps),
        change: `${POLICY_ACTION_NAME[confirm.policy.policyAction]} → 허용으로 바꾼 v${confirm.policy.version + 1}을 만듭니다.${target ? ` ${allowWarning(target)}` : ''}`,
        reversible: '이전 버전은 이력에 남고, 다시 바꿔 되돌릴 수 있습니다.', danger: true,
      };
    }
    return {
      action: confirm.policy.enabled ? '비활성화' : '활성화', target: policyTargetName(confirm.policy.detectionTarget, caps),
      change: statusChangeText(confirm.policy),
      reversible: `언제든 다시 ${confirm.policy.enabled ? '활성화' : '비활성화'}할 수 있습니다 · 감사 로그에 기록됩니다.`,
      danger: confirm.policy.enabled,
    };
  })();
  const confirmLocked = locked || conflict || (confirm?.type !== 'create-allow' && versionChanged);

  const actionSelect = (policy: DetectionPolicy, target: PolicyCapabilityTarget | undefined, label: string, id: string) => {
    const allowed = POLICY_ACTIONS.filter((action) => target?.allowedActions.includes(action) || action === policy.policyAction);
    return <select id={id} className="pg-polt-select" aria-label={label} value={policy.policyAction} data-tone={policyTone(policy.policyAction)}
      disabled={locked || !target} title={blockedReason ?? (!target ? '지원 목록에 없는 대상이라 바꿀 수 없습니다.' : undefined)}
      onChange={(event) => changeAction(policy, event.target.value as PolicyAction)}>
      {allowed.map((action) => <option key={action} value={action} disabled={!target?.allowedActions.includes(action)}>{POLICY_ACTION_NAME[action]}</option>)}
    </select>;
  };

  const catalogCodes = new Set([...CATEGORIES, ...CATEGORIES.flatMap((category) => itemsOf(category, caps).map((item) => item.code))]);
  const others = (policies.data ?? []).filter((policy) => !catalogCodes.has(policy.detectionTarget.trim().toUpperCase()));
  const anyContext = CATEGORIES.some((category) => itemsOf(category, caps).some((item) => item.requiresContext));

  const categoryCard = (category: (typeof CATEGORIES)[number]) => {
    const items = itemsOf(category, caps);
    const categoryPolicy = policyFor(policies.data, category);
    const categoryTarget = findCapabilityTarget(caps, category);
    const title = categoryName(category);
    const hit = hitText(category, true);
    const rowKey = targetKey(category);
    return <section key={category} className="pg-card pg-polt" aria-labelledby={`pg-polt-${category}`}>
      <header className="pg-polt-head" data-selected={categoryPolicy && categoryPolicy.policyId === selectedPolicyId ? 'true' : undefined} aria-current={categoryPolicy && categoryPolicy.policyId === selectedPolicyId ? 'true' : undefined}>
        <div className="pg-polt-heading">
          <h2 id={`pg-polt-${category}`} className="pg-card-title">{title}</h2>
          <span className="pg-polt-count">{formatCount(items.length)}개 항목</span>
        </div>
        <div className="pg-polt-default">
          <label className="pg-polt-default-label" htmlFor={`pg-polt-default-${category}`}>기본 처리</label>
          {categoryPolicy?.enabled
            ? actionSelect(categoryPolicy, categoryTarget, `${title} 기본 처리`, `pg-polt-default-${category}`)
            : <span id={`pg-polt-default-${category}`} className="pg-polt-fallback">{categoryPolicy ? `차단 · ${title} 정책 꺼짐` : `차단 · ${title} 정책 없음`}</span>}
          {pendingKey === rowKey && <span className="pg-polt-saving" role="status">저장 중…</span>}
          {categoryPolicy && <PgRowMenu label={`${title} 기본 처리`} items={[
            { label: '변경 이력', onSelect: () => setHistoryPolicy(categoryPolicy) },
            ...(canManage ? [{ label: categoryPolicy.enabled ? '비활성화' : '활성화', danger: categoryPolicy.enabled, disabled: locked, onSelect: () => { startMutation(); setConfirm({ type: 'status', policy: categoryPolicy }); } }] : []),
          ]} />}
        </div>
        <p className="pg-polt-meta">
          {categoryPolicy ? <>
            <span className="mono" title={categoryPolicy.policyId}>{categoryPolicy.policyId}</span>
            <span>v{categoryPolicy.version}</span>
            {categoryPolicy.updatedAt && <span title={formatDateTime(categoryPolicy.updatedAt)}>수정 {formatShortDateTime(categoryPolicy.updatedAt)}</span>}
          </> : <span>{title} 분류 정책이 없어 따로 처리하지 않는 항목은 차단됩니다</span>}
          {hit ? <span title={hit.title}>최근 30일 탐지 {hit.count.toLocaleString('ko-KR')}건</span>
            : hits.isLoading ? <span>최근 30일 탐지 불러오는 중</span> : hits.isError ? <span title="보안 현황 집계를 불러오지 못했습니다">최근 30일 탐지 확인 불가</span> : null}
          {categoryPolicy?.enabled && categoryPolicy.policyAction === 'MASK_PARTIAL' && <span>부분 마스킹은 항목별 규칙</span>}
        </p>
        {rowError?.key === rowKey && <p className="form-error pg-polt-error" role="alert">{rowError.message}</p>}
      </header>
      <ul className="pg-polt-list" aria-label={`${title} 항목`}>
        {items.map((item) => {
          const policy = policyFor(policies.data, item.code);
          const on = Boolean(policy?.enabled);
          const key = targetKey(item.code);
          const busy = pendingKey === key;
          const effective = on && policy ? policy.policyAction : inherited(categoryPolicy, item.target).action;
          const itemHit = hitText(item.code);
          const switchTitle = blockedReason ?? (!canManage ? '이 화면에서는 바꿀 수 없습니다.' : on ? '끄면 분류 기본 처리를 따릅니다' : '켜면 이 항목만 따로 처리합니다');
          const selected = Boolean(policy && policy.policyId === selectedPolicyId);
          return <li key={item.code} className="pg-polt-item" data-on={on ? 'true' : undefined} data-tone={policyTone(effective)} data-selected={selected ? 'true' : undefined} aria-current={selected ? 'true' : undefined}>
            <div className="pg-polt-name">
              <span className="pg-polt-label" title={policy ? `${policy.policyId} · v${policy.version}${policy.updatedAt ? ` · 수정 ${formatDateTime(policy.updatedAt)}` : ''}${policy.updatedBy ? ` · ${policy.updatedBy}` : ''}` : undefined}>{item.name}</span>
              {item.requiresContext && <PgBadge variant="tag" className="pg-polt-context" title="값 앞에 이름표가 있을 때만 잡습니다">이름표 필요</PgBadge>}
              <span className="pg-polt-code mono">{item.code}</span>
              {itemHit && itemHit.count > 0 && <span className="pg-polt-hit" title={itemHit.title}>30일 {itemHit.count.toLocaleString('ko-KR')}건</span>}
            </div>
            <div className="pg-polt-controls">
              <button type="button" role="switch" className="pg-polt-switch" aria-checked={on} aria-label={`${item.name} 따로 처리`}
                disabled={locked || (!policy && !item.target)} title={switchTitle} onClick={() => switchItem(item, policy, categoryPolicy)}>
                <span className="pg-polt-knob" aria-hidden="true" />
              </button>
              <span className="pg-polt-action">
                {on && policy
                  ? actionSelect(policy, item.target, `${item.name} 처리 방식`, `pg-polt-action-${item.code}`)
                  : <span className="pg-polt-inherit" title={`지금 처리: ${inherited(categoryPolicy, item.target).text}`}>기본 처리 따름</span>}
              </span>
              <span className="pg-polt-state">
                {busy ? <span className="pg-polt-saving" role="status">저장 중…</span>
                  : <PgBadge tone={on ? 'allow' : 'neutral'}>{on ? '적용 중' : '꺼짐'}</PgBadge>}
              </span>
              <span className="pg-polt-menu">{policy ? <PgRowMenu label={item.name} items={[{ label: '변경 이력', onSelect: () => setHistoryPolicy(policy) }]} /> : null}</span>
            </div>
            {on && policy?.policyAction === 'MASK_PARTIAL' && item.target?.partialMasking && <p className="pg-polt-rule">부분 마스킹 규칙 · {item.target.partialMasking}</p>}
            {rowError?.key === key && <p className="form-error pg-polt-error" role="alert">{rowError.message}</p>}
          </li>;
        })}
      </ul>
    </section>;
  };

  return (
    <div className="pg-screen pg-pol pg-polt-screen">
      <PgPageHeader
        title="탐지 정책"
        description="항목마다 처리 방식(허용·차단·마스킹)을 정합니다"
        refresh={<PgRefresh updatedAt={policies.dataUpdatedAt} fetching={policies.isFetching} failed={policies.isError} onRefresh={() => policies.refetch()} />}
      />
      {policies.isError && policies.data && canRetainQueryData(policies.error) && <p className="pg-stale" role="status">갱신 실패 · 아래는 마지막 성공 조회 결과입니다. 관리 작업은 조회가 회복되면 사용할 수 있습니다.</p>}
      {capabilities.isError && !caps && <p className="pg-stale pg-polc-capfail" role="status">처리 방식 목록을 불러오지 못해 정책 변경을 쉬고 있습니다 · <button type="button" className="pg-polc-retry" disabled={capabilities.isFetching} onClick={() => capabilities.refetch()}>{capabilities.isFetching ? '다시 불러오는 중…' : '다시 시도'}</button></p>}
      <details className="pg-pol-guide"><summary>탐지와 처리 방식 안내</summary>
        <p>항목을 켜면 그 항목만 따로 처리하고, 끄면 분류 기본 처리를 따릅니다. 항목별 처리가 분류 기본 처리보다 먼저 적용되고, 맞는 활성 정책이 없으면 차단됩니다.</p>
        <p>처리 방식: 허용(그대로 보냄) · 차단(보내지 않음) · 부분 마스킹(항목별 규칙으로 일부만 가림) · 전체 마스킹([EMAIL_ADDRESS] 같은 항목 표시로 교체). 자격증명은 부분 마스킹을 지원하지 않습니다.</p>
        <p>정책을 켜도 새 탐지 규칙이 생기지는 않습니다. 기밀 키워드와 문서 일치는 이 정책을 거치지 않고 차단됩니다.</p>
      </details>
      {policies.isLoading ? <section className="pg-card"><div className="pg-card-body"><PgSkeleton rows={6} /></div></section>
        : policies.isError && (!policies.data || !canRetainQueryData(policies.error))
          ? <section className="pg-card"><div className="pg-card-body"><PgError message="탐지 정책을 불러오지 못했습니다." error={policies.error} onRetry={() => policies.refetch()} /></div></section>
          : <>
            {CATEGORIES.map(categoryCard)}
            {others.length > 0 && <section className="pg-card pg-polt" aria-labelledby="pg-polt-others">
              <header className="pg-polt-head"><div className="pg-polt-heading"><h2 id="pg-polt-others" className="pg-card-title">그 밖의 정책</h2><span className="pg-polt-count">처리 방식 목록에 없는 대상 · 바꿀 수 없음</span></div></header>
              <ul className="pg-polt-list" aria-label="그 밖의 정책">{others.map((policy) => <li key={policy.policyId} className="pg-polt-item" data-on={policy.enabled ? 'true' : undefined} data-tone={policyTone(policy.finalPolicyAction)} data-selected={policy.policyId === selectedPolicyId ? 'true' : undefined} aria-current={policy.policyId === selectedPolicyId ? 'true' : undefined}>
                <div className="pg-polt-name"><span className="pg-polt-label">{uiLabel(policy.detectionTarget)}</span><span className="pg-polt-code mono">{policy.policyId}</span>
                  {(() => { const otherHit = hitText(policy.detectionTarget.trim().toUpperCase()); return otherHit ? <span className="pg-polt-hit" title={otherHit.title}>30일 {otherHit.count.toLocaleString('ko-KR')}건</span> : null; })()}</div>
                <div className="pg-polt-controls">
                  <span className="pg-polt-action"><PgBadge tone={policyTone(policy.finalPolicyAction)}>{POLICY_ACTION_NAME[policy.finalPolicyAction]}</PgBadge></span>
                  <span className="pg-polt-state"><PgBadge tone={policy.enabled ? 'allow' : 'neutral'}>{policy.enabled ? '적용 중' : '꺼짐'}</PgBadge></span>
                  <span className="pg-polt-menu"><PgRowMenu label={uiLabel(policy.detectionTarget)} items={[{ label: '변경 이력', onSelect: () => setHistoryPolicy(policy) }]} /></span>
                </div>
              </li>)}</ul>
            </section>}
            <div className="pg-polt-notes">
              {anyContext && <p>* 이름표 필요: ‘비밀번호:’처럼 값 앞에 이름표가 있을 때만 잡습니다. {BIRTH_NOTE}</p>}
              <p title={caps ? `runtime_verified: ${String(caps.runtimeVerified)} · 목록 버전 ${caps.catalogVersion}` : undefined}>{caps
                ? (caps.runtimeVerified ? `항목은 설정 목록 기준 · 목록 버전 ${caps.catalogVersion}` : '항목은 설정 목록 기준(실행 중 규칙 실시간 확인 아님)')
                : '처리 방식 목록을 불러오지 못해 운영 Detection에서 확인해 둔 항목으로 표시'}</p>
              <p>기밀 키워드·문서 일치는 이 정책과 관계없이 차단됩니다(기밀 키워드: 맞는 정책이 없어 기본값 차단 · 문서 일치: 민감정보 검사 전에 차단).</p>
            </div>
          </>}
      <PgConfirmDialog
        open={Boolean(confirm) && canRetainQueryData(policies.error)}
        onOpenChange={(open) => { if (!open && !pending) { setConfirm(null); setConfirmError(''); } }}
        action={confirmProps.action}
        target={confirmProps.target}
        change={confirmProps.change}
        reversible={confirmProps.reversible}
        danger={confirmProps.danger}
        busy={pending}
        busyLabel="처리 중..."
        disabled={confirmLocked}
        error={confirmError ? `변경 실패 · ${confirmError}` : undefined}
        onConfirm={() => {
          if (!confirm || confirmLocked) return;
          if (confirm.type === 'create-allow') create.mutate({ target: confirm.target, action: 'ALLOW' });
          else if (confirm.type === 'update') update.mutate({ policy: confirm.policy, action: confirm.action });
          else toggle.mutate(confirm.policy);
        }}
      >
        {confirm && confirm.type !== 'create-allow' && <p className="pg-confirm-id">{confirm.policy.policyId}</p>}
        {confirm?.type !== 'create-allow' && versionChanged && !conflict && <p className="form-error" role="alert">정책 버전이 변경됐습니다. 창을 닫고 최신 정책을 다시 확인하세요.</p>}
        {policies.isError && <p className="form-error" role="alert">최신 정책 조회가 회복되면 변경할 수 있습니다.</p>}
      </PgConfirmDialog>
      <PgDrawer
        open={Boolean(historyPolicy) && canRetainQueryData(policies.error)}
        onOpenChange={(open) => { if (!open) setHistoryPolicy(null); }}
        title="정책 버전 이력"
        description={historyPolicy ? `${policyTargetName(historyPolicy.detectionTarget, caps)} · ${historyPolicy.policyId} · 과거 버전은 읽기 전용` : undefined}
      >
        {history.isLoading ? <PgSkeleton rows={4} />
          : history.isError ? <PgError variant="inline" message="버전 이력을 불러오지 못했습니다." error={history.error} onRetry={() => history.refetch()} />
          : !history.data?.length ? <PgEmpty title="기록된 정책 버전 이력이 없습니다." description="이 정책에서 조회 가능한 과거 버전이 없습니다." />
          : <Table card aria-label="버전 이력" className="pg-pol-history">
            <TableHeader><TableRow><TableHead>시간 · 버전</TableHead><TableHead>변경자</TableHead><TableHead>변경 내용</TableHead><TableHead>변경 후 처리 방식</TableHead><TableHead>활성 상태</TableHead></TableRow></TableHeader>
            <TableBody>
              {history.data.slice().sort((a, b) => b.version - a.version).map((version) => {
                const previous = history.data.find((item) => item.version === version.version - 1);
                return <TableRow key={version.version} data-tone={ACTION_TONE[version.action]}>
                  <TableCell data-card="title"><b>v{version.version}</b> <time className="pg-muted" title={formatDateTime(version.createdAt)}>{formatDateTime(version.createdAt)}</time></TableCell>
                  <TableCell data-card="info" data-label="변경자">{version.changedBy}</TableCell>
                  <TableCell data-card="info" data-label="변경 내용">{policyChangeText(version, previous)}</TableCell>
                  <TableCell data-card="badge"><PgBadge tone={policyTone(version.policyAction)} title={version.actionVariant}>{POLICY_ACTION_NAME[version.policyAction]}</PgBadge></TableCell>
                  <TableCell data-card="info" data-label="상태">{version.enabled ? '활성' : '비활성'}</TableCell>
                </TableRow>;
              })}
            </TableBody>
          </Table>}
      </PgDrawer>
    </div>
  );
}
