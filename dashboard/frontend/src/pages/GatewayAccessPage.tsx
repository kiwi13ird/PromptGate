import { LockKeyhole } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PgBadge, PgEmpty, PgError, PgPageHeader, PgRefresh, PgSkeleton, PgStatusStrip, type StripLevel } from '@/src/components/pg';
import { AccessBlockDialog, AccessSavedView, AccessUnblockDialog } from '@/src/components/AccessBlockDialog';
import { ClientIdentity, useClientAliasEditor } from '@/src/components/ClientAlias';
import { useClientAliases, useGatewayAccess } from '@/src/hooks/useGatewayAccess';
import { auditKeys, dashboardKeys, trafficKeys } from '@/src/queries/keys';
import { dashboardService } from '@/src/services/dashboardService';
import {
  ACCESS_NOT_READY_MESSAGE,
  accessApplyStatus,
  accessErrorMessage,
  accessSavedText,
  blockNumber,
  blockReasonText,
  countConnectedClients,
  findActiveRule,
  formatSavedAt,
  gatewayAccessKeys,
  gatewayAccessService,
  isAccessConflict,
  isAccessNotReady,
  isBlockableClientId,
  modeConfirmText,
  parseReasonParam,
  ruleDurationText,
  ruleIsActive,
  ruleStatus,
  type AccessRule,
  type BlockReasonCode,
  type GatewayAccessResponse,
} from '@/src/services/gatewayAccessService';
import { trafficService } from '@/src/services/trafficService';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { uiMode } from '@runtime/ui-mode';
import '@/src/access-block.css';

// 접속 차단(재설계 3f, 설계 5.8): 머리([차단 추가] 주) → 상태 띠(저장 판 · Gateway 반영 · 최근 5분 차단) → 차단 목록 표
// (대상[별칭 + ID] · 사유 태그 · 기간 배지 "남은 시간" · 메모(공개 표시) · 등록 · [해제]) + "만료·해제 포함" → 설정 카드 '확장 ID 없는 접속 차단'.
// 표 자리 720px 이하에서는 카드. 차단 시작점 3곳(이벤트 상세·트래픽·여기)은 같은 대화상자(AccessBlockDialog)를 쓴다.
const ACCESS_LEVEL: Readonly<Record<'ok' | 'pending' | 'warn', StripLevel>> = { ok: 'ok', pending: 'progress', warn: 'warn' };
const ACCESS_WORD = { ok: '반영 완료', pending: '반영 대기', warn: '확인 필요' } as const;

// 접속 차단 탭(2026-10-12): 확장 프로그램 ID 차단 목록 · ‘확장 ID 없는 접속 차단’ · Gateway 반영 상태. 탐지 정책 메뉴의 네 번째 보기.

/** ‘확장 ID 없는 접속 차단’ 켜기·끄기 확인창. 켤 때는 지금 확장 ID 없이 연결 중인 IP 수를 보여 준다 */
function AccessModeDialog({ turnOn, doc, counts, stale, onClose }: {
  turnOn: boolean;
  doc: GatewayAccessResponse;
  counts: { connected: number; withoutId: number } | null;
  stale: boolean;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const [saved, setSaved] = useState<number | null>(null);
  const save = useMutation({
    mutationFn: () => gatewayAccessService.setMode(turnOn, doc.version),
    onSuccess: async result => {
      setSaved(result.version ?? doc.version + 1);
      await Promise.all([
        client.invalidateQueries({ queryKey: gatewayAccessKeys.detail() }),
        client.invalidateQueries({ queryKey: auditKeys.all }),
      ]);
    },
    onError: async error => {
      if (isAccessConflict(error)) await client.invalidateQueries({ queryKey: gatewayAccessKeys.detail() });
    },
  });
  const busy = save.isPending;
  const verb = turnOn ? '켜기' : '끄기';
  return (
    <Dialog open onOpenChange={open => { if (!open && !busy) onClose(); }}>
      <DialogContent className="admin-dialog confirm-dialog console-dialog acc-dialog">
        <DialogHeader>
          <DialogTitle>확장 ID 없는 접속 차단 {verb}</DialogTitle>
          <DialogDescription>저장하면 약 10초 안에 Gateway에 반영됩니다.</DialogDescription>
        </DialogHeader>
        {saved !== null ? (
          <>
            <AccessSavedView title="설정 저장 완료" version={saved} />
            <DialogFooter><Button onClick={onClose}>닫기</Button></DialogFooter>
          </>
        ) : (
          <>
            <ul className="acc-confirm-lines">{modeConfirmText(turnOn, counts, stale).map(line => <li key={line}>{line}</li>)}</ul>
            {save.isError && <p className="form-error" role="alert">저장 실패 · {accessErrorMessage(save.error)}</p>}
            <DialogFooter>
              <Button variant="outline" disabled={busy} onClick={onClose}>취소</Button>
              <Button disabled={busy} onClick={() => { save.reset(); save.mutate(); }}>{busy ? '저장 중…' : verb}</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function GatewayAccessPage() {
  const canManage = uiMode.canManagePolicies;
  const [showAll, setShowAll] = useState(false);
  const [adding, setAdding] = useState(false);
  const [unblocking, setUnblocking] = useState<AccessRule | null>(null);
  const [modeTarget, setModeTarget] = useState<boolean | null>(null);
  // 보고서의 '이 사용자 차단' 링크(/policies/access?block=<확장 ID>&reason=<사유>): 대상·사유를 채운 차단 대화상자만 연다. 저장은 관리자가 확인할 때만
  const [searchParams, setSearchParams] = useSearchParams();
  const [linkedBlock, setLinkedBlock] = useState<{ clientId: string; reasons: BlockReasonCode[] } | null>(null);
  // 대화상자를 열지 않은 이유. 별칭은 그리는 때 붙인다(별칭 목록이 문서보다 늦게 와도 맞게)
  const [linkNotice, setLinkNotice] = useState<{ reason: 'invalid' | 'readonly' | 'blocked'; clientId: string } | null>(null);
  const query = useGatewayAccess();
  const { aliases } = useClientAliases();
  const aliasEditor = useClientAliasEditor(aliases);
  // 연결 중인 IP: 확장 ID 없는 접속 수(확인창)와 ID 입력 후보(추가)에 쓴다
  const clientsQuery = useQuery({ queryKey: trafficKeys.clients(), queryFn: ({ signal }) => trafficService.getClients(signal), retry: false, staleTime: 10_000 });
  // 보조 숫자(2026-10-15): '최근 5분 막은 요청'은 HTTP 요청 수(화면 로딩 포함)라 보안 이벤트에 남은 접속 차단 기록 수를 같이 적는다(새 서버만 줌)
  const accessRecords = useQuery({ queryKey: dashboardKeys.summary('24H'), queryFn: ({ signal }) => dashboardService.getSummary('24H', signal), staleTime: 60_000, retry: false });
  const accessRecordCount = accessRecords.data?.counting?.accessBlocked;
  const doc = query.data;
  const now = Date.now();
  const blockParam = searchParams.get('block');
  const reasonParam = searchParams.get('reason');
  // 목록이 올 때까지 기다렸다가 한 번만 처리하고 주소에서 지운다 - 새로고침·뒤로 가기로 대화상자가 다시 열리지 않게.
  // 저장하면 규칙이 생겨 ‘이미 차단 중’이 되므로, 대화상자는 주소가 아니라 이 상태로 연다
  useEffect(() => {
    if (blockParam === null || !doc) return;
    const next = new URLSearchParams(searchParams);
    next.delete('block');
    next.delete('reason');
    setSearchParams(next, { replace: true });
    const clientId = blockParam.trim();
    if (!isBlockableClientId(clientId)) setLinkNotice({ reason: 'invalid', clientId });
    else if (!canManage) setLinkNotice({ reason: 'readonly', clientId });
    else if (findActiveRule(doc.rules, clientId, Date.now())) setLinkNotice({ reason: 'blocked', clientId });
    else {
      setLinkNotice(null);
      setLinkedBlock({ clientId, reasons: parseReasonParam(reasonParam) });
    }
  }, [blockParam, reasonParam, doc, canManage, searchParams, setSearchParams]);
  // 적용 중인 규칙을 먼저, 각각 최근 등록 순. 만료는 화면 시계로도 따라간다
  const sorted = [...(doc?.rules ?? [])].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const active = sorted.filter(rule => ruleIsActive(rule, now));
  const rows = showAll ? [...active, ...sorted.filter(rule => !ruleIsActive(rule, now))] : active;
  const suggestions = useMemo(() => {
    const seen = new Set<string>();
    const list: Array<{ clientId: string; ip: string }> = [];
    for (const item of clientsQuery.data?.clients ?? []) {
      if (!isBlockableClientId(item.clientId) || seen.has(item.clientId) || (doc && findActiveRule(doc.rules, item.clientId, Date.now()))) continue;
      seen.add(item.clientId);
      list.push({ clientId: item.clientId, ip: item.ip });
    }
    return list;
  }, [clientsQuery.data, doc]);
  const counts = clientsQuery.data ? countConnectedClients(clientsQuery.data.clients) : null;

  const notDeployed = query.isError && isAccessNotReady(query.error);
  const loadFailed = query.isError && (!doc || !canRetainQueryData(query.error));
  const state = doc ? accessApplyStatus(doc, now) : null;
  return (
    <div className="pg-screen pg-acc acc-page">
      <PgPageHeader
        title="접속 차단"
        description="확장 프로그램 ID 단위로 LLM 사용 차단 · 사용자에게 사유 표시"
        primary={canManage && doc ? <Button onClick={() => setAdding(true)}>차단 추가</Button> : undefined}
        secondary={canManage ? undefined : <PgBadge variant="tag" className="pg-readonly"><LockKeyhole aria-hidden="true" />읽기 전용</PgBadge>}
        refresh={<PgRefresh updatedAt={query.dataUpdatedAt} fetching={query.isFetching} failed={query.isError} onRefresh={() => query.refetch()} />}
      />
      {linkNotice && <p className="pg-stale" role="status">{
        linkNotice.reason === 'invalid' ? '링크의 확장 프로그램 ID가 올바르지 않거나 사용자를 구분할 수 없는 ID라 차단 창을 열지 않았습니다.'
          : linkNotice.reason === 'readonly' ? '읽기 전용이라 차단할 수 없습니다.'
            : `${aliases.get(linkNotice.clientId) ?? linkNotice.clientId}은(는) 이미 차단 중입니다.`
      }</p>}
      {query.isError && doc && canRetainQueryData(query.error) && (
        <p className="pg-stale" role="status">갱신 실패 · 아래는 마지막 성공 조회 결과입니다. 저장은 조회가 회복되면 할 수 있습니다.</p>
      )}
      {query.isLoading ? (
        <PgSkeleton shape="table" rows={4} />
      ) : notDeployed && !doc ? (
        <PgStatusStrip level="unknown" word="서버 반영 전" label="서버 반영 상태" facts={[<span key="m">{ACCESS_NOT_READY_MESSAGE}</span>]} />
      ) : loadFailed ? (
        <PgError message={`접속 차단 목록을 불러오지 못했습니다. ${accessErrorMessage(query.error)}`} onRetry={() => query.refetch()} />
      ) : doc && state ? (
        <>
          <PgStatusStrip level={ACCESS_LEVEL[state.tone]} word={ACCESS_WORD[state.tone]} label="저장·반영 상태"
            facts={[<span key="s" className="pg-strip-main">{accessSavedText(doc, now)}</span>, <span key="g" className="pg-strip-sub">{state.text}</span>,
              accessRecordCount !== undefined && <span key="e" className="pg-strip-sub" title="보안 이벤트에 남은 접속 차단 기록(같은 사용자·같은 사유는 10분에 1건만 남김). 보안 현황 카드에서는 빼고 따로 셈">최근 24시간 접속 차단 기록 {accessRecordCount.toLocaleString('ko-KR')}건</span>]} />
          <section className="pg-card pg-acc-rules" aria-labelledby="acc-rules-title">
            <header className="pg-card-head">
              <h2 id="acc-rules-title" className="pg-card-title">차단 목록</h2>
              <span className="pg-card-note">적용 중 {active.length}</span>
              <label className="pg-card-head-end pg-acc-showall"><input type="checkbox" checked={showAll} onChange={event => setShowAll(event.target.checked)} />만료·해제 포함(최근 200개)</label>
            </header>
            {rows.length ? (
              <Table card aria-label="차단 목록" className="pg-acc-table acc-rules-table">
                <TableHeader><TableRow>
                  <TableHead>대상</TableHead><TableHead>사유</TableHead><TableHead>메모</TableHead><TableHead>기간</TableHead><TableHead>등록</TableHead>
                  <TableHead><span className="sr-only">작업</span></TableHead>
                </TableRow></TableHeader>
                <TableBody>{rows.map(rule => {
                  const status = ruleStatus(rule, now);
                  const name = aliases.get(rule.client_id) ?? rule.client_id;
                  return <TableRow key={rule.id} className={status === 'ACTIVE' ? undefined : 'is-inactive'} data-tone={status === 'ACTIVE' ? 'block' : 'neutral'}>
                    <TableCell data-card="title">
                      <ClientIdentity clientId={rule.client_id} alias={aliases.get(rule.client_id)} onEdit={canManage ? () => aliasEditor.edit(rule.client_id) : undefined} />
                      <small className="pg-acc-number" title="사용자에게 보이는 차단 번호">차단 번호 {blockNumber(rule.id)}</small>
                    </TableCell>
                    <TableCell data-card="info"><span className="pg-acc-reasons">{rule.reasons.length ? rule.reasons.map(code => <PgBadge key={code} variant="tag">{blockReasonText(code)}</PgBadge>) : '-'}</span></TableCell>
                    <TableCell data-card="body" data-empty={rule.memo ? undefined : ''} className="pg-acc-memo">
                      {rule.memo || '-'}
                      {rule.memo && rule.show_memo_to_user ? <PgBadge tone="mask" className="pg-acc-public" title="이 메모는 차단된 사용자에게도 보입니다">메모 공개</PgBadge> : null}
                    </TableCell>
                    <TableCell data-card="badge"><PgBadge tone={status === 'ACTIVE' ? 'block' : 'neutral'}>{ruleDurationText(rule, now)}</PgBadge></TableCell>
                    <TableCell data-card="info" className="pg-acc-created">
                      {rule.created_by}<small>{formatSavedAt(rule.created_at)}</small>
                      {rule.removed_at && <small>해제 {rule.removed_by ?? '-'} · {formatSavedAt(rule.removed_at)}</small>}
                    </TableCell>
                    <TableCell data-card="actions" data-empty={canManage && status === 'ACTIVE' ? undefined : ''} className="pg-acc-actions">{canManage && status === 'ACTIVE' ? <Button size="sm" variant="outline" aria-label={`${name} 차단 해제`} onClick={() => setUnblocking(rule)}>해제</Button> : null}</TableCell>
                  </TableRow>;
                })}</TableBody>
              </Table>
            ) : (
              <PgEmpty
                title={showAll ? '차단 목록이 비어 있습니다.' : '적용 중인 차단이 없습니다.'}
                description={showAll ? '연결 중인 IP 표나 보안 이벤트에서 차단하거나 위의 차단 추가로 직접 등록할 수 있습니다.' : '만료·해제된 차단은 ‘만료·해제 포함’을 켜면 보입니다.'}
              />
            )}
            <footer className="pg-card-foot">차단된 사용자에게는 사유가 보이고, 메모는 공개를 고른 경우에만 보입니다.</footer>
          </section>
          <section className="pg-card pg-acc-mode" aria-labelledby="acc-mode-title">
            <header className="pg-card-head"><h2 id="acc-mode-title" className="pg-card-title">확장 프로그램 ID 없는 접속</h2><span className="pg-card-note pg-card-head-end">기본값 꺼짐</span></header>
            <div className="pg-card-body">
              <label className="acc-switch pg-acc-switch">
                <input type="checkbox" role="switch" aria-label="확장 ID 없는 접속 차단" checked={doc.require_client_id} disabled={!canManage || modeTarget !== null}
                  onChange={() => setModeTarget(!doc.require_client_id)} />
                확장 ID 없는 접속 차단
                <PgBadge tone={doc.require_client_id ? 'block' : 'neutral'}>{doc.require_client_id ? '켜짐' : '꺼짐'}</PgBadge>
              </label>
              <p className="pg-acc-mode-note">켜면 확장 프로그램 ID 없이 프록시로 들어오는 요청을 Gateway가 막습니다. 상태 확인·내 요청 기록(llm-gateway.local)과 Gateway 자기 PC(127.0.0.1)는 막지 않습니다.</p>
            </div>
          </section>
        </>
      ) : null}
      {doc && adding && <AccessBlockDialog suggestions={suggestions} aliases={aliases} document={doc} onClose={() => setAdding(false)} />}
      {doc && linkedBlock && <AccessBlockDialog key={linkedBlock.clientId} clientId={linkedBlock.clientId} initialReasons={linkedBlock.reasons} aliases={aliases} document={doc} onClose={() => setLinkedBlock(null)} />}
      {doc && unblocking && <AccessUnblockDialog key={unblocking.id} rule={unblocking} aliases={aliases} document={doc} onClose={() => setUnblocking(null)} />}
      {doc && modeTarget !== null && <AccessModeDialog turnOn={modeTarget} doc={doc} counts={counts} stale={Boolean(clientsQuery.data?.stale)} onClose={() => setModeTarget(null)} />}
      {aliasEditor.dialog}
    </div>
  );
}
