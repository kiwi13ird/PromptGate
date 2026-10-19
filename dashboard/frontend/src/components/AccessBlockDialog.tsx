import { useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { ClientIdentity } from '@/src/components/ClientAlias';
import { useGatewayAccess } from '@/src/hooks/useGatewayAccess';
import { PgSegment } from '@/src/components/pg';
import { auditKeys } from '@/src/queries/keys';
import {
  BLOCK_DURATION_OPTIONS,
  BLOCK_REASON_OPTIONS,
  MEMO_MAX,
  ACCESS_DUPLICATE_MESSAGE,
  accessErrorMessage,
  blockReasonText,
  findActiveRule,
  gatewayAccessKeys,
  gatewayAccessService,
  isAccessConflict,
  isVersionApplied,
  orderReasons,
  remainingBadgeText,
  userVisibleBlock,
  validateBlockInput,
  type AccessRule,
  type BlockDuration,
  type BlockReasonCode,
  type GatewayAccessResponse,
} from '@/src/services/gatewayAccessService';
import '@/src/access-block.css';

/** 저장 직후 Gateway 반영 표시: 반영 대기 → 반영됨 (Gateway가 저장한 번호 이상을 보고하면) */
export function AccessApplyStatus({ savedVersion }: { savedVersion: number }) {
  const query = useGatewayAccess({ pendingVersion: savedVersion });
  const done = isVersionApplied(query.data, savedVersion);
  const applied = query.data?.applied;
  return <p className={`acc-apply acc-apply--${done ? 'ok' : 'pending'}`} role="status">
    <strong>{done ? '반영됨' : '반영 대기'}</strong>
    <small>{done && applied && typeof applied === 'object' ? `Gateway v${applied.version}`
      : query.isError ? '반영 상태를 확인하지 못했습니다. 잠시 후 다시 확인합니다.' : 'Gateway가 다음 보고 때 반영합니다(최대 약 11초).'}</small>
  </p>;
}

/** 저장이 끝난 뒤 대화상자 본문 */
export function AccessSavedView({ title, version }: { title: string; version: number }) {
  return <div className="acc-saved">
    <p className="acc-saved-title">{title} · v{version}</p>
    <AccessApplyStatus savedVersion={version} />
  </div>;
}

interface Suggestion { clientId: string; ip: string }

/**
 * 확장 프로그램 ID 차단 대화상자. clientId를 주면 그 사용자(연결 IP 표 · 보안 이벤트), 안 주면 ID를 직접 입력(‘추가’)한다.
 * 확인하면 ‘반영 대기’가 보이고 Gateway가 보고하면 ‘반영됨’으로 바뀐다.
 */
export function AccessBlockDialog({ clientId: presetId, initialReasons, suggestions = [], aliases, document, onClose }: {
  clientId?: string;
  /** 처음부터 골라 둘 사유(보고서 링크의 reason). 저장은 관리자가 확인할 때만 */
  initialReasons?: readonly BlockReasonCode[];
  suggestions?: readonly Suggestion[];
  aliases: ReadonlyMap<string, string>;
  document: GatewayAccessResponse;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const [idText, setIdText] = useState(presetId ?? '');
  const [duration, setDuration] = useState<BlockDuration>('1d');
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set(initialReasons ?? []));
  const [memo, setMemo] = useState('');
  const [showMemo, setShowMemo] = useState(false);
  const [saved, setSaved] = useState<number | null>(null);
  const [conflict, setConflict] = useState('');
  const clientId = (presetId ?? idText).trim();
  // 메모를 공개하려면 메모가 있어야 한다: 메모가 비면 체크도 꺼진 것으로 본다
  const hasMemo = memo.trim().length > 0;
  const memoPublic = showMemo && hasMemo;
  const problem = validateBlockInput({ clientId, reasons: [...selected], memo, showMemoToUser: memoPublic }, document.rules);
  const otherSelected = selected.has('OTHER');
  const preview = userVisibleBlock(orderReasons(selected), memo, memoPublic);
  const save = useMutation({
    mutationFn: () => gatewayAccessService.addRule({ clientId, reasons: orderReasons(selected), memo, duration, ...(memoPublic ? { showMemoToUser: true } : {}) }, document.version),
    onSuccess: async result => {
      setConflict('');
      setSaved(result.version ?? document.version + 1);
      await Promise.all([
        client.invalidateQueries({ queryKey: gatewayAccessKeys.detail() }),
        client.invalidateQueries({ queryKey: auditKeys.all }),
      ]);
    },
    onError: async error => {
      if (!isAccessConflict(error)) return;
      // 409: 번호가 바뀌었거나 같은 ID에 이미 차단 규칙이 있다 - 최신 문서를 다시 읽어 어느 쪽인지 알린다
      try {
        const fresh = await client.fetchQuery({ queryKey: gatewayAccessKeys.detail(), queryFn: ({ signal }) => gatewayAccessService.get(signal), staleTime: 0 });
        setConflict(findActiveRule(fresh.rules, clientId, Date.now()) ? ACCESS_DUPLICATE_MESSAGE : accessErrorMessage(error));
      } catch {
        setConflict(accessErrorMessage(error));
      }
    },
  });
  const busy = save.isPending;
  const toggleReason = (code: string) => {
    save.reset();
    setConflict('');
    setSelected(current => {
      const next = new Set(current);
      if (next.has(code)) next.delete(code); else next.add(code);
      return next;
    });
  };
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (problem || busy) return;
    save.reset();
    setConflict('');
    save.mutate();
  };
  const failure = conflict || (save.isError && !isAccessConflict(save.error) ? accessErrorMessage(save.error) : '');
  return (
    <Dialog open onOpenChange={open => { if (!open && !busy) onClose(); }}>
      <DialogContent className="admin-dialog console-dialog acc-dialog">
        <DialogHeader>
          <DialogTitle>LLM 사용 차단</DialogTitle>
          <DialogDescription>이 확장 프로그램 ID의 요청을 Gateway가 막습니다(약 10초 안에 반영). 차단된 사용자에게는 선택한 사유가 보입니다. 메모는 공개를 고른 경우에만 보입니다.</DialogDescription>
        </DialogHeader>
        {saved !== null ? (
          <>
            <AccessSavedView title="차단 등록 완료" version={saved} />
            <DialogFooter><Button onClick={onClose}>닫기</Button></DialogFooter>
          </>
        ) : (
          <form className="acc-form" onSubmit={submit} aria-label="LLM 사용 차단">
            {presetId ? (
              <div className="acc-target"><span className="acc-label">대상</span><ClientIdentity clientId={presetId} alias={aliases.get(presetId)} /></div>
            ) : (
              <label className="acc-field"><span className="acc-label">확장 프로그램 ID</span>
                <Input aria-label="차단할 확장 프로그램 ID" list="acc-client-suggestions" value={idText} maxLength={80} placeholder="chrome-…" autoComplete="off" disabled={busy}
                  onChange={event => { setIdText(event.target.value); save.reset(); setConflict(''); }} />
                <datalist id="acc-client-suggestions">
                  {suggestions.map(item => <option key={item.clientId} value={item.clientId}>{aliases.get(item.clientId) ? `${aliases.get(item.clientId)} · ${item.ip}` : item.ip}</option>)}
                </datalist>
              </label>
            )}
            {/* 기간: 라디오 → 세그먼트(설계 4.11, 재설계 2단계 — 이벤트 상세·트래픽·접속 차단 3곳이 같은 대화상자) */}
            <PgSegment legend="기간" name="acc-duration" className="acc-fieldset" disabled={busy} value={duration} onChange={setDuration}
              options={BLOCK_DURATION_OPTIONS.map(option => ({ value: option.code, label: option.label }))} />
            <fieldset className="acc-fieldset" disabled={busy}>
              <legend>사유 <small>(하나 이상 선택 · 사용자에게 보입니다)</small></legend>
              <div className="acc-chips">
                {BLOCK_REASON_OPTIONS.map(option => (
                  <label key={option.code} className={`acc-chip${selected.has(option.code) ? ' is-on' : ''}`}>
                    <input type="checkbox" checked={selected.has(option.code)} onChange={() => toggleReason(option.code)} />
                    {option.label}
                  </label>
                ))}
              </div>
            </fieldset>
            <label className="acc-field"><span className="acc-label">메모 <small>{otherSelected ? '(기타는 필수)' : '(선택)'}</small></span>
              <textarea aria-label="메모" rows={3} maxLength={MEMO_MAX} value={memo} disabled={busy} placeholder="기본은 관리자만 볼 수 있습니다."
                onChange={event => { setMemo(event.target.value); if (!event.target.value.trim()) setShowMemo(false); save.reset(); setConflict(''); }} />
            </label>
            <small className="acc-count">{memo.length} / {MEMO_MAX}자</small>
            <label className={`acc-check${hasMemo ? '' : ' is-disabled'}`}>
              <input type="checkbox" checked={memoPublic} disabled={busy || !hasMemo}
                onChange={event => { setShowMemo(event.target.checked); save.reset(); setConflict(''); }} />
              사용자에게 메모도 보이기
              {hasMemo ? null : <small>메모를 입력하면 고를 수 있습니다</small>}
            </label>
            <section className="acc-preview" aria-label="사용자에게 보이는 내용">
              <strong>사용자에게 보이는 내용</strong>
              <p>{preview.reasonLine}</p>
              {preview.memoLine ? <p>{preview.memoLine}</p> : null}
            </section>
            {problem ? <p className="acc-hint" role="status">{problem}</p> : null}
            {failure ? <p className="form-error" role="alert">차단 실패 · {failure}</p> : null}
            <DialogFooter>
              <Button type="button" variant="outline" disabled={busy} onClick={onClose}>취소</Button>
              <Button type="submit" variant="danger-solid" disabled={Boolean(problem) || busy}>{busy ? '차단 중…' : '차단'}</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** 차단 해제 확인 대화상자 */
export function AccessUnblockDialog({ rule, aliases, document, onClose }: {
  rule: AccessRule;
  aliases: ReadonlyMap<string, string>;
  document: GatewayAccessResponse;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const [saved, setSaved] = useState<number | null>(null);
  const remove = useMutation({
    mutationFn: () => gatewayAccessService.removeRule(rule.id, document.version),
    onSuccess: async result => {
      setSaved(result.version ?? document.version + 1);
      await Promise.all([
        client.invalidateQueries({ queryKey: gatewayAccessKeys.detail() }),
        client.invalidateQueries({ queryKey: auditKeys.all }),
      ]);
    },
    onError: async error => {
      if (isAccessConflict(error)) await client.invalidateQueries({ queryKey: gatewayAccessKeys.detail() });   // 최신 목록으로 다시 그린다
    },
  });
  const busy = remove.isPending;
  return (
    <Dialog open onOpenChange={open => { if (!open && !busy) onClose(); }}>
      <DialogContent className="admin-dialog confirm-dialog console-dialog acc-dialog">
        <DialogHeader>
          <DialogTitle>LLM 사용 차단 해제</DialogTitle>
          <DialogDescription>해제하면 약 10초 안에 이 확장 프로그램 ID로 다시 LLM을 쓸 수 있습니다.</DialogDescription>
        </DialogHeader>
        {saved !== null ? (
          <>
            <AccessSavedView title="차단 해제 완료" version={saved} />
            <DialogFooter><Button onClick={onClose}>닫기</Button></DialogFooter>
          </>
        ) : (
          <>
            <dl className="acc-summary">
              <div><dt>대상</dt><dd><ClientIdentity clientId={rule.client_id} alias={aliases.get(rule.client_id)} /></dd></div>
              <div><dt>사유</dt><dd>{rule.reasons.map(blockReasonText).join(' · ') || '-'}</dd></div>
              <div><dt>기간</dt><dd>{remainingBadgeText(rule, Date.now())}</dd></div>
            </dl>
            {remove.isError && <p className="form-error" role="alert">해제 실패 · {accessErrorMessage(remove.error)}</p>}
            <DialogFooter>
              <Button variant="outline" disabled={busy} onClick={onClose}>취소</Button>
              <Button disabled={busy} onClick={() => { remove.reset(); remove.mutate(); }}>{busy ? '해제 중…' : '해제'}</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
