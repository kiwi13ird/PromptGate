import { Pencil } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { auditKeys } from '@/src/queries/keys';
import {
  ALIAS_MAX,
  accessErrorMessage,
  clientAliasService,
  gatewayAccessKeys,
  validateAlias,
  type ClientAliasesResponse,
} from '@/src/services/gatewayAccessService';
import { notifySuccess } from '@/src/utils/feedback';
import '@/src/access-block.css';

/** 확장 프로그램 ID 표시: 별칭이 있으면 별칭을 먼저, ID는 아래 작은 글씨로. onEdit이 있으면 연필(별칭 수정) 버튼 */
export function ClientIdentity({ clientId, alias, onEdit }: { clientId: string; alias?: string; onEdit?: () => void }) {
  return <span className={`acc-identity${alias ? ' has-alias' : ''}`}>
    {alias ? <strong className="acc-alias" title={alias}>{alias}</strong> : null}
    <code className="acc-id" title={clientId}>{clientId}</code>
    {onEdit ? <button type="button" className="acc-pencil" aria-label={`${alias ?? clientId} 별칭 수정`} title="별칭 수정" onClick={onEdit}><Pencil aria-hidden="true" /></button> : null}
  </span>;
}

/** 별칭 입력 대화상자. 비우고 저장하면 별칭을 지운다 */
export function ClientAliasDialog({ clientId, current, onClose }: { clientId: string; current?: string; onClose: () => void }) {
  const client = useQueryClient();
  const [text, setText] = useState(current ?? '');
  const problem = validateAlias(text);
  const save = useMutation({
    mutationFn: () => clientAliasService.set(clientId, text),
    onSuccess: async () => {
      const alias = text.trim();
      // 목록을 다시 받기 전에 화면부터 바꾼다
      client.setQueryData<ClientAliasesResponse>(gatewayAccessKeys.aliases(), old => ({
        items: [...(old?.items ?? []).filter(item => item.client_id !== clientId), ...(alias ? [{ client_id: clientId, alias }] : [])],
      }));
      notifySuccess(alias ? '별칭을 저장했습니다.' : '별칭을 지웠습니다.');
      onClose();
      await Promise.all([
        client.invalidateQueries({ queryKey: gatewayAccessKeys.aliases() }),
        client.invalidateQueries({ queryKey: auditKeys.all }),
      ]);
    },
  });
  const busy = save.isPending;
  const unchanged = text.trim() === (current ?? '');
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (problem || busy || unchanged) return;
    save.mutate();
  };
  return (
    <Dialog open onOpenChange={open => { if (!open && !busy) onClose(); }}>
      <DialogContent className="admin-dialog confirm-dialog console-dialog acc-dialog">
        <DialogHeader>
          <DialogTitle>별칭 수정</DialogTitle>
          <DialogDescription>대시보드에서 이 확장 프로그램 ID 대신 보일 이름입니다. 비우면 별칭을 지웁니다.</DialogDescription>
        </DialogHeader>
        <form className="acc-form" onSubmit={submit}>
          <div className="acc-target"><span className="acc-label">대상</span><code className="acc-id" title={clientId}>{clientId}</code></div>
          <label className="acc-field"><span className="acc-label">별칭</span>
            <Input aria-label="별칭" value={text} maxLength={ALIAS_MAX} placeholder="예: 홍길동 PC" autoComplete="off" disabled={busy} onChange={event => { setText(event.target.value); save.reset(); }} />
          </label>
          <small className="acc-count">{text.length} / {ALIAS_MAX}자</small>
          {problem && <p className="form-error" role="alert">{problem}</p>}
          {save.isError && <p className="form-error" role="alert">저장 실패 · {accessErrorMessage(save.error)}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>취소</Button>
            <Button type="submit" disabled={busy || Boolean(problem) || unchanged}>{busy ? '저장 중…' : '저장'}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** 별칭 수정 대화상자를 여는 상태. edit(clientId)로 열고, dialog를 화면 어디든 한 번 그린다 */
export function useClientAliasEditor(aliases: ReadonlyMap<string, string>) {
  const [clientId, setClientId] = useState<string | null>(null);
  const dialog = clientId ? <ClientAliasDialog key={clientId} clientId={clientId} current={aliases.get(clientId)} onClose={() => setClientId(null)} /> : null;
  return { edit: setClientId, dialog };
}
