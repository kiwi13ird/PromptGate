import type { ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

/**
 * 확인 대화상자 규칙(설계 4.11)을 부품으로 묶은 것.
 *  제목: "행동 · 대상"(예: "보호 중지 · 05_투자유치_자료.docx")
 *  본문: 바뀌는 것 1줄 + 되돌릴 수 있는지 1줄
 *  버튼: [취소] [행동 이름] — 확정 버튼 이름 = 행동. 위험 조치(danger)면 빨간 채움(danger-solid)
 * 범위: 지금 확인창이 있는 조치만 이 모양으로 바꾼다(확인창을 새로 넣지 않음). 화면별 문구 교체는 3단계.
 */
export function confirmTitle(action: string, target?: string) {
  return target ? `${action} · ${target}` : action;
}

export function PgConfirmDialog({ open, onOpenChange, action, target, change, reversible, danger = false, busy = false, busyLabel, disabled = false, error, onConfirm, children }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** 행동 이름(제목 앞부분 = 확정 버튼 글자) */
  action: string;
  target?: string;
  /** 바뀌는 것 1줄 */
  change: string;
  /** 되돌릴 수 있는지 1줄 */
  reversible: string;
  danger?: boolean;
  busy?: boolean;
  busyLabel?: string;
  disabled?: boolean;
  /** 실패 안내(있으면 role=alert 한 줄) */
  error?: string;
  onConfirm: () => void;
  children?: ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => { if (!busy) onOpenChange(next); }}>
      <DialogContent className="admin-dialog confirm-dialog console-dialog pg-confirm">
        <DialogHeader>
          <DialogTitle>{confirmTitle(action, target)}</DialogTitle>
          <DialogDescription className="pg-confirm-lines">
            <span>{change}</span>
            <span>{reversible}</span>
          </DialogDescription>
        </DialogHeader>
        {children}
        {error && <p className="form-error" role="alert">{error}</p>}
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={() => onOpenChange(false)}>취소</Button>
          <Button variant={danger ? 'danger-solid' : 'default'} disabled={busy || disabled} onClick={onConfirm}>{busy ? busyLabel ?? `${action} 중…` : action}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
