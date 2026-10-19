import type { ReactNode } from 'react';
import { Dialog as DialogPrimitive } from '@base-ui/react/dialog';
import { X } from 'lucide-react';
import { Button } from '@/components/ui/button';

/**
 * 상세 서랍(설계 4.8). 오른쪽 480px · 머리(제목·닫기) + 본문 스크롤 + 아래 조치. 모바일(800px 이하)은 전체 화면.
 * 긴 부가 정보만 담는다(감사 로그 변경 내용, 정책 이력, 시스템 구성 요소 세부). 이벤트 상세·문서 본문 보기에는 쓰지 않는다.
 * 모달 대화상자(@base-ui/react Dialog)로 연다: 포커스가 서랍 안에 갇히고, Esc·바깥 누름·닫기 버튼으로 닫히며, 닫으면 연 버튼으로 포커스가 돌아간다.
 */
export function PgDrawer({ open, onOpenChange, title, description, actions, children }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  /** 아래 조치(버튼). 없으면 조치 줄을 그리지 않는다 */
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={(next) => onOpenChange(next)}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Backdrop className="pg-drawer-backdrop" />
        <DialogPrimitive.Popup className="pg-drawer" data-slot="drawer">
          <div className="pg-drawer-head">
            <div className="pg-drawer-heading">
              <DialogPrimitive.Title className="pg-drawer-title">{title}</DialogPrimitive.Title>
              {description && <DialogPrimitive.Description className="pg-drawer-description">{description}</DialogPrimitive.Description>}
            </div>
            <DialogPrimitive.Close render={<Button variant="ghost" size="icon" className="pg-drawer-close" aria-label="닫기" title="닫기" />}>
              <X aria-hidden="true" />
            </DialogPrimitive.Close>
          </div>
          <div className="pg-drawer-body">{children}</div>
          {actions && <div className="pg-drawer-actions">{actions}</div>}
        </DialogPrimitive.Popup>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
