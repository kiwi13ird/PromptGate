import { useEffect } from 'react';
import { documentTitle } from '@/src/navigation';

/** 브라우저 탭 제목을 "화면 이름 · PromptGate"로 둔다(설계 2.1). 관리자 화면은 AppLayout이 경로로 정하고, 뼈대 밖 화면(로그인·404)만 이 훅을 쓴다 */
export function useDocumentTitle(title: string) {
  useEffect(() => {
    document.title = documentTitle(title);
  }, [title]);
}
