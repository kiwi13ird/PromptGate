import { useEffect, useRef, useState } from 'react';
import { Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { copyText } from '@/src/utils/copyText';

export function ReviewLinkCopy({ eventId }: { eventId: string }) {
  const url = `${window.location.origin}/events/${encodeURIComponent(eventId)}?view=compare`;
  const [status, setStatus] = useState<'idle' | 'copying' | 'copied' | 'manual'>('idle');
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (status === 'manual') { input.current?.focus(); input.current?.select(); } }, [status]);
  useEffect(() => {
    if (status !== 'copied') return;
    const timer = window.setTimeout(() => setStatus('idle'), 3000);
    return () => window.clearTimeout(timer);
  }, [status]);
  return <div className="review-link-copy"><Button variant="outline" disabled={status === 'copying'} onClick={async () => {
    setStatus('copying'); setStatus(await copyText(url) ? 'copied' : 'manual');
  }}><Copy size={14}/>{status === 'copied' ? '링크 복사됨' : status === 'copying' ? '복사 중…' : '검토 링크 복사'}</Button>
    {status === 'copied' && <span role="status" className="sr-only">검토 링크를 복사했습니다. 열람에는 관리자 로그인이 필요합니다.</span>}
    {status === 'manual' && <div className="review-link-manual"><label htmlFor="review-link-manual">자동 복사가 제한됐습니다. 아래 주소를 선택해 복사하세요.</label><input id="review-link-manual" ref={input} readOnly value={url}/><small>열람에는 관리자 로그인이 필요합니다.</small></div>}
  </div>;
}
