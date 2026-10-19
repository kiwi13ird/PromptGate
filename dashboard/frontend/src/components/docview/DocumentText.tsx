// 텍스트 보기(설계 6.3 '모든 형식'): 탐지가 실제로 비교하는 글자(documents.normalized_text)를 1,800자 쪽으로.
// 그리기는 이벤트 근거 화면의 PageText를 고치지 않고 가져다 쓴다(같은 쪽 모양 · 같은 가림).
import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { PageText } from '@/src/components/EvidenceDocumentViewer';
import { PgError } from '@/src/components/pg';
import { DOCUMENT_VIEW_PROBLEM_TEXT, documentViewProblem, documentViewService, type DocumentViewProblem } from '@/src/services/documentViewService';

const PAGE_SIZE = 1800;

export function DocumentText({ documentId, viewId, embedded = false, originalHint = false, onProblem }: {
  documentId: string;
  viewId: string;
  /** HWP 미리보기 아래처럼 바깥이 이미 스크롤 영역이면 true */
  embedded?: boolean;
  /** 텍스트가 너무 길 때 '원본 모양 보기로 확인'을 안내할지(원본 모양을 그릴 수 있는 형식·크기일 때만) */
  originalHint?: boolean;
  onProblem?: (problem: DocumentViewProblem) => void;
}) {
  const [offset, setOffset] = useState(0);
  const query = useQuery({
    queryKey: ['document-view-text', documentId, viewId, offset],
    queryFn: async ({ signal }) => {
      try {
        return await documentViewService.getTextPage(documentId, viewId, offset, signal);
      } catch (error) {
        const problem = documentViewProblem(error);
        if (problem === 'version-changed' || problem === 'view-expired' || problem === 'unauthorized') onProblem?.(problem);
        throw error;
      }
    },
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const data = query.data;
  const page = data?.page;
  const total = page?.total_chars ?? 0;
  const start = page?.char_start ?? offset;
  const count = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const body = query.isLoading ? <p className="pg-dv-loading" role="status">텍스트를 불러오는 중…</p>
    : query.isError ? <PgError variant="inline" message={`텍스트를 불러오지 못함 · ${DOCUMENT_VIEW_PROBLEM_TEXT[documentViewProblem(query.error)]}`} onRetry={() => query.refetch()} />
    : !page || page.status !== 'AVAILABLE'
      ? <p className="pg-dv-text-empty" role="status">{page?.status === 'TOO_LARGE' ? (originalHint ? '텍스트가 200만 자를 넘어 표시하지 않음 · 원본 모양 보기로 확인' : '텍스트가 200만 자를 넘어 표시하지 않음') : data?.index_status === 'FAILED' ? '색인에 실패해 탐지 기준 텍스트가 없음' : '색인이 끝나면 표시(지금은 탐지 기준 텍스트가 없음)'}</p>
      : <article className="pg-dv-paper pg-dv-text-paper" aria-label="탐지 기준 텍스트">
          <div className="pg-dv-text-body"><PageText page={page} sideLabel="보호 문서" /></div>
          <footer className="pg-dv-text-foot">문자 {start.toLocaleString('ko-KR')}–{(page.char_end ?? start).toLocaleString('ko-KR')} / {total.toLocaleString('ko-KR')}</footer>
        </article>;
  return (
    <section className={`pg-dv-text${embedded ? ' is-embedded' : ' pg-dv-scroll'}`} aria-label="텍스트 보기" tabIndex={embedded ? undefined : 0}>
      <div className="pg-dv-text-bar">
        <span className="pg-dv-text-source">탐지 기준 텍스트{data?.redaction === 'APPLIED' ? ' · 개인정보 가림' : data?.redaction === 'OFF' ? ' · 가림 꺼짐(서버 설정)' : ''}</span>
        {data && data.index_status !== 'READY' && page?.status === 'AVAILABLE' && <span className="pg-dv-text-stale" role="note">색인 중 · 텍스트는 이전 판일 수 있음</span>}
        {count > 1 && (
          <span className="pg-dv-text-pager">
            <Button type="button" variant="outline" size="icon-sm" aria-label="텍스트 이전 쪽" title="텍스트 이전 쪽" disabled={query.isFetching || start === 0} onClick={() => setOffset(Math.max(0, start - PAGE_SIZE))}><ChevronLeft aria-hidden="true" /></Button>
            <span className="pg-num">{Math.floor(start / PAGE_SIZE) + 1} / {count}</span>
            <Button type="button" variant="outline" size="icon-sm" aria-label="텍스트 다음 쪽" title="텍스트 다음 쪽" disabled={query.isFetching || start + PAGE_SIZE >= total} onClick={() => setOffset(start + PAGE_SIZE)}><ChevronRight aria-hidden="true" /></Button>
          </span>
        )}
      </div>
      {body}
    </section>
  );
}
