// 보호 문서 본문 보기 뷰어(재설계 3h, 설계안 6.4 '화면 구성'·6.5 배치·6.6 보안).
// 머리(문서명·배지·형식·크기·쪽·판·등록 / [원본 모양·텍스트] [상세 ›] [×]) → 정보 띠(색인·키워드·최근 탐지)
// → 도구 줄(쪽 ‹ n/N › · 배율 − % + · 폭 맞춤 · '열람 기록됨 · 열람 번호') → 그리기 자리(+ 워터마크).
// - 열 때마다 서버가 감사 기록(문서 열람)을 남긴다. 자동 갱신·창 포커스로 다시 열지 않는다(열람 번호는 이 화면이 열려 있는 동안 하나).
// - 원본 바이트는 react-query 캐시·브라우저 저장소에 넣지 않고 이 부품 상태로만 든다(닫으면 놓음).
// - 형식별 그리기 부품과 라이브러리(pdf.js·docx-preview·jszip)는 처음 열 때 동적 import(별도 묶음).
// - '원본 내려받기'는 2026-10-13 사용자 피드백으로 뺐다(머리 버튼·⋯ 메뉴·그리기 실패 띠). 대시보드 서버도 download=1을 404로 돌려준다.
import { Component, lazy, Suspense, useEffect, useMemo, useRef, useState, type ErrorInfo, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, Minus, Plus, X } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { PgBadge, PgError, PgSegment } from '@/src/components/pg';
import { useAuth } from '@/src/hooks/useAuth';
import { detectionOpsKeys, detectionOpsService } from '@/src/services/detectionOpsService';
import {
  DOCUMENT_VIEW_LIMIT_BYTES, DOCUMENT_VIEW_PROBLEM_TEXT, documentViewProblem, documentViewService,
  type DocumentView, type DocumentViewMode, type DocumentViewProblem,
} from '@/src/services/documentViewService';
import type { ConfidentialDocument } from '@/src/types/policy';
import { documentProtectionStage } from '@/src/utils/documentPresentation';
import { formatBytes, formatDateTime, formatShortDateTime } from '@/src/utils/format';
import { DocumentText } from './DocumentText';
import { Watermark, watermarkText } from './Watermark';
import type { RenderInfo, RendererProps, ZoomSetting } from './types';

const PdfPages = lazy(() => import('./PdfPages'));
const DocxFrame = lazy(() => import('./DocxFrame'));
const XlsxGrid = lazy(() => import('./XlsxGrid'));
const HwpPreview = lazy(() => import('./HwpPreview'));

const ZOOM_STEPS = [0.5, 0.67, 0.75, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2];
const RENDERABLE = new Set(['pdf', 'docx', 'xlsx', 'hwp', 'hwpx']);
const INDEX_BADGE: Record<string, string> = { READY: '완료', PROCESSING: '처리 중', FAILED: '분석 실패' };

// 워터마크용 관리자. 부품 시험처럼 AuthProvider 밖이면 null(useAuth는 useContext를 늘 먼저 부르므로 훅 순서는 같다)
function useSignedInUser() {
  try {
    return useAuth().user;
  } catch {
    return null;
  }
}

/** 형식별 부품을 불러오다 실패(묶음 받기 실패·부품 예외)하면 텍스트 보기로 넘긴다 */
class RenderBoundary extends Component<{ onError: (reason: string) => void; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  componentDidCatch(error: unknown, _info: ErrorInfo) {
    this.props.onError(/Failed to fetch dynamically imported module|Loading chunk|Importing a module script failed/i.test(String((error as Error)?.message)) ? '보기 부품을 받지 못함' : '그리는 중 오류');
  }
  render() { return this.state.failed ? null : this.props.children; }
}
// 클래스 정적 메서드 문법 대신 대입: Tailwind가 소스의 그 낱말을 유틸리티 이름으로 읽어 첫 화면 CSS에 규칙을 더하지 않게
Object.assign(RenderBoundary, { getDerivedStateFromError: () => ({ failed: true }) });

type OriginalState =
  | { viewId: string; status: 'loading' }
  | { viewId: string; status: 'ready'; data: ArrayBuffer }
  | { viewId: string; status: 'error'; problem: DocumentViewProblem };

export interface DocumentViewerProps {
  documentId: string;
  /** 목록에서 고른 문서(이름·상태·판·등록 정보). 없으면 열람 응답 값만 보인다 */
  document?: ConfidentialDocument;
  mode: DocumentViewMode;
  onModeChange: (mode: DocumentViewMode, options?: { replace?: boolean }) => void;
  onClose: () => void;
}

export function DocumentViewer({ documentId, document, mode, onModeChange, onClose }: DocumentViewerProps) {
  const client = useQueryClient();
  const user = useSignedInUser();
  const [openSeq, setOpenSeq] = useState(0);
  const modeRef = useRef(mode);
  modeRef.current = mode;

  // 열람 시작(감사 기록 1건). 열려 있는 동안 다시 부르지 않는다
  const view = useQuery({
    queryKey: ['document-view', documentId, openSeq],
    queryFn: ({ signal }) => documentViewService.startView(documentId, modeRef.current, signal),
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchOnMount: false,
  });
  const opened = view.data;
  useEffect(() => { if (opened) void client.invalidateQueries({ queryKey: ['audit-logs'] }); }, [opened, client]);

  const keywords = useQuery({ queryKey: detectionOpsKeys.keywords(), queryFn: ({ signal }) => detectionOpsService.getKeywords(signal), retry: false, refetchOnWindowFocus: false });

  const [failure, setFailure] = useState<{ viewId: string; reason: string } | null>(null);
  const [original, setOriginal] = useState<OriginalState | null>(null);
  const [info, setInfo] = useState<RenderInfo>({});
  const [zoom, setZoom] = useState<ZoomSetting | null>(null);
  const [page, setPage] = useState(1);
  const [pageJump, setPageJump] = useState(0);
  const [blocking, setBlocking] = useState<DocumentViewProblem | null>(null);
  const [infoOpen, setInfoOpen] = useState(false);

  const viewId = opened?.view_id;
  const format = opened?.format ?? null;
  // 처음 배율: 쪽 문서(PDF·DOCX)는 폭 맞춤, XLSX는 100%(넓은 시트를 줄이면 글자를 못 읽음 — 표 안 가로 스크롤, 설계 6.5)
  const zoomSetting: ZoomSetting = zoom ?? (format === 'xlsx' ? 1 : 'fit');
  const tooLarge = Boolean(opened && opened.size > DOCUMENT_VIEW_LIMIT_BYTES);
  const renderable = Boolean(format && RENDERABLE.has(format) && !tooLarge);
  const failed = failure && failure.viewId === viewId ? failure.reason : null;
  const showOriginal = mode === 'original' && renderable && !failed;

  // 새 열람이면 그리기 상태를 처음으로
  useEffect(() => {
    setInfo({});
    setPage(1);
    setBlocking(null);
  }, [viewId]);

  // 원본 받기(원본 모양일 때만, 열람 번호마다 한 번)
  useEffect(() => {
    if (!viewId || !showOriginal || original?.viewId === viewId) return;
    const controller = new AbortController();
    setOriginal({ viewId, status: 'loading' });
    documentViewService.getOriginal(documentId, viewId, controller.signal).then(
      (result) => setOriginal({ viewId, status: 'ready', data: result.data }),
      (error: unknown) => {
        if (controller.signal.aborted) return;
        const problem = documentViewProblem(error);
        setOriginal({ viewId, status: 'error', problem });
        if (problem === 'too-large') onModeChange('text', { replace: true });
        else if (problem === 'version-changed' || problem === 'view-expired') setBlocking(problem);
      },
    );
    return () => {
      controller.abort();
      setOriginal((current) => (current?.viewId === viewId && current.status === 'loading' ? null : current));
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewId, showOriginal, documentId]);
  // 닫거나 다른 문서로 바꾸면 바이트를 놓는다
  useEffect(() => () => setOriginal(null), [documentId]);

  const onFailure = (reason: string) => {
    if (!viewId) return;
    setFailure((current) => (current?.viewId === viewId ? current : { viewId, reason }));
    onModeChange('text', { replace: true });
  };
  const onInfo = (next: RenderInfo) => setInfo((current) => ({ ...current, ...next }));

  const reopen = () => { setFailure(null); setOriginal(null); setOpenSeq((value) => value + 1); };

  const name = document?.documentName ?? opened?.document_name ?? documentId;
  const stage = document ? documentProtectionStage(document) : null;
  const statusLabel = stage?.label ?? (opened?.status === 'INACTIVE' ? '보호 중지' : undefined);
  const retired = (document?.status ?? opened?.status) === 'INACTIVE';
  const formatLabel = (format ?? document?.fileType ?? '').toUpperCase();
  const pagesLabel = info.pages && showOriginal ? (format === 'xlsx' ? `시트 ${info.pages}개` : format === 'docx' ? `약 ${info.pages}쪽` : format === 'pdf' ? `${info.pages}쪽` : '') : '';
  const meta = [formatLabel, opened ? formatBytes(opened.size) : '', pagesLabel, opened ? `판 ${opened.version}` : document?.version ? `판 ${document.version}` : '',
    document ? `${formatShortDateTime(document.registeredAt)}${document.owner ? ` ${document.owner}` : ''} 등록` : ''].filter(Boolean);
  const stamp = opened ? watermarkText({ adminId: user?.id ?? user?.email ?? '관리자', issuedAt: opened.issued_at, viewRef: opened.view_ref }) : '';

  const docKeywords = useMemo(() => (keywords.data ?? []).filter((keyword) => keyword.doc_id === documentId), [keywords.data, documentId]);
  const approved = docKeywords.filter((keyword) => keyword.status === 'approved');
  const pending = docKeywords.length - approved.length;

  const rendererProps: RendererProps | null = original?.status === 'ready' && original.viewId === viewId ? {
    data: original.data, zoom: zoomSetting, page, pageJump, onInfo, onFailure,
    onPageChange: (next) => setPage(next),
  } : null;
  const textView = opened ? <DocumentText key={opened.view_id} documentId={documentId} viewId={opened.view_id} embedded={format === 'hwp' || format === 'hwpx'} originalHint={renderable && !failed && format !== 'hwp' && format !== 'hwpx'} onProblem={setBlocking} /> : null;

  const pageCount = info.pages ?? 0;
  const pageable = showOriginal && (format === 'pdf' || format === 'docx') && pageCount > 0;
  const zoomable = showOriginal && (format === 'pdf' || format === 'docx' || format === 'xlsx');
  const effective = info.effectiveZoom ?? 1;
  const stepZoom = (direction: 1 | -1) => {
    const next = direction > 0 ? ZOOM_STEPS.find((step) => step > effective + 0.001) : [...ZOOM_STEPS].reverse().find((step) => step < effective - 0.001);
    setZoom(next ?? effective);
  };
  const goPage = (next: number) => { setPage(Math.min(Math.max(1, next), pageCount)); setPageJump((value) => value + 1); };

  const modeOptions = [
    { value: 'original' as const, label: '원본 모양', title: renderable ? '원본 파일 그대로(개인정보 가림 없음)' : tooLarge ? '20MB를 넘는 원본은 텍스트로만' : '이 형식은 원본 모양을 지원하지 않음' },
    { value: 'text' as const, label: '텍스트', title: '탐지 기준 텍스트(개인정보 가림)' },
  ];

  return (
    <section className="pg-card pg-dv" aria-label="문서 본문 보기" data-format={format ?? undefined} data-view-ref={opened?.view_ref}>
      <header className="pg-dv-head">
        <Button type="button" variant="ghost" size="sm" className="pg-dv-back" onClick={onClose}><ChevronLeft aria-hidden="true" />목록</Button>
        <div className="pg-dv-title">
          <h2 title={name}>{name}</h2>
          {statusLabel && <PgBadge value={statusLabel} title={stage?.detail} />}
        </div>
        <div className="pg-dv-actions">
          <PgSegment legend="보기 방식" legendHidden name={`pg-dv-mode-${documentId}`} className="pg-dv-mode" value={showOriginal ? 'original' : 'text'}
            options={modeOptions} disabled={!opened}
            onChange={(next) => { if (next === 'original' && (!renderable || failed)) return; onModeChange(next); }} />
          {/* 좁은 화면의 ⋯ 메뉴는 '상세 보기' 하나만 남아 링크로 바로 보인다 */}
          <Link className="pg-dv-detail" to={`/documents/${encodeURIComponent(documentId)}`}>상세<span aria-hidden="true"> ›</span></Link>
          <Button type="button" variant="ghost" size="icon" className="pg-dv-close pg-dv-hide-m" aria-label="본문 보기 닫기" title="닫기" onClick={onClose}><X aria-hidden="true" /></Button>
        </div>
        {meta.length > 0 && <p className="pg-dv-meta" title={document ? formatDateTime(document.registeredAt) : undefined}>{meta.join(' · ')}</p>}
      </header>

      <div className={`pg-dv-info${infoOpen ? ' is-open' : ''}`}>
        <div className="pg-dv-info-item">
          <span className="pg-dv-k">색인</span>
          {document ? <PgBadge variant="dot" value={INDEX_BADGE[document.chunkIndexStatus] ?? '확인 불가'} /> : opened ? <PgBadge variant="dot" value={INDEX_BADGE[opened.index_status] ?? '확인 불가'} /> : null}
          {document && document.chunkIndexStatus === 'READY' && <span className="pg-dv-sub">창 {document.chunkCount.toLocaleString('ko-KR')}개</span>}
          <button type="button" className="pg-dv-more pg-dv-only-m" aria-expanded={infoOpen} onClick={() => setInfoOpen((value) => !value)}>{infoOpen ? '정보 접기' : '정보 더보기'}</button>
        </div>
        <div className="pg-dv-info-item">
          <span className="pg-dv-k">키워드</span>
          {keywords.isLoading ? <span className="pg-dv-sub">확인 중</span>
            : keywords.isError ? <span className="pg-dv-sub">확인 불가</span>
            : approved.length ? <>{approved.slice(0, 3).map((keyword) => <PgBadge key={keyword.id} variant="tag">{keyword.keyword}</PgBadge>)}{approved.length > 3 && <span className="pg-dv-sub">+{approved.length - 3}</span>}</>
            : <span className="pg-dv-sub">승인된 키워드 없음</span>}
          {pending > 0 && <Link className="pg-dv-link" to="/policies/keywords">승인 대기 {pending}<span aria-hidden="true"> ›</span></Link>}
        </div>
        <div className="pg-dv-info-item">
          <span className="pg-dv-k">최근 탐지</span>
          {document?.lastDetectedAt
            ? <><span className="pg-dv-sub" title={formatDateTime(document.lastDetectedAt)}>{formatShortDateTime(document.lastDetectedAt)} · 누적 {(document.modifiedPartialDetectionCount ?? 0).toLocaleString('ko-KR')}건</span>
                <Link className="pg-dv-link" to={`/events?documentId=${encodeURIComponent(documentId)}&period=30D`}>이벤트<span aria-hidden="true"> ›</span></Link></>
            : <span className="pg-dv-sub">없음</span>}
        </div>
      </div>

      {retired && <p className="pg-dv-band pg-dv-band--neutral" role="note">보호 중지됨 · 탐지에 쓰지 않음 · 다시 켜기 전 내용 확인용</p>}
      {failed && <p className="pg-dv-band pg-dv-band--warn" role="alert">원본 모양으로 그리지 못함 · {failed} · 텍스트로 표시</p>}
      {tooLarge && <p className="pg-dv-band pg-dv-band--warn" role="note">원본이 20MB를 넘어 텍스트로만 표시</p>}
      {opened && !renderable && !tooLarge && <p className="pg-dv-band pg-dv-band--neutral" role="note">이 형식({opened.format ?? '알 수 없음'})은 원본 모양 보기를 지원하지 않음 · 텍스트로 표시</p>}
      {original?.status === 'error' && original.viewId === viewId && !blocking && original.problem !== 'too-large' && (
        <div className="pg-dv-band-wrap"><PgError variant="inline" message={`원본을 불러오지 못함 · ${DOCUMENT_VIEW_PROBLEM_TEXT[original.problem]}`} onRetry={() => setOriginal(null)} /></div>
      )}
      {blocking && <p className="pg-dv-band pg-dv-band--warn" role="alert">{DOCUMENT_VIEW_PROBLEM_TEXT[blocking]}<button type="button" className="pg-dv-band-action" onClick={reopen}>다시 열기</button></p>}

      <div className="pg-dv-bar" role="toolbar" aria-label="보기 도구">
        {pageable && (
          <span className="pg-dv-pages">
            <Button type="button" variant="outline" size="icon-sm" aria-label="이전 쪽" title="이전 쪽" disabled={page <= 1} onClick={() => goPage(page - 1)}><ChevronLeft aria-hidden="true" /></Button>
            <span className="pg-num" aria-live="polite">{page} / {pageCount}쪽</span>
            <Button type="button" variant="outline" size="icon-sm" aria-label="다음 쪽" title="다음 쪽" disabled={page >= pageCount} onClick={() => goPage(page + 1)}><ChevronRight aria-hidden="true" /></Button>
          </span>
        )}
        {zoomable && (
          <span className="pg-dv-zoom">
            <Button type="button" variant="outline" size="icon-sm" aria-label="축소" title="축소" disabled={effective <= ZOOM_STEPS[0]} onClick={() => stepZoom(-1)}><Minus aria-hidden="true" /></Button>
            <span className="pg-num pg-dv-zoom-value">{Math.round(effective * 100)}%</span>
            <Button type="button" variant="outline" size="icon-sm" aria-label="확대" title="확대" disabled={effective >= ZOOM_STEPS[ZOOM_STEPS.length - 1]} onClick={() => stepZoom(1)}><Plus aria-hidden="true" /></Button>
            <Button type="button" variant="ghost" size="sm" aria-pressed={zoomSetting === 'fit'} onClick={() => setZoom('fit')}>폭 맞춤</Button>
          </span>
        )}
        {showOriginal && format === 'docx' && <span className="pg-dv-note">쪽 나눔은 근삿값</span>}
        {showOriginal && info.note && <span className="pg-dv-note">{info.note}</span>}
        {showOriginal && <span className="pg-dv-note pg-dv-hide-m">원본 그대로 · 가림 없음</span>}
        {opened && <span className="pg-dv-viewlog" title={`열람 시각 ${formatDateTime(opened.issued_at)} · 감사 로그에 '문서 열람'으로 남음`}><span className="pg-dv-lamp" aria-hidden="true" />열람 기록됨 · 열람 {opened.view_ref}</span>}
      </div>

      <div className="pg-dv-canvas" data-mode={showOriginal ? 'original' : 'text'}>
        {view.isLoading ? <p className="pg-dv-loading" role="status">열람을 기록하고 여는 중…</p>
          : view.isError ? <div className="pg-dv-canvas-msg"><PgError message={`본문을 열지 못함 · ${DOCUMENT_VIEW_PROBLEM_TEXT[documentViewProblem(view.error)]}`} onRetry={reopen} /></div>
          : !opened ? null
          : !showOriginal ? (format === 'hwp' || format === 'hwpx' ? <div className="pg-dv-scroll pg-dv-hwp">{textView}</div> : textView)
          : !rendererProps ? (original?.status === 'error' ? textView : <p className="pg-dv-loading" role="status">원본을 받는 중…</p>)
          : (
            <RenderBoundary key={viewId} onError={onFailure}>
              <Suspense fallback={<p className="pg-dv-loading" role="status">보기 부품을 불러오는 중…</p>}>
                {format === 'pdf' ? <PdfPages {...rendererProps} />
                  : format === 'docx' ? <DocxFrame {...rendererProps} />
                  : format === 'xlsx' ? <XlsxGrid {...rendererProps} />
                  : <HwpPreview {...rendererProps} format={format === 'hwpx' ? 'hwpx' : 'hwp'} textSlot={textView} />}
              </Suspense>
            </RenderBoundary>
          )}
        {opened && <Watermark text={stamp} />}
      </div>
    </section>
  );
}

export type { DocumentView };
