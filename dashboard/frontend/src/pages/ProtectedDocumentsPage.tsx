import { FileUp } from 'lucide-react';
import { useMemo, useState, type ChangeEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import {
  PgBadge, PgConfirmDialog, PgCount, PgEmpty, PgError, PgFilterBar, PgPageHeader, PgPager, PgRefresh, PgRowMenu, PgSegment, PgSkeleton, PgStatusStrip,
  badgeTone, type PgFilterChip, type StripLevel,
} from '@/src/components/pg';
import { DocumentViewer } from '@/src/components/docview/DocumentViewer';
import { documentKeys } from '@/src/queries/keys';
import { documentService } from '@/src/services/documentService';
import type { DocumentViewMode } from '@/src/services/documentViewService';
import { formatBytes, formatDateTime, formatShortDateTime, formatCount } from '@/src/utils/format';
import { notifyError, notifySuccess, safeMessage } from '@/src/utils/feedback';
import { documentProtectionStage } from '@/src/utils/documentPresentation';
import type { ConfidentialDocument as ProtectedDocument } from '@/src/types/policy';
import { uiMode } from '@runtime/ui-mode';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import '@/src/styles/documents.css';
import { isDemoDocument } from '@/src/utils/demoDocuments';

// 재설계 3e(설계 5.4) + 3h 본문 보기 들어가는 곳(6.5).
// 머리([문서 등록] 주) → 상태 띠("5개 중 4개 보호 중 · 1개 분석 중 · 오류 0") → 필터 바(검색 + 상태 세그먼트 + 더보기[파일 형식])
// → 표 5열(문서·상태·누적 탐지·소유자·등록) + 행 조치 [보기] ⋯[상세 보기·보호 중지] — 표 자리 720px 이하에서 카드.
// [보기]를 누르면 주소에 ?view=<문서 ID>&mode=original|text(새 경로 없음 → 뒤로 가기·링크 공유) → 왼쪽 목록 288px + 오른쪽 뷰어.
// 상태는 문서 상태 + 색인 상태를 배지 1개로 합친다(documentProtectionStage, 보안 현황 ③과 같은 규칙). 서버 값은 그대로.

const maxUploadBytes = 20 * 1024 * 1024;
const allowedExtensions = new Set(['pdf', 'docx', 'xlsx', 'hwp', 'hwpx']);
// HWP·HWPX는 한컴 설치 여부에 따라 브라우저 MIME이 제각각이라 확인하지 않음(서버가 파일 구조로 확인)
const mimeUncheckedExtensions = new Set(['hwp', 'hwpx']);
const allowedMimeTypes = new Set([
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
]);
const PAGE_SIZE = 10;

function validateUpload(file: File) {
  const extension = file.name.split('.').pop()?.toLowerCase() ?? '';
  if (!allowedExtensions.has(extension))
    return 'PDF, DOCX, XLSX, HWP, HWPX 파일만 등록할 수 있습니다.';
  if (file.type && !mimeUncheckedExtensions.has(extension) && !allowedMimeTypes.has(file.type))
    return '파일 형식과 MIME 유형이 허용 목록과 일치하지 않습니다.';
  if (file.size <= 0) return '내용이 없는 파일은 등록할 수 없습니다.';
  if (file.size > maxUploadBytes) return '파일 크기는 20MB 이하여야 합니다.';
  return '';
}

type StageKey = 'PROTECTED' | 'ANALYZING' | 'FAILED' | 'STOPPED' | 'CHECK';
type StageFilter = 'ALL' | StageKey;
const STAGE_KEY: Record<string, StageKey> = { '보호 중': 'PROTECTED', '분석 중': 'ANALYZING', '분석 실패': 'FAILED', '보호 중지': 'STOPPED', '준비 확인 필요': 'CHECK' };
const STAGE_TEXT: Record<StageKey, string> = { PROTECTED: '보호 중', ANALYZING: '분석 중', FAILED: '분석 실패', STOPPED: '보호 중지', CHECK: '확인 필요' };   // 2026-10-16: 행 배지와 같은 말
const stageOf = (document: ProtectedDocument) => STAGE_KEY[documentProtectionStage(document).label] ?? 'CHECK';
const rowTone = (document: ProtectedDocument) => {
  const label = documentProtectionStage(document).label;
  return label === '보호 중' ? undefined : badgeTone(label);
};
const documentPath = (document: ProtectedDocument) => `/documents/${encodeURIComponent(document.documentId)}`;
/** 문서 ID가 파일 이름(확장자 뺀 것)과 같으면 보이지 않는다(설계 5.4 상세와 같은 규칙) */
const idDiffers = (document: ProtectedDocument) => document.documentId !== document.documentName.replace(/\.[^.]+$/, '') && document.documentId !== document.documentName;

function DocumentMeta({ document }: { document: ProtectedDocument }) {
  return (
    <span className="pg-doc-meta">
      <span className="pg-doc-format">{document.fileType}</span>
      {isDemoDocument(document.documentId) && <span className="pg-doc-demo" title="시연용 문서 · 문서 수와 이 문서만 일치한 이벤트는 통계에서 뺌">시연 · 통계 제외</span>}
      {document.version && <span>판 {document.version}</span>}
      {document.fileSize !== undefined && <span>{formatBytes(document.fileSize)}</span>}
      {idDiffers(document) && <span className="pg-doc-id" title={document.documentId}>{document.documentId}</span>}
    </span>
  );
}

export function ProtectedDocumentsPage() {
  const navigate = useNavigate();
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const viewing = params.get('view');
  const viewMode: DocumentViewMode = params.get('mode') === 'text' ? 'text' : 'original';
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState('');
  const [search, setSearch] = useState('');
  const [stageFilter, setStageFilter] = useState<StageFilter>('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const [confirmDocument, setConfirmDocument] = useState<ProtectedDocument | null>(null);
  const documents = useQuery({
    ...liveQueryOptions,
    queryKey: documentKeys.list(),
    queryFn: ({ signal }) => documentService.getDocuments(signal),
  });
  const upload = useMutation({
    mutationFn: (file: File) => documentService.registerDocument(file),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: documentKeys.all });
      await client.invalidateQueries({ queryKey: ['audit-logs'] });
      setUploadOpen(false);
      setSelectedFile(null);
      notifySuccess('보호 문서 등록 요청이 완료되었습니다. 처리 상태를 확인하세요.');
    },
    onError: notifyError,
  });
  const changeStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'ACTIVE' | 'INACTIVE' }) => documentService.changeDocumentStatus(id, status),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: documentKeys.all });
      await client.invalidateQueries({ queryKey: ['audit-logs'] });
      setConfirmDocument(null);
      notifySuccess('문서 보호 상태를 변경했습니다.');
    },
    onError: notifyError,
  });
  const chooseFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
    setFileError(file ? validateUpload(file) : '');
    upload.reset();
  };

  const pending = upload.isPending || changeStatus.isPending;
  const readOnly = pending || documents.isError;
  const retained = documents.data && canRetainQueryData(documents.error) ? documents.data : undefined;
  const counts = useMemo(() => {
    const result: Record<StageKey, number> = { PROTECTED: 0, ANALYZING: 0, FAILED: 0, STOPPED: 0, CHECK: 0 };
    for (const document of retained ?? []) result[stageOf(document)] += 1;
    return result;
  }, [retained]);
  // 상태 띠의 문서 수(2026-10-16 공통 규칙): 시연 문서(DEMO_) 제외. 목록·보호 상태 단추 수는 목록에 보이는 그대로(시연 문서 포함)
  const stats = useMemo(() => {
    const result: Record<StageKey, number> = { PROTECTED: 0, ANALYZING: 0, FAILED: 0, STOPPED: 0, CHECK: 0 };
    const counted = (retained ?? []).filter(document => !isDemoDocument(document.documentId));
    for (const document of counted) result[stageOf(document)] += 1;
    return { counts: result, total: counted.length, demo: (retained?.length ?? 0) - counted.length };
  }, [retained]);
  const query = search.trim().toLocaleLowerCase();
  const visible = (retained ?? []).filter(document =>
    (stageFilter === 'ALL' || stageOf(document) === stageFilter) &&
    (typeFilter === 'ALL' || document.fileType === typeFilter) &&
    [document.documentId, document.documentName, document.owner ?? ''].some(text => text.toLocaleLowerCase().includes(query)));
  const totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageRows = visible.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  // 빈 열 숨김(설계 4.5): 이 쪽의 모든 행이 탐지 기록 없음이면 '누적 탐지 · 최근' 열을 그리지 않는다
  const showDetection = pageRows.some(document => document.lastDetectedAt);
  const currentDocument = documents.data?.find(item => item.documentId === confirmDocument?.documentId);
  const statusChanged = Boolean(confirmDocument && currentDocument?.status !== confirmDocument.status);
  const types = [...new Set(documents.data?.map(item => item.fileType) ?? [])].sort();

  const resetFilters = () => { setSearch(''); setStageFilter('ALL'); setTypeFilter('ALL'); setPage(1); };
  const chips: PgFilterChip[] = [
    ...(query ? [{ key: 'search', label: `검색: ${search.trim()}`, onRemove: () => { setSearch(''); setPage(1); } }] : []),
    ...(stageFilter !== 'ALL' ? [{ key: 'stage', label: `상태: ${STAGE_TEXT[stageFilter]}`, onRemove: () => { setStageFilter('ALL'); setPage(1); } }] : []),
    ...(typeFilter !== 'ALL' ? [{ key: 'type', label: `형식: ${typeFilter.toUpperCase()}`, onRemove: () => { setTypeFilter('ALL'); setPage(1); } }] : []),
  ];

  const openView = (documentId: string) => setParams((current) => {
    const next = new URLSearchParams(current);
    next.set('view', documentId);
    next.set('mode', current.get('mode') === 'text' ? 'text' : 'original');
    return next;
  });
  const closeView = () => setParams((current) => {
    const next = new URLSearchParams(current);
    next.delete('view');
    next.delete('mode');
    return next;
  });
  const changeMode = (mode: DocumentViewMode, options?: { replace?: boolean }) => setParams((current) => {
    const next = new URLSearchParams(current);
    next.set('mode', mode);
    return next;
  }, { replace: options?.replace ?? true });

  const total = retained?.length ?? 0;
  const stripLevel: StripLevel = stats.counts.FAILED ? 'bad' : stats.counts.ANALYZING || stats.counts.CHECK ? 'progress' : stats.total ? 'ok' : 'unknown';
  const strip = retained && (
    <PgStatusStrip level={stripLevel} label="보호 문서 상태"
      word={stats.total ? `${formatCount(stats.total)}개 중 ${formatCount(stats.counts.PROTECTED)}개 보호 중` : '등록된 문서 없음'}
      facts={stats.total ? [`분석 중 ${formatCount(stats.counts.ANALYZING)}`, `분석 실패 ${formatCount(stats.counts.FAILED)}`, stats.counts.STOPPED > 0 && `보호 중지 ${formatCount(stats.counts.STOPPED)}`, stats.counts.CHECK > 0 && `확인 필요 ${formatCount(stats.counts.CHECK)}`, stats.demo > 0 && `시연 문서 ${formatCount(stats.demo)}개 제외`] : []}
      end={<span>본문 보기는 열람 기록이 남음</span>} />
  );
  const segmentOptions = ([['ALL', '전체', total], ['PROTECTED', '보호 중', counts.PROTECTED], ['ANALYZING', '분석 중', counts.ANALYZING], ['FAILED', '분석 실패', counts.FAILED], ['STOPPED', '보호 중지', counts.STOPPED],
    ...(counts.CHECK ? [['CHECK', '확인 필요', counts.CHECK] as const] : [])] as const).map(([value, label, count]) => ({ value: value as StageFilter, label: <>{label} <b>{count}</b></> }));

  const viewDocument = viewing ? documents.data?.find(item => item.documentId === viewing) : undefined;

  const table = documents.isLoading ? (
    <div className="pg-card-body"><PgSkeleton rows={5} /></div>
  ) : documents.isError && !retained ? (
    <div className="pg-card-body"><PgError message="보호 문서를 불러오지 못했습니다." error={documents.error} onRetry={() => documents.refetch()} /></div>
  ) : pageRows.length ? (
    <>
      <Table card aria-label="보호 문서" className="pg-doc-table">
        <TableHeader>
          <TableRow>
            <TableHead>문서</TableHead>
            <TableHead>상태</TableHead>
            {showDetection && <TableHead className="pg-num" title="문서 구간 일치로 탐지된 이벤트 수(시험·시연 기록 제외 · 10/11 전 파일 재전송·같은 질문 재시도는 1건으로 접음 = 보안 현황과 같은 기준)">누적 탐지 · 최근</TableHead>}
            <TableHead>소유자</TableHead>
            <TableHead>등록</TableHead>
            <TableHead className="pg-doc-col-actions">조치</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {pageRows.map(document => {
            const stage = documentProtectionStage(document);
            const active = document.status === 'ACTIVE';
            return (
              <TableRow key={document.documentId} className="pg-doc-row" data-tone={rowTone(document)} tabIndex={0} aria-label={`${document.documentName} 문서 상세`}
                onClick={event => { if (!(event.target as HTMLElement).closest('a,button,input,select,textarea,details,[role="menu"]')) void navigate(documentPath(document)); }}
                onKeyDown={event => { if (event.target === event.currentTarget && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); void navigate(documentPath(document)); } }}>
                <TableCell data-card="title" className="pg-doc-cell-name">
                  <Link className="pg-doc-name" title={document.documentName} to={documentPath(document)}>{document.documentName}</Link>
                  <DocumentMeta document={document} />
                </TableCell>
                <TableCell data-card="badge"><PgBadge value={stage.label} title={stage.detail} /></TableCell>
                {showDetection && (
                  <TableCell data-card="info" data-label="탐지" className="pg-num" data-empty={document.lastDetectedAt ? undefined : ''}>
                    {document.lastDetectedAt
                      ? <span className="pg-doc-hits" title={`최근 ${formatDateTime(document.lastDetectedAt)}`}><strong>{(document.modifiedPartialDetectionCount ?? 0).toLocaleString('ko-KR')}건</strong><small>{formatShortDateTime(document.lastDetectedAt)}</small></span>
                      : <span className="pg-muted">–</span>}
                  </TableCell>
                )}
                <TableCell data-card="info" data-empty={document.owner ? undefined : ''}>
                  <span className="pg-doc-owner" title={document.owner}>{document.owner ?? '–'}</span>
                </TableCell>
                <TableCell data-card="info" title={formatDateTime(document.registeredAt)}>{formatShortDateTime(document.registeredAt)} 등록</TableCell>
                <TableCell data-card="actions" className="pg-doc-col-actions">
                  <span className="pg-row-actions">
                    <Button type="button" size="sm" variant="outline" aria-label={`${document.documentName} 본문 보기`} onClick={() => openView(document.documentId)}>보기</Button>
                    <PgRowMenu label={document.documentName} items={[
                      { label: '상세 보기', onSelect: () => void navigate(documentPath(document)) },
                      ...(uiMode.canManageDocuments ? [{
                        label: active ? '보호 중지' : '보호 시작', danger: active, disabled: readOnly,
                        title: readOnly ? '최신 문서 조회가 회복되면 바꿀 수 있습니다' : undefined,
                        onSelect: () => { changeStatus.reset(); setConfirmDocument(document); },
                      }] : []),
                    ]} />
                  </span>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <div className="pg-card-foot pg-doc-foot"><PgPager page={currentPage} totalPages={totalPages} onPage={setPage} label="보호 문서 쪽 이동" /></div>
    </>
  ) : (
    <PgEmpty
      title={documents.data?.length ? '검색 조건에 맞는 문서가 없습니다.' : '등록된 보호 문서가 없습니다.'}
      description={documents.data?.length ? '검색어 또는 보호 상태를 바꾸세요.' : '문서를 등록하면 분석이 끝난 뒤 보호를 시작합니다.'}
      action={documents.data?.length ? <Button type="button" variant="outline" size="sm" onClick={resetFilters}>조건 초기화</Button> : undefined} />
  );

  return (
    <div className={`pg-screen pg-doc${viewing ? ' is-viewing' : ''}`}>
      <PgPageHeader
        title="보호 문서"
        refresh={<PgRefresh updatedAt={documents.dataUpdatedAt} fetching={documents.isFetching} failed={documents.isError} onRefresh={() => documents.refetch()} />}
        primary={uiMode.canManageDocuments ? <Button disabled={readOnly} onClick={() => { upload.reset(); setUploadOpen(true); }}><FileUp />문서 등록</Button> : undefined}
        strip={strip}
      />
      {documents.isError && retained && <PgError variant="inline" message="갱신 실패 · 아래는 마지막 성공 조회 결과입니다. 관리 작업은 조회가 회복되면 사용할 수 있습니다." onRetry={() => documents.refetch()} />}

      {viewing ? (
        <div className="pg-doc-split">
          <aside className="pg-card pg-doc-side" aria-label="보호 문서 목록">
            <div className="pg-doc-side-search">
              <Input aria-label="문서명 · ID · 소유자 검색" value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} placeholder="문서 이름 검색" />
            </div>
            <ul className="pg-doc-side-list">
              {visible.map(document => {
                const stage = documentProtectionStage(document);
                const current = document.documentId === viewing;
                return (
                  <li key={document.documentId}>
                    <button type="button" className="pg-doc-side-item" aria-current={current ? 'true' : undefined} onClick={() => { if (!current) openView(document.documentId); }}>
                      <span className="pg-doc-side-name">
                        <b title={document.documentName}>{document.documentName}</b>
                        <span>{[document.fileType.toUpperCase(), document.version && `판 ${document.version}`, formatShortDateTime(document.registeredAt)].filter(Boolean).join(' · ')}</span>
                      </span>
                      <PgBadge value={stage.label} />
                    </button>
                  </li>
                );
              })}
              {!visible.length && <li className="pg-doc-side-empty">{documents.isLoading ? '불러오는 중…' : '조건에 맞는 문서 없음'}</li>}
            </ul>
            <div className="pg-doc-side-foot"><PgCount total={visible.length} unit="개" /><button type="button" className="pg-doc-side-close" onClick={closeView}>표로 보기</button></div>
          </aside>
          <DocumentViewer key={viewing} documentId={viewing} document={viewDocument} mode={viewMode} onModeChange={changeMode} onClose={closeView} />
        </div>
      ) : (
        <>
          <PgFilterBar label="보호 문서 검색"
            search={<Input aria-label="문서명 · ID · 소유자 검색" value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} placeholder="문서명 · ID · 소유자" />}
            filters={<PgSegment legend="보호 상태" legendHidden name="pg-doc-stage" className="pg-doc-stage" value={stageFilter} options={segmentOptions} disabled={!retained}
              onChange={value => { setStageFilter(value); setPage(1); }} />}
            more={<label className="pg-field">파일 형식
              <select aria-label="파일 형식" value={typeFilter} onChange={event => { setTypeFilter(event.target.value); setPage(1); }}>
                <option value="ALL">전체</option>
                {types.map(type => <option key={type} value={type}>{type}</option>)}
              </select></label>}
            moreCount={typeFilter !== 'ALL' ? 1 : 0}
            chips={chips}
            onReset={resetFilters}
          />
          <section className="pg-card pg-doc-list" aria-labelledby="pg-doc-list-title">
            <header className="pg-card-head">
              <h2 id="pg-doc-list-title" className="pg-card-title">등록 문서</h2>
              {retained && <span className="pg-card-note"><PgCount total={visible.length} unit="개" />{visible.length !== total ? ` / 전체 ${formatCount(total)}개` : ''}</span>}
              <span className="pg-card-note pg-card-head-end">보기 = 본문 보기 · ⋯ 상세·보호 중지</span>
            </header>
            {table}
          </section>
        </>
      )}

      <details className="pg-doc-principle">
        <summary>본문 보기 원칙</summary>
        <p>본문 보기는 열 때마다 감사 로그에 남고(문서 열람), 화면에 관리자 ID·열람 시각·열람 번호가 겹쳐 보입니다. 원본 모양은 파일 그대로라 개인정보 가림이 없고, 텍스트 보기는 이벤트 근거 화면과 같은 가림을 씁니다. 지문(해시) 값은 표시하지 않습니다.</p>
      </details>

      <Dialog
        open={uploadOpen && canRetainQueryData(documents.error)}
        onOpenChange={(open) => {
          if (upload.isPending) return;
          setUploadOpen(open);
          if (!open) {
            setSelectedFile(null);
            setFileError('');
          }
        }}
      >
        <DialogContent className="admin-dialog console-dialog document-upload-dialog">
          <DialogHeader>
            <DialogTitle>보호 문서 등록</DialogTitle>
            <DialogDescription>{uiMode.uploadDescription}</DialogDescription>
          </DialogHeader>
          <div className="dialog-form">
            <label className="upload-zone">
              <FileUp />
              <strong>{selectedFile?.name ?? '파일을 선택하세요'}</strong>
              <span>최대 20MB · PDF, DOCX, XLSX, HWP, HWPX</span>
              <input aria-label="등록할 문서 파일" className="sr-only" type="file" onChange={chooseFile} disabled={readOnly} accept=".pdf,.docx,.xlsx,.hwp,.hwpx" />
            </label>
            <p className="security-copy">파일 등록 후 탐지 서버의 분석·색인 상태를 문서 목록에서 확인할 수 있습니다.</p>
            {upload.isPending && <p className="security-copy" role="status">업로드 중 · 파일 크기와 네트워크에 따라 최대 2분 걸립니다.</p>}
            {fileError && <p className="form-error" role="alert">{fileError}</p>}
            {upload.isError && <p className="form-error" role="alert">등록 실패 · {safeMessage(upload.error)} 선택한 파일은 유지됩니다.</p>}
            {documents.isError && <p className="form-error" role="alert">최신 문서 조회가 회복되면 등록할 수 있습니다.</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)} disabled={pending}>취소</Button>
            <Button onClick={() => selectedFile && !fileError && !readOnly && upload.mutate(selectedFile)} disabled={!selectedFile || Boolean(fileError) || readOnly}>
              {upload.isPending ? '업로드 중…' : '등록'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <PgConfirmDialog
        open={Boolean(confirmDocument) && canRetainQueryData(documents.error)}
        onOpenChange={open => { if (!open && !pending) setConfirmDocument(null); }}
        action={confirmDocument?.status === 'ACTIVE' ? '보호 중지' : '보호 시작'}
        target={confirmDocument?.documentName}
        // 2026-10-16 Detection 반영(docs/handoff/detection-keyword-logic-2026-10-16/CONTRACT.md 3절): 보호 중지 문서의 승인 키워드도 탐지에서 빠짐
        change={confirmDocument?.status === 'ACTIVE' ? '탐지 서버가 이 문서로 더 이상 탐지하지 않습니다(구간 일치·이 문서의 승인 키워드 모두). 관리자 활동에 기록됩니다.' : '탐지 서버가 이 문서로 다시 탐지합니다(구간 일치·이 문서의 승인 키워드). 관리자 활동에 기록됩니다.'}
        reversible={confirmDocument?.status === 'ACTIVE' ? '원본은 삭제하지 않으며 ⋯ 메뉴에서 다시 보호 시작할 수 있습니다.' : '⋯ 메뉴에서 다시 보호 중지할 수 있습니다.'}
        danger={confirmDocument?.status === 'ACTIVE'}
        busy={pending}
        busyLabel="처리 중…"
        disabled={readOnly || statusChanged}
        error={changeStatus.isError ? `상태 변경 실패 · ${safeMessage(changeStatus.error)}` : undefined}
        onConfirm={() => { if (confirmDocument && !readOnly && !statusChanged) changeStatus.mutate({ id: confirmDocument.documentId, status: confirmDocument.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE' }); }}
      >
        {statusChanged && <p className="form-error" role="alert">문서 상태가 이미 변경됐습니다. 창을 닫고 최신 상태를 확인하세요.</p>}
        {documents.isError && <p className="form-error" role="alert">최신 문서 조회가 회복되면 변경할 수 있습니다.</p>}
      </PgConfirmDialog>
    </div>
  );
}
