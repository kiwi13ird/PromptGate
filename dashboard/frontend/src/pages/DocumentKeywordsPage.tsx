import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { toast } from '@/components/ui/toast';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { GpuStatusBadge } from '@/src/components/GpuStatusBadge';
import { PgBadge, PgConfirmDialog, PgEmpty, PgError, PgPageHeader, PgRefresh, PgSegment, PgSkeleton } from '@/src/components/pg';
import { dashboardKeys, documentKeys } from '@/src/queries/keys';
import { dashboardService } from '@/src/services/dashboardService';
import { documentService } from '@/src/services/documentService';
import {
  detectionOpsKeys,
  detectionOpsMessage,
  detectionOpsService,
  keywordGenerality,
  keywordGeneralityText,
  type DocumentKeyword,
  type KeywordJob,
  type KeywordJobList,
} from '@/src/services/detectionOpsService';
import type { ConfidentialDocument } from '@/src/types/policy';
import { formatDateTime, formatShortDateTime, formatCount } from '@/src/utils/format';
import { notifySuccess } from '@/src/utils/feedback';
import { uiMode } from '@runtime/ui-mode';

// 문서별 키워드(재설계 3a, 설계 5.5·목업 keywords.html): 문서 카드 하나에 그 문서의 승인 대기 후보를 모은다.
// 좁은 화면(후보 표 자리 720px 이하)에서는 후보 표가 카드로 바뀌어 승인·수정·반려 버튼이 화면 안에 있다(표→카드, 설계 4.6).
// 기능·API 호출은 그대로: 승인·반려·삭제·수정(저장/저장 후 승인)·직접 추가·추출 요청·추출 재시도·반영 재시도.

const JOB_LABEL: Record<KeywordJob['status'], string> = {
  queued: '추출 대기',
  running: '추출 중',
  done: '추출 완료',
  failed: '추출 실패',
};
const JOB_TONE = { queued: 'info', running: 'info', done: 'neutral', failed: 'block' } as const;
/** 추출하지 않고 끝난 작업(2026-10-15 감사 9번): Detection은 문서가 없어졌거나 판이 바뀌어 건너뛴 작업도 done + error 'superseded: …'로 끝낸다 */
const isSkippedJob = (job?: Pick<KeywordJob, 'status' | 'error'>) => job?.status === 'done' && typeof job.error === 'string' && job.error.startsWith('superseded');
const SOURCE_LABEL: Record<string, string> = { llm: 'LLM 추출', manual: '직접 추가' };
const CHIP_LIMIT = 6;
const EVIDENCE_LIMIT = 3;

type View = 'pending' | 'approved' | 'failed' | 'all';

type DocumentRow = {
  docId: string;
  name: string;
  document?: ConfidentialDocument;
  approved: DocumentKeyword[];
  pending: DocumentKeyword[];
  job?: KeywordJob;
};

function failed(context: 'extract' | 'keyword' | 'edit') {
  return (error: unknown) =>
    toast.add({ title: '작업을 완료하지 못했습니다.', description: detectionOpsMessage(error, context), type: 'error', priority: 'high' });
}

function buildRows(documents: ConfidentialDocument[], keywords: DocumentKeyword[], jobs: KeywordJob[]): DocumentRow[] {
  const rows = new Map<string, DocumentRow>();
  for (const document of documents)
    rows.set(document.documentId, { docId: document.documentId, name: document.documentName, document, approved: [], pending: [] });
  for (const keyword of keywords) {
    const row = rows.get(keyword.doc_id) ?? { docId: keyword.doc_id, name: keyword.doc_id, approved: [], pending: [] };
    (keyword.status === 'approved' ? row.approved : row.pending).push(keyword);
    rows.set(keyword.doc_id, row);
  }
  for (const job of [...jobs].sort((a, b) => b.id - a.id)) {
    const row = rows.get(job.doc_id);
    if (row && !row.job) row.job = job;
  }
  for (const row of rows.values()) row.pending.sort((a, b) => a.id - b.id);
  // 승인 대기가 있는 문서를 먼저, 나머지는 이름순
  return [...rows.values()].sort((a, b) => Number(b.pending.length > 0) - Number(a.pending.length > 0) || a.name.localeCompare(b.name, 'ko'));
}

function isExtracting(list?: KeywordJobList) {
  return (list?.counts.queued ?? 0) + (list?.counts.running ?? 0) > 0;
}

function Chips({ keywords }: { keywords: DocumentKeyword[] }) {
  return (
    <span className="pg-kw-chips dops-chips">
      {keywords.slice(0, CHIP_LIMIT).map(keyword => (
        <PgBadge variant="tag" key={keyword.id} title={[keyword.keyword, keywordGeneralityText(keyword)].filter(Boolean).join(' · ')}>{keyword.keyword}</PgBadge>
      ))}
      {keywords.length > CHIP_LIMIT && <span className="pg-kw-muted">외 {formatCount(keywords.length - CHIP_LIMIT)}개</span>}
      {(generic => generic > 0 && <span className="pg-kw-generic-note">일반 표현일 수 있음 {formatCount(generic)}개</span>)(keywords.filter(keyword => keywordGenerality(keyword).generic).length)}
    </span>
  );
}

/** 추출 상태 배지: "추출 완료 10.04 14:26"(시각 전체는 title) / 기록 없으면 "요청 기록 없음" */
function JobBadge({ job }: { job?: KeywordJob }) {
  if (!job) return <PgBadge tone="neutral">요청 기록 없음</PgBadge>;
  const at = job.finished_at ?? job.created_at ?? '';
  const skipped = isSkippedJob(job);
  return (
    <PgBadge tone={JOB_TONE[job.status]} title={at ? `${formatDateTime(at)}${skipped ? ' · 문서가 바뀌거나 없어져 추출하지 않고 끝남' : ''}` : undefined}>
      {skipped ? '추출 건너뜀' : JOB_LABEL[job.status]}{at && <small>{formatShortDateTime(at)}</small>}
    </PgBadge>
  );
}

export function DocumentKeywordsPage() {
  const client = useQueryClient();
  const canManage = uiMode.canManagePolicies;
  const [view, setView] = useState<View>('pending');
  const [openDoc, setOpenDoc] = useState<string | null>(null);
  const [unapplied, setUnapplied] = useState<ReadonlySet<number>>(new Set());
  const [removing, setRemoving] = useState<DocumentKeyword | null>(null);
  const [draft, setDraft] = useState({ keyword: '', approve: false });

  // 추출이 대기·진행 중이면 3초마다 다시 읽어 결과(새 후보)를 바로 보여준다
  const jobs = useQuery<KeywordJobList>({
    ...liveQueryOptions,
    refetchInterval: query => (isExtracting(query.state.data) ? 3_000 : liveQueryOptions.refetchInterval),
    queryKey: detectionOpsKeys.keywordJobs(),
    queryFn: ({ signal }) => detectionOpsService.getKeywordJobs(signal),
  });
  const extracting = isExtracting(jobs.data);
  const keywords = useQuery({
    ...liveQueryOptions,
    refetchInterval: extracting ? 3_000 : liveQueryOptions.refetchInterval,
    queryKey: detectionOpsKeys.keywords(),
    queryFn: ({ signal }) => detectionOpsService.getKeywords(signal),
  });
  const documents = useQuery({ ...liveQueryOptions, queryKey: documentKeys.list(), queryFn: ({ signal }) => documentService.getDocuments(signal) });
  // 최근 30일 기밀 키워드 탐지 건수(2026-10-10)
  const hits = useQuery({ queryKey: dashboardKeys.summary('30D'), queryFn: ({ signal }) => dashboardService.getSummary('30D', signal), staleTime: 60_000 });
  const keywordHits = hits.data?.insights?.categoryCounts?.find(category => category.key === 'KEYWORD')?.events;
  const gpu = useQuery({ queryKey: detectionOpsKeys.gpu(), queryFn: ({ signal }) => detectionOpsService.getGpuStatus(signal), refetchInterval: 30_000, retry: false });

  const rows = useMemo(
    () => buildRows(documents.data ?? [], keywords.data ?? [], jobs.data?.jobs ?? []),
    [documents.data, keywords.data, jobs.data],
  );
  const nameOf = useMemo(() => new Map(rows.map(row => [row.docId, row.name])), [rows]);
  const pendingTotal = useMemo(() => (keywords.data ?? []).filter(keyword => keyword.status === 'pending').length, [keywords.data]);

  // 추출이 끝나면 알리고 키워드를 바로 다시 읽는다(대기·진행 → 완료/실패로 바뀐 작업만).
  // 키워드와 작업 상태는 따로 읽으므로, 완료를 본 시점에 키워드 목록이 아직 이전 것일 수 있다
  const lastStatus = useRef(new Map<number, KeywordJob['status']>());
  useEffect(() => {
    for (const job of jobs.data?.jobs ?? []) {
      const before = lastStatus.current.get(job.id);
      if ((before === 'queued' || before === 'running') && job.status === 'done' && !isSkippedJob(job)) {
        void client.invalidateQueries({ queryKey: detectionOpsKeys.keywords() });
        notifySuccess(`키워드 추출 완료 · ${nameOf.get(job.doc_id) ?? job.doc_id}`, '새 후보는 승인 대기 목록에서 확인하세요.');
      }
      if ((before === 'queued' || before === 'running') && job.status === 'failed')
        toast.add({ title: `키워드 추출 실패 · ${nameOf.get(job.doc_id) ?? job.doc_id}`, description: "문서의 '추출 재시도'를 눌러주세요.", type: 'error', priority: 'high' });
      lastStatus.current.set(job.id, job.status);
    }
  }, [jobs.data, nameOf, client]);

  const refresh = () => Promise.all([
    client.invalidateQueries({ queryKey: detectionOpsKeys.keywords() }),
    client.invalidateQueries({ queryKey: detectionOpsKeys.keywordJobs() }),
  ]);
  const markApplied = (keywordId: number, applied: boolean | undefined) =>
    setUnapplied(current => {
      const next = new Set(current);
      if (applied === false) next.add(keywordId);
      else next.delete(keywordId);
      return next;
    });

  const approve = useMutation({
    mutationFn: (keyword: DocumentKeyword) => detectionOpsService.approveKeyword(keyword.id),
    onSuccess: async (result, keyword) => {
      markApplied(keyword.id, result.applied);
      if (result.applied === false)
        toast.add({ title: '승인됨 · 탐지 반영 실패', description: "승인은 저장됐지만 탐지 서버에 아직 반영되지 않았습니다. '반영 재시도'를 눌러주세요.", type: 'warning', priority: 'high' });
      else notifySuccess('키워드를 승인했습니다.', '탐지에 바로 반영됐습니다.');
      await refresh();
    },
    onError: failed('keyword'),
  });
  const remove = useMutation({
    mutationFn: (keyword: DocumentKeyword) => detectionOpsService.rejectKeyword(keyword.id),
    onSuccess: async (result, keyword) => {
      markApplied(keyword.id, true);
      setRemoving(null);
      if (keyword.status === 'approved' && result.applied === false)
        toast.add({ title: '삭제됨 · 탐지 반영 실패', description: '키워드는 삭제됐지만 탐지 서버가 아직 이전 목록을 쓰고 있습니다. 다른 키워드를 승인·삭제하면 함께 반영됩니다.', type: 'warning', priority: 'high' });
      else if (keyword.status === 'approved') notifySuccess('키워드를 삭제했습니다.', '탐지에서 바로 빠졌습니다.');
      else notifySuccess('키워드를 반려했습니다.');
      await refresh();
    },
    onError: failed('keyword'),
  });
  const add = useMutation({
    mutationFn: ({ docId, keyword, approveNow }: { docId: string; keyword: string; approveNow: boolean }) =>
      detectionOpsService.addKeyword(keyword, docId, approveNow),
    onSuccess: async (result) => {
      setDraft({ keyword: '', approve: false });
      if (result.status === 'approved') markApplied(result.id, result.applied);
      if (result.status === 'approved' && result.applied === false)
        toast.add({ title: '추가·승인됨 · 탐지 반영 실패', description: "'반영 재시도'를 눌러주세요.", type: 'warning', priority: 'high' });
      else notifySuccess('키워드를 추가했습니다.', result.status === 'approved' ? '승인되어 탐지에 반영됐습니다.' : '승인 대기 목록에 들어갔습니다.');
      await refresh();
    },
    onError: failed('keyword'),
  });
  // 승인 대기 키워드 고치기. "저장 후 승인"은 고친 뒤 승인까지(승인은 멱등이라 둘째 단계만 다시 해도 된다)
  const edit = useMutation({
    mutationFn: async ({ keyword, value, approveAfter }: { keyword: DocumentKeyword; value: string; approveAfter: boolean }) => {
      const updated = await detectionOpsService.updateKeyword(keyword.id, value);
      return { updated, approved: approveAfter ? await detectionOpsService.approveKeyword(keyword.id) : undefined };
    },
    onSuccess: async ({ updated, approved }) => {
      if (approved) {
        markApplied(updated.id, approved.applied);
        if (approved.applied === false)
          toast.add({ title: '수정·승인됨 · 탐지 반영 실패', description: "'반영 재시도'를 눌러주세요.", type: 'warning', priority: 'high' });
        else notifySuccess('키워드를 고친 뒤 승인했습니다.', '탐지에 바로 반영됐습니다.');
      } else notifySuccess('키워드를 고쳤습니다.', '승인 대기 상태 그대로입니다.');
      await refresh();
    },
    onError: async (error: unknown) => {
      failed('edit')(error);
      await refresh();
    },
  });
  const extract = useMutation({
    mutationFn: (docId: string) => detectionOpsService.requestExtraction(docId),
    onSuccess: async () => {
      notifySuccess('키워드 추출을 요청했습니다.', gpu.data?.connected ? '끝나면 새 후보가 승인 대기 목록에 올라옵니다.' : 'GPU가 응답하지 않아 대기합니다. GPU가 켜지면 차례로 처리됩니다.');
      await refresh();
    },
    onError: failed('extract'),
  });
  const retry = useMutation({
    mutationFn: (jobId: number) => detectionOpsService.retryJob(jobId),
    onSuccess: async () => {
      notifySuccess('추출을 다시 요청했습니다.');
      await refresh();
    },
    onError: failed('extract'),
  });

  const counts = jobs.data?.counts;
  const approvedTotal = keywords.data?.filter(keyword => keyword.status === 'approved').length ?? 0;
  // 추출 실패 = 지금 등록된 문서 중 마지막 추출이 실패인 문서(보안 현황 '키워드 추출 실패 문서'와 같은 기준, 감사 8번).
  // 단추 숫자도 이 목록 수 — 전에는 실패 상태 작업 행 전체 수(옛 실패 작업까지)라 목록과 달랐다
  const failedDocs = rows.filter(row => row.document && row.job?.status === 'failed');
  const loading = keywords.isLoading || documents.isLoading;
  const loadError = keywords.isError && !keywords.data ? keywords.error : documents.isError && !documents.data ? documents.error : null;
  const keywordActions: KeywordActions = {
    canManage,
    unapplied,
    busyId: approve.isPending ? approve.variables?.id : undefined,
    onApprove: (keyword: DocumentKeyword) => approve.mutate(keyword),
    onRemove: (keyword: DocumentKeyword) => { remove.reset(); setRemoving(keyword); },
    editingId: edit.isPending ? edit.variables?.keyword.id : undefined,
    onEdit: (keyword: DocumentKeyword, value: string, approveAfter: boolean) =>
      edit.mutateAsync({ keyword, value, approveAfter }).then(() => true, () => false),
  };

  const submitDraft = (event: FormEvent<HTMLFormElement>, docId: string) => {
    event.preventDefault();
    const keyword = draft.keyword.trim();
    if (!keyword || add.isPending) return;
    add.mutate({ docId, keyword, approveNow: draft.approve });
  };
  const toggleManage = (docId: string) => { setOpenDoc(current => (current === docId ? null : docId)); setDraft({ keyword: '', approve: false }); };

  const docActions = (row: DocumentRow) => {
    const busyJob = row.job?.status === 'queued' || row.job?.status === 'running';
    const indexed = row.document?.chunkIndexStatus === 'READY' && row.document.status === 'ACTIVE';
    const expanded = openDoc === row.docId;
    return (
      <>
        {canManage && row.job?.status === 'failed' ? (
          <Button size="sm" variant="outline" disabled={retry.isPending} onClick={() => row.job && retry.mutate(row.job.id)}>추출 재시도</Button>
        ) : canManage && (
          <Button
            size="sm"
            variant="outline"
            disabled={!indexed || busyJob || (extract.isPending && extract.variables === row.docId)}
            title={!indexed ? '색인이 끝난 활성 문서만 추출할 수 있습니다.' : busyJob ? '이미 추출 요청이 진행 중입니다.' : undefined}
            onClick={() => extract.mutate(row.docId)}
          >
            추출 요청
          </Button>
        )}
        <Button size="sm" variant="ghost" aria-expanded={expanded} onClick={() => toggleManage(row.docId)}>
          {expanded ? '닫기' : '키워드 관리'}
        </Button>
      </>
    );
  };
  const managePanel = (row: DocumentRow) => openDoc === row.docId && (
    <div className="pg-kw-manage">
      {row.approved.length ? (
        <ApprovedTable label={`${row.name} 키워드`} keywords={row.approved} {...keywordActions} />
      ) : <p className="pg-kw-muted">승인된 키워드가 없습니다. 후보를 승인하거나 아래에서 직접 추가하세요.</p>}
      {canManage && (
        <form className="pg-kw-add" onSubmit={event => submitDraft(event, row.docId)}>
          <Input
            type="text"
            aria-label="추가할 키워드"
            placeholder="본문에 있는 표현 그대로 (2~100자)"
            value={draft.keyword}
            maxLength={100}
            onChange={event => setDraft(current => ({ ...current, keyword: event.target.value }))}
          />
          <label>
            <input type="checkbox" checked={draft.approve} onChange={event => setDraft(current => ({ ...current, approve: event.target.checked }))} />
            바로 승인
          </label>
          <Button type="submit" size="sm" disabled={add.isPending || draft.keyword.trim().length < 2}>
            {add.isPending ? '추가 중…' : '키워드 추가'}
          </Button>
        </form>
      )}
    </div>
  );

  const cardRows = view === 'pending' ? rows.filter(row => row.pending.length > 0)
    : view === 'approved' ? rows.filter(row => row.approved.length > 0)
      : view === 'failed' ? failedDocs
        : rows;
  const restRows = view === 'pending' ? rows.filter(row => row.pending.length === 0) : [];
  const ready = Boolean(keywords.data);
  const count = (value: number | undefined) => <b>{ready ? value ?? 0 : '–'}</b>;
  const cardsEmpty = {
    pending: extracting ? '추출 중입니다. 끝나면 새 후보가 여기에 올라옵니다.' : '승인 대기 중인 키워드가 없습니다.',
    approved: '승인된 키워드가 있는 문서가 없습니다.',
    failed: '추출에 실패한 문서가 없습니다.',
    all: '등록된 보호 문서가 없습니다.',
  }[view];

  return (
    <div className="pg-screen pg-kw-page">
      <PgPageHeader
        title="문서별 키워드"
        description="LLM이 뽑은 후보 중 승인한 키워드만 탐지에 사용"
        secondary={<GpuStatusBadge />}
        refresh={<PgRefresh updatedAt={keywords.dataUpdatedAt} fetching={keywords.isFetching} failed={keywords.isError} onRefresh={() => refresh()} />}
      />
      <div className="pg-kw-toolbar">
        <PgSegment
          legend="키워드 현황"
          legendHidden
          name="pg-kw-view"
          value={view}
          onChange={setView}
          options={[
            { value: 'pending', label: <>승인 대기 {count(pendingTotal)}개</>, title: '승인 대기 키워드 수 · 누르면 그 키워드가 있는 문서' },
            { value: 'approved', label: <>승인됨 {count(approvedTotal)}개</>, title: '승인된 키워드 수 · 누르면 그 키워드가 있는 문서' },
            { value: 'failed', label: <>추출 실패 문서 <b>{jobs.data && documents.data ? failedDocs.length : '–'}</b></>, title: '마지막 추출이 실패한 등록 문서 보기' },
            { value: 'all', label: <>전체 문서 <b>{documents.data ? rows.length : '–'}</b></> },
          ]}
        />
        <p className="pg-kw-facts">
          <span>최근 30일 키워드 탐지 <b>{keywordHits ?? '–'}</b>건</span>
          {(counts?.queued ?? 0) > 0 && <span>추출 대기 <b>{counts?.queued}</b></span>}
          {(counts?.running ?? 0) > 0 && <span>추출 중 <b>{counts?.running}</b></span>}
          <span>승인 즉시 탐지에 반영</span>
        </p>
      </div>
      {gpu.data && !gpu.data.connected && (counts?.queued ?? 0) > 0 && (
        <p className="pg-kw-notice" role="status">GPU가 응답하지 않아 추출 요청 {formatCount(counts?.queued ?? 0)}건이 대기 중입니다. GPU가 켜지면 차례로 처리됩니다.</p>
      )}

      {loading ? (
        <PgSkeleton shape="table" rows={3} />
      ) : loadError ? (
        <PgError message="키워드를 불러오지 못했습니다." error={loadError} onRetry={() => { void keywords.refetch(); void documents.refetch(); }} />
      ) : (
        <>
          <section className="pg-kw-cards" aria-labelledby="pg-kw-cards-title">
            <h2 id="pg-kw-cards-title" className="sr-only">
              {view === 'pending' ? `승인 대기 키워드 ${formatCount(pendingTotal)}개` : view === 'approved' ? `승인된 키워드가 있는 문서 ${formatCount(cardRows.length)}개` : view === 'failed' ? `추출 실패 문서 ${formatCount(cardRows.length)}개` : `전체 문서 ${formatCount(cardRows.length)}개`}
            </h2>
            {cardRows.length === 0 ? (
              <div className="pg-kw-card"><PgEmpty title={cardsEmpty} description={view === 'pending' && !extracting ? '아래 문서에서 추출을 요청하면 후보가 여기에 올라옵니다.' : undefined} /></div>
            ) : cardRows.map(row => (
              <article className="pg-kw-card" key={row.docId} aria-labelledby={`pg-kw-doc-${row.docId}`}>
                <header className="pg-kw-card-head">
                  <h3 id={`pg-kw-doc-${row.docId}`} className="pg-kw-doc-name" title={row.docId}>{row.name}</h3>
                  <JobBadge job={row.job} />
                  <span className="pg-kw-doc-counts">대기 <b>{row.pending.length}</b> · 승인 {row.approved.length}</span>
                  {row.document?.status === 'INACTIVE' && <PgBadge tone="neutral" title="탐지 제외(문서 보호 중지) · 이 문서의 승인 키워드는 탐지에 쓰이지 않음, 다시 보호하면 돌아옴">보호 중지 문서</PgBadge>}
                  {!row.document && <PgBadge tone="neutral">문서 목록에 없음</PgBadge>}
                  <span className="pg-kw-card-actions">{docActions(row)}</span>
                </header>
                {row.pending.length > 0 && (
                  <CandidateTable label={`승인 대기 키워드 · ${row.name}`} keywords={row.pending} {...keywordActions} />
                )}
                {managePanel(row)}
                <footer className="pg-kw-card-foot">
                  <span className="pg-kw-muted">승인된 키워드{row.approved.length ? ` ${row.approved.length}` : ': 없음'}</span>
                  {row.approved.length > 0 && <Chips keywords={row.approved} />}
                </footer>
              </article>
            ))}
          </section>

          {view === 'pending' && restRows.length > 0 && (
            <section className="pg-kw-card pg-kw-rest" aria-labelledby="pg-kw-rest-title">
              <header className="pg-kw-card-head">
                <h2 id="pg-kw-rest-title" className="pg-kw-doc-name">대기 없는 문서 {restRows.length}</h2>
                <span className="pg-kw-muted pg-kw-card-actions">승인된 키워드 · 추출 상태</span>
              </header>
              <Table card aria-label="대기 없는 문서" className="pg-kw-rest-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>문서</TableHead>
                    <TableHead>승인된 키워드</TableHead>
                    <TableHead>추출</TableHead>
                    <TableHead className="pg-kw-col-actions">관리</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {restRows.flatMap(row => {
                    const tone = row.job?.status === 'failed' ? 'block' : undefined;
                    const main = (
                      <TableRow key={row.docId} data-tone={tone}>
                        <TableCell data-card="title">
                          <span className="pg-kw-rest-name" title={row.docId}>{row.name}</span>
                          {row.document?.status === 'INACTIVE' && <small className="pg-kw-muted" title="탐지 제외(문서 보호 중지) · 이 문서의 승인 키워드는 탐지에 쓰이지 않음, 다시 보호하면 돌아옴">보호 중지 문서</small>}
                          {!row.document && <small className="pg-kw-muted">문서 목록에 없음</small>}
                        </TableCell>
                        <TableCell data-card="body">
                          {row.approved.length ? <span className="pg-kw-rest-approved"><span className="pg-kw-muted">승인 {row.approved.length}</span><Chips keywords={row.approved} /></span> : <span className="pg-kw-muted">아직 없음</span>}
                        </TableCell>
                        <TableCell data-card="badge"><JobBadge job={row.job} /></TableCell>
                        <TableCell data-card="actions"><span className="pg-kw-row-actions">{docActions(row)}</span></TableCell>
                      </TableRow>
                    );
                    if (openDoc !== row.docId) return [main];
                    return [main, (
                      <TableRow key={`${row.docId}-manage`} className="pg-kw-manage-row">
                        <TableCell colSpan={4} data-card="body">{managePanel(row)}</TableCell>
                      </TableRow>
                    )];
                  })}
                </TableBody>
              </Table>
            </section>
          )}
        </>
      )}

      <PgConfirmDialog
        open={removing !== null}
        onOpenChange={open => { if (!open) setRemoving(null); }}
        action={removing?.status === 'approved' ? '삭제' : '반려'}
        target={removing?.keyword}
        change={removing?.status === 'approved' ? '승인된 키워드를 지웁니다. 탐지에서도 바로 빠집니다.' : '후보 목록에서 지웁니다. 탐지에는 쓰이지 않습니다.'}
        reversible={removing?.status === 'approved' ? '되돌리려면 직접 추가해 다시 승인해야 합니다.' : '되돌리려면 직접 추가해야 합니다.'}
        danger
        busy={remove.isPending}
        busyLabel="처리 중…"
        onConfirm={() => removing && remove.mutate(removing)}
      />
    </div>
  );
}

// 근거 문장에서 키워드를 굵게(대소문자 무시). 문장은 본문에서 시스템이 잘라 온 원문이다.
function EvidenceLine({ line, keyword }: { line: string; keyword: string }) {
  const at = line.toLowerCase().indexOf(keyword.toLowerCase());
  if (at < 0 || !keyword) return <>{line}</>;
  return (
    <>
      {line.slice(0, at)}
      <mark>{line.slice(at, at + keyword.length)}</mark>
      {line.slice(at + keyword.length)}
    </>
  );
}

/** 근거 문장: 기본 펼침(설계 5.5), 4개 이상이면 3개 + 더보기 */
function Evidence({ text, keyword }: { text: string; keyword: string }) {
  const [all, setAll] = useState(false);
  const lines = text.split('\n').filter(Boolean);
  const shown = all ? lines : lines.slice(0, EVIDENCE_LIMIT);
  return (
    <div className="pg-kw-evidence dops-evidence">
      <span className="pg-kw-label">근거 문장</span>
      {shown.map((line, index) => (
        <p key={index}><EvidenceLine line={line} keyword={keyword} /></p>
      ))}
      {lines.length > EVIDENCE_LIMIT && (
        <button type="button" className="pg-kw-more" aria-expanded={all} onClick={() => setAll(value => !value)}>
          {all ? '접기' : `더보기 ${lines.length - EVIDENCE_LIMIT}`}
        </button>
      )}
    </div>
  );
}

type KeywordActions = {
  canManage: boolean;
  unapplied: ReadonlySet<number>;
  busyId?: number;
  editingId?: number;
  onApprove: (keyword: DocumentKeyword) => void;
  onRemove: (keyword: DocumentKeyword) => void;
  onEdit: (keyword: DocumentKeyword, value: string, approveAfter: boolean) => Promise<boolean>;
};

/**
 * 후보 표(설계 5.5 '후보 1개에 보이는 것'): 키워드·상태 배지(승인 대기·일반 표현·탐지 반영 실패) | 선정 이유·근거 문장·주의 |
 * 보호 문서 포함 | 무관 문장 포함(1 이상이면 주의 바탕) | 승인·수정·반려 + 출처·등록 시각.
 * 열 이름은 화면 읽기 프로그램에만(칸 안에 이름표가 있다). 표 자리 720px 이하에서는 카드(버튼 3등분, 높이 40).
 */
function CandidateTable({ label, keywords, canManage, unapplied, busyId, editingId, onApprove, onRemove, onEdit }: { label: string; keywords: DocumentKeyword[] } & KeywordActions) {
  const [editing, setEditing] = useState<{ id: number; value: string } | null>(null);
  const save = async (keyword: DocumentKeyword, approveAfter: boolean) => {
    if (!editing) return;
    if (await onEdit(keyword, editing.value.trim(), approveAfter)) setEditing(null);
  };
  return (
    <Table card aria-label={label} className="pg-kw-table">
      <TableHeader className="pg-kw-head">
        <TableRow>
          <TableHead>키워드</TableHead>
          <TableHead>선정 이유 · 근거</TableHead>
          <TableHead title="추출 때 기준으로 활성 보호 문서 중 이 표현이 들어 있는 문서 수(이 문서 포함) · 직접 추가한 키워드는 미측정">보호 문서 포함</TableHead>
          <TableHead title="기밀과 무관한 공개 문장(공시 등) 중 이 표현이 나오는 수 - 높으면 오탐 가능성이 큽니다">무관 문장 포함</TableHead>
          <TableHead>{canManage ? '관리' : '등록'}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {keywords.map(keyword => {
          const isEditing = editing?.id === keyword.id;
          const saving = editingId === keyword.id;
          const value = isEditing ? editing.value.trim() : '';
          const canSave = isEditing && value.length >= 2 && value.length <= 100 && value !== keyword.keyword && !saving;
          const generality = keywordGenerality(keyword);
          const generic = generality.generic;
          const neg = keyword.neg_hits;
          return (
            <TableRow key={keyword.id} className="pg-kw-row">
              <TableCell data-card="title" className="pg-kw-cell-keyword">
                {isEditing ? (
                  <Input
                    type="text"
                    className="pg-kw-edit"
                    aria-label={`${keyword.keyword} 수정`}
                    value={editing.value}
                    maxLength={100}
                    autoFocus
                    disabled={saving}
                    onChange={event => setEditing({ id: keyword.id, value: event.target.value })}
                    onKeyDown={event => {
                      if (event.key === 'Enter' && canSave) void save(keyword, false);
                      if (event.key === 'Escape') setEditing(null);
                    }}
                  />
                ) : <span className="pg-kw-keyword">{keyword.keyword}</span>}
                <span className="pg-kw-badges">
                  <PgBadge tone="info">승인 대기</PgBadge>
                  {generic && <PgBadge tone="mask" title={keywordGeneralityText(keyword) ?? undefined}>일반 표현</PgBadge>}
                  {unapplied.has(keyword.id) && <PgBadge tone="mask">탐지 반영 실패</PgBadge>}
                </span>
              </TableCell>
              <TableCell data-card="body" className="pg-kw-cell-reason">
                {keyword.reason && <p className="pg-kw-reason"><span className="pg-kw-label">선정 이유</span>{keyword.reason}</p>}
                {keyword.evidence && <Evidence text={keyword.evidence} keyword={keyword.keyword} />}
                {generic && (
                  <p className="pg-kw-caution">
                    <span aria-hidden="true">⚠ </span>{generality.common ? keywordGeneralityText(keyword) : <>일반적인 표현일 수 있습니다{keyword.reason_check?.kind ? `(${keyword.reason_check.kind})` : ''}</>} · 근거 문장을 확인하세요
                  </p>
                )}
                {keyword.reason_check?.ok === false && (
                  <p className="pg-kw-check">자동 설명 검사를 통과하지 못해 짧은 설명으로 대신했습니다</p>
                )}
              </TableCell>
              <TableCell className="pg-kw-cell-count">
                <span className="pg-kw-count"><span>보호 문서 포함</span><b>{keyword.doc_hits ?? <span className="pg-kw-muted">미측정</span>}</b></span>
              </TableCell>
              <TableCell className="pg-kw-cell-count">
                <span className={`pg-kw-count${neg !== null && neg !== undefined && neg >= 1 ? ' is-warn' : ''}`}><span>무관 문장 포함</span><b>{neg ?? <span className="pg-kw-muted">미측정</span>}</b></span>
              </TableCell>
              <TableCell data-card="actions" className="pg-kw-cell-actions">
                {canManage && (
                  <span className="pg-kw-actions">
                    {isEditing ? (
                      <>
                        <Button size="sm" disabled={!canSave} onClick={() => void save(keyword, false)}>{saving ? '저장 중…' : '저장'}</Button>
                        <Button size="sm" variant="outline" disabled={!canSave} onClick={() => void save(keyword, true)}>저장 후 승인</Button>
                        <Button size="sm" variant="outline" disabled={saving} onClick={() => setEditing(null)}>취소</Button>
                      </>
                    ) : (
                      <>
                        <Button size="sm" disabled={busyId === keyword.id} onClick={() => onApprove(keyword)}>승인</Button>
                        <Button size="sm" variant="outline" onClick={() => setEditing({ id: keyword.id, value: keyword.keyword })}>수정</Button>
                        <Button size="sm" variant="danger" onClick={() => onRemove(keyword)}>반려</Button>
                      </>
                    )}
                  </span>
                )}
                <span className="pg-kw-meta" title={keyword.created_at ? formatDateTime(keyword.created_at) : undefined}>
                  {SOURCE_LABEL[keyword.source] ?? keyword.source}{keyword.created_at ? ` · ${formatShortDateTime(keyword.created_at)}` : ''}
                </span>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

/** 승인된 키워드(키워드 관리): 키워드 | 결정(관리자·시각) | 삭제·반영 재시도. 수정은 승인 대기 후보만 */
function ApprovedTable({ label, keywords, canManage, unapplied, busyId, onApprove, onRemove }: { label: string; keywords: DocumentKeyword[] } & KeywordActions) {
  return (
    <Table card aria-label={label} className="pg-kw-approved-table">
      <TableHeader>
        <TableRow>
          <TableHead>키워드</TableHead>
          <TableHead>상태</TableHead>
          <TableHead>결정</TableHead>
          {canManage && <TableHead className="pg-kw-col-actions">관리</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {keywords.map(keyword => (
          <TableRow key={keyword.id} data-tone={unapplied.has(keyword.id) ? 'mask' : undefined}>
            <TableCell data-card="title"><span className="pg-kw-keyword">{keyword.keyword}</span>{keywordGenerality(keyword).generic && <small className="pg-kw-generic-note">{keywordGeneralityText(keyword)}</small>}</TableCell>
            <TableCell data-card="badge">
              {unapplied.has(keyword.id) ? <PgBadge tone="mask">탐지 반영 실패</PgBadge> : <PgBadge tone="allow">승인됨</PgBadge>}
              {keywordGenerality(keyword).generic && <PgBadge tone="mask" title={keywordGeneralityText(keyword) ?? undefined}>일반 표현</PgBadge>}
            </TableCell>
            <TableCell data-card="info" title={keyword.decided_at ? formatDateTime(keyword.decided_at) : undefined}>
              {keyword.decided_at
                ? `${keyword.decided_by ?? '관리자 미기록'} · ${formatShortDateTime(keyword.decided_at)}`
                : `${SOURCE_LABEL[keyword.source] ?? keyword.source}${keyword.created_at ? ` · 등록 ${formatShortDateTime(keyword.created_at)}` : ''}`}
            </TableCell>
            {canManage && (
              <TableCell data-card="actions">
                <span className="pg-kw-row-actions">
                  {unapplied.has(keyword.id) && (
                    <Button size="sm" variant="outline" disabled={busyId === keyword.id} onClick={() => onApprove(keyword)}>반영 재시도</Button>
                  )}
                  <Button size="sm" variant="danger" onClick={() => onRemove(keyword)}>삭제</Button>
                </span>
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
