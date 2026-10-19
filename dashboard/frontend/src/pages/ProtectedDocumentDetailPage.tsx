import { uiLabel } from '@/src/utils/labels';
import { ArrowLeft, FileSearch } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { PgBadge, PgCount, PgEmpty, PgError, PgPageHeader, PgPager, PgRefresh, PgSkeleton, PgStatusStrip } from '@/src/components/pg';
import { EventsTable } from '@/src/components/EventsTable';
import { documentService } from '@/src/services/documentService';
import { eventService } from '@/src/services/eventService';
import { detectionOpsKeys, detectionOpsService } from '@/src/services/detectionOpsService';
import type { EventFilters } from '@/src/types/event';
import { formatDateTime, formatBytes, formatCount } from '@/src/utils/format';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { ApiError } from '@/src/api/errors';
import { DocumentProtectionBadge } from '@/src/components/DocumentProtectionBadge';
import { documentProtectionStage } from '@/src/utils/documentPresentation';
import '@/src/styles/documents.css';

// 재설계 3e 상세(설계 5.4 '상세'): 머리(문서명 + 상태 배지 + [본문 보기]) → 분할 배치
//  왼쪽: 문서 정보 격자(문서 ID는 이름과 같으면 숨김·판·분류·소유자·탐지 방식·등록·최근 탐지) → 연결 이벤트(보안 이벤트 표 부품 그대로, 5.2)
//  오른쪽: 지표 2칸 → 등록된 키워드(승인·승인 대기) → 접힘 2개(색인·기술 정보 / 본문 보기 원칙 — '원문 비노출'을 6.6에 따라 고침)
// 연결 이벤트 조회·쪽 이동·자동 갱신은 그대로.

const relatedEventFilters = (documentId: string, page: number): EventFilters => ({
  query: '',
  period: '30D',
  finalAction: 'ALL',
  recommendedAction: 'ALL',
  detector: 'ALL',
  matchType: 'ALL',
  scoreKind: 'ALL',
  degraded: 'ALL',
  detectionOutcome: 'ALL',
  degradedReason: 'ALL',
  failurePolicy: 'ALL',
  documentId,
  severity: 'ALL',
  status: 'ALL',
  targetLlm: 'ALL',
  sort: 'OCCURRED_AT_DESC',
  page,
  pageSize: 20,
  // 누적 탐지와 같은 기준(2026-10-15): 10/11 전 파일 재전송을 1건으로 접는다(옛 서버는 이 칸을 모르고 전부 줌)
  scope: 'counted',
});

export function ProtectedDocumentDetailPage() {
  const { documentId = '' } = useParams();
  const navigate = useNavigate();
  const [cursor, setCursor] = useState({ documentId, page: 1 });
  const page = cursor.documentId === documentId ? cursor.page : 1;
  const query = useQuery({
    ...liveQueryOptions,
    queryKey: ['documents', 'detail', documentId, page],
    queryFn: async ({ signal }) => {
      const [documents, events] = await Promise.all([
        documentService.getDocuments(signal),
        eventService.getEvents(relatedEventFilters(documentId, page), signal),
      ]);
      return {
        document: documents.find((item) => item.documentId === documentId),
        events,
      };
    },
  });
  const keywords = useQuery({ queryKey: detectionOpsKeys.keywords(), queryFn: ({ signal }) => detectionOpsService.getKeywords(signal), retry: false, refetchOnWindowFocus: false, enabled: Boolean(query.data?.document) });

  const backLink = (
    <Link className="pg-doc-back" to="/documents">
      <ArrowLeft aria-hidden="true" /> 보호 문서
    </Link>
  );
  const shell = (body: React.ReactNode) => <div className="pg-screen pg-doc-detail">{backLink}{body}</div>;
  const notFound = shell(<PgEmpty title="보호 문서를 찾을 수 없습니다." description="삭제됐거나 주소가 잘못됐습니다." action={<Link className="pg-doc-link" to="/documents">보호 문서 목록</Link>} />);
  if (query.isLoading) return shell(<PgSkeleton shape="kpi-table" rows={6} />);
  if (query.isError && (!query.data || !canRetainQueryData(query.error)))
    return query.error instanceof ApiError && query.error.status === 404 ? notFound : shell(
      <PgError message="보호 문서 상세 정보를 불러오지 못했습니다." error={query.error} onRetry={() => query.refetch()} />,
    );
  if (!query.data?.document) return notFound;

  const document = query.data.document;
  const stage = documentProtectionStage(document);
  const docKeywords = (keywords.data ?? []).filter((keyword) => keyword.doc_id === document.documentId);
  const approved = docKeywords.filter((keyword) => keyword.status === 'approved');
  const pendingKeywords = docKeywords.length - approved.length;
  const showId = document.documentId !== document.documentName && document.documentId !== document.documentName.replace(/\.[^.]+$/, '');
  const events = query.data.events;
  return shell(
    <>
      <PgPageHeader
        title={document.documentName}
        secondary={<DocumentProtectionBadge document={document} />}
        primary={<Button type="button" onClick={() => void navigate(`/documents?view=${encodeURIComponent(document.documentId)}&mode=original`)}><FileSearch aria-hidden="true" />본문 보기</Button>}
        refresh={<PgRefresh updatedAt={query.dataUpdatedAt} fetching={query.isFetching} failed={query.isError} onRefresh={() => query.refetch()} />}
        strip={document.status === 'INACTIVE' ? <PgStatusStrip level="unknown" word="보호 중지됨" facts={['구간 일치·승인 키워드 모두 탐지에 쓰지 않음', '등록 기록·원본은 그대로']} label="보호 상태" /> : undefined}
      />
      {query.isError && <PgError variant="inline" message="갱신 실패 · 아래는 마지막 성공 조회 결과입니다." onRetry={() => query.refetch()} />}
      <div className="pg-doc-detail-grid">
        <div className="pg-doc-detail-main">
          <section className="pg-card" aria-labelledby="pg-doc-info-title">
            <header className="pg-card-head"><h2 id="pg-doc-info-title" className="pg-card-title">문서 정보</h2></header>
            <div className="pg-card-body">
              <p className="pg-doc-stage-note">{stage.detail} 실제 차단·치환 결과는 아래 연결 이벤트에서 확인하세요.</p>
              <dl className="pg-doc-facts">
                {showId && <div><dt>문서 ID</dt><dd className="pg-doc-mono">{document.documentId}</dd></div>}
                {document.version && <div><dt>판</dt><dd>{document.version}</dd></div>}
                {document.classification && <div><dt>문서 분류</dt><dd>{uiLabel(document.classification)}</dd></div>}
                {document.owner && <div><dt>소유자</dt><dd>{document.owner}</dd></div>}
                {!!document.activeDetectors.length && <div><dt>사용 중인 탐지 방식</dt><dd>{document.activeDetectors.map((detector) => uiLabel(detector)).join(' · ')}</dd></div>}
                <div><dt>등록 시각</dt><dd>{formatDateTime(document.registeredAt)}</dd></div>
                {document.lastDetectedAt && <div><dt>최근 탐지 시각</dt><dd>{formatDateTime(document.lastDetectedAt)}</dd></div>}
              </dl>
            </div>
          </section>
          <section className="pg-card pg-doc-events" aria-labelledby="pg-doc-events-title">
            <header className="pg-card-head">
              <h2 id="pg-doc-events-title" className="pg-card-title">연결 이벤트 · 최근 30일</h2>
              <span className="pg-card-note"><PgCount total={events.total} unit="건" /></span>
            </header>
            {events.items.length ? (
              <EventsTable events={events.items} />
            ) : (
              <PgEmpty title="최근 30일 동안 이 문서와 일치한 보안 이벤트가 없습니다." />
            )}
            {events.totalPages > 1 && <div className="pg-card-foot"><PgPager page={events.page} totalPages={events.totalPages} onPage={(next) => setCursor({ documentId, page: next })} label="연결 이벤트 쪽 이동" /></div>}
          </section>
        </div>
        <aside className="pg-doc-detail-side" aria-label="문서 요약">
          <dl className="pg-doc-kpis" aria-label="연결된 탐지 기록 집계">
            <div><dt title="시험·시연 기록 제외 · 10/11 전 파일 재전송·같은 질문 재시도는 1건으로 접음(보안 현황·보호 문서 목록과 같은 기준)">최근 30일 연결 이벤트</dt><dd className="pg-num">{events.total}<small>건</small></dd></div>
            {document.modifiedPartialDetectionCount !== undefined && <div><dt>누적 문서 구간 일치 탐지</dt><dd className="pg-num">{document.modifiedPartialDetectionCount}<small>건</small></dd></div>}
          </dl>
          <section className="pg-card" aria-labelledby="pg-doc-kw-title">
            <header className="pg-card-head"><h2 id="pg-doc-kw-title" className="pg-card-title">등록된 키워드</h2>
              <Link className="pg-card-head-end pg-doc-link" to="/policies/keywords">키워드 관리<span aria-hidden="true"> ›</span></Link></header>
            <div className="pg-card-body pg-doc-kw">
              {keywords.isLoading ? <span className="pg-muted">확인 중</span>
                : keywords.isError ? <span className="pg-muted">키워드를 불러오지 못함</span>
                : approved.length ? <span className="pg-doc-kw-list">{approved.map((keyword) => <PgBadge key={keyword.id} variant="tag">{keyword.keyword}</PgBadge>)}</span>
                : <span className="pg-muted">승인된 키워드 없음</span>}
              {pendingKeywords > 0 && <Link className="pg-doc-link" to="/policies/keywords">승인 대기 {pendingKeywords}<span aria-hidden="true"> ›</span></Link>}
            </div>
          </section>
          <details className="pg-doc-disclosure">
            <summary>색인 · 기술 정보</summary>
            <dl className="pg-doc-facts">
              <div><dt>파일 형식</dt><dd>{document.fileType}</dd></div>
              {document.fileSize !== undefined && <div><dt>파일 크기</dt><dd>{formatBytes(document.fileSize)}</dd></div>}
              <div><dt>처리 상태</dt><dd>{uiLabel(document.processingStatus)}</dd></div>
              <div><dt>문서 구간 색인</dt><dd>{uiLabel(document.chunkIndexStatus)}</dd></div>
              <div><dt>색인 구간 수</dt><dd>{formatCount(document.chunkCount)}개</dd></div>
            </dl>
          </details>
          <details className="pg-doc-disclosure">
            <summary>본문 보기 원칙</summary>
            <p>[본문 보기]로 원본 모양과 탐지 기준 텍스트를 볼 수 있습니다. 열 때마다 감사 로그에 남고, 화면에 관리자 ID·열람 시각·열람 번호가 겹쳐 보입니다. 원본 모양은 파일 그대로라 개인정보 가림이 없습니다. 지문(해시) 값은 표시하지 않습니다.</p>
          </details>
        </aside>
      </div>
    </>,
  );
}
