import { Fragment, useEffect, useId, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ApiError } from '@/src/api/errors';
import { blockReasonText } from '@/src/api/gatewayAccessSchemas';
import { FileComparisonView } from '@/src/components/FileComparisonView';
import { askViewerKey, myRequestsService, OWN_REQUEST_LIMIT, type OwnEvidence, type OwnRequest, type OwnRequestFile, type ViewerKeyResult } from '@/src/services/myRequestsService';
import { copyText } from '@/src/utils/copyText';
import { formatDateTime, formatCount } from '@/src/utils/format';
import { uiLabel } from '@/src/utils/labels';
import { CLIENT_ID_MISSING_USER_REASON, hasReasonLabel, isAccessBlockReason, isNoResponseReason, isUninspectedReason, reasonLabel } from '@/src/utils/reasonLabels';
import '@/src/detection-ops.css';
import '@/src/my-requests-access.css';

// 내 요청 기록 (2026-10-09). 확장 프로그램 팝업의 '로그 확인'으로 여는 사용자용 페이지.
// 관리자 메뉴·로그인 없이, 이 브라우저가 보낸 요청 중 가려졌거나 막힌 것만 보여 준다.
const RESULT: Record<string, string> = { MASK: '마스킹', BLOCK: '차단', ALLOW: '허용' };
const kind = (item: OwnRequest) => item.attached_files?.length
  ? `${item.content_type === 'file' ? '파일' : '프롬프트'} + 파일 ${item.attached_files.length}`
  : item.content_type === 'file' ? '파일' : '프롬프트';

function entityTotals(item: OwnRequest) {
  const totals = new Map<string, number>();
  for (const member of [item, ...(item.attached_files ?? [])])
    for (const { entity_type, count } of member.entity_counts) totals.set(entity_type, (totals.get(entity_type) ?? 0) + count);
  return [...totals.entries()];
}

// 차단·가림 사유(2026-10-10): 차단·마스킹된 요청·파일만(백엔드 ownReasonCode와 같은 규칙).
// 칸 일부를 가린 뒤 검사가 끊겨 나머지가 원본으로 나간 마스킹 건도 사유를 보인다. 검사 없이 전송된(허용) 파일의 사유는 보이지 않는다
const showsReason = (action?: string | null) => action === 'BLOCK' || action === 'MASK';
// 접속 차단 안내(2026-10-12): 막힌 이유를 사용자에게 보인다. client_blocked는 관리자가 고른 사유(+ 공개를 고른 메모), client_id_missing은 고정 사유.
// 사유·메모가 오지 않으면(옛 서버 · 규칙에 사유 없음) 사유 줄 없이 기본 이름표만 보인다
interface AccessNoticeSource { reason_code?: string; reasons?: string[]; block_reasons?: string[]; user_memo?: string | null }
interface AccessNotice { reason: string | null; memo: string | null }
function accessNotice(source: AccessNoticeSource): AccessNotice | null {
  if (source.reason_code === 'client_id_missing') return { reason: CLIENT_ID_MISSING_USER_REASON, memo: null };
  if (source.reason_code !== 'client_blocked') return null;
  const codes = source.reasons?.length ? source.reasons : source.block_reasons;   // 서버는 block_reasons로 보낸다(10/12)
  const reason = codes?.length ? [...new Set(codes)].map(blockReasonText).join(' · ') : null;
  const memo = source.user_memo?.trim() || null;
  return reason || memo ? { reason, memo } : null;
}

function requestReasons(item: OwnRequest) {
  const labels = new Set<string>();
  for (const member of [item, ...(item.attached_files ?? [])]) {
    if (!showsReason(member.final_action)) continue;
    const notice = isAccessBlockReason(member.reason_code) ? accessNotice(member) : null;
    if (notice?.reason) labels.add(`접속 차단 · 사유: ${notice.reason}`);
    else if (hasReasonLabel(member.reason_code)) labels.add(reasonLabel(member.reason_code));
  }
  return [...labels];
}
// 요청·첨부 파일에 붙은 관리자 안내 메모(공개를 고른 것만 온다)
function requestMemos(item: OwnRequest) {
  const memos = new Set<string>();
  for (const member of [item, ...(item.attached_files ?? [])])
    if (showsReason(member.final_action)) { const memo = accessNotice(member)?.memo; if (memo) memos.add(memo); }
  return [...memos];
}

// 요청 ID(2026-10-12): 사용자가 관리자에게 문의할 때 알려 줄 번호. 값이 없으면(옛 서버) 줄을 그리지 않는다
const requestIdText = (value?: string | null) => value?.trim() || null;

// 펼친 상세 맨 위 한 줄: 요청 ID + 복사 버튼. 자동 복사가 막히면 직접 복사할 수 있게 칸을 열어 선택해 둔다
function RequestIdLine({ id }: { id: string }) {
  const [status, setStatus] = useState<'idle' | 'copying' | 'copied' | 'manual'>('idle');
  const field = useRef<HTMLInputElement>(null);
  const fieldId = useId();
  useEffect(() => { if (status === 'manual') { field.current?.focus(); field.current?.select(); } }, [status]);
  useEffect(() => {
    if (status !== 'copied') return;
    const timer = window.setTimeout(() => setStatus('idle'), 3000);
    return () => window.clearTimeout(timer);
  }, [status]);
  const copy = async () => {
    if (status === 'copying') return;
    setStatus('copying');
    setStatus(await copyText(id) ? 'copied' : 'manual');
  };
  return <div className="dops-my-reqid">
    <div className="dops-my-reqid-row">
      <span className="dops-my-reqid-label">요청 ID</span>
      <code className="dops-my-reqid-value">{id}</code>
      <button type="button" className="dops-my-reqid-copy" onClick={() => void copy()}>{status === 'copied' ? '복사됨' : '요청 ID 복사'}</button>
      <span role="status" className="sr-only">{status === 'copied' ? '요청 ID를 복사했습니다.' : ''}</span>
    </div>
    <p className="dops-my-reqid-hint">관리자에게 문의할 때 이 요청 ID를 알려 주십시오.</p>
    {status === 'manual' && <div className="dops-my-reqid-manual">
      <label htmlFor={fieldId}>자동 복사가 되지 않았습니다. 아래 칸의 요청 ID를 직접 복사하십시오.</label>
      <input id={fieldId} ref={field} readOnly value={id} />
    </div>}
  </div>;
}

// 첨부 파일이 묶음 대표와 다른 요청 ID를 가지면 제목(파일 이름) 옆에 작게 보인다
function EvidenceTitle({ title, filename, requestId }: { title: string; filename?: string; requestId?: string | null }) {
  return <h3>{title}{filename ? <span className="dops-my-filename"> · {filename}</span> : null}
    {requestId ? <small className="dops-my-reqid-inline">요청 ID <code>{requestId}</code></small> : null}</h3>;
}

function EvidenceBody({ evidence, title, listed, attachment = false, groupRequestId = null }: {
  evidence: OwnEvidence; title: string; listed?: OwnRequestFile; attachment?: boolean; groupRequestId?: string | null;
}) {
  const blocked = evidence.final_action === 'BLOCK';
  const ownId = attachment ? requestIdText(listed?.request_id) ?? requestIdText(evidence.request_id) : null;
  const fileId = ownId && ownId !== groupRequestId ? ownId : null;
  if (evidence.protected_document)
    return <section className="dops-my-evidence"><EvidenceTitle title={title} requestId={fileId} />
      <p className="dops-my-blocked" role="note">보호 문서와 일치하여 차단되었습니다. 상세 내용은 관리자만 확인할 수 있습니다.</p></section>;
  const reason = showsReason(evidence.final_action) ? evidence.reason_code : undefined;
  if (evidence.status !== 'AVAILABLE' && (isUninspectedReason(reason) || isNoResponseReason(reason)))
    return <section className="dops-my-evidence"><EvidenceTitle title={title} requestId={fileId} />
      <p className="evidence-notice">{isUninspectedReason(reason)
        ? '검사할 수 없는 파일이라 내용을 검사하지 않았습니다.'
        : '보안 검사가 제때 끝나지 않아 내용을 검사하지 못했습니다.'}</p></section>;
  // 접속 차단(2026-10-12): 관리자 설정으로 접속 단계에서 막아 내용을 검사하지 않았다. 사유(메모)는 관리자만 본다
  if (evidence.status !== 'AVAILABLE' && isAccessBlockReason(reason)) {
    // 사유·메모는 근거 응답에 있으면 그것을, 없으면 목록 항목의 것을 쓴다
    const notice = accessNotice({ reason_code: reason, reasons: evidence.reasons ?? evidence.block_reasons ?? listed?.reasons ?? listed?.block_reasons, user_memo: evidence.user_memo ?? listed?.user_memo });
    return <section className="dops-my-evidence"><EvidenceTitle title={title} requestId={fileId} />
      <p className="evidence-notice">관리자에 의해 LLM 사용이 제한되어 내용을 검사하지 않았습니다.</p>
      {notice?.reason ? <p className="dops-my-note">접속 차단 · 사유: {notice.reason}</p> : null}
      {notice?.memo ? <p className="dops-my-note">관리자 안내: {notice.memo}</p> : null}
    </section>;
  }
  if (evidence.status === 'NOT_RECORDED')
    return <section className="dops-my-evidence"><EvidenceTitle title={title} requestId={fileId} />
      <p className="evidence-notice">검사 기록이 아직 반영되지 않았습니다. 잠시 후 다시 확인하십시오.</p></section>;
  const comparison = evidence.file_comparison ?? evidence.prompt_comparison;
  if (evidence.status === 'TOO_LARGE' || !comparison)
    return <section className="dops-my-evidence"><EvidenceTitle title={title} requestId={fileId} /><p className="evidence-notice">내용이 길어 표시하지 않습니다.</p></section>;
  // 허용된 질문은 판정 기록에 '후'를 따로 남기지 않는다 - 가린 곳이 없으면 그대로 보낸 글만 보여 준다
  if (!evidence.file_comparison && evidence.final_action === 'ALLOW' && comparison.segments.every(segment => !segment.spans.length))
    return <section className="dops-my-evidence"><EvidenceTitle title={title} requestId={fileId} />
      <p className="dops-file-note">정상 처리되었습니다.</p>
      <p className="dops-my-plain" aria-label="전송 내용">{comparison.segments.map(segment => segment.before).join('\n')}</p></section>;
  return <section className="dops-my-evidence">
    <EvidenceTitle title={title} filename={evidence.filename} requestId={fileId} />
    <FileComparisonView comparison={comparison} variant={evidence.file_comparison ? 'file' : 'text'} blocked={blocked} />
  </section>;
}

function EvidenceFor({ viewerKey, item, title, attachment, groupRequestId }: {
  viewerKey: string; item: OwnRequestFile; title: string; attachment?: boolean; groupRequestId?: string | null;
}) {
  const evidence = useQuery({
    queryKey: ['my-request-evidence', item.event_id],
    queryFn: ({ signal }) => myRequestsService.evidence(viewerKey, item.event_id, signal),
    staleTime: 0,
  });
  if (evidence.isPending) return <output className="dops-my-loading">{title} 기록 불러오는 중</output>;
  if (evidence.isError) return <p className="dops-my-error" role="alert">{title} 기록을 불러올 수 없습니다.</p>;
  return <EvidenceBody evidence={evidence.data} title={title} listed={item} attachment={attachment} groupRequestId={groupRequestId} />;
}

function RequestRow({ viewerKey, item }: { viewerKey: string; item: OwnRequest }) {
  const [open, setOpen] = useState(false);
  const result = item.group_final_action ?? item.final_action;
  const totals = entityTotals(item);
  const protectedDocument = item.protected_document || (item.attached_files ?? []).some(file => file.protected_document);
  const reasons = requestReasons(item);
  const memos = requestMemos(item);
  const requestId = requestIdText(item.request_id);   // 첨부 파일 묶음은 대표(질문) 요청 ID 한 줄
  return <Fragment>
    <tr className={open ? 'dops-my-row open' : 'dops-my-row'}>
      <td className="dops-my-time">{formatDateTime(item.occurred_at)}</td>
      <td>{item.target_llm ?? '—'}</td>
      <td>{kind(item)}</td>
      <td><span className={`dops-my-result ${result.toLowerCase()}`}>{RESULT[result] ?? result}</span></td>
      <td><div className="dops-chips">
        {protectedDocument && <span className="dops-chip">보호 문서</span>}
        {reasons.map(label => <span key={label} className="dops-chip dops-chip--reason dops-chip--wrap">{label}</span>)}
        {totals.map(([type, count]) => <span key={type} className="dops-chip">{uiLabel(type)} {count}</span>)}
      </div>
      {memos.map(memo => <p key={memo} className="dops-my-note">관리자 안내: {memo}</p>)}</td>
      <td><button type="button" className="dops-my-toggle" aria-expanded={open} onClick={() => setOpen(value => !value)}>{open ? '닫기' : '상세 보기'}</button></td>
    </tr>
    {open && <tr className="dops-my-detail"><td colSpan={6}>
      {requestId && <RequestIdLine id={requestId} />}
      <EvidenceFor viewerKey={viewerKey} item={item} title={item.content_type === 'file' ? '파일' : '프롬프트'} />
      {(item.attached_files ?? []).map((file, index) =>
        <EvidenceFor key={file.event_id} viewerKey={viewerKey} item={file} title={`첨부 파일 ${index + 1}`} attachment groupRequestId={requestId} />)}
    </td></tr>}
  </Fragment>;
}

function RequestList({ viewerKey }: { viewerKey: string }) {
  const list = useQuery({
    queryKey: ['my-requests', viewerKey.slice(0, 8)],
    queryFn: ({ signal }) => myRequestsService.list(viewerKey, signal),
    staleTime: 0,
  });
  if (list.isPending) return <output className="dops-my-loading">기록 불러오는 중</output>;
  if (list.isError)
    return <div className="dops-my-panel" role="alert">
      <p>{list.error instanceof ApiError && list.error.code === 'UNAUTHORIZED'
        ? '열람 키를 확인할 수 없습니다. 확장 프로그램을 다시 불러온 후 재시도하십시오.'
        : '기록을 불러올 수 없습니다. 잠시 후 다시 시도하십시오.'}</p>
      <button type="button" onClick={() => void list.refetch()}>다시 시도</button>
    </div>;
  if (!list.data.items.length)
    return <div className="dops-my-panel"><p>최근 {list.data.window_days}일간 마스킹·차단된 요청이 없습니다.</p>
      <p className="dops-file-note">2026-10-09 이후 확장 프로그램 1.4.1에서 전송된 요청부터 표시됩니다.</p></div>;
  return <>
    <div className="dops-my-toolbar"><span>{formatCount(list.data.items.length)}건{list.data.truncated && <span className="dops-my-truncated"> · 최근 {formatCount(list.data.limit ?? OWN_REQUEST_LIMIT)}건까지만 표시(이전 기록 생략)</span>}</span>
      <button type="button" onClick={() => void list.refetch()} disabled={list.isFetching}>{list.isFetching ? '불러오는 중' : '새로 고침'}</button></div>
    <div className="table-scroll"><table className="dops-my-table">
      <thead><tr><th scope="col">전송 시각</th><th scope="col">서비스</th><th scope="col">유형</th><th scope="col">처리 결과</th><th scope="col">탐지 항목</th><th scope="col"><span className="sr-only">상세</span></th></tr></thead>
      <tbody>{list.data.items.map(item => <RequestRow key={item.event_id} viewerKey={viewerKey} item={item} />)}</tbody>
    </table></div>
  </>;
}

export function MyRequestsPage() {
  const [key, setKey] = useState<ViewerKeyResult | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let alive = true;
    setKey(null);
    void askViewerKey().then(result => { if (alive) setKey(result); });
    return () => { alive = false; };
  }, [attempt]);

  return <main id="main-content" className="dops-my">
    <header className="dops-my-head">
      <p className="dops-my-brand">PromptGate</p>
      <h1>내 요청 기록</h1>
      <p>최근 7일간 이 브라우저에서 전송된 요청 중 마스킹·차단된 요청을 최근 {OWN_REQUEST_LIMIT}건까지 표시합니다. 본인 요청만 표시됩니다.</p>
    </header>
    {key === null && <output className="dops-my-loading">확장 프로그램 확인 중</output>}
    {key?.status === 'NO_EXTENSION' && <div className="dops-my-panel" role="alert">
      <p><strong>확장 프로그램을 찾을 수 없습니다.</strong></p>
      <p>PromptGate 확장 프로그램(1.4.1 이상)이 설치된 Chrome에서 PromptGate 창의 &apos;내 요청 기록 보기&apos; 버튼으로 접속하십시오.</p>
      <button type="button" onClick={() => setAttempt(value => value + 1)}>다시 확인</button>
    </div>}
    {key?.status === 'NOT_READY' && <div className="dops-my-panel" role="alert">
      <p>확장 프로그램 준비 중입니다. 잠시 후 다시 확인하십시오.</p>
      <button type="button" onClick={() => setAttempt(value => value + 1)}>다시 확인</button>
    </div>}
    {key?.status === 'READY' && <>
      {!key.identityEnabled && <p className="dops-my-warning" role="note">
        확장 프로그램 설정의 &apos;클라이언트 식별 헤더 전송&apos;이 꺼져 있어 이후 요청은 기록되지 않습니다.</p>}
      <RequestList viewerKey={key.viewerKey} />
    </>}
  </main>;
}
