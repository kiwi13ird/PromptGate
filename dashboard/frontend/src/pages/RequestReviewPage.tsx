import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, Navigate, useParams } from 'react-router-dom';
import { PageHeader } from '@/src/components/common';
import { demoToolsService } from '@/src/services/demoToolsService';
import { formatDateTime, formatCount } from '@/src/utils/format';
import { lookupMatches } from '@/src/utils/requestLookup';

// The route is behind ProtectedRoute. A request ID is a locator, never a credential.
export function RequestReviewPage() {
  const { requestId = '' } = useParams();
  return <RequestReviewContent key={requestId} requestId={requestId} />;
}
function RequestReviewContent({ requestId }: { requestId: string }) {
  const [expired, setExpired] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const valid = !!requestId && requestId.length <= 200;
  useEffect(() => { const timer = window.setTimeout(() => setExpired(true), 120000); return () => window.clearTimeout(timer); }, [attempt]);
  const restart = () => { setExpired(false); setAttempt(value => value + 1); };
  const query = useQuery({ queryKey: ['request-review', requestId, attempt], queryFn: ({ signal }) => demoToolsService.lookup('request', requestId, undefined, signal),
    enabled: valid, retry: false, refetchOnWindowFocus: false, refetchIntervalInBackground: false,
    refetchInterval: q => !expired && q.state.data?.status === 'WAITING' ? 1500 : false });
  const data = query.isError ? undefined : query.data;
  const matching = data ? lookupMatches(data, 'request', requestId) : false;
  const exact = matching && data?.status === 'FOUND' && data.count === 1 && data.items.length === 1;
  if (exact) return <Navigate to={`/events/${encodeURIComponent(data.items[0].event_id)}?view=compare`} replace />;
  const ambiguous = valid && !query.isError && !query.isPending && data?.status === 'AMBIGUOUS' && matching;
  return <div className="console-data-page request-review-page" data-ui="legacy"><PageHeader title="내 요청의 처리 근거" description="요청 번호와 정확히 연결된 사건만 확인합니다." />
    <section className="panel table-panel request-review-panel">
      <div className="panel-heading"><div><p className="eyebrow">요청 확인</p><h3>연결된 사건</h3></div>{ambiguous && data && <span>{formatCount(data.items.length)}건</span>}</div>
      <dl className="request-review-meta"><div><dt>요청 번호</dt><dd>{requestId}</dd></div></dl>
      {!valid ? <p className="request-review-status" role="alert">올바른 요청 번호가 필요합니다.</p> : query.isError ? <p className="request-review-status" role="status">사건 조회에 실패했습니다. <button type="button" onClick={restart}>다시 확인</button></p>
        : query.isPending ? <p className="request-review-status" role="status">해당 요청의 사건을 조회하고 있습니다.</p>
        : data && (!matching || data.status === 'FOUND') ? <p className="request-review-status" role="alert">조회 응답의 요청 번호가 일치하지 않아 자동으로 사건을 열지 않았습니다. <button type="button" onClick={restart}>다시 확인</button></p>
        : data?.status === 'AMBIGUOUS' ? <><p className="request-review-status" role="status">같은 요청 번호로 여러 사건이 기록돼 자동으로 선택하지 않습니다.</p>
          <div className="table-scroll"><table className="request-review-table"><thead><tr><th>발생 시각</th><th>대상 LLM</th><th>이벤트</th></tr></thead>
            <tbody>{data.items.map(item => <tr key={item.event_id}><td><time dateTime={item.occurred_at}>{formatDateTime(item.occurred_at)}</time></td><td>{item.target_llm}</td>
              <td><Link className="mono" to={`/events/${encodeURIComponent(item.event_id)}?view=compare`}>{item.event_id}</Link></td></tr>)}</tbody></table></div></>
        : <p className="request-review-status" role="status">{expired ? <>2분 동안 해당 사건이 확인되지 않았습니다. 프록시 경로와 요청 번호를 확인하세요. <button type="button" onClick={restart}>다시 2분 기다리기</button></> : '사건 저장을 기다리고 있습니다. 연결되면 본문 비교 화면으로 이동합니다.'}</p>}
      <p className="request-review-foot"><Link to="/events">보안 이벤트 목록으로</Link></p>
    </section></div>;
}
