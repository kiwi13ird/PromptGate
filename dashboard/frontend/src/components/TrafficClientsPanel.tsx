import { useMemo, useState } from 'react';
import { Pencil } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { TrafficClient, TrafficClients } from '@/src/types/traffic';
import { isBlockableClientId, remainingBadgeText, type AccessRule } from '@/src/services/gatewayAccessService';
import { PgBadge, PgCount, PgEmpty, PgError, PgPager, PgSkeleton } from '@/src/components/pg';
import '@/src/access-block.css';
import { formatCount } from '@/src/utils/format';

// 연결 중인 IP(2026-10-12). 트래픽 화면의 '요청 기록과 탐지 결과' 표 자리.
// Gateway가 10초마다 보내는 지표의 clients를 백엔드(GET /api/traffic/clients)에서 받아 그대로 보여 준다.
// 재설계 3c(설계 4.6·5.9): 9열 → 7열(대상[이름·IP·ID] · 상태[차단 중·남은 시간 배지] · 5분 요청 · 연결 · LLM · 마지막 활동 · 관리),
// '처음 확인'은 마지막 활동 칸의 title로. 표 자리 720px 이하에서는 카드(차단·해제 버튼이 화면 안).
const PAGE_SIZE = 20;

export function formatRelativeTime(value: string, now: number) {
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return '시각 미기록';
  const seconds = Math.max(0, Math.floor((now - at) / 1000));
  if (seconds < 10) return '방금';
  if (seconds < 60) return `${seconds}초 전`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}분 전`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}시간 전`;
  return `${Math.floor(hours / 24)}일 전`;
}

const exactTime = (value: string) =>
  Number.isFinite(Date.parse(value))
    ? new Intl.DateTimeFormat('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone: 'Asia/Seoul', timeZoneName: 'short' }).format(new Date(value))
    : '시각 미기록';
const clockTime = (value: string) => new Date(value).toLocaleTimeString('ko-KR', { timeZone: 'Asia/Seoul', hourCycle: 'h23' });
const windowLabel = (seconds: number) => (seconds % 60 === 0 ? `${seconds / 60}분` : `${seconds}초`);

export const isConnected = (client: TrafficClient) => client.connections > 0;

// 대기 연결: 30초 넘게 응답을 받고 있는 요청. 처리 중(30초 미만)과 따로 센다
const WAITING_HINT = '응답을 오래 받고 있는 연결(스트리밍 등) — 정상';
// 검사 요청(2026-10-15): Gateway requests_5m·targets = 최근 5분 보안 검사를 거친 요청만(10/14까지는 화면 로딩·자산까지 센 HTTP 요청 전체).
// 서버 응답 칸 이름(requests_5m·targets)은 그대로, 칸 이름·설명만 바꾼다
const INSPECTED_BASIS = '질문(프롬프트)·파일 업로드처럼 보안 검사를 거친 요청(차단·마스킹·허용, 검사 응답 없음·검사 못 한 파일 포함). 페이지 로딩·이미지 등 자산·상태 확인은 세지 않음';

/**
 * 접속 차단 관리(2026-10-12). 서버가 접속 차단 API에 답할 때만 넘어온다 - 없으면 '관리' 칸 없이 예전 표 그대로.
 * 별칭은 읽기 전용 관리자에게도 보이고, 차단·해제·별칭 수정 버튼은 canManage일 때만 보인다.
 */
export interface TrafficClientsManage {
  canManage: boolean;
  aliases: ReadonlyMap<string, string>;
  activeRuleOf: (clientId: string) => AccessRule | undefined;
  onBlock: (clientId: string) => void;
  onUnblock: (rule: AccessRule) => void;
  onEditAlias: (clientId: string) => void;
}

function ManageCell({ client, manage, rule }: { client: TrafficClient; manage: TrafficClientsManage; rule?: AccessRule }) {
  const clientId = client.clientId;
  if (!isBlockableClientId(clientId)) return <TableCell data-card="actions" className="pg-tr-ip-manage"><span className="pg-muted" title="확장 프로그램 ID가 없는 접속은 이 표에서 차단할 수 없습니다">ID 없음</span></TableCell>;
  const name = manage.aliases.get(clientId) ?? clientId;
  if (!manage.canManage) return <TableCell data-card="actions" data-empty="" className="pg-tr-ip-manage" />;
  return <TableCell data-card="actions" className="pg-tr-ip-manage">
    {rule
      ? <Button size="sm" variant="outline" aria-label={`${name} 차단 해제`} onClick={() => manage.onUnblock(rule)}>해제</Button>
      : <Button size="sm" variant="danger" aria-label={`${name} 차단`} onClick={() => manage.onBlock(clientId)}>차단</Button>}
  </TableCell>;
}

export function TrafficClientsPanel({ data, loading, error, onRetry, now = Date.now(), manage }: {
  data?: TrafficClients;
  loading: boolean;
  error?: unknown;
  onRetry: () => unknown;
  now?: number;
  manage?: TrafficClientsManage;
}) {
  const [page, setPage] = useState(1);
  // 같은 IP에 확장 프로그램이 여럿이면(공유기 뒤 여러 PC·한 PC의 여러 브라우저) 이웃한 줄로 모으고 줄마다 수를 보인다.
  // 서버 순서는 IP별 첫 등장 순으로 지킨다
  const clients = useMemo(() => {
    const list = data?.clients ?? [];
    const first = new Map<string, number>();
    list.forEach((client, index) => { if (!first.has(client.ip)) first.set(client.ip, index); });
    return list.map((client, index) => ({ client, index })).sort((a, b) => (first.get(a.client.ip)! - first.get(b.client.ip)!) || a.index - b.index).map(item => item.client);
  }, [data?.clients]);
  const sameIpCount = useMemo(() => {
    const counts = new Map<string, number>();
    // 확장 ID 없는 줄(식별 헤더를 아직 못 본 연결)은 확장 수에 넣지 않는다(Gateway 계약 3절, 2026-10-15)
    for (const client of clients) if (client.clientId) counts.set(client.ip, (counts.get(client.ip) ?? 0) + 1);
    return counts;
  }, [clients]);
  // 머리 숫자는 IP 수(시스템 상태 '연결 중인 IP'와 같은 셈). 한 IP에 확장 프로그램 줄이 여럿이어도 IP 하나(2026-10-15)
  const connectedIps = new Set(clients.filter(isConnected).map(client => client.ip));
  const connected = connectedIps.size;
  const recentOnly = new Set(clients.filter(client => !connectedIps.has(client.ip)).map(client => client.ip)).size;
  const totalPages = Math.max(1, Math.ceil(clients.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const rows = clients.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  const windowText = windowLabel(data?.windowSeconds ?? 300);
  return <section className="pg-card pg-tr-ips traffic-clients-panel" aria-labelledby="traffic-clients-title">
    <header className="pg-card-head">
      <h2 id="traffic-clients-title" className="pg-card-title">연결 중인 IP</h2>
      {data && <span className="pg-card-note pg-card-head-end traffic-clients-counts">연결 중 IP {connected} · 최근 활동 IP {recentOnly} · {data.receivedAt ? <time dateTime={data.receivedAt} title={exactTime(data.receivedAt)}>수신 {clockTime(data.receivedAt)}</time> : '수신 기록 없음'}</span>}
    </header>
    {error && data ? <p className="pg-stale pg-card-notice" role="status">갱신 실패 · 아래는 마지막으로 받은 연결 상태입니다.</p> : null}
    {data?.stale && data.receivedAt ? <p className="pg-stale pg-card-notice" role="status">Gateway 지표가 30초 넘게 들어오지 않아 연결 상태가 오래되었을 수 있습니다.</p> : null}
    {loading && !data ? <div className="pg-card-body"><PgSkeleton rows={3} /></div>
      : !data ? <div className="pg-card-body"><PgError variant="inline" message="연결 중인 IP를 불러오지 못했습니다." error={error} onRetry={() => void onRetry()} /></div>
      : !data.receivedAt ? <PgEmpty title="Gateway 지표를 아직 받지 못했습니다." description="Gateway가 지표를 보내면 연결 중인 IP가 표시됩니다." />
      : !clients.length ? <PgEmpty title={data.stale ? '마지막으로 받은 지표에 연결된 IP가 없습니다.' : '지금 연결된 IP가 없습니다.'} description="최근 10분 안에 요청한 IP도 없습니다." />
      : <>
        {clients.length > PAGE_SIZE && <div className="pg-card-count"><PgCount total={clients.length} /></div>}
        <Table card aria-label="연결 중인 IP" className={`pg-tr-ip-table${manage ? ' pg-tr-ip-table--manage' : ''}`}>
          <TableHeader><TableRow>
            <TableHead>대상</TableHead>
            <TableHead title="연결 중: 지금 열린 연결이 있음 · 최근 활동: 연결은 끊겼고 10분 안에 요청함 · 차단 중: 접속 차단 목록에 있음">상태</TableHead>
            <TableHead className="pg-num" title={INSPECTED_BASIS}>최근 {windowText} 검사 요청</TableHead>
            <TableHead className="pg-num" title="이 IP가 Gateway(프록시)에 열어 둔 연결 수. LLM 외 사이트·상태 확인 연결, 쉬고 있는 연결도 포함">열린 연결</TableHead>
            <TableHead title={`최근 ${windowText} 검사 요청의 LLM별 수`}>대상 LLM</TableHead>
            <TableHead title="마지막으로 연결·요청이 있었던 시각(화면 로딩·상태 확인 포함). 사람이 질문한 시각과 다를 수 있음">마지막 활동</TableHead>
            {manage && <TableHead className="pg-tr-ip-manage">관리</TableHead>}
          </TableRow></TableHeader>
          <TableBody>{rows.map((client, index) => {
            const rule = manage && client.clientId && isBlockableClientId(client.clientId) ? manage.activeRuleOf(client.clientId) : undefined;
            const alias = manage && client.clientId ? manage.aliases.get(client.clientId) : undefined;
            const sameIp = sameIpCount.get(client.ip) ?? 1;
            const editAlias = manage?.canManage && client.clientId && isBlockableClientId(client.clientId) ? () => manage.onEditAlias(client.clientId as string) : undefined;
            return <TableRow key={`${client.ip}-${client.clientId ?? ''}-${index}`} data-tone={rule ? 'block' : isConnected(client) ? 'allow' : 'neutral'}>
              {/* 카드 이름이 '연결 중인 IP'라 IP가 첫 줄(주 표시), 둘째 줄은 누가 쓰는지(별칭 · 확장 프로그램 ID) */}
              <TableCell data-card="title" className="pg-tr-ip-target"><div className="pg-tr-ip-who">
                <span className="pg-tr-ip-main">
                  <code className="pg-tr-ip-addr" title={client.ip}>{client.ip}</code>
                  {sameIp > 1 && client.clientId && <span className="pg-tr-ip-multi" title="같은 IP에서 여러 확장 프로그램이 접속함(공유기·같은 PC의 여러 브라우저 등)">이 IP 확장 {formatCount(sameIp)}개</span>}
                </span>
                <span className="pg-tr-ip-sub">
                  {alias && <span className="pg-tr-ip-alias" title={alias}>{alias}</span>}
                  {client.clientId
                    ? <code className="pg-tr-ip-id" title={client.clientId}>{client.clientId}</code>
                    : <span className="pg-tr-ip-noid" title="확장 프로그램 ID 없음">확장 ID 없음</span>}
                  {editAlias && <button type="button" className="acc-pencil" aria-label={`${alias ?? client.clientId} 별칭 수정`} title="별칭 수정" onClick={editAlias}><Pencil aria-hidden="true" /></button>}
                </span>
              </div></TableCell>
              <TableCell data-card="badge" className="pg-tr-ip-status">
                {rule && <PgBadge tone="block" variant="dot" title="Gateway가 이 확장 프로그램 ID의 요청을 막고 있습니다">차단 중 · {remainingBadgeText(rule, now)}</PgBadge>}
                <PgBadge tone={isConnected(client) ? 'allow' : 'neutral'} variant="dot">{isConnected(client) ? '연결 중' : '최근 활동'}</PgBadge>
                {client.inflight > 0 && <small>처리 중 {formatCount(client.inflight)}건</small>}
                {client.waiting > 0 && <small title={WAITING_HINT}>대기 연결 {formatCount(client.waiting)}개</small>}
              </TableCell>
              <TableCell data-card="info" data-label={`${windowText} 검사 요청`} className="pg-num">{client.requests5m.toLocaleString('ko-KR')}</TableCell>
              <TableCell data-card="info" data-label="연결" className="pg-num">{client.connections.toLocaleString('ko-KR')}</TableCell>
              <TableCell data-card="info" data-empty={client.targets.length ? undefined : ''}>{client.targets.length ? client.targets.map(({ llm, count }) => `${llm} ${count}`).join(' · ') : '-'}</TableCell>
              <TableCell data-card="info"><time dateTime={client.lastSeenAt} title={`${exactTime(client.lastSeenAt)} · 처음 확인 ${formatRelativeTime(client.firstSeenAt, now)}(${exactTime(client.firstSeenAt)})`}>{formatRelativeTime(client.lastSeenAt, now)}</time></TableCell>
              {manage && <ManageCell client={client} manage={manage} rule={rule} />}
            </TableRow>;
          })}</TableBody>
        </Table>
        <PgPager page={currentPage} totalPages={totalPages} onPage={setPage} label="연결 중인 IP 쪽 이동" />
        <p className="pg-card-foot pg-tr-ip-basis">검사 요청 = {INSPECTED_BASIS}</p>
      </>}
  </section>;
}
