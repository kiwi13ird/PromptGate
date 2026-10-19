"""연결 중인 IP 표(2026-10-12): 대시보드 '트래픽 및 성능' 화면에 Gateway에 붙어 있는 IP를 보여 준다.

지표 전송기(gateway._publisher_snapshot)의 "clients" 칸에만 싣는다. 요청마다 찍는 지표 로그·이벤트 메타데이터에는
넣지 않고, IP 목록을 로그로 남기지 않는다. 프로세스 메모리에서만 센다(질문·파일 원문, 경로 없음).

항목 하나(대시보드 계약):
  ip            mitmproxy가 본 접속 IP. IPv4가 IPv6 형식(::ffff:a.b.c.d)으로 오면 IPv4로, 영역 표시(%eth0)는 뗀다.
  client_id     확장 프로그램 식별 헤더(x-llmsgw-client-id, client_identity가 읽는 것)의 마지막 값. 없거나 형식이 틀리면 null
  connections   지금 열려 있는 TCP 연결 수(mitmproxy client_connected/client_disconnected). 연결 id로 세서 음수가 되지 않는다
  inflight      처리 중인 요청 수 중 시작한 지 30초가 안 된 것(Gateway 지표와 같은 자리: 요청 시작 → response/error 훅)
  waiting       처리 중인 요청 수 중 시작한 지 30초 이상 된 것(대기 연결: 스트리밍 응답·긴 폴링처럼 오래 열려 있는 요청).
                inflight + waiting = 아직 끝나지 않은 요청 전체. 요청마다 시작 시각을 들고 있다가 표를 만들 때 나이로 가른다
  requests_5m   최근 300초에 보안 검사를 거친 요청 수(2026-10-15부터, 화면 '최근 5분 검사 요청').
                질문(프롬프트)·파일 업로드처럼 Gateway가 Detection을 부르거나 판정(차단·마스킹·허용·검사 응답 없음·
                검사 못 한 파일)을 한 요청만 센다(request_inspected, Gateway가 요청 하나에 한 번). 페이지 로딩·이미지·
                스크립트 같은 자산, 상태 확인·폴링, 접속 차단으로 막은 요청은 세지 않는다.
                10/14까지는 LLM 사이트로 간 HTTP 요청 전체를 셌다(10/15 운영 로그: 24시간 3,890건 중 검사·판정한 요청 24건)
  targets       최근 300초 LLM별 검사 요청 수(ChatGPT·Claude·Gemini, 보안 이벤트 targetLlm과 같은 이름), 많은 순 10개까지
  first_seen_at / last_seen_at   ISO-8601 UTC(…Z). last_seen = 마지막 연결·끊김·요청 시작·끝·검사

IP 안 확장 ID 묶음(by_client, 2026-10-15, snapshot(by_client=True)일 때만 - 대시보드가 metrics_ext를 알린 뒤):
  같은 IP 뒤에 확장 프로그램이 여럿이면(공유기 뒤 여러 PC·한 PC의 여러 브라우저) 위 칸들을 확장 ID별로 나눈 목록.
  항목 = {client_id, connections, inflight, waiting, requests_5m, targets, first_seen_at, last_seen_at}(IP 항목에서 ip를 뺀 모양).
  나누는 기준: 요청은 그 요청의 식별 헤더 값(없으면 그 연결에서 마지막으로 본 값), 연결은 그 연결로 온 요청에서 마지막으로 본 값.
  아직 식별 헤더가 붙은 요청이 없는 연결·헤더 없는 요청은 client_id null 묶음. 묶음 합 = IP 항목 값(최대 20묶음, 최근 활동 순).
  옛 칸(client_id = 그 IP에서 마지막으로 본 값, 숫자는 IP 합계)은 그대로다.

목록: 연결이 남아 있거나 마지막 활동이 600초 안인 IP, 최근 활동 순 200개까지. 그보다 오래 조용한 IP는 메모리에서 뺀다.
메모리 상한: IP 1000개(넘으면 연결·처리 중 요청이 없는 IP 중 가장 오래 조용한 것부터 뺀다), 최근 검사 요청 기록 50,000건
(넘으면 오래된 것부터 버린다: 아주 바쁠 때는 requests_5m이 실제보다 적게 나올 수 있다). IP마다 연결 id 집합은
실제로 열린 소켓 수만큼이라 운영체제 파일 수 상한을 넘지 않는다. 처리 중 요청의 시작 시각도 IP 항목에 달려 있어
항목이 빠지면 같이 빠지고, 끝나지 않은 요청이 쌓여도 실제로 열려 있는 요청 수를 넘지 않는다.
요청 훅은 이벤트 루프와 파일 업로드 작업 스레드(4개)에서 함께 부르므로 모든 상태는 잠금 안에서만 다룬다.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone

WINDOW_SECONDS = 300
IDLE_SECONDS = 600
LONG_INFLIGHT_SECONDS = 30   # 처리 중인 채로 이만큼 지나면 inflight 대신 waiting(대기 연결)으로 센다
MAX_LISTED = 200
MAX_TRACKED = 1000
MAX_RECENT_REQUESTS = 50_000
MAX_TARGETS = 10
MAX_BY_CLIENT = 20           # IP 항목 안 확장 ID 묶음 목록 상한(최근 활동 순)
MAX_SEEN_PER_IP = 50         # IP마다 확장 ID별 처음·마지막 활동 시각을 들고 있는 수(넘으면 가장 오래 조용한 것부터 뺀다)
IP_MAX_CHARS = 45
CLIENT_ID_MAX_CHARS = 80
TARGET_MAX_CHARS = 40
_CLIENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,%d}" % (CLIENT_ID_MAX_CHARS - 1))


def normalize_ip(value) -> str | None:
    """접속 IP 문자열 → 표에 쓸 형태. IP가 아니면 None(세지 않는다)."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    text = str(address)
    return text if len(text) <= IP_MAX_CHARS else None


def normalize_client_id(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _CLIENT_ID_RE.fullmatch(value) else None


def _target_name(value) -> str:
    if isinstance(value, str) and 0 < len(value) <= TARGET_MAX_CHARS and value.isprintable():
        return value
    return "Unknown"


def _top_targets(counts) -> dict:
    """LLM별 수, 많은 순(같으면 이름 순) MAX_TARGETS개."""
    if not counts:
        return {}
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_TARGETS])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class _Entry:
    __slots__ = ("ip", "gen", "conns", "active", "client_id", "first_seen", "last_seen", "seen")

    def __init__(self, ip: str, gen: int, now: float):
        self.ip = ip
        self.gen = gen              # 같은 IP가 빠졌다 다시 생기면 새 번호: 옛 요청의 끝이 새 항목을 줄이지 않게
        self.conns: dict = {}       # 열린 연결 id → 그 연결로 온 요청에서 마지막으로 본 확장 ID(아직 없으면 None)
        self.active: dict[int, tuple[float, str | None]] = {}   # 아직 끝나지 않은 요청: 요청 번호 → (시작 시각, 확장 ID)
        self.client_id: str | None = None
        self.first_seen = now
        self.last_seen = now
        self.seen: dict = {}        # 확장 ID(없으면 None) → [처음 활동, 마지막 활동] (by_client 묶음 시각)

    def busy(self) -> bool:
        return bool(self.conns) or bool(self.active)

    def split_active(self, now: float, long_seconds: float, key=...) -> tuple[int, int]:
        """(inflight, waiting): 시작한 지 long_seconds 미만 / 이상인 요청 수. key를 주면 그 확장 ID 묶음만."""
        starts = [started for started, owner in self.active.values() if key is ... or owner == key]
        waiting = sum(1 for started in starts if now - started >= long_seconds)
        return len(starts) - waiting, waiting

    def touch(self, key, now: float) -> None:
        times = self.seen.get(key)
        if times is not None:
            times[1] = now
            return
        if len(self.seen) >= MAX_SEEN_PER_IP:
            del self.seen[min(self.seen, key=lambda k: self.seen[k][1])]
        self.seen[key] = [now, now]

    def owner(self, client_id, conn_id):
        """요청의 확장 ID: 그 요청의 식별 헤더 값, 없으면 그 연결에서 마지막으로 본 값. 헤더 값이 있으면 연결에도 적는다."""
        if client_id is not None:
            if conn_id in self.conns:
                self.conns[conn_id] = client_id
            return client_id
        return self.conns.get(conn_id) if conn_id is not None else None


class ClientTracker:
    def __init__(self, *, clock=time.time, window_seconds=WINDOW_SECONDS, idle_seconds=IDLE_SECONDS,
                 long_inflight_seconds=LONG_INFLIGHT_SECONDS,
                 max_listed=MAX_LISTED, max_tracked=MAX_TRACKED, max_recent=MAX_RECENT_REQUESTS):
        self._clock = clock
        self._window = window_seconds
        self._idle = idle_seconds
        self._long_inflight = long_inflight_seconds
        self._max_listed = max_listed
        self._max_tracked = max_tracked
        self._max_recent = max_recent
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        self._recent: deque = deque()   # 검사한 요청: (검사를 마친 시각, ip, LLM 이름), 시각 순
        self._next_gen = 0
        self._next_request = 0

    # -- mitmproxy 연결 훅
    def connected(self, ip, conn_id) -> None:
        ip = normalize_ip(ip)
        if ip is None or conn_id is None:
            return
        with self._lock:
            now = self._clock()
            entry = self._entry(ip, now)
            entry.conns.setdefault(conn_id, None)
            entry.touch(entry.conns[conn_id], now)

    def disconnected(self, ip, conn_id) -> None:
        ip = normalize_ip(ip)
        if ip is None or conn_id is None:
            return
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None or conn_id not in entry.conns:
                return   # 모르는 연결(빠진 항목·스크립트 다시 읽기 전 연결·두 번 끊김): 아무것도 안 함
            now = self._clock()
            entry.touch(entry.conns.pop(conn_id), now)
            entry.last_seen = now

    # -- 요청 시작·끝(Gateway 지표와 같은 자리): 처리 중·대기 연결(inflight·waiting)만. 요청 수는 request_inspected
    def request_started(self, ip, client_id=None, conn_id=None):
        """처리 중 +1(시작 시각을 요청 번호로 들고 있음). 돌려준 표(ticket)를 request_finished에 넘긴다.
        표는 겉으로는 아무 값이다(Gateway는 그대로 보관했다 넘기기만 한다). IP가 아니면 None.
        2026-10-15: 여기서는 최근 요청 수에 넣지 않는다(자산·폴링까지 세던 것). 검사한 요청만 request_inspected가 센다.
        client_id(요청의 식별 헤더 값)·conn_id(mitmproxy 연결 id)는 by_client 묶음용(없어도 된다)."""
        ip = normalize_ip(ip)
        if ip is None:
            return None
        client_id = normalize_client_id(client_id)
        with self._lock:
            now = self._clock()
            entry = self._entry(ip, now)
            key = entry.owner(client_id, conn_id)
            self._next_request += 1
            entry.active[self._next_request] = (now, key)
            entry.touch(key, now)
            return (ip, entry.gen, self._next_request)

    def request_inspected(self, ip, target=None, client_id=None, conn_id=None) -> None:
        """보안 검사를 거친 요청 1건(2026-10-15): 최근 5분 검사 요청 수(requests_5m)·LLM별 수(targets)에 넣는다.
        Gateway가 요청 처리를 마칠 때 요청 하나에 한 번만 부른다(gateway._count_inspected_request).
        처리 중·연결 수와는 따로다(시작하지 않은 요청이라도 IP 항목을 만들고 활동으로 본다). IP가 아니면 세지 않는다."""
        ip = normalize_ip(ip)
        if ip is None:
            return
        target = _target_name(target)
        client_id = normalize_client_id(client_id)
        with self._lock:
            now = self._clock()
            entry = self._entry(ip, now)
            key = entry.owner(client_id, conn_id)
            entry.touch(key, now)
            self._prune_recent(now)
            while len(self._recent) >= self._max_recent:
                self._recent.popleft()
            self._recent.append((now, ip, target, key))

    def request_finished(self, ticket) -> None:
        if not isinstance(ticket, (tuple, list)) or len(ticket) != 3:
            return
        ip, gen, request_id = ticket
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None or entry.gen != gen:
                return
            now = self._clock()
            started = entry.active.pop(request_id, None)   # 모르는 번호·두 번 끝남: 아무것도 안 줄인다
            if started is not None:
                entry.touch(started[1], now)
            entry.last_seen = now

    def note_client_id(self, ip, client_id, conn_id=None) -> None:
        """확장 프로그램 식별 헤더 값(client_identity가 읽은 client_id). 헤더 없는 요청은 이전 값을 지우지 않는다.
        conn_id를 주면 그 연결도 이 확장 ID 묶음으로 센다(by_client)."""
        ip = normalize_ip(ip)
        client_id = normalize_client_id(client_id)
        if ip is None or client_id is None:
            return
        with self._lock:
            entry = self._entries.get(ip)
            if entry is not None:
                entry.client_id = client_id
                entry.owner(client_id, conn_id)
                entry.touch(client_id, self._clock())

    # -- 지표 전송기
    def snapshot(self, by_client: bool = False) -> list[dict]:
        """by_client=False: 10/12 계약 그대로(항목 9칸). True: 항목마다 by_client(확장 ID 묶음) 칸을 더한다."""
        with self._lock:
            now = self._clock()
            self._expire(now)
            self._prune_recent(now)
            totals: Counter = Counter()
            per_target: dict[str, Counter] = {}
            per_key: dict[tuple, Counter] = {}
            for _, ip, target, key in self._recent:
                if ip in self._entries:
                    totals[ip] += 1
                    per_target.setdefault(ip, Counter())[target] += 1
                    if by_client:
                        per_key.setdefault((ip, key), Counter())[target] += 1
            ordered = sorted(self._entries.values(), key=lambda e: (e.last_seen, e.gen), reverse=True)
            rows = []
            for entry in ordered[:self._max_listed]:
                inflight, waiting = entry.split_active(now, self._long_inflight)
                row = {
                    "ip": entry.ip,
                    "client_id": entry.client_id,
                    "connections": len(entry.conns),
                    "inflight": inflight,
                    "waiting": waiting,
                    "requests_5m": totals.get(entry.ip, 0),
                    "targets": _top_targets(per_target.get(entry.ip)),
                    "first_seen_at": _iso(entry.first_seen),
                    "last_seen_at": _iso(entry.last_seen),
                }
                if by_client:
                    row["by_client"] = self._groups(entry, now, per_key)
                rows.append(row)
            return rows

    def _groups(self, entry: _Entry, now: float, per_key: dict) -> list[dict]:
        """IP 항목 하나의 확장 ID 묶음(잠금 안). 지금 연결·처리 중·최근 5분 검사가 있는 묶음 + 10분 안에 활동한 확장 ID 묶음.
        client_id null 묶음(식별 헤더를 아직 못 본 연결·헤더 없는 요청)은 지금 연결·처리 중·최근 검사가 있을 때만 싣는다."""
        keys = set(entry.conns.values())
        keys.update(owner for _, owner in entry.active.values())
        keys.update(key for (ip, key) in per_key if ip == entry.ip)
        for key, (_, last) in list(entry.seen.items()):
            if now - last > self._idle and key not in keys:
                del entry.seen[key]   # 오래 조용한 묶음 시각은 버린다
            elif key is not None:
                keys.add(key)
        groups = []
        for key in keys:
            first, last = entry.seen.get(key, (entry.first_seen, entry.last_seen))
            inflight, waiting = entry.split_active(now, self._long_inflight, key)
            targets = per_key.get((entry.ip, key))
            groups.append({
                "client_id": key,
                "connections": sum(1 for owner in entry.conns.values() if owner == key),
                "inflight": inflight,
                "waiting": waiting,
                "requests_5m": sum(targets.values()) if targets else 0,
                "targets": _top_targets(targets),
                "first_seen_at": _iso(first),
                "last_seen_at": _iso(last),
                "_last": last,
            })
        groups.sort(key=lambda g: (g["_last"], g["client_id"] or ""), reverse=True)
        for group in groups:
            del group["_last"]
        return groups[:MAX_BY_CLIENT]

    def tracked_count(self) -> int:
        with self._lock:
            return len(self._entries)

    # -- 잠금 안에서만
    def _entry(self, ip: str, now: float) -> _Entry:
        entry = self._entries.get(ip)
        if entry is None:
            self._expire(now)
            if len(self._entries) >= self._max_tracked:
                oldest = min(self._entries.values(), key=lambda e: (e.busy(), e.last_seen))
                del self._entries[oldest.ip]
            self._next_gen += 1
            entry = _Entry(ip, self._next_gen, now)
            self._entries[ip] = entry
        entry.last_seen = now
        return entry

    def _expire(self, now: float) -> None:
        stale = [ip for ip, entry in self._entries.items()
                 if not entry.conns and now - entry.last_seen > self._idle]
        for ip in stale:
            del self._entries[ip]

    def _prune_recent(self, now: float) -> None:
        cutoff = now - self._window
        while self._recent and self._recent[0][0] <= cutoff:
            self._recent.popleft()
