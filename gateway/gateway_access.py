"""접속 차단(2026-10-12): 확장 프로그램 ID 차단·'확장 ID 없는 접속 차단'.

대시보드가 저장한 목록을 지표 전송(10초 주기) 응답의 gateway_access 칸으로 받아 요청마다 집행한다
(gateway_settings.py와 같은 통로·같은 구조, 칸은 따로).

문서(대시보드 → Gateway), 칸이 정확히 같을 것(모르는 칸·빠진 칸 거부):
  {"version": 1 이상, "revision": uuid(소문자), "updated_at": ISO(시간대 필수), "require_client_id": bool,
   "rules": [{"id": uuid(소문자), "client_id": ^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$, "expires_at": ISO|null,
              "reasons"?: [사유 코드 1~6개, 중복 없음], "user_memo"?: 글 1~200자|null}]}  (최대 500개)
  - reasons·user_memo(10/12 사유 안내)는 있어도 없어도 받는다(옛 대시보드). 그 밖의 칸은 지금처럼 거부(관리자 메모 memo 포함)
  - user_memo = 관리자가 '사용자에게 메모도 보이기'를 고른 규칙에만 온다. 차단 안내·접속 상태에 그대로 보인다
  - 칸 없음 = 대시보드가 아직 못 읽음 → 지금 목록 유지 / null = 저장된 목록 없음 → 비움(사본 삭제)
  - version·revision이 다르면 통째 교체(번호가 작아져도 따름) / 틀리면 문서 통째 거부, 지금 목록 유지, 거부 칸 보고
  - 만료는 Gateway 시계로 본다(대시보드가 꺼져도 제때 풀림). 문서에 이미 만료된 규칙이 있어도 거부하지 않는다
보고(Gateway → 대시보드, 지표 본문 access_applied): version·revision·source(NONE|CACHE|DASHBOARD)·applied_at·
  rejected(마지막으로 받은 문서가 틀렸으면 그 칸 경로, 맞으면 null)·active_rules·require_client_id·denied_5m.
  대시보드에서 칸을 받은 뒤(또는 시작 때 사본을 읽었으면)만 싣고, 실은 전송이 400이면 뺀다.

예외: llm-gateway.local(health·접속 상태·내 기록 중계·검토 파일), 접속 IP 127.0.0.0/8·::1. 막은 요청은 Detection을 부르지 않는다.
차단 안내(10/12 사유 안내): 403 안내 페이지·JSON에 사유 이름표('사유: 보안 조사 중 · 관리자 요청')와 user_memo('관리자 안내: …')를
  싣는다. 사유가 없는 규칙(옛 대시보드)은 사유 줄 없음. 확장 ID 없는 접속은 '사유: 확장 프로그램 식별 정보 없음'.
접속 상태(GET http://llm-gateway.local/__llmsgw/access-status, access_status): 확장 프로그램이 이 브라우저의 차단 여부·사유를
  묻는다. 확장 ID = 확장 프로그램이 직접 붙인 X-LLMSGW-Client-Id(식별 머리와 같은 이름·형식) → 없으면 같은 연결에서 본 ID.
  그 ID의 규칙만 답한다(다른 확장 ID의 규칙·관리자 메모는 싣지 않음). 실제 집행과 같은 판단(접속 IP 예외 포함).
목록을 못 읽으면(사본 손상·다른 대시보드 사본) 풀린 상태로 돌고 경고 로그를 남긴다(fail-open).
쓰는 쪽은 지표 작업 스레드(offer), 읽는 쪽(요청 훅)은 current()로 참조 하나만 읽는다(AccessList는 바꾸지 않는다).
로그에는 확장 ID·IP를 남기지 않는다(규칙 번호 앞 8자·횟수만).
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mitmproxy import http

from client_identity import IDENTITY_HEADERS
from gateway_client_tracker import normalize_client_id, normalize_ip

MAX_SAFE_INTEGER = 2 ** 53 - 1
MAX_RULES = 500
DOCUMENT_FIELDS = ("version", "revision", "updated_at", "require_client_id", "rules")
RULE_FIELDS = ("id", "client_id", "expires_at")
RULE_OPTIONAL_FIELDS = ("reasons", "user_memo")   # 10/12 사유 안내: 없어도 받는다(옛 대시보드)
SOURCES = ("NONE", "CACHE", "DASHBOARD")
# 사유 이름표(대시보드 gateway-access.mjs BLOCK_REASONS와 같은 코드·이름)
REASON_LABELS = {
    "LEAK_DOC_REPEAT": "기밀 문서 반복 유출 시도",
    "PII_REPEAT": "개인정보 반복 입력",
    "INVESTIGATION": "보안 조사 중",
    "LEAVE": "퇴사·휴직 예정",
    "ADMIN_REQUEST": "관리자 요청",
    "OTHER": "기타",
}
MISSING_REASON = ("CLIENT_ID_MISSING", "확장 프로그램 식별 정보 없음")   # 확장 ID 없는 접속(고정 사유)
USER_MEMO_MAX_CHARS = 200      # 대시보드 MEMO_MAX_CHARS(코드 포인트 수, Python len과 같음)
STATUS_PATH = "/__llmsgw/access-status"
DOCUMENT_FIELD = "gateway_access"     # 문서 전체 모양이 틀렸을 때 거부 칸 이름

REASON_BLOCKED = "client_blocked"
REASON_MISSING = "client_id_missing"
USER_MESSAGE = "관리자에 의해 LLM 사용이 제한되었습니다."
EXEMPT_HOSTS = frozenset({"llm-gateway.local"})
CLIENT_ID_HEADER = next(name for name, field in IDENTITY_HEADERS.items() if field == "client_id")

EVENT_INTERVAL_SECONDS = 600          # 같은 (규칙 또는 'missing', 확장 ID 또는 IP) 보안 이벤트는 10분에 1건
EVENT_MAX_KEYS = 4096
DENIED_WINDOW_SECONDS = 300           # denied_5m
CONNECTION_MAX_ENTRIES = 8192
KST = timezone(timedelta(hours=9))

REVISION_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$")
FIELD_RE = re.compile(r"^[a-z0-9_.]{1,100}$")
# 대시보드는 메모를 한 줄로 맞추고 제어 문자를 받지 않는다. 짝 없는 서로게이트는 UTF-8로 못 쓰므로(안내 페이지가 깨짐) 거부
_MEMO_BAD_RE = re.compile(r"[\x00-\x1f\x7f\ud800-\udfff]")
# 대시보드는 toISOString() 값(2026-10-12T05:00:00.000Z)을 준다. 시간대 없는 값은 받지 않는다
_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})$")


class AccessError(ValueError):
    """field = 틀린 칸 경로(rules.3.client_id 등). 보고의 rejected에 그대로 싣는다."""

    def __init__(self, field: str):
        super().__init__(field)
        self.field = field if FIELD_RE.fullmatch(field or "") else DOCUMENT_FIELD


@dataclass(frozen=True)
class AccessRule:
    id: str
    client_id: str
    expires_at: str | None        # 받은 그대로(사본에 다시 쓴다)
    expires_ts: float | None      # epoch 초. None = 영구
    reasons: tuple | None = None  # 사유 코드(받은 순서). None = 칸 없음(옛 대시보드)
    user_memo: str | None = None  # 사용자에게 보이는 관리자 안내(관리자가 고른 경우만)

    def active(self, now: float) -> bool:
        return self.expires_ts is None or now < self.expires_ts

    @property
    def number(self) -> str:
        """차단 번호: 규칙 번호 앞 8자(사용자 안내·로그)."""
        return self.id[:8]

    def document(self) -> dict:
        item = {"id": self.id, "client_id": self.client_id, "expires_at": self.expires_at}
        if self.reasons is not None:
            item["reasons"] = list(self.reasons)
        if self.user_memo is not None:
            item["user_memo"] = self.user_memo
        return item


@dataclass(frozen=True, eq=False)
class AccessList:
    version: int | None = None
    revision: str | None = None
    updated_at: str | None = None
    require_client_id: bool = False
    rules: tuple = ()
    by_client: dict | None = None     # 확장 ID → 규칙 묶음(만든 뒤 바꾸지 않는다)
    source: str = "NONE"
    applied_at: str | None = None

    @property
    def key(self) -> tuple:
        return (self.version, self.revision)

    @property
    def enforcing(self) -> bool:
        """규칙도 없고 '확장 ID 없는 접속 차단'도 꺼져 있으면 요청마다 볼 것이 없다."""
        return bool(self.rules) or self.require_client_id

    def match(self, client_id: str | None, now: float) -> AccessRule | None:
        """확장 ID에 맞는 적용 중 규칙. 여럿이면 영구 → 늦게 풀리는 것."""
        if not client_id or not self.by_client:
            return None
        best = None
        for rule in self.by_client.get(client_id, ()):
            if not rule.active(now):
                continue
            if best is None or (best.expires_ts is not None
                                and (rule.expires_ts is None or rule.expires_ts > best.expires_ts)):
                best = rule
        return best

    def active_count(self, now: float) -> int:
        return sum(1 for rule in self.rules if rule.active(now))

    def document(self) -> dict:
        """대시보드 문서 모양. 디스크 사본에 쓴다."""
        return {"version": self.version, "revision": self.revision, "updated_at": self.updated_at,
                "require_client_id": self.require_client_id,
                "rules": [r.document() for r in self.rules]}


EMPTY = AccessList()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ------------------------------------------------------------------ 검증

def _exact(value, fields, path, optional=()):
    """필수 칸이 모두 있고, 필수·선택 칸 밖의 칸이 없을 것."""
    if (not isinstance(value, dict) or any(key not in value for key in fields)
            or any(key not in fields and key not in optional for key in value)):
        raise AccessError(path)
    return value


def _reasons(value, path) -> tuple:
    if (not isinstance(value, list) or not 1 <= len(value) <= len(REASON_LABELS)
            or any(not isinstance(code, str) or code not in REASON_LABELS for code in value)
            or len(set(value)) != len(value)):
        raise AccessError(path)
    return tuple(value)


def _user_memo(value, path) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= USER_MEMO_MAX_CHARS or _MEMO_BAD_RE.search(value):
        raise AccessError(path)
    return value


def iso_timestamp(value) -> float | None:
    """ISO-8601(시간대 필수) → epoch 초. 형식·값이 틀리면 None."""
    if not isinstance(value, str) or len(value) > 50:
        return None
    match = _ISO_RE.fullmatch(value)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    try:
        if zone == "Z":
            tz = timezone.utc
        else:
            sign = 1 if zone[0] == "+" else -1
            tz = timezone(sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
        micro = int((fraction or "0").ljust(6, "0")[:6])
        moment = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second or 0), micro, tz)
    except ValueError:
        return None
    return moment.timestamp()


def parse_access(document, *, source: str = "DASHBOARD", applied_at: str | None = None) -> AccessList:
    """gateway_access 문서 → AccessList. 틀리면 AccessError(칸 경로). 칸 모양을 먼저 모두 본 뒤 값을 본다."""
    doc = _exact(document, DOCUMENT_FIELDS, DOCUMENT_FIELD)
    raw_rules = doc["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise AccessError("rules")
    for index, raw in enumerate(raw_rules):
        _exact(raw, RULE_FIELDS, f"rules.{index}", RULE_OPTIONAL_FIELDS)
    version = doc["version"]
    if type(version) is not int or not 1 <= version <= MAX_SAFE_INTEGER:
        raise AccessError("version")
    revision = doc["revision"]
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise AccessError("revision")
    updated_at = doc["updated_at"]
    if iso_timestamp(updated_at) is None:
        raise AccessError("updated_at")
    if type(doc["require_client_id"]) is not bool:
        raise AccessError("require_client_id")
    rules, seen, by_client = [], set(), {}
    for index, raw in enumerate(raw_rules):
        rule_id = raw["id"]
        if not isinstance(rule_id, str) or not REVISION_RE.fullmatch(rule_id) or rule_id in seen:
            raise AccessError(f"rules.{index}.id")
        client_id = raw["client_id"]
        if not isinstance(client_id, str) or not CLIENT_ID_RE.fullmatch(client_id):
            raise AccessError(f"rules.{index}.client_id")
        expires_at = raw["expires_at"]
        expires_ts = None
        if expires_at is not None:
            expires_ts = iso_timestamp(expires_at)
            if expires_ts is None:
                raise AccessError(f"rules.{index}.expires_at")
        reasons = _reasons(raw["reasons"], f"rules.{index}.reasons") if "reasons" in raw else None
        user_memo = _user_memo(raw.get("user_memo"), f"rules.{index}.user_memo")
        seen.add(rule_id)
        rule = AccessRule(rule_id, client_id, expires_at, expires_ts, reasons, user_memo)
        rules.append(rule)
        by_client[client_id] = by_client.get(client_id, ()) + (rule,)
    return AccessList(version=version, revision=revision, updated_at=updated_at,
                      require_client_id=doc["require_client_id"], rules=tuple(rules), by_client=by_client,
                      source=source, applied_at=applied_at or _now_iso())


def _rejected_version(document):
    version = document.get("version") if isinstance(document, dict) else None
    return version if type(version) is int else None


def cache_path_from_env(default_dir, environ=None) -> Path:
    env = os.environ if environ is None else environ
    configured = (env.get("GATEWAY_ACCESS_CACHE_PATH") or "").strip()
    return Path(configured) if configured else Path(default_dir) / "var" / "gateway-access.json"


# ------------------------------------------------------------------ 판단 (요청마다)

@dataclass(frozen=True)
class AccessDecision:
    reason_code: str                  # client_blocked | client_id_missing
    rule: AccessRule | None = None
    client_id: str | None = None


def exempt_peer(peer_ip) -> bool:
    """접속 IP가 127.0.0.0/8·::1(같은 서버의 배포 점검)이면 막지 않는다."""
    if not isinstance(peer_ip, str) or not peer_ip:
        return False
    try:
        address = ipaddress.ip_address(peer_ip.split("%", 1)[0])
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def top_level_navigation(method, headers) -> bool:
    """주소창·새로 고침으로 여는 페이지(GET·HEAD, Sec-Fetch-Mode navigate + Sec-Fetch-Dest document).
    확장 프로그램 식별 규칙(declarativeNetRequest, resourceTypes 지정 없음)은 main_frame 요청에 머리를 붙이지 않는다."""
    return (str(method or "").upper() in {"GET", "HEAD"}
            and str(headers.get("sec-fetch-mode", "")).lower() == "navigate"
            and str(headers.get("sec-fetch-dest", "")).lower() == "document")


def cors_preflight(method, headers) -> bool:
    return str(method or "").upper() == "OPTIONS" and bool(headers.get("access-control-request-method"))


def decide(access: AccessList, client_id: str | None, *, navigation: bool, preflight: bool,
           now: float) -> AccessDecision | None:
    """None = 통과. client_id는 형식이 맞는 값만(없으면 None).
    '확장 ID 없는 접속 차단'은 화면 이동(최상위 페이지)·CORS 사전 확인에는 쓰지 않는다: 둘 다 확장 프로그램이 머리를
    붙일 수 없는 요청이고 내용이 없다(질문·파일은 그 뒤 fetch 요청에서 막힌다)."""
    if client_id:
        rule = access.match(client_id, now)
        return AccessDecision(REASON_BLOCKED, rule, client_id) if rule else None
    if access.require_client_id and not navigation and not preflight:
        return AccessDecision(REASON_MISSING)
    return None


class ConnectionClientIds:
    """연결(mitmproxy client 연결 id) → 그 연결에서 마지막으로 본 확장 ID.
    최상위 페이지 요청에는 식별 머리가 없어서, 같은 연결의 앞 요청에서 본 ID로 차단 안내 화면을 보여 준다.
    연결 하나는 브라우저 하나라 NAT로 섞이지 않는다. client_disconnected에서 지운다."""

    def __init__(self, max_entries: int = CONNECTION_MAX_ENTRIES):
        self._max = max_entries
        self._ids: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def remember(self, conn_id, client_id) -> None:
        if conn_id is None or not client_id:
            return
        with self._lock:
            if self._ids.get(conn_id) != client_id:
                self._ids[conn_id] = client_id
            self._ids.move_to_end(conn_id)
            while len(self._ids) > self._max:
                self._ids.popitem(last=False)

    def get(self, conn_id) -> str | None:
        if conn_id is None:
            return None
        with self._lock:
            return self._ids.get(conn_id)

    def forget(self, conn_id) -> None:
        if conn_id is None:
            return
        with self._lock:
            self._ids.pop(conn_id, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._ids)


# ------------------------------------------------------------------ 응답·기록

@dataclass
class AccessBlockResult:
    """대시보드 이벤트 변환(dashboard_event_mapper)에 넘기는 판정. Detection 판정이 아니다(검사 안 함)."""
    request_id: str
    reason_code: str
    access_rule_id: str | None = None
    blocked: bool = True
    action: str = "block"
    decided_by: str = "none"
    degraded: bool = False
    http_status: int = 403
    user_message: str = USER_MESSAGE
    reason: str = "gateway: access blocked"


def release_label(rule: AccessRule | None) -> str:
    if rule is None or rule.expires_ts is None:
        return "관리자 해제 시"
    return datetime.fromtimestamp(rule.expires_ts, KST).strftime("%m/%d %H:%M")


_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM 사용 제한</title>
<style>
body{{margin:0;font-family:system-ui,-apple-system,"Malgun Gothic","Apple SD Gothic Neo",sans-serif;background:#f4f5f7;color:#1f2328}}
main{{max-width:440px;margin:12vh auto 0;padding:28px 24px;background:#fff;border:1px solid #d0d7de;border-radius:10px}}
h1{{margin:0 0 10px;font-size:20px}}p{{margin:0 0 18px;line-height:1.6}}
.why{{margin:0 0 18px;padding:10px 14px;background:#fff5f5;border:1px solid #f0c4c4;border-radius:8px;font-size:14px}}
.why p{{margin:0;word-break:keep-all;overflow-wrap:anywhere}}.why p+p{{margin-top:4px}}
dl{{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;margin:0;font-size:14px}}
dt{{color:#59636e}}dd{{margin:0;font-family:ui-monospace,Consolas,monospace;word-break:break-all}}
@media (prefers-color-scheme:dark){{body{{background:#0d1117;color:#e6edf3}}main{{background:#161b22;border-color:#30363d}}dt{{color:#9198a1}}.why{{background:#2b1618;border-color:#6e3134}}}}
@media (max-width:480px){{main{{margin:24px 16px 0}}}}
</style></head>
<body><main><h1>LLM 사용 제한</h1><p>{message}</p>{notes}<dl>{rows}</dl></main></body></html>
"""


def decision_reasons(decision: AccessDecision | None) -> list[tuple[str, str]]:
    """사용자에게 보일 사유 (코드, 이름표). 확장 ID 없음 = 고정 사유, 사유 칸이 없는 규칙(옛 대시보드) = 없음."""
    if decision is None:
        return []
    if decision.reason_code == REASON_MISSING:
        return [MISSING_REASON]
    if decision.rule is None or not decision.rule.reasons:
        return []
    return [(code, REASON_LABELS[code]) for code in decision.rule.reasons]


def reason_items(reasons) -> list[dict]:
    return [{"code": code, "label": label} for code, label in reasons]


def _user_notes(reasons, memo) -> list[str]:
    notes = []
    if reasons:
        notes.append("사유: " + " · ".join(label for _, label in reasons))
    if memo:
        notes.append("관리자 안내: " + memo)
    return notes


def block_response(decision: AccessDecision, request_id: str, *, navigate: bool) -> http.Response:
    """화면 이동(Sec-Fetch-Mode: navigate) → 403 안내 페이지, 그 밖 → 403 JSON.
    사유 이름표·user_memo(대시보드가 보낸 경우만)를 싣는다. 관리자 메모(memo)는 문서에 오지 않는다."""
    reasons = decision_reasons(decision)
    memo = decision.rule.user_memo if decision.rule is not None else None
    if navigate:
        notes = "".join(f"<p>{html.escape(note)}</p>" for note in _user_notes(reasons, memo))
        rows = []
        if decision.rule is not None:
            rows.append(("차단 번호", decision.rule.number))
        rows.append(("해제 예정", release_label(decision.rule)))
        rows.append(("요청 번호", request_id))
        body = _PAGE.format(message=html.escape(USER_MESSAGE),
                            notes=f'<div class="why">{notes}</div>' if notes else "",
                            rows="".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd>" for k, v in rows))
        return http.Response.make(403, body.encode("utf-8"), {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
    error = {"type": "access_blocked", "message": USER_MESSAGE, "reason_code": decision.reason_code,
             "request_id": request_id}
    if reasons:                       # 사유가 없는 규칙(옛 대시보드)은 지금과 같은 모양
        error["reasons"] = reason_items(reasons)
    if memo:
        error["user_memo"] = memo
    return http.Response.make(403, json.dumps({"error": error}, ensure_ascii=False).encode("utf-8"), {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
    })


# ------------------------------------------------------------------ 접속 상태 (확장 프로그램이 묻는다)

def _iso_z(ts: float) -> str | None:
    """epoch 초 → 2026-10-12T06:00:00.000Z. 나타낼 수 없는 값(9999년 넘음 등)은 None."""
    try:
        moment = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ts)
    except (OverflowError, ValueError):
        return None
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def access_status(access: AccessList, client_id: str | None, *, exempt: bool, now: float) -> dict:
    """GET /__llmsgw/access-status 본문 = 이 확장 ID의 질문·파일 요청이 지금 막히는지(요청마다 하는 decide와 같은 판단).
    client_id는 형식이 맞는 값만(없으면 None). exempt = 접속 IP 예외(127.0.0.0/8·::1, 실제로 막지 않음).
    이 확장 ID에 걸린 규칙 하나만 싣는다: 다른 확장 ID의 규칙·관리자 메모는 없고, user_memo는 대시보드가 보낸 경우만."""
    decision = None if exempt else decide(access, client_id, navigation=False, preflight=False, now=now)
    rule = decision.rule if decision is not None else None
    return {
        "blocked": decision is not None,
        "reason_code": decision.reason_code if decision is not None else None,
        "reasons": reason_items(decision_reasons(decision)),
        "user_memo": rule.user_memo if rule is not None else None,
        "until": _iso_z(rule.expires_ts) if rule is not None and rule.expires_ts is not None else None,
        "block_id": rule.number if rule is not None else None,
        "require_client_id": access.require_client_id,
        "client_id_present": bool(client_id),
        "checked_at": _iso_z(now),
    }


def status_response(payload: dict, status: int = 200, extra: dict | None = None) -> http.Response:
    """접속 상태 응답. CORS 머리는 붙이지 않는다(웹 페이지는 못 읽음, 확장 프로그램은 host_permissions로 읽는다)."""
    return http.Response.make(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        **(extra or {}),
    })


class EventLimiter:
    """같은 열쇠의 보안 이벤트는 interval초에 1건. 열쇠는 메모리 안에서만(최대 max_keys개, 오래된 것부터 지움)."""

    def __init__(self, interval: float = EVENT_INTERVAL_SECONDS, max_keys: int = EVENT_MAX_KEYS, clock=time.time):
        self._interval = interval
        self._max = max_keys
        self._clock = clock
        self._seen: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key) -> bool:
        with self._lock:
            now = self._clock()
            while self._seen:
                oldest = next(iter(self._seen.values()))
                if len(self._seen) < self._max and now - oldest < self._interval:
                    break
                self._seen.popitem(last=False)
            last = self._seen.get(key)
            if last is not None and now - last < self._interval:
                return False
            self._seen[key] = now
            self._seen.move_to_end(key)
            return True


class DeniedCounter:
    """최근 window초에 막은 요청 수(초 단위 칸)."""

    def __init__(self, window: int = DENIED_WINDOW_SECONDS, clock=time.time):
        self._window = window
        self._clock = clock
        self._buckets: deque = deque()   # [초, 수]
        self._lock = threading.Lock()

    def _prune(self, now_second: int) -> None:
        while self._buckets and self._buckets[0][0] <= now_second - self._window:
            self._buckets.popleft()

    def add(self) -> None:
        with self._lock:
            second = int(self._clock())
            self._prune(second)
            if self._buckets and self._buckets[-1][0] == second:
                self._buckets[-1][1] += 1
            else:
                self._buckets.append([second, 1])

    def count(self) -> int:
        with self._lock:
            self._prune(int(self._clock()))
            return sum(count for _, count in self._buckets)


# ------------------------------------------------------------------ 보관

class AccessHolder:
    """지표 응답으로 받은 목록을 들고 있다. 쓰기는 offer(지표 작업 스레드), 읽기는 current()."""

    _REJECT_LOG_KEYS = 64

    def __init__(self, *, cache_path=None, metrics_url: str | None = None, logger=print, clock=time.time):
        self._cache_path = Path(cache_path) if cache_path else None
        # 사본은 같은 대시보드 주소에서 받은 것만 쓴다(가짜 대시보드로 시험한 사본이 운영 재시작에 쓰이지 않게)
        self._url_hash = hashlib.sha256(metrics_url.encode("utf-8")).hexdigest() if metrics_url else None
        self._logger = logger
        self._clock = clock
        self._lock = threading.Lock()
        self._current = EMPTY
        self._rejected: str | None = None
        self._rejected_logged: list[tuple] = []
        self._include_report = False     # 다음 지표에 access_applied를 실음(칸을 받았거나 사본을 읽음)
        self._last_report_sent = False
        self._on_change = None
        self._denied = DeniedCounter(clock=clock)
        self._events = EventLimiter(clock=clock)
        self._load_cache()
        current = self._current
        self._log(f"[ACCESS] source={current.source} version={current.version if current.version else '-'} "
                  f"rules={len(current.rules)} require_client_id={str(current.require_client_id).lower()}")

    # -- 읽기 (잠금 없음, 참조 하나)
    def current(self) -> AccessList:
        return self._current

    def now(self) -> float:
        return self._clock()

    def set_on_change(self, callback) -> None:
        self._on_change = callback

    def _log(self, message: str) -> None:
        try:
            self._logger(message)
        except Exception:
            pass

    # -- 막은 요청
    def note_denied(self) -> None:
        self._denied.add()

    def allow_event(self, key) -> bool:
        return self._events.allow(key)

    # -- 디스크 사본
    def _load_cache(self) -> None:
        path = self._cache_path
        if path is None or self._url_hash is None:
            return
        try:
            if not path.exists():
                return
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("metrics_url_sha256") != self._url_hash:
                self._log("[ACCESS] WARNING cache ignored; running without access rules reason=other_dashboard")
                return
            access = parse_access(raw.get("document"), source="CACHE")
        except AccessError as exc:
            self._log(f"[ACCESS] WARNING cache ignored; running without access rules reason=invalid field={exc.field}")
            return
        except (OSError, ValueError, TypeError) as exc:
            self._log(f"[ACCESS] WARNING cache ignored; running without access rules reason={type(exc).__name__}")
            return
        self._current = access
        self._include_report = True

    def _save_cache(self, access: AccessList) -> None:
        path = self._cache_path
        if path is None or self._url_hash is None:
            return
        temporary = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
            data = json.dumps({"metrics_url_sha256": self._url_hash, "document": access.document()},
                              ensure_ascii=False, separators=(",", ":"))
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            temporary = None
        except Exception as exc:
            self._log(f"[ACCESS] cache write failed error_type={type(exc).__name__}")
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _remove_cache(self) -> None:
        path = self._cache_path
        if path is None:
            return
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            self._log(f"[ACCESS] cache remove failed error_type={type(exc).__name__}")

    # -- 지표 응답 처리
    def offer(self, payload) -> None:
        """지표 전송 2xx 응답 본문. gateway_access 칸이 없으면 아무것도 안 함(옛 대시보드·목록을 아직 못 읽음)."""
        if not isinstance(payload, dict) or "gateway_access" not in payload:
            return
        document = payload["gateway_access"]
        changed = False
        with self._lock:
            self._include_report = True
            current = self._current
            if document is None:
                # 대시보드에 저장된 목록 없음 → 비움(규칙 없음, 확장 ID 없는 접속 허용), 디스크 사본 삭제
                self._rejected = None
                if current is not EMPTY:
                    self._current = EMPTY
                    changed = True
                    self._log("[ACCESS] cleared source=NONE")
                self._remove_cache()
            else:
                try:
                    parsed = parse_access(document, source="DASHBOARD")
                except AccessError as exc:
                    self._rejected = exc.field
                    key = (_rejected_version(document), exc.field)
                    if key not in self._rejected_logged:   # 같은 문서가 10초마다 다시 와도 한 번만
                        self._rejected_logged = (self._rejected_logged + [key])[-self._REJECT_LOG_KEYS:]
                        self._log(f"[ACCESS] rejected version={key[0]} field={exc.field}")
                    return
                self._rejected = None
                if parsed.key == current.key:
                    if current.source == "CACHE":   # 재시작 후 사본과 같은 판을 대시보드가 확인
                        self._current = replace(current, source="DASHBOARD")
                    return
                # "다르면 교체"(크면이 아님): DB를 되돌려 번호가 작아져도 따라간다
                self._current = parsed
                self._save_cache(parsed)
                changed = True
                self._log(f"[ACCESS] applied version={parsed.version} rules={len(parsed.rules)} "
                          f"require_client_id={str(parsed.require_client_id).lower()}")
        if changed and self._on_change is not None:
            try:
                self._on_change()   # 다음 지표를 바로 보내 반영 보고를 앞당긴다
            except Exception:
                pass

    def on_metrics_status(self, http_status) -> None:
        """access_applied를 실은 전송이 400이면(옛 대시보드: 모르는 칸) 다음부터 뺀다. 칸이 다시 오면 다시 싣는다."""
        if http_status == 400:
            with self._lock:
                if self._last_report_sent and self._include_report:
                    self._include_report = False
                    self._log("[ACCESS] report omitted after HTTP 400")

    def report(self) -> dict:
        current = self._current
        return {
            "version": current.version,
            "revision": current.revision,
            "source": current.source,
            "applied_at": current.applied_at,
            "rejected": self._rejected,
            "active_rules": current.active_count(self._clock()),
            "require_client_id": current.require_client_id,
            "denied_5m": self._denied.count(),
        }

    def report_field(self) -> dict:
        """지표 전송기 전용. 칸을 받은 뒤(또는 사본을 읽은 뒤)만 싣는다(옛 대시보드는 모르는 칸이면 지표 전체를 400)."""
        with self._lock:
            include = self._include_report
            self._last_report_sent = include
            return {"access_applied": self.report()} if include else {}
