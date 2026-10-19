"""기간 집계 - 대시보드 이벤트 1건 단위, 한국 시각 (설계 v1 3.3~3.4, v2 3.1).

RDS를 읽기만 한다(세션을 읽기 전용으로 둔다). 원문(`decisions.prompt`)·가린 글(`masked_text`)·문서 본문은 여기서 읽지
않는다 - 가린 글은 내용 경향을 켰을 때 content.py만 읽는다.

SQL은 이벤트 메타데이터(조치·사유·서비스·검출기·문서 번호·유형 개수)만 가져오고 시험 제외·재전송 묶기·판단 묶음(cat)·
한국 날짜 묶기는 파이썬에서 한다. 이벤트는 기간당 수백~수천 건이라 충분히 빠르고, 같은 코드를 합성 자료로 시험할 수 있다.
기준은 v1 3.3 SQL `ev`와 같다(시험 접두어 정규식, 재전송 4.348초·10/11 04:23 UTC 전, cat 순서, 서비스 분리).
"""

from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from . import same_text as st

KST = timezone(timedelta(hours=9))
UTC = timezone.utc

# ---------------------------------------------------------------- 기준 (한 곳)

# 시험 제외: 대시보드 TEST_CLIENT_PREFIXES와 같은 접두어(v1 결정 2). 바꾸면 대시보드 설정도 같이 바꾼다.
# legacy = Gateway 서비스 가동 전 손으로 띄운 gateway.py 시험 호출을 판정 기록에서 되살린 123건(client legacy-gateway,
# source RDS_DECISIONS_BACKFILL, 9/15~9/23) - 공통 규칙 docs/handoff/stats-rules-2026-10-16/SPEC.md 1.1
TEST_CLIENT_PREFIXES = tuple(p.strip() for p in os.environ.get(
    "REPORT_TEST_CLIENT_PREFIXES", "demo,evidence,codex,diag,gateway,legacy").split(",") if p.strip())

# 시연 문서: 문서 번호 접두어. 문서 일치가 시연 문서뿐인 이벤트는 빼고 등록 문서 수에서도 뺀다(SPEC 1.3·2.2)
DEMO_DOC_PREFIX = "DEMO_"


def is_demo_doc(doc_id) -> bool:
    return isinstance(doc_id, str) and doc_id.startswith(DEMO_DOC_PREFIX)


def test_client_re(prefixes: Iterable[str] = TEST_CLIENT_PREFIXES) -> re.Pattern:
    return re.compile(r"^(%s)(-|$)" % "|".join(re.escape(p) for p in prefixes))


# 판정 기록 쪽: 서비스 허용 목록 + 가린 파일 재검사 행(`#verify`) 제외
DECISION_SERVICES = ("ChatGPT", "Claude", "Gemini", "OpenAI")
RECHECK_PATTERN = "%#verify"

UNKNOWN_CLIENT = "unknown-client"
RESEND_GAP = timedelta(seconds=4.348)
RESEND_CUTOFF = datetime(2026, 10, 11, 4, 23, tzinfo=UTC)         # 이후는 Gateway가 이미 묶음(파일만)
# 질문 재시도: 같은 사용자·서비스·조치·사유·질문 본문(정규화 해시)이 RESEND_GAP 안에 다시 오면 1건. Gateway는 질문을 묶지
# 않으므로 기준 시각 없음. 같은 키 반복 간격 실측(3초 안 7개 → 빈 구간 → 7.5초부터)이 근거(SPEC 2.3)
PMS_CUTOFF = datetime(2026, 10, 11, 2, 23, 29, tzinfo=UTC)        # 처리 시간이 LLM 응답까지 재던 구간 끝
MASKED_TEXT_START = datetime(2026, 10, 9, 7, 20, tzinfo=UTC)      # 가린 글 기록 시작(한국 10/9 16:20)

# 기준 변경 시각 - 기간·비교 기간이 걸치면 '비교 주의'(v1 3.8)
CRITERIA_CHANGES = (
    (datetime(2026, 10, 9, 7, 20, tzinfo=UTC), "마스킹한 글 기록 시작(질문·파일 전후 비교 연결)"),
    (PMS_CUTOFF, "처리 시간 기준 변경(AI 서비스 응답 대기 제외)"),
    (RESEND_CUTOFF, "Gateway 파일 재전송 묶기 시작"),
    (datetime(2026, 10, 11, 6, 41, tzinfo=UTC), "Claude 새 화면 질문 검사 시작"),
    (datetime(2026, 10, 11, 15, 0, tzinfo=UTC), "PDF·HWP·HWPX 마스킹 시작"),
)

UNINSPECTABLE_RC = ("file_uninspectable_image", "file_uninspectable_scanned_pdf", "file_uninspectable_other",
                    "file_too_large")
MASK_FAILED_RC = ("mask_application_failed", "file_masking_failed")
# 접속 차단: Gateway가 Detection을 부르기 전에 막은 요청(gateway_access.py REASON_BLOCKED·REASON_MISSING, 운영 RDS 값).
# 옛 이름(ip_blocked·extension_blocked)은 운영 기록에 없지만 받아 둔다(2026-10-15 감사: 실제 코드가 안 걸려 '개인정보'로 셈)
ACCESS_RC = ("client_blocked", "client_id_missing", "ip_blocked", "extension_blocked")
ACCESS_RC_LABELS = {"client_blocked": "차단한 확장 ID", "client_id_missing": "확장 ID 없음",
                    "ip_blocked": "차단한 IP(옛 이름)", "extension_blocked": "차단한 확장(옛 이름)"}

CAT_LABELS = {
    "doc": "기밀문서 일치", "keyword": "기밀 키워드", "pii": "개인정보·인증정보", "mask_failed": "마스킹 실패",
    "uninspectable": "검사 불가 파일", "no_check": "검사 서버 응답 없음", "access": "접속 차단",
    "clean": "문제 없음", "other": "기타",
}
ACTION_LABELS = {"BLOCK": "차단", "MASK": "마스킹", "ALLOW": "허용"}
ACTIONS = ("BLOCK", "MASK", "ALLOW")
CT_LABELS = {"prompt": "프롬프트", "file": "파일"}

RC_LABELS = {
    "detection_unreachable": "검사 서버 연결 실패", "detection_timeout": "검사 시간 초과",
    "detection_error": "검사 서버 오류", "detection_parse_error": "검사 서버 응답 해석 실패", "file_uninspectable_image": "이미지 파일",
    "file_uninspectable_scanned_pdf": "스캔 PDF", "file_uninspectable_other": "그 밖 형식",
    "file_too_large": "크기 초과", "mask_application_failed": "마스킹 적용 실패", "file_masking_failed": "파일 마스킹 실패",
    "": "응답 없음(사유 미기록)",
}

CREDENTIAL_TYPES = ("GENERIC_API_KEY", "PASSWORD", "GITHUB_TOKEN", "AWS_ACCESS_KEY", "PRIVATE_KEY")
PII_NAMES = {
    "KR_PHONE_NUMBER": "전화번호", "EMAIL_ADDRESS": "이메일", "KR_RRN": "주민등록번호",
    "KR_FOREIGN_REGISTRATION_NUMBER": "외국인등록번호", "KR_DATE_OF_BIRTH": "생년월일",
    "KR_BANK_ACCOUNT": "계좌번호", "KR_ADDRESS": "주소", "KR_POSTAL_CODE": "우편번호",
    "GENERIC_API_KEY": "API 키", "PASSWORD": "비밀번호", "GITHUB_TOKEN": "GitHub 토큰",
    "AWS_ACCESS_KEY": "AWS 접근 키", "PRIVATE_KEY": "개인 키", "DOC_KEYWORD": "기밀 키워드",
}
SERVICE_IDS = {"ChatGPT": "CHATGPT", "Claude": "CLAUDE", "Claude(새 화면)": "CLAUDE_NEW", "Gemini": "GEMINI",
               "OpenAI API": "OPENAI_API"}

# 관리 작업 중 '설정·정책 변경'이 아닌 것(로그인·조사·보고서·GPU·요청)
_NOT_CHANGE_PREFIX = ("ADMIN_LOGIN", "ADMIN_LOGOUT", "EVENT_", "REPORT_", "GPU_")
ADMIN_ACTION_LABELS = {
    "DOCUMENT_REGISTER": "보호 문서 등록", "DOCUMENT_RETIRE": "보호 문서 해제", "KEYWORD_APPROVE": "키워드 승인",
    "KEYWORD_DELETE": "키워드 삭제", "KEYWORD_ADD": "키워드 추가", "KEYWORD_EXTRACT_REQUEST": "키워드 추출 요청",
    "EVENT_STATUS_CHANGED": "이벤트 상태 변경", "EVENT_ASSIGNED": "이벤트 담당 지정", "EVENT_NOTE_ADDED": "이벤트 메모",
    "REPORT_CREATE": "보고서 생성", "GPU_START": "GPU 켜기", "GPU_STOP": "GPU 끄기",
    "GATEWAY_SETTINGS_UPDATE": "Gateway 설정 저장", "POLICY_UPDATE": "탐지 정책 변경",
    "ACCESS_RULE_ADD": "접속 차단 규칙 추가", "ACCESS_RULE_REMOVE": "접속 차단 규칙 해제",
    "ACCESS_MODE_UPDATE": "접속 차단 방식 변경", "CLIENT_ALIAS_UPDATE": "클라이언트 별칭 변경",
}


class ReportSumError(RuntimeError):
    """카드·표 합계가 검사 수와 다름 - 틀린 숫자로 파일을 만들지 않는다(v1 3.8)."""


def is_setting_change(action: str) -> bool:
    return not (action.startswith(_NOT_CHANGE_PREFIX) or action.endswith("_REQUEST"))


# ---------------------------------------------------------------- 시각

def kst_bounds(start: date, end_excl: date) -> tuple[datetime, datetime]:
    """한국 날짜 [start, end_excl) → UTC 경계."""
    return (datetime(start.year, start.month, start.day, tzinfo=KST).astimezone(UTC),
            datetime(end_excl.year, end_excl.month, end_excl.day, tzinfo=KST).astimezone(UTC))


def kst_day(ts: datetime) -> date:
    return ts.astimezone(KST).date()


def kst_md(ts: datetime) -> str:
    t = ts.astimezone(KST)
    return f"{t.month}/{t.day}"


def kst_hm(ts: datetime) -> str:
    t = ts.astimezone(KST)
    return f"{t.month}/{t.day} {t.hour:02d}:{t.minute:02d}"


def md(d: date) -> str:
    return f"{d.month}/{d.day}"


def percentile(values: list[float], q: float) -> float | None:
    """Postgres percentile_cont와 같은 선형 보간."""
    if not values:
        return None
    xs = sorted(values)
    pos = (len(xs) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


# ---------------------------------------------------------------- SQL (메타데이터만)

EVENTS_SQL = """
select e.event_id,
       split_part(coalesce(e.request_id, ''), '#', 1) as root,
       e.occurred_at, e.created_at, e.client_id, e.target_llm, e.final_action,
       e.event->>'content_type' as ct, e.event->>'reason_code' as rc, e.event->>'file_id' as fid,
       coalesce(e.event->'degraded' = 'true'::jsonb, false) as deg,
       coalesce(e.event->>'endpoint', '') like '/v1/%%' as ep_v1,
       coalesce(e.event->>'endpoint', '') like '/claudeai-rpc/%%' as ep_rpc,
       case when jsonb_typeof(e.event->'processing_ms') = 'number' then (e.event->>'processing_ms')::float end as pms,
       case when e.event->>'content_type' = 'prompt' then
         (select case when count(*) = 1 and bool_and(x.prompt is not null)
                      then md5(btrim(regexp_replace(max(x.prompt), '\\s+', ' ', 'g'))) end
          from decisions x where x.request_id = e.request_id) end as prompt_hash,
       coalesce((select jsonb_agg(jsonb_build_object('detector', d->>'detector', 'doc', d->>'matched_document_id',
                                                     'ents', coalesce(d->'entity_counts', '[]'::jsonb)))
                 from jsonb_array_elements(case when jsonb_typeof(e.event->'detections') = 'array'
                                                then e.event->'detections' else '[]'::jsonb end) d), '[]'::jsonb) as dets
from dashboard_security_events e
where e.occurred_at >= %s and e.occurred_at < %s
order by e.occurred_at, e.event_id
"""

_DEC_WHERE = "service = any(%s) and request_id not like %s"

DECISION_ROOTS_SQL = f"""
select split_part(request_id, '#', 1) as root, max(service) as svc, max(content_type) as ct,
       max(lower(substring(filename from '\\.([A-Za-z0-9]{{1,5}})$'))) filter (where content_type = 'file') as ext,
       bool_or(hash_status = 'error' or signature_status = 'error') as err, count(*) as n
from decisions
where ts >= %s and ts < %s and {_DEC_WHERE}
group by 1
"""

# '문서와 같은 글자'(2026-10-16, 대시보드와 같은 값): 대시보드 서버 #evidenceRows와 같은 행 - 이벤트 원본·같은 요청 번호의
# 판정 기록(2건 이상이면 대조 불가)·문서 본문·판정 당시 보존본. 계산은 same_text.py(대시보드 코드 이식)
SAME_EVENTS_SQL = "select event_id, event from dashboard_security_events where event_id = any(%s)"
SAME_DECISIONS_SQL = """
select request_id, ts, decided_by, doc_id, doc_span, input_span, prompt_kept, document_ref,
       length(prompt) as prompt_chars, case when length(prompt) <= %s then prompt else null end as prompt
from decisions where request_id = any(%s)
"""
SAME_DOCUMENTS_SQL = """
select doc_id, version, length(normalized_text) as normalized_chars,
       case when length(normalized_text) <= %s then normalized_text else null end as normalized_text
from documents where doc_id = any(%s)
"""
SAME_VERSIONS_SQL = """
select doc_id, version, normalized_sha256, length(normalized_text) as normalized_chars,
       case when length(normalized_text) <= %s then normalized_text else null end as normalized_text
from dashboard_document_versions where doc_id = %s and version = %s and normalized_sha256 = %s
"""

DECISION_STATS_SQL = f"""
select count(*) as rows,
       percentile_cont(0.5) within group (order by total_ms)::float as p50,
       percentile_cont(0.95) within group (order by total_ms)::float as p95,
       count(distinct split_part(request_id, '#', 1)) filter (where hash_status = 'error' or signature_status = 'error') as err_roots
from decisions
where ts >= %s and ts < %s and {_DEC_WHERE}
"""

DECISION_ONLY_SQL = f"""
with r as (select split_part(request_id, '#', 1) as root, max(service) as svc, max(content_type) as ct
           from decisions where ts >= %s and ts < %s and {_DEC_WHERE} group by 1)
select svc, coalesce(ct, '') as ct, count(*) as n from r
where not exists (select 1 from dashboard_security_events e
                  where e.request_id is not null and split_part(e.request_id, '#', 1) = r.root)
group by 1, 2 order by 3 desc
"""

DOCUMENTS_SQL = "select doc_id, format, status, index_status, classification, registered_at from documents order by doc_id"

ADMIN_SQL = """
select occurred_at, admin_id, action, target_type, result
from dashboard_admin_activity_history
where occurred_at >= %s and occurred_at < %s
order by occurred_at
"""

GATEWAY_SETTINGS_SQL = """
select version, settings, updated_by, updated_at from dashboard_gateway_settings
where updated_at < %s
  and (updated_at >= %s or version = (select max(version) from dashboard_gateway_settings where updated_at < %s))
order by version
"""


def _rows(conn, sql: str, params: list | tuple = ()) -> list[dict]:
    cur = conn.execute(sql, list(params))
    if cur.description is None:
        return []
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def prepare_session(conn) -> None:
    """읽기 전용 세션 + 문장 시간 한도. 집계가 운영 RDS에 쓰는 일이 없게 한다."""
    conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
    conn.execute("SET statement_timeout = '60s'")
    conn.execute("SET TIME ZONE 'Asia/Seoul'")


def _dec_params() -> list:
    return [list(DECISION_SERVICES), RECHECK_PATTERN]


def fetch_events(conn, t0: datetime, t1: datetime) -> list[dict]:
    return _rows(conn, EVENTS_SQL, [t0, t1])


def fetch_decision_roots(conn, t0: datetime, t1: datetime) -> dict[str, dict]:
    """판정 기록 요청 단위(형식·오류). 이벤트와 시각이 조금 어긋나므로 앞뒤 1일 여유."""
    lo, hi = t0 - timedelta(days=1), t1 + timedelta(days=1)
    return {r["root"]: r for r in _rows(conn, DECISION_ROOTS_SQL, [lo, hi, *_dec_params()])}


def fetch_same_text(conn, event_ids: Iterable[str]) -> dict[str, dict]:
    """이벤트마다 {문서: '문서와 같은 글자' 요약}(READY {same_chars, input_chars, differences} · UNAVAILABLE {reason}).
    대시보드 목록·상세와 같은 행·같은 계산(same_text.py). 문서 구간 일치(WINDOW_HASH)가 없는 이벤트는 빠진다."""
    ids = sorted(set(event_ids))
    if not ids:
        return {}
    events = {r["event_id"]: r["event"] for r in _rows(conn, SAME_EVENTS_SQL, [ids]) if isinstance(r.get("event"), dict)}
    rids = sorted({e["request_id"] for e in events.values() if isinstance(e.get("request_id"), str) and e["request_id"]})
    decs: dict[str, list[dict]] = defaultdict(list)
    for r in (_rows(conn, SAME_DECISIONS_SQL, [st.TEXT_LIMIT, rids]) if rids else []):
        decs[r["request_id"]].append(r)
    doc_ids = sorted({d for e in events.values() for d in st.window_docs(e) if isinstance(d, str)})
    current = [r for r in _rows(conn, SAME_DOCUMENTS_SQL, [st.TEXT_LIMIT, doc_ids])] if doc_ids else []
    archived: dict[tuple, list[dict]] = {}
    cache: dict = {}
    out: dict[str, dict] = {}
    for eid in ids:
        e = events.get(eid)
        if e is None:
            continue
        rows = decs.get(e.get("request_id"), []) if isinstance(e.get("request_id"), str) else []
        docs = list(current)
        ref = st.archived_ref(e, rows)
        if ref is not None:
            if ref not in archived:
                archived[ref] = [{**r, "evidence_source": "EVENT_DOCUMENT_VERSION"}
                                 for r in _rows(conn, SAME_VERSIONS_SQL, [st.TEXT_LIMIT, *ref])]
            docs += archived[ref]
        same = st.event_same_text(e, rows, docs, cache=cache)
        if same:
            out[eid] = same
    return out


def attach_same_text(ev: list[dict], same: dict[str, dict]) -> None:
    for e in ev:
        e["same"] = dict(same.get(e["id"]) or {})


def same_targets(ev: list[dict]) -> list[str]:
    """'문서와 같은 글자'를 보여 주는 이벤트: 기밀 문서 일치 차단(보호 문서 상세 표·사건 '낮아짐' 판정)."""
    return [e["id"] for e in ev if e["action"] == "BLOCK" and e["cat"] == "doc" and e["docs"]]


# ---------------------------------------------------------------- 이벤트 다듬기 (v1 `ev`)

def _cat(action: str, rc: str, deg: bool, dets: list[dict]) -> str:
    """사유 코드는 Gateway(접속 차단·검사 불가·마스킹 실패·detection_*)와 Detection(doc_excerpt·pii·none) 실제 값.
    기밀(doc·keyword)·개인정보(pii)는 검출 목록으로만 정한다 - Detection 사유 코드만으로는 세지 않음(SPEC 2.6)."""
    if rc in ACCESS_RC:                          # Detection 호출 전 거부 - 검출이 붙을 수 없다
        return "access"
    if any(d.get("detector") and d.get("detector") != "SIGNATURE" for d in dets):
        return "doc"
    if any(x.get("entity_type") == "DOC_KEYWORD" for d in dets for x in (d.get("ents") or [])):
        return "keyword"
    if rc in UNINSPECTABLE_RC:
        return "uninspectable"
    if rc in MASK_FAILED_RC:
        return "mask_failed"
    if deg or rc.startswith("detection"):
        return "no_check"
    if action in ("BLOCK", "MASK"):
        # 2026-10-17 공통 규칙(SPEC 2.6, 대시보드 hasSensitiveFinding과 같음): 검출된 값이 있어야 개인정보·기밀로 센다.
        # 검출 목록 없이 사유 코드(pii·doc_excerpt)만 남은 기록(9/29 파일 차단 2건)과 사유·검출 모두 없는 기록(9/23 옛 형식)은
        # '그 밖'(카드 밖 차단)
        if any(_has_value(d) for d in dets):     # 패턴 검출 값 1개 이상(개인정보·인증정보)
            return "pii"
        return "other"
    if action == "ALLOW":
        return "clean"
    return "other"


def _has_value(det: dict) -> bool:
    """탐지 1건에 검출 값(entity_counts의 count > 0)이 하나라도 있는지 - 대시보드 hasSensitiveFinding의 패턴 검사 쪽 조건."""
    for x in det.get("ents") or []:
        try:
            if int(x.get("count") or 0) > 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _svc(llm: str, ep_v1: bool, ep_rpc: bool) -> str:
    if llm == "ChatGPT" and ep_v1:
        return "OpenAI API"
    if llm == "Claude" and ep_rpc:
        return "Claude(새 화면)"
    return llm


def prepare_events(rows: list[dict], t0: datetime, t1: datetime, *, test_re: re.Pattern | None = None,
                   access_by_rc: Counter | None = None) -> tuple[list[dict], dict]:
    """원시 행 → 집계 단위 이벤트. 반환 (이벤트, {'test': 시험 제외 수, 'demo': 시연 문서 제외 수,
    'resend': 접은 수(파일 재전송 + 질문 재시도), 'resend_file', 'resend_prompt', 'access': 접속 차단 수}).
    순서·값은 대시보드와 같은 공통 규칙(docs/handoff/stats-rules-2026-10-16/SPEC.md).
    access_by_rc를 주면 접속 차단 수를 사유 코드별로 더한다(관측 범위 줄)."""
    test_re = test_re or test_client_re()
    stats = {"test": 0, "demo": 0, "resend": 0, "resend_file": 0, "resend_prompt": 0, "access": 0}
    ev0 = []
    for r in rows:
        ts = r["occurred_at"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if not (t0 <= ts < t1):
            continue
        client = r.get("client_id") or ""
        if test_re.match(client):
            stats["test"] += 1
            continue
        doc_hits = {d.get("doc") for d in (r.get("dets") or [])
                    if d.get("detector") and d.get("detector") != "SIGNATURE" and d.get("doc")}
        if doc_hits and all(is_demo_doc(d) for d in doc_hits):
            stats["demo"] += 1
            continue
        ev0.append((r, ts))
    ev0.sort(key=lambda x: (x[1], x[0]["event_id"]))
    last: dict[tuple, datetime] = {}
    last_prompt: dict[tuple, datetime] = {}
    out = []
    for r, ts in ev0:
        ct, rc, fid = r.get("ct") or "", r.get("rc") or "", r.get("fid") or ""
        part = (r.get("client_id") or "", r.get("target_llm") or "", ct, r["final_action"], rc, fid)
        gap = ts - last[part] if part in last else None
        last[part] = ts
        if ct == "file" and gap is not None and gap <= RESEND_GAP and ts < RESEND_CUTOFF:
            stats["resend_file"] += 1
            stats["resend"] += 1
            continue
        ph = r.get("prompt_hash")
        if ct == "prompt" and ph:
            kp = (r.get("client_id") or "", r.get("target_llm") or "", "prompt", r["final_action"], rc, ph)
            gp = ts - last_prompt[kp] if kp in last_prompt else None
            last_prompt[kp] = ts
            if gp is not None and gp <= RESEND_GAP:
                stats["resend_prompt"] += 1
                stats["resend"] += 1
                continue
        dets = r.get("dets") or []
        cat = _cat(r["final_action"], rc, bool(r.get("deg")), dets)
        if cat == "access":                      # 접속 차단은 검사 합계와 따로(v1 3.3)
            stats["access"] += 1
            if access_by_rc is not None:
                access_by_rc[rc] += 1
            continue
        ents: Counter = Counter()
        docs = set()
        for d in dets:
            if d.get("detector") and d.get("detector") != "SIGNATURE" and d.get("doc"):
                docs.add(d["doc"])
            for x in d.get("ents") or []:
                if x.get("entity_type"):
                    try:
                        ents[x["entity_type"]] += int(x.get("count") or 0)
                    except (TypeError, ValueError):
                        ents[x["entity_type"]] += 0
        created = r.get("created_at")
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        client = r.get("client_id") or UNKNOWN_CLIENT
        out.append({
            "id": r["event_id"], "root": r.get("root") or "", "ts": ts, "created": created,
            "client": client, "ident": client != UNKNOWN_CLIENT,
            "llm": r.get("target_llm") or "", "svc": _svc(r.get("target_llm") or "", bool(r.get("ep_v1")), bool(r.get("ep_rpc"))),
            "action": r["final_action"], "ct": ct, "rc": rc, "fid": fid, "deg": bool(r.get("deg")),
            "pms": r.get("pms"), "cat": cat, "docs": tuple(sorted(docs)), "ents": dict(ents),
            "day": kst_day(ts),
        })
    for e in out:
        e["cred"] = any(t in CREDENTIAL_TYPES for t in e["ents"])
        e["pii_types"] = tuple(sorted(t for t in e["ents"] if t != "DOC_KEYWORD"))
    return out, stats


def attach_decisions(ev: list[dict], roots: dict[str, dict]) -> None:
    """판정 기록 정보(파일 형식)를 이벤트에 붙인다. 판정 기록 없는 파일은 사유로 형식을 정한다."""
    for e in ev:
        r = roots.get(e["root"]) if e["root"] else None
        e["has_decision"] = r is not None and bool(r.get("n"))
        if e["ct"] == "file":
            ext = (r or {}).get("ext")
            e["fmt"] = ext.upper() if ext else ("이미지" if e["rc"] == "file_uninspectable_image" else "기타")
        else:
            e["fmt"] = ""


# ---------------------------------------------------------------- 지표 (이번·이전 기간 공용)

CARD_FILTERS = {
    "secret": lambda e: e["action"] == "BLOCK" and e["cat"] in ("doc", "keyword"),
    "mask": lambda e: e["action"] == "MASK",
    "pii_block": lambda e: e["action"] == "BLOCK" and e["cat"] in ("pii", "mask_failed"),
    "uninsp_block": lambda e: e["action"] == "BLOCK" and e["cat"] == "uninspectable",
    "unchecked": lambda e: e["action"] == "ALLOW" and e["cat"] in ("uninspectable", "no_check"),
    "allow_clean": lambda e: e["action"] == "ALLOW" and e["cat"] == "clean",
}


def _count(ev, pred) -> int:
    return sum(1 for e in ev if pred(e))


def metrics(ev: list[dict], start: date, end_excl: date) -> dict:
    """한 기간의 표·카드. 합계가 안 맞으면 ReportSumError."""
    total = len(ev)
    cards = {k: _count(ev, f) for k, f in CARD_FILTERS.items()}
    rest = _count(ev, lambda e: not any(f(e) for f in CARD_FILTERS.values()))
    cards.update(total=total, rest=rest,
                 prompt=_count(ev, lambda e: e["ct"] == "prompt"), file=_count(ev, lambda e: e["ct"] == "file"),
                 secret_doc=_count(ev, lambda e: e["action"] == "BLOCK" and e["cat"] == "doc"),
                 secret_kw=_count(ev, lambda e: e["action"] == "BLOCK" and e["cat"] == "keyword"),
                 mask_failed=_count(ev, lambda e: e["action"] == "BLOCK" and e["cat"] == "mask_failed"),
                 block=_count(ev, lambda e: e["action"] == "BLOCK"),
                 allow=_count(ev, lambda e: e["action"] == "ALLOW"))
    cards["other_ct"] = total - cards["prompt"] - cards["file"]

    by_action_cat = Counter((e["action"], e["cat"]) for e in ev)
    by_path = Counter((e["ct"] or "", e["action"]) for e in ev)
    by_svc = Counter((e["svc"], e["action"]) for e in ev)
    daily: dict[str, Counter] = {}
    d = start
    while d < end_excl:
        daily[d.isoformat()] = Counter()
        d += timedelta(days=1)
    for e in ev:
        daily.setdefault(e["day"].isoformat(), Counter())[e["action"]] += 1

    # 합계 검사: 카드 합 + 문제 없는 허용 + 그 밖 = 검사, 표마다 합 = 검사
    card_sum = sum(cards[k] for k in CARD_FILTERS) + rest
    checks = {"cards": card_sum, "action_cat": sum(by_action_cat.values()), "path": sum(by_path.values()),
              "service": sum(by_svc.values()), "daily": sum(sum(c.values()) for c in daily.values()),
              "ct": cards["prompt"] + cards["file"] + cards["other_ct"]}
    bad = {k: v for k, v in checks.items() if v != total}
    if bad:
        raise ReportSumError(f"합계 불일치: 검사 {total}, " + ", ".join(f"{k} {v}" for k, v in bad.items()))

    pii: dict[str, dict] = {}
    for e in ev:
        for t, n in e["ents"].items():
            if t == "DOC_KEYWORD":
                continue
            p = pii.setdefault(t, {"code": t, "name": PII_NAMES.get(t, t), "items": 0, "values": 0,
                                   "BLOCK": 0, "MASK": 0, "ALLOW": 0, "cred": t in CREDENTIAL_TYPES})
            p["items"] += 1
            p["values"] += n
            p[e["action"]] = p.get(e["action"], 0) + 1
    pii_list = sorted(pii.values(), key=lambda p: (-p["items"], p["code"]))

    formats = Counter((e["fmt"], e["action"]) for e in ev if e["ct"] == "file")
    docs: dict[str, dict] = {}
    for e in ev:
        if not (e["action"] == "BLOCK" and e["cat"] == "doc"):
            continue
        for doc in e["docs"]:
            x = docs.setdefault(doc, {"doc": doc, "n": 0, "days": set(), "first": e["ts"], "last": e["ts"],
                                      "same_max": None, "same_na": 0})
            x["n"] += 1
            x["days"].add(e["day"])
            x["first"], x["last"] = min(x["first"], e["ts"]), max(x["last"], e["ts"])
            s = (e.get("same") or {}).get(doc)       # '문서와 같은 글자'(대시보드와 같은 값) - 가장 높은 값 · 대조 불가 건수
            r = st.summary_ratio(s)
            if r is not None:
                if x["same_max"] is None or r > st.summary_ratio(x["same_max"]):
                    x["same_max"] = s
            elif s is not None:
                x["same_na"] += 1
    doc_list = sorted(docs.values(), key=lambda x: (-x["n"], x["doc"]))
    for x in doc_list:
        x["days"] = len(x["days"])

    unchecked_by_rc = Counter(e["rc"] for e in ev if CARD_FILTERS["unchecked"](e))
    timeout_by_action = Counter(e["action"] for e in ev if e["rc"] == "detection_timeout")
    pms = [e["pms"] for e in ev if e["pms"] is not None and e["ts"] >= PMS_CUTOFF]
    delay = [(e["created"] - e["ts"]).total_seconds() * 1000 for e in ev if e.get("created")]
    users = Counter(e["client"] for e in ev)
    return {
        "cards": cards, "by_action_cat": by_action_cat, "by_path": by_path, "by_svc": by_svc, "daily": daily,
        "pii": pii_list, "cred_events": _count(ev, lambda e: e["cred"]), "formats": formats, "docs": doc_list,
        "unchecked_by_rc": unchecked_by_rc, "timeout_by_action": timeout_by_action,
        "pms": {"n": len(pms), "p50": percentile(pms, 0.5), "p95": percentile(pms, 0.95), "max": max(pms) if pms else None},
        "delay": {"n": len(delay), "p95": percentile(delay, 0.95), "max": max(delay) if delay else None},
        "users": users, "ident_users": sorted(c for c in users if c != UNKNOWN_CLIENT),
        "unident": users.get(UNKNOWN_CLIENT, 0),
        "event_only": _count(ev, lambda e: e["root"] and not e.get("has_decision", True)
                             and e["cat"] not in ("uninspectable", "no_check", "access")),
        "no_request_id": _count(ev, lambda e: not e["root"]),
    }


# ---------------------------------------------------------------- 그 밖 표

def fetch_decision_stats(conn, t0: datetime, t1: datetime) -> dict:
    s = _rows(conn, DECISION_STATS_SQL, [t0, t1, *_dec_params()])[0]
    only = _rows(conn, DECISION_ONLY_SQL, [t0, t1, *_dec_params()])
    return {"rows": s["rows"] or 0, "p50": s["p50"], "p95": s["p95"], "err_roots": s["err_roots"] or 0,
            "decision_only": only, "decision_only_n": sum(r["n"] for r in only)}


def fetch_admin(conn, t0: datetime, t1: datetime) -> dict:
    rows = _rows(conn, ADMIN_SQL, [t0, t1])
    ops = [r for r in rows if r["action"] not in ("ADMIN_LOGIN", "ADMIN_LOGOUT")]
    return {"ops": ops, "by_action": Counter(r["action"] for r in ops),
            "changes": [r for r in ops if is_setting_change(r["action"])],
            "login_fail": sum(1 for r in rows if r["action"] == "ADMIN_LOGIN" and r["result"] == "FAILURE")}


def _flat(obj: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out.update(_flat(v, f"{prefix}{k}."))
        return out
    return {prefix.rstrip("."): obj}


def fetch_gateway_changes(conn, t0: datetime, t1: datetime) -> dict:
    """기간 안 Gateway 설정 버전 → 바뀐 값만 전→후. 행이 없으면 '대시보드 저장 없음(기본값)'."""
    rows = _rows(conn, GATEWAY_SETTINGS_SQL, [t1, t0, t0])
    if not rows:
        return {"saved": False, "changes": []}
    changes = []
    prev = None
    for r in rows:
        if r["updated_at"] < t0:
            prev = r
            continue
        before = _flat(prev["settings"]) if prev else {}
        after = _flat(r["settings"] or {})
        for k in sorted(set(before) | set(after)):
            if before.get(k) != after.get(k):
                changes.append({"at": r["updated_at"], "key": k, "before": before.get(k), "after": after.get(k),
                                "by": r["updated_by"], "version": r["version"]})
        prev = r
    return {"saved": True, "changes": changes}


def fetch_aliases(conn) -> dict[str, str]:
    """확장 ID 별칭(대시보드 표). 표가 없거나 못 읽으면 빈 값 - 짧은 ID로 표시한다."""
    try:
        exists = conn.execute("select to_regclass('dashboard_client_aliases') is not null").fetchone()[0]
        if not exists:
            return {}
        return {r["client_id"]: r["alias"] for r in _rows(conn, "select client_id, alias from dashboard_client_aliases")}
    except Exception:  # noqa: BLE001 - 별칭은 보조 표시
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {}


FIRST_BY_CLIENT_SQL = "select client_id, min(occurred_at) as first from dashboard_security_events group by client_id"


def earliest_event(conn, test_re: re.Pattern | None = None) -> datetime | None:
    """비교 가능 판정의 첫 기록 = 시험 접두어(legacy 포함)가 아닌 이벤트 중 가장 이른 것(공통 규칙 SPEC 2.5).
    옛 판정 기록(9/15~9/23)을 빼면 첫 기록은 9/23 - 그 전 비교 기간은 '비교 불가'."""
    test_re = test_re or test_client_re()
    firsts = [r["first"] for r in _rows(conn, FIRST_BY_CLIENT_SQL) if not test_re.match(r["client_id"] or "")]
    v = min(firsts, default=None)
    if v is not None and v.tzinfo is None:
        v = v.replace(tzinfo=UTC)
    return v


# ---------------------------------------------------------------- 수집

def collect(conn, start: date, end_excl: date) -> dict:
    """이번 기간 [start, end_excl)과 같은 길이 직전 기간. 결과는 사건 묶기·사실 목록·렌더러가 같이 쓴다."""
    days = (end_excl - start).days
    prev_start, prev_end = start - timedelta(days=days), start
    t0, t1 = kst_bounds(start, end_excl)
    p0, p1 = kst_bounds(prev_start, prev_end)
    test_re = test_client_re()

    raw = fetch_events(conn, t0, t1)
    access_rc: Counter = Counter()
    ev, ex = prepare_events(raw, t0, t1, test_re=test_re, access_by_rc=access_rc)
    roots = fetch_decision_roots(conn, t0, t1)
    attach_decisions(ev, roots)
    attach_same_text(ev, fetch_same_text(conn, same_targets(ev)))
    cur = metrics(ev, start, end_excl)

    first = earliest_event(conn, test_re)
    comparable = first is not None and first <= p0
    prev = prev_ex = prev_ev = None
    prev_access_rc: Counter | None = None
    if comparable:
        prev_access_rc = Counter()
        prev_ev, prev_ex = prepare_events(fetch_events(conn, p0, p1), p0, p1, test_re=test_re, access_by_rc=prev_access_rc)
        attach_decisions(prev_ev, fetch_decision_roots(conn, p0, p1))
        prev = metrics(prev_ev, prev_start, prev_end)
        prev["decisions"] = fetch_decision_stats(conn, p0, p1)
        prev["admin"] = fetch_admin(conn, p0, p1)

    criteria = [{"at": at, "label": label, "inside": t0 <= at < t1}
                for at, label in CRITERIA_CHANGES if (p0 if comparable else t0) < at < t1]
    a = {
        "start": start, "end_excl": end_excl, "end": end_excl - timedelta(days=1), "days": days,
        "prev_start": prev_start, "prev_end": prev_end - timedelta(days=1), "comparable": comparable,
        "t0": t0, "t1": t1, "events": ev, "excluded": ex, "prev_excluded": prev_ex,
        "access_by_rc": access_rc, "prev_access_by_rc": prev_access_rc,
        "cur": cur, "prev": prev, "prev_events": prev_ev,
        "decisions": fetch_decision_stats(conn, t0, t1),
        "documents": [d for d in _rows(conn, DOCUMENTS_SQL) if not is_demo_doc(d.get("doc_id"))],
        "admin": fetch_admin(conn, t0, t1),
        "gateway": fetch_gateway_changes(conn, t0, t1),
        "aliases": fetch_aliases(conn),
        "criteria": criteria,
        "first_event": first,
    }
    return a


# ---------------------------------------------------------------- 주요 이슈 I1~I8 (v1 3.4-8) → 사실 번호 R1~R8

ISSUES = {
    "R1": ("기밀 차단", "높음", "해당 문서 사용 이력 확인 · 문서 접근 권한 검토"),
    "R2": ("새로 차단된 문서", "확인", "사용 부서 확인"),
    "R3": ("인증정보 노출 시도", "높음", "해당 인증정보 교체 · 비밀값 관리 안내"),
    "R4": ("검사 없이 통과", "높음", "검사 불가 파일 설정 검토 · 검사 서버 연결 점검"),
    "R5": ("마스킹 실패 차단", "확인", "해당 파일 형식 마스킹 점검"),
    "R6": ("기록 누락", "확인", "이벤트 전송·판정 기록 전송 점검"),
    "R7": ("탐지 단계 오류", "높음", "탐지 단계 상태 점검"),
    "R8": ("설정·정책 변경", "정보", "권고 없음"),
}
SEV = {"높음": "critical", "확인": "serious", "정보": "warning", "해당 없음": "good"}


def new_docs(a: dict) -> list[str]:
    if not a["prev"]:
        return []
    before = {d["doc"] for d in a["prev"]["docs"]}
    return [d["doc"] for d in a["cur"]["docs"] if d["doc"] not in before]


def evaluate_issues(a: dict, *, policy_changes: int = 0) -> list[dict]:
    """걸린 이슈. 문구는 집계 문장(LLM 안 거침). 고정 건수 기준 없음 - '1건 이상'(v1 결정 9)."""
    c = a["cur"]["cards"]
    cur = a["cur"]
    out = []

    def add(code, fact, off=False):
        name, level, scope = ISSUES[code]
        out.append({"code": code, "name": name, "level": "해당 없음" if off else level,
                    "sev": SEV["해당 없음" if off else level], "fact": fact, "scope": scope, "off": off})

    if c["secret"]:
        add("R1", f"기밀 차단 {c['secret']}건 · 문서 일치 {c['secret_doc']} · 키워드 {c['secret_kw']}")
    nd = new_docs(a)
    if nd:
        add("R2", f"새로 차단된 문서 {len(nd)}종")
    cred = [p for p in cur["pii"] if p["cred"]]
    if cur["cred_events"]:
        add("R3", f"인증정보 포함 {cur['cred_events']}건 · " + " · ".join(f"{p['name']} {p['items']}" for p in cred))
    if c["unchecked"]:
        parts = " · ".join(f"{RC_LABELS.get(rc, rc)} {n}" for rc, n in cur["unchecked_by_rc"].most_common())
        add("R4", f"검사 없이 통과 {c['unchecked']}건 · {parts}")
    if c["mask_failed"]:
        add("R5", f"마스킹 실패 차단 {c['mask_failed']}건")
    lost = a["decisions"]["decision_only_n"] + cur["event_only"]
    if lost:
        add("R6", f"판정만 있는 요청 {a['decisions']['decision_only_n']}건 · 이벤트만 있는 검사 대상 {cur['event_only']}건")
    err = a["decisions"]["err_roots"]
    add("R7", f"탐지 단계 오류 {err}건" if err else "0건", off=not err)
    changes = len(a["admin"]["changes"]) + len(a["gateway"]["changes"]) + policy_changes
    if changes:
        add("R8", f"관리 작업 {len(a['admin']['changes'])}건 · Gateway 설정 {len(a['gateway']['changes'])}건 · "
                  f"탐지 정책 {policy_changes}건")
    return out
