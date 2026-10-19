"""내용 경향 (설계 v2 4.6-e). 이미 가린 글만, 사설 GPU에서, 고정 범주로 분류한다.

- 켰을 때만 `decisions.masked_text`를 읽는다. 끄면 이 모듈의 SQL은 아예 실행되지 않는다(전역 REPORT_CONTENT_TREND, 보고서마다 체크)
- 표본 글은 메모리에서만 만든다: 한 번 더 가리기 → 주소·긴 값 지우기 → 숫자 '#' → 400자. 파일 이름·사용자 ID는 넣지 않는다
- 보고서에는 범주별 건수와 고정 문구만 나간다. 생성 기록에는 항목 코드(이벤트 번호 없이)와 입력 묶음 해시만 남긴다
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter, defaultdict

from .aggregate import DECISION_SERVICES, MASKED_TEXT_START, RECHECK_PATTERN

SAMPLE_LIMIT = 60
TEXT_LIMIT = 400
BATCH = 10

# 범주(고정) - 코드, 이름, 하위 유형[(코드, 고정 문구)]. 하위 유형이 범주와 안 맞으면 그 범주의 '기타'
CATEGORIES = (
    ("CS", "고객 응대", (("CS_REPLY", "문의 답변 작성"), ("CS_LOG", "상담·민원 기록"), ("CS_LIST", "고객 명단·연락처"))),
    ("HR", "인사·노무", (("HR_HIRE", "채용·지원자"), ("HR_PAY", "급여·근태"), ("HR_EVAL", "평가·인사 기록"))),
    ("FIN", "재무·회계", (("FIN_SUM", "매출·비용 집계"), ("FIN_BUDGET", "예산·정산"), ("FIN_TAX", "세금·증빙"))),
    ("LEGAL", "계약·법무", (("LEGAL_CONTRACT", "계약서·합의서"), ("LEGAL_DISPUTE", "분쟁·소송"), ("LEGAL_RULE", "규정·준법"))),
    ("SALES", "영업·마케팅", (("SALES_PROPOSAL", "제안서·견적"), ("SALES_ACCOUNTS", "거래처 목록"), ("SALES_PR", "홍보·행사"))),
    ("DEV", "개발·기술", (("DEV_CODE", "코드·설정"), ("DEV_LOG", "로그·오류 분석"), ("DEV_ACCESS", "접속·인증 정보"))),
    ("PLAN", "전략·기획", (("PLAN_BIZ", "사업 계획·보고서"), ("PLAN_MEETING", "회의록"), ("PLAN_EXEC", "임원 보고"))),
    ("PERSONAL", "개인 용도", (("PERSONAL_DOC", "개인 서류·이력서"), ("PERSONAL_MSG", "사적 연락"))),
    ("ETC", "기타", (("ETC_SHORT", "짧은 글"), ("ETC_UNKNOWN", "판단 불가"))),
)
CAT_CODES = tuple(c for c, _, _ in CATEGORIES)
CAT_NAMES = {c: n for c, n, _ in CATEGORIES}
SUB_NAMES = {s: n for _, _, subs in CATEGORIES for s, n in subs}
SUB_CAT = {s: c for c, _, subs in CATEGORIES for s, _ in subs}
for _c in CAT_CODES:
    if _c != "ETC":
        SUB_NAMES[f"{_c}_OTHER"] = "기타"
        SUB_CAT[f"{_c}_OTHER"] = _c
SUB_CODES = tuple(SUB_NAMES)
TASKS = (("SUMMARY", "요약"), ("TRANSLATE", "번역"), ("FORMAT", "정리·표 변환"), ("WRITE", "작성·수정"),
         ("REVIEW", "분석·검토"), ("QUESTION", "질문"), ("OTHER", "기타"))
TASK_NAMES = dict(TASKS)
TASK_CODES = tuple(TASK_NAMES)

FOOTER = "마스킹한 글만 분류 · 허용·기밀 차단 건 글은 안 봄 · 10/9 16:20 전 마스킹은 저장된 글 없음"


def global_enabled() -> bool:
    """전역 스위치. 값이 없으면 꺼짐 - 유출·GPU 기록 시험(시험 7)을 통과한 뒤 운영에서 켠다."""
    raw = os.environ.get("REPORT_CONTENT_TREND", os.environ.get("REPORT_CONTENT_TENDENCY", "off"))
    return raw.strip().lower() in ("1", "on", "true", "yes")


def fix_sub(cat: str, sub: str) -> str:
    """하위 유형이 범주와 안 맞으면 그 범주의 '기타'."""
    if SUB_CAT.get(sub) == cat:
        return sub
    return "ETC_UNKNOWN" if cat == "ETC" else f"{cat}_OTHER"


# ---------------------------------------------------------------- 표본 고르기

def _h(event_id: str) -> str:
    return hashlib.sha256(event_id.encode("utf-8")).hexdigest()


def select_sample(pool: list[dict], limit: int = SAMPLE_LIMIT) -> list[dict]:
    """상한을 넘으면 (사용자, 서비스, 경로) 묶음별 비례(큰 나머지 순)로 고르고, 묶음 안은 sha256(event_id) 순.

    같은 입력이면 늘 같은 표본(다시 만들어도 같음). 결과도 sha256 순.
    """
    if len(pool) <= limit:
        return sorted(pool, key=lambda e: _h(e["id"]))
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in pool:
        groups[(e["client"], e["svc"], e["ct"])].append(e)
    total = len(pool)
    quota = {}
    rema = []
    for g, items in groups.items():
        exact = limit * len(items) / total
        quota[g] = int(exact)
        rema.append((-(exact - int(exact)), -len(items), str(g)))
    left = limit - sum(quota.values())
    keys = {str(g): g for g in groups}
    for _, _, gs in sorted(rema)[:left]:
        quota[keys[gs]] += 1
    out = []
    for g, items in groups.items():
        out += sorted(items, key=lambda e: _h(e["id"]))[:quota[g]]
    return sorted(out, key=lambda e: _h(e["id"]))


# ---------------------------------------------------------------- 보고서용 재가림 (메모리에서만)

_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_DOMAIN = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:com|net|org|kr|io|co|ai|dev|app|gov|edu|info|biz|me|jp|cn|us)\b",
                     re.IGNORECASE)
_LONG = re.compile(r"[A-Za-z0-9+/=_\-]{21,}")
_LONG_AFTER = re.compile(r"[A-Za-z#+/=_\-]{21,}")
_DIGIT = re.compile(r"\d")
_SPACE = re.compile(r"\s+")


def remask(rows: list[dict]) -> str:
    """가린 글 행들 → 보고서용 항목 글. rows: [{'text': masked_text, 'order': block_order, 'findings': [{'t','r'}]}].

    1 셀 순서로 ' / ' 이음 2 findings의 바꾼 값(부분 가림 포함)을 [유형] 전체 가림으로 3 주소·긴 값 4 숫자 '#'
    5 공백 정리 후 400자(낱말 경계). 주소를 숫자보다 먼저 지운다 - 숫자를 먼저 바꾸면 이메일 꼴이 깨져 안 잡힌다.
    """
    ordered = sorted(rows, key=lambda r: (r.get("order") is None, r.get("order") or 0))
    text = " / ".join((r.get("text") or "").strip() for r in ordered if (r.get("text") or "").strip())
    subs = set()
    for r in ordered:
        for f in r.get("findings") or []:
            t, rep = (f.get("t") or "").strip(), (f.get("r") or "")
            if t and rep and rep != f"[{t}]" and len(rep) >= 2:
                subs.add((rep, f"[{t}]"))
    for rep, tag in sorted(subs, key=lambda x: -len(x[0])):
        text = text.replace(rep, tag)
    text = _URL.sub("[주소]", text)
    text = _EMAIL.sub("[주소]", text)
    text = _DOMAIN.sub("[주소]", text)
    text = _LONG.sub("[값]", text)
    text = _DIGIT.sub("#", text)
    text = _LONG_AFTER.sub("[값]", text)
    text = _SPACE.sub(" ", text).strip()
    if len(text) > TEXT_LIMIT:
        cut = text[:TEXT_LIMIT]
        sp = cut.rfind(" ")
        text = cut[:sp] if sp >= TEXT_LIMIT * 3 // 4 else cut
    return text


# ---------------------------------------------------------------- 가린 글 읽기 (켰을 때만)

POOL_SQL = """
select split_part(request_id, '#', 1) as root, content_type as ct, count(*) as n
from decisions
where ts >= %s and ts < %s and masked_text is not null and service = any(%s) and request_id not like %s
  and split_part(request_id, '#', 1) = any(%s)
group by 1, 2
"""

TEXT_SQL = """
select split_part(request_id, '#', 1) as root, content_type as ct, block_order, ts, masked_text,
       (select jsonb_agg(jsonb_build_object('t', f->>'entity_type', 'r', f->>'replacement'))
        from jsonb_array_elements(case when jsonb_typeof(findings) = 'array' then findings else '[]'::jsonb end) f) as fs,
       lower(substring(filename from '\\.([A-Za-z0-9]{1,5})$')) as ext
from decisions
where ts >= %s and ts < %s and masked_text is not null and service = any(%s) and request_id not like %s
  and split_part(request_id, '#', 1) = any(%s)
order by 1, block_order nulls last, ts
"""


def build_items(conn, events: list[dict], t0, t1) -> dict:
    """마스킹 이벤트 → 표본 항목. 반환 {'pool': M, 'items': [{i, path, fmt, text, _ev}], 'mask_events': N}.

    `_ev`(이벤트)는 메모리 안 집계용 - 생성 기록·LLM 입력에는 넣지 않는다.
    """
    from datetime import timedelta

    masks = [e for e in events if e["action"] == "MASK" and e["root"]]
    lo, hi = t0 - timedelta(days=1), t1 + timedelta(days=1)
    params = [lo, hi, list(DECISION_SERVICES), RECHECK_PATTERN]
    roots = sorted({e["root"] for e in masks})
    have = set()
    if roots:
        cur = conn.execute(POOL_SQL, [*params, roots])
        have = {(r[0], r[1]) for r in cur.fetchall()}
    pool = [e for e in masks if (e["root"], e["ct"]) in have]
    sample = select_sample(pool)
    rows_by: dict[tuple, list[dict]] = defaultdict(list)
    ext_by: dict[tuple, str] = {}
    if sample:
        cur = conn.execute(TEXT_SQL, [*params, sorted({e["root"] for e in sample})])
        for root, ct, order, _ts, text, fs, ext in cur.fetchall():
            rows_by[(root, ct)].append({"text": text, "order": order, "findings": fs or []})
            if ext:
                ext_by[(root, ct)] = ext
    items = []
    for n, e in enumerate(sample, 1):
        rows = rows_by.get((e["root"], e["ct"]), [])
        items.append({"i": f"C{n:02d}", "path": "파일" if e["ct"] == "file" else "프롬프트",
                      "fmt": (ext_by.get((e["root"], e["ct"])) or "").upper() if e["ct"] == "file" else "",
                      "text": remask(rows), "_ev": e})
    return {"pool": len(pool), "items": items, "mask_events": len(masks),
            "before_start": any(e["ts"] < MASKED_TEXT_START for e in masks)}


def batches(items: list[dict], size: int = BATCH) -> list[list[dict]]:
    """10건씩 한 호출. 항목 번호는 호출마다 C01부터 다시 붙인다(스키마 enum이 짧게)."""
    out = []
    for k in range(0, len(items), size):
        chunk = items[k:k + size]
        out.append([{**it, "i": f"C{j:02d}"} for j, it in enumerate(chunk, 1)])
    return out


def batch_hash(batch: list[dict]) -> str:
    """입력 묶음 해시 - 같은 표본인지 확인용. 글 자체는 저장하지 않는다."""
    h = hashlib.sha256()
    for it in batch:
        h.update(f"{it['i']}\x1f{it['path']}\x1f{it['fmt']}\x1f{it['text']}\x1e".encode("utf-8"))
    return h.hexdigest()[:16]


# ---------------------------------------------------------------- 집계 (분류 결과 → 표)

def tally(classified: list[dict], doc_cats: dict[str, str], events: list[dict]) -> list[dict]:
    """범주별 마스킹 표본 수·기밀 차단 수·주요 하위 유형·주요 요청 형태. 사용자별로 나누지 않는다.

    classified: [{'cat','sub','task'}] (이벤트 번호 없음). doc_cats: 보호 문서 → 범주.
    """
    rows = {c: {"cat": c, "name": CAT_NAMES[c], "mask": 0, "secret": 0, "subs": Counter(), "tasks": Counter()}
            for c in CAT_CODES}
    for it in classified:
        r = rows[it["cat"]]
        r["mask"] += 1
        r["subs"][it["sub"]] += 1
        r["tasks"][it["task"]] += 1
    for e in events:
        if e["action"] == "BLOCK" and e["cat"] == "doc":
            for c in sorted({doc_cats.get(d) for d in e["docs"] if doc_cats.get(d)}):
                rows[c]["secret"] += 1
    out = []
    for c in CAT_CODES:
        r = rows[c]
        if not r["mask"] and not r["secret"]:
            continue
        r["top_subs"] = [(SUB_NAMES[s], n) for s, n in sorted(r["subs"].items(), key=lambda x: (-x[1], x[0]))[:2]]
        r["top_task"] = [(TASK_NAMES[t], n) for t, n in sorted(r["tasks"].items(), key=lambda x: (-x[1], x[0]))[:1]]
        out.append(r)
    out.sort(key=lambda r: (-(r["mask"] + r["secret"]), CAT_CODES.index(r["cat"])))
    return out
