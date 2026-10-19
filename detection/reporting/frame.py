"""보고서 틀 - 한 장 요약 상태·깔때기·관측 범위·차단 뒤 재요청 묶음·같은 패턴 사건 (설계 v3 A1~A5, A9 요약 쪽).

코드만 - LLM 없음. 숫자는 집계(aggregate)·사건(incidents)·사실 목록(facts)에서만 오고, 문장은 고정 틀에 숫자를 넣는다.
여기서 만든 사실(F_ATTN·F_EXPOSED·F_BYPASS 등)은 사실 목록에 들어가지만 섹션 태그가 없어 LLM 입력·인용 허용 목록에
가지 않는다(compose는 섹션 태그로 사실을 고른다).

아래 기준값은 이 보고서의 설정값이며 업계 기준·벤치마크가 아니다. 보고서 '정의·기준'(11. 참고)과 한 장 요약 바닥글에 그대로 찍힌다.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta

from . import aggregate as ag
from .incidents import RETRY, Incident, event_label, group

# ---------------------------------------------------------------- 기준값 (우리 설정값, 업계 기준 아님)

MIN_PREV_COUNT = 10     # 이전 기간 건수가 10건 미만인 카드는 증감 %를 쓰지 않고 절대 증감만 쓴다(1건에서 50건이 '+4,900%'로 읽히는 것을 막음)
PER = 1000              # 비율 단위: 검사 1,000건당 건수
MIN_BASE = 30           # 표본 적음: 이번·이전 기간 중 하나라도 검사가 30건 미만이면 증감 %·1,000건당 비율을 쓰지 않고 절대 증감만 쓴다
# 한 장 요약 상태(양호·주의·위험) = 아래 세 항목 중 가장 높은 단계. 비율 항목은 검사 1,000건당 건수로 비교한다
EXPOSED_WARN = 10       # 노출 1,000건당 10건(1%) 이상이면 주의
EXPOSED_RISK = 50       # 노출 1,000건당 50건(5%) 이상이면 위험
BYPASS_WARN = 1         # 식별 사용자 '차단 뒤 통과' 사건 1건 이상이면 주의
BYPASS_RISK = 3         # 식별 사용자 '차단 뒤 통과' 사건 3건 이상이면 위험
UNSEEN_WARN = 20        # 검사 못 함(검사 불가 파일·검사 서버 응답 없음) 1,000건당 20건(2%) 이상이면 주의
UNSEEN_RISK = 100       # 검사 못 함 1,000건당 100건(10%) 이상이면 위험
MAX_GROUPS = 12         # 차단 뒤 재요청 절에 카드로 보이는 묶음 수(나머지는 '외 N묶음')
MAX_CHANGES = 2         # 한 장 요약 '이전 대비' 줄 수(절대 증감이 큰 순)

STATUS_LABELS = ("양호", "주의", "위험")
NA = "확인 불가"         # 보고서가 읽지 않는 자료
NO_PREV = "비교 불가"    # 이전 기간 기록 없음

DETECTED_CATS = ("doc", "keyword", "pii", "mask_failed")     # 탐지: 기밀 문서·키워드·개인정보·인증정보·마스킹 실패
UNSEEN_CATS = ("uninspectable", "no_check")                 # 검사 못 함: 검사 불가 파일·검사 서버 응답 없음
# '이전 대비' 후보(위험 지표만 - 검사 수는 첫 문장에 있음). 순서는 같은 차이일 때의 순서
CHANGE_CANDIDATES = ("F_SECRET", "F_UNCHECKED", "F_BYPASS", "F_PII_BLOCK", "F_MASK", "F_UNINSP_BLOCK")


# ---------------------------------------------------------------- 표기

def num(n: int, unit: str = "건") -> str:
    return f"{int(n):,}{unit}"


def small_base(n: int, prev_n: int | None) -> bool:
    """이번(n)·이전(prev_n, 없으면 None) 기간 검사 수 중 하나라도 MIN_BASE 미만."""
    return n < MIN_BASE or (prev_n is not None and prev_n < MIN_BASE)


def small_prev(prev) -> bool:
    """이전 기간 건수가 MIN_PREV_COUNT 미만(0 제외 - 0은 원래 % 없음)이면 증감 %를 쓰지 않는다."""
    return prev is not None and 0 < prev < MIN_PREV_COUNT


def per1000(count: int, base: int) -> float | None:
    """검사 1,000건당 건수. 그 기간 검사가 MIN_BASE 미만이면 None(쓰지 않음)."""
    if base < MIN_BASE or base <= 0:
        return None
    return count * PER / base


def rate_text(count: int, base: int) -> str | None:
    r = per1000(count, base)
    return None if r is None else f"1,000건당 {r:,.1f}"


def share_text(count: int, base: int) -> str | None:
    """비중(%) - 표본 적음이면 None."""
    if base < MIN_BASE or base <= 0:
        return None
    return f"{count / base * 100:.1f}%"


# ---------------------------------------------------------------- A2 깔때기

def detected_allow(e: dict) -> bool:
    """탐지 후 허용 = 허용인데 탐지 사유(기밀 문서·키워드·개인정보·인증정보·마스킹 실패)가 있거나, 정책상 허용된 개인정보·기밀 문서 일치가 있는 요청.
    aggregate._cat은 탐지가 있어도 허용이면 '문제 없음'(clean)으로 나누므로 유형·문서가 있는지를 같이 본다."""
    return e["action"] == "ALLOW" and (e["cat"] in DETECTED_CATS or (e["cat"] == "clean" and bool(e.get("pii_types") or e.get("docs"))))


def funnel_counts(ev: list[dict]) -> dict:
    """검사 → 탐지·검사 못 함 → 개입(차단·마스킹) → 노출. 이벤트 1건 단위, aggregate의 판단 묶음(cat)만 쓴다.

    검사 = 차단 + 마스킹 + 허용 + 그 밖 조치
    탐지·검사 못 함 = 개입 + 노출 = 탐지 + 검사 못 함
    노출 = 검사 없이 통과(검사 불가 파일·검사 서버 응답 없음으로 허용) + 탐지 후 허용(탐지 사유인데 허용)
    검사 = 개입 + 노출 + 문제 없음 허용 + 그 밖 조치
    """
    total = len(ev)
    block = sum(1 for e in ev if e["action"] == "BLOCK")
    mask = sum(1 for e in ev if e["action"] == "MASK")
    allow = sum(1 for e in ev if e["action"] == "ALLOW")
    unchecked = sum(1 for e in ev if e["action"] == "ALLOW" and e["cat"] in UNSEEN_CATS)
    det_allow = sum(1 for e in ev if detected_allow(e))
    clean = sum(1 for e in ev if e["action"] == "ALLOW" and e["cat"] == "clean" and not detected_allow(e))
    attn = [e for e in ev if e["action"] in ("BLOCK", "MASK") or detected_allow(e)
            or (e["action"] == "ALLOW" and e["cat"] in UNSEEN_CATS)]
    intervened = block + mask
    exposed = unchecked + det_allow
    return {
        "total": total, "block": block, "mask": mask, "allow": allow, "other_action": total - block - mask - allow,
        "attention": len(attn), "detected": sum(1 for e in attn if e["cat"] in DETECTED_CATS or detected_allow(e)),
        "unseen": sum(1 for e in attn if e["cat"] in UNSEEN_CATS),
        "intervened": intervened, "unchecked": unchecked, "det_allow": det_allow, "exposed": exposed,
        "clean": clean, "rest": total - intervened - exposed - clean,
        "nocheck_pass": sum(1 for e in ev if e["action"] == "ALLOW" and e["cat"] == "no_check"),
        "timeout": sum(1 for e in ev if e["rc"] == "detection_timeout"),
    }


def funnel_line(fc: dict) -> str:
    """깔때기 해석 한 줄(고정 틀)."""
    s = (f"검사 {num(fc['total'])} 중 탐지·검사 못 함 {num(fc['attention'])} → 차단·마스킹 {num(fc['intervened'])}, "
         f"노출 {num(fc['exposed'])}")
    r = rate_text(fc["exposed"], fc["total"])
    if r:
        s += f"({r})"
    if fc["clean"]:
        s += f" · 나머지 {num(fc['clean'])}은 탐지 없이 허용"
    if fc["rest"]:
        s += f" · 그 밖 조치 {num(fc['rest'])}"
    return s


# ---------------------------------------------------------------- A5 차단 뒤 재요청·통과

def after_first_block(inc: Incident) -> int:
    """사건 안 첫 차단 뒤 요청 수(역할 무관). 차단이 없으면 0."""
    idx = next((k for k, m in enumerate(inc.members) if m.e["action"] == "BLOCK"), None)
    return 0 if idx is None else len(inc.members) - idx - 1


def bypass_pairs(ev: list[dict]) -> list[tuple[dict, dict]]:
    """'차단 뒤 통과' 쌍 = (차단 이벤트, 그 뒤 10분 안 같은 서비스에서 허용된 이벤트) - 식별 사용자별로, 차단 하나에 한 쌍.
    사건 묶기가 아니라 사용자별 이벤트를 시간순으로 직접 훑는다 - 사건이 중간의 다른 요청으로 닫혀도 놓치지 않는다.
    미식별은 사람을 가를 수 없어 세지 않는다."""
    per: dict[str, list[dict]] = defaultdict(list)
    for e in ev:
        if e["ident"]:
            per[e["client"]].append(e)
    out = []
    for evs in per.values():
        last: dict[str, dict] = {}
        for e in sorted(evs, key=lambda x: (x["ts"], x["id"])):
            if e["action"] == "BLOCK":
                last[e["svc"]] = e
            elif e["action"] == "ALLOW":
                b = last.get(e["svc"])
                if b is not None and timedelta(0) <= e["ts"] - b["ts"] <= RETRY:
                    out.append((b, e))
                    last.pop(e["svc"], None)
    return out


def bypass_episodes(ev: list[dict]) -> tuple[int, int]:
    """(차단 뒤 통과 횟수, 해당 사용자 수) - bypass_pairs 한 곳에서 센다."""
    pairs = bypass_pairs(ev)
    return len(pairs), len({b["client"] for b, _ in pairs})


def bypass_count(incidents: list[Incident]) -> int:
    """'차단 뒤 통과' = 식별 사용자 사건 중 차단 뒤 10분 안 같은 서비스 허용이 있는 것(incidents.ALLOW_AFTER).
    미식별은 사람을 가를 수 없어 incidents가 차단 뒤 요청을 묶지 않는다 - 그래서 식별 사용자만 센다."""
    return sum(1 for i in incidents if i.ident and i.allow_after_block)


def target_label(e: dict) -> str:
    """대상 이름(고정 문구 + 문서 이름·개인정보 유형 이름, 사용자 글 없음)."""
    cat = e["cat"]
    if cat == "doc":
        return " · ".join(e["docs"]) or "기밀 문서"
    if cat == "keyword":
        return "기밀 키워드"
    if cat in ("pii", "mask_failed"):
        names = [ag.PII_NAMES.get(t, t) for t in e["pii_types"]]
        return event_label(e) + (f"({' · '.join(names)})" if names else "")
    if cat == "uninspectable":
        return f"검사 불가 파일({ag.RC_LABELS.get(e['rc'], e['rc'])})"
    if cat == "no_check":
        return "검사 서버 응답 없음"
    return event_label(e)


def retry_groups(incidents: list[Incident], pairs: list[tuple[dict, dict]] | None = None) -> list[dict]:
    """첫 차단 뒤 요청이 있는 사건을 첫 차단의 대상(문서·키워드·유형)별로 묶는다.

    줄마다: 사건 수, 식별·미식별 사건 수, 식별 사용자(U 번호), 첫 차단 뒤 요청 평균, 차단 뒤 통과 사건 수,
    마지막 결과(사건 마지막 요청의 조치) 분포, 기간, 사건 번호. 순서: 차단 뒤 통과 → 사건 수 → 대상 이름.
    pairs(bypass_pairs)를 주면 '차단 뒤 통과'는 그 쌍 중 차단이 이 묶음 사건 안에 있는 것의 수(머리 줄과 같은 단위),
    없으면 사건 안에 차단 뒤 허용이 있는 사건 수.
    """
    groups: dict[str, dict] = {}
    for inc in incidents:
        if after_first_block(inc) < 1:
            continue
        first = next(m.e for m in inc.members if m.e["action"] == "BLOCK")
        key = first.get("key") or ""
        g = groups.setdefault(key, {"key": key, "label": target_label(first), "cat": first["cat"],
                                    "docs": list(first["docs"]), "incs": []})
        g["incs"].append(inc)
    out = []
    for g in groups.values():
        incs = sorted(g["incs"], key=lambda i: (i.start, i.id))
        ident = [i for i in incs if i.ident]
        member_ids = {m.e["id"] for i in incs for m in i.members}
        last = Counter(i.members[-1].e["action"] for i in incs)
        out.append({
            "key": g["key"], "label": g["label"], "cat": g["cat"], "docs": g["docs"], "n": len(incs),
            "ident": len(ident), "unident": len(incs) - len(ident),
            "users": list(dict.fromkeys(i.user for i in ident if i.user)),
            "avg_after": sum(after_first_block(i) for i in incs) / len(incs),
            "passed": bypass_count(incs) if pairs is None else sum(1 for b, _ in pairs if b["id"] in member_ids),
            "last": [(a, last[a]) for a in ag.ACTIONS if last.get(a)],
            "start": incs[0].start, "end": max(i.end for i in incs), "ids": [i.id for i in incs],
        })
    out.sort(key=lambda g: (-g["passed"], -g["n"], g["label"]))
    return out


def group_line(g: dict) -> str:
    """재요청 묶음 한 줄(고정 틀)."""
    last = " · ".join(f"{ag.ACTION_LABELS[a]} {n}" for a, n in g["last"])
    return (f"사건 {num(g['n'])} · 식별 {g['ident']} · 미식별 {g['unident']} · 첫 차단 뒤 요청 평균 {g['avg_after']:.1f}건 · "
            f"차단 뒤 통과 {num(g['passed'])} · 마지막 결과 {last}")


def bypass_headline(n: int, users: int, groups: list[dict]) -> str:
    retried = sum(g["n"] for g in groups)
    s = f"차단 뒤 통과 {num(n)}(식별 사용자 {users}명) · 차단 뒤 재요청 사건 {num(retried)}"
    top = [g for g in groups if g["passed"]]
    if top:
        s += " · 첫 차단 대상 " + ", ".join(f"{g['label']} {num(g['passed'])}" for g in top[:2])
        if len(top) > 2:
            s += f" 외 {len(top) - 2}묶음"
    return s


# ---------------------------------------------------------------- A5 같은 패턴 사건(주요 사건 카드)

def same_pattern(ids: list[str], steps: dict[str, list[str]], by_id: dict[str, Incident]) -> list[list[str]]:
    """단계 글(steps)과 첫 대상(키)이 같은 사건을 하나로 묶는다. 순서는 ids 순서(묶음은 첫 구성원 자리)."""
    out: list[list[str]] = []
    pos: dict[tuple, int] = {}
    for iid in ids:
        sig = (tuple(steps[iid]), by_id[iid].members[0].e.get("key") or "", tuple(m.e["action"] for m in by_id[iid].members))
        if sig in pos:
            out[pos[sig]].append(iid)
        else:
            pos[sig] = len(out)
            out.append([iid])
    return out


# ---------------------------------------------------------------- 사실 (섹션 태그 없음 → LLM에 안 감)

FRAME_FACTS = (("F_ATTN", "탐지·검사 못 함", "attention"), ("F_DETECTED", "탐지", "detected"),
               ("F_UNSEEN", "검사 못 함", "unseen"), ("F_INTERVENED", "차단·마스킹", "intervened"),
               ("F_EXPOSED", "노출", "exposed"), ("F_DET_ALLOW", "탐지 후 허용", "det_allow"),
               ("F_NOCHECK_PASS", "검사 서버 응답 없이 통과", "nocheck_pass"), ("F_TIMEOUT", "검사 시간 초과", "timeout"))


def add_facts(fx, a: dict, incidents: list[Incident]) -> None:
    """깔때기·차단 뒤 통과 사실을 사실 목록에 넣는다(secs 없음). 이전 기간은 같은 함수로 센다(숫자 출처 하나)."""
    cur = funnel_counts(a["events"])
    prev_ev = a.get("prev_events")
    prev = funnel_counts(prev_ev) if prev_ev is not None else None
    for fid, label, key in FRAME_FACTS:
        fx.add(fid, "count", label, value=cur[key], prev=None if prev is None else prev[key], unit="건", denom="F_TOTAL")
    pb = bypass_episodes(prev_ev)[0] if prev_ev is not None else None
    fx.add("F_BYPASS", "count", "차단 뒤 통과", value=bypass_episodes(a["events"])[0], prev=pb, unit="건", denom="F_TOTAL")


# ---------------------------------------------------------------- A1 상태·첫 문장·이전 대비

def _level(count: int, base: int, warn: int, risk: int, *, rate: bool) -> int:
    """정수 비교(1,000건당 기준은 count×1000 ≥ 기준×base) - 경계값에서 소수 오차 없음."""
    lhs = count * PER if rate else count
    w, r = (warn * base, risk * base) if rate else (warn, risk)
    return 2 if lhs >= r else (1 if lhs >= w else 0)


def status(fx) -> dict:
    """세 항목(노출 비율·차단 뒤 통과·검사 못 함 비율) → 양호/주의/위험. 검사 0건이면 '확인 불가'."""
    n = fx.get("F_TOTAL")["value"]
    exp, byp, uns = fx.get("F_EXPOSED")["value"], fx.get("F_BYPASS")["value"], fx.get("F_UNSEEN")["value"]
    flags = [
        {"key": "exposed", "label": "노출", "sub": "검사 없이 통과 + 탐지 후 허용", "value": exp, "rate": True,
         "warn": EXPOSED_WARN, "risk": EXPOSED_RISK},
        {"key": "bypass", "label": "차단 뒤 통과", "sub": "식별 사용자 사건", "value": byp, "rate": False,
         "warn": BYPASS_WARN, "risk": BYPASS_RISK},
        {"key": "unseen", "label": "검사 못 함", "sub": "검사 불가 파일·검사 서버 응답 없음", "value": uns, "rate": True,
         "warn": UNSEEN_WARN, "risk": UNSEEN_RISK},
    ]
    for f in flags:
        if f["rate"] and not n:
            f["level"] = None
            continue
        if f["rate"] and n < MIN_BASE:      # 표본 적음: 1,000건당 비율은 쓰지 않으므로 비율 항목은 단계를 매기지 않는다(건수만)
            f["level"], f["small"], f["per1000"] = None, True, None
            continue
        f["level"] = _level(f["value"], n, f["warn"], f["risk"], rate=f["rate"])
        f["per1000"] = f["value"] * PER / n if f["rate"] else None
    if not n:
        return {"label": NA, "level": None, "flags": flags, "small": True, "total": 0}
    levels = [f["level"] for f in flags if f["level"] is not None]
    if n < MIN_BASE and not any(lv > 0 for lv in levels):
        return {"label": "표본 적음", "level": None, "flags": flags, "small": True, "total": n}
    level = max(levels)
    return {"label": STATUS_LABELS[level], "level": level, "flags": flags, "small": n < MIN_BASE, "total": n}


def flag_value_text(f: dict) -> str:
    if f.get("small") and f.get("level") is None:
        return f"{num(f['value'])} · 표본 적음(비율 생략)"
    if f.get("level") is None:
        return NA
    if not f["rate"]:
        return num(f["value"])
    return f"{num(f['value'])} · 1,000건당 {f['per1000']:,.1f}"


def flag_rule_text(f: dict) -> str:
    if f["rate"]:
        return f"1,000건당 주의 {f['warn']} · 위험 {f['risk']} 이상"
    return f"주의 {f['warn']}건 · 위험 {f['risk']}건 이상"


def lead_sentence(period: str, fx) -> str:
    """한 장 요약 첫 문장(고정 틀, 코드가 만든다)."""
    g = lambda fid: fx.get(fid)["value"]       # noqa: E731
    if not g("F_TOTAL"):
        return f"{period}에 기록된 검사가 없음"
    s = (f"{period}에 {num(g('F_TOTAL'))}을 검사해 {num(g('F_BLOCK'))} 차단, {num(g('F_MASK'))} 마스킹, "
         f"{num(g('F_UNCHECKED'))}은 검사 없이 통과")
    if g("F_DET_ALLOW"):
        s += f", {num(g('F_DET_ALLOW'))}은 탐지 후 허용"
    return s


def change_clauses(fx, comparable: bool) -> tuple[list[str], str | None]:
    """이전 대비 줄(최대 MAX_CHANGES, 절대 증감이 큰 순) + 덧붙임. 표본 적음이면 1,000건당 비율 없이 절대 증감만."""
    if not comparable or fx.get("F_TOTAL").get("prev") is None:
        return [], "이전 기간 기록 없음(비교 불가)"
    n, pn = fx.get("F_TOTAL")["value"], fx.get("F_TOTAL")["prev"]
    small = small_base(n, pn)
    cands = [fid for fid in CHANGE_CANDIDATES if fid in fx and fx.get(fid).get("prev") is not None
             and fx.get(fid)["value"] != fx.get(fid)["prev"]]
    cands.sort(key=lambda fid: (-abs(fx.get(fid)["value"] - fx.get(fid)["prev"]), CHANGE_CANDIDATES.index(fid)))
    out = []
    for fid in cands[:MAX_CHANGES]:
        f = fx.get(fid)
        v, p, u = f["value"], f["prev"], f.get("unit", "건")
        s = f"{f['label']} {p:,}→{v:,}{u}({v - p:+,}{u})"
        if not small:
            s += f" · 1,000건당 {p * PER / pn:,.1f}→{v * PER / n:,.1f}"
        out.append(s)
    note = f"검사 {pn:,}→{n:,}건"
    if small:
        note += f" · 표본 적음(검사 {MIN_BASE}건 미만 기간이 있어 비율 생략)"
    if not out:
        note += " · 위험 지표는 이전과 같음"
    return out, note


# ---------------------------------------------------------------- A3 관측 범위(못 본 것)

_DET_RC_NOTE = "검사 서버가 답하지 않아 그대로 보냄"
_UNINSP_RC_NOTE = "글을 꺼낼 수 없는 파일이라 그대로 보냄"


def _count(ev, pred) -> int:
    return sum(1 for e in ev if pred(e))


def _split(ev: list[dict], pred) -> str:
    c = Counter(e["action"] for e in ev if pred(e))
    return " · ".join(f"{ag.ACTION_LABELS.get(a, a)} {c[a]}" for a in ag.ACTIONS if c.get(a)) or "없음"


def coverage(a: dict, fx) -> list[dict]:
    """관측 범위 줄 [{key, label, cur, prev, note, sub}] - 값은 글. 이전 기간 없으면 '비교 불가', 안 읽는 자료는 '확인 불가'."""
    ev, pev = a["events"], a.get("prev_events")
    has_prev = pev is not None
    n = len(ev)

    def pair(fn):
        return fn(ev), (fn(pev) if has_prev else None)

    def cell(v, fmt=num):
        return NO_PREV if v is None else fmt(v)

    rows = []
    unchk = lambda e: e["action"] == "ALLOW" and e["cat"] in UNSEEN_CATS       # noqa: E731
    c, p = pair(lambda x: _count(x, unchk))
    rows.append({"key": "unchecked", "label": "검사 없이 통과", "cur": num(c), "prev": cell(p),
                 "note": "판정 없이 AI 서비스로 보냄 · 사유별은 아래", "sub": False})
    rcs = Counter(e["rc"] for e in ev if unchk(e))
    prcs = Counter(e["rc"] for e in pev if unchk(e)) if has_prev else Counter()
    for rc in sorted(set(rcs) | set(prcs), key=lambda r: (-rcs.get(r, 0), r)):
        note = _DET_RC_NOTE if (rc.startswith("detection") or not rc) else _UNINSP_RC_NOTE
        if not rc:
            note += "(사유 기록 없음)"
        rows.append({"key": f"unchecked:{rc}", "label": ag.RC_LABELS.get(rc, rc), "cur": num(rcs.get(rc, 0)),
                     "prev": num(prcs.get(rc, 0)) if has_prev else NO_PREV, "note": note, "sub": True})

    u, pu = pair(lambda x: _count(x, lambda e: not e["ident"]))
    sh = share_text(u, n)
    psh = share_text(pu, len(pev)) if has_prev else None
    rows.append({"key": "unident", "label": "식별 안 됨 요청", "cur": num(u) + (f" · {sh}" if sh else ""),
                 "prev": NO_PREV if pu is None else num(pu) + (f" · {psh}" if psh else ""),
                 "note": "확장 ID가 없어 사용자별 판단·차단 뒤 통과 묶기를 못 함", "sub": False})

    uninsp = lambda e: e["cat"] == "uninspectable"       # noqa: E731

    def by_rc(x):
        cnt = Counter(e["rc"] for e in x if uninsp(e))
        total = sum(cnt.values())
        parts = " · ".join(f"{ag.RC_LABELS.get(r, r)} {k}" for r, k in sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0])))
        return num(total) + (f"({parts})" if parts else "")

    rows.append({"key": "uninspectable", "label": "검사 불가 파일", "cur": by_rc(ev), "prev": by_rc(pev) if has_prev else NO_PREV,
                 "note": f"이미지·스캔 PDF 등 내용을 못 봄 · 이번 처리 {_split(ev, uninsp)}", "sub": False})

    d = a["decisions"]
    pd = (a.get("prev") or {}).get("decisions") if has_prev else None

    def ms(v):
        if v is None:
            return "기록 없음"
        return f"{v / 1000:.2f}초" if v >= 1000 else f"{v:.0f}ms"

    rows.append({"key": "det_p95", "label": "검사 서버 판정 시간 p95", "cur": ms(d.get("p95")),
                 "prev": ms(pd.get("p95")) if pd else NO_PREV, "note": "판정 기록 기준 · 호출 1회", "sub": False})
    tmo = lambda e: e["rc"] == "detection_timeout"       # noqa: E731
    t, pt = pair(lambda x: _count(x, tmo))
    rows.append({"key": "timeout", "label": "검사 시간 초과", "cur": num(t), "prev": cell(pt),
                 "note": f"이번 처리 {_split(ev, tmo)}", "sub": False})
    np_, pnp = pair(lambda x: _count(x, lambda e: e["action"] == "ALLOW" and e["cat"] == "no_check"))
    rows.append({"key": "nocheck_pass", "label": "검사 서버 응답 없이 통과", "cur": num(np_), "prev": cell(pnp),
                 "note": "연결 실패·시간 초과·오류 때 그대로 보낸 요청", "sub": False})
    rows.append({"key": "stage_err", "label": "탐지 단계 오류", "cur": num(d.get("err_roots") or 0),
                 "prev": num(pd.get("err_roots") or 0) if pd else NO_PREV,
                 "note": "판정 기록에 탐지 단계 오류가 남은 요청", "sub": False})
    rows.append({"key": "decision_only", "label": "판정만 있는 요청", "cur": num(d.get("decision_only_n") or 0),
                 "prev": num(pd.get("decision_only_n") or 0) if pd else NO_PREV,
                 "note": "검사는 했지만 대시보드 기록이 없어 이 보고서 숫자에 빠짐", "sub": False})
    # 접속 차단(2026-10-15): Gateway가 검사 전에 막은 요청 - 검사·차단 합계 밖, 여기서만 따로 보인다
    ex, pex = a.get("excluded") or {}, a.get("prev_excluded") if has_prev else None
    acc, pacc = a.get("access_by_rc") or Counter(), (a.get("prev_access_by_rc") or Counter()) if has_prev else Counter()
    rows.append({"key": "access", "label": "접속 차단", "cur": num(ex.get("access", 0)),
                 "prev": num((pex or {}).get("access", 0)) if has_prev else NO_PREV,
                 "note": "확장 ID가 없거나 차단한 확장이라 Gateway가 검사 전에 막음 · 검사·차단 합계에 넣지 않음", "sub": False})
    for rc in sorted(set(acc) | set(pacc), key=lambda r: (-acc.get(r, 0), r)):
        rows.append({"key": f"access:{rc}", "label": ag.ACCESS_RC_LABELS.get(rc, rc), "cur": num(acc.get(rc, 0)),
                     "prev": num(pacc.get(rc, 0)) if has_prev else NO_PREV, "note": rc, "sub": True})
    kw = fx.by_id.get("F_KW_PENDING")
    rows.append({"key": "kw_pending", "label": "승인 대기 키워드", "cur": num(kw["value"], "개") if kw else NA, "prev": NA,
                 "note": "승인 전 키워드는 검사에 쓰지 않음 · 생성 시점 값", "sub": False})
    rows.append({"key": "freshness", "label": "보호 문서·키워드 반영 시점", "cur": NA, "prev": NA,
                 "note": "마지막 반영 시각을 이 보고서가 읽지 않음", "sub": False})
    return rows


def coverage_headline(a: dict, fx) -> str:
    """관측 범위 한 줄(한 장 요약용)."""
    ev = a["events"]
    n = len(ev)
    u = _count(ev, lambda e: not e["ident"])
    sh = share_text(u, n)
    return (f"검사 없이 통과 {num(fx.get('F_UNCHECKED')['value'])} · 검사 불가 파일 {num(_count(ev, lambda e: e['cat'] == 'uninspectable'))}"
            f" · 검사 시간 초과 {num(fx.get('F_TIMEOUT')['value'])} · 식별 안 됨 {num(u)}" + (f"({sh})" if sh else "")
            + f" · 판정만 있는 요청 {num(a['decisions'].get('decision_only_n') or 0)}")


# ---------------------------------------------------------------- A4 일별 추이 변경 표시선

_AT = re.compile(r"^(\d{1,2})/(\d{1,2}) (\d{2}):(\d{2})$")


def change_marks(fx, days: list[str], *, per_day: int = 3) -> list[dict]:
    """사실 목록의 변경(관리 작업·Gateway 설정·탐지 정책·기준 변경, 8절 표와 같음) → 날짜별 표시선.

    반환 [{i: 날짜 위치, n: 표시 번호, md, items: ['16:20 마스킹한 글 기록 시작', …], more: 넘친 수}]. 기간 밖·시각 모름은 뺀다.
    """
    pos = {}
    for i, d in enumerate(days):
        y, m, dd = d.split("-")
        pos[f"{int(m)}/{int(dd)}"] = i
    by_day: dict[int, list[str]] = {}
    for fid in fx.ids(lambda f: f["type"] == "change"):
        f = fx.get(fid)
        m = _AT.match(str(f.get("at") or ""))
        if not m:
            continue
        i = pos.get(f"{int(m.group(1))}/{int(m.group(2))}")
        if i is None:
            continue
        by_day.setdefault(i, []).append(f"{m.group(3)}:{m.group(4)} {f['label']}")
    out = []
    for k, i in enumerate(sorted(by_day), 1):
        items = sorted(by_day[i])
        y, mo, dd = days[i].split("-")
        out.append({"i": i, "n": k, "md": f"{int(mo)}/{int(dd)}", "items": items[:per_day],
                    "more": max(0, len(items) - per_day), "all": items})
    return out


# ---------------------------------------------------------------- 정의·기준(각주)

def status_rule_line() -> str:
    return (f"상태 = 세 항목 중 가장 높은 단계 · 노출 1,000건당 {EXPOSED_WARN} 이상 주의·{EXPOSED_RISK} 이상 위험 · "
            f"차단 뒤 통과 {BYPASS_WARN}건 이상 주의·{BYPASS_RISK}건 이상 위험 · 검사 못 함 1,000건당 {UNSEEN_WARN} 이상 주의·"
            f"{UNSEEN_RISK} 이상 위험 · 기준값은 이 보고서의 설정값(업계 기준 아님)")


def definitions() -> list[tuple[str, str]]:
    """(용어, 정의) - 11. 참고의 '정의·기준'."""
    return [
        ("상태(양호·주의·위험)", status_rule_line() + " · 검사 0건이면 확인 불가 · 검사 "
         f"{MIN_BASE}건 미만이면 노출·검사 못 함은 단계 없이 건수만 보이고(차단 뒤 통과만 단계를 매김), 단계를 매길 항목이 없으면 '표본 적음'"),
        ("노출", "검사 없이 통과(검사 서버 연결 실패·시간 초과·오류로 보냄, 이미지·스캔 PDF·크기 초과 등 검사 불가 파일을 보냄)"
         " + 탐지 후 허용(탐지 사유이거나 개인정보 유형·기밀 문서 일치가 있는데 정책상 허용). 넣지 않음: 마스킹 후 전송(차단·마스킹으로 셈), 검사했지만 탐지하지 못한 것(잴 수 없음),"
         " 접속 차단·판정만 있는 요청(검사 합계 밖)"),
        ("탐지·검사 못 함", "탐지 = 기밀 문서 일치·기밀 키워드·개인정보·인증정보·마스킹 실패 사유 · 검사 못 함 = 검사 불가 파일·검사 서버 응답 없음 사유"
         " · 조치와 무관하게 사유로 나눔 · 탐지·검사 못 함 = 차단·마스킹 + 노출"),
        ("검사 합계", "검사 = 차단·마스킹 + 노출 + 문제 없음 허용(+ 그 밖 조치) = 차단 + 마스킹 + 허용"),
        ("차단 뒤 통과", f"식별 사용자가 차단된 뒤 {int(RETRY.total_seconds() // 60)}분 안 같은 서비스에서 허용된 요청을 받은 횟수(차단→허용 쌍마다 1)."
         " 사건 묶기와 별개로 사용자별 요청을 시간순으로 세어 사건 경계에 영향받지 않음 · 같은 내용인지는 모름(원문 안 봄) · 미식별은 사람을 가를 수 없어 세지 않음"),
        ("차단 뒤 재요청", "사건 안 첫 차단 뒤 요청이 1건 이상 있는 사건 · 첫 차단의 대상(문서·키워드·유형)별로 묶음"),
        ("같은 패턴 사건", "주요 사건 중 단계 글과 첫 대상이 같은 사건을 카드 하나로 묶음(사건별 카드는 펼쳐 보기)"),
        ("1,000건당", "그 기간 검사 1,000건당 건수"),
        ("이전 건수 적음", f"카드의 이전 기간 건수가 1~{MIN_PREV_COUNT - 1}건이면 증감 %를 쓰지 않고 절대 증감만 씀(작은 수에서 비율이 크게 보이는 것을 막음)"),
        ("표본 적음", f"이번·이전 기간 중 검사가 {MIN_BASE}건 미만인 기간이 있으면 증감 %와 1,000건당 비율을 쓰지 않고 절대 증감만 씀"),
        ("일별 추이 표시선", "기간 안 관리 작업·Gateway 설정·탐지 정책·기준 변경(8절 표와 같음), 번호는 날짜 순"),
        ("문서와 같은 글자", "보낸 입력의 공백 뺀 글자 중 보호 문서(판정 당시 보존본, 없으면 지금 문서)와 같은 글자의 비율 · 대시보드 목록·상세와 같은 값"
         " · 토큰·키·주민번호·전화·메일은 가린 뒤 가린 덩어리 하나를 한 글자로 셈 · 소수 첫째 자리 내림, 다른 글자가 있으면 100%로 올리지 않음"
         " · 대조할 본문이 없거나 검사 서버가 같은 글로 확인한 문장과 대조 결과가 어긋나면 '대조 불가'"
         " · 보호 문서 상세 표는 차단 건 중 가장 높은 값 · 사건 단계 표시는 같은 대상 직전 차단보다 값이 작을 때(대조 불가는 비교 안 함)"
         " · 검사 서버가 매기는 30자 구간 해시 점수와 다른 값(그 점수는 보고서에 쓰지 않음)"),
    ]
