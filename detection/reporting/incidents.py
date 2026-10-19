"""사건 묶기·구성원 역할·사건 등급·규칙 순위, 사용자 사실·규칙 등급 (설계 v2 4.5, 4.6-c). 코드만 - LLM 없음.

규칙: 같은 사용자 + 같은 대상 30분 간격, 또는 차단 뒤 10분 안 같은 서비스 요청(허용 포함).
식별 안 됨(확장 ID 없음)은 사람을 가를 수 없으므로 같은 서비스·같은 대상 키 흐름 안에서 30분 간격만 묶는다
(차단 뒤 재시도 묶기 없음). '수정 후 재시도'라고 쓰지 않는다 - 원문을 안 보므로 같은 내용인지 모른다.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .same_text import summary_ratio

GAP = timedelta(minutes=30)
RETRY = timedelta(minutes=10)

ROLE_LABELS = {
    "FIRST": "첫 결과", "REPEAT": "같은 대상 반복", "RATE_DOWN": "같은 대상 반복(문서와 같은 글자 낮아짐)",
    "CHANGED": "차단 뒤 결과 바뀜", "ALLOW_AFTER": "차단 뒤 허용", "OTHER_TARGET": "다른 대상",
}
GRADE_LABELS = {1: "기밀 차단", 2: "인증정보", 3: "검사 없이 통과", 4: "그 밖 차단", 5: "마스킹만"}
LEVELS = ("높음", "중간", "낮음")
CANDIDATES = 15     # LLM에 주는 사건 후보(등급 1~4 중 규칙 순위 상위)
NARRATED = 12       # 서술하는 사건 수


def target_key(e: dict) -> str:
    cat = e["cat"]
    if cat == "doc":
        return "doc:" + ",".join(e["docs"])
    if cat == "keyword":
        return "kw"
    if cat in ("pii", "mask_failed"):
        return f"{cat}:" + ",".join(e["pii_types"])
    if cat == "uninspectable":
        return "uninspectable:" + e["rc"]
    if cat == "no_check":
        return "no_check"
    return f"{cat}:{e['rc']}"


def attention(e: dict) -> bool:
    """사건을 시작·이을 수 있는 이벤트: 차단·마스킹, 검사 없이 통과. 문제 없는 허용은 사건을 시작하지 않음."""
    return e["action"] in ("BLOCK", "MASK") or (e["action"] == "ALLOW" and e["cat"] in ("uninspectable", "no_check"))


def event_class(e: dict) -> int:
    """1 기밀 차단 → 2 인증정보 → 3 검사 없이 통과 → 4 그 밖 차단 → 5 마스킹 → 9 그 밖(재시도 창의 허용)."""
    if e["action"] == "BLOCK" and e["cat"] in ("doc", "keyword"):
        return 1
    if e["action"] in ("BLOCK", "MASK") and e.get("cred"):
        return 2
    if e["action"] == "ALLOW" and e["cat"] in ("uninspectable", "no_check"):
        return 3
    if e["action"] == "BLOCK":
        return 4
    if e["action"] == "MASK":
        return 5
    return 9


EVENT_LABELS = {
    "doc": "기밀 차단", "keyword": "기밀 키워드 차단", "mask_failed": "마스킹 실패 차단",
    "uninspectable": "검사 불가 차단", "no_check": "응답 없음 차단",
}


def event_label(e: dict) -> str:
    """사건 단계에 쓰는 고정 이름(사용자 글 없음)."""
    a, cat = e["action"], e["cat"]
    if a == "BLOCK":
        if cat == "pii":
            return "인증정보 차단" if e.get("cred") else "개인정보 차단"
        return EVENT_LABELS.get(cat, "차단")
    if a == "MASK":
        return "인증정보 마스킹" if e.get("cred") else "개인정보 마스킹"
    if cat in ("uninspectable", "no_check"):
        return "검사 없이 통과"
    return "허용"


@dataclass
class Member:
    e: dict
    role: str


@dataclass
class Incident:
    members: list[Member] = field(default_factory=list)
    id: str = ""
    user: str = ""          # U 번호(식별) 또는 '' (미식별)

    @property
    def events(self) -> list[dict]:
        return [m.e for m in self.members]

    @property
    def client(self) -> str:
        return self.members[0].e["client"]

    @property
    def ident(self) -> bool:
        return self.members[0].e["ident"]

    @property
    def start(self):
        return self.members[0].e["ts"]

    @property
    def end(self):
        return self.members[-1].e["ts"]

    @property
    def keys(self) -> set[str]:
        return {m.e["key"] for m in self.members if attention(m.e)}

    @property
    def grade(self) -> int:
        return min(event_class(e) for e in self.events)

    def count(self, action: str) -> int:
        return sum(1 for e in self.events if e["action"] == action)

    @property
    def allow_after_block(self) -> bool:
        return any(m.role == "ALLOW_AFTER" for m in self.members)

    @property
    def retries(self) -> int:
        return sum(1 for m in self.members if m.role in ("CHANGED", "ALLOW_AFTER", "OTHER_TARGET"))

    @property
    def services(self) -> list[str]:
        return list(dict.fromkeys(e["svc"] for e in self.events))

    @property
    def docs(self) -> list[str]:
        return list(dict.fromkeys(d for e in self.events for d in e["docs"]))

    @property
    def span_min(self) -> float:
        return (self.end - self.start).total_seconds() / 60


def _blocks_in_window(x: Incident, e: dict) -> list[dict]:
    return [m.e for m in x.members if m.e["action"] == "BLOCK" and timedelta(0) <= e["ts"] - m.e["ts"] <= RETRY
            and m.e["svc"] == e["svc"]]


def _joins_ident(x: Incident, e: dict) -> bool:
    last = x.members[-1].e
    same = attention(e) and e["ts"] - last["ts"] <= GAP and e["key"] in x.keys
    return same or bool(_blocks_in_window(x, e))


def _joins_unknown(x: Incident, e: dict) -> bool:
    last = x.members[-1].e
    return attention(e) and e["svc"] == last["svc"] and e["key"] == last["key"] and e["ts"] - last["ts"] <= GAP


def _rate(e: dict) -> float | None:
    """그 이벤트 문서들의 '문서와 같은 글자' 비율 최댓값(대시보드와 같은 값). 모두 대조 불가·없음이면 None(비교 안 함)."""
    rates = [r for r in (summary_ratio((e.get("same") or {}).get(d)) for d in e["docs"]) if r is not None]
    return max(rates) if rates else None


def _role(x: Incident, e: dict) -> str:
    same_key = [m.e for m in x.members if m.e["key"] == e["key"]]
    if e["action"] == "BLOCK" and e["cat"] == "doc" and same_key:
        prev = next((p for p in reversed(same_key) if p["action"] == "BLOCK"), None)
        r0, r1 = (_rate(prev), _rate(e)) if prev is not None else (None, None)
        if r0 is not None and r1 is not None and r1 < r0:
            return "RATE_DOWN"
    if x.ident and _blocks_in_window(x, e):
        if e["action"] == "ALLOW":
            return "ALLOW_AFTER"
        if e["action"] == "MASK":
            return "CHANGED"
        if not same_key:
            return "OTHER_TARGET"
    return "REPEAT"


def group(events: list[dict], *, unknown_by_target: bool = True) -> list[Incident]:
    """사건 목록(시작 시각 순, 번호 I1…). events는 aggregate.prepare_events 결과(시간순 아니어도 됨).

    unknown_by_target=False면 식별 안 됨도 한 흐름으로 본다(설계 3.2 시뮬레이션과 같은 방식 - 비교용).
    """
    streams: dict[tuple, list[dict]] = defaultdict(list)
    for e in events:
        e["key"] = target_key(e)
        if e["ident"]:
            streams[("u", e["client"])].append(e)
        elif unknown_by_target:
            streams[("x", e["svc"], e["key"])].append(e)
        else:
            streams[("x",)].append(e)
    out: list[Incident] = []
    for skey in sorted(streams, key=lambda k: tuple(str(v) for v in k)):
        evs = sorted(streams[skey], key=lambda e: (e["ts"], e["id"]))
        x: Incident | None = None
        for e in evs:
            if x is not None:
                ok = _joins_ident(x, e) if e["ident"] else _joins_unknown(x, e)
                if ok:
                    x.members.append(Member(e, _role(x, e)))
                    continue
                out.append(x)
                x = None
            if attention(e):
                x = Incident([Member(e, "FIRST")])
        if x is not None:
            out.append(x)
    out.sort(key=lambda i: (i.start, i.members[0].e["id"]))
    for n, inc in enumerate(out, 1):
        inc.id = f"I{n}"
    return out


def rule_order(incidents: list[Incident]) -> list[Incident]:
    """규칙 순위: 등급 → 차단 뒤 허용 있음 → 구성원 수 → 시작 시각."""
    return sorted(incidents, key=lambda i: (i.grade, not i.allow_after_block, -len(i.members), i.start, i.id))


def candidates(incidents: list[Incident]) -> list[Incident]:
    return [i for i in rule_order(incidents) if i.grade <= 4][:CANDIDATES]


# ---------------------------------------------------------------- 사용자

def user_facts(events: list[dict], incidents: list[Incident]) -> list[dict]:
    """식별 사용자별 사실 + 규칙 등급. 번호 U1…은 규칙 등급 → 건수 순."""
    by: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["ident"]:
            by[e["client"]].append(e)
    users = []
    for client, evs in by.items():
        evs.sort(key=lambda e: (e["ts"], e["id"]))
        secret = [e for e in evs if event_class(e) == 1]
        blocks = [e for e in evs if e["action"] == "BLOCK"]
        retry = bta = 0
        for i, b in enumerate(evs):
            if b["action"] != "BLOCK":
                continue
            nxt = [f for f in evs[i + 1:] if f["ts"] - b["ts"] <= RETRY and f["svc"] == b["svc"]]
            if nxt:
                retry += 1
            if any(f["action"] == "ALLOW" for f in nxt):
                bta += 1
        u = {
            "client": client, "events": len(evs), "secret": len(secret),
            "docs": len({d for e in secret for d in e["docs"]}),
            "cred": sum(1 for e in evs if e["action"] in ("BLOCK", "MASK") and e.get("cred")),
            "retry": retry, "block_then_allow": bta, "block": len(blocks),
            "mask": sum(1 for e in evs if e["action"] == "MASK"),
            "unchecked": sum(1 for e in evs if e["action"] == "ALLOW" and e["cat"] in ("uninspectable", "no_check")),
            "days": len({e["day"] for e in evs}),
            "incidents": [i.id for i in incidents if i.ident and i.client == client],
        }
        u["rule_level"] = rule_level(u)
        users.append(u)
    users.sort(key=lambda u: (LEVELS.index(u["rule_level"]), -u["secret"], -u["cred"], -u["events"], u["client"]))
    for n, u in enumerate(users, 1):
        u["id"] = f"U{n}"
    ids = {u["client"]: u["id"] for u in users}
    for inc in incidents:
        inc.user = ids.get(inc.client, "") if inc.ident else ""
    return users


def rule_level(u: dict) -> str:
    """규칙 등급(기준선, 임의 건수 기준 없음)."""
    if (u["secret"] and (u["retry"] or u["docs"] >= 2)) or (u["cred"] and u["retry"]):
        return "높음"
    if u["secret"] or u["cred"] or u["block"]:
        return "중간"
    return "낮음"


def basis_rule(u: dict) -> str:
    """규칙 등급을 정한 조건 이름(숫자 없음) - LLM 사용자 호출의 '등급 근거' 사실(U번호.BASIS) 이름표.
    rule_level과 같은 조건을 같은 순서로 본다(2026-10-16, '…가 많음' 오채택: 등급 근거 없이 건수만 주던 것을 고침)."""
    if rule_level(u) == "높음":
        parts = []
        if u["secret"] and u["retry"]:
            parts.append("기밀 차단과 차단 뒤 재시도가 함께 있음")
        if u["secret"] and u["docs"] >= 2:
            parts.append("서로 다른 기밀 문서 여러 종이 차단됨")
        if u["cred"] and u["retry"]:
            parts.append("인증정보 포함과 차단 뒤 재시도가 함께 있음")
        return "높음 근거: " + " · ".join(parts)
    if u["secret"]:
        return "중간 근거: 기밀 차단은 있으나 차단 뒤 재시도·여러 문서는 없음"
    if u["cred"]:
        return "중간 근거: 인증정보 포함은 있으나 차단 뒤 재시도는 없음"
    if u["block"]:
        return "중간 근거: 기밀·인증정보가 아닌 차단만 있음"
    return "낮음 근거: 차단·기밀·인증정보 없음"


def basis_labels(u: dict) -> str:
    """규칙 등급 근거 이름표(대체 문장) - '기밀 차단 2 · 차단 뒤 재시도 1'."""
    parts = [("기밀 차단", u["secret"]), ("서로 다른 문서", u["docs"] if u["docs"] >= 2 else 0),
             ("인증정보", u["cred"]), ("차단 뒤 재시도", u["retry"]), ("차단 뒤 허용", u["block_then_allow"]),
             ("차단", u["block"] if not u["secret"] and not u["cred"] else 0), ("마스킹", u["mask"]),
             ("검사 없이 통과", u["unchecked"])]
    shown = [f"{k} {v}" for k, v in parts if v]
    return " · ".join(shown) or f"검사 {u['events']}"
