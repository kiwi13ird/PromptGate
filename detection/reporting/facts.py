"""사실 목록(번호·형식·값) + 자리표시 렌더러 (설계 v2 4.4).

사실 하나 = 번호 + 형식 + 값(+ 이전 값) + 섹션 태그. 머리: F 지표, K 기여, E 변경, I 사건, U 사용자, D 보호 문서,
R 이슈, G 내용 범주 집계. LLM은 `{ID}`·`{ID|꼴}` 자리표시로만 숫자·이름을 쓰고, 렌더러가 이름표·숫자·방향 낱말을 넣는다.
사용자 별칭·확장 ID는 LLM 보기(llm_view)에서 빠진다 - `U2` 번호만 간다.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Callable

from . import aggregate as ag
from . import frame
from . import same_text as st
from .content import CAT_NAMES
from .incidents import GRADE_LABELS, ROLE_LABELS, Incident, basis_rule, event_label

SECTION_NAMES = {"S1": "요약", "S2": "판정 현황", "S3": "기밀정보", "S4": "개인정보·인증정보", "S5": "주요 사건",
                 "S6": "사용자별 위험", "S7": "내용 경향", "S8": "설정·정책 변경", "S9": "운영 상태",
                 "S10": "권고·다음 조치"}

PH = re.compile(r"\{([A-Z][A-Z0-9_]*(?:\.[A-Z0-9_]+)?)(?:\|([^{}|]*))?\}")
FORMS = {"count": ("값", "이전", "변화", "비율"), "rate": ("값", "이전", "변화"), "time": ("값", "이전", "변화"),
         "share": ("값",)}
NUMERIC = ("count", "rate", "time", "share", "span")
_PRIVATE = ("client", "display", "_pred")


class RenderError(ValueError):
    pass


def short_id(client: str) -> str:
    return client if len(client) <= 12 else client[:11] + "…"


# ---------------------------------------------------------------- 값 표기

def _num(v: float | int, unit: str = "") -> str:
    if isinstance(v, float) and not v.is_integer():
        return f"{v:,.1f}{unit}"
    return f"{int(v):,}{unit}"


def _time_unit(*vals: float) -> str:
    return "초" if max(abs(v) for v in vals) >= 1000 else "ms"


def _time(v: float, unit: str) -> str:
    return f"{v / 1000:.2f}" if unit == "초" else f"{v:.0f}"


def span_text(minutes: float) -> str:
    if minutes < 1:
        return "1분 미만"
    m = int(round(minutes))
    return f"{m // 60}시간 {m % 60}분" if m >= 60 else f"{m}분"


class Facts:
    def __init__(self) -> None:
        self.by_id: dict[str, dict] = {}

    def add(self, fid: str, ftype: str, label: str = "", *, secs=(), **kw) -> dict:
        if not PH.fullmatch("{" + fid + "}"):
            raise ValueError(f"bad fact id {fid}")
        f = {"id": fid, "type": ftype, "label": label, "secs": list(secs), **kw}
        self.by_id[fid] = f
        return f

    def __contains__(self, fid: str) -> bool:
        return fid in self.by_id

    def get(self, fid: str) -> dict:
        return self.by_id[fid]

    def ids(self, pred: Callable[[dict], bool] = lambda f: True) -> list[str]:
        return [k for k, f in self.by_id.items() if pred(f)]

    def llm_view(self, ids) -> list[dict]:
        """LLM에 주는 사실. 별칭·확장 ID·내부 키는 뺀다. 사용자 사실은 이름표도 뺀다(U 번호만)."""
        out = []
        for fid in ids:
            f = self.by_id[fid]
            v = {k: val for k, val in f.items() if k not in _PRIVATE and k != "secs" and val is not None}
            if f["type"] == "user":
                v.pop("label", None)
            out.append(v)
        return out

    def name_view(self, ids) -> list[dict]:
        """이름만(번호·형식·이름표). 기여 사실이 가리키는 사건·문서·사용자를 짧게 줄 때."""
        out = []
        for fid in ids:
            f = self.by_id[fid]
            v = {"id": fid, "type": f["type"]}
            if f["type"] != "user":
                v["label"] = f["label"]
            if f["type"] == "incident":
                v["grade"] = f.get("grade")
            out.append(v)
        return out

    # ------------------------------------------------------------ 렌더
    def value_text(self, f: dict, which: str = "value") -> str:
        v = f.get(which)
        if v is None:
            raise RenderError(f"{f['id']} has no {which}")
        t = f["type"]
        if t in ("count", "share"):
            return _num(v, f.get("unit", "건"))
        if t == "rate":
            return f"{v:.1f}%"
        if t == "time":
            u = _time_unit(v)
            return _time(v, u) + u
        raise RenderError(f"{f['id']} is not numeric")

    def render_one(self, fid: str, form: str | None) -> str:
        f = self.by_id.get(fid)
        if f is None:
            raise RenderError(f"unknown {fid}")
        t = f["type"]
        if form is None:
            if t in ("count", "rate", "time"):
                return f"{f['label']} {self.value_text(f)}"
            if t == "share":
                of = self.by_id[f["of"]]
                return f"{of['label']} {self.value_text(of)} 중 {self.value_text(f)}"
            if t == "ts":
                return f["value"]
            if t == "span":
                return span_text(f["value"])
            if t == "change":
                tail = f"({f.get('before') or '없음'}→{f.get('after') or '없음'})" if ("before" in f or "after" in f) else ""
                return f"{f['at']} {f['label']}{tail}"
            if t == "user":
                return f["display"]
            return f["label"]
        if form not in FORMS.get(t, ()):
            raise RenderError(f"{fid} form {form}")
        if form == "값":
            return self.value_text(f)
        if form == "이전":
            return self.value_text(f, "prev")
        if form == "비율":
            den = self.by_id.get(f.get("denom") or "")
            if den is None:
                raise RenderError(f"{fid} has no denom")
            d = den["value"]
            pct = f"{(f['value'] / d * 100) if d else 0:.1f}%"
            if f.get("ratio_label"):     # 사용자 건수: 분모 이름표까지 - '차단 전체 43건 중 26건(60.5%)'
                return f"{den['label']} {self.value_text(den)} 중 {self.value_text(f)}({pct})"
            return f"{pct}({f['value']:,}/{d:,})"
        # 변화 - 방향 낱말은 렌더러만 쓴다
        v, p = f.get("value"), f.get("prev")
        if p is None or v is None:
            raise RenderError(f"{fid} has no prev")
        if t == "count":
            u = f.get("unit", "건")
            d = v - p
            if d == 0:
                return f"같음({_num(v, u)})"
            return f"{_num(abs(d), u)} {'늘어남' if d > 0 else '줄어듦'}({_num(p)}→{_num(v)})"
        if t == "rate":
            d = round(v, 1) - round(p, 1)
            if abs(d) < 0.05:
                return f"같음({v:.1f}%)"
            return f"{abs(d):.1f}%p {'높아짐' if d > 0 else '낮아짐'}({p:.1f}→{v:.1f}%)"
        u = _time_unit(v, p)
        a, b = _time(p, u), _time(v, u)
        if a == b:
            return f"같음({b}{u})"
        diff = _time(abs(v - p), u)
        return f"{diff}{u} {'늘어남' if v > p else '줄어듦'}({a}→{b}{u})"

    def render(self, text: str) -> str:
        """자리표시를 바꾸고 바로 뒤 조사를 받침에 맞춘다. 잘못된 자리표시는 RenderError(검사기가 먼저 거른다)."""
        out, pos = [], 0
        for m in PH.finditer(text):
            out.append(text[pos:m.start()])
            rendered = self.render_one(m.group(1), m.group(2))
            out.append(rendered)
            pos = m.end()
            jm = _JOSA.match(text, pos)
            if jm:
                out.append(fix_josa(rendered, jm.group(1)))
                pos = jm.end()
        out.append(text[pos:])
        return "".join(out)


# ---------------------------------------------------------------- 조사 맞춤

_JOSA = re.compile(r"(으로|로|이|가|은|는|을|를|과|와)(?![가-힣])")
_PAIRS = {"이": ("이", "가"), "가": ("이", "가"), "은": ("은", "는"), "는": ("은", "는"), "을": ("을", "를"),
          "를": ("을", "를"), "과": ("과", "와"), "와": ("과", "와"), "으로": ("으로", "로"), "로": ("으로", "로")}
_DIGIT_JONG = {"0": 21, "1": 8, "2": 0, "3": 16, "4": 0, "5": 0, "6": 1, "7": 8, "8": 8, "9": 0}  # 영 일 이 삼 사 오 육 칠 팔 구


def _jong(word: str) -> int | None:
    """끝 글자 받침 번호(0 없음, 8 ㄹ). 닫는 괄호·따옴표·말줄임은 건너뛴다."""
    for ch in reversed(word.strip()):
        if ch in ")]}'\"…·%>":
            if ch == "%":
                return 0   # 퍼센트
            continue
        if "가" <= ch <= "힣":
            return (ord(ch) - 0xAC00) % 28
        if ch in _DIGIT_JONG:
            return _DIGIT_JONG[ch]
        if ch.isalpha():
            return 8 if ch.lower() in "lr" else (16 if ch.lower() in "mn" else 0)
        return 0
    return 0


def fix_josa(word: str, josa: str) -> str:
    with_b, without = _PAIRS[josa]
    j = _jong(word)
    if josa in ("으로", "로"):
        return "로" if j in (0, 8) else "으로"
    return with_b if j else without


def placeholders(text: str) -> list[tuple[str, str | None]]:
    return [(m.group(1), m.group(2)) for m in PH.finditer(text)]


def strip_placeholders(text: str) -> str:
    return PH.sub(" ", text)


# ---------------------------------------------------------------- 사실 만들기

def _svc_id(svc: str) -> str:
    return ag.SERVICE_IDS.get(svc) or re.sub(r"[^A-Z0-9]+", "_", svc.upper()).strip("_") or "OTHER"


def event_count_facts(a: dict) -> list[tuple]:
    """(번호, 이름표, 단위, 섹션, 술어, 분모) - 이번·이전 기간 이벤트에 같은 술어를 쓴다(숫자 출처 하나)."""
    F = ag.CARD_FILTERS
    specs = [
        ("F_TOTAL", "검사", "건", ("S1", "S2"), lambda e: True, None),
        ("F_PROMPT", "프롬프트 검사", "건", ("S1", "S2"), lambda e: e["ct"] == "prompt", "F_TOTAL"),
        ("F_FILE", "파일 검사", "건", ("S1", "S2"), lambda e: e["ct"] == "file", "F_TOTAL"),
        ("F_SECRET", "기밀 차단", "건", ("S1", "S3"), F["secret"], "F_TOTAL"),
        ("F_SECRET_DOC", "기밀 차단(문서 일치)", "건", ("S1", "S3"), lambda e: e["action"] == "BLOCK" and e["cat"] == "doc", "F_SECRET"),
        ("F_SECRET_KW", "기밀 차단(키워드)", "건", ("S1", "S3"), lambda e: e["action"] == "BLOCK" and e["cat"] == "keyword", "F_SECRET"),
        ("F_MASK", "개인정보 마스킹", "건", ("S1", "S2", "S4"), F["mask"], "F_TOTAL"),
        ("F_PII_BLOCK", "개인정보 차단", "건", ("S1", "S4"), F["pii_block"], "F_TOTAL"),
        ("F_UNINSP_BLOCK", "검사 불가 차단", "건", ("S1", "S2", "S9"), F["uninsp_block"], "F_TOTAL"),
        ("F_UNCHECKED", "검사 없이 통과", "건", ("S1", "S2", "S9"), F["unchecked"], "F_TOTAL"),
        ("F_ALLOW", "문제 없음 허용", "건", ("S1", "S2"), F["allow_clean"], "F_TOTAL"),
        ("F_BLOCK", "차단 전체", "건", ("S2",), lambda e: e["action"] == "BLOCK", "F_TOTAL"),
        ("F_ALLOW_ALL", "허용 전체", "건", ("S2",), lambda e: e["action"] == "ALLOW", "F_TOTAL"),
        ("F_PROMPT_BLOCK", "프롬프트 차단", "건", ("S2",), lambda e: e["ct"] == "prompt" and e["action"] == "BLOCK", "F_PROMPT"),
        ("F_PROMPT_MASK", "프롬프트 마스킹", "건", ("S2",), lambda e: e["ct"] == "prompt" and e["action"] == "MASK", "F_PROMPT"),
        ("F_FILE_BLOCK", "파일 차단", "건", ("S2",), lambda e: e["ct"] == "file" and e["action"] == "BLOCK", "F_FILE"),
        ("F_FILE_MASK", "파일 마스킹", "건", ("S2",), lambda e: e["ct"] == "file" and e["action"] == "MASK", "F_FILE"),
        ("F_MASK_FAIL", "마스킹 실패 차단", "건", ("S4",), lambda e: e["action"] == "BLOCK" and e["cat"] == "mask_failed", "F_PII_BLOCK"),
        ("F_CRED", "인증정보 포함", "건", ("S4",), lambda e: e["cred"], "F_TOTAL"),
        ("F_UNIDENT", "식별 안 됨 검사", "건", ("S6",), lambda e: not e["ident"], "F_TOTAL"),
    ]
    svcs = sorted({e["svc"] for e in a["events"]} | {e["svc"] for e in (a.get("prev_events") or [])})
    for s in svcs:
        sid = _svc_id(s)
        specs.append((f"F_SVC_{sid}", f"{s} 검사", "건", ("S2",), (lambda s: lambda e: e["svc"] == s)(s), "F_TOTAL"))
        specs.append((f"F_SVC_{sid}_BLOCK", f"{s} 차단", "건", ("S2",),
                      (lambda s: lambda e: e["svc"] == s and e["action"] == "BLOCK")(s), f"F_SVC_{sid}"))
    for p in a["cur"]["pii"]:
        specs.append((f"F_T_{p['code']}", f"{p['name']} 포함", "건", ("S4",),
                      (lambda t: lambda e: t in e["ents"])(p["code"]), "F_TOTAL"))
    fmts = sorted({e["fmt"] for e in a["events"] if e["ct"] == "file"})
    for fmt in fmts:
        fid = re.sub(r"[^A-Z0-9]+", "_", fmt.upper()) or "ETC"
        if not re.fullmatch(r"[A-Z0-9_]+", fid):
            fid = "IMAGE" if fmt == "이미지" else "ETC"
        specs.append((f"F_FMT_{fid}", f"{fmt} 파일", "건", ("S4",),
                      (lambda f: lambda e: e["ct"] == "file" and e["fmt"] == f)(fmt), "F_FILE"))
        specs.append((f"F_FMT_{fid}_MASK", f"{fmt} 파일 마스킹", "건", ("S4",),
                      (lambda f: lambda e: e["ct"] == "file" and e["fmt"] == f and e["action"] == "MASK")(fmt), f"F_FMT_{fid}"))
    for rc in sorted(a["cur"]["unchecked_by_rc"]):
        fid = re.sub(r"[^A-Z0-9]+", "_", (rc or "NONE").upper())
        specs.append((f"F_UNCHK_{fid}", f"{ag.RC_LABELS.get(rc, rc)} 통과", "건", ("S9",),
                      (lambda r: lambda e: F["unchecked"](e) and e["rc"] == r)(rc), "F_UNCHECKED"))
    return specs


def build(a: dict, incidents: list[Incident], users: list[dict], *, issues: list[dict] | None = None,
          local: dict | None = None, content: dict | None = None) -> Facts:
    """집계·사건·사용자·이슈·(내용 경향) → 사실 목록."""
    fx = Facts()
    local = local or {}
    prev_ev = a.get("prev_events")
    cur, prev = a["cur"], a["prev"]
    preds: dict[str, Callable] = {}

    for fid, label, unit, secs, pred, denom in event_count_facts(a):
        v = sum(1 for e in a["events"] if pred(e))
        p = sum(1 for e in prev_ev if pred(e)) if prev_ev is not None else None
        if fid.startswith(("F_SVC_", "F_T_", "F_FMT_", "F_UNCHK_")) and not v and not p:
            continue
        fx.add(fid, "count", label, secs=secs, value=v, prev=p, unit=unit, denom=denom if denom in fx else None)
        preds[fid] = pred

    def rate(fid, label, secs, num, den):
        fn, fd = fx.get(num), fx.get(den)
        v = fn["value"] / fd["value"] * 100 if fd["value"] else 0.0
        p = (fn["prev"] / fd["prev"] * 100 if fd["prev"] else 0.0) if fn["prev"] is not None else None
        fx.add(fid, "rate", label, secs=secs, value=round(v, 2), prev=None if p is None else round(p, 2))

    rate("F_MASK_RATE", "마스킹 비율", ("S2", "S4"), "F_MASK", "F_TOTAL")
    rate("F_BLOCK_RATE", "차단 비율", ("S2",), "F_BLOCK", "F_TOTAL")
    rate("F_SECRET_RATE", "기밀 차단 비율", ("S3",), "F_SECRET", "F_TOTAL")

    # 기밀정보(S3)
    docs = cur["docs"]
    fx.add("F_DOCS_HIT", "count", "기밀 차단 문서", secs=("S3",), value=len(docs),
           prev=len(prev["docs"]) if prev else None, unit="종")
    new = ag.new_docs(a)
    fx.add("F_DOCS_NEW", "count", "새로 차단된 문서", secs=("S3",), value=len(new), prev=None, unit="종")
    active = [d for d in a["documents"] if d.get("status") == "active"]
    fx.add("F_DOCS_REG", "count", "등록 문서", secs=("S3",), value=len(active), prev=None, unit="종")
    kw = local.get("keywords")
    if kw:
        fx.add("F_KW_APPROVED", "count", "승인 키워드", secs=("S3",), value=kw["approved"], prev=None, unit="개")
        fx.add("F_KW_PENDING", "count", "승인 대기 키워드", secs=("S3",), value=kw["pending"], prev=None, unit="개")
    doc_ids = {}
    for n, d in enumerate(docs, 1):
        did = f"D{n}"
        doc_ids[d["doc"]] = did
        fx.add(did, "doc", d["doc"], secs=("S3",), events=d["n"], days=d["days"], new=d["doc"] in new,
               same_text_max=None if d["same_max"] is None else st.format_summary(d["same_max"]),
               same_text_unavailable=d["same_na"] or None)
        fx.add(f"{did}.N", "count", "차단", secs=("S3",), value=d["n"],
               prev=next((x["n"] for x in prev["docs"] if x["doc"] == d["doc"]), 0) if prev else None, unit="건")

    # 사용자(S6)
    user_ids = {u["client"]: u["id"] for u in users}
    fx.add("F_USERS", "count", "식별 사용자", secs=("S6",), value=len(users),
           prev=len(prev["ident_users"]) if prev else None, unit="명")
    fx.add("F_USERS_HIGH", "count", "규칙 등급 높음 사용자", secs=("S6",),
           value=sum(1 for u in users if u["rule_level"] == "높음"), prev=None, unit="명")
    sub = (("EVENTS", "events", "검사", "건"), ("SECRET", "secret", "기밀 차단", "건"), ("DOCS", "docs", "서로 다른 문서", "종"),
           ("CRED", "cred", "인증정보", "건"), ("RETRY", "retry", "차단 뒤 재시도", "건"),
           ("BTA", "block_then_allow", "차단 뒤 허용", "건"), ("BLOCK", "block", "차단", "건"), ("MASK", "mask", "마스킹", "건"),
           ("UNCHECKED", "unchecked", "검사 없이 통과", "건"), ("DAYS", "days", "활동일", "일"))
    aliases = a.get("aliases") or {}
    # 사용자 건수의 분모 = 같은 정의의 기간 전체 값(검사·차단·마스킹·기밀 차단) → {U1.BLOCK|비율}로만 비교(2026-10-16)
    user_denom = {"EVENTS": "F_TOTAL", "BLOCK": "F_BLOCK", "MASK": "F_MASK", "SECRET": "F_SECRET"}
    for u in users:
        fx.add(u["id"], "user", "", secs=("S6",), client=u["client"],
               display=aliases.get(u["client"]) or short_id(u["client"]), rule_level=u["rule_level"],
               incidents=u["incidents"], **{k: u[k] for _, k, _, _ in sub})
        fx.add(f"{u['id']}.BASIS", "basis", basis_rule(u), secs=("S6",), level=u["rule_level"])
        for code, key, label, unit in sub:
            if code == "EVENTS" or u[key]:
                den = user_denom.get(code)
                fx.add(f"{u['id']}.{code}", "count", label, secs=("S6",), value=u[key], prev=None, unit=unit,
                       denom=den if den in fx else None, ratio_label=True if den in fx else None)
    fx.add("UX", "name", "식별 안 됨", secs=("S6",))

    # 사건(S5)
    for inc in incidents:
        steps = _steps(inc, doc_ids)
        fx.add(inc.id, "incident", f"사건 {inc.id[1:]}", secs=("S5",),
               user=inc.user or "미식별", svc=" · ".join(inc.services), grade=GRADE_LABELS[inc.grade],
               start=ag.kst_hm(inc.start), span_min=round(inc.span_min, 1), events=len(inc.members),
               block=inc.count("BLOCK"), mask=inc.count("MASK"), allow=inc.count("ALLOW"),
               allow_after_block=inc.allow_after_block, steps=steps,
               docs=[doc_ids[d] for d in inc.docs if d in doc_ids])
        fx.add(f"{inc.id}.START", "ts", "시작", secs=("S5",), value=ag.kst_hm(inc.start))
        fx.add(f"{inc.id}.SPAN", "span", "길이", secs=("S5",), value=round(inc.span_min, 2))
        fx.add(f"{inc.id}.EVENTS", "count", "요청", secs=("S5",), value=len(inc.members), prev=None, unit="건")
        for code, act, label in (("BLOCK", "BLOCK", "차단"), ("MASK", "MASK", "마스킹"), ("ALLOW", "ALLOW", "허용")):
            if inc.count(act):
                fx.add(f"{inc.id}.{code}", "count", label, secs=("S5",), value=inc.count(act), prev=None, unit="건")
        if inc.retries:
            fx.add(f"{inc.id}.RETRY", "count", "차단 뒤 요청", secs=("S5",), value=inc.retries, prev=None, unit="건")
    by_grade = Counter(i.grade for i in incidents)
    fx.add("F_INC", "count", "사건", secs=("S5",), value=len(incidents), prev=None, unit="건")
    for g, label in GRADE_LABELS.items():
        if by_grade.get(g):
            fx.add(f"F_INC_G{g}", "count", f"{label} 사건", secs=("S5",), value=by_grade[g], prev=None, unit="건")
    fx.add("F_INC_UNIDENT", "count", "미식별 사건", secs=("S5",), value=sum(1 for i in incidents if not i.ident),
           prev=None, unit="건")

    # 설정·정책 변경(S8)
    adm, padm = a["admin"], (prev or {}).get("admin")
    fx.add("F_ADMIN_OPS", "count", "관리 작업", secs=("S8",), value=len(adm["ops"]),
           prev=len(padm["ops"]) if padm else None, unit="건")
    fx.add("F_CHANGES", "count", "설정·정책 변경 작업", secs=("S8",), value=len(adm["changes"]),
           prev=len(padm["changes"]) if padm else None, unit="건")
    fx.add("F_LOGIN_FAIL", "count", "로그인 실패", secs=("S8",), value=adm["login_fail"],
           prev=padm["login_fail"] if padm else None, unit="건")
    fx.add("F_GW_CHANGES", "count", "Gateway 설정 변경", secs=("S8",), value=len(a["gateway"]["changes"]), prev=None, unit="건")
    pol = local.get("policy_changes")
    if pol is not None:
        fx.add("F_POLICY_CHANGES", "count", "탐지 정책 변경", secs=("S8",), value=len(pol), prev=None, unit="건")
    n = 0
    for r in adm["changes"]:
        n += 1
        fx.add(f"E{n}", "change", ag.ADMIN_ACTION_LABELS.get(r["action"], r["action"]) +
               ("" if r["result"] == "SUCCESS" else " 실패"), secs=("S8",), at=ag.kst_hm(r["occurred_at"]))
    for c in a["gateway"]["changes"]:
        n += 1
        fx.add(f"E{n}", "change", f"Gateway 설정 {c['key']}", secs=("S8",), at=ag.kst_hm(c["at"]),
               before=_short(c["before"]), after=_short(c["after"]))
    for c in pol or []:
        n += 1
        fx.add(f"E{n}", "change", f"탐지 정책 {c['target']}", secs=("S8",), at=c["at"],
               before=c.get("before"), after=c.get("after"))
    for c in a["criteria"]:
        if c["inside"]:
            n += 1
            fx.add(f"E{n}", "change", c["label"], secs=("S8",), at=ag.kst_hm(c["at"]), kind="기준 변경")

    # 운영 상태(S9)
    def tfact(fid, label, value, pvalue):
        if value is not None:
            fx.add(fid, "time", label, secs=("S9",), value=round(value, 1), prev=None if pvalue is None else round(pvalue, 1))

    pp = (prev or {}).get("pms") or {}
    tfact("F_P50", "Gateway 처리 시간 중앙값", cur["pms"]["p50"], pp.get("p50") if pp.get("n") else None)
    tfact("F_P95", "Gateway 처리 시간 p95", cur["pms"]["p95"], pp.get("p95") if pp.get("n") else None)
    tfact("F_PMAX", "Gateway 처리 시간 최대", cur["pms"]["max"], pp.get("max") if pp.get("n") else None)
    pd = (prev or {}).get("decisions") or {}
    tfact("F_DET_P50", "검사 서버 판정 시간 중앙값", a["decisions"]["p50"], pd.get("p50"))
    tfact("F_DET_P95", "검사 서버 판정 시간 p95", a["decisions"]["p95"], pd.get("p95"))
    tfact("F_DELAY_P95", "이벤트 수신 지연 p95", cur["delay"]["p95"], ((prev or {}).get("delay") or {}).get("p95"))
    fx.add("F_STAGE_ERR", "count", "탐지 단계 오류", secs=("S9",), value=a["decisions"]["err_roots"],
           prev=pd.get("err_roots") if pd else None, unit="건")
    fx.add("F_DEC_ONLY", "count", "판정만 있는 요청", secs=("S9",), value=a["decisions"]["decision_only_n"],
           prev=pd.get("decision_only_n") if pd else None, unit="건")
    fx.add("F_EV_ONLY", "count", "이벤트만 있는 검사 대상", secs=("S9",), value=cur["event_only"],
           prev=prev["event_only"] if prev else None, unit="건")

    if content:
        add_content(fx, content)
    _contrib(fx, a, incidents, user_ids, doc_ids, preds)
    for r in issues or []:
        if not r["off"]:
            fx.add(r["code"], "issue", r["name"], secs=("S10",), level=r["level"], fact=r["fact"],
                   related=[x for x in _related(r["code"], fx, incidents, users, doc_ids, new) if x in fx])
    # 보고서 틀(설계 v3 A1~A5) 사실 - 섹션 태그 없음: 한 장 요약·깔때기·관측 범위만 쓰고 LLM 입력·인용 목록에는 안 간다
    frame.add_facts(fx, a, incidents)
    return fx


def add_content(fx: Facts, content: dict) -> None:
    """내용 경향 G 사실(범주별 건수). 해설 호출은 이것만 보고 표본 글은 못 본다."""
    fx.add("G_SAMPLE", "count", "내용 경향 표본", secs=("S7",), value=content["sample"], prev=None, unit="건")
    fx.add("G_POOL", "count", "글이 저장된 마스킹", secs=("S7",), value=content["pool"], prev=None, unit="건")
    for r in content["rows"]:
        if r["mask"]:
            fx.add(f"G_{r['cat']}.MASK", "count", f"{CAT_NAMES[r['cat']]} 표본", secs=("S7",), value=r["mask"],
                   prev=None, unit="건", subs=[s for s, _ in r["top_subs"]], task=[t for t, _ in r["top_task"]])
        if r["secret"]:
            fx.add(f"G_{r['cat']}.SECRET", "count", f"{CAT_NAMES[r['cat']]} 기밀 차단", secs=("S7",),
                   value=r["secret"], prev=None, unit="건")


def _related(code: str, fx: Facts, incidents: list[Incident], users: list[dict], doc_ids: dict, new: list[str]) -> list[str]:
    """이슈와 관련된 사실 번호 - 권고 문장 섹션 범위(검사 12)와 LLM 입력에 쓴다."""
    if code == "R1":
        return (["F_SECRET", "F_SECRET_DOC", "F_SECRET_KW", "F_KW_PENDING"] + list(doc_ids.values())
                + [i.id for i in incidents if i.grade == 1] + [u["id"] for u in users if u["secret"]])
    if code == "R2":
        return ["F_DOCS_NEW"] + [doc_ids[d] for d in new if d in doc_ids]
    if code == "R3":
        return (["F_CRED"] + [f"F_T_{t}" for t in ag.CREDENTIAL_TYPES]
                + [i.id for i in incidents if i.grade == 2] + [u["id"] for u in users if u["cred"]])
    if code == "R4":
        return ["F_UNCHECKED"] + fx.ids(lambda f: f["id"].startswith("F_UNCHK_")) + [i.id for i in incidents if i.grade == 3]
    if code == "R5":
        return ["F_MASK_FAIL"]
    if code == "R6":
        return ["F_DEC_ONLY", "F_EV_ONLY"]
    if code == "R7":
        return ["F_STAGE_ERR"]
    if code == "R8":
        return ["F_CHANGES", "F_GW_CHANGES", "F_POLICY_CHANGES"] + fx.ids(lambda f: f["type"] == "change")
    return []


def _short(v: Any) -> str:
    s = "없음" if v is None else (("켬" if v else "끔") if isinstance(v, bool) else str(v))
    return s if len(s) <= 40 else s[:39] + "…"


def _steps(inc: Incident, doc_ids: dict[str, str]) -> list[str]:
    """구성원 역할 → 고정 문구(사용자 글 없음). 연속 같은 문구는 ×n으로 접는다."""
    raw = []
    for m in inc.members:
        e = m.e
        if m.role == "FIRST":
            ds = [doc_ids[d] for d in e["docs"] if d in doc_ids]
            raw.append(event_label(e) + (" " + "·".join(ds) if ds else ""))
        elif m.role in ("CHANGED", "OTHER_TARGET"):
            raw.append(f"{ROLE_LABELS[m.role]}({event_label(e)})")
        else:
            raw.append(ROLE_LABELS[m.role])
    out: list[str] = []
    for s in raw:
        if out and (out[-1] == s or out[-1].startswith(s + " ×")):
            base, _, cnt = out[-1].partition(" ×")
            out[-1] = f"{base} ×{int(cnt or 1) + 1}"
        else:
            out.append(s)
    return out


def _contrib(fx: Facts, a: dict, incidents: list[Incident], user_ids: dict, doc_ids: dict, preds: dict) -> None:
    """기여 사실 K: 변화가 있는 지표마다 사건·사용자·문서·서비스별 몫 상위 3개(코드가 계산, v2 4.6-a)."""
    inc_of = {m.e["id"]: inc.id for inc in incidents for m in inc.members}
    k = 0
    for fid, pred in preds.items():
        f = fx.get(fid)
        if f["prev"] is None or f["value"] == f["prev"] or not f["value"]:
            continue
        groups: Counter = Counter()
        order = {}
        for e in a["events"]:
            if not pred(e):
                continue
            keys = []
            if e["id"] in inc_of:
                keys.append(("inc", inc_of[e["id"]]))
            keys.append(("user", user_ids.get(e["client"], "UX") if e["ident"] else "UX"))
            for d in e["docs"]:
                if d in doc_ids:
                    keys.append(("doc", doc_ids[d]))
            keys.append(("svc", e["svc"]))
            for key in keys:
                groups[key] += 1
        rank = {"inc": 0, "user": 1, "doc": 2, "svc": 3}
        top = sorted(groups.items(), key=lambda x: (-x[1], rank[x[0][0]], str(x[0][1])))[:3]
        for (dim, by), n in top:
            k += 1
            fx.add(f"K{k}", "share", f"{f['label']} 중 {by}", secs=f["secs"], of=fid, value=n,
                   unit=f.get("unit", "건"), by=by if dim != "svc" else None, by_service=by if dim == "svc" else None)
