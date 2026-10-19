"""LLM 작업 5가지 → 검사 → 대체 문장 합치기 (설계 v2 4.6, 4.9, 4.13).

순서: 1차(사건 순위·해설 A·사용자 위험·문서 범주·표본 분류, 동시 4) → 2차(사건 서술·해설 B) → 3차(요약·권고).
호출 하나가 실패·시간 초과·JSON 오류면 그 작업 섹션만 대체 문장. LLM 단계 전체 상한(420초)을 넘긴 호출도 대체 문장.
대체 문장은 LLM과 같은 자리표시 렌더러를 쓴다 - 숫자 출처가 하나.
설계 v3 B1·B2(문장 글자 문법)는 기본 켬, REPORT_LLM_TEXT_GRAMMAR=off로 끈다(llm.py).
"""

from __future__ import annotations

import math
import os
import re
import time
import urllib.parse
from typing import Any, Callable

from . import llm, verify
from . import content as ct
from .aggregate import kst_hm
from .facts import SECTION_NAMES, Facts, add_content
from .incidents import GRADE_LABELS, NARRATED, Incident, basis_labels, candidates, event_label, rule_order

COMMENT_A = ("S2", "S3", "S4")
# 사용자 호출에 함께 주는 기간 전체 값(사용자 건수 비율의 분모, facts.py user_denom과 같은 것)
USER_PERIOD = ("F_TOTAL", "F_BLOCK", "F_MASK", "F_SECRET")
COMMENT_B = ("S7", "S8", "S9")
PRIMARY = {
    "S2": ("F_TOTAL", "F_BLOCK", "F_MASK", "F_ALLOW_ALL", "F_PROMPT", "F_FILE"),
    "S3": ("F_SECRET", "F_SECRET_DOC", "F_SECRET_KW", "F_DOCS_HIT", "F_DOCS_NEW"),
    "S4": ("F_MASK", "F_PII_BLOCK", "F_MASK_FAIL", "F_CRED"),
    "S8": ("F_ADMIN_OPS", "F_CHANGES", "F_GW_CHANGES", "F_POLICY_CHANGES", "F_LOGIN_FAIL"),
    "S9": ("F_UNCHECKED", "F_UNINSP_BLOCK", "F_STAGE_ERR", "F_DEC_ONLY", "F_EV_ONLY"),
}
ACTIONS = {
    "BLOCK_USER": "이 사용자 차단", "USER_EVENTS": "사용자 기록 보기", "DOC_EVENTS": "문서 차단 이력",
    "CREDENTIAL_EVENTS": "인증정보 이벤트 확인", "KEYWORD_PENDING": "승인 대기 키워드 처리", "DOC_REGISTER": "보호 문서 등록",
    "GATEWAY_SETTINGS": "Gateway 처리 설정 확인", "REQUIRE_ID": "확장 ID 없는 접속 검토", "POLICY_CHECK": "탐지 정책 확인",
    "SYSTEM_CHECK": "시스템 상태 확인", "NONE": "조치 없음",
}
LINK_BASE = os.environ.get("REPORT_LINK_BASE", "").rstrip("/")
MAX_SEC_FACTS = 14   # 해설 호출 섹션당 지표 수 상한
MAX_K_OF = 3         # 기여 사실을 붙이는 지표 수


def access_block_link_enabled() -> bool:
    """접속 차단 화면(주소로 대화상자 열기)이 운영에 올라간 뒤 on. 그 전에는 BLOCK_USER 대신 사용자 기록 링크(설계 7장)."""
    return os.environ.get("REPORT_ACCESS_BLOCK_LINK", "off").strip().lower() in ("1", "on", "true", "yes")


# ---------------------------------------------------------------- 렌더된 문장

def _line(fx: Facts, template: str, cites=None, src: str = "sql") -> dict:
    from .facts import placeholders
    c = list(dict.fromkeys([*(cites or []), *(p for p, _ in placeholders(template))]))
    return {"text": fx.render(template), "cites": c, "src": src, "tpl": template}


def _changed(fx: Facts, fid: str) -> bool:
    f = fx.by_id.get(fid)
    return bool(f) and f.get("prev") is not None and f["value"] != f["prev"]


def _with_prev(fx: Facts, fid: str) -> str:
    return "{%s}(이전 {%s|이전})" % (fid, fid) if fx.get(fid).get("prev") is not None else "{%s}" % fid


# ---------------------------------------------------------------- 대체 문장 (4.9)

def fallback_summary(fx: Facts) -> list[dict]:
    """v1 규칙: 기밀 차단 → 검사 없이 통과 → 이전 대비 차이 큰 카드."""
    lines = [_line(fx, _with_prev(fx, "F_SECRET") + (" · 문서 일치 {F_SECRET_DOC|값} · 키워드 {F_SECRET_KW|값}"
                                                      if fx.get("F_SECRET")["value"] else "")),
             _line(fx, _with_prev(fx, "F_UNCHECKED"))]
    rest = ["F_TOTAL", "F_MASK", "F_PII_BLOCK", "F_UNINSP_BLOCK", "F_ALLOW"]
    changed = sorted((f for f in rest if _changed(fx, f)),
                     key=lambda f: (-abs(fx.get(f)["value"] - fx.get(f)["prev"]), rest.index(f)))
    third = changed[0] if changed else "F_TOTAL"
    lines.append(_line(fx, "%s {%s|변화}" % (fx.get(third)["label"], third) if changed else _with_prev(fx, third)))
    return lines


def fallback_commentary(fx: Facts, sec: str, content_rows: list[dict] | None = None) -> list[dict]:
    if sec == "S7":
        if not content_rows:
            return []
        top = next((r for r in content_rows if r["mask"]), None)
        return [_line(fx, "{G_%s.MASK}" % top["cat"])] if top else []
    prim = [f for f in PRIMARY.get(sec, ()) if f in fx]
    changed = sorted((f for f in prim if _changed(fx, f)),
                     key=lambda f: (-abs(fx.get(f)["value"] - fx.get(f)["prev"]), prim.index(f)))
    pick = changed[:2] + [f for f in prim if f not in changed][:max(0, 2 - len(changed))]
    return [_line(fx, _with_prev(fx, f)) for f in pick[:2]]


def fallback_incident(fx: Facts, inc: Incident) -> dict:
    """'{사용자} · {시작} · {서비스} · {첫 결과} 뒤 {N}건 · 마지막 {조치}'."""
    who = "{%s}" % inc.user if inc.user else "미식별 사용자"
    first = event_label(inc.members[0].e)
    tail = ""
    if len(inc.members) > 1:
        last = {"BLOCK": "차단", "MASK": "마스킹", "ALLOW": "허용"}[inc.members[-1].e["action"]]
        tail = f" · {first} 뒤 {len(inc.members) - 1}건 · 마지막 {last}"
    else:
        tail = f" · {first}"
    text = f"{who} · {{{inc.id}.START}} · {' · '.join(inc.services)}{tail}"
    return {"course": [_line(fx, text, [inc.id])], "result": None, "risk": None, "src": "sql"}


# ---------------------------------------------------------------- 조치·링크 (4.6-d)

def allowed_actions(code: str, fx: Facts, users: list[dict], levels: dict[str, str], incidents: list[Incident],
                    content_cond: bool) -> dict[str, list[str]]:
    hi_mid = [u for u in users if levels.get(u["id"]) in ("높음", "중간")]
    all_u = [u["id"] for u in users]
    docs = fx.ids(lambda f: f["type"] == "doc")
    out: dict[str, list[str]] = {}
    if code == "R1":
        out["BLOCK_USER"] = [u["id"] for u in hi_mid if u["secret"]]
        out["USER_EVENTS"] = [u["id"] for u in users if u["secret"]] + [u for u in all_u
                                                                       if u not in {x["id"] for x in users if x["secret"]}]
        out["DOC_EVENTS"] = docs
        if "F_KW_PENDING" in fx and fx.get("F_KW_PENDING")["value"]:
            out["KEYWORD_PENDING"] = ["NONE"]
        if fx.get("F_SECRET_KW")["value"] or content_cond:
            out["DOC_REGISTER"] = ["NONE"]
        if any(i.grade == 1 and not i.ident for i in incidents):
            out["REQUIRE_ID"] = ["NONE"]
    elif code == "R2":
        out["DOC_EVENTS"] = [d for d in docs if fx.get(d).get("new")]
        out["USER_EVENTS"] = all_u
    elif code == "R3":
        out["BLOCK_USER"] = [u["id"] for u in hi_mid if u["cred"]]
        out["USER_EVENTS"] = [u["id"] for u in users if u["cred"]] + [u for u in all_u
                                                                     if u not in {x["id"] for x in users if x["cred"]}]
        out["CREDENTIAL_EVENTS"] = ["NONE"]
    elif code == "R4":
        out["GATEWAY_SETTINGS"] = ["NONE"]
        out["USER_EVENTS"] = all_u
    elif code == "R5":
        out["POLICY_CHECK"] = ["NONE"]
        out["USER_EVENTS"] = all_u
    elif code in ("R6", "R7"):
        out["SYSTEM_CHECK"] = ["NONE"]
        out["USER_EVENTS"] = all_u
    elif code == "R8":
        out["NONE"] = ["NONE"]
        out["USER_EVENTS"] = all_u
    return {k: v for k, v in out.items() if v}


def default_action(allowed: dict[str, list[str]]) -> tuple[str, str]:
    """이슈 기본 조치: 조치 표 순서에서 대상이 있는 첫 줄."""
    for code in llm.ACTION_CODES:
        if allowed.get(code):
            return code, allowed[code][0]
    return "NONE", "NONE"


def build_link(action: str, target: str, fx: Facts, a: dict, issue: str) -> dict | None:
    """링크는 코드가 만든다(LLM은 주소를 쓰지 않음). 같은 탭 이동, 경로 글자도 같이 보인다(내려받은 파일용)."""
    q = urllib.parse.quote
    note = None
    if action == "BLOCK_USER" and not access_block_link_enabled():
        action, note = "USER_EVENTS", "접속 차단 화면 반영 전 - 사용자 기록에서 차단"
    if action == "NONE":
        return None
    if action in ("BLOCK_USER", "USER_EVENTS"):
        client = fx.get(target)["client"]
        if action == "BLOCK_USER":
            reason = "LEAK_DOC_REPEAT" if issue == "R1" else "PII_REPEAT"
            path = f"/policies/access?block={q(client, safe='')}&reason={reason}"
        else:
            path = f"/events?q={q(client, safe='')}&period=30D"
    elif action == "DOC_EVENTS":
        path = f"/events?documentId={q(fx.get(target)['label'], safe='')}&period=30D"
    else:
        path = {"CREDENTIAL_EVENTS": "/events?category=CREDENTIAL&period=30D", "KEYWORD_PENDING": "/policies/keywords",
                "DOC_REGISTER": "/documents", "GATEWAY_SETTINGS": "/policies/gateway", "REQUIRE_ID": "/policies/access",
                "POLICY_CHECK": "/policies", "SYSTEM_CHECK": "/system"}[action]
    recent = None
    if "period=30D" in path:
        import datetime as _dt
        age = (_dt.date.today() - a["start"]).days
        if a["days"] > 30 or age > 30:
            recent = "최근 30일"
    return {"action": action, "label": ACTIONS[action], "href": LINK_BASE + path, "path": path,
            "note": note, "recent": recent}


# ---------------------------------------------------------------- 실행

class Composer:
    def __init__(self, a: dict, fx: Facts, incidents: list[Incident], users: list[dict], issues: list[dict], *,
                 content_items: list[dict] | None = None, content_pool: int = 0,
                 registered_docs: list[dict] | None = None,
                 progress: Callable[[int, int], None] = lambda d, t: None, call=llm.call) -> None:
        self.a, self.fx, self.incidents, self.users, self.issues = a, fx, incidents, users, issues
        self.items = content_items or []
        self.pool = content_pool
        self.registered = registered_docs or []
        self.progress = progress
        self.call = call
        self.calls: list[dict] = []
        self.dropped: list[dict] = []
        self.grams = verify.sample_grams([it["text"] for it in self.items])
        self.done = 0
        self.total = 0

    # ------------------------------------------------------------ 사실 묶음
    def _sec_ids(self, sec: str) -> list[str]:
        """해설 호출에 줄 그 섹션 사실 - 8,192토큰 한도 안에 들게 줄인다(4.10).

        지표: 대표 지표(PRIMARY) + 이전 대비 차이 큰 순, 값·이전 값이 모두 0인 것은 뺌, 최대 MAX_SEC_FACTS개.
        기여(K): 차이가 가장 큰 지표 MAX_K_OF개의 몫만(지표마다 상위 3개는 facts.py가 이미 고름). 문서(S3): 차단 많은 순 5종.
        """
        fx = self.fx
        metric = [f for f in fx.by_id.values() if sec in f["secs"] and f["type"] in ("count", "rate", "time")
                  and not re.match(r"[UIDG]\d|G_", f["id"]) and not (not f["value"] and not f.get("prev"))]
        prim = [f["id"] for f in metric if f["id"] in PRIMARY.get(sec, ())]

        def diff(f):
            if f.get("prev") is None:
                return 0.0
            return abs(f["value"] - f["prev"]) / (abs(f["prev"]) or 1.0)

        rest = [f["id"] for f in sorted(metric, key=lambda f: -diff(f)) if f["id"] not in prim]
        ids = (prim + rest)[:MAX_SEC_FACTS]
        changed = sorted((fx.get(i) for i in ids if fx.get(i)["type"] == "count" and _changed(fx, i)),
                         key=lambda f: -abs(f["value"] - f["prev"]))[:MAX_K_OF]
        top = {f["id"] for f in changed}
        ids += [k for k, f in fx.by_id.items() if f["type"] == "share" and f["of"] in top]
        if sec == "S3":
            for d in fx.ids(lambda f: f["type"] == "doc")[:5]:
                ids += [d, f"{d}.N"]
        return ids

    def _refs(self, ids: list[str]) -> list[str]:
        """기여 사실이 가리키는 이름(사건·사용자·문서)."""
        out = []
        for fid in ids:
            by = self.fx.get(fid).get("by")
            if by and by in self.fx and by not in ids and by not in out:
                out.append(by)
        return out

    def _record(self, name: str, task: str, status: str, res: Any) -> None:
        entry = {"name": name, "task": task, "status": status}
        if status == "ok":
            entry.update(ms=res["ms"], usage=res["usage"], prompt=res["prompt"])
        elif status == "error":
            entry["error"] = f"{type(res).__name__}: {str(res)[:160]}"
        self.calls.append(entry)

    def _tick(self, _name: str) -> None:
        self.done += 1
        self.progress(self.done, self.total)

    def _ph(self, ids) -> dict | None:
        """B1·B2: 켜져 있으면 그 호출 번호 → 쓸 수 있는 꼴(문장 글자 문법용). 꺼져 있으면 None(스키마 전과 같음)."""
        return llm.placeholder_forms(self.fx, ids) if llm.text_grammar_on() else None

    # ------------------------------------------------------------ 작업 준비
    def job_commentary(self, secs: tuple[str, ...]):
        sections, allowed, scope = [], set(), {}
        changes = self.fx.ids(lambda f: f["type"] == "change")
        for s in secs:
            ids = self._sec_ids(s) if s != "S7" else self.fx.ids(lambda f: f["id"].startswith("G_"))
            if not ids:     # 쓸 사실이 없는 섹션(전부 0 등)은 부르지 않고 집계 문장
                continue
            refs = self._refs(ids)
            sections.append({"sec": s, "name": SECTION_NAMES[s], "facts": self.fx.llm_view(ids),
                             "names": self.fx.name_view(refs)})
            allowed |= set(ids) | set(refs)
            scope[s] = set(ids)
        allowed |= set(changes)
        payload = {"sections": sections, "changes": self.fx.llm_view(changes)}
        secs_present = [s["sec"] for s in sections]
        schema = llm.schema_commentary(secs_present, sorted(allowed), self._ph(allowed)) if secs_present else None
        return payload, schema, allowed, scope, secs_present, secs

    def run(self, deadline_s: float = llm.STAGE_LIMIT, *, content_on: bool) -> dict:
        t_end = time.monotonic() + deadline_s
        fx = self.fx
        cands = candidates(self.incidents)
        cand_ids = [i.id for i in cands]
        by_id = {i.id: i for i in self.incidents}
        top_users = self.users[:10]
        cmA = self.job_commentary(COMMENT_A)
        doc_ids = fx.ids(lambda f: f["type"] == "doc")
        batches = ct.batches(self.items) if content_on else []
        docs_for_cat = []
        if content_on:
            blocked = {fx.get(d)["label"]: d for d in doc_ids}
            k = 0
            for d in self.registered:
                if d["doc_id"] in blocked:
                    docs_for_cat.append({"id": blocked[d["doc_id"]], "name": d["doc_id"], "_cls": d.get("classification")})
                else:
                    k += 1
                    docs_for_cat.append({"id": f"X{k}", "name": d["doc_id"], "_cls": d.get("classification")})
        # 분류 값이 범주 코드·이름이면 그것을 먼저 쓴다(4.6-e)
        name_to_code = {v: c for c, v in ct.CAT_NAMES.items()}
        preset = {}
        for d in docs_for_cat:
            cls = (d.get("_cls") or "").strip()
            code = cls.upper() if cls.upper() in ct.CAT_CODES else name_to_code.get(cls)
            if code:
                preset[d["id"]] = code
        to_cat = [d for d in docs_for_cat if d["id"] not in preset]

        n_narr = math.ceil(min(NARRATED, len(cands)) / 4) if cands else 0
        self.total = (1 if cands else 0) + (1 if cmA[4] else 0) + (1 if top_users else 0) + (1 if to_cat else 0) + len(batches) \
            + n_narr + 1 + 1
        jobs = []
        if cands:
            payload = {"candidates": [dict(fx.llm_view([i.id])[0], rule_rank=n) for n, i in enumerate(cands, 1)]}
            jobs.append(("rank", lambda p=payload: self.call("rank", p, llm.schema_rank(cand_ids))))
        if cmA[4]:
            jobs.append(("commentary_a", lambda: self.call("commentary", cmA[0], cmA[1])))
        if top_users:
            u_allowed = []
            u_payload = []
            for u in top_users:
                subs = fx.ids(lambda f, uid=u["id"]: f["id"].startswith(uid + "."))
                u_allowed += [u["id"], *subs]
                u_payload.append({"user": fx.llm_view([u["id"]])[0], "facts": fx.llm_view(subs)})
            # 비율의 분모(기간 전체 값)도 보여 준다 - 인용은 되지만 이유 범위(12)는 그 사용자 사실(_merge_users)
            period = [p for p in USER_PERIOD if p in fx]
            u_allowed += period
            u_schema = llm.schema_users([u["id"] for u in top_users], u_allowed, self._ph(u_allowed))
            u_body = {"users": u_payload, "period": fx.llm_view(period)}
            jobs.append(("users", lambda: self.call("users", u_body, u_schema)))
        if to_cat:
            dpay = {"docs": [{"id": d["id"], "name": d["name"]} for d in to_cat]}
            jobs.append(("doccat", lambda: self.call("doccat", dpay, llm.schema_doccat([d["id"] for d in to_cat]))))
        for n, b in enumerate(batches):
            bp = {"items": [{k: it[k] for k in ("i", "path", "fmt", "text")} for it in b]}
            jobs.append((f"classify_{n}", lambda bp=bp, ids=[it["i"] for it in b]:
                         self.call("classify", bp, llm.schema_classify(ids))))
        r1 = llm.run_parallel(jobs, deadline=t_end, on_done=self._tick)
        for name, (status, res) in r1.items():
            self._record(name, name.split("_")[0] if name.startswith("classify") else name, status, res)

        # ---- 1차 결과
        order, rank_note, rank_src = [i.id for i in rule_order(cands)], None, "sql"
        if "rank" in r1 and r1["rank"][0] == "ok":
            grade1 = {i.id for i in cands if i.grade == 1}
            order, rank_note = verify.check_order(r1["rank"][1]["out"].get("order"), [i.id for i in cands], grade1, NARRATED)
            rank_src = "sql" if rank_note and rank_note.startswith("등급 1") else "llm"
        commentary = self._merge_commentary(r1.get("commentary_a"), cmA)
        levels, user_text = self._merge_users(r1.get("users"), top_users)
        content = self._merge_content(content_on, batches, r1, to_cat, preset, docs_for_cat)
        if content.get("rows") is not None:
            add_content(fx, content)

        # ---- 2차: 사건 서술(순위 상위 12건, 4건씩) + 해설 B
        narr_ids = order[:NARRATED]
        jobs2 = []
        narr_batches = [narr_ids[k:k + 4] for k in range(0, len(narr_ids), 4)]
        narr_ctx = []
        for n, ids in enumerate(narr_batches):
            items, allowed = [], set()
            for iid in ids:
                inc = by_id[iid]
                subs = fx.ids(lambda f, iid=iid: f["id"].startswith(iid + "."))
                names = ([inc.user] if inc.user else []) + list(fx.get(iid).get("docs") or [])
                items.append({"incident": fx.llm_view([iid])[0], "facts": fx.llm_view(subs), "names": fx.name_view(names)})
                allowed |= {iid, *subs, *names}
            schema = llm.schema_narrate(ids, sorted(allowed), self._ph(allowed))
            narr_ctx.append((ids, allowed))
            jobs2.append((f"narrate_{n}", lambda p={"incidents": items}, s=schema: self.call("narrate", p, s)))
        cmB = self.job_commentary(COMMENT_B)
        if cmB[4]:
            jobs2.append(("commentary_b", lambda: self.call("commentary", cmB[0], cmB[1])))
        self.total = self.done + len(jobs2) + 1
        r2 = llm.run_parallel(jobs2, deadline=t_end, on_done=self._tick)
        for name, (status, res) in r2.items():
            self._record(name, name.split("_")[0], status, res)
        commentary.update(self._merge_commentary(r2.get("commentary_b"), cmB, content_rows=content.get("rows")))
        narr = {}
        for n, (ids, allowed) in enumerate(narr_ctx):
            narr.update(self._merge_narr(r2.get(f"narrate_{n}"), ids, allowed, by_id))
        for iid in [i.id for i in self.incidents]:
            if iid not in narr and iid in narr_ids:
                narr[iid] = fallback_incident(fx, by_id[iid])

        # ---- 3차: 요약·권고
        content_cond = bool(content.get("unregistered_cats"))
        allowed_by_issue = {r["code"]: allowed_actions(r["code"], fx, self.users, levels, self.incidents, content_cond)
                            for r in self.issues if not r["off"]}
        rec_payload, rec_allowed, rec_schema, rec_scope = self._recs_job(allowed_by_issue, levels, order)
        r3 = llm.run_parallel([("recs", lambda: self.call("recs", rec_payload, rec_schema))], deadline=t_end,
                              on_done=self._tick)
        self._record("recs", "recs", *r3["recs"])
        summary, recs = self._merge_recs(r3["recs"], rec_allowed, rec_scope, allowed_by_issue)

        return {"summary": summary, "commentary": commentary, "order": order, "rank_src": rank_src,
                "rank_note": rank_note, "narr": narr, "levels": levels, "user_text": user_text, "recs": recs,
                "content": content, "calls": self.calls, "dropped": self.dropped}

    # ------------------------------------------------------------ 합치기
    def _verify(self, lines, allowed, scope, section, *, eval_check: bool = False) -> list[dict]:
        ctx = verify.Ctx(self.fx, set(allowed), scope, self.grams, eval_check=eval_check)
        kept, dropped = verify.filter_lines(lines if isinstance(lines, list) else [], ctx, section=section)
        self.dropped += dropped
        return [_line(self.fx, k["t"], k["c"], "llm") for k in kept]

    def _merge_commentary(self, res, job, content_rows=None) -> dict:
        payload, schema, allowed, scope, secs, group = job
        got = {}
        if res and res[0] == "ok":
            for s in res[1]["out"].get("sections") or []:
                if isinstance(s, dict) and s.get("sec") in secs and s["sec"] not in got:
                    got[s["sec"]] = self._verify((s.get("lines") or [])[:3], allowed, scope[s["sec"]], s["sec"])
        out = {}
        # 호출에서 빠진 섹션(S7 표본 없음 등)도 대체 문장 자리를 만든다
        for s in group:
            if got.get(s):
                out[s] = {"src": "llm", "lines": got[s]}
            else:
                out[s] = {"src": "sql", "lines": fallback_commentary(self.fx, s, content_rows),
                          "attempted": s in secs}
        return out

    def _merge_users(self, res, top_users) -> tuple[dict, dict]:
        levels = {u["id"]: u["rule_level"] for u in self.users}
        text = {u["id"]: {"src": "sql", "lines": [], "level_src": "rule", "note": None} for u in self.users}
        if not res or res[0] != "ok":
            return levels, text
        top = {u["id"]: u for u in top_users}
        seen = set()
        for item in res[1]["out"].get("users") or []:
            if not isinstance(item, dict) or item.get("id") not in top or item["id"] in seen:
                continue
            uid = item["id"]
            seen.add(uid)
            own = {uid, *self.fx.ids(lambda f: f["id"].startswith(uid + "."))}
            allowed = own | {p for p in USER_PERIOD if p in self.fx}
            kept = self._verify((item.get("why") or [])[:3], allowed, own, "S6", eval_check=True)
            level, why = verify.check_level(uid, str(item.get("level")), top[uid]["rule_level"],
                                            [{"c": k["cites"]} for k in kept])
            if why:
                self.dropped.append({"section": "S6", "line": f"{uid} 등급 {item.get('level')}", "why": why})
            levels[uid] = level
            text[uid] = {"src": "llm" if kept else "sql", "lines": kept, "level_src": "rule" if why else "llm",
                         "note": why}
        return levels, text

    def _merge_narr(self, res, ids, allowed, by_id) -> dict:
        out = {}
        if not res or res[0] != "ok":
            return out
        for item in res[1]["out"].get("items") or []:
            if not isinstance(item, dict) or item.get("id") not in ids or item["id"] in out:
                continue
            iid = item["id"]
            scope = {iid, *self.fx.ids(lambda f: f["id"].startswith(iid + "."))}
            course = self._verify((item.get("course") or [])[:2], allowed, scope, "S5")
            result = self._verify([item.get("result")], allowed, scope, "S5") if item.get("result") else []
            risk = self._verify([item.get("risk")], allowed, scope, "S5") if item.get("risk") else []
            if not course and not result and not risk:
                continue
            if not course:
                course = fallback_incident(self.fx, by_id[iid])["course"]
            out[iid] = {"course": course, "result": result[0] if result else None, "risk": risk[0] if risk else None,
                        "src": "llm"}
        return out

    def _merge_content(self, content_on, batches, r1, to_cat, preset, docs_for_cat) -> dict:
        if not content_on:
            return {"rows": None}
        if not self.items:
            return {"rows": None, "state": "no_sample"}
        classified, failed, hashes = [], 0, []
        for n, b in enumerate(batches):
            hashes.append(ct.batch_hash(b))
            res = r1.get(f"classify_{n}")
            if not res or res[0] != "ok":
                failed += len(b)
                continue
            got = {}
            for it in res[1]["out"].get("items") or []:
                if not isinstance(it, dict) or it.get("i") not in {x["i"] for x in b} or it["i"] in got:
                    continue
                cat = it.get("cat") if it.get("cat") in ct.CAT_CODES else None
                task = it.get("task") if it.get("task") in ct.TASK_CODES else "OTHER"
                if cat is None:
                    continue
                got[it["i"]] = {"cat": cat, "sub": ct.fix_sub(cat, str(it.get("sub"))), "task": task}
            failed += len(b) - len(got)
            classified += [got[x["i"]] for x in b if x["i"] in got]
        if not classified:
            return {"rows": None, "state": "failed", "reason": "분류 호출 실패"}
        cats = dict(preset)
        res = r1.get("doccat")
        if res and res[0] == "ok":
            ok_ids = {d["id"] for d in to_cat}
            for d in res[1]["out"].get("docs") or []:
                if isinstance(d, dict) and d.get("id") in ok_ids and d.get("cat") in ct.CAT_CODES:
                    cats.setdefault(d["id"], d["cat"])
        doc_cats = {}
        for d in docs_for_cat:
            if d["id"] in cats:
                doc_cats[d["name"]] = cats[d["id"]]
        rows = ct.tally(classified, doc_cats, self.a["events"])
        reg_cats = set(doc_cats.values())
        unregistered = [r["cat"] for r in rows if r["mask"] and r["cat"] not in reg_cats and r["cat"] not in ("ETC", "PERSONAL")]
        return {"rows": rows, "state": "on", "sample": len(self.items), "pool": self.pool, "failed": failed,
                "classified": [{k: c[k] for k in ("cat", "sub", "task")} for c in classified],
                "batch_hashes": hashes, "doc_cats_known": bool(res and res[0] == "ok") or bool(preset),
                "unregistered_cats": unregistered}

    def _recs_job(self, allowed_by_issue, levels, order):
        fx = self.fx
        cards = fx.ids(lambda f: "S1" in f["secs"] and f["type"] == "count")
        issues = [r for r in self.issues if not r["off"]]
        allowed = set(cards) | {r["code"] for r in issues}
        scope = {}
        iss_payload = []
        targets = set()
        for r in issues:
            rel = fx.get(r["code"]).get("related") or []
            allowed |= set(rel)
            scope[r["code"]] = {r["code"], *rel}
            acts = allowed_by_issue.get(r["code"], {})
            for v in acts.values():
                targets |= {t for t in v if t != "NONE"}
            iss_payload.append({**fx.llm_view([r["code"]])[0], "actions": acts})
        top = [i for i in order[:5]]
        allowed |= set(top) | set(levels) | targets
        names = sorted({x for x in allowed if x.startswith(("D", "U")) and x in fx and "." not in x})
        payload = {"cards": fx.llm_view(cards), "issues": iss_payload,
                   "incidents": fx.name_view(top), "users": [{"id": u, "level": lv} for u, lv in levels.items()],
                   "names": fx.name_view(names)}
        allowed = {x for x in allowed if x in fx}
        schema = llm.schema_recs([r["code"] for r in issues], sorted(targets), sorted(allowed), self._ph(allowed))
        return payload, allowed, schema, scope

    def _merge_recs(self, res, allowed, scope, allowed_by_issue) -> tuple[dict, list[dict]]:
        fx = self.fx
        fb = fallback_summary(fx)
        summary = {"src": "sql", "lines": fb}
        got = {}
        if res[0] == "ok":
            out = res[1]["out"]
            kept = self._verify((out.get("summary") or [])[:3], allowed, None, "S1")
            if kept:
                lines = kept[:]
                for line in fb:
                    if len(lines) >= 3:
                        break
                    if not any(set(line["cites"]) & set(k["cites"]) for k in lines):
                        lines.append(line)
                summary = {"src": "llm" if len(kept) >= 3 else "partial", "lines": lines[:3]}
            for r in out.get("recs") or []:
                if not isinstance(r, dict) or r.get("issue") not in scope or r["issue"] in got:
                    continue
                code = r["issue"]
                kept = self._verify([r.get("line")], allowed, scope[code], "S10")
                action, target = str(r.get("action")), str(r.get("target"))
                why = verify.check_action(action, target, allowed_by_issue.get(code, {}))
                if why:
                    self.dropped.append({"section": "S10", "line": f"{code} {action}→{target}", "why": why})
                    action, target = default_action(allowed_by_issue.get(code, {}))
                got[code] = {"line": kept[0] if kept else None, "action": action, "target": target,
                             "action_src": "sql" if why else "llm"}
        recs = []
        for r in self.issues:
            if r["off"]:
                continue
            code = r["code"]
            g = got.get(code)
            if g is None:
                action, target = default_action(allowed_by_issue.get(code, {}))
                g = {"line": None, "action": action, "target": target, "action_src": "sql"}
            line = g["line"] or {"text": r["scope"], "cites": [code], "src": "sql", "tpl": r["scope"]}
            recs.append({"issue": code, "name": r["name"], "level": r["level"], "fact": r["fact"], "line": line,
                         "action": g["action"], "target": g["target"], "action_src": g["action_src"],
                         "link": build_link(g["action"], g["target"], fx, self.a, code)})
        return summary, recs


def compose_fallback(a: dict, fx: Facts, incidents: list[Incident], users: list[dict], issues: list[dict]) -> dict:
    """LLM 없이 전부 집계 문장(LLM 끔·블라인드 비교용 집계판)."""
    levels = {u["id"]: u["rule_level"] for u in users}
    order = [i.id for i in rule_order(candidates(incidents))]
    narr = {iid: fallback_incident(fx, next(i for i in incidents if i.id == iid)) for iid in order[:NARRATED]}
    commentary = {s: {"src": "sql", "lines": fallback_commentary(fx, s)} for s in (*COMMENT_A, *COMMENT_B)}
    content_cond = False
    recs = []
    for r in issues:
        if r["off"]:
            continue
        allowed = allowed_actions(r["code"], fx, users, levels, incidents, content_cond)
        action, target = default_action(allowed)
        recs.append({"issue": r["code"], "name": r["name"], "level": r["level"], "fact": r["fact"],
                     "line": {"text": r["scope"], "cites": [r["code"]], "src": "sql", "tpl": r["scope"]},
                     "action": action, "target": target, "action_src": "sql",
                     "link": build_link(action, target, fx, a, r["code"])})
    return {"summary": {"src": "sql", "lines": fallback_summary(fx)}, "commentary": commentary, "order": order,
            "rank_src": "sql", "rank_note": None, "narr": narr, "levels": levels,
            "user_text": {u["id"]: {"src": "sql", "lines": [], "level_src": "rule", "note": None} for u in users},
            "recs": recs, "content": {"rows": None}, "calls": [], "dropped": []}
