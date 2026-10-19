"""문장 출처 기록 - 보고서 HTML에는 쓰지 않고 생성 기록 JSON(`<id>.json`)에만 남긴다 (2026-10-12 사용자 지적).

HTML은 일반 보고서처럼 읽혀야 한다: LLM·집계 이름표, 인용 번호, 작성 방식을 화면에 쓰지 않는다.
어느 문장이 LLM에서 왔고 어떤 사실 번호를 인용했는지, 순위·등급·조치를 누가 정했는지는 여기서 모아 JSON에 넣는다.
버린 문장과 이유는 생성 기록의 `dropped`에 따로 있다(compose.py).
"""

from __future__ import annotations


def _sentence(sec: str, kind: str, line: dict | None, **extra) -> dict | None:
    if not line:
        return None
    return {"sec": sec, "kind": kind, "src": line.get("src", "sql"), "text": line.get("text"),
            "cites": list(line.get("cites") or []), "tpl": line.get("tpl"), **extra}


def collect(doc: dict) -> dict:
    """compose 결과(doc) → {sentences, rank, levels, actions}. 순서는 보고서 섹션 순서."""
    out: list[dict] = []

    def add(sec, kind, line, **extra):
        s = _sentence(sec, kind, line, **extra)
        if s:
            out.append(s)

    summary = doc.get("summary") or {}
    for ln in summary.get("lines") or []:
        add("S1", "summary", ln, block_src=summary.get("src"))
    for sec, block in (doc.get("commentary") or {}).items():
        for ln in block.get("lines") or []:
            add(sec, "commentary", ln, block_src=block.get("src"))
    for iid, n in (doc.get("narr") or {}).items():
        for ln in n.get("course") or []:
            add("S5", "incident_course", ln, incident=iid)
        add("S5", "incident_result", n.get("result"), incident=iid)
        add("S5", "incident_risk", n.get("risk"), incident=iid)
    levels = []
    for uid, t in (doc.get("user_text") or {}).items():
        for ln in t.get("lines") or []:
            add("S6", "user_why", ln, user=uid)
        levels.append({"user": uid, "level": (doc.get("levels") or {}).get(uid), "level_src": t.get("level_src"),
                       "note": t.get("note")})
    actions = []
    for r in doc.get("recs") or []:
        add("S10", "recommendation", r.get("line"), issue=r.get("issue"))
        actions.append({"issue": r.get("issue"), "action": r.get("action"), "target": r.get("target"),
                        "action_src": r.get("action_src")})
    return {"sentences": out,
            "rank": {"src": doc.get("rank_src"), "note": doc.get("rank_note"), "order": list(doc.get("order") or [])},
            "levels": levels, "actions": actions}
