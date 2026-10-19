"""python -m reporting --from 2026-10-01 --to 2026-10-13 [--out 파일] [--no-llm] [--content-trend|--no-content-trend]
                      [--blind] [--note 문장 ...] [--env-file pg.env] [--no-local-api]

기간은 한국 날짜 [from, to) - to 날짜는 포함하지 않는다. DSN은 DETECTION_PG_DSN(pg.env)을 쓴다.
단계: 집계(이벤트 1건·한국 시각) → 사건 묶기·사용자 사실 → 사실 목록 → (LLM) 작업 5가지 → 검사 → 대체 문장 합치기 →
HTML + 생성 기록 JSON(가린 글·LLM 입력은 저장 안 함) → 보고서가 켠 GPU는 끔.
HTML에는 LLM·집계 표시, 인용 번호, 작성 방식을 쓰지 않는다. 문장 출처·인용·버린 문장은 생성 기록 JSON에만 남는다.
LLM이 실패해도 보고서는 집계 문장으로 만든다. 카드 합계가 안 맞으면 파일을 만들지 않고 실패(종료 코드 2).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

from . import content as ct
from . import facts as factmod
from . import gpu, llm, local_api, provenance
from .aggregate import ReportSumError, collect, evaluate_issues, prepare_session
from .compose import Composer, compose_fallback
from .incidents import NARRATED, group, user_facts
from .render import render

OUT_DIR = Path(os.environ.get("REPORT_OUT_DIR", "/opt/detection/reports"))


def load_env_file(path: str) -> None:
    """pg.env 형식(KEY=VALUE, 따옴표 선택)을 읽어 환경에 없는 것만 채운다. 값은 출력하지 않는다."""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        os.environ.setdefault(key, value.strip().strip("'\""))


def content_decision(use_llm: bool, requested: bool | None, global_on: bool) -> tuple[bool, str, str | None]:
    """(켬 여부, 상태, 생성 기록 메모). 전역 꺼짐이면 요청이 켬이어도 끔 - 'off(전역)'."""
    if not use_llm:
        return False, "no_llm", None
    if not global_on:
        return False, "off_global", "off(전역)" if requested else None
    if requested is False:
        return False, "off", None
    return True, "on", None


def llm_lines(doc: dict) -> tuple[int, list[str]]:
    """남은 LLM 문장 수, 대체 문장으로 채운 섹션(LLM을 시도했는데)."""
    kept, fell = 0, []
    if doc["summary"]["src"] in ("llm", "partial"):
        kept += sum(1 for x in doc["summary"]["lines"] if x["src"] == "llm")
    if doc["summary"]["src"] != "llm":
        fell.append("S1")
    for s, block in doc["commentary"].items():
        n = sum(1 for x in block["lines"] if x["src"] == "llm")
        kept += n
        if block["src"] != "llm" and block.get("attempted", True) and (s != "S7" or doc["content"].get("rows")):
            fell.append(s)
    narr_fb = False
    for n in doc["narr"].values():
        lines = [*(n.get("course") or []), n.get("result"), n.get("risk")]
        kept += sum(1 for x in lines if x and x["src"] == "llm")
        narr_fb |= n.get("src") != "llm"
    if narr_fb or doc.get("rank_src") != "llm" and doc["narr"]:
        fell.append("S5")
    user_fb = False
    for t in doc["user_text"].values():
        kept += sum(1 for x in t.get("lines") or [] if x["src"] == "llm")
    user_fb = any(t.get("src") != "llm" for t in list(doc["user_text"].values())[:10])
    if user_fb:
        fell.append("S6")
    rec_fb = False
    for r in doc["recs"]:
        if r["line"]["src"] == "llm":
            kept += 1
        else:
            rec_fb = True
    if rec_fb:
        fell.append("S10")
    return kept, fell


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="reporting")
    p.add_argument("--from", dest="start", required=True, type=date.fromisoformat)
    p.add_argument("--to", dest="end", required=True, type=date.fromisoformat)
    p.add_argument("--out")
    p.add_argument("--no-llm", action="store_true")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--content-trend", dest="content_trend", action="store_true", default=None,
                   help="내용 경향 포함(전역 REPORT_CONTENT_TREND가 on일 때만)")
    g.add_argument("--no-content-trend", dest="content_trend", action="store_false")
    p.add_argument("--blind", action="store_true",
                   help="LLM판·집계판 비교 파일 2벌도 만든다(HTML에는 어느 쪽인지 안 써 있고 생성 기록 JSON의 blind에만 있음)")
    p.add_argument("--note", action="append", default=[], help="참고 사항에 덧붙일 문장")
    p.add_argument("--env-file", help="KEY=VALUE 파일(pg.env). 탐지 API가 이 명령을 자식 프로세스로 띄울 때 쓴다")
    p.add_argument("--no-local-api", action="store_true", help="Detection 로컬 API(정책·키워드·상태)를 읽지 않는다")
    args = p.parse_args(argv)
    if args.env_file:
        load_env_file(args.env_file)

    out_path = Path(args.out) if args.out else OUT_DIR / f"report_{args.start}_{args.end}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    progress_path = out_path.with_suffix(".progress")
    report_id = out_path.stem

    def progress(stage: str, done: int | None = None, total: int | None = None) -> None:
        """진행 단계 - 생성 API(jobs.status)가 읽어 대시보드에 보여 준다."""
        body = {"stage": stage} if done is None else {"stage": stage, "llm_done": done, "llm_total": total}
        try:
            progress_path.write_text(json.dumps(body), encoding="utf-8")
        except OSError:
            pass

    use_llm = not args.no_llm
    content_on, content_state, content_note = content_decision(use_llm, args.content_trend, ct.global_enabled())

    progress("aggregating")
    t0 = time.perf_counter()
    import psycopg

    items_info = None
    try:
        with psycopg.connect(os.environ["DETECTION_PG_DSN"], autocommit=True) as conn:
            prepare_session(conn)
            a = collect(conn, args.start, args.end)
            if content_on:   # 끄면 가린 글 열을 아예 읽지 않는다
                items_info = ct.build_items(conn, a["events"], a["t0"], a["t1"])
    except ReportSumError as exc:
        print(f"합계 불일치: {exc}", file=sys.stderr)
        return 2
    agg_ms = (time.perf_counter() - t0) * 1000

    local = {}
    if not args.no_local_api:
        local = {"keywords": local_api.keyword_counts(),
                 "policy_changes": local_api.policy_changes(a["t0"], a["t1"]),
                 "system": local_api.system_status()}
    progress("incidents")
    incidents = group(a["events"])
    users = user_facts(a["events"], incidents)
    issues = evaluate_issues(a, policy_changes=len(local.get("policy_changes") or []))
    fx = factmod.build(a, incidents, users, issues=issues, local=local)

    doc_sql = compose_fallback(a, fx, incidents, users, issues)
    doc, llm_ms, err, gpu_state = doc_sql, None, None, None
    if use_llm:
        gpu_state = gpu.ensure_ready(llm.LLM_URL.rsplit("/chat/completions", 1)[0] + "/models",
                                     progress=lambda s: progress(s))
        err = gpu_state["error"]
        if gpu_state["ready"]:
            progress("llm", 0, 0)
            items = (items_info or {}).get("items") or []
            comp = Composer(a, fx, incidents, users, issues, content_items=items,
                            content_pool=(items_info or {}).get("pool", 0),
                            registered_docs=[d for d in a["documents"] if d.get("status") == "active"],
                            progress=lambda d, t: progress("llm", d, t))
            t1 = time.perf_counter()
            try:
                doc = comp.run(content_on=content_on)
            except Exception as exc:  # noqa: BLE001 - 조합 단계 오류도 집계 문장으로 계속
                err, doc = f"{type(exc).__name__}: {str(exc)[:200]}", doc_sql
            llm_ms = (time.perf_counter() - t1) * 1000
    if content_on:
        if doc is doc_sql:
            reason = "GPU 응답 없음" if gpu_state and not gpu_state["ready"] else "LLM 단계 실패"
            doc_sql["content"] = {"rows": None, "state": "failed", "reason": reason}
            content_state = "failed"
        elif doc["content"].get("rows"):
            content_state = "on"
        else:
            content_state = doc["content"].get("state") or "no_sample"

    kept, fell = llm_lines(doc) if doc is not doc_sql else (0, [])
    dropped = doc["dropped"]
    if not use_llm:
        writer, mode = "집계 문장 (LLM 미사용)", "sql"
    elif doc is doc_sql:
        writer, mode = "집계 문장 (LLM 호출 실패)", "sql"
    else:
        mode = "partial" if fell else "llm"
        writer = f"{llm.LLM_MODEL} · LLM {kept}문장 · 버림 {len(dropped)}" + (" · 일부 집계 문장" if fell else "")
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    rows = (doc["content"].get("rows") if isinstance(doc["content"], dict) else None) or []
    meta = {"notes": args.note, "stamp": f"생성 {stamp}", "content_state": content_state,
            "system": local.get("system"),
            "content_note": (f"내용 경향 표본 {doc['content'].get('sample')}/{doc['content'].get('pool')}건(가린 글만)"
                             if rows else None)}
    progress("rendering")
    out_path.write_text(render(a, fx, incidents, users, issues, doc, meta), encoding="utf-8")

    blind = None
    if args.blind:
        pair = {"llm": doc, "sql": doc_sql}
        order = ["llm", "sql"] if secrets.randbelow(2) == 0 else ["sql", "llm"]
        blind = {"A": order[0], "B": order[1]}
        for label, kind in blind.items():
            m = dict(meta, blind=True)
            out_path.with_name(f"{report_id}.blind-{label}.html").write_text(
                render(a, fx, incidents, users, issues, pair[kind], m), encoding="utf-8")

    stop = None
    if use_llm and gpu_state and gpu_state.get("started"):
        progress("gpu_stopping_after")
        stop = gpu.auto_stop(gpu_state, busy=lambda: local_api.gpu_busy(report_id))
    usage = {}
    for c in doc["calls"]:
        for k, v in (c.get("usage") or {}).items():
            if isinstance(v, (int, float)):
                usage[k] = usage.get(k, 0) + v
    levels = doc["levels"]
    log = {
        "out": str(out_path), "from": str(args.start), "to": str(args.end),
        "compare_from": str(a["prev_start"]) if a["comparable"] else None,
        "compare_to": str(a["prev_end"]) if a["comparable"] else None,
        "use_llm": use_llm, "llm_used": doc is not doc_sql, "mode": mode, "writer": writer,
        "content_trend": {"requested": args.content_trend, "effective": content_on, "state": content_state,
                          "note": content_note,
                          **({"reason": doc["content"]["reason"]} if doc["content"].get("reason") else {})},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "items": a["cur"]["cards"]["total"], "rows": a["decisions"]["rows"], "excluded": a["excluded"],
        "cards": {k: v for k, v in a["cur"]["cards"].items()},
        "agg_ms": round(agg_ms), "llm_ms": round(llm_ms) if llm_ms else None, "usage": usage, "llm_error": err,
        "gpu": dict(gpu_state or {}, auto_stop=stop) if gpu_state else None,
        "calls": doc["calls"], "kept": kept, "dropped": dropped, "fallback_sections": fell,
        "sources": {"summary": doc["summary"]["src"], **{s: b["src"] for s, b in doc["commentary"].items()},
                    "rank": doc.get("rank_src"), "recs": "llm" if any(r["line"]["src"] == "llm" for r in doc["recs"]) else "sql"},
        "incidents": {"total": len(incidents), "narrated": min(NARRATED, len(doc["order"])),
                      "by_grade": {str(g): sum(1 for i in incidents if i.grade == g) for g in range(1, 6)}},
        "users": len(users), "users_high": sum(1 for v in levels.values() if v == "높음"),
        "content": ({"sample": doc["content"].get("sample"), "pool": doc["content"].get("pool"),
                     "rows": [{"cat": r["cat"], "mask": r["mask"], "secret": r["secret"]} for r in rows],
                     "classified": doc["content"].get("classified"), "batch_hashes": doc["content"].get("batch_hashes")}
                    if rows else None),
        "blind": blind,
        "provenance": provenance.collect(doc),
    }
    out_path.with_suffix(".json").write_text(json.dumps(log, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    progress_path.unlink(missing_ok=True)
    print(json.dumps({k: v for k, v in log.items() if k not in ("dropped", "calls", "content", "provenance")}, ensure_ascii=False,
                     default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
