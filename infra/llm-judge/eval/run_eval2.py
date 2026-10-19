"""2·3단계 실험 — 프롬프트 v2(값 나열 → 대조 → 결론, 압축 출력) / s1(Y·N 한 글자) — GPU 인스턴스에서 실행.

    /opt/judge/.venv/bin/python run_eval2.py --mode v2 --eval eval_v1.jsonl --run-id v2
    /opt/judge/.venv/bin/python run_eval2.py --mode s1 --eval eval_v1.jsonl --run-id s1

프롬프트 조립(user_message)·인용 위치 계산(find_ws)·저장 표는 run_eval.py(base-v1)와 같다.
- v2: 출력 순서 input_values → matched → contains → candidate → 인용(40자). 판정 이유·확신도 없음.
      출력 순서는 스키마 properties 순서를 따른다(확인됨). 공백 없는 JSON 옵션(disable_any_whitespace,
      whitespace_pattern)은 vLLM 0.29 기본 백엔드에서 무시돼 적용되지 않았다 — 요청에 남겨 두되 효과 없음.
- s1: 최대 1토큰. 'Y'/'N' 상위 로그확률로 포함 확률(p_yes)을 함께 기록. 결론은 둘 중 큰 쪽(문턱값 조정 없음).
"""
import argparse
import hashlib
import json
import math
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run_eval import DDL, find_ws, model_name, user_message  # noqa: E402

VLLM = "http://127.0.0.1:8000/v1/chat/completions"
MODES = {"v2": ("prompt_v2.txt", "judge-prompt-v2"), "s1": ("prompt_s1.txt", "judge-s1-v2")}
SCHEMA_V2 = {
    "type": "object",
    "properties": {
        "input_values": {"type": "array", "items": {"type": "string", "maxLength": 30}, "maxItems": 6},
        "matched": {"type": "array", "items": {"type": "string", "maxLength": 30}, "maxItems": 6},
        "contains": {"type": "boolean"},
        "candidate": {"type": ["integer", "null"], "minimum": 1, "maximum": 3},
        "doc_quote": {"type": ["string", "null"], "maxLength": 40},
        "input_quote": {"type": ["string", "null"], "maxLength": 40},
    },
    "required": ["input_values", "matched", "contains", "candidate", "doc_quote", "input_quote"],
    "additionalProperties": False,
}


def call(body, timeout):
    req = urllib.request.Request(VLLM, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), int((time.perf_counter() - t) * 1000), None
    except TimeoutError:
        return None, int((time.perf_counter() - t) * 1000), "timeout"
    except (urllib.error.URLError, OSError) as e:
        detail = e.read().decode("utf-8", "replace")[:300] if hasattr(e, "read") else str(e)
        return None, int((time.perf_counter() - t) * 1000), f"error: {detail}"


def base_body(item, system):
    return {"model": "qwen3-8b", "temperature": 0, "top_p": 1, "seed": 0,
            "chat_template_kwargs": {"enable_thinking": False},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_message(item)}]}


def judge_v2(item, system, timeout):
    body = {**base_body(item, system), "max_tokens": 300,
            "structured_outputs": {"json": SCHEMA_V2, "disable_any_whitespace": True}}
    resp, ms, err = call(body, timeout)
    if err:
        return {"status": "timeout" if err == "timeout" else "error", "raw_output": err, "elapsed_ms": ms}
    raw = resp["choices"][0]["message"]["content"]
    out = {"raw_output": raw, "elapsed_ms": ms,
           "tokens_in": resp["usage"]["prompt_tokens"], "tokens_out": resp["usage"]["completion_tokens"]}
    try:
        o = json.loads(raw)
        assert isinstance(o["contains"], bool)
    except Exception:
        return {**out, "status": "schema_error"}
    out.update(contains=int(o["contains"]), evidence=json.dumps(o.get("matched"), ensure_ascii=False))
    if not o["contains"]:
        return {**out, "status": "ok"}
    cands, ci = item["candidates"], o.get("candidate")
    if not isinstance(ci, int) or not 1 <= ci <= len(cands):
        return {**out, "status": "schema_error", "contains": None}
    c = cands[ci - 1]
    dpos, ipos = find_ws(c["text"], o.get("doc_quote")), find_ws(item["input_text"], o.get("input_quote"))
    out["doc_id"] = c["doc_id"]
    if dpos is None or ipos is None:
        return {**out, "status": "invalid_quote", "contains": None}
    base = int(c["span"].split("-")[0])
    out["doc_span"], out["input_span"] = f"{base + dpos[0]}-{base + dpos[1]}", f"{ipos[0]}-{ipos[1]}"
    return {**out, "status": "ok"}


def judge_s1(item, system, timeout):
    body = {**base_body(item, system), "max_tokens": 1, "logprobs": True, "top_logprobs": 10}
    resp, ms, err = call(body, timeout)
    if err:
        return {"status": "timeout" if err == "timeout" else "error", "raw_output": err, "elapsed_ms": ms}
    ch = resp["choices"][0]
    tok = ch["message"]["content"] or ""
    # 'Y'와 ' Y'처럼 공백만 다른 토큰이 따로 나온다. 공백을 떼고 합칠 때 가장 높은 값을 남긴다
    # (처음 구현은 뒤의 낮은 값이 덮어써 p_yes가 뒤집혔다 — 2026-09-21 시험 실행에서 발견).
    lp = {}
    for t in ch["logprobs"]["content"][0]["top_logprobs"]:
        k = t["token"].strip()
        lp[k] = max(lp.get(k, -math.inf), t["logprob"])
    y, n = lp.get("Y", -math.inf), lp.get("N", -math.inf)
    out = {"elapsed_ms": ms, "tokens_in": resp["usage"]["prompt_tokens"],
           "tokens_out": resp["usage"]["completion_tokens"]}
    if y == -math.inf and n == -math.inf:
        return {**out, "status": "schema_error", "raw_output": json.dumps({"token": tok, "top": lp}, ensure_ascii=False)}
    p_yes = 1 / (1 + math.exp(n - y)) if y != -math.inf and n != -math.inf else (1.0 if n == -math.inf else 0.0)
    contains = p_yes > 0.5
    raw = json.dumps({"contains": contains, "p_yes": round(p_yes, 4), "token": tok}, ensure_ascii=False)
    return {**out, "status": "ok", "contains": int(contains), "raw_output": raw, "evidence": f"p_yes={p_yes:.4f}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=list(MODES), required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--db", default="/opt/judge/data/judge.sqlite3")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=120)
    a = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    fname, prompt_version = MODES[a.mode]
    system = (HERE / fname).read_text(encoding="utf-8").rstrip("\n")
    prompt_sha = hashlib.sha256(system.encode()).hexdigest()
    judge = judge_v2 if a.mode == "v2" else judge_s1
    model = model_name()
    db = sqlite3.connect(a.db)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(DDL)

    items = [json.loads(x) for x in Path(a.eval).read_text(encoding="utf-8").splitlines() if x.strip()]
    if a.limit:
        items = items[: a.limit]
    done = {r[0] for r in db.execute("SELECT decision_id FROM judgments WHERE model=? AND prompt_version=?",
                                     (model, prompt_version))}
    todo = [it for it in items if it["item_id"] not in done]
    print(f"mode={a.mode} model={model} prompt={prompt_version} sha={prompt_sha[:12]} 전체 {len(items)} · 남은 {len(todo)}")
    t0 = time.time()
    for k, it in enumerate(todo, 1):
        r = judge(it, system, a.timeout)
        text = it["input_text"]
        db.execute(
            "INSERT OR IGNORE INTO judgments (decision_id, source, run_id, ts, status, contains, doc_id, doc_span,"
            " input_span, evidence, confidence, candidates, input_sha256, input_chars, raw_output, tokens_in,"
            " tokens_out, elapsed_ms, model, prompt_version, prompt_sha256, input_text, candidates_text)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (it["item_id"], "eval", a.run_id, time.time(), r["status"], r.get("contains"), r.get("doc_id"),
             r.get("doc_span"), r.get("input_span"), r.get("evidence"), None,
             json.dumps([{"doc_id": c["doc_id"], "span": c["span"]} for c in it["candidates"]], ensure_ascii=False),
             hashlib.sha256(text.encode()).hexdigest(), len(text), r.get("raw_output"), r.get("tokens_in"),
             r.get("tokens_out"), r.get("elapsed_ms"), model, prompt_version, prompt_sha, text,
             json.dumps(it["candidates"], ensure_ascii=False)))
        db.commit()
        if k % 10 == 0 or k == len(todo):
            el = time.time() - t0
            print(f"  {k}/{len(todo)}  경과 {el/60:.1f}분  남은 예상 {el/k*(len(todo)-k)/60:.1f}분  마지막 {it['item_id']} {r['status']}")
    print("완료")


if __name__ == "__main__":
    main()
