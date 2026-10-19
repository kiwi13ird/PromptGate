"""평가셋을 vLLM(Qwen3-8B)에 돌려 판정을 judge.sqlite3에 저장한다 — GPU 인스턴스에서 실행.

judge-api가 할 일(프롬프트 조립 → 구조화 출력 호출 → 인용 위치 계산 → 저장)을 같은 규칙으로 수행한다.
설계: docs/pipelines/llm-judge-serving-design.md §3.1·§4·§5

    /opt/judge/.venv/bin/python run_eval.py --eval eval_v1.jsonl --run-id base-v1 [--limit 3]

- 멱등: (decision_id, model, prompt_version)이 이미 있으면 건너뛴다 → 끊겨도 다시 실행하면 이어서 한다.
- 표준 라이브러리만 쓴다.
"""
import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
VLLM = "http://127.0.0.1:8000/v1/chat/completions"
PROMPT_VERSION = "judge-prompt-v1"
SCHEMA = {
    "type": "object",
    "properties": {
        "contains": {"type": "boolean"},
        "candidate": {"type": ["integer", "null"], "minimum": 1, "maximum": 3},
        "doc_quote": {"type": ["string", "null"], "maxLength": 80},
        "input_quote": {"type": ["string", "null"], "maxLength": 80},
        "evidence": {"type": "string", "maxLength": 200},
        "confidence": {"type": "string", "enum": ["high", "low"]},
    },
    "required": ["contains", "candidate", "doc_quote", "input_quote", "evidence", "confidence"],
    "additionalProperties": False,
}
DDL = """
CREATE TABLE IF NOT EXISTS judgments (
    id INTEGER PRIMARY KEY, decision_id TEXT NOT NULL, source TEXT NOT NULL, run_id TEXT, ts REAL NOT NULL,
    status TEXT NOT NULL, contains INTEGER, doc_id TEXT, doc_span TEXT, input_span TEXT, evidence TEXT,
    confidence TEXT, candidates TEXT, input_sha256 TEXT NOT NULL, input_chars INTEGER NOT NULL,
    input_truncated INTEGER NOT NULL DEFAULT 0, raw_output TEXT, tokens_in INTEGER, tokens_out INTEGER,
    elapsed_ms INTEGER, model TEXT NOT NULL, prompt_version TEXT NOT NULL, prompt_sha256 TEXT NOT NULL,
    input_text TEXT, candidates_text TEXT, UNIQUE (decision_id, model, prompt_version));
CREATE INDEX IF NOT EXISTS judgments_ts ON judgments (ts);
CREATE INDEX IF NOT EXISTS judgments_run ON judgments (source, run_id);
CREATE INDEX IF NOT EXISTS judgments_contains ON judgments (contains);
"""


def model_name():
    v = dict(line.split("=", 1) for line in Path("/opt/judge/VERSIONS").read_text().split("\n") if "=" in line)
    return f"{v['model_repo']}@{v['model_revision']}"


def user_message(item):
    parts = ["[입력]", "<<<", item["input_text"], ">>>", "", "[후보]"]
    for i, c in enumerate(item["candidates"], 1):
        parts += [f"({i}) doc_id={c['doc_id']} span={c['span']}", "<<<", c["text"], ">>>"]
    return "\n".join(parts)


def find_ws(hay, needle):
    """공백 차이를 무시하고 needle을 hay에서 찾아 (시작, 끝) 원문 좌표를 돌려준다. 없으면 None."""
    if not needle:
        return None
    idx = [i for i, ch in enumerate(hay) if not ch.isspace()]
    h = "".join(hay[i] for i in idx)
    n = re.sub(r"\s+", "", needle)
    if not n:
        return None
    k = h.find(n)
    if k < 0:
        return None
    return idx[k], idx[k + len(n) - 1] + 1


def judge(item, system, timeout):
    body = {
        "model": "qwen3-8b",
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_message(item)}],
        "temperature": 0, "top_p": 1, "seed": 0, "max_tokens": 300,
        "chat_template_kwargs": {"enable_thinking": False},
        "response_format": {"type": "json_schema", "json_schema": {"name": "judge", "schema": SCHEMA}},
    }
    req = urllib.request.Request(VLLM, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.load(r)
    except TimeoutError:
        return {"status": "timeout", "elapsed_ms": int((time.perf_counter() - t) * 1000)}
    except (urllib.error.URLError, OSError) as e:
        detail = e.read().decode("utf-8", "replace")[:300] if hasattr(e, "read") else str(e)
        return {"status": "error", "raw_output": detail, "elapsed_ms": int((time.perf_counter() - t) * 1000)}
    ms = int((time.perf_counter() - t) * 1000)
    raw = resp["choices"][0]["message"]["content"]
    out = {"raw_output": raw, "elapsed_ms": ms,
           "tokens_in": resp["usage"]["prompt_tokens"], "tokens_out": resp["usage"]["completion_tokens"]}
    try:
        o = json.loads(raw)
        assert isinstance(o["contains"], bool) and o["confidence"] in ("high", "low")
    except Exception:
        return {**out, "status": "schema_error"}
    out.update(contains=int(o["contains"]), evidence=o.get("evidence"), confidence=o["confidence"])
    if not o["contains"]:
        return {**out, "status": "ok"}
    cands = item["candidates"]
    ci = o.get("candidate")
    if not isinstance(ci, int) or not 1 <= ci <= len(cands):
        return {**out, "status": "schema_error", "contains": None}
    c = cands[ci - 1]
    dpos, ipos = find_ws(c["text"], o.get("doc_quote")), find_ws(item["input_text"], o.get("input_quote"))
    out["doc_id"] = c["doc_id"]
    if dpos is None or ipos is None:
        return {**out, "status": "invalid_quote", "contains": None}
    base = int(c["span"].split("-")[0])
    out["doc_span"] = f"{base + dpos[0]}-{base + dpos[1]}"
    out["input_span"] = f"{ipos[0]}-{ipos[1]}"
    return {**out, "status": "ok"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--db", default="/opt/judge/data/judge.sqlite3")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=120)
    a = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    system = (HERE / "prompt_v1.txt").read_text(encoding="utf-8").rstrip("\n")
    prompt_sha = hashlib.sha256(system.encode()).hexdigest()
    model = model_name()
    Path(a.db).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(a.db)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(DDL)
    Path(a.db).chmod(0o600)

    items = [json.loads(line) for line in Path(a.eval).read_text(encoding="utf-8").splitlines() if line.strip()]
    if a.limit:
        items = items[: a.limit]
    done = {r[0] for r in db.execute("SELECT decision_id FROM judgments WHERE model=? AND prompt_version=?",
                                     (model, PROMPT_VERSION))}
    todo = [it for it in items if it["item_id"] not in done]
    print(f"model={model} prompt={PROMPT_VERSION} sha={prompt_sha[:12]} 전체 {len(items)} · 남은 {len(todo)}")
    t0 = time.time()
    for n, it in enumerate(todo, 1):
        r = judge(it, system, a.timeout)
        text = it["input_text"]
        db.execute(
            "INSERT OR IGNORE INTO judgments (decision_id, source, run_id, ts, status, contains, doc_id, doc_span,"
            " input_span, evidence, confidence, candidates, input_sha256, input_chars, raw_output, tokens_in,"
            " tokens_out, elapsed_ms, model, prompt_version, prompt_sha256, input_text, candidates_text)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (it["item_id"], "eval", a.run_id, time.time(), r["status"], r.get("contains"), r.get("doc_id"),
             r.get("doc_span"), r.get("input_span"), r.get("evidence"), r.get("confidence"),
             json.dumps([{"doc_id": c["doc_id"], "span": c["span"]} for c in it["candidates"]], ensure_ascii=False),
             hashlib.sha256(text.encode()).hexdigest(), len(text), r.get("raw_output"), r.get("tokens_in"),
             r.get("tokens_out"), r.get("elapsed_ms"), model, PROMPT_VERSION, prompt_sha, text,
             json.dumps(it["candidates"], ensure_ascii=False)))
        db.commit()
        if n % 10 == 0 or n == len(todo):
            el = time.time() - t0
            print(f"  {n}/{len(todo)}  경과 {el/60:.1f}분  남은 예상 {el/n*(len(todo)-n)/60:.1f}분  마지막 {it['item_id']} {r['status']}")
    print("완료")


if __name__ == "__main__":
    main()
