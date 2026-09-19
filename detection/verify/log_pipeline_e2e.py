"""운영 경로 확인 - 실제 /detect → decisions.jsonl → detection-logshipper → RDS decisions.

python -m verify.log_pipeline_e2e functional   기능: 차단·통과·같은 요청 번호 2번·빈 번호·번호 없음 → 응답과 DB 행 비교
python -m verify.log_pipeline_e2e load N C TAG 동시 C로 N건 보내고 응답 시간 분포 출력
python -m verify.log_pipeline_e2e wait         전송 서비스가 밀린 것을 다 보낼 때까지 대기(최대 60초)
python -m verify.log_pipeline_e2e rows TAG     요청 번호가 TAG로 시작하는 DB 행 수
요청 번호는 모두 e2e-0915- 로 시작한다(나중에 지우기 쉽게).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from detection_service.pg_store import _default_connect
from detection_service.pipeline import preprocess

API = "http://127.0.0.1:8000"
VERIFY = Path(__file__).resolve().parent
PREFIX = "e2e-0915-"


def post(body: dict) -> tuple[int, dict, float]:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(API + "/detect", data=data, headers={"content-type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()), time.perf_counter() - t
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}"), time.perf_counter() - t


def health() -> dict:
    with urllib.request.urlopen(API + "/health", timeout=5) as r:
        return json.loads(r.read())


def db_rows(where: str, params: tuple) -> list[dict]:
    conn = _default_connect(os.environ["DETECTION_PG_DSN"])
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT decision_id::text, request_id, service, format, text_chars, blocked, decided_by, doc_id, "
                        "doc_span, input_span, score, pii_hits, reason, hash_status, signature_status, total_ms, prompt "
                        f"FROM decisions WHERE {where} ORDER BY ts", params)
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    finally:
        conn.close()


def wait(max_s: float = 60) -> dict:
    t = time.time()
    while time.time() - t < max_s:
        sync = health().get("log_sync") or {}
        # 상태 파일은 약 1초마다 갱신된다 - 대기를 시작한 뒤 2초 이상 지나 쓰인 상태만 믿는다
        if sync.get("pending_bytes") == 0 and (sync.get("updated_ts") or 0) > t + 2:
            return {"waited_s": round(time.time() - t, 1), **sync}
        time.sleep(0.5)
    return {"waited_s": None, **(health().get("log_sync") or {})}


def functional() -> int:
    run = uuid.uuid4().hex[:6]
    cases = []
    for name in ("unrelated", "nda_300", "payroll_1500", "payroll_row_tab"):
        body = json.loads((VERIFY / f"{name}.json").read_text(encoding="utf-8"))
        body["request_id"] = f"{PREFIX}{run}-{name}"
        body["source"] = {"service": "e2e", "format": "verify"}
        cases.append((name, body))
    dup_id = f"{PREFIX}{run}-dup"
    cases.append(("dup_1", {"request_id": dup_id, "normalized_text": "같은 요청 번호 첫 번째 입력", "source": {"service": "e2e"}}))
    cases.append(("dup_2", {"request_id": dup_id, "normalized_text": "같은 요청 번호 두 번째 입력", "source": {"service": "e2e"}}))
    results = {}
    for name, body in cases:
        results[name] = (body, *post(body))
    empty = post({"request_id": "", "normalized_text": f"빈 번호 {run}"})[0]
    missing = post({"normalized_text": f"번호 없음 {run}"})[0]
    synced = wait()

    report = {"run": run, "empty_id_status": empty, "missing_id_status": missing, "sync": synced, "cases": {}}
    ok = empty == 422 and missing == 422 and synced["waited_s"] is not None
    for name, (body, status, resp, _) in results.items():
        # 저장되는 prompt는 탐지 API가 정규화한 본문이다(탭→공백 등)
        rows = db_rows("request_id = %s AND prompt = %s", (body["request_id"], preprocess(body["normalized_text"])))
        fields_bad = []
        if len(rows) == 1:
            row = rows[0]
            for k in ("request_id", "blocked", "decided_by", "doc_id", "doc_span", "input_span", "pii_hits", "reason", "hash_status", "signature_status"):
                if row[k] != resp[k]:
                    fields_bad.append(k)
            for k in ("score", "total_ms"):
                if (row[k] is None) != (resp[k] is None) or (row[k] is not None and abs(row[k] - resp[k]) > 1e-3):
                    fields_bad.append(k)
        report["cases"][name] = {"http": status, "blocked": resp.get("blocked"), "decided_by": resp.get("decided_by"),
                                 "doc_id": resp.get("doc_id"), "doc_span": resp.get("doc_span"), "db_rows": len(rows),
                                 "field_mismatch": fields_bad}
        ok = ok and status == 200 and len(rows) == 1 and not fields_bad
    dup_rows = db_rows("request_id = %s", (dup_id,))
    report["dup_rows_in_db"] = len(dup_rows)
    report["dup_distinct_decision_ids"] = len({r["decision_id"] for r in dup_rows})
    ok = ok and len(dup_rows) == 2 and report["dup_distinct_decision_ids"] == 2
    report["ok"] = ok
    print(json.dumps(report, ensure_ascii=False, indent=1))
    return 0 if ok else 1


def load(n: int, conc: int, tag: str) -> int:
    texts = [json.loads((VERIFY / f"{x}.json").read_text(encoding="utf-8"))["normalized_text"]
             for x in ("unrelated", "nda_300", "payroll_row_tab")]
    lat: list[float] = []
    codes: dict[int, int] = {}
    lock = threading.Lock()
    counter = iter(range(n))

    def worker():
        while True:
            with lock:
                i = next(counter, None)
            if i is None:
                return
            status, _, dt = post({"request_id": f"{PREFIX}{tag}-{i}", "normalized_text": texts[i % 3],
                                  "source": {"service": "e2e-load"}})
            with lock:
                lat.append(dt)
                codes[status] = codes.get(status, 0) + 1

    t = time.perf_counter()
    th = [threading.Thread(target=worker) for _ in range(conc)]
    for x in th:
        x.start()
    for x in th:
        x.join()
    wall = time.perf_counter() - t
    lat.sort()
    pct = lambda p: round(lat[min(len(lat) - 1, int(p * len(lat)))] * 1000, 1)
    print(json.dumps({"tag": tag, "n": n, "concurrency": conc, "codes": codes, "p50_ms": pct(0.5), "p95_ms": pct(0.95),
                      "p99_ms": pct(0.99), "max_ms": round(lat[-1] * 1000, 1), "wall_s": round(wall, 2)}))
    return 0


def rows(tag: str) -> int:
    conn = _default_connect(os.environ["DETECTION_PG_DSN"])
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), count(DISTINCT decision_id) FROM decisions WHERE request_id LIKE %s", (f"{PREFIX}{tag}-%",))
        n, d = cur.fetchone()
    conn.close()
    print(json.dumps({"tag": tag, "db_rows": n, "distinct_decision_ids": d}))
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "functional":
        sys.exit(functional())
    if cmd == "load":
        sys.exit(load(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))
    if cmd == "wait":
        print(json.dumps(wait()))
        sys.exit(0)
    if cmd == "rows":
        sys.exit(rows(sys.argv[2]))
