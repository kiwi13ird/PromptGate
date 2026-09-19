"""전송 서비스 실 RDS 시험 - 운영 표 대신 임시 표 decisions_shiptest에 쓰고, 끝나면 지운다.

실행(Detection EC2): set -a; . /opt/detection/pg.env; set +a
                    PYTHONPATH=<src> <venv>/bin/python -m verify.log_shipper_rds_check

A. 동시 쓰기 8스레드 × 500줄 + 작은 회전 크기 + 전송 중 무작위 장애(삽입 전 끊김·커밋 후 끊김) → 매번 전송 서비스를 새로 만든다(재시작)
   기대: DB 4000행, decision_id 집합 일치, 모든 열 값 일치, log_check missing 0
B. 데이터 오류(CHECK 위반 줄) → 그 줄만 거절 파일로, 나머지는 들어감
C. RDS에 닿지 않는 주소 → 예외, 위치 그대로 → 정상 주소로 바꾸면 따라잡음
"""

from __future__ import annotations

import json
import os
import random
import shutil
import tempfile
import threading
import time
import uuid
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from detection_service import log_check
from detection_service.decision_log import DecisionLog
from detection_service.log_shipper import Shipper, rejected_path
from detection_service.pg_store import PgWriter, _default_connect

TABLE = "decisions_shiptest"
DDL = f"""
DROP TABLE IF EXISTS {TABLE};
CREATE TABLE {TABLE} (
    decision_id uuid PRIMARY KEY, request_id text NOT NULL, ts timestamptz NOT NULL, service text, format text,
    text_chars integer NOT NULL, blocked boolean NOT NULL,
    decided_by text NOT NULL CHECK (decided_by IN ('windowhash', 'signature', 'none')),
    doc_id text, doc_span text, input_span text, score real, pii_hits text, reason text NOT NULL,
    hash_status text NOT NULL CHECK (hash_status IN ('ok', 'error')),
    signature_status text NOT NULL CHECK (signature_status IN ('ok', 'error', 'skipped')),
    total_ms real NOT NULL, prompt text, prompt_kept boolean NOT NULL DEFAULT true
);
"""

PROMPTS = ["점심 메뉴 추천해줘", '따옴표 "안" 과 역슬래시 \\ 와 탭\t', "여러 줄\n입력\n입니다", "이모지 😀 섞임",
           "15_NDA_초안의 구간 그대로 " * 40, "a" * 3000]


class Flaky:
    """진짜 PgWriter를 감싸 무작위로 끊는다."""

    def __init__(self, inner: PgWriter, rng: random.Random, p_before: float, p_after: float):
        self.inner, self.rng, self.p_before, self.p_after = inner, rng, p_before, p_after
        self.before = self.after = 0

    def insert_many(self, records):
        if self.rng.random() < self.p_before:
            self.before += 1
            raise ConnectionError("injected: connection lost before insert")
        n = self.inner.insert_many(records)
        if self.rng.random() < self.p_after:
            self.after += 1
            raise ConnectionError("injected: connection lost after commit")
        return n


def rec(i: int, rng: random.Random, **kw) -> dict:
    blocked = rng.random() < 0.3
    r = {"decision_id": str(uuid.uuid4()), "request_id": f"t{i % 997}", "ts": time.time(), "service": "ChatGPT",
         "format": "chatgpt_web", "text_chars": 0, "blocked": blocked, "decided_by": "windowhash" if blocked else "none",
         "doc_id": "15_NDA_초안" if blocked else None, "doc_span": "216-516" if blocked else None,
         "input_span": "0-300" if blocked else None, "score": round(rng.random(), 4) if blocked else None,
         "pii_hits": None, "reason": "일치" if blocked else "매치 없음", "hash_status": "ok",
         "signature_status": "skipped" if blocked else "ok", "total_ms": round(rng.random() * 5, 1),
         "prompt": rng.choice(PROMPTS) + f" #{i}"}
    r["text_chars"] = len(r["prompt"])
    r.update(kw)
    return r


def fetch_all(conn) -> dict[str, dict]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT decision_id::text, request_id, ts, service, format, text_chars, blocked, decided_by, doc_id, "
                    f"doc_span, input_span, score, pii_hits, reason, hash_status, signature_status, total_ms, prompt FROM {TABLE}")
        cols = [d.name for d in cur.description]
        return {row[0]: dict(zip(cols, row)) for row in cur.fetchall()}


def same(a: dict, db: dict) -> list[str]:
    bad = []
    for k in ("request_id", "service", "format", "text_chars", "blocked", "decided_by", "doc_id", "doc_span",
              "input_span", "pii_hits", "reason", "hash_status", "signature_status", "prompt"):
        if a[k] != db[k]:
            bad.append(k)
    if abs(db["ts"].astimezone(timezone.utc).timestamp() - a["ts"]) > 1e-5:
        bad.append("ts")
    for k in ("score", "total_ms"):  # real(float4)
        if (a[k] is None) != (db[k] is None) or (a[k] is not None and abs(a[k] - db[k]) > 1e-3):
            bad.append(k)
    return bad


def phase_a(dsn: str, work: Path) -> dict:
    rng = random.Random(20260915)
    log = DecisionLog(work / "decisions.jsonl", max_bytes=20_000, backups=1000)
    written: dict[str, dict] = {}
    lock = threading.Lock()

    def writer(t: int):
        wrng = random.Random(t)
        for i in range(500):
            r = rec(t * 1000 + i, wrng)
            assert log.write(r)
            with lock:
                written[r["decision_id"]] = r
            if wrng.random() < 0.05:
                time.sleep(0.002)

    real = PgWriter(dsn, table=TABLE)
    flaky = Flaky(real, rng, p_before=0.05, p_after=0.05)
    restarts = 0
    done = threading.Event()
    threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)]
    t0 = time.time()
    for th in threads:
        th.start()

    def ship_loop():
        nonlocal restarts
        shipper = Shipper(log.path, flaky, backups=1000, batch_lines=50)
        shipper.init_offset(start_at_end=False)
        idle_after_done = 0
        while True:
            try:
                progressed = shipper.ship_once()
            except Exception:
                restarts += 1
                shipper = Shipper(log.path, flaky, backups=1000, batch_lines=50)  # 재시작: 파일에서 위치를 다시 읽는다
                continue
            if not progressed:
                if done.is_set():
                    idle_after_done += 1
                    if idle_after_done >= 3:
                        return
                time.sleep(0.01)

    shipper_thread = threading.Thread(target=ship_loop)
    shipper_thread.start()
    for th in threads:
        th.join()
    done.set()
    shipper_thread.join()
    elapsed = time.time() - t0

    conn = _default_connect(dsn)
    rows = fetch_all(conn)
    mismatched = [d for d, r in written.items() if d in rows and same(r, rows[d])]
    check = log_check.check(log.path, conn, table=TABLE, backups=1000)
    conn.close()
    real.close()
    return {
        "written": len(written), "db_rows": len(rows), "set_equal": set(rows) == set(written),
        "value_mismatch_rows": len(mismatched), "files": len(list(work.glob("decisions.jsonl*"))),
        "injected_before": flaky.before, "injected_after_commit": flaky.after, "restarts": restarts,
        "elapsed_s": round(elapsed, 1), "log_check": {k: check[k] for k in ("lines", "shipped_region", "pending", "in_db", "missing", "duplicate_ids", "ok")},
    }


def phase_b(dsn: str, work: Path) -> dict:
    rng = random.Random(2)
    log = DecisionLog(work / "decisions.jsonl")
    recs = [rec(i, rng) for i in range(20)]
    recs[7]["decided_by"] = "bogus"  # CHECK 위반
    for r in recs:
        log.write(r)
    writer = PgWriter(dsn, table=TABLE)
    shipper = Shipper(log.path, writer)
    shipper.init_offset(start_at_end=False)
    while shipper.ship_once():
        pass
    conn = _default_connect(dsn)
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {TABLE} WHERE decision_id = ANY(%s::uuid[])", ([r["decision_id"] for r in recs],))
        n = cur.fetchone()[0]
    rej = [json.loads(json.loads(x)["line"])["decision_id"] for x in rejected_path(log.path).read_text(encoding="utf-8").splitlines()]
    check = log_check.check(log.path, conn, table=TABLE)
    conn.close()
    writer.close()
    return {"in_db": n, "rejected": rej == [recs[7]["decision_id"]], "rejected_total": shipper.status["rejected_total"],
            "log_check_ok": check["ok"], "missing": check["missing"]}


def phase_c(dsn: str, work: Path) -> dict:
    rng = random.Random(3)
    log = DecisionLog(work / "decisions.jsonl")
    recs = [rec(i, rng) for i in range(30)]
    for r in recs:
        log.write(r)
    parts = urlsplit(dsn)
    host = parts.hostname or ""
    bad_dsn = urlunsplit(parts._replace(netloc=parts.netloc.replace(host, "10.255.255.1")))
    bad = PgWriter(bad_dsn, table=TABLE)
    shipper = Shipper(log.path, bad)
    shipper.init_offset(start_at_end=False)
    errors = []
    t = time.time()
    for _ in range(2):
        try:
            shipper.ship_once()
        except Exception as exc:
            errors.append(type(exc).__name__)
    down_s = round(time.time() - t, 1)
    pos_after_failures = shipper.load_offset().pos
    good = PgWriter(dsn, table=TABLE)
    shipper.writer = good
    while shipper.ship_once():
        pass
    conn = _default_connect(dsn)
    check = log_check.check(log.path, conn, table=TABLE)
    conn.close()
    good.close()
    return {"errors": errors, "seconds_for_2_failures": down_s, "offset_pos_during_outage": pos_after_failures,
            "after_recover_in_db": check["in_db"], "missing": check["missing"], "ok": check["ok"]}


def main() -> int:
    dsn = os.environ["DETECTION_PG_DSN"]
    conn = _default_connect(dsn)
    conn.execute(DDL)
    conn.close()
    base = Path(tempfile.mkdtemp(prefix="shiptest-"))
    result = {}
    try:
        for name, fn in (("A_concurrency_rotation_crash", phase_a), ("B_data_error", phase_b), ("C_rds_unreachable", phase_c)):
            work = base / name
            work.mkdir()
            result[name] = fn(dsn, work)
            print(name, json.dumps(result[name], ensure_ascii=False), flush=True)
    finally:
        conn = _default_connect(dsn)
        conn.execute(f"DROP TABLE IF EXISTS {TABLE}")
        conn.close()
        shutil.rmtree(base, ignore_errors=True)
    a, b, c = result["A_concurrency_rotation_crash"], result["B_data_error"], result["C_rds_unreachable"]
    ok = (a["set_equal"] and a["db_rows"] == a["written"] == 4000 and a["value_mismatch_rows"] == 0 and a["log_check"]["ok"] and a["log_check"]["in_db"] == 4000
          and b["in_db"] == 19 and b["rejected"] and b["log_check_ok"]
          and c["offset_pos_during_outage"] == 0 and c["ok"] and c["after_recover_in_db"] == 30)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
