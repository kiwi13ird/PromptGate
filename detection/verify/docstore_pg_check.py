"""문서 등록·인덱서 실 RDS 시험 - 임시 스키마 docstore_test의 documents와 빈 Redis DB(기본 9)를 쓰고, 끝나면 둘 다 지운다.

실행(Detection EC2): set -a; . /opt/detection/pg.env; set +a
                    cd /opt/detection/src && REDIS_PASSWORD=<REDIS_PASSWORD> .venv/bin/python -m verify.docstore_pg_check [corpus 폴더]
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import zipfile
from pathlib import Path

import psycopg

from docstore import indexer, registry
from preprocessing.router import process_input
from windowhash import detect, engine, index

SCHEMA = "docstore_test"
REDIS_TEST_DB = int(os.environ.get("DOCSTORE_TEST_REDIS_DB", 9))
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{'OK' if ok else 'FAIL'}] {name} {detail}", flush=True)


def connect(dsn: str):
    return psycopg.connect(dsn, autocommit=True, connect_timeout=5, options=f"-c search_path={SCHEMA}")


def members_of(r, doc_id: str) -> set[tuple[str, str]]:
    out = set()
    for k in r.scan_iter("wh:*", count=5000):
        if k.startswith("wh:doc:") or k == "wh:docs":
            continue
        for m in r.smembers(k):
            if m.rsplit(":", 2)[0] == doc_id:
                out.add((k, m))
    return out


def expected(doc_id: str, text: str) -> set[tuple[str, str]]:
    return {(f"wh:{h}", f"{doc_id}:{s}:{e}") for h, s, e in engine.document_windows(text)}


def row(conn, doc_id: str) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT version, status, index_status, index_windows, text_chars, format, index_error, normalized_text "
                    "FROM documents WHERE doc_id = %s", (doc_id,))
        v = cur.fetchone()
    keys = ("version", "status", "index_status", "index_windows", "text_chars", "format", "index_error", "normalized_text")
    return dict(zip(keys, v)) if v else {}


def main() -> int:
    dsn = os.environ["DETECTION_PG_DSN"]
    corpus = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/detection/corpus")
    files = sorted(p for p in corpus.iterdir() if p.suffix in (".docx", ".xlsx"))
    a, b, c = files[0], files[5], files[16]  # docx, docx, xlsx

    r = index.connect(db=REDIS_TEST_DB)
    if r.dbsize() != 0:
        print(f"Redis db{REDIS_TEST_DB} is not empty - abort")
        return 2

    admin = psycopg.connect(dsn, autocommit=True)
    admin.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    admin.execute(f"CREATE SCHEMA {SCHEMA}")
    admin.execute(f"CREATE TABLE {SCHEMA}.documents (LIKE public.documents INCLUDING ALL)")
    conn = connect(dsn)
    try:
        # 1. 등록
        outs = [registry.register(conn, p.name, p.read_bytes(), registered_by="test").outcome for p in (a, b, c)]
        check("등록 3건 created", outs == ["created"] * 3, str(outs))
        check("같은 파일 재등록은 unchanged", registry.register(conn, a.name, a.read_bytes()).outcome == "unchanged")
        try:
            registry.register(conn, "memo.txt", "그냥 텍스트".encode())
            check("지원하지 않는 형식 거절", False)
        except registry.UnsupportedDocument:
            check("지원하지 않는 형식 거절", True)
        check("등록 직후 pending", registry.summary(conn) == {"active/pending": 3}, str(registry.summary(conn)))

        # 2. 색인
        res = indexer.run_pending(conn, r)
        check("인덱서 3건 indexed", [x["outcome"] for x in res] == ["indexed"] * 3,
              str([(x["doc_id"], x["outcome"], x.get("seconds")) for x in res]))
        for p in (a, b, c):
            text = process_input(str(p)).normalized_text
            d = row(conn, p.stem)
            check(f"{p.stem}: DB 텍스트 = CLI 파싱 텍스트", d["normalized_text"] == text, f"chars={d['text_chars']}")
            check(f"{p.stem}: Redis 원소 = 기대 창", members_of(r, p.stem) == expected(p.stem, text),
                  f"windows={d['index_windows']}")
            check(f"{p.stem}: 문서별 목록 = 기대 창", index.doc_windows(r, p.stem) == set(engine.document_windows(text)))
        ta = row(conn, a.stem)["normalized_text"]
        check("구간 조회 = 텍스트 슬라이스", registry.get_span(conn, a.stem, 100, 400) == ta[100:400])
        dec = detect.decide(detect.query_text(r, ta[1000:1300]))
        check("색인으로 발췌 차단", dec.blocked and dec.signal.x_evidence == a.stem, dec.reason)

        # 3. 교체: a 이름으로 b의 내용
        rr = registry.register(conn, a.name, b.read_bytes())
        check("다른 내용 재등록은 updated v2", (rr.outcome, rr.version) == ("updated", 2))
        indexer.run_pending(conn, r)
        tb = process_input(str(b)).normalized_text
        check("교체 후 a 원소 = b 내용의 창(옛 창 0)", members_of(r, a.stem) == expected(a.stem, tb))
        dec = detect.decide(detect.query_text(r, ta[1000:1300]))
        check("교체 후 옛 내용 발췌는 a로 걸리지 않음", not (dec.blocked and dec.signal.x_evidence == a.stem), dec.reason)

        # 4. 퇴역
        check("퇴역 요청", registry.retire(conn, c.stem))
        res = indexer.run_pending(conn, r)
        check("퇴역 처리", [x["outcome"] for x in res] == ["retired"], str(res))
        check("퇴역 후 c 원소 0·목록 없음·wh:docs 제외",
              not members_of(r, c.stem) and not r.exists(index.doc_key(c.stem)) and c.stem not in r.smembers("wh:docs"))
        d = row(conn, c.stem)
        check("퇴역 후 행·텍스트 유지", d["status"] == "retired" and d["index_windows"] == 0 and bool(d["normalized_text"]))

        # 5. 파싱 실패 → error → reindex
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", "<<not xml")
        registry.register(conn, "broken.docx", buf.getvalue())
        res = indexer.run_pending(conn, r)
        d = row(conn, "broken")
        check("깨진 docx → error", res[-1]["outcome"] == "error" and d["index_status"] == "error" and bool(d["index_error"]),
              (d["index_error"] or "")[:80])
        check("reindex → pending", registry.request_reindex(conn, "broken") == 1 and row(conn, "broken")["index_status"] == "pending")
        indexer.run_pending(conn, r)

        # 6. 처리 도중 재등록 → superseded → 다음 차례에 새 내용
        registry.register(conn, a.name, a.read_bytes())  # v3 (내용 a로 복귀)
        claimed = indexer.claim(conn)
        registry.register(conn, a.name, c.read_bytes())  # 처리 중에 v4 (내용 c)
        out = indexer.index_one(conn, r, claimed)
        check("처리 중 재등록 → superseded, 행은 pending", out["outcome"] == "superseded" and row(conn, a.stem)["index_status"] == "pending",
              f"version={row(conn, a.stem)['version']}")
        indexer.run_pending(conn, r)
        tc = process_input(str(c)).normalized_text
        check("다음 차례에 최신 내용으로 색인", members_of(r, a.stem) == expected(a.stem, tc) and row(conn, a.stem)["version"] == 4)

        # 7. 멈춘 indexing 복구
        conn.execute("UPDATE documents SET index_status = 'indexing' WHERE doc_id = %s", (b.stem,))
        check("recover: indexing → pending", indexer.recover(conn) == 1 and row(conn, b.stem)["index_status"] == "pending")
        indexer.run_pending(conn, r)

        # 8. 동시 claim은 서로 다른 행
        for p in files[1:5]:
            registry.register(conn, p.name, p.read_bytes())
        got: list[str] = []
        lock = threading.Lock()

        def grab():
            cc = connect(dsn)
            x = indexer.claim(cc)
            with lock:
                got.append(x["doc_id"] if x else None)
            cc.close()

        ths = [threading.Thread(target=grab) for _ in range(4)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        check("동시 claim 4건 = 서로 다른 4행", len(set(got)) == 4 and None not in got, str(got))
        indexer.recover(conn)
        res = indexer.run_pending(conn, r)
        check("나머지 처리", all(x["outcome"] == "indexed" for x in res) and len(res) == 4)
    finally:
        conn.close()
        admin.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
        admin.close()
        r.flushdb()  # 시작할 때 비어 있음을 확인한 시험용 DB
    failed = [n for n, ok, _ in results if not ok]
    print(json.dumps({"checks": len(results), "failed": failed}, ensure_ascii=False))
    print("PASS" if not failed else "FAIL")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
