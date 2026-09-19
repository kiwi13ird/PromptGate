"""문서 인덱서 - RDS `documents`의 대기 행을 Redis 창 해시 색인으로 만든다 (detection-indexer.service, Detection EC2).

반복(5초 간격):
  1. 대기 행 하나를 잡는다: index_status 'pending' → 'indexing' (FOR UPDATE SKIP LOCKED, 한 행은 한 인덱서만)
  2. status='active'  : 원본 바이트 → 임시 파일 → preprocessing.process_input(탐지 CLI 적재와 같은 함수) → 정규화 텍스트
                        → windowhash.engine.document_windows → index.replace_doc_windows(새 창 먼저, 옛 창 나중)
                        → index_status='indexed', index_windows, normalized_text, text_chars, format, indexed_at
     status='retired' : index.remove_doc → index_status='indexed', index_windows=0 (텍스트는 남김)
  3. 실패 → index_status='error', index_error. `docstore.cli reindex`로 다시 대기시킨다.
  끝 상태는 **잡을 때의 version·'indexing'일 때만** 쓴다. 도중에 재등록·퇴역되면(version 증가·pending) 덮어쓰지 않고
  다음 차례에 새 상태로 다시 처리한다.

파싱은 자식 프로세스에서 시간 제한(PARSE_TIMEOUT)을 두고 한다 - 병적인 PDF가 인덱서를 영원히 붙잡지 않게.
CPU는 systemd에서 제한한다(Nice·CPUQuota) - 같은 인스턴스의 탐지 API 응답을 지키려고.
시작할 때 'indexing'에 멈춘 행을 'pending'으로 되돌린다(인덱서가 하나만 도는 전제).

실행: python -m docstore.indexer            환경변수 DETECTION_PG_DSN, REDIS_DB/REDIS_PASSWORD(탐지 API와 같은 DB 번호)
      python -m docstore.indexer --once     대기 행을 모두 처리하고 끝낸다
"""

from __future__ import annotations

import argparse
import logging
import multiprocessing as mp
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("docstore.indexer")

POLL_SECONDS = 5.0
PARSE_TIMEOUT = 1800.0
MAX_BACKOFF = 60.0

CLAIM_SQL = (
    "UPDATE documents SET index_status = 'indexing' "
    "WHERE doc_id = (SELECT doc_id FROM documents WHERE index_status = 'pending' "
    "ORDER BY registered_at, doc_id LIMIT 1 FOR UPDATE SKIP LOCKED) "
    "RETURNING doc_id, filename, original, version, status"
)


class ParseError(Exception):
    pass


def _parse_worker(path: str, sender) -> None:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from preprocessing.router import process_input

        doc = process_input(path)
        if doc.success:
            sender.send(("ok", doc.normalized_text, doc.format))
        else:
            sender.send(("fail", f"{doc.error_type}: {doc.error_message}", doc.format))
    except BaseException as exc:  # noqa: BLE001 - 자식에서 난 모든 것을 부모에 알린다
        sender.send(("fail", f"{type(exc).__name__}: {exc}", None))
    finally:
        sender.close()


def parse_document(filename: str, data: bytes, timeout: float = PARSE_TIMEOUT) -> tuple[str, str]:
    """원본 바이트 → (정규화 텍스트, 형식). 실패·시간 초과는 ParseError."""
    with tempfile.TemporaryDirectory(prefix="docstore-") as d:
        path = Path(d) / (Path(filename).name or "document")
        path.write_bytes(data)
        receiver, sender = mp.Pipe(duplex=False)
        proc = mp.Process(target=_parse_worker, args=(str(path), sender), daemon=True)
        proc.start()
        sender.close()
        try:
            if not receiver.poll(timeout):
                raise ParseError(f"파싱 시간 초과({timeout:.0f}초)")
            kind, value, fmt = receiver.recv()
        except EOFError:
            raise ParseError(f"파싱 프로세스가 결과 없이 끝남(exit={proc.exitcode})") from None
        finally:
            if proc.is_alive():
                proc.terminate()
            proc.join(5)
            receiver.close()
    if kind != "ok":
        raise ParseError(value)
    if not value:
        raise ParseError("정규화 텍스트가 비었습니다")
    return value, fmt


def recover(conn: Any) -> int:
    with conn.cursor() as cur:
        cur.execute("UPDATE documents SET index_status = 'pending' WHERE index_status = 'indexing'")
        return cur.rowcount


def claim(conn: Any) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(CLAIM_SQL)
        row = cur.fetchone()
    if row is None:
        return None
    doc_id, filename, original, version, status = row
    return {"doc_id": doc_id, "filename": filename, "original": bytes(original), "version": version, "status": status}


def index_one(conn: Any, r: Any, row: dict[str, Any],
              parse: Callable[[str, bytes], tuple[str, str]] = parse_document) -> dict[str, Any]:
    """잡은 행 하나를 처리한다. 결과 dict: outcome = indexed | retired | error | superseded."""
    from windowhash import engine, index

    doc_id, version = row["doc_id"], row["version"]
    t0 = time.perf_counter()
    try:
        if row["status"] == "retired":
            removed = index.remove_doc(r, doc_id)
            with conn.cursor() as cur:
                cur.execute("UPDATE documents SET index_status = 'indexed', index_windows = 0, index_error = NULL, "
                            "indexed_at = now() WHERE doc_id = %s AND version = %s AND status = 'retired' "
                            "AND index_status = 'indexing'", (doc_id, version))
                done = cur.rowcount == 1
            return {"doc_id": doc_id, "outcome": "retired" if done else "superseded", "removed": removed,
                    "seconds": round(time.perf_counter() - t0, 2)}

        text, fmt = parse(row["filename"], row["original"])
        windows = engine.document_windows(text)
        if not windows:
            raise ParseError(f"창이 없습니다(한글·영문·숫자 {len(engine.compact(text).codes)}자 < 창 길이)")
        stats = index.replace_doc_windows(r, doc_id, windows)
        with conn.cursor() as cur:
            cur.execute("UPDATE documents SET index_status = 'indexed', index_windows = %s, normalized_text = %s, "
                        "text_chars = %s, format = %s, index_error = NULL, indexed_at = now() "
                        "WHERE doc_id = %s AND version = %s AND status = 'active' AND index_status = 'indexing'",
                        (len(windows), text, len(text), fmt, doc_id, version))
            done = cur.rowcount == 1
        return {"doc_id": doc_id, "outcome": "indexed" if done else "superseded", **stats, "text_chars": len(text),
                "seconds": round(time.perf_counter() - t0, 2)}
    except Exception as exc:
        if not isinstance(exc, ParseError) and _is_connection_error(exc):
            raise  # DB·Redis 연결 문제는 문서 탓이 아니다 - 상태를 바꾸지 않고 위에서 재시도(시작 시 recover)
        msg = f"{type(exc).__name__}: {exc}"[:2000]
        with conn.cursor() as cur:
            cur.execute("UPDATE documents SET index_status = 'error', index_error = %s "
                        "WHERE doc_id = %s AND version = %s AND index_status = 'indexing'", (msg, doc_id, version))
        return {"doc_id": doc_id, "outcome": "error", "error": msg, "seconds": round(time.perf_counter() - t0, 2)}


def _is_connection_error(exc: BaseException) -> bool:
    names = {c.__name__ for c in type(exc).__mro__}
    return bool(names & {"OperationalError", "InterfaceError", "ConnectionError", "TimeoutError"})


def run_pending(conn: Any, r: Any, parse=parse_document) -> list[dict[str, Any]]:
    results = []
    while True:
        row = claim(conn)
        if row is None:
            return results
        res = index_one(conn, r, row, parse)
        log.info("%s", res)
        results.append(res)


def run(dsn: str, r: Any, stop: threading.Event | None = None, *, poll: float = POLL_SECONDS) -> None:
    from detection_service.pg_store import _default_connect

    stop = stop or threading.Event()
    conn = None
    backoff = 1.0
    while not stop.is_set():
        try:
            if conn is None:
                conn = _default_connect(dsn)
                n = recover(conn)
                if n:
                    log.warning("recovered %d rows stuck in 'indexing'", n)
            run_pending(conn, r)
            backoff = 1.0
            stop.wait(poll)
        except Exception as exc:
            log.warning("indexer loop failed, retry in %.0fs: %s", backoff, exc)
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            conn = None
            stop.wait(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from detection_service.pg_store import _default_connect
    from windowhash.index import connect as connect_redis

    ap = argparse.ArgumentParser(description="RDS documents → Redis window-hash index")
    ap.add_argument("--once", action="store_true", help="대기 행을 모두 처리하고 끝낸다")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    dsn = os.environ.get("DETECTION_PG_DSN", "").strip()
    if not dsn:
        log.error("DETECTION_PG_DSN is not set")
        return 2
    r = connect_redis()
    log.info("indexer start: redis db%s", r.connection_pool.connection_kwargs.get("db"))
    if args.once:
        conn = _default_connect(dsn)
        recover(conn)
        results = run_pending(conn, r)
        conn.close()
        return 1 if any(x["outcome"] == "error" for x in results) else 0
    run(dsn, r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
