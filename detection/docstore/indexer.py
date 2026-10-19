"""문서 인덱서 - RDS `documents`의 대기 행을 Redis 창 해시 색인으로 만든다 (detection-indexer.service, Detection EC2).

반복(5초 간격):
  1. 대기 행 하나를 잡는다: index_status 'pending' → 'indexing' (FOR UPDATE SKIP LOCKED, 한 행은 한 인덱서만)
  2. status='active'  : 원본 바이트 → 임시 파일 → preprocessing.process_input(탐지 CLI 적재와 같은 함수) → 정규화 텍스트
                        → windowhash.engine.document_windows → index.replace_doc_windows(새 창 먼저, 옛 창 나중)
                        → index_status='indexed', index_windows, normalized_text, text_chars, format, indexed_at
     status='retired' : index.remove_doc → index_status='indexed', index_windows=0 (텍스트는 남김)
  3. 실패 → index_status='error', index_error. `docstore.cli reindex`로 다시 대기시킨다.
  4. 색인 성공(indexed) → 키워드 DB(KEYWORD_DB)에 추출 작업을 넣는다(docstore.keyword_extractor가 처리).
     키워드 DB가 없거나 실패해도 색인은 성공으로 끝난다 - 키워드는 부가 기능이다.
  5. 키워드 DB 맞추기(KeywordSync, 2026-10-16): 매 주기 RDS 문서 상태를 키워드 DB `doc_states`로 옮긴다. 보호 여부가 바뀌면
     탐지 API `/admin/reload-signatures`를 불러 보호 중지 문서의 승인 키워드를 탐지에서 빼거나 되살린다(실패하면 다음 주기에 다시).
     문서 집합이 바뀌거나(색인 완료·중지·상태 변경) 문서 수를 안 센 키워드가 있으면 키워드마다 '보호 문서 몇 개에 나오는가'를
     다시 세 reason_check에 쓴다. 이 단계의 실패도 색인을 멈추지 않는다.
  끝 상태는 **잡을 때의 version·'indexing'일 때만** 쓴다. 도중에 재등록·퇴역되면(version 증가·pending) 덮어쓰지 않고
  다음 차례에 새 상태로 다시 처리한다.

파싱은 자식 프로세스에서 시간 제한(PARSE_TIMEOUT)을 두고 한다 - 병적인 PDF가 인덱서를 영원히 붙잡지 않게.
CPU는 systemd에서 제한한다(Nice·CPUQuota) - 같은 인스턴스의 탐지 API 응답을 지키려고.
시작할 때 'indexing'에 멈춘 행을 'pending'으로 되돌린다(인덱서가 하나만 도는 전제).

실행: python -m docstore.indexer            환경변수 DETECTION_PG_DSN, REDIS_DB/REDIS_PASSWORD(탐지 API와 같은 DB 번호)
      python -m docstore.indexer --once     대기 행을 모두 처리하고 끝낸다
      python -m docstore.indexer --sync-keywords   키워드 DB 맞추기(상태·문서 수)만 한 번 하고 결과를 출력한다
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing as mp
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("docstore.indexer")

POLL_SECONDS = 5.0
PARSE_TIMEOUT = 1800.0
MAX_BACKOFF = 60.0
RELOAD_URL = os.environ.get("DETECTION_RELOAD_URL", "http://127.0.0.1:8000/admin/reload-signatures")
RELOAD_TIMEOUT = 10.0
ACTIVE_TEXTS_SQL = "SELECT normalized_text FROM documents WHERE status = 'active' AND normalized_text IS NOT NULL"

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
    from detection_service.document_evidence import begin_update, finish_update, archive

    doc_id, version = row["doc_id"], row["version"]
    t0 = time.perf_counter()
    updating = False
    try:
        if row["status"] == "retired":
            begin_update(r, doc_id)
            updating = True
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
        begin_update(r, doc_id)
        updating = True
        stats = index.replace_doc_windows(r, doc_id, windows)
        with conn.cursor() as cur:
            cur.execute("UPDATE documents SET index_status = 'indexed', index_windows = %s, normalized_text = %s, "
                        "text_chars = %s, format = %s, index_error = NULL, indexed_at = now() "
                        "WHERE doc_id = %s AND version = %s AND status = 'active' AND index_status = 'indexing'",
                        (len(windows), text, len(text), fmt, doc_id, version))
            done = cur.rowcount == 1
        if done:
            archive(conn, r, row, text)
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
    finally:
        if updating:
            finish_update(r)


def _is_connection_error(exc: BaseException) -> bool:
    names = {c.__name__ for c in type(exc).__mro__}
    return bool(names & {"OperationalError", "InterfaceError", "ConnectionError", "TimeoutError"})


def enqueue_keyword_job(doc_id: str, version: int) -> dict | None:
    """색인이 끝난 문서의 키워드 추출 작업을 넣는다. 키워드 DB가 설정 안 됐거나 실패하면 None(색인 결과는 그대로)."""
    from detection_service import keyword_store

    if keyword_store.unavailable_reason() is not None:
        return None
    try:
        return keyword_store.enqueue_job(doc_id, version)
    except Exception as exc:  # noqa: BLE001 - 키워드 큐 실패가 색인을 실패시키지 않는다
        log.warning("keyword job enqueue failed for %s: %s", doc_id, exc)
        return None


def run_pending(conn: Any, r: Any, parse=parse_document) -> list[dict[str, Any]]:
    results = []
    while True:
        row = claim(conn)
        if row is None:
            return results
        res = index_one(conn, r, row, parse)
        if res["outcome"] == "indexed":
            job = enqueue_keyword_job(row["doc_id"], row["version"])
            res["keyword_job"] = job["id"] if job else None
        log.info("%s", res)
        results.append(res)


def request_reload(url: str = RELOAD_URL, timeout: float = RELOAD_TIMEOUT) -> bool:
    """탐지 API에 키워드·시그니처 재로딩을 요청한다. 성공(2xx)이면 True. 예외를 올리지 않는다."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=b"", method="POST"), timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001 - 다음 주기에 다시 부른다
        log.warning("detection reload failed: %s", exc)
        return False


class KeywordSync:
    """키워드 DB를 RDS 문서에 맞춘다(모듈 docstring 5번). step()은 색인 주기마다 불린다."""

    def __init__(self, reload: Callable[[], bool] = request_reload) -> None:
        self.reload = reload
        self.reload_pending = False
        self.counted = False      # 시작 후 첫 주기에는 한 번 센다

    def step(self, conn: Any, results: list[dict[str, Any]] = (), *, force_count: bool = False) -> dict | None:
        import sqlite3

        from detection_service import keyword_store

        if keyword_store.unavailable_reason() is not None:
            return None
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT doc_id, status, version FROM documents")
                states = cur.fetchall()
            changed = keyword_store.sync_doc_states(states)
            if changed:
                self.reload_pending = True
            out: dict[str, Any] = {"documents": len(states), "state_changed": len(changed)}
            docs_changed = any(x.get("outcome") in ("indexed", "retired") for x in results)
            if force_count or not self.counted or changed or docs_changed or keyword_store.missing_doc_counts():
                with conn.cursor() as cur:
                    cur.execute(ACTIVE_TEXTS_SQL)
                    texts = [row[0] for row in cur.fetchall()]
                out["counts"] = keyword_store.refresh_doc_counts(texts)
                self.counted = True
            if self.reload_pending:
                self.reload_pending = not self.reload()
                out["reloaded"] = not self.reload_pending
            if changed or "counts" in out:
                log.info("keyword sync %s", out)   # 키워드 값·문서 이름은 남기지 않는다(건수만)
            return out
        except sqlite3.Error as exc:
            log.warning("keyword sync failed (keyword DB): %s", exc)
            return None
        except Exception as exc:
            if _is_connection_error(exc):
                raise  # RDS 연결 문제 - 위 반복이 다시 연결한다
            log.warning("keyword sync failed: %s", exc)
            return None


def run(dsn: str, r: Any, stop: threading.Event | None = None, *, poll: float = POLL_SECONDS,
        sync: KeywordSync | None = None) -> None:
    from detection_service.pg_store import _default_connect

    stop = stop or threading.Event()
    sync = sync or KeywordSync()
    conn = None
    backoff = 1.0
    while not stop.is_set():
        try:
            if conn is None:
                conn = _default_connect(dsn)
                n = recover(conn)
                if n:
                    log.warning("recovered %d rows stuck in 'indexing'", n)
            results = run_pending(conn, r)
            sync.step(conn, results)
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
    ap.add_argument("--sync-keywords", action="store_true", help="키워드 DB 맞추기(상태·문서 수)만 한 번 하고 끝낸다")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    dsn = os.environ.get("DETECTION_PG_DSN", "").strip()
    if not dsn:
        log.error("DETECTION_PG_DSN is not set")
        return 2
    from detection_service import keyword_store

    if not keyword_store.configure_database(os.environ.get("KEYWORD_DB")):
        log.warning("keyword DB unavailable - no keyword extraction jobs: %s", keyword_store.unavailable_reason())
    if args.sync_keywords:
        conn = _default_connect(dsn)
        try:
            out = KeywordSync().step(conn, force_count=True)
        finally:
            conn.close()
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out is not None else 1
    r = connect_redis()
    log.info("indexer start: redis db%s", r.connection_pool.connection_kwargs.get("db"))
    if args.once:
        conn = _default_connect(dsn)
        recover(conn)
        results = run_pending(conn, r)
        KeywordSync().step(conn, results)
        conn.close()
        return 1 if any(x["outcome"] == "error" for x in results) else 0
    run(dsn, r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
