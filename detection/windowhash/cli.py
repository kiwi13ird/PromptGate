"""적재용 CLI(옛 경로). hashdb/cli.py와 같은 인터페이스.

2026-09-15부터 운영 적재는 `python -m docstore.cli register` → detection-indexer(RDS documents → Redis db3)가 한다.
이 CLI는 비상·실험용으로만 남긴다. 운영 Redis DB(3)에 직접 쓰면 RDS documents와 색인이 어긋나므로 쓰지 않는다.

  python -m windowhash.cli ingest <파일 또는 디렉터리> [--db PATH] [--redis-host/-port/-db/-password]

옵션은 `ingest` 앞에 써도 뒤에 써도 된다(서버 첫 적재 때 뒤에 썼다가 argparse가 거부한 적이 있어 양쪽 다 받게 했다).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from windowhash.index import connect as connect_redis  # noqa: E402
from windowhash.ingest import ingest_directory, ingest_file  # noqa: E402
from windowhash.store import connect as connect_sqlite  # noqa: E402

_DEFAULT_DB = Path(__file__).resolve().parent / "windowhash.sqlite3"


def _cmd_ingest(args: argparse.Namespace) -> None:
    conn = connect_sqlite(args.db)
    r = connect_redis(host=args.redis_host, port=args.redis_port, db=args.redis_db, password=args.redis_password)
    target = Path(args.path)
    results = [ingest_file(conn, r, target)] if target.is_file() else ingest_directory(conn, r, target)
    ok = 0
    for res in results:
        if res["ok"]:
            ok += 1
            print(f"OK   {res['doc_id']:35s} windows={res['windows']}")
        else:
            print(f"FAIL {res['path']:35s} {res['error']}")
    print(f"\n{ok}/{len(results)}건 적재 완료 -> SQLite {args.db} + Redis db{r.connection_pool.connection_kwargs['db']}")


def _add_conn_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db", default=str(_DEFAULT_DB))
    p.add_argument("--redis-host", default=None)
    p.add_argument("--redis-port", type=int, default=None)
    p.add_argument("--redis-db", type=int, default=None)
    p.add_argument("--redis-password", default=None)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _add_conn_args(parser)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("ingest", help="파일 또는 디렉터리를 SQLite+Redis에 적재")
    p.add_argument("path")
    _add_conn_args(p)
    p.set_defaults(func=_cmd_ingest)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
