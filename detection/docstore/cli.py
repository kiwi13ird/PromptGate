"""기밀문서 등록 명령 - 관리자 대시보드가 생기기 전까지 Detection EC2에서 쓴다. 대시보드의 관리 API는 같은 registry 함수를 쓴다.

  python -m docstore.cli register <파일 또는 폴더>... [--title T] [--classification C] [--by 이름]
  python -m docstore.cli retire <doc_id>
  python -m docstore.cli reindex [<doc_id> | --all]
  python -m docstore.cli list [--status active|retired]
  python -m docstore.cli span <doc_id> <start>-<end>        판정의 doc_span 구간 원문
  python -m docstore.cli wait [--timeout 초]               대기·색인 중인 문서가 없어질 때까지 기다리고 결과 표시

환경변수 DETECTION_PG_DSN. 등록은 원본만 넣고 끝난다 - 파싱·색인은 detection-indexer가 한다(`wait`로 확인).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_service.pg_store import _default_connect  # noqa: E402
from docstore import registry  # noqa: E402

_SUFFIXES = {".pdf", ".docx", ".xlsx"}


def _files(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out += sorted(x for x in p.iterdir() if x.is_file() and x.suffix.lower() in _SUFFIXES)
        else:
            out.append(p)
    return out


def _print_rows(rows: list[dict]) -> None:
    for d in rows:
        err = f"  error={d['index_error'][:80]}" if d.get("index_error") else ""
        print(f"{d['doc_id']:32s} v{d['version']:<3d} {d['status']:8s} {d['index_status']:9s} "
              f"format={d['format'] or '-':5s} windows={d['index_windows'] if d['index_windows'] is not None else '-':>7} "
              f"chars={d['text_chars'] if d['text_chars'] is not None else '-':>7}{err}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="기밀문서 등록·조회 (RDS documents)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("register")
    p.add_argument("paths", nargs="+")
    p.add_argument("--title")
    p.add_argument("--classification")
    p.add_argument("--by", default=os.environ.get("USER"))
    p = sub.add_parser("retire")
    p.add_argument("doc_id")
    p = sub.add_parser("reindex")
    p.add_argument("doc_id", nargs="?")
    p.add_argument("--all", action="store_true")
    p = sub.add_parser("list")
    p.add_argument("--status", choices=("active", "retired"))
    p = sub.add_parser("span")
    p.add_argument("doc_id")
    p.add_argument("span", help="start-end (판정의 doc_span)")
    p = sub.add_parser("wait")
    p.add_argument("--timeout", type=float, default=600)
    args = ap.parse_args(argv)

    dsn = os.environ.get("DETECTION_PG_DSN", "").strip()
    if not dsn:
        print("DETECTION_PG_DSN is not set", file=sys.stderr)
        return 2
    conn = _default_connect(dsn)
    try:
        if args.cmd == "register":
            files = _files(args.paths)
            failed = 0
            for f in files:
                try:
                    res = registry.register(conn, f.name, f.read_bytes(), title=args.title if len(files) == 1 else None,
                                            classification=args.classification, registered_by=args.by)
                    print(f"{res.outcome:9s} {res.doc_id:32s} v{res.version} {res.format}")
                except (registry.UnsupportedDocument, OSError) as exc:
                    failed += 1
                    print(f"FAIL      {f}: {exc}")
            print(f"{len(files) - failed}/{len(files)} 등록. 색인은 detection-indexer가 처리한다(`wait`로 확인).")
            return 1 if failed else 0
        if args.cmd == "retire":
            ok = registry.retire(conn, args.doc_id)
            print("retired" if ok else "해당 active 문서 없음")
            return 0 if ok else 1
        if args.cmd == "reindex":
            if not args.all and not args.doc_id:
                print("doc_id 또는 --all", file=sys.stderr)
                return 2
            print(f"{registry.request_reindex(conn, None if args.all else args.doc_id)}건 대기")
            return 0
        if args.cmd == "list":
            _print_rows(registry.list_documents(conn, args.status))
            print(registry.summary(conn))
            return 0
        if args.cmd == "span":
            start, _, end = args.span.partition("-")
            text = registry.get_span(conn, args.doc_id, int(start), int(end))
            if text is None:
                print("문서 또는 정규화 텍스트 없음", file=sys.stderr)
                return 1
            print(text)
            return 0
        if args.cmd == "wait":
            t = time.time()
            while True:
                s = registry.summary(conn)
                busy = sum(v for k, v in s.items() if k.endswith("/pending") or k.endswith("/indexing"))
                if busy == 0 or time.time() - t > args.timeout:
                    break
                time.sleep(2)
            rows = registry.list_documents(conn)
            _print_rows(rows)
            print(s, f"{time.time() - t:.0f}초")
            errors = [d for d in rows if d["index_status"] == "error"]
            return 1 if busy or errors else 0
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
