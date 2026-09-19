"""판정 로그 대조 - 로그 파일의 모든 판정이 RDS `decisions`에 있는지 decision_id 단위로 확인한다.

실행: python -m detection_service.log_check [--table decisions] [--show 20]
출력(JSON 한 덩어리):
  lines            로그 파일(지금 + 회전 파일)의 decision_id 있는 줄 수
  legacy_lines     decision_id 없는 옛 형식 줄(2026-09-15 이전, 대조 대상 아님)
  shipped_region   전송 서비스 진행 위치 이전의 줄 수 - 이미 DB에 있어야 하는 줄
  pending          진행 위치 이후의 줄 수 - 아직 보내는 중
  rejected         DB가 거절해 shipper.rejected.jsonl로 뺀 줄 수
  in_db            shipped_region 중 DB에 있는 줄 수
  missing          shipped_region 중 DB에도 없고 거절 목록에도 없는 줄 수  ← 0이어야 정상
  duplicate_ids    로그 파일 안에서 같은 decision_id가 두 번 이상 나온 수 ← 0이어야 정상
  ok               missing == 0 and duplicate_ids == 0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .decision_log import BACKUPS, DEFAULT_PATH, rotated_path
from .log_shipper import Offset, Shipper, rejected_path
from .pg_store import _IDENT, _default_connect


def scan(log_path: Path, offset: Offset | None, backups: int = BACKUPS) -> dict[str, Any]:
    chain = [log_path] + [rotated_path(log_path, i) for i in range(1, backups + 1)]
    off_idx = None
    if offset is not None and offset.ino is not None:
        for i, p in enumerate(chain):
            if p.exists() and p.stat().st_ino == offset.ino:
                off_idx = i
    shipped: list[str] = []
    pending: list[str] = []
    legacy = 0
    seen: dict[str, int] = {}
    for i in range(len(chain) - 1, -1, -1):  # 오래된 파일부터
        p = chain[i]
        if not p.exists():
            continue
        data = p.read_bytes()
        pos = 0
        for raw in data.split(b"\n"):
            line_end = pos + len(raw) + 1
            if raw.strip():
                try:
                    rec = json.loads(raw)
                except ValueError:
                    rec = None
                did = rec.get("decision_id") if isinstance(rec, dict) else None
                if not did:
                    legacy += 1
                else:
                    seen[did] = seen.get(did, 0) + 1
                    if off_idx is None:
                        already = False
                    elif i > off_idx:
                        already = True
                    elif i == off_idx:
                        already = line_end <= offset.pos
                    else:
                        already = False
                    (shipped if already else pending).append(did)
            pos = line_end
    return {"shipped": shipped, "pending": pending, "legacy": legacy,
            "duplicates": sum(1 for c in seen.values() if c > 1)}


def rejected_ids(log_path: Path) -> set[str]:
    out: set[str] = set()
    p = rejected_path(log_path)
    if not p.exists():
        return out
    for raw in p.read_text(encoding="utf-8").splitlines():
        try:
            did = json.loads(json.loads(raw)["line"]).get("decision_id")
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        if did:
            out.add(did)
    return out


def ids_in_db(conn: Any, ids: list[str], table: str = "decisions") -> set[str]:
    if not _IDENT.match(table):
        raise ValueError(table)
    found: set[str] = set()
    with conn.cursor() as cur:
        for i in range(0, len(ids), 1000):
            cur.execute(f"SELECT decision_id::text FROM {table} WHERE decision_id = ANY(%s::uuid[])", (ids[i:i + 1000],))
            found.update(r[0] for r in cur.fetchall())
    return found


def check(log_path: Path, conn: Any, *, table: str = "decisions", show: int = 20, backups: int = BACKUPS) -> dict[str, Any]:
    offset = Shipper(log_path, writer=None).load_offset()
    s = scan(log_path, offset, backups)
    rej = rejected_ids(log_path)
    found = ids_in_db(conn, s["shipped"], table)
    missing = [d for d in s["shipped"] if d not in found and d not in rej]
    return {
        "lines": len(s["shipped"]) + len(s["pending"]), "legacy_lines": s["legacy"],
        "shipped_region": len(s["shipped"]), "pending": len(s["pending"]), "rejected": len(rej),
        "in_db": len(found), "missing": len(missing), "missing_sample": missing[:show],
        "duplicate_ids": s["duplicates"], "ok": not missing and s["duplicates"] == 0,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="decisions.jsonl vs RDS decisions")
    ap.add_argument("--table", default="decisions")
    ap.add_argument("--show", type=int, default=20)
    args = ap.parse_args(argv)
    dsn = os.environ.get("DETECTION_PG_DSN", "").strip()
    if not dsn:
        print("DETECTION_PG_DSN is not set", file=sys.stderr)
        return 2
    log_path = Path(os.environ.get("DETECTION_LOG_PATH", DEFAULT_PATH))
    conn = _default_connect(dsn)
    try:
        result = check(log_path, conn, table=args.table, show=args.show)
    finally:
        conn.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
