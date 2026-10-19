"""운영 Signature DB를 schema/seed SQL로 재현 가능하게 초기화한다."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def initialize(db_path: str | Path) -> Path:
    target = Path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    base = Path(__file__).resolve().parent
    connection = sqlite3.connect(target)
    try:
        for filename in ("schema.sql", "seed_rules.sql", "seed_policies.sql"):
            connection.executescript((base / filename).read_text(encoding="utf-8"))
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    finally:
        connection.close()
    return target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", default="/var/lib/detection/signature.db")
    args = parser.parse_args()
    print(initialize(args.db_path))


if __name__ == "__main__":
    main()
