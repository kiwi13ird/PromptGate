"""Redis 역색인 - 실시간 조회가 때리는 유일한 저장소.

키: `wh:{hash}` Set, 원소 `"{doc_id}:{start}:{end}"` (창이 차지하는 원문 구간 [start, end))
     `wh:docs` Set, 적재된 doc_id 목록
     `wh:doc:{doc_id}` Set, 원소 `"{hash}:{start}:{end}"` - 이 문서가 넣은 창 목록(2026-09-15). 교체·퇴역 때 옛 창만 빼는 데 쓴다.
       실시간 조회는 읽지 않는다. SQLite 원장의 windows 표를 대신한다.
같은 창이 한 문서 안에 여러 번 나오면 원소가 여러 개다(같은 문서라 근거로는 하나).

쓰기 순서(중간에 죽어도 다시 돌리면 맞아지게): 넣을 때도 뺄 때도 `wh:{hash}`를 먼저, 문서별 목록을 나중에 바꾼다.
목록은 "이미 반영된 것"만 담으므로, 재시도는 목록과 새 창의 차이만큼 다시 넣고 뺀다.
"""

from __future__ import annotations

import os
from typing import Iterable

import redis

Posting = tuple[str, int, int]  # (doc_id, start, end)


def connect(host: str | None = None, port: int | None = None, db: int | None = None, password: str | None = None) -> redis.Redis:
    """환경변수(REDIS_HOST/PORT/DB/PASSWORD)로 기본값을 잡는다 - hashdb.redis_index.connect와 동일."""
    return redis.Redis(
        host=host or os.environ.get("REDIS_HOST", "127.0.0.1"),
        port=int(port if port is not None else os.environ.get("REDIS_PORT", 6379)),
        db=int(db if db is not None else os.environ.get("REDIS_DB", 1)),
        password=password or os.environ.get("REDIS_PASSWORD") or None,
        decode_responses=True,
    )


def write_windows(r: redis.Redis, doc_id: str, windows: Iterable[tuple[int, int, int]]) -> None:
    """(hash, start, end) 목록을 색인에 넣는다. 파이프라인으로 왕복 한 번."""
    pipe = r.pipeline(transaction=False)
    for h, start, end in windows:
        pipe.sadd(f"wh:{h}", f"{doc_id}:{start}:{end}")
    pipe.sadd("wh:docs", doc_id)
    pipe.execute()


def delete_windows(r: redis.Redis, doc_id: str, windows: Iterable[tuple[int, int, int]]) -> None:
    """재적재·삭제 전에 이 문서의 옛 창을 뺀다. 목록은 SQLite 원장에서 온다(역방향 색인)."""
    pipe = r.pipeline(transaction=False)
    for h, start, end in windows:
        pipe.srem(f"wh:{h}", f"{doc_id}:{start}:{end}")
    pipe.srem("wh:docs", doc_id)
    pipe.execute()


CHUNK = 5000  # 파이프라인 한 번에 보내는 명령 수


def doc_key(doc_id: str) -> str:
    return f"wh:doc:{doc_id}"


def doc_windows(r: redis.Redis, doc_id: str) -> set[tuple[int, int, int]]:
    out = set()
    for m in r.sscan_iter(doc_key(doc_id), count=CHUNK):
        h, start, end = m.split(":")
        out.add((int(h), int(start), int(end)))
    return out


def _apply(r: redis.Redis, doc_id: str, windows: list[tuple[int, int, int]], add: bool) -> None:
    """묶음마다: `wh:{hash}` 원소를 먼저, 같은 파이프라인 끝에서 문서별 목록을 한 명령으로 바꾼다(명령 순서 보장)."""
    key = doc_key(doc_id)
    for i in range(0, len(windows), CHUNK):
        chunk = windows[i:i + CHUNK]
        pipe = r.pipeline(transaction=False)
        for h, start, end in chunk:
            if add:
                pipe.sadd(f"wh:{h}", f"{doc_id}:{start}:{end}")
            else:
                pipe.srem(f"wh:{h}", f"{doc_id}:{start}:{end}")
        members = [f"{h}:{start}:{end}" for h, start, end in chunk]
        (pipe.sadd if add else pipe.srem)(key, *members)
        pipe.execute()


def replace_doc_windows(r: redis.Redis, doc_id: str, windows: Iterable[tuple[int, int, int]]) -> dict[str, int]:
    """문서의 창을 `windows`로 맞춘다. 새 창을 먼저 넣고, 새 목록에 없는 옛 창을 뺀다(중간에 탐지가 비지 않게)."""
    new = set(windows)
    old = doc_windows(r, doc_id) if r.exists(doc_key(doc_id)) else set()
    add = sorted(new - old)
    rem = sorted(old - new)
    _apply(r, doc_id, add, add=True)
    r.sadd("wh:docs", doc_id)
    _apply(r, doc_id, rem, add=False)
    return {"windows": len(new), "added": len(add), "removed": len(rem)}


def remove_doc(r: redis.Redis, doc_id: str) -> int:
    """문서의 창을 모두 뺀다(퇴역). 뺀 창 수."""
    old = sorted(doc_windows(r, doc_id))
    _apply(r, doc_id, old, add=False)
    r.srem("wh:docs", doc_id)
    r.delete(doc_key(doc_id))
    return len(old)


def lookup(r: redis.Redis, hashes: list[int]) -> dict[int, set[Posting]]:
    """hash -> {(doc_id, start, end)}. 없는 해시는 빈 set."""
    unique = list(dict.fromkeys(hashes))
    if not unique:
        return {}
    pipe = r.pipeline(transaction=False)
    for h in unique:
        pipe.smembers(f"wh:{h}")
    return {h: {_parse(m) for m in members} for h, members in zip(unique, pipe.execute())}


def document_count(r: redis.Redis) -> int:
    return int(r.scard("wh:docs"))


def _parse(member: str) -> Posting:
    head, _, end = member.rpartition(":")
    doc_id, _, start = head.rpartition(":")
    return doc_id, int(start), int(end)
