"""두 Redis 색인 DB 비교 - CLI로 만든 옛 색인(기본 db1)과 인덱서가 만든 새 색인(기본 db3)이 탐지에 같은지.

python -m verify.index_compare [old_db] [new_db]
  1. 색인 원소: 옛 DB의 모든 wh:{hash} 키와 원소가 새 DB에 똑같이 있는지, 새 DB에 남는 키가 없는지(문서별 목록 wh:doc:* 제외)
  2. wh:docs 동일
  3. 새 DB의 문서별 목록 원소 수 합 = RDS documents.index_windows 합
  4. 판정: 문서마다 발췌(100·300·1000자)·문장 교체본과 무관 문장, verify/*.json을 두 DB로 판정해 결과가 같은지
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from detection_service.pg_store import _default_connect
from preprocessing.normalizer import normalize_text
from windowhash import detect, index

MALICIOUS = "이건 악의적으로 조작한 문장이다."


def all_keys(r) -> list[str]:
    return [k for k in r.scan_iter("wh:*", count=10000) if k != "wh:docs" and not k.startswith("wh:doc:")]


def compare_members(old, new) -> dict:
    keys_old = all_keys(old)
    keys_new = set(all_keys(new))
    diff_keys = 0
    for i in range(0, len(keys_old), 2000):
        chunk = keys_old[i:i + 2000]
        po, pn = old.pipeline(transaction=False), new.pipeline(transaction=False)
        for k in chunk:
            po.smembers(k)
            pn.smembers(k)
        for k, a, b in zip(chunk, po.execute(), pn.execute()):
            if a != b:
                diff_keys += 1
    return {"old_keys": len(keys_old), "new_keys": len(keys_new), "keys_only_in_new": len(keys_new - set(keys_old)),
            "keys_with_different_members": diff_keys}


def verdict(r, text: str) -> tuple:
    d = detect.decide(detect.query_text(r, normalize_text(text)))
    s = d.signal
    return (d.blocked, d.reason) if s is None else (d.blocked, s.x_evidence, s.x_chunk_span, s.start, s.end, round(s.score, 6))


def main() -> int:
    old_db = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    new_db = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    old, new = index.connect(db=old_db), index.connect(db=new_db)
    out: dict = {"members": compare_members(old, new)}
    out["wh_docs_equal"] = old.smembers("wh:docs") == new.smembers("wh:docs")
    out["docs"] = len(new.smembers("wh:docs"))

    conn = _default_connect(os.environ["DETECTION_PG_DSN"])
    with conn.cursor() as cur:
        cur.execute("SELECT doc_id, normalized_text, index_windows FROM documents WHERE status = 'active' ORDER BY doc_id")
        docs = cur.fetchall()
    conn.close()
    list_total = sum(new.scard(index.doc_key(d)) for d, _, _ in docs)
    out["doc_list_total"] = list_total
    out["db_index_windows_total"] = sum(w for _, _, w in docs)

    cases: list[tuple[str, str]] = []
    for doc_id, text, _ in docs:
        n = len(text)
        for length in (100, 300, 1000):
            start = (n * 37 // 100) % max(n - length, 1)
            ex = text[start:start + length]
            cases.append((f"{doc_id}:{length}", ex))
            mid = len(ex) // 2
            cases.append((f"{doc_id}:{length}:edit", ex[:mid - 20] + MALICIOUS + ex[mid + 20:]))
    for p in sorted((Path(__file__).resolve().parent).glob("*.json")):
        cases.append((p.name, json.loads(p.read_text(encoding="utf-8"))["normalized_text"]))
    cases.append(("unrelated", "다음 주 화요일 회의실 예약 가능한지 확인해 주시고 점심 메뉴도 추천 부탁드립니다."))

    mismatches = []
    blocked = 0
    for name, text in cases:
        a, b = verdict(old, text), verdict(new, text)
        blocked += bool(a[0])
        if a != b:
            mismatches.append({"case": name, "old": a, "new": b})
    out["verdict_cases"] = len(cases)
    out["verdict_blocked_old"] = blocked
    out["verdict_mismatches"] = len(mismatches)
    out["mismatch_sample"] = mismatches[:5]
    m = out["members"]
    ok = (m["keys_only_in_new"] == 0 and m["keys_with_different_members"] == 0 and m["old_keys"] == m["new_keys"]
          and out["wh_docs_equal"] and list_total == out["db_index_windows_total"] and not mismatches)
    out["ok"] = ok
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
