"""Bind new decisions to immutable indexed document versions, not today's DB row.

Index updates use an odd/even generation guard. Evidence is omitted on legacy
indexes, concurrent updates, unavailable Redis, or incomplete archive writes.
No DB query is added to real-time detection.
"""
import hashlib
import json

EPOCH_KEY = "wh:evidence:epoch"


def meta_key(doc_id):
    return f"wh:evidence:document:{doc_id}"


def read_epoch(r):
    try:
        value = r.get(EPOCH_KEY)
        return int(value) if value is not None else None
    except Exception:
        return None


def reference(r, row, before):
    if before is None or before % 2 or not row.get("doc_id"):
        return None
    try:
        value = json.loads(r.get(meta_key(row["doc_id"])) or "null")
        after = read_epoch(r)
        if after != before or not isinstance(value, dict):
            return None
        if value.get("doc_id") != row["doc_id"] or not isinstance(value.get("version"), int):
            return None
        digest = value.get("normalized_sha256", "")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return None
        return {"doc_id": row["doc_id"], "version": value["version"], "normalized_sha256": digest,
                "index_epoch": before, "basis": "STABLE_INDEX_VERSION"}
    except Exception:
        return None


def begin_update(r, doc_id):
    # One indexer is the established service contract. Odd after a crash remains
    # odd until this update completes; queries then omit version assertions.
    before = read_epoch(r) or 0
    r.incrby(EPOCH_KEY, 2 if before % 2 else 1)
    r.delete(meta_key(doc_id))


def finish_update(r):
    r.incr(EPOCH_KEY)


def archive(conn, r, row, text):
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO dashboard_document_versions (doc_id,version,filename,normalized_text,normalized_sha256) "
                    "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (doc_id,version) DO NOTHING",
                    (row["doc_id"], row["version"], row["filename"], text, digest))
        cur.execute("SELECT normalized_sha256 FROM dashboard_document_versions WHERE doc_id=%s AND version=%s",
                    (row["doc_id"], row["version"]))
        saved = cur.fetchone()
        if not saved or saved[0] != digest:
            raise ValueError("immutable document version conflict")
    r.set(meta_key(row["doc_id"]), json.dumps({"doc_id": row["doc_id"], "version": int(row["version"]),
                                             "normalized_sha256": digest}))
