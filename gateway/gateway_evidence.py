"""Bounded, privacy-protected proof of an actual request-body rewrite.

This does not prove the upstream accepted the request or generated an answer.
Never retains cookies, headers, whole JSON bodies, or original sensitive values.
"""
import hashlib
import re

LIMIT = 4000


def redact(text):
    patterns = [
        r"\bBearer\s+[A-Za-z0-9._~+/-]+=*",
        r"(?:api[_ -]?key|access[_ -]?token|secret|password|비밀번호)\s*[=:]\s*[\"']?[^\s\"',;]+",
        r"\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b",
        r"\b\d{6}\s*[-–]?\s*[1-8]\d{6}\b",
        r"(?<!\d)(?:\+82[- .]?)?0?1[016789][- .]?\d{3,4}[- .]?\d{4}(?!\d)",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ]
    for pattern in patterns:
        text = re.sub(pattern, lambda m: "█" * len(m[0]), text, flags=re.I)
    return text


def capture_mask(flow, before, after, result, representation):
    if not isinstance(before, str) or not isinstance(after, str) or before == after or max(len(before),len(after))>2_000_000:
        return
    request_id = getattr(result, "request_id", "")
    if not request_id:
        return
    spans = []
    protected = list(before)
    for hit in (getattr(result, "findings", None) or getattr(result, "mask_spans", None) or []):
        start, end = hit.get("start"), hit.get("end")
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(before):
            protected[start:end] = ["█"] * (end - start)
            if len(spans) < 100:
                spans.append({"start": start, "end": end, "entityType": str(hit.get("entity_type", "SENSITIVE"))[:100]})
    proof = {
        "status": "REQUEST_REWRITTEN", "representation": representation,
        "beforePreview": redact("".join(protected))[:LIMIT], "afterPreview": redact(after)[:LIMIT],
        "beforeChars": len(before), "afterChars": len(after),
        "previewTruncated": max(len(before), len(after)) > LIMIT,
        "outboundTextSha256": hashlib.sha256(after.encode("utf-8")).hexdigest(), "spans": spans,
    }
    flow.metadata.setdefault("gw_mask_evidence", {})[request_id] = proof
