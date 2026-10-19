"""POST /redact/pdf 호출 참고 구현 + 배포 확인 도구(2026-10-11, 명세 §3.2·§3.5). Gateway `detection_client.redact_pdf`의 본보기.

- 표준 라이브러리(urllib)만. 응답은 조각으로 읽으며 조각 사이마다 monotonic 총시한을 본다(urlopen(timeout=)은 소켓
  작업마다의 제한이라 총시한이 아니다).
- 200 외 응답·시간 초과·연결 실패·형식 오류는 모두 `RedactResult(status="error", reason=...)` - 호출한 쪽은 masked/clean만
  통과로 다룬다(clean이면 원본, masked면 돌려받은 PDF). 그 밖은 원본을 보내지 않는다.
- X-Deadline-Ms = 호출 시한의 80%(돌려받는 전송 몫을 남김).

사용(서버, 같은 venv)
  python -m verify.redact_pdf_call --url http://127.0.0.1:8000 --fake      가짜 값 PDF를 만들어 왕복(PyMuPDF 필요)
  python -m verify.redact_pdf_call --url http://127.0.0.1:8000 --file x.pdf  주어진 PDF(가짜 값 문서만)
출력은 상태·쪽 수·건수·시간뿐이다. 값·원문·파일 이름은 출력하지 않는다. 요청 번호는 selftest-로 시작(보고서 집계에서 빠짐).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

STATUSES = {"masked", "clean", "blocked", "unsupported", "residual", "busy", "timeout", "error"}
JSON_KEYS = {"status", "pages", "text_pages", "masked_pages", "pii_hits", "residual", "decision", "detail", "elapsed_ms"}
PREFIX_RE = re.compile(r"^[A-Za-z0-9#:_-]{1,150}$")
HITS_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*:\d+(?:,[A-Z][A-Z0-9_]*:\d+)*)?$")
MAX_RESPONSE = 20 * 1024 * 1024 + 64 * 1024
CHUNK = 64 * 1024


@dataclass
class RedactResult:
    status: str
    pdf: bytes | None = field(default=None, repr=False)
    pages: int | None = None
    text_pages: int | None = None
    masked_pages: int | None = None
    pii_hits: str | None = None
    residual: str | None = None
    decision: dict | None = None
    detail: str | None = None
    elapsed_ms: float | None = None
    reason: str | None = None        # 호출 쪽 실패 사유(status="error"일 때)


def _fail(reason: str) -> RedactResult:
    return RedactResult(status="error", reason=reason)


def _read(resp, deadline: float, limit: int) -> bytes:
    chunks, total = [], 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("total deadline")
        chunk = resp.read(CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise ValueError("response too large")
        chunks.append(chunk)


def _int_header(headers, name: str) -> int:
    value = headers.get(name)
    if value is None or not value.isdigit():
        raise ValueError(f"bad {name}")
    return int(value)


def redact_pdf(base_url: str, prefix: str, data: bytes, source: dict, timeout: float) -> RedactResult:
    """source = {"service": .., "endpoint": .., "filename": ..}. timeout = 호출 쪽 총시한(초, 보통 파일 대기 시간)."""
    if not PREFIX_RE.fullmatch(prefix):
        return _fail("bad_prefix")
    started = time.monotonic()
    deadline = started + timeout
    deadline_ms = max(100, min(30000, int(timeout * 1000 * 0.8)))
    headers = {"Content-Type": "application/pdf", "X-Request-Prefix": prefix, "X-Deadline-Ms": str(deadline_ms)}
    if source.get("service"):
        headers["X-Source-Service"] = str(source["service"])
    if source.get("endpoint"):
        headers["X-Source-Endpoint"] = str(source["endpoint"])[:512]
    if source.get("filename"):
        headers["X-Source-Filename"] = urllib.parse.quote(str(source["filename"])[:255], safe="")
    request = urllib.request.Request(base_url.rstrip("/") + "/redact/pdf", data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=max(0.1, timeout)) as resp:
            body = _read(resp, deadline, MAX_RESPONSE)
            ctype = (resp.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype == "application/pdf":
                if resp.headers.get("X-Redact-Status") != "masked" or not body.startswith(b"%PDF-"):
                    return _fail("bad_pdf_response")
                hits = resp.headers.get("X-Redact-Pii-Hits", "")
                if not HITS_RE.fullmatch(hits):
                    return _fail("bad_pii_hits")
                return RedactResult(status="masked", pdf=body, pages=_int_header(resp.headers, "X-Redact-Pages"),
                                    text_pages=_int_header(resp.headers, "X-Redact-Text-Pages"),
                                    masked_pages=_int_header(resp.headers, "X-Redact-Masked-Pages"),
                                    pii_hits=hits or None, elapsed_ms=float(resp.headers.get("X-Redact-Elapsed-Ms", "0")))
            if ctype != "application/json":
                return _fail("bad_content_type")
            parsed = json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return _fail(f"http_{exc.code}")
    except (TimeoutError, OSError) as exc:     # 연결 실패·소켓 시간 초과·총시한 초과
        return _fail(f"io:{type(exc).__name__}")
    except (ValueError, UnicodeDecodeError) as exc:
        return _fail(f"format:{type(exc).__name__}")
    if not isinstance(parsed, dict) or set(parsed) != JSON_KEYS:
        return _fail("bad_json_shape")
    status = parsed.get("status")
    if status not in STATUSES or status == "masked":
        return _fail("bad_status")
    if status == "blocked" and not isinstance(parsed.get("decision"), dict):
        return _fail("blocked_without_decision")
    return RedactResult(status=status, pages=parsed["pages"], text_pages=parsed["text_pages"],
                        masked_pages=parsed["masked_pages"], pii_hits=parsed["pii_hits"], residual=parsed["residual"],
                        decision=parsed["decision"], detail=parsed["detail"], elapsed_ms=parsed["elapsed_ms"])


# ---------------------------------------------------------------- 배포 확인


FAKE_VALUES = ["900101-1234567", "010-1234-5678", "hong.gildong@example.com"]


def fake_pdf() -> bytes:
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    page.insert_font(fontname="kr", fontbuffer=fitz.Font("cjk").buffer)
    lines = ["[selftest] fake data only", f"RRN {FAKE_VALUES[0]} phone {FAKE_VALUES[1]}", f"mail {FAKE_VALUES[2]}",
             "plain words stay here"]
    for i, line in enumerate(lines):
        page.insert_text((60, 80 + 22 * i), line, fontname="kr", fontsize=11)
    doc.subset_fonts()
    return doc.tobytes(garbage=3, deflate=True)


def values_left(pdf: bytes) -> int:
    import fitz

    doc = fitz.open(stream=pdf, filetype="pdf")
    text = re.sub(r"\s+", "", "".join(p.get_text(flags=2 | 128, clip=fitz.INFINITE_RECT()) for p in doc))
    return sum(1 for v in FAKE_VALUES if v in text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--timeout", type=float, default=2.0, help="호출 쪽 총시한(초) - Gateway 파일 대기 시간")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--fake", action="store_true")
    group.add_argument("--file")
    args = ap.parse_args(argv)
    data = fake_pdf() if args.fake else open(args.file, "rb").read()
    prefix = f"selftest-redact-{int(time.time())}"
    result = redact_pdf(args.url, prefix, data, {"service": "selftest", "endpoint": "verify"}, args.timeout)
    out = {"status": result.status, "reason": result.reason, "detail": result.detail, "pages": result.pages,
           "text_pages": result.text_pages, "masked_pages": result.masked_pages, "pii_hits": result.pii_hits,
           "residual": result.residual, "elapsed_ms": result.elapsed_ms, "prefix": prefix}
    if result.pdf is not None:
        out["out_bytes"] = len(result.pdf)
        if args.fake:
            out["fake_values_left"] = values_left(result.pdf)
    print(json.dumps(out, ensure_ascii=False))
    if args.fake:
        return 0 if result.status == "masked" and out.get("fake_values_left") == 0 else 1
    return 0 if result.status in ("masked", "clean") else 1


if __name__ == "__main__":
    sys.exit(main())
