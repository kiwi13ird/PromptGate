"""Gateway EC2에서 Detection EC2의 `POST /detect`를 호출한다.

`gateway-detection-integration-design.md` §5 스케치의 실제 구현. 표준 라이브러리만 쓴다
(hashdb와 같은 원칙, `hashdb/README.md` "설치" 절 참고) - Gateway EC2에 이미 올라간 것 외에
새 pip 의존성(httpx/requests)을 추가하지 않는다.

검사 실패 정책과 제한시간은 환경변수로 설정한다. 기존 기본값 FAIL_OPEN/0.5초는
유지하며, 실패를 정상 허용 판정과 구분해 기록한다. 설정 오류는 조용히 허용하지 않는다.
"""

from __future__ import annotations

import http.client
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

def runtime_settings():
    policy = os.getenv('DETECTION_FAILURE_POLICY', 'FAIL_OPEN').strip().upper()
    if policy not in {'FAIL_OPEN', 'FAIL_CLOSED'}:
        raise ValueError('DETECTION_FAILURE_POLICY must be FAIL_OPEN or FAIL_CLOSED')
    try:
        timeout = float(os.getenv('DETECTION_TIMEOUT_SECONDS', '0.5'))
    except ValueError:
        raise ValueError('DETECTION_TIMEOUT_SECONDS must be numeric') from None
    if not math.isfinite(timeout) or not 0.05 <= timeout <= 30:
        raise ValueError('DETECTION_TIMEOUT_SECONDS must be between 0.05 and 30')
    return policy, timeout


_FAILURE_POLICY, _TIMEOUT_SECONDS = runtime_settings()


@dataclass
class DetectionResult:
    """Detection 응답을 그대로 담는다(2026-09-14 구조: DB decisions 행과 같은 이름). 무응답이면 degraded=True,
    action="allow_degraded"."""

    blocked: bool
    reason: str
    degraded: bool = False  # True면 실제 판정이 아니라 통신 실패로 인한 잠정 결과
    degraded_reason: str | None = None
    failure_policy: str | None = None
    request_id: str = ""
    decided_by: str = "none"  # "windowhash" | "signature" | "none"
    doc_id: str | None = None
    doc_span: str | None = None
    input_span: str | None = None
    score: float | None = None  # 표본 추정치(창 기준) - 일치 위치에 따라 달라진다. 보고용 아님
    match_rate: float | None = None  # 일치율: 일치 글자 / 입력 글자. 대시보드·보고서가 쓰는 값
    pii_hits: str | None = None
    hash_status: str | None = None
    signature_status: str | None = None
    total_ms: float | None = None
    mask_spans: list[dict] | None = None
    policy_id: str | None = None
    policy_version: int | None = None
    findings: list[dict] | None = None
    masked_text: str | None = None
    # Gateway가 해석 없이 집행할 값
    action: str = "allow"  # "allow" | "block" | "allow_degraded"
    reason_code: str = "none"  # "doc_excerpt" | "pii" | "none" | "detection_unreachable"
    user_message: str | None = None
    http_status: int | None = None
    # 옛 응답(evidence 블록) 호환 - 새 서버에서는 항상 None
    evidence: dict | None = None


def failure_result(reason: str, failure_policy: str, request_id: str) -> DetectionResult:
    """Detection 무응답·실패 판정(TIMEOUT·UNREACHABLE·PARSE_ERROR·OTHER). check() 안의 실패와 같은 값.

    2026-10-10: Gateway가 같은 요청 안에서 무응답을 다음 호출에 넘길 때(다시 부르지 않음) 받는 쪽 규칙
    (질문·파일)으로 판정을 새로 만들 수 있게 모듈 함수로 꺼냈다. check()의 동작은 같다.
    """
    closed = failure_policy == 'FAIL_CLOSED'
    return DetectionResult(
        blocked=closed, reason=f'inspection failed: {reason}; {failure_policy}',
        degraded=True, degraded_reason=reason, failure_policy=failure_policy,
        action='block' if closed else 'allow_degraded',
        reason_code={'TIMEOUT': 'detection_timeout', 'PARSE_ERROR': 'detection_parse_error',
                     'OTHER': 'detection_error', 'UNREACHABLE': 'detection_unreachable'}[reason],
        request_id=request_id, http_status=503 if closed else None,
        user_message='보안 검사를 완료하지 못해 장애 처리 정책에 따라 전송을 차단했습니다.' if closed else None,
    )


def check(
    base_url: str,
    request_id: str,
    normalized_text: str,
    source: dict | None = None,
    timeout: float = _TIMEOUT_SECONDS,
    failure_policy: str = _FAILURE_POLICY,
) -> DetectionResult:
    """Detection EC2에 정규화된 텍스트를 보내고 판정을 받는다.

    통신 실패(타임아웃 포함) 시 예외를 올리지 않고 (잠정) 통과시킨다 - 이 계층에서
    예외가 나면 gateway.py의 나머지 요청 처리 전체가 죽으므로, 실패를 값으로 돌려주는 쪽을
    택한다. degraded=True로 표시되므로 호출자가 로그·알림 여부를 판단할 수 있다.
    """
    if failure_policy not in {'FAIL_OPEN', 'FAIL_CLOSED'}:
        raise ValueError('Invalid inspection failure policy')
    if not math.isfinite(timeout) or not 0.05 <= timeout <= 30:
        raise ValueError('Invalid inspection timeout')

    def failed(reason):
        return failure_result(reason, failure_policy, request_id)

    payload = json.dumps(
        {"request_id": request_id, "normalized_text": normalized_text, "source": source or {}}
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/detect",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except TimeoutError:
        return failed('TIMEOUT')
    except urllib.error.HTTPError:
        return failed('OTHER')
    except urllib.error.URLError as exc:
        return failed('TIMEOUT' if isinstance(exc.reason, TimeoutError) else 'UNREACHABLE')
    except OSError:
        return failed('UNREACHABLE')
    except ValueError:
        return failed('PARSE_ERROR')
    except http.client.HTTPException:
        # 2026-10-11: 응답이 깨짐(본문 끊김 IncompleteRead·상태 줄 오류 BadStatusLine·긴 머리 LineTooLong·깨진 chunked).
        # OSError·ValueError가 아니라 잡지 않으면 요청 처리 밖으로 나가고, mitmproxy는 애드온 오류만 남긴 채 원래 요청을
        # 보낸다(처리 설정이 '차단'이어도). RemoteDisconnected는 OSError라 위에서 UNREACHABLE 그대로
        return failed('OTHER')
    except Exception:
        # 마지막 안전망: 이 계층의 예외는 원본 전송으로 끝나므로 실패 판정(처리 설정대로 차단·원본 전송)으로 바꾼다
        return failed('OTHER')

    result = _result_from_body(body, request_id)
    return result if result is not None else failed('PARSE_ERROR')


def _result_from_body(body, request_id: str) -> DetectionResult | None:
    """`/detect` 응답 본문(JSON 해석 뒤) → DetectionResult. 쓸 수 없는 모양이면 None(호출 쪽이 PARSE_ERROR로).

    2026-10-11: check()에서 꺼냈다(동작 같음). `/redact/pdf`의 blocked 응답 decision(그 쪽 /detect 응답과 같은 모양)도
    이 함수로 해석한다(명세 §3.5)."""
    # A syntactically valid JSON response may still be unusable. Never turn an
    # unknown action or malformed envelope into a normal ALLOW by falling through.
    if not isinstance(body, dict) or type(body.get('blocked')) is not bool or not isinstance(body.get('reason'), str):
        return None
    decision = body.get('decision')
    if decision is None:
        decision = {}
    if not isinstance(decision, dict):
        return None
    action = decision.get('action', 'block' if body['blocked'] else 'allow')
    if not isinstance(action, str) or action not in {'block', 'block_notify', 'allow', 'allow_notify', 'allow_degraded', 'mask', 'mask_partial', 'mask_full'}:
        return None
    if any(decision.get(key) is not None and not isinstance(decision[key], str) for key in ('user_message', 'reason_code')):
        return None
    status = decision.get('http_status')
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        return None
    return DetectionResult(
        blocked=body["blocked"],
        reason=body["reason"],
        request_id=body.get("request_id") or request_id,
        decided_by=body.get("decided_by", "none"),
        doc_id=body.get("doc_id"), doc_span=body.get("doc_span"), input_span=body.get("input_span"),
        score=body.get("score"), match_rate=body.get("match_rate"), pii_hits=body.get("pii_hits"),
        hash_status=body.get("hash_status"), signature_status=body.get("signature_status"), total_ms=body.get("total_ms"),
        mask_spans=body.get("mask_spans") or [],
        policy_id=body.get("policy_id"),
        policy_version=body.get("policy_version"),
        findings=body.get("findings") or [],
        masked_text=body.get("masked_text"),
        action=action,
        reason_code=decision.get("reason_code", "none"),
        user_message=decision.get("user_message"),
        http_status=decision.get("http_status"),
        evidence=body.get("evidence"),
    )


# ============================================================
# PDF 가림 호출 `POST /redact/pdf` (2026-10-11, masking-design/SPEC.md §3.2·§3.5)
# ============================================================
# 요청 본문은 PDF 원본 바이트 그대로(multipart 아님), 기록 번호·출처는 머리글(질의 문자열은 uvicorn 접근 기록에 남음).
# 총시한(timeout)은 Gateway 파일 대기 시간이고 Detection 쪽 시한(X-Deadline-Ms)은 그 80%(돌려보내는 전송 몫).
# 보낼 때·받을 때 모두 조각마다 남은 시간을 소켓 제한으로 다시 걸고 monotonic 총시한을 확인한다
# (urlopen(timeout=)은 소켓 작업마다의 제한이라 조각을 천천히 보내는 응답이면 총시간이 늘어난다 - 그래서 이 호출만
# 표준 라이브러리 http.client를 직접 쓴다. urllib도 안에서 같은 것을 쓴다).
# 실패(시간 초과·연결·HTTP 오류·JSON 오류·모르는 status·형식 오류)는 예외 대신 RedactResult(status="error")로 돌려준다.

REDACT_STATUSES = frozenset({"masked", "clean", "blocked", "unsupported", "residual", "busy", "timeout", "error"})
REDACT_MAX_PDF_BYTES = 20 * 1024 * 1024      # Detection MAX_OUTPUT_BYTES와 같음(넘으면 Detection이 unsupported)
REDACT_MAX_JSON_BYTES = 4 * 1024 * 1024      # blocked 응답의 decision(쪽 /detect 응답 모양)까지
REDACT_DEADLINE_SHARE = 0.8
REDACT_DEADLINE_MIN_MS, REDACT_DEADLINE_MAX_MS = 100, 30_000
REDACT_CHUNK = 64 * 1024
_REDACT_PREFIX_RE = re.compile(r"^[A-Za-z0-9#:_-]{1,150}$")
_REDACT_SERVICE_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
_REDACT_COUNTS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}:\d{1,9}(?:,[A-Za-z][A-Za-z0-9_]{0,63}:\d{1,9}){0,63}$")
_REDACT_DETAIL_RE = re.compile(r"[^A-Za-z0-9_:.-]")


@dataclass
class RedactResult:
    """`/redact/pdf` 결과. status는 Detection 응답 그대로, 호출 실패는 "error"(reason = TIMEOUT·UNREACHABLE·HTTP_404·
    PARSE_ERROR·TOO_LARGE·OTHER). 값·원문·파일 이름은 담지 않는다(pdf는 가린 PDF 바이트, masked일 때만)."""

    status: str
    reason: str | None = None
    pdf: bytes | None = None
    pages: int | None = None
    text_pages: int | None = None
    masked_pages: int | None = None
    pii_hits: str | None = None
    residual: str | None = None
    decision: DetectionResult | None = None
    elapsed_ms: float | None = None
    http_status: int | None = None


class _RedactDeadline(TimeoutError):
    pass


def redact_deadline_ms(timeout: float) -> int:
    """Detection 쪽 시한(X-Deadline-Ms) = Gateway 총시한의 80%, 100~30000ms."""
    ms = int(timeout * 1000 * REDACT_DEADLINE_SHARE)
    return max(REDACT_DEADLINE_MIN_MS, min(REDACT_DEADLINE_MAX_MS, ms))


def _redact_headers(prefix: str, length: int, source: dict, timeout: float) -> dict:
    headers = {
        "Content-Type": "application/pdf",
        "Content-Length": str(length),
        "X-Request-Prefix": prefix,
        "X-Deadline-Ms": str(redact_deadline_ms(timeout)),
        "Cache-Control": "no-store",
    }
    service = source.get("service")
    if isinstance(service, str) and _REDACT_SERVICE_RE.fullmatch(service):
        headers["X-Source-Service"] = service
    endpoint = source.get("endpoint")
    if isinstance(endpoint, str):
        endpoint = endpoint.split("?", 1)[0][:512]   # 질의 문자열은 보내지 않는다
        if endpoint and endpoint.isascii() and endpoint.isprintable():
            headers["X-Source-Endpoint"] = endpoint
    filename = source.get("filename")
    if isinstance(filename, str) and filename and filename.isprintable():
        headers["X-Source-Filename"] = urllib.parse.quote(filename[:255], safe="", encoding="utf-8")
    return headers


def _count_or_none(value):
    if value is None:
        return None
    if type(value) is int and 0 <= value <= 10_000_000:
        return value
    raise ValueError("bad count")


def _counts_text_or_none(value):
    if value is None or value == "":
        return None
    if isinstance(value, str) and len(value) <= 4096 and _REDACT_COUNTS_RE.fullmatch(value):
        return value
    raise ValueError("bad counts")


def _redact_detail(value) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return _REDACT_DETAIL_RE.sub("_", value)[:64]


def _redact_from_pdf(headers, body: bytes, elapsed_ms: float) -> RedactResult:
    if (headers.get("X-Redact-Status") or "").strip() != "masked" or not body.startswith(b"%PDF-"):
        raise ValueError("bad masked reply")

    def count(name):
        raw = (headers.get(name) or "").strip()
        if not raw.isascii() or not raw.isdigit():
            raise ValueError("bad count header")
        return _count_or_none(int(raw))

    return RedactResult(
        status="masked", pdf=body, pages=count("X-Redact-Pages"), text_pages=count("X-Redact-Text-Pages"),
        masked_pages=count("X-Redact-Masked-Pages"),
        pii_hits=_counts_text_or_none((headers.get("X-Redact-Pii-Hits") or "").strip()),
        elapsed_ms=elapsed_ms, http_status=200,
    )


def _redact_from_json(body: bytes, prefix: str, elapsed_ms: float) -> RedactResult:
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("bad reply")
    status = data.get("status")
    if not isinstance(status, str) or status not in REDACT_STATUSES or status == "masked":
        raise ValueError("unknown status")   # masked는 PDF 본문으로만 온다
    decision = None
    if status == "blocked":
        raw = data.get("decision")
        decision = _result_from_body(raw, f"{prefix}#f:0:pdf") if isinstance(raw, dict) else None
        if decision is None or decision.action not in {"block", "block_notify"}:
            raise ValueError("bad blocked decision")
    return RedactResult(
        status=status, reason=_redact_detail(data.get("detail")),
        pages=_count_or_none(data.get("pages")), text_pages=_count_or_none(data.get("text_pages")),
        masked_pages=_count_or_none(data.get("masked_pages")),
        pii_hits=_counts_text_or_none(data.get("pii_hits")), residual=_counts_text_or_none(data.get("residual")),
        decision=decision, elapsed_ms=elapsed_ms, http_status=200,
    )


def redact_pdf(base_url: str, prefix: str, data: bytes, source: dict | None = None,
               timeout: float = 2.0) -> RedactResult:
    """Detection `POST /redact/pdf`에 PDF 원본을 보내고 결과를 받는다. 예외를 올리지 않는다(실패 = status "error").

    timeout은 총시한(초, 보내기·기다리기·받기 합계). Detection 쪽 시한은 그 80%를 X-Deadline-Ms로 보낸다.
    호출 쪽 인자 오류(시한·기록 번호 모양)만 ValueError(check()와 같은 원칙)."""
    started = time.monotonic()

    def failed(reason, http_status=None):
        return RedactResult(status="error", reason=reason, http_status=http_status,
                            elapsed_ms=round((time.monotonic() - started) * 1000, 1))

    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 30:
        raise ValueError("Invalid redact timeout")
    if not isinstance(prefix, str) or not _REDACT_PREFIX_RE.fullmatch(prefix):
        raise ValueError("Invalid redact request prefix")
    data = bytes(data or b"")
    if len(data) > REDACT_MAX_PDF_BYTES:
        return failed("TOO_LARGE")
    deadline = started + timeout

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise _RedactDeadline("redact deadline")
        return left

    conn = response = None
    try:
        parts = urllib.parse.urlsplit(base_url.rstrip("/"))
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return failed("OTHER")
        connection_class = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = connection_class(parts.hostname, parts.port, timeout=remaining())
        conn.putrequest("POST", (parts.path or "") + "/redact/pdf", skip_accept_encoding=True)
        for name, value in _redact_headers(prefix, len(data), source or {}, timeout).items():
            conn.putheader(name, value)
        conn.endheaders()                      # 연결 + 머리글 전송
        # 소켓을 따로 잡아 둔다: 응답이 'Connection: close'면 getresponse()가 conn.sock을 None으로 비우고 응답 쪽에
        # 넘긴다(같은 소켓 객체라 시한을 계속 걸 수 있다)
        sock = conn.sock
        view = memoryview(data)
        for offset in range(0, len(data), REDACT_CHUNK):
            sock.settimeout(remaining())
            sock.sendall(view[offset:offset + REDACT_CHUNK])
        sock.settimeout(remaining())
        response = conn.getresponse()
        status = response.status
        media = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        limit = REDACT_MAX_PDF_BYTES if media == "application/pdf" else REDACT_MAX_JSON_BYTES
        declared = (response.getheader("Content-Length") or "").strip()
        if declared.isascii() and declared.isdigit() and int(declared) > limit:
            return failed("TOO_LARGE", status)
        chunks, total = [], 0
        while not response.isclosed():         # 본문을 다 읽으면 응답이 닫힌다(그 뒤 소켓은 쓰지 않음)
            sock.settimeout(remaining())
            chunk = response.read1(REDACT_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return failed("TOO_LARGE", status)
            chunks.append(chunk)
        body = b"".join(chunks)
        elapsed = round((time.monotonic() - started) * 1000, 1)
        if status != 200:
            return failed(f"HTTP_{status}", status)
        if media == "application/pdf":
            return _redact_from_pdf(response.headers, body, elapsed)
        if media == "application/json":
            return _redact_from_json(body, prefix, elapsed)
        return failed("PARSE_ERROR", status)
    except TimeoutError:          # _RedactDeadline·socket.timeout 포함
        return failed("TIMEOUT")
    except ValueError:            # JSON·머리글·모양 오류(UnicodeDecodeError 포함)
        return failed("PARSE_ERROR")
    except http.client.HTTPException:
        return failed("OTHER")
    except OSError:
        return failed("UNREACHABLE")
    except Exception:
        return failed("OTHER")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
