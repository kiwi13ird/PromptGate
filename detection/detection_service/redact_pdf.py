"""POST /redact/pdf - 가려야 하는 PDF를 지워서 돌려준다(2026-10-11 명세 §3.2·§3.3, PDF 마스킹 2단계).

흐름(부모 = 이 모듈, 자식 = `pdf_worker.py`)
  1. 접수: 머리글 확인 → 본문을 `request.stream()`으로 누적 상한까지 읽음 → 무거운 일은 스레드에서
  2. 자식: PDF 열기(열람 암호면 unsupported) → 쪽마다 글자(글리프 기준)·상자, 주석·양식 값 줄, ActualText 글자
  3. 부모: 글자 있는 쪽마다 `pipeline.run`(쪽 기록 `{prefix}#f:0:pdf:body:p{n}`, block_order=n). 어느 쪽이 차단이면 blocked
  4. 지울 것(replacement 있는 적중)이 없으면 원본 글자로 재검사 → 남는 값이 없으면 clean, 있으면 residual(위치를 못 찾은 값)
  5. 자식: 지우기(검은 상자, 글자 넣지 않음) → 문서 정리 → 저장(garbage=1, 객체 스트림) → 저장본 모든 쪽 재추출 + 객체 사전 문자열 검사
  6. 부모: 재추출 글자 재검사(원문·정규화·공백 뺀 것 - 정책상 가려야 하는 적중만 셈) + 사전 검사 → masked 또는 residual

- 처리 결과는 모두 200(masked면 application/pdf, 그 밖은 JSON), 입력 오류는 4xx. 응답에는 값·원문·파일 이름을 넣지 않는다.
- 동시 1건(남은 시한만큼 기다리고 못 얻으면 busy). 자식은 첫 요청 때 띄우고, 시한 초과·오류·비정상 종료면 죽이고 다음에 새로 띄운다.
- 자식은 `python -I`, 허용 목록 환경변수만(Redis·DB 접속 정보 없음), RLIMIT_AS·nice 10·oom_score_adj 1000(`pdf_worker.harden`).
- 인식기·정책·기록은 부모에만 있다 - 자식은 재로딩된 규칙을 모르고 정책 DB를 쓰면 안 된다.

이 모듈 맨 위는 표준 라이브러리·fastapi만 import한다. pipeline·인식기·정규화는 요청을 처리할 때 불러온다 -
`main.py`가 이 모듈을 못 불러와도 `/detect`는 뜬다(`/health`의 redact_pdf=false).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

log = logging.getLogger("detection.redact_pdf")

router = APIRouter()

WORKER_PATH = Path(__file__).resolve().with_name("pdf_worker.py")

MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_OUTPUT_BYTES = 20 * 1024 * 1024
MAX_REPLY_JSON = 64 * 1024 * 1024
DEADLINE_MIN_MS, DEADLINE_MAX_MS = 100, 30_000
PREFIX_RE = re.compile(r"^[A-Za-z0-9#:_-]{1,150}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
ENDPOINT_MAX = 512
FILENAME_MAX = 255
# Gateway `gateway_settings.DETECTION_WORST_MS_PER_1K_CHARS`(실측 최악 속도)와 같은 값. 시한 안에 쪽 판정을 끝낼 수 있는
# 글자 수만 받는다(공백 아닌 글자). 전체 글자(공백 포함)는 그 4배 + 여유 - rawdict 메모리 상한 역할.
WORST_MS_PER_1K_CHARS = 24.8
STATUSES = ("masked", "clean", "blocked", "unsupported", "residual", "busy", "timeout", "error")
COUNTED_ACTIONS = frozenset({"MASK_PARTIAL", "MASK_FULL", "BLOCK_NOTIFY"})
REPLACEMENT_TOKEN = re.compile(r"\[[A-Z][A-Z0-9_]*\]")

# 자식 환경변수 허용 목록 - 서비스 비밀 값(REDIS_PASSWORD 등)은 넘기지 않는다
CHILD_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT")
DEFAULT_RLIMIT_CAP = 1024 * 1024 * 1024

# 쪽 판정 전에 글자 수가 같은 대체만 한다(글자 좌표가 그대로라 지울 자리가 어긋나지 않음). 정규화(normalize_text)가
# 바꾸는 대시·공백 변형 중 1:1인 것 - 인식기는 파일 칸을 원본 좌표 글자로 보므로 en dash 든 주민번호도 잡히게.
_PREMAP = str.maketrans({
    **{c: "-" for c in "‐‑‒–—―−"},
    **{c: " " for c in "\t              　"},
})


class WorkerError(RuntimeError):
    """자식이 비정상(죽음·약속 위반·작업 예외)."""


class WorkerTimeout(WorkerError):
    """시한 초과로 자식을 죽였다."""


class _Deadline(Exception):
    def __init__(self, where: str) -> None:
        super().__init__(where)
        self.where = where


# ---------------------------------------------------------------- 자식 관리


def _rlimit_as() -> int:
    """자식 주소 공간 상한(바이트). 환경변수 DETECTION_REDACT_PDF_RLIMIT_MB가 있으면 그 값, 없으면 min(1GiB, MemTotal/4)."""
    configured = os.environ.get("DETECTION_REDACT_PDF_RLIMIT_MB")
    if configured:
        try:
            return max(0, int(configured)) * 1024 * 1024
        except ValueError:
            pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return min(DEFAULT_RLIMIT_CAP, int(line.split()[1]) * 1024 // 4)
    except (OSError, ValueError, IndexError):
        pass
    return DEFAULT_RLIMIT_CAP


def _child_command(test_ops: bool = False) -> tuple[list[str], dict[str, str]]:
    env = {k: os.environ[k] for k in CHILD_ENV_KEEP if k in os.environ}
    exe = sys.executable
    if sys.platform == "win32":
        # Windows venv의 python.exe는 진짜 인터프리터를 다시 띄우는 중계 프로그램이라 죽여도 자식이 남는다 -
        # multiprocessing(bpo-35797)처럼 기본 인터프리터를 직접 띄우고 venv 위치를 넘긴다.
        base = getattr(sys, "_base_executable", None)
        if base and os.path.normcase(os.path.abspath(base)) != os.path.normcase(os.path.abspath(exe)):
            env["__PYVENV_LAUNCHER__"] = exe
            exe = base
    cmd = [exe, "-I", str(WORKER_PATH), "--rlimit-as", str(_rlimit_as())]
    if test_ops:
        cmd.append("--test-ops")
    return cmd, env


class Worker:
    """자식 하나. 요청마다 감시 타이머가 시한에 자식을 죽인다(읽기가 막혀 있어도 EOF로 풀림)."""

    def __init__(self, proc: subprocess.Popen) -> None:
        self.proc = proc
        self.dead = False
        self.jobs = 0
        self._expired = threading.Event()

    @classmethod
    def spawn(cls, deadline: float, *, test_ops: bool = False) -> "Worker":
        cmd, env = _child_command(test_ops)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, close_fds=True, cwd=str(WORKER_PATH.parent))
        worker = cls(proc)
        hello, _ = worker.request(None, None, deadline)
        if hello.get("op") != "hello" or hello.get("protocol") != 1:
            worker.close()
            raise WorkerError("bad_hello")
        return worker

    def alive(self) -> bool:
        return not self.dead and self.proc.poll() is None

    def _expire(self) -> None:
        self._expired.set()
        self.kill()

    def request(self, cmd: dict | None, blob: bytes | None, deadline: float, *,
                max_json: int = MAX_REPLY_JSON, max_blob: int = 0) -> tuple[dict, bytes | None]:
        from . import pdf_worker as wire

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self.kill()
            raise WorkerTimeout("deadline")
        self._expired.clear()
        timer = threading.Timer(remaining, self._expire)
        timer.daemon = True
        timer.start()
        try:
            if cmd is not None:
                wire.write_frame(self.proc.stdin, wire.encode_json({**cmd, "blob": blob is not None}))
                if blob is not None:
                    wire.write_frame(self.proc.stdin, blob)
                self.proc.stdin.flush()
            reply = wire.decode_json(wire.read_frame(self.proc.stdout, max_json))
            data = None
            if reply.get("blob") is True:
                data = wire.read_frame(self.proc.stdout, max_blob)
        except (OSError, EOFError, ValueError) as exc:
            self.kill()
            if self._expired.is_set():
                raise WorkerTimeout("deadline") from exc
            raise WorkerError(type(exc).__name__) from exc
        finally:
            timer.cancel()
        if self._expired.is_set():
            self.kill()
            raise WorkerTimeout("deadline")
        if reply.get("ok") is not True:
            self.kill()
            raise WorkerError(str(reply.get("error") or "failed")[:64])
        return reply, data

    def kill(self) -> None:
        self.dead = True
        try:
            self.proc.kill()
        except OSError:
            pass

    def close(self) -> None:
        self.kill()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


class Runtime:
    """동시 1건 잠금 + 다시 쓰는 자식 하나."""

    # 자식이 이만큼 이상 메모리를 썼으면 작업 뒤 내린다(다음 요청이 새로 띄움). 주소 공간 상한의 절반.
    RECYCLE_FRACTION = 0.5

    def __init__(self) -> None:
        self.slot = threading.BoundedSemaphore(1)
        self.worker: Worker | None = None
        self.spawned = 0
        self.test_ops = False
        self._guard = threading.Lock()

    def worker_for(self, deadline: float) -> Worker:
        with self._guard:
            if self.worker is not None and not self.worker.alive():
                self.worker.close()
                self.worker = None
            if self.worker is None:
                try:
                    self.worker = Worker.spawn(deadline, test_ops=self.test_ops)
                except OSError as exc:
                    raise WorkerError("spawn_failed") from exc
                self.spawned += 1
            return self.worker

    def discard(self) -> None:
        with self._guard:
            if self.worker is not None:
                self.worker.close()
                self.worker = None

    def after_job(self, reply: dict | None) -> None:
        worker = self.worker
        if worker is None or not worker.alive():
            self.discard()
            return
        try:
            worker.request({"op": "release"}, None, time.monotonic() + 2.0)
        except WorkerError:
            self.discard()
            return
        peak = (reply or {}).get("vm_hwm_kb")
        limit = _rlimit_as()
        if isinstance(peak, int) and limit and peak * 1024 > limit * self.RECYCLE_FRACTION:
            self.discard()


RUNTIME = Runtime()


def shutdown() -> None:
    """앱 종료 때(lifespan) 자식을 내린다."""
    RUNTIME.discard()


# ---------------------------------------------------------------- 요청 머리글


class InputError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class Meta:
    prefix: str
    deadline_ms: int
    service: str | None
    endpoint: str | None
    filename: str | None

    def source(self, page: int) -> dict[str, Any]:
        return {"service": self.service, "endpoint": self.endpoint, "filename": self.filename,
                "content_type": "file", "format": "pdf", "signature_original_offsets": True, "block_order": page}


def _printable(value: str) -> bool:
    return all(c.isprintable() for c in value)


def parse_headers(headers) -> Meta:
    prefix = headers.get("x-request-prefix")
    if prefix is None or not PREFIX_RE.fullmatch(prefix):
        raise InputError(400, "bad_request_prefix")
    raw_deadline = headers.get("x-deadline-ms")
    if raw_deadline is None or not raw_deadline.strip().isdigit():
        raise InputError(400, "bad_deadline")
    deadline_ms = int(raw_deadline.strip())
    if not DEADLINE_MIN_MS <= deadline_ms <= DEADLINE_MAX_MS:
        raise InputError(400, "bad_deadline")
    service = headers.get("x-source-service")
    if service is not None and not SERVICE_RE.fullmatch(service):
        raise InputError(400, "bad_source_service")
    endpoint = headers.get("x-source-endpoint")
    if endpoint is not None:
        endpoint = endpoint.split("?", 1)[0] or None  # 질의 문자열은 기록에 남기지 않는다(Gateway도 빼고 보냄)
    if endpoint is not None and (len(endpoint) > ENDPOINT_MAX or not _printable(endpoint)):
        raise InputError(400, "bad_source_endpoint")
    filename = headers.get("x-source-filename")
    if filename is not None:
        try:
            filename = unquote(filename, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise InputError(400, "bad_source_filename") from exc
        if not filename or len(filename) > FILENAME_MAX or not _printable(filename):
            raise InputError(400, "bad_source_filename")
    media = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if media != "application/pdf":
        raise InputError(415, "content_type_not_pdf")
    length = headers.get("content-length")
    if length is not None:
        if not length.strip().isdigit():
            raise InputError(400, "bad_content_length")
        if int(length) > MAX_INPUT_BYTES:
            raise InputError(413, "too_large")
    return Meta(prefix, deadline_ms, service, endpoint, filename)


class _BodyTooLarge(Exception):
    pass


async def _read_body(request: Request, limit: int) -> bytes:
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------- 처리


@dataclass
class Outcome:
    status: str
    pages: int | None = None
    text_pages: int | None = None
    masked_pages: int | None = None
    pii_hits: str | None = None
    residual: str | None = None
    decision: dict | None = None
    detail: str | None = None
    pdf: bytes | None = field(default=None, repr=False)


def _counts_text(counts: Counter) -> str | None:
    return ",".join(f"{k}:{v}" for k, v in sorted(counts.items()) if v) or None


def _parse_hits(value: str | None) -> Counter:
    out: Counter = Counter()
    for part in (value or "").split(","):
        name, _, n = part.partition(":")
        if name and n.isdigit():
            out[name] += int(n)
    return out


def _check(deadline: float, where: str) -> None:
    if time.monotonic() > deadline:
        raise _Deadline(where)


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


class _Checker:
    """재검사 - 인식기 + 정책. 정책상 가려야 하는 적중(MASK_PARTIAL·MASK_FULL·BLOCK_NOTIFY, 정책 없음 = BLOCK_NOTIFY)만 센다."""

    def __init__(self) -> None:
        from preprocessing.normalizer import normalize_for_matching, normalize_text
        from signature import engine as signature

        from . import policy_store

        self.signature = signature
        self.policy_store = policy_store
        self.normalize_text = normalize_text
        self.normalize_for_matching = normalize_for_matching
        self._evident: dict[tuple[str, str], bool] = {}

    def self_evident(self, value: str, entity_type: str) -> bool:
        """값만 따로 검사해도 같은 유형으로 잡히는가. 아니면 이름표(`비밀번호:` 등)에 기대는 적중이다."""
        key = (value, entity_type)
        if key not in self._evident:
            try:
                hits = self.signature.query(value)
            except Exception:
                hits = []
            self._evident[key] = any(h.entity_type == entity_type for h in hits)
        return self._evident[key]

    def counted(self, text: str, *, squashed: bool) -> Counter:
        hits = [h for h in self.signature.query(text) if not REPLACEMENT_TOKEN.fullmatch(text[h.start:h.end])]
        if squashed:
            # 공백을 빼면 이름표와 다음 낱말이 붙어 이름표 규칙(PASSWORD 등)이 아무 글자나 잡는다 - 공백 뺀 검사는
            # 값만으로 잡히는 유형(주민번호·전화·메일·토큰)을 위한 것이라 이름표에 기대는 적중은 세지 않는다.
            hits = [h for h in hits if self.self_evident(text[h.start:h.end], h.entity_type)]
        if not hits:
            return Counter()
        resolution = self.policy_store.resolve(hits)
        return Counter(h.entity_type for h, action in zip(hits, resolution.hit_actions) if action in COUNTED_ACTIONS)

    def residual(self, pages: list[tuple[str, str | None]], deadline: float) -> Counter:
        total: Counter = Counter()
        for text, actual in pages:
            for source in (text, actual):
                if not source or not source.strip():
                    continue
                _check(deadline, "recheck")
                per: Counter = Counter()
                seen = set()
                for variant, squashed in ((source, False), (self.normalize_text(source), False),
                                          (_squash(source), True), (self.normalize_for_matching(source), True)):
                    if not variant or (variant, squashed) in seen:
                        continue
                    seen.add((variant, squashed))
                    for k, v in self.counted(variant, squashed=squashed).items():
                        per[k] = max(per[k], v)
                total.update(per)
        return total


def _label_start(text: str, start: int) -> int:
    """이름표에 기대는 값이면 바로 앞 이름표(구분자 `:`·`=`·`：`와 그 앞 낱말)까지 지울 구간을 넓힌다.

    값만 지우면 재검사에서 남은 이름표가 다음 줄 낱말을 값으로 잡는다(명세 §6-7) - 이름표도 같이 지운다.
    """
    j = start
    while j > 0 and text[j - 1].isspace():
        j -= 1
    if j > 0 and text[j - 1] in "\"'":
        j -= 1
    if j == 0 or text[j - 1] not in ":=：":
        return start
    j -= 1
    while j > 0 and text[j - 1] in " \t":
        j -= 1
    if j > 0 and text[j - 1] in "\"'":
        j -= 1
    k = j
    while k > 0 and not text[k - 1].isspace() and j - k < 64:
        k -= 1
    return k if k < j else start


# 10/12 사용자 결정: 지운 자리 표시는 질문·DOCX·HWPX와 같은 Detection 대체 글자([KR_RRN]·[KR_PHONE_NUMBER] 등).
# 부분 가림 정책이어도 PDF는 값 전체를 지우므로 전체 가림 표시를 쓴다. 영문 기본 글꼴(Helvetica)로 쓸 수 있는 ASCII뿐
PDF_LABEL_DEFAULT = "[PII]"


def pdf_label(entity_type: str) -> str:
    from signature.masker import REPLACEMENTS

    entity = str(entity_type or "")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,40}", entity):
        return PDF_LABEL_DEFAULT
    return REPLACEMENTS.get(entity, f"[{entity}]")


def _merge_spans(spans: list[tuple]) -> list[list]:
    """(시작, 끝[, 표시]) → 겹치는 구간을 합친 [시작, 끝, 표시]. 표시가 다른 구간이 합쳐지면 [PII]."""
    out: list[list] = []
    for item in sorted(spans, key=lambda x: (x[0], x[1])):
        s, e = item[0], item[1]
        label = item[2] if len(item) > 2 else PDF_LABEL_DEFAULT
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
            if out[-1][2] != label:
                out[-1][2] = PDF_LABEL_DEFAULT
        else:
            out.append([s, e, label])
    return out


def _pages_from(reply: dict, expected: int | None = None) -> list[tuple[str, str | None]]:
    pages = reply.get("pages")
    count = reply.get("page_count")
    if not isinstance(pages, list) or not isinstance(count, int) or count != len(pages):
        raise WorkerError("bad_reply")
    if expected is not None and count != expected:
        raise WorkerError("page_count_changed")
    out = []
    for page in pages:
        text = page.get("t") if isinstance(page, dict) else None
        actual = page.get("a") if isinstance(page, dict) else None
        if not isinstance(text, str) or not (actual is None or isinstance(actual, str)):
            raise WorkerError("bad_reply")
        out.append((text, actual))
    return out


def _public_decision(response) -> dict:
    """차단한 쪽의 /detect 응답(같은 모양). 쪽 글자로 만든 masked_text와 부분 가림 값(replacement)은 뺀다."""
    body = response.model_dump()
    body["masked_text"] = None
    for finding in body.get("findings") or []:
        finding["replacement"] = None
    return body


def _budget(deadline_ms: int) -> tuple[int, int]:
    nonspace = int(deadline_ms * 1000 / WORST_MS_PER_1K_CHARS)
    return nonspace * 4 + 10_000, nonspace


def run_job(worker: Worker, body: bytes, meta: Meta, deadline: float, redis_client, decision_log,
            job: Outcome) -> tuple[Outcome, dict | None]:
    from . import pipeline

    max_total, max_nonspace = _budget(meta.deadline_ms)
    reply, _ = worker.request({"op": "extract", "max_total_chars": max_total, "max_nonspace_chars": max_nonspace},
                              body, deadline)
    if reply.get("status") == "unsupported":
        job.status, job.detail = "unsupported", str(reply.get("detail") or "unsupported")[:64]
        return job, reply
    if reply.get("status") != "ok":
        raise WorkerError("bad_reply")
    pages = _pages_from(reply)
    job.pages = len(pages)
    text_pages = [n for n, (text, _) in enumerate(pages) if text.strip()]
    job.text_pages = len(text_pages)
    if not text_pages:
        job.status, job.detail = "unsupported", "no_text"
        return job, reply

    checker = _Checker()
    counts: Counter = Counter()
    spans: dict[int, list[list[int]]] = {}
    values: list[str] = []
    value_types: list[str] = []
    for n in text_pages:
        _check(deadline, "judge")
        original = pages[n][0]
        text = original.translate(_PREMAP)
        response = pipeline.run(redis_client, text, request_id=f"{meta.prefix}#f:0:pdf:body:p{n}",
                                source=meta.source(n), decision_log=decision_log)
        counts.update(_parse_hits(response.pii_hits))
        job.pii_hits = _counts_text(counts)
        if response.blocked or response.decision.action in ("block", "block_notify"):
            job.status, job.decision, job.detail = "blocked", _public_decision(response), f"page:{n}"
            return job, reply
        if response.hash_status != "ok" or response.signature_status != "ok":
            job.status, job.detail = "error", "page_check_incomplete"
            return job, reply
        page_spans = []
        for finding in response.findings:
            if finding.replacement is None:
                continue
            s, e = finding.start, finding.end
            if not 0 <= s < e <= len(text):
                raise WorkerError("finding_out_of_range")
            for value in {original[s:e], text[s:e]}:
                values.append(value)
                value_types.append(finding.entity_type)
            if not checker.self_evident(text[s:e], finding.entity_type):
                s = _label_start(text, s)
            page_spans.append((s, e, pdf_label(finding.entity_type)))
        if page_spans:
            spans[n] = _merge_spans(page_spans)

    if not spans:
        residual = checker.residual(pages, deadline)
        if residual:
            job.status, job.residual, job.detail = "residual", _counts_text(residual), "unlocated_value"
        else:
            job.status = "clean"
        return job, reply

    job.masked_pages = len(spans)
    _check(deadline, "before_redact")
    reply, pdf = worker.request({"op": "redact", "spans": {str(k): v for k, v in spans.items()}, "values": values,
                                 "max_output": MAX_OUTPUT_BYTES}, None, deadline, max_blob=MAX_OUTPUT_BYTES)
    if reply.get("status") == "unsupported":
        job.status, job.detail = "unsupported", str(reply.get("detail") or "unsupported")[:64]
        return job, reply
    if reply.get("status") != "ok" or pdf is None or reply.get("size") != len(pdf) or not pdf.startswith(b"%PDF-"):
        raise WorkerError("bad_reply")
    after = _pages_from(reply, expected=len(pages))
    residual = checker.residual(after, deadline)
    hits = reply.get("dict_hits")
    if not isinstance(hits, list) or not all(isinstance(k, int) and 0 <= k < len(values) for k in hits):
        raise WorkerError("bad_reply")
    for k in set(hits):
        residual[value_types[k]] += 1
    if residual:
        job.status, job.residual, job.detail = "residual", _counts_text(residual), "recheck"
        return job, reply
    job.status, job.pdf = "masked", pdf
    return job, reply


def process(body: bytes, meta: Meta, deadline: float, redis_client, decision_log) -> Outcome:
    """스레드에서 돈다. 예외를 올리지 않는다 - 모든 실패는 상태값으로."""
    job = Outcome("error")
    if not RUNTIME.slot.acquire(timeout=max(0.0, deadline - time.monotonic())):
        job.status, job.detail = "busy", "busy"
        return job
    reply = None
    try:
        worker = RUNTIME.worker_for(deadline)
        worker.jobs += 1
        job, reply = run_job(worker, body, meta, deadline, redis_client, decision_log, job)
    except WorkerTimeout:
        RUNTIME.discard()
        job.status, job.detail, job.pdf = "timeout", "worker", None
    except _Deadline as exc:
        job.status, job.detail, job.pdf = "timeout", exc.where, None
    except WorkerError as exc:
        RUNTIME.discard()
        job.status, job.detail, job.pdf = "error", f"worker:{exc}"[:64], None
    except Exception as exc:  # noqa: BLE001 - 어떤 실패도 원본을 통과시키지 않는다(Gateway는 200 masked/clean만 보냄)
        log.warning("redact_pdf failed: %s", type(exc).__name__)
        job.status, job.detail, job.pdf = "error", type(exc).__name__[:64], None
    finally:
        try:
            RUNTIME.after_job(reply)
        finally:
            RUNTIME.slot.release()
    if job.status != "masked":
        job.pdf = None
    return job


# ---------------------------------------------------------------- 엔드포인트


def _json(job: Outcome, elapsed_ms: float) -> JSONResponse:
    return JSONResponse(
        {"status": job.status, "pages": job.pages, "text_pages": job.text_pages, "masked_pages": job.masked_pages,
         "pii_hits": job.pii_hits, "residual": job.residual, "decision": job.decision, "detail": job.detail,
         "elapsed_ms": round(elapsed_ms, 1)},
        headers={"X-Redact-Status": job.status, "Cache-Control": "no-store"},
    )


@router.post("/redact/pdf")
async def redact_pdf(request: Request):
    started = time.monotonic()
    try:
        meta = parse_headers(request.headers)
    except InputError as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    deadline = started + meta.deadline_ms / 1000
    try:
        body = await asyncio.wait_for(_read_body(request, MAX_INPUT_BYTES), timeout=max(0.001, deadline - time.monotonic()))
    except _BodyTooLarge:
        return JSONResponse({"detail": "too_large"}, status_code=413)
    except asyncio.TimeoutError:
        return _json(Outcome("timeout", detail="upload"), (time.monotonic() - started) * 1000)
    if b"%PDF-" not in body[:1024]:
        return JSONResponse({"detail": "not_pdf"}, status_code=415)
    state = request.app.state
    job = await run_in_threadpool(process, body, meta, deadline, state.redis, state.decision_log)
    elapsed = (time.monotonic() - started) * 1000
    if job.status == "masked" and job.pdf is not None:
        return Response(content=job.pdf, media_type="application/pdf", headers={
            "X-Redact-Status": "masked",
            "X-Redact-Pages": str(job.pages),
            "X-Redact-Text-Pages": str(job.text_pages),
            "X-Redact-Masked-Pages": str(job.masked_pages),
            "X-Redact-Pii-Hits": job.pii_hits or "",
            "X-Redact-Elapsed-Ms": f"{elapsed:.1f}",
            "Cache-Control": "no-store",
        })
    return _json(job, elapsed)
