"""시스템 상태 - 대시보드 '시스템 상태' 화면용 GET /admin/system-status의 재료 (2026-10-12).

한 번의 호출로 Detection 자신·Redis·로그 전송·키워드 작업과, AWS에서 읽어 오는 EC2 인스턴스·RDS 상태를 돌려준다.

- 읽기 전용이다. 인스턴스를 켜거나 끄지 않는다(GPU 켜기·끄기는 reporting/gpu.py).
- AWS 호출(EC2 2번·RDS 1번)은 호출마다 2초에 끊고, 결과는 30초 재사용한다. 호출은 백그라운드 스레드에서 한 번에 하나만 돌고
  요청은 최대 AWS_WAIT초만 기다린다 - 대시보드 백엔드가 Detection을 2.5초에 끊으므로, AWS가 느릴 때 이 엔드포인트가 막혀
  Detection 전체가 '끊김'으로 보이면 안 된다. 기다리다 놓친 부분은 "unavailable"로 내고, 늦게 끝난 결과는 다음 요청이 받는다.
- 응답에는 비밀(DSN·비밀번호·토큰)과 RDS 호스트 이름을 싣지 않는다. AWS 오류는 메시지(ARN·계정 번호가 들어 있다) 없이
  고정된 짧은 코드로만 낸다. DSN은 호스트 첫 레이블을 뽑는 데만 쓰고 기록하지 않는다.

환경변수:
  SYSTEM_STATUS_INSTANCES  "gateway=i-...,detection=i-...,dashboard=i-..." 미설정이면 DEFAULT_INSTANCES. gpu는 REPORT_GPU_INSTANCE_ID에서 온다.
  SYSTEM_STATUS_RDS_ID     RDS 식별자. 없으면 DETECTION_PG_DSN 호스트의 첫 레이블. 둘 다 없으면 rds.error="not_configured".
                           (탐지 API 프로세스는 RDS 접속 정보를 읽지 않게 만들어져 있어 보통 DSN이 없다 - 이 값을 드롭인에 넣는다.)
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import math
import os
import re
import threading
import time
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from reporting import gpu as report_gpu

log = logging.getLogger("detection.system_status")

REGION = "ap-northeast-2"
AWS_CALL_TIMEOUT = 2.0    # 연결·응답 각각. 재시도하지 않는다
AWS_TTL = 30.0            # AWS 조회 결과 재사용 시간
AWS_WAIT = 2.0            # 한 요청이 AWS 결과를 기다리는 최대 시간
REDIS_WAIT = 0.5          # PING(+문서 수) 응답을 기다리는 최대 시간
ABANDON_AFTER = 15.0      # 이만큼 안 끝나는 조회는 멈춘 것으로 보고 새로 시작한다(DNS 지연 등)

LOG_FAILURES_DOWN = 3     # 연속 실패가 이만큼이면 전송 이상 - 대시보드 판정 기준과 같다
LOG_STALL_S = 600.0       # 보낼 것이 남았는데 마지막 성공이 이보다 오래면 이상 - 대시보드 판정 기준과 같다
LOG_STATUS_STALE_S = 90.0 # 전송 서비스는 1초 안팎마다 상태 파일을 갱신한다. 이보다 오래되면 서비스가 멈춘 것

DEFAULT_INSTANCES = "gateway=i-0a8b8aee6f3d24a36,detection=i-0ff450ae50695041a,dashboard=i-09593052f863fb7c2"
_ENV_ROLES = ("gateway", "detection", "dashboard")   # gpu는 REPORT_GPU_INSTANCE_ID 하나로만 정한다
_INSTANCE_ID = re.compile(r"i-[0-9a-f]{8,17}")
_RDS_ID = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,62}")
_PERMISSION_CODES = frozenset({"UnauthorizedOperation", "AccessDenied", "AccessDeniedException", "UnauthorizedAccess"})
_RDS_NOT_FOUND_CODES = frozenset({"DBInstanceNotFound", "DBInstanceNotFoundFault"})

_STARTED_TS = time.time()
_STARTED_MONO = time.monotonic()


# ---------------------------------------------------------------- 작은 도구

def iso_utc(ts: Any) -> str | None:
    """epoch 초 → "2026-10-12T01:02:03Z". 값이 없거나 이상하면 None."""
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def _count(value: Any, default: int | None = 0) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return default
    return int(value)


def _text(value: Any, limit: int = 64) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    code = error.get("Code") if isinstance(error, dict) else None
    return code if isinstance(code, str) else ""


def _aws_error(exc: BaseException) -> str:
    """AWS 오류를 "permission_missing"|"unavailable" 둘로 줄인다. 오류 메시지는 쓰지 않는다."""
    return "permission_missing" if _error_code(exc) in _PERMISSION_CODES else "unavailable"


# ---------------------------------------------------------------- 설정 읽기

def configured_instances(environ: Mapping[str, str], gpu_instance_id: str = "") -> list[tuple[str, str]]:
    """조회할 (역할, 인스턴스 ID) 목록. 잘못된 항목은 건너뛴다. 순서는 gateway·detection·dashboard·gpu."""
    raw = environ.get("SYSTEM_STATUS_INSTANCES")
    if raw is None:
        raw = DEFAULT_INSTANCES
    found: dict[str, str] = {}
    ignored = 0
    for part in raw.split(","):
        if not part.strip():
            continue
        role, sep, instance_id = part.partition("=")
        role, instance_id = role.strip().lower(), instance_id.strip()
        if sep and role in _ENV_ROLES and role not in found and _INSTANCE_ID.fullmatch(instance_id):
            found[role] = instance_id
        else:
            ignored += 1
    if ignored:
        log.warning("SYSTEM_STATUS_INSTANCES: %d invalid entries ignored", ignored)
    items = [(role, found[role]) for role in _ENV_ROLES if role in found]
    gpu = (gpu_instance_id or "").strip()
    if gpu and _INSTANCE_ID.fullmatch(gpu):
        items.append(("gpu", gpu))
    return items


def _dsn_host(dsn: str) -> str | None:
    if "://" in dsn:
        try:
            host = urlsplit(dsn).hostname
        except ValueError:
            return None
    else:  # libpq 키=값 형식: host=... (따옴표 가능)
        match = re.search(r"(?:^|\s)host\s*=\s*(?:'([^']*)'|(\S+))", dsn)
        host = (match.group(1) or match.group(2)) if match else None
    return host.split(",")[0].strip() if host else None


def rds_identifier(environ: Mapping[str, str]) -> str | None:
    """RDS 식별자: SYSTEM_STATUS_RDS_ID, 없으면 DETECTION_PG_DSN 호스트의 첫 DNS 레이블. 모르면 None."""
    explicit = (environ.get("SYSTEM_STATUS_RDS_ID") or "").strip()
    if explicit:
        return explicit if _RDS_ID.fullmatch(explicit) else None
    host = _dsn_host((environ.get("DETECTION_PG_DSN") or "").strip())
    if not host or host.startswith("/"):   # 호스트 없음·유닉스 소켓 경로
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None                        # IP 주소는 DNS 이름이 아니다
    except ValueError:
        pass
    label = host.split(".")[0]
    return label if _RDS_ID.fullmatch(label) else None


# ---------------------------------------------------------------- AWS (EC2·RDS)

def _aws_config():
    from botocore.config import Config

    return Config(connect_timeout=AWS_CALL_TIMEOUT, read_timeout=AWS_CALL_TIMEOUT, retries={"max_attempts": 0})


@functools.lru_cache(maxsize=1)
def _ec2_client():
    import boto3  # Detection venv에만 필요하다(GPU 제어가 이미 쓴다)

    return boto3.client("ec2", region_name=REGION, config=_aws_config())


@functools.lru_cache(maxsize=1)
def _rds_client():
    import boto3

    return boto3.client("rds", region_name=REGION, config=_aws_config())


def _instances_failed(error: str) -> dict[str, Any]:
    return {"ok": False, "error": error, "status_checks": None, "items": []}


def collect_instances(ec2_factory: Callable[[], Any], instances: list[tuple[str, str]]) -> dict[str, Any]:
    """EC2 상태. describe_instances가 되면 ok - 상태 점검(describe_instance_status)은 권한이 따로라 status_checks로 나눈다.

    예외를 올리지 않는다. 인스턴스 ID는 Filters로 묻는다 - 없어진 ID가 하나 있어도 나머지 조회가 통째로 실패하지 않는다.
    """
    if not instances:
        return {"ok": True, "error": None, "status_checks": "ok", "items": []}
    ids = [instance_id for _, instance_id in instances]
    try:
        ec2 = ec2_factory()
        found = ec2.describe_instances(Filters=[{"Name": "instance-id", "Values": ids}])
    except Exception as exc:  # noqa: BLE001 - 권한 없음·시간 초과·boto3 없음 모두 화면에는 같은 한 줄
        log.warning("describe_instances failed: %s", type(exc).__name__)
        return _instances_failed(_aws_error(exc))
    by_id: dict[str, Any] = {}
    for reservation in found.get("Reservations") or []:
        for instance in reservation.get("Instances") or []:
            if isinstance(instance, dict) and isinstance(instance.get("InstanceId"), str):
                by_id[instance["InstanceId"]] = instance

    checks = "ok"
    statuses: dict[str, tuple[str | None, str | None]] = {}
    present = [instance_id for instance_id in ids if instance_id in by_id]
    if present:
        try:
            response = ec2.describe_instance_status(InstanceIds=present, IncludeAllInstances=True)
            for entry in response.get("InstanceStatuses") or []:
                statuses[entry.get("InstanceId")] = (_text((entry.get("SystemStatus") or {}).get("Status")),
                                                      _text((entry.get("InstanceStatus") or {}).get("Status")))
        except Exception as exc:  # noqa: BLE001
            log.warning("describe_instance_status failed: %s", type(exc).__name__)
            checks = _aws_error(exc)

    items = []
    for role, instance_id in instances:
        instance = by_id.get(instance_id)
        name = next((tag.get("Value") for tag in (instance or {}).get("Tags") or []
                     if isinstance(tag, dict) and tag.get("Key") == "Name"), None)
        system_status, instance_status = statuses.get(instance_id, (None, None))
        items.append({
            "role": role,
            "instance_id": instance_id,
            "name": _text(name),
            "state": (_text((instance.get("State") or {}).get("Name")) or "unknown") if instance else "not_found",
            "system_status": system_status,
            "instance_status": instance_status,
        })
    return {"ok": True, "error": None, "status_checks": checks, "items": items}


def collect_rds(rds_factory: Callable[[], Any], identifier: str | None) -> dict[str, Any]:
    """RDS 인스턴스 상태(available 등)와 엔진. 예외를 올리지 않는다."""
    if not identifier:
        return {"ok": False, "error": "not_configured", "identifier": None, "status": None, "engine": None}
    failed = {"ok": False, "identifier": identifier, "status": None, "engine": None}
    try:
        found = rds_factory().describe_db_instances(DBInstanceIdentifier=identifier)
    except Exception as exc:  # noqa: BLE001
        log.warning("describe_db_instances failed: %s", type(exc).__name__)
        # 식별자에 맞는 인스턴스가 없다 = 설정이 틀렸다
        return {**failed, "error": "not_configured" if _error_code(exc) in _RDS_NOT_FOUND_CODES else _aws_error(exc)}
    instance = next(iter(found.get("DBInstances") or []), None)
    if not isinstance(instance, dict):
        return {**failed, "error": "unavailable"}
    return {"ok": True, "error": None, "identifier": identifier,
            "status": _text(instance.get("DBInstanceStatus")), "engine": _text(instance.get("Engine"))}


# ---------------------------------------------------------------- Redis · 로그 전송 · 키워드 작업

def probe_redis(client: Any, *, clock: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    """PING 지연과 색인 문서 수. 예외를 올리지 않는다(오류는 클래스 이름만 - 메시지에 주소가 들어 있을 수 있다)."""
    started = clock()
    try:
        client.ping()
        latency = round((clock() - started) * 1000, 1)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "latency_ms": None, "error": type(exc).__name__[:40], "documents": None}
    try:
        documents = int(client.scard("wh:docs"))
    except Exception:  # noqa: BLE001
        documents = None
    return {"ok": True, "latency_ms": latency, "error": None, "documents": documents}


def log_shipping_state(status: Mapping[str, Any] | None, now: float) -> dict[str, Any]:
    """전송 서비스 상태 파일(shipper.status.json) → 화면용. ok는 대시보드 판정과 같은 기준에 '서비스가 살아 있는가'를 더한 것."""
    if status is None:
        return {"ok": False, "pending_bytes": 0, "last_ok_at": None, "consecutive_failures": 0, "rejected_total": 0,
                "last_error": "status_file_missing"}
    failures = _count(status.get("consecutive_failures"))
    pending = _count(status.get("pending_bytes"))
    last_ok = status.get("last_ok_ts") if isinstance(status.get("last_ok_ts"), (int, float)) else None
    updated = status.get("updated_ts")
    stale = isinstance(updated, bool) or not isinstance(updated, (int, float)) or now - updated > LOG_STATUS_STALE_S
    stalled = pending > 0 and (last_ok is None or now - last_ok > LOG_STALL_S)
    # last_error는 지금 실패 중일 때만 보인다 - 전송 서비스는 한 번 난 오류 이름을 복구 뒤에도 파일에 남겨 둔다
    last_error = _text(status.get("last_error"), 60) if failures > 0 else None
    if stale:
        last_error = "shipper_not_running"
    return {"ok": failures < LOG_FAILURES_DOWN and not stale and not stalled, "pending_bytes": pending,
            "last_ok_at": iso_utc(last_ok), "consecutive_failures": failures,
            "rejected_total": _count(status.get("rejected_total")), "last_error": last_error}


def keyword_jobs_state(jobs: Mapping[str, Any] | None) -> dict[str, int | None]:
    """키워드 작업 건수. 키워드 저장소를 못 쓰면 값은 모두 None(0으로 보이면 '정상'으로 읽힌다)."""
    jobs = jobs or {}
    return {key: _count(jobs.get(key), None) for key in ("queued", "running", "failed")}


# ---------------------------------------------------------------- 조회 재사용·대기 제한

class _Refresher:
    """compute()를 백그라운드 스레드에서 돌려 결과를 ttl초 재사용한다. 같은 key로는 한 번에 하나만 돈다."""

    def __init__(self, ttl: float, clock: Callable[[], float]) -> None:
        self.ttl = ttl
        self.clock = clock
        self._lock = threading.Lock()
        self._key: Any = None
        self._value: Any = None
        self._stamp: float | None = None
        self._pending: tuple[Future, float, Any] | None = None   # (결과, 시작 시각, key)

    def start(self, key: Any, compute: Callable[[], Any], fallback: Any) -> Future:
        """신선한 결과가 있으면 끝난 Future를, 아니면 진행 중인(없으면 새로 시작한) Future를 돌려준다."""
        with self._lock:
            now = self.clock()
            if self._stamp is not None and self._key == key and now - self._stamp < self.ttl:
                done: Future = Future()
                done.set_result(self._value)
                return done
            if self._pending is not None and self._pending[2] == key and now - self._pending[1] < ABANDON_AFTER:
                return self._pending[0]
            future: Future = Future()
            self._pending = (future, now, key)   # 멈춘 이전 조회는 버린다 - 늦게 끝나도 결과를 저장하지 않는다
        threading.Thread(target=self._run, args=(future, key, compute, fallback), daemon=True,
                         name="system-status-refresh").start()
        return future

    def _run(self, future: Future, key: Any, compute: Callable[[], Any], fallback: Any) -> None:
        try:
            value = compute()
        except Exception as exc:  # noqa: BLE001 - compute는 예외를 올리지 않게 짜여 있다. 그래도 요청이 끝까지 기다리지 않게
            log.warning("status refresh failed: %s", type(exc).__name__)
            value = fallback
        with self._lock:
            if self._pending is not None and self._pending[0] is future:
                self._pending = None
                self._key, self._value, self._stamp = key, value, self.clock()
        future.set_result(value)


class StatusCollector:
    def __init__(self, *, ec2_factory: Callable[[], Any] | None = None, rds_factory: Callable[[], Any] | None = None,
                 environ: Mapping[str, str] | None = None, gpu_instance_id: Callable[[], str] | None = None,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
                 ttl: float = AWS_TTL, aws_wait: float = AWS_WAIT, redis_wait: float = REDIS_WAIT) -> None:
        self.ec2_factory = ec2_factory or _ec2_client
        self.rds_factory = rds_factory or _rds_client
        self.environ = os.environ if environ is None else environ
        self.gpu_instance_id = gpu_instance_id or (lambda: report_gpu.INSTANCE_ID)   # 호출 때 읽는다
        self.clock = clock
        self.wall = wall
        self.aws_wait = aws_wait
        self.redis_wait = redis_wait
        self._ec2 = _Refresher(ttl, clock)
        self._rds = _Refresher(ttl, clock)
        self._redis = _Refresher(0.0, clock)   # 재사용은 없고, 멈춘 PING이 쌓이지 않게 한 번에 하나만

    def _wait(self, future: Future, deadline: float, fallback: Any) -> Any:
        try:
            return future.result(timeout=max(deadline - self.clock(), 0.0))
        except FutureTimeout:
            return fallback

    def collect(self, *, redis_client: Any, shipper_status: Mapping[str, Any] | None, signatures: Mapping[str, Any],
                policies: int | None, keyword_jobs: Mapping[str, Any] | None, redact_pdf: bool) -> dict[str, Any]:
        started = self.clock()
        now = self.wall()
        instances = configured_instances(self.environ, self.gpu_instance_id())
        rds_id = rds_identifier(self.environ)
        # 느린 것(AWS)을 먼저 시작해 두고, 그동안 나머지를 읽는다
        ec2_future = self._ec2.start(tuple(instances), lambda: collect_instances(self.ec2_factory, instances),
                                     _instances_failed("unavailable"))
        rds_future = self._rds.start(rds_id, lambda: collect_rds(self.rds_factory, rds_id),
                                     {"ok": False, "error": "unavailable", "identifier": rds_id, "status": None,
                                      "engine": None})
        redis_future = self._redis.start(id(redis_client), lambda: probe_redis(redis_client, clock=self.clock),
                                         {"ok": False, "latency_ms": None, "error": "unavailable", "documents": None})
        redis_state = self._wait(redis_future, started + self.redis_wait,
                                 {"ok": False, "latency_ms": None, "error": "timeout", "documents": None})
        aws_deadline = started + self.aws_wait
        instances_state = self._wait(ec2_future, aws_deadline, _instances_failed("unavailable"))
        rds_state = self._wait(rds_future, aws_deadline,
                               {"ok": False, "error": "unavailable", "identifier": rds_id, "status": None,
                                "engine": None})
        return {
            "checked_at": iso_utc(now),
            "detection": {
                "status": "ok",
                "started_at": iso_utc(_STARTED_TS),
                "uptime_s": max(int(time.monotonic() - _STARTED_MONO), 0),
                "signatures": {key: _count(signatures.get(key), None) for key in ("builtin", "database", "keywords")},
                "documents": redis_state["documents"],
                "policies": _count(policies, None),
                "redact_pdf": bool(redact_pdf),
            },
            "redis": {key: redis_state[key] for key in ("ok", "latency_ms", "error")},
            "log_shipping": log_shipping_state(shipper_status, now),
            "keyword_jobs": keyword_jobs_state(keyword_jobs),
            "instances": instances_state,
            "rds": rds_state,
        }


COLLECTOR = StatusCollector()
