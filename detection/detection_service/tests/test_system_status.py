"""GET /admin/system-status - 가짜 EC2·RDS(botocore 오류와 같은 `.response`를 가진 예외)와 fakeredis로 확인한다.

확인하는 것: 응답 모양(계약), 권한 없음 처리(IAM을 아직 안 붙인 상태), 30초 재사용, AWS가 느릴 때 요청이 2초 안에 끝나는지,
Redis 무응답이 0.5초에 끊기는지(진짜 소켓), 비밀·호스트가 응답과 로그에 나가지 않는지, /detect가 막히지 않는지.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import sys
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace

import fakeredis
import pytest
import redis
from fastapi.testclient import TestClient

from detection_service import system_status
from detection_service.system_status import (
    DEFAULT_INSTANCES,
    StatusCollector,
    collect_instances,
    collect_rds,
    configured_instances,
    keyword_jobs_state,
    log_shipping_state,
    probe_redis,
    rds_identifier,
)

ISO_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
GW, DET, DASH, GPU = "i-0a8b8aee6f3d24a36", "i-0ff450ae50695041a", "i-09593052f863fb7c2", "i-094b015caf120ab1e"
ARN_TEXT = "User: arn:aws:sts::123456789012:assumed-role/promptgate-detection-role/i-0ff450ae50695041a is not authorized"


class FakeClientError(Exception):
    """botocore.exceptions.ClientError와 같은 모양: `.response["Error"]["Code"]`."""

    def __init__(self, code: str, message: str = ARN_TEXT) -> None:
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


def _instance(instance_id: str, state: str = "running", name: str | None = None) -> dict:
    out = {"InstanceId": instance_id, "State": {"Code": 16, "Name": state}}
    if name:
        out["Tags"] = [{"Key": "Env", "Value": "x"}, {"Key": "Name", "Value": name}]
    return out


class FakeEC2:
    def __init__(self, instances=None, statuses=None, describe_error=None, status_error=None, gate=None) -> None:
        self.instances = instances if instances is not None else [
            _instance(GW, name="gateway"), _instance(DET, name="detection"), _instance(DASH, name="dashboard")]
        self.statuses = statuses if statuses is not None else {
            GW: ("ok", "ok"), DET: ("ok", "ok"), DASH: ("ok", "impaired")}
        self.describe_error, self.status_error, self.gate = describe_error, status_error, gate
        self.calls: list[tuple[str, dict]] = []

    def count(self, name: str) -> int:
        return sum(1 for call, _ in self.calls if call == name)

    def describe_instances(self, **kwargs):
        self.calls.append(("describe_instances", kwargs))
        if self.gate is not None:
            self.gate.wait(10)
        if self.describe_error:
            raise self.describe_error
        wanted = kwargs["Filters"][0]["Values"]
        return {"Reservations": [{"Instances": [i for i in self.instances if i["InstanceId"] in wanted]}]}

    def describe_instance_status(self, **kwargs):
        self.calls.append(("describe_instance_status", kwargs))
        if self.status_error:
            raise self.status_error
        return {"InstanceStatuses": [
            {"InstanceId": i, "SystemStatus": {"Status": s[0]}, "InstanceStatus": {"Status": s[1]}}
            for i, s in self.statuses.items() if i in kwargs["InstanceIds"]]}


class FakeRDS:
    def __init__(self, error=None, status="available") -> None:
        self.error, self.status, self.calls = error, status, []

    def describe_db_instances(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"DBInstances": [{"DBInstanceIdentifier": kwargs["DBInstanceIdentifier"], "DBInstanceStatus": self.status,
                                 "Engine": "postgres", "Endpoint": {"Address": "secret-host.rds.amazonaws.com"}}]}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def make_collector(ec2=None, rds=None, environ=None, gpu="", **kwargs) -> StatusCollector:
    ec2 = ec2 if ec2 is not None else FakeEC2()
    rds = rds if rds is not None else FakeRDS()
    env = {"SYSTEM_STATUS_RDS_ID": "promptgate-db"} if environ is None else environ
    return StatusCollector(ec2_factory=lambda: ec2, rds_factory=lambda: rds, environ=env,
                           gpu_instance_id=lambda: gpu, **kwargs)


def collect(collector: StatusCollector, **over) -> dict:
    args = dict(redis_client=fakeredis.FakeRedis(decode_responses=True), shipper_status=None,
                signatures={"builtin": 9, "database": 2, "keywords": 5}, policies=2,
                keyword_jobs={"queued": 1, "running": 0, "failed": 0, "done": 7, "extractor": None}, redact_pdf=True)
    args.update(over)
    return collector.collect(**args)


# ---------------------------------------------------------------- 설정 읽기

def test_default_instances_when_env_unset():
    assert configured_instances({}) == [("gateway", GW), ("detection", DET), ("dashboard", DASH)]
    assert DEFAULT_INSTANCES == f"gateway={GW},detection={DET},dashboard={DASH}"


def test_env_overrides_defaults_and_gpu_comes_last():
    env = {"SYSTEM_STATUS_INSTANCES": f"dashboard=i-0123456789abcdef0, gateway = {GW}"}
    assert configured_instances(env, GPU) == [("gateway", GW), ("dashboard", "i-0123456789abcdef0"), ("gpu", GPU)]


def test_invalid_entries_are_skipped_not_fatal(caplog):
    env = {"SYSTEM_STATUS_INSTANCES": f"gateway=not-an-id,bogus={GW},gpu={GPU},detection={DET},detection=i-00000000,x"}
    with caplog.at_level(logging.WARNING):
        assert configured_instances(env) == [("detection", DET)]   # gpu는 환경변수가 아니라 REPORT_GPU_INSTANCE_ID로만
    assert "5 invalid" in caplog.text and GW not in caplog.text    # 개수만 기록하고 값은 기록하지 않는다


def test_set_but_empty_env_means_no_instances():
    assert configured_instances({"SYSTEM_STATUS_INSTANCES": ""}) == []
    assert configured_instances({"SYSTEM_STATUS_INSTANCES": ""}, GPU) == [("gpu", GPU)]


@pytest.mark.parametrize("env, expected", [
    ({"SYSTEM_STATUS_RDS_ID": "my-db", "DETECTION_PG_DSN": "postgresql://u:p@other.x.rds.amazonaws.com/dlp"}, "my-db"),
    ({"DETECTION_PG_DSN": "postgresql://postgres:p%40ss@promptgate-db.abc.ap-northeast-2.rds.amazonaws.com:5432/dlp?sslmode=require"},
     "promptgate-db"),
    ({"DETECTION_PG_DSN": "postgres://u@a-db.x.y.rds.amazonaws.com,b-db.x.y/dlp"}, "a-db"),
    ({"DETECTION_PG_DSN": "host=kv-db.abc.rds.amazonaws.com port=5432 dbname=dlp user=u password=secret"}, "kv-db"),
    ({"DETECTION_PG_DSN": "host='quoted-db.abc.rds.amazonaws.com' dbname=dlp"}, "quoted-db"),
    ({"DETECTION_PG_DSN": "postgresql://u:p@10.0.1.20:5432/dlp"}, None),            # IP는 DNS 이름이 아니다
    ({"DETECTION_PG_DSN": "postgresql://u:p@[::1]:5432/dlp"}, None),
    ({"DETECTION_PG_DSN": "host=/var/run/postgresql dbname=dlp"}, None),
    ({"DETECTION_PG_DSN": "postgresql:///dlp"}, None),
    ({"DETECTION_PG_DSN": "not a dsn"}, None),
    ({"SYSTEM_STATUS_RDS_ID": "9bad_id"}, None),
    ({}, None),
])
def test_rds_identifier(env, expected):
    assert rds_identifier(env) == expected


# ---------------------------------------------------------------- EC2

def test_instances_with_status_checks():
    ec2 = FakeEC2()
    out = collect_instances(lambda: ec2, configured_instances({}))
    assert out["ok"] is True and out["error"] is None and out["status_checks"] == "ok"
    assert out["items"][1] == {"role": "detection", "instance_id": DET, "name": "detection", "state": "running",
                               "system_status": "ok", "instance_status": "ok"}
    assert out["items"][2]["instance_status"] == "impaired"
    # 한 번에 묻고, 없어진 ID가 있어도 통째로 실패하지 않게 Filters로 묻는다. 상태 점검은 꺼진 인스턴스도 포함해서.
    assert ec2.calls[0] == ("describe_instances", {"Filters": [{"Name": "instance-id", "Values": [GW, DET, DASH]}]})
    assert ec2.calls[1] == ("describe_instance_status", {"InstanceIds": [GW, DET, DASH], "IncludeAllInstances": True})


def test_status_check_permission_missing_keeps_instances_ok():
    """IAM에 ec2:DescribeInstanceStatus를 아직 안 붙였을 때 - 지금 운영의 모습."""
    ec2 = FakeEC2(status_error=FakeClientError("UnauthorizedOperation"))
    out = collect_instances(lambda: ec2, configured_instances({}))
    assert out["ok"] is True and out["error"] is None and out["status_checks"] == "permission_missing"
    assert [i["state"] for i in out["items"]] == ["running"] * 3
    assert all(i["system_status"] is None and i["instance_status"] is None for i in out["items"])


def test_status_check_other_failure_is_unavailable_not_permission():
    ec2 = FakeEC2(status_error=TimeoutError("read timeout"))
    assert collect_instances(lambda: ec2, configured_instances({}))["status_checks"] == "unavailable"


@pytest.mark.parametrize("error, expected", [
    (FakeClientError("UnauthorizedOperation"), "permission_missing"),
    (FakeClientError("AccessDenied"), "permission_missing"),
    (FakeClientError("RequestLimitExceeded"), "unavailable"),
    (TimeoutError("connect timeout"), "unavailable"),
    (ImportError("No module named 'boto3'"), "unavailable"),
])
def test_describe_instances_failure(error, expected):
    out = collect_instances(lambda: FakeEC2(describe_error=error), configured_instances({}))
    assert out == {"ok": False, "error": expected, "status_checks": None, "items": []}
    assert "arn:" not in json.dumps(out)    # 오류 메시지는 응답에 없다


def test_factory_failure_is_unavailable():
    def no_boto3():
        raise ImportError("No module named 'boto3'")

    assert collect_instances(no_boto3, configured_instances({}))["error"] == "unavailable"


def test_vanished_instance_is_not_found_and_skips_status_call():
    ec2 = FakeEC2(instances=[_instance(GW)])
    out = collect_instances(lambda: ec2, configured_instances({}))
    assert [(i["role"], i["state"]) for i in out["items"]] == [("gateway", "running"), ("detection", "not_found"),
                                                              ("dashboard", "not_found")]
    assert ec2.calls[1][1]["InstanceIds"] == [GW]


def test_no_instances_configured_makes_no_call():
    def boom():
        raise AssertionError("must not create a client")

    assert collect_instances(boom, []) == {"ok": True, "error": None, "status_checks": "ok", "items": []}


def test_stopped_gpu_instance_and_long_name_are_passed_through():
    ec2 = FakeEC2(instances=[_instance(GPU, state="stopped", name="x" * 200)], statuses={GPU: ("not-applicable",) * 2})
    out = collect_instances(lambda: ec2, [("gpu", GPU)])
    assert out["items"][0]["state"] == "stopped" and len(out["items"][0]["name"]) == 64
    assert out["items"][0]["system_status"] == "not-applicable"


# ---------------------------------------------------------------- RDS

def test_rds_ok_exposes_only_identifier_status_engine():
    out = collect_rds(lambda: FakeRDS(), "promptgate-db")
    assert out == {"ok": True, "error": None, "identifier": "promptgate-db", "status": "available", "engine": "postgres"}


@pytest.mark.parametrize("error, expected", [
    (FakeClientError("AccessDenied"), "permission_missing"),
    (FakeClientError("DBInstanceNotFound"), "not_configured"),
    (FakeClientError("Throttling"), "unavailable"),
    (OSError("timed out"), "unavailable"),
])
def test_rds_failures(error, expected):
    out = collect_rds(lambda: FakeRDS(error=error), "promptgate-db")
    assert out == {"ok": False, "error": expected, "identifier": "promptgate-db", "status": None, "engine": None}


def test_rds_without_identifier_is_not_configured_and_makes_no_call():
    def boom():
        raise AssertionError("must not create a client")

    assert collect_rds(boom, None) == {"ok": False, "error": "not_configured", "identifier": None, "status": None,
                                       "engine": None}


# ---------------------------------------------------------------- AWS 클라이언트 만들기 (boto3는 이 환경에 없다 - 모듈을 가짜로 대신 둔다)

def test_aws_clients_are_seoul_with_two_second_timeouts_and_no_retries(monkeypatch):
    created = []
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda service, **kwargs: created.append((service, kwargs)) or object()
    fake_config = types.ModuleType("botocore.config")

    class Config:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

    fake_config.Config = Config
    fake_botocore = types.ModuleType("botocore")
    fake_botocore.config = fake_config
    for name, module in (("boto3", fake_boto3), ("botocore", fake_botocore), ("botocore.config", fake_config)):
        monkeypatch.setitem(sys.modules, name, module)
    system_status._ec2_client.cache_clear()
    system_status._rds_client.cache_clear()
    try:
        system_status._ec2_client()
        system_status._rds_client()
    finally:
        system_status._ec2_client.cache_clear()
        system_status._rds_client.cache_clear()
    assert [service for service, _ in created] == ["ec2", "rds"]
    for _, kwargs in created:
        assert kwargs["region_name"] == "ap-northeast-2"
        assert kwargs["config"].kwargs == {"connect_timeout": 2.0, "read_timeout": 2.0, "retries": {"max_attempts": 0}}


def test_requests_match_real_service_models():
    """진짜 boto3의 Stubber가 요청 매개변수·응답 모양을 서비스 모델로 검증한다. boto3가 없는 환경(로컬 venv)에서는 건너뛴다."""
    boto3 = pytest.importorskip("boto3")
    from botocore.exceptions import ClientError
    from botocore.stub import Stubber

    creds = dict(region_name="ap-northeast-2", aws_access_key_id="test", aws_secret_access_key="test")
    ec2, rds = boto3.client("ec2", **creds), boto3.client("rds", **creds)
    with Stubber(ec2) as ec2_stub, Stubber(rds) as rds_stub:
        ec2_stub.add_response("describe_instances", {"Reservations": [{"Instances": [_instance(DET, name="detection")]}]},
                              {"Filters": [{"Name": "instance-id", "Values": [DET]}]})
        ec2_stub.add_client_error("describe_instance_status", "UnauthorizedOperation", http_status_code=403,
                                  expected_params={"InstanceIds": [DET], "IncludeAllInstances": True})
        out = collect_instances(lambda: ec2, [("detection", DET)])
        assert out["status_checks"] == "permission_missing" and out["items"][0]["state"] == "running"
        rds_stub.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceStatus": "available", "Engine": "postgres"}]},
                              {"DBInstanceIdentifier": "promptgate-db"})
        assert collect_rds(lambda: rds, "promptgate-db")["status"] == "available"
        rds_stub.add_client_error("describe_db_instances", "AccessDenied", http_status_code=403)
        assert collect_rds(lambda: rds, "promptgate-db")["error"] == "permission_missing"
    assert isinstance(ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeDBInstances"), Exception)


# ---------------------------------------------------------------- Redis · 로그 전송 · 키워드 작업

def test_probe_redis_ok_reports_latency_and_document_count():
    client = fakeredis.FakeRedis(decode_responses=True)
    client.sadd("wh:docs", "a", "b", "c")
    out = probe_redis(client)
    assert out["ok"] is True and out["error"] is None and out["documents"] == 3
    assert isinstance(out["latency_ms"], float) and 0 <= out["latency_ms"] < 1000


def test_probe_redis_down_gives_class_name_only():
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server)
    server.connected = False
    assert probe_redis(client) == {"ok": False, "latency_ms": None, "error": "ConnectionError", "documents": None}


NOW = 1_800_000_000.0


def _shipper(**over) -> dict:
    base = {"pending_bytes": 0, "shipped_total": 10, "rejected_total": 0, "consecutive_failures": 0,
            "last_ok_ts": NOW - 5, "updated_ts": NOW - 1, "last_error": None}
    base.update(over)
    return base


def test_log_shipping_healthy():
    out = log_shipping_state(_shipper(pending_bytes=120, rejected_total=2), NOW)
    assert out == {"ok": True, "pending_bytes": 120, "last_ok_at": system_status.iso_utc(NOW - 5),
                   "consecutive_failures": 0, "rejected_total": 2, "last_error": None}
    assert ISO_Z.fullmatch(out["last_ok_at"])


def test_log_shipping_old_error_name_is_hidden_after_recovery():
    assert log_shipping_state(_shipper(last_error="OperationalError", consecutive_failures=0), NOW)["last_error"] is None


@pytest.mark.parametrize("over, last_error", [
    ({"consecutive_failures": 3, "last_error": "OperationalError"}, "OperationalError"),
    ({"pending_bytes": 10, "last_ok_ts": NOW - 601}, None),                  # 보낼 것이 남았는데 10분 넘게 성공 없음
    ({"pending_bytes": 10, "last_ok_ts": None}, None),
    ({"updated_ts": NOW - 91}, "shipper_not_running"),                       # 상태 파일이 멈춤 = 서비스가 안 돈다
    ({"updated_ts": None}, "shipper_not_running"),
])
def test_log_shipping_unhealthy(over, last_error):
    out = log_shipping_state(_shipper(**over), NOW)
    assert out["ok"] is False and out["last_error"] == last_error


def test_log_shipping_two_failures_or_idle_old_success_is_still_ok():
    assert log_shipping_state(_shipper(consecutive_failures=2, last_error="X"), NOW)["ok"] is True
    assert log_shipping_state(_shipper(pending_bytes=0, last_ok_ts=NOW - 86400), NOW)["ok"] is True   # 보낼 게 없으면 오래돼도 정상


def test_log_shipping_missing_file():
    assert log_shipping_state(None, NOW) == {"ok": False, "pending_bytes": 0, "last_ok_at": None,
                                             "consecutive_failures": 0, "rejected_total": 0,
                                             "last_error": "status_file_missing"}


def test_log_shipping_tolerates_garbage_values():
    out = log_shipping_state({"pending_bytes": None, "consecutive_failures": "x", "rejected_total": float("nan"),
                              "last_ok_ts": float("inf"), "updated_ts": NOW}, NOW)
    assert out["pending_bytes"] == 0 and out["rejected_total"] == 0 and out["last_ok_at"] is None


def test_keyword_jobs_state():
    assert keyword_jobs_state({"queued": 2, "running": 1, "failed": 0, "done": 9, "extractor": {"gpu": "up"}}) == {
        "queued": 2, "running": 1, "failed": 0}
    assert keyword_jobs_state(None) == {"queued": None, "running": None, "failed": None}   # 저장소를 못 쓸 때 0으로 보이면 안 된다


# ---------------------------------------------------------------- 수집기

def test_collect_matches_contract_shape():
    out = collect(make_collector(gpu=GPU, ec2=FakeEC2(instances=[_instance(GW), _instance(DET), _instance(DASH),
                                                                _instance(GPU, state="stopped")],
                                                      statuses={GPU: ("not-applicable",) * 2})),
                  redis_client=_redis_with_docs(4), shipper_status=_shipper())
    assert list(out) == ["checked_at", "detection", "redis", "log_shipping", "keyword_jobs", "instances", "rds"]
    assert ISO_Z.fullmatch(out["checked_at"])
    det = out["detection"]
    assert list(det) == ["status", "started_at", "uptime_s", "signatures", "documents", "policies", "redact_pdf"]
    assert det["status"] == "ok" and ISO_Z.fullmatch(det["started_at"]) and det["uptime_s"] >= 0
    assert det["signatures"] == {"builtin": 9, "database": 2, "keywords": 5}
    assert det["documents"] == 4 and det["policies"] == 2 and det["redact_pdf"] is True
    assert list(out["redis"]) == ["ok", "latency_ms", "error"] and out["redis"]["ok"] is True
    assert list(out["log_shipping"]) == ["ok", "pending_bytes", "last_ok_at", "consecutive_failures", "rejected_total",
                                         "last_error"]
    assert out["keyword_jobs"] == {"queued": 1, "running": 0, "failed": 0}
    assert list(out["instances"]) == ["ok", "error", "status_checks", "items"]
    assert [i["role"] for i in out["instances"]["items"]] == ["gateway", "detection", "dashboard", "gpu"]
    assert list(out["instances"]["items"][0]) == ["role", "instance_id", "name", "state", "system_status", "instance_status"]
    assert out["rds"] == {"ok": True, "error": None, "identifier": "promptgate-db", "status": "available", "engine": "postgres"}
    json.dumps(out)


def _redis_with_docs(n: int):
    client = fakeredis.FakeRedis(decode_responses=True)
    for i in range(n):
        client.sadd("wh:docs", f"doc-{i}")
    return client


def test_aws_results_are_cached_for_30_seconds():
    clock, ec2, rds = Clock(), FakeEC2(), FakeRDS()
    collector = make_collector(ec2=ec2, rds=rds, clock=clock)
    collect(collector)
    collect(collector)
    clock.t += 29
    collect(collector)
    assert (ec2.count("describe_instances"), ec2.count("describe_instance_status"), len(rds.calls)) == (1, 1, 1)
    clock.t += 2    # 31초
    collect(collector)
    assert (ec2.count("describe_instances"), ec2.count("describe_instance_status"), len(rds.calls)) == (2, 2, 2)


def test_permission_error_is_cached_too_and_clears_after_ttl():
    clock, ec2 = Clock(), FakeEC2(status_error=FakeClientError("UnauthorizedOperation"))
    collector = make_collector(ec2=ec2, clock=clock)
    assert collect(collector)["instances"]["status_checks"] == "permission_missing"
    ec2.status_error = None                       # 그 사이에 IAM 정책을 붙였다
    assert collect(collector)["instances"]["status_checks"] == "permission_missing"   # 아직 30초 안
    clock.t += 31
    out = collect(collector)
    assert out["instances"]["status_checks"] == "ok" and out["instances"]["items"][0]["system_status"] == "ok"


def test_slow_aws_is_cut_at_the_wait_and_late_result_is_used_next_time():
    gate = threading.Event()
    ec2 = FakeEC2(gate=gate)
    collector = make_collector(ec2=ec2, aws_wait=0.15)
    started = time.monotonic()
    out = collect(collector)
    assert time.monotonic() - started < 1.0
    assert out["instances"] == {"ok": False, "error": "unavailable", "status_checks": None, "items": []}
    assert out["rds"]["ok"] is True                                  # EC2가 늦어도 RDS 결과는 나온다
    assert out["redis"]["ok"] is True and out["detection"]["status"] == "ok"
    assert collect(collector)["instances"]["error"] == "unavailable"  # 아직 안 끝났다 - 같은 조회를 기다릴 뿐 새로 시작하지 않는다
    gate.set()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        out = collect(collector)
        if out["instances"]["ok"]:
            break
        time.sleep(0.02)
    assert out["instances"]["ok"] is True and len(out["instances"]["items"]) == 3
    assert ec2.count("describe_instances") == 1


def test_stuck_call_is_replaced_after_abandon_window():
    clock, gate = Clock(), threading.Event()
    ec2 = FakeEC2(gate=gate)
    collector = make_collector(ec2=ec2, clock=clock, aws_wait=0.05)
    collect(collector)
    collect(collector)
    assert ec2.count("describe_instances") == 1
    clock.t += 16                                  # 15초가 넘도록 안 끝난 조회는 멈춘 것
    collect(collector)
    assert ec2.count("describe_instances") == 2
    gate.set()


def test_changed_config_does_not_reuse_cache():
    env = {"SYSTEM_STATUS_RDS_ID": "first-db"}
    rds = FakeRDS()
    collector = make_collector(rds=rds, environ=env)
    assert collect(collector)["rds"]["identifier"] == "first-db"
    env["SYSTEM_STATUS_RDS_ID"] = "second-db"
    assert collect(collector)["rds"]["identifier"] == "second-db"


def test_rds_not_configured_without_env():
    out = collect(make_collector(environ={}))
    assert out["rds"] == {"ok": False, "error": "not_configured", "identifier": None, "status": None, "engine": None}


def test_redis_black_hole_is_cut_at_the_wait_with_a_real_socket():
    """연결은 받지만 응답이 없는 Redis(boto3 없이도 실제 소켓으로). 클라이언트 자체 타임아웃(5초)이 아니라 0.3초에 끊겨야 한다."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    held: list[socket.socket] = []

    def accept_forever() -> None:
        while True:
            try:
                held.append(listener.accept()[0])
            except OSError:
                return

    threading.Thread(target=accept_forever, daemon=True).start()
    client = redis.Redis(host="127.0.0.1", port=listener.getsockname()[1], socket_timeout=5, socket_connect_timeout=5)
    try:
        collector = make_collector(redis_wait=0.3)
        started = time.monotonic()
        out = collect(collector, redis_client=client)
        assert 0.25 <= time.monotonic() - started < 1.5
        assert out["redis"] == {"ok": False, "latency_ms": None, "error": "timeout"}
        assert out["detection"]["documents"] is None and out["detection"]["status"] == "ok"
    finally:
        listener.close()
        for conn in held:
            conn.close()
        client.close()


def test_output_and_logs_never_contain_secrets_or_rds_host(caplog):
    dsn = "postgresql://postgres:S3cr3tPw%21@promptgate-db.cabc123xyz.ap-northeast-2.rds.amazonaws.com:5432/dlp?sslmode=require"
    ok = make_collector(environ={"DETECTION_PG_DSN": dsn})
    failing = make_collector(environ={"DETECTION_PG_DSN": dsn}, rds=FakeRDS(error=FakeClientError(
        "AccessDenied", "arn:aws:rds:ap-northeast-2:123456789012:db:promptgate-db denied S3cr3tPw")),
        ec2=FakeEC2(describe_error=FakeClientError("UnauthorizedOperation")))
    with caplog.at_level(logging.DEBUG):
        texts = [json.dumps(collect(c)) for c in (ok, failing)] + [caplog.text]
    joined = "\n".join(texts)
    for secret in ("S3cr3t", "cabc123xyz", "rds.amazonaws.com", "123456789012", "arn:", "sslmode"):
        assert secret not in joined, secret
    assert '"identifier": "promptgate-db"' in texts[0]


# ---------------------------------------------------------------- 엔드포인트

@pytest.fixture()
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_redis = _redis_with_docs(3)
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setenv("DETECTION_LOG_PATH", str(logs / "decisions.jsonl"))
    for name in ("DETECTION_PG_DSN", "POLICY_DB", "SIGNATURE_DB", "KEYWORD_DB", "SYSTEM_STATUS_INSTANCES",
                 "SYSTEM_STATUS_RDS_ID"):
        monkeypatch.delenv(name, raising=False)
    import detection_service.main as main_module

    monkeypatch.setattr(main_module, "connect_redis", lambda: fake_redis)
    ec2, rds = FakeEC2(), FakeRDS()
    collector = make_collector(ec2=ec2, rds=rds, gpu="", aws_wait=1.0)
    monkeypatch.setattr(system_status, "COLLECTOR", collector)
    with TestClient(main_module.app) as client:
        yield SimpleNamespace(client=client, ec2=ec2, rds=rds, logs=logs, main=main_module)


def test_endpoint_returns_contract_shape_without_credentials(api):
    (api.logs / "shipper.status.json").write_text(json.dumps(_shipper(
        pending_bytes=0, last_ok_ts=time.time() - 3, updated_ts=time.time() - 1)), encoding="utf-8")
    response = api.client.get("/admin/system-status")      # 헤더 없이 - /admin/gpu와 같은 접근 규칙
    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["checked_at", "detection", "redis", "log_shipping", "keyword_jobs", "instances", "rds"]
    assert body["detection"]["documents"] == 3 and body["redis"]["ok"] is True
    assert body["detection"]["signatures"]["builtin"] == len(api.main.signature.PII_RECOGNIZERS)
    assert isinstance(body["detection"]["signatures"]["database"], int)
    assert body["detection"]["redact_pdf"] is api.main.REDACT_PDF_ENABLED
    assert body["log_shipping"]["ok"] is True and ISO_Z.fullmatch(body["log_shipping"]["last_ok_at"])
    assert body["keyword_jobs"] == {"queued": None, "running": None, "failed": None}      # 이 환경엔 키워드 DB가 없다
    assert [i["role"] for i in body["instances"]["items"]] == ["gateway", "detection", "dashboard"]
    assert body["rds"]["status"] == "available"


def test_endpoint_shows_keyword_jobs_when_store_is_available(api, monkeypatch):
    monkeypatch.setattr(api.main, "_keyword_jobs_state", lambda: {"queued": 4, "running": 1, "failed": 2, "extractor": None})
    assert api.client.get("/admin/system-status").json()["keyword_jobs"] == {"queued": 4, "running": 1, "failed": 2}


def test_endpoint_reports_missing_iam_without_failing(api):
    api.ec2.status_error = FakeClientError("UnauthorizedOperation")
    api.rds.error = FakeClientError("AccessDenied")
    body = api.client.get("/admin/system-status").json()
    assert body["instances"]["ok"] is True and body["instances"]["status_checks"] == "permission_missing"
    assert body["rds"]["ok"] is False and body["rds"]["error"] == "permission_missing"
    assert body["redis"]["ok"] is True and body["detection"]["status"] == "ok"


def test_endpoint_survives_unreadable_local_sources(api, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("disk")

    monkeypatch.setattr(api.main, "read_status", boom)
    monkeypatch.setattr(api.main, "_signature_state", boom)
    monkeypatch.setattr(api.main.policy_store, "list_policies", boom)
    response = api.client.get("/admin/system-status")
    assert response.status_code == 200
    body = response.json()
    assert body["log_shipping"]["last_error"] == "status_file_missing"
    assert body["detection"]["signatures"] == {"builtin": None, "database": None, "keywords": None}
    assert body["detection"]["policies"] is None and body["redis"]["ok"] is True


def test_endpoint_with_slow_aws_does_not_block_detect(api):
    gate = threading.Event()
    api.ec2.gate = gate
    result: dict = {}

    def call_status() -> None:
        started = time.monotonic()
        result["response"] = api.client.get("/admin/system-status")
        result["elapsed"] = time.monotonic() - started

    thread = threading.Thread(target=call_status)
    thread.start()
    time.sleep(0.2)                                     # 상태 요청이 AWS를 기다리는 동안
    started = time.monotonic()
    detect = api.client.post("/detect", json={"request_id": "r1", "normalized_text": "오늘 점심 메뉴는 김치찌개였다."})
    assert detect.status_code == 200 and time.monotonic() - started < 0.8
    thread.join(5)
    gate.set()
    assert result["response"].status_code == 200 and result["elapsed"] < 2.0
    assert result["response"].json()["instances"]["error"] == "unavailable"
