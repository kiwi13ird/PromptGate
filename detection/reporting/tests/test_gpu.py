"""GPU 깨우기 - 가짜 EC2·가짜 시계로 상태 전이를 확인한다."""

import pytest

from reporting.gpu import ensure_ready


class FakeEC2:
    def __init__(self, states, boot_ticks=3, fail=None):
        self.states = list(states)       # describe가 차례로 돌려줄 상태
        self.started = 0
        self.boot_ticks = boot_ticks
        self.fail = fail

    def describe_instances(self, InstanceIds):
        if self.fail:
            raise self.fail
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"Reservations": [{"Instances": [{"State": {"Name": state}}]}]}

    def start_instances(self, InstanceIds):
        self.started += 1


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run(ec2, ready_after=None, wait=300, instance="i-x"):
    clock = Clock()
    stages = []
    ready = (lambda url: ready_after is not None and clock.t >= ready_after)
    out = ensure_ready("http://gpu/v1/models", instance_id=instance, wait_seconds=wait, progress=stages.append,
                       ready=ready, ec2_factory=lambda region: ec2, sleep=clock.sleep, clock=clock)
    return out, stages


def test_already_up_does_nothing():
    ec2 = FakeEC2(["running"])
    out, stages = run(ec2, ready_after=0)
    assert out == {"ready": True, "started": False, "waited_s": 0.0, "error": None}
    assert ec2.started == 0 and stages == []


def test_stopped_is_started_and_waited():
    ec2 = FakeEC2(["stopped"])
    out, stages = run(ec2, ready_after=150)
    assert out["ready"] and out["started"] and out["waited_s"] == 150
    assert ec2.started == 1
    assert stages == ["gpu_starting", "gpu_booting"]


def test_stopping_waits_then_starts():
    ec2 = FakeEC2(["stopping", "stopping", "stopped"])
    out, stages = run(ec2, ready_after=200)
    assert out["ready"] and ec2.started == 1
    assert stages[0] == "gpu_stopping"


def test_running_but_vllm_not_ready_is_not_restarted():
    ec2 = FakeEC2(["running"])
    out, _ = run(ec2, ready_after=60)
    assert out["ready"] and not out["started"] and ec2.started == 0


def test_timeout_gives_up_without_exception():
    ec2 = FakeEC2(["stopped"])
    out, _ = run(ec2, ready_after=None, wait=100)
    assert not out["ready"] and "초과" in out["error"]


def test_no_permission_is_reported_not_raised():
    class Unauthorized(Exception):
        pass

    out, _ = run(FakeEC2(["stopped"], fail=Unauthorized("ec2:DescribeInstances denied")), ready_after=None)
    assert not out["ready"] and out["error"].startswith("GPU 시작 실패: Unauthorized")


def test_not_configured_does_not_touch_ec2():
    def boom(region):
        raise AssertionError("must not create client")

    clock = Clock()
    out = ensure_ready("http://gpu/v1/models", instance_id="", ready=lambda u: False, ec2_factory=boom,
                       sleep=clock.sleep, clock=clock)
    assert not out["ready"] and "미설정" in out["error"]


# ---------------------------------------------------------------- 보고서가 켠 GPU 자동 끄기 (설계 v2 4.10)

from reporting import local_api
from reporting.gpu import auto_stop


class StopEC2:
    def __init__(self, state="running", fail=None):
        self.state, self.fail, self.stopped = state, fail, 0

    def describe_instances(self, InstanceIds):
        return {"Reservations": [{"Instances": [{"State": {"Name": self.state}}]}]}

    def stop_instances(self, InstanceIds):
        if self.fail:
            raise self.fail
        self.stopped += 1


def _stop(state, busy, ec2=None, **kw):
    ec2 = ec2 or StopEC2()
    out = auto_stop(state, busy=busy, instance_id="i-x", ec2_factory=lambda region: ec2, enabled=True, **kw)
    return out, ec2


def test_auto_stop_only_when_report_started_it_and_nothing_else_runs():
    out, ec2 = _stop({"started": True}, lambda: [])
    assert out == {"stopped": True, "reason": "ok"} and ec2.stopped == 1


def test_auto_stop_leaves_gpu_that_was_already_on():
    def boom(region):
        raise AssertionError("must not touch EC2")
    out = auto_stop({"started": False, "ready": True}, busy=lambda: [], instance_id="i-x", ec2_factory=boom, enabled=True)
    assert out == {"stopped": False, "reason": "not_started_by_report"}


@pytest.mark.parametrize("busy, reason", [(["keyword_job"], "busy:keyword_job"), (["report"], "busy:report"),
                                          (None, "busy_unknown")])
def test_auto_stop_skips_when_busy_or_unknown(busy, reason):
    out, ec2 = _stop({"started": True}, lambda: busy)
    assert out == {"stopped": False, "reason": reason} and ec2.stopped == 0


def test_auto_stop_state_error_and_disabled():
    out, ec2 = _stop({"started": True}, lambda: [], StopEC2(state="stopping"))
    assert out == {"stopped": False, "reason": "state:stopping"} and ec2.stopped == 0

    class Unauthorized(Exception):
        pass

    out, _ = _stop({"started": True}, lambda: [], StopEC2(fail=Unauthorized("no")))
    assert out == {"stopped": False, "reason": "error:Unauthorized"}
    assert auto_stop({"started": True}, busy=lambda: [], instance_id="i-x", enabled=False) == {"stopped": False, "reason": "disabled"}
    assert auto_stop({"started": True}, busy=lambda: [], instance_id="", enabled=True) == {"stopped": False, "reason": "not_configured"}


def test_gpu_busy_reads_keyword_jobs_and_other_reports():
    def fake(health, reports):
        def get(path):
            if path == "/health":
                return health
            if path == "/admin/reports":
                return {"reports": reports}
            raise AssertionError(path)
        return get

    me = {"report_id": "report_me", "status": "running"}
    assert local_api.gpu_busy("report_me", get=fake({"keyword_jobs": {"queued": 0, "running": 0}}, [me])) == []
    assert local_api.gpu_busy("report_me", get=fake({"keyword_jobs": {"queued": 2, "running": 0}}, [me])) == ["keyword_job"]
    assert local_api.gpu_busy("report_me", get=fake({"keyword_jobs": None},
                                                    [me, {"report_id": "report_other", "status": "running"}])) == ["report"]

    def down(path):
        raise OSError("refused")
    assert local_api.gpu_busy("report_me", get=down) is None
