"""GPU 깨우기 - 보고서를 만들 때 LLM 서버가 응답하지 않으면 GPU 인스턴스를 시작하고 준비될 때까지 기다린다.

GPU(g6.xlarge, vLLM)는 평소 꺼 둔다. 켜면 부팅 시 vLLM이 자동으로 뜨고 약 147초 뒤 /v1/models가 200이 된다(10/1 실측).
시작·중지 권한은 Detection의 IAM 역할에 **이 인스턴스 하나만** 준다(infra/aws/detection-gpu-start-policy.json).
보고서가 켠 GPU는 생성 뒤 끈다(auto_stop, 2026-10-12 설계 v2 4.10) - 키워드 작업·다른 보고서가 없을 때만.
그 밖에는 대시보드의 GPU 끄기 버튼(control 함수)으로 사람이 끈다(2026-10-07).

설정(환경변수):
  REPORT_GPU_INSTANCE_ID   없으면 깨우지 않는다(지금까지와 같이 GPU가 꺼져 있으면 SQL 문장 보고서)
  REPORT_GPU_REGION        기본 ap-northeast-2
  REPORT_GPU_WAIT_SECONDS  기본 300 - 넘으면 포기하고 SQL 문장 보고서
  REPORT_GPU_AUTO_STOP     기본 on - off면 보고서가 켠 GPU도 끄지 않는다
"""

from __future__ import annotations

import functools
import os
import time
import urllib.request
from typing import Callable

INSTANCE_ID = os.environ.get("REPORT_GPU_INSTANCE_ID", "").strip()
REGION = os.environ.get("REPORT_GPU_REGION", "ap-northeast-2")
WAIT_SECONDS = float(os.environ.get("REPORT_GPU_WAIT_SECONDS", "300"))
POLL_SECONDS = 5.0


class GpuError(RuntimeError):
    pass


def llm_ready(models_url: str, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(models_url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def connection_status(models_url: str, timeout: float = 3.0, *,
                      opener: Callable[..., object] = urllib.request.urlopen,
                      clock: Callable[[], float] = time.monotonic) -> dict:
    """GPU(LLM 서버) 연결 상태 - 대시보드 표시용. **읽기 전용**: 깨우지 않는다.

    반환 {"connected": bool, "models": [모델 id], "latency_ms": int|None, "error": str|None}.
    꺼져 있으면 사설 주소에 응답이 없어 timeout까지 기다린다 - 호출 쪽에서 결과를 잠시 재사용한다.
    """
    import json

    t0 = clock()
    try:
        with opener(models_url, timeout=timeout) as r:
            ok = r.status == 200
            body = json.loads(r.read() or b"{}") if ok else {}
    except Exception as exc:  # 연결 거부·시간 초과·잘못된 JSON - 모두 "연결 안 됨"
        return {"connected": False, "models": [], "latency_ms": None, "error": type(exc).__name__}
    if not ok:
        return {"connected": False, "models": [], "latency_ms": None, "error": f"HTTP {r.status}"}
    models = [m.get("id") for m in body.get("data", []) if isinstance(m, dict) and m.get("id")]
    return {"connected": True, "models": models, "latency_ms": round((clock() - t0) * 1000), "error": None}


def _ec2(region: str):
    import boto3  # Detection venv에만 필요하다 - 깨우기를 쓰지 않으면 import하지 않는다

    return boto3.client("ec2", region_name=region)


# ---------------------------------------------------------------- 대시보드 켜기·끄기 (2026-10-07)
# 대시보드 백엔드가 Detection을 3초에 끊으므로 짧게 끊고 재시도하지 않는다. 클라이언트는 한 번 만들어 재사용한다.
CONTROL_TIMEOUT = 2.0


class GpuControlError(RuntimeError):
    def __init__(self, message: str, *, status_code: int, code: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


@functools.lru_cache(maxsize=4)
def _ec2_quick(region: str):
    import boto3
    from botocore.config import Config

    return boto3.client("ec2", region_name=region, config=Config(
        connect_timeout=CONTROL_TIMEOUT, read_timeout=CONTROL_TIMEOUT, retries={"max_attempts": 1}))


def _control_error(exc: Exception) -> GpuControlError:
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    if code == "UnauthorizedOperation":
        return GpuControlError("Detection IAM role is not allowed to control the GPU instance.",
                               status_code=403, code="GPU_PERMISSION")
    if code == "IncorrectInstanceState":
        return GpuControlError("GPU instance is changing state.", status_code=409, code="GPU_STATE")
    return GpuControlError(f"GPU control failed: {type(exc).__name__}", status_code=502, code="GPU_CONTROL_FAILED")


def instance_state(*, instance_id: str = INSTANCE_ID, region: str = REGION, ec2_factory=_ec2_quick) -> str:
    """EC2 상태 이름(pending|running|stopping|stopped|...). 미설정이면 409, 그 밖의 실패는 GpuControlError."""
    if not instance_id:
        raise GpuControlError("GPU instance id is not configured.", status_code=409, code="GPU_NOT_CONFIGURED")
    try:
        found = ec2_factory(region).describe_instances(InstanceIds=[instance_id])
        return found["Reservations"][0]["Instances"][0]["State"]["Name"]
    except Exception as exc:  # 권한 없음·boto3 없음·네트워크 - 화면에는 상태 미확인으로 보인다
        raise _control_error(exc) from exc


def control(action: str, *, instance_id: str = INSTANCE_ID, region: str = REGION, ec2_factory=_ec2_quick) -> dict:
    """GPU 인스턴스 켜기(start)·끄기(stop). 반환 {"instance_id", "previous_state", "instance_state"}.

    켜기는 stopped에서만, 끄기는 running에서만 한다 - 바뀌는 중(pending·stopping)이면 409 GPU_STATE.
    """
    if action not in ("start", "stop"):
        raise ValueError(action)
    current = instance_state(instance_id=instance_id, region=region, ec2_factory=ec2_factory)
    if current != ("stopped" if action == "start" else "running"):
        raise GpuControlError(f"GPU instance is {current}.", status_code=409, code="GPU_STATE")
    try:
        ec2 = ec2_factory(region)
        if action == "start":
            changed = ec2.start_instances(InstanceIds=[instance_id])["StartingInstances"][0]
        else:
            changed = ec2.stop_instances(InstanceIds=[instance_id])["StoppingInstances"][0]
    except Exception as exc:
        raise _control_error(exc) from exc
    return {"instance_id": instance_id, "previous_state": changed["PreviousState"]["Name"],
            "instance_state": changed["CurrentState"]["Name"]}


AUTO_STOP = os.environ.get("REPORT_GPU_AUTO_STOP", "on").strip().lower() not in ("0", "off", "false", "no")


def auto_stop(state: dict | None, *, busy: Callable[[], list[str] | None], instance_id: str = INSTANCE_ID,
              region: str = REGION, ec2_factory=_ec2, enabled: bool | None = None) -> dict:
    """보고서가 켠 GPU를 생성 뒤 끈다(설계 v2 4.10, v1 결정 11). 반환 {"stopped": bool, "reason": str}.

    끄는 조건: 이 보고서가 켰음(state.started) + 키워드 작업 대기·실행 없음 + 다른 보고서 생성 없음 + 지금 running.
    처음부터 켜져 있었으면 그대로 둔다. 다른 작업 여부를 확인 못 하면(busy()가 None) 끄지 않는다. 예외를 올리지 않는다.
    """
    if not (AUTO_STOP if enabled is None else enabled):
        return {"stopped": False, "reason": "disabled"}
    if not state or not state.get("started"):
        return {"stopped": False, "reason": "not_started_by_report"}
    if not instance_id:
        return {"stopped": False, "reason": "not_configured"}
    try:
        reasons = busy()
    except Exception:  # noqa: BLE001
        reasons = None
    if reasons is None:
        return {"stopped": False, "reason": "busy_unknown"}
    if reasons:
        return {"stopped": False, "reason": "busy:" + ",".join(reasons)}
    try:
        ec2 = ec2_factory(region)
        current = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
        if current != "running":
            return {"stopped": False, "reason": f"state:{current}"}
        ec2.stop_instances(InstanceIds=[instance_id])
    except Exception as exc:  # noqa: BLE001 - 권한 없음 등. 대시보드 끄기 버튼으로 끌 수 있다
        return {"stopped": False, "reason": f"error:{type(exc).__name__}"}
    return {"stopped": True, "reason": "ok"}


def ensure_ready(models_url: str, *, instance_id: str = INSTANCE_ID, region: str = REGION,
                 wait_seconds: float = WAIT_SECONDS, progress: Callable[[str], None] = lambda s: None,
                 ready: Callable[[str], bool] = llm_ready, ec2_factory=_ec2,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> dict:
    """LLM이 응답하게 만든다. 반환: {"ready": bool, "started": bool, "waited_s": float, "error": str|None}.

    예외를 올리지 않는다 - 실패하면 ready=False와 사유를 돌려주고, 호출한 쪽은 SQL 문장 보고서로 계속한다.
    """
    t0 = clock()
    if ready(models_url):
        return {"ready": True, "started": False, "waited_s": 0.0, "error": None}
    if not instance_id:
        return {"ready": False, "started": False, "waited_s": 0.0, "error": "GPU 응답 없음 (자동 시작 미설정)"}
    try:
        ec2 = ec2_factory(region)
        state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "stopping":
            # 중지 중인 인스턴스는 시작할 수 없다 - stopped가 될 때까지 기다린다
            progress("gpu_stopping")
            while state == "stopping" and clock() - t0 < wait_seconds:
                sleep(POLL_SECONDS)
                state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
        started = False
        if state == "stopped":
            progress("gpu_starting")
            ec2.start_instances(InstanceIds=[instance_id])
            started = True
        elif state not in ("pending", "running"):
            return {"ready": False, "started": False, "waited_s": round(clock() - t0, 1),
                    "error": f"GPU 인스턴스 상태 {state}"}
        progress("gpu_booting")
        while clock() - t0 < wait_seconds:
            if ready(models_url):
                return {"ready": True, "started": started, "waited_s": round(clock() - t0, 1), "error": None}
            sleep(POLL_SECONDS)
        return {"ready": False, "started": started, "waited_s": round(clock() - t0, 1),
                "error": f"GPU 준비 대기 {wait_seconds:.0f}초 초과"}
    except Exception as exc:  # 권한 없음(UnauthorizedOperation)·boto3 없음 등
        return {"ready": False, "started": False, "waited_s": round(clock() - t0, 1),
                "error": f"GPU 시작 실패: {type(exc).__name__}: {str(exc)[:200]}"}
