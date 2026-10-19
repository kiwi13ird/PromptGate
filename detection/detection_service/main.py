"""Detection API — windowhash(창 해시 탐지)를 HTTP로 노출한다.

Gateway EC2와 Detection EC2는 별개 인스턴스이고, 이 모듈은 그 네트워크 홉의 서버 쪽이다. 실시간 조회는 Redis만 본다.
적재는 `windowhash.cli ingest`가 별도 배치로 담당한다.

기록: 로그 파일 `DETECTION_LOG_PATH`(기본 /opt/detection/logs/decisions.jsonl)에만 쓴다. RDS `decisions`로는 별도 서비스
`detection_service.log_shipper`(detection-logshipper.service)가 옮긴다 - 이 API는 RDS에 연결하지 않는다(2026-09-15).
`/health`는 전송 서비스 상태 파일을 읽어 `log_sync`로 보여준다.
설계: docs/pipelines/detection-decision-log-design.md §11, infra/postgres/schema_mvp.sql
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from reporting import gpu as report_gpu
from reporting.jobs import ReportError, ReportJobs, content_trend_enabled
from signature import engine as signature
from windowhash.index import connect as connect_redis

from . import keyword_store, pipeline, policy_store, system_status
from .decision_log import DEFAULT_PATH as DEFAULT_LOG_PATH
from .decision_log import DecisionLog
from .log_shipper import read_status
from .schemas import DetectRequest, DetectResponse

# PDF 가림 API(2026-10-11, 명세 §3.3). 이 모듈을 못 불러와도 /detect는 떠야 한다 - 실패는 /health의 redact_pdf=false.
try:
    from . import redact_pdf as _redact_pdf
except Exception as _exc:  # noqa: BLE001
    logging.getLogger("detection.main").warning("redact_pdf disabled: %s", type(_exc).__name__)
    _redact_pdf = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.redis = connect_redis()
    app.state.decision_log = DecisionLog(os.environ.get("DETECTION_LOG_PATH", DEFAULT_LOG_PATH))
    policy_store.configure_database(os.environ.get("POLICY_DB") or os.environ.get("SIGNATURE_DB"))
    # 키워드 DB는 시그니처 DB와 따로다(시그니처 DB 디렉터리는 서비스가 쓸 수 없다). 실패해도 예외를 올리지 않는다 -
    # 키워드 관리 API만 503이 되고 탐지는 뜬다(2026-10-01 사고 이후).
    keyword_store.configure_database(os.environ.get("KEYWORD_DB"))
    # 보고서는 자식 프로세스가 만든다. API는 RDS 접속 정보를 읽지 않고 파일 경로만 넘긴다(reporting/jobs.py).
    app.state.reports = ReportJobs(os.environ.get("REPORT_OUT_DIR", "/opt/detection/reports"),
                                   os.environ.get("REPORT_ENV_FILE", "/opt/detection/pg.env"))
    try:
        yield
    finally:
        if _redact_pdf is not None:
            try:
                _redact_pdf.shutdown()  # 가림 자식 프로세스를 내린다
            except Exception:  # noqa: BLE001
                pass
        app.state.redis.close()


app = FastAPI(lifespan=lifespan)

REDACT_PDF_ENABLED = False
if _redact_pdf is not None:
    try:
        app.include_router(_redact_pdf.router)
        REDACT_PDF_ENABLED = True
    except Exception as _exc:  # noqa: BLE001
        logging.getLogger("detection.main").warning("redact_pdf router not added: %s", type(_exc).__name__)


@app.post("/detect", response_model=DetectResponse)
def detect_endpoint(req: DetectRequest) -> DetectResponse:
    return pipeline.run(
        app.state.redis,
        req.normalized_text,
        request_id=req.request_id,
        source=req.source.model_dump(),
        decision_log=app.state.decision_log,
    )


def _signature_state() -> dict[str, Any]:
    """규칙 현황. 내장 인식기(코드)·DB 규칙·승인 키워드를 나눠 센다.

    키워드는 **개수만** 싣는다 - 키워드 목록은 그 자체로 기밀(프로젝트 코드명·고객사명)이다.
    """
    return {
        "builtin": len(signature.PII_RECOGNIZERS),
        "database": signature.DATABASE_RULES,
        "keywords": signature.KEYWORDS,
        # 키워드 로딩이 실패해도 탐지는 돈다 - 대신 여기에 드러낸다. 키워드 관리 API를 못 쓰는 이유도 같이.
        "keyword_error": signature.KEYWORD_ERROR,
        "keyword_admin": "ok" if keyword_store.unavailable_reason() is None else keyword_store.unavailable_reason(),
        "loaded_at": signature.LOADED_AT or None,
        "source": signature.RULE_SOURCE,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    sync = read_status(app.state.decision_log.path)
    if sync is not None:
        sync = {k: sync.get(k) for k in ("pending_bytes", "shipped_total", "rejected_total", "consecutive_failures",
                                          "lost_files_total", "bad_lines_total", "legacy_lines_total",
                                          "last_ok_ts", "started_ts", "updated_ts")}
    try:  # Redis가 죽었을 때가 /health가 가장 필요한 때다 - 여기서 500을 내면 안 된다
        documents = app.state.redis.scard("wh:docs")
    except Exception:
        documents = None
    # 인증이 없는 엔드포인트다. 문서 **개수**만 싣고 문서명(doc_id)은 싣지 않는다.
    return {
        "status": "ok",
        "log_sync": sync,
        "signatures": _signature_state(),
        "policies": {"loaded": len(policy_store.list_policies())},
        "index": {"documents": documents},
        "keyword_jobs": _keyword_jobs_state(),
        "redact_pdf": REDACT_PDF_ENABLED,  # POST /redact/pdf 사용 가능 여부(2026-10-11)
    }


def _keyword_jobs_state() -> dict[str, Any] | None:
    """추출 작업 대기 현황 + 추출 서비스가 마지막으로 본 GPU 상태. GPU가 꺼져 있으면 queued가 쌓이고 gpu='down'."""
    if keyword_store.unavailable_reason() is not None:
        return None
    try:
        counts = keyword_store.job_counts()
    except Exception:
        return None
    extractor = None
    path = os.environ.get("KEYWORD_EXTRACTOR_STATUS", "/opt/detection/logs/keyword-extractor.status.json")
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        extractor = {k: raw.get(k) for k in ("gpu", "updated_ts")}
    except (OSError, ValueError):
        pass
    return {**counts, "extractor": extractor}


@app.get("/admin/documents/fingerprints")
def document_fingerprints() -> list[dict[str, Any]]:
    """Return non-sensitive Redis index evidence for dashboard administrators.

    Only document identifiers and aggregate window counts are exposed. Hashes,
    postings, normalized text, and original document bytes never leave the
    Detection instance.
    """
    redis_client = app.state.redis
    document_ids = sorted(str(value) for value in redis_client.smembers("wh:docs"))
    return [
        {
            "document_id": document_id,
            "indexed": True,
            "window_count": int(redis_client.scard(f"wh:doc:{document_id}")),
        }
        for document_id in document_ids
    ]


@app.post("/admin/reload-signatures")
def reload_signatures() -> dict[str, Any]:
    """시그니처 규칙을 다시 읽는다. 재시작 없이 패턴을 바꾸기 위한 것.

    시작 시 로딩과 동작이 다르다 - 시작 시에는 로딩 실패가 기동을 실패시키지만(의도된 것),
    여기서는 500만 내고 서비스는 쓰던 규칙으로 계속 돈다.

    **인증을 두지 않는다**(2026-09-29 결정). `/detect`와 같은 수준으로, 같은 VPC 안에서 보안
    그룹으로만 막는다 - 배포가 아니라 프로젝트 형태라 토큰 관리 비용이 이득보다 크다.
    외부에 내보내는 서비스가 되면 다시 검토해야 한다.
    """
    try:
        signature.configure_database(os.environ.get("SIGNATURE_DB"))
    except Exception as exc:
        # 전역 RECOGNIZERS는 안 바뀌었다 - 쓰던 규칙이 그대로 살아 있다.
        raise HTTPException(
            status_code=500,
            detail={"reloaded": False, "error": f"{type(exc).__name__}: {exc}", "signatures": _signature_state()},
        )
    return {"reloaded": True, "signatures": _signature_state()}


class PolicyCreate(BaseModel):
    detection_target: str = Field(min_length=2, max_length=48)
    action: str = Field(min_length=4, max_length=20)


class PolicyUpdate(BaseModel):
    action: str = Field(min_length=4, max_length=20)
    expected_version: int = Field(ge=1)


class PolicyStatusUpdate(BaseModel):
    enabled: bool
    expected_version: int = Field(ge=1)


def _actor(value: str | None) -> str:
    value = (value or "dashboard-admin").strip()
    return value[:100] or "dashboard-admin"


def _policy_call(callback):
    try:
        return callback()
    except policy_store.PolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}) from exc


@app.get("/admin/policies")
def list_policies() -> list[dict[str, Any]]:
    return policy_store.list_policies()


@app.get("/admin/policies/{policy_id}")
def get_policy(policy_id: str) -> dict[str, Any]:
    return _policy_call(lambda: policy_store.get_policy(policy_id))


@app.get("/admin/policies/{policy_id}/versions")
def policy_versions(policy_id: str) -> list[dict[str, Any]]:
    return _policy_call(lambda: policy_store.history(policy_id))


@app.post("/admin/policies", status_code=201)
def create_policy(body: PolicyCreate, x_admin_id: str | None = Header(default=None)) -> dict[str, Any]:
    return _policy_call(lambda: policy_store.create(body.detection_target, body.action, _actor(x_admin_id)))


@app.patch("/admin/policies/{policy_id}")
def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    x_admin_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return _policy_call(lambda: policy_store.update(policy_id, body.action, body.expected_version, _actor(x_admin_id)))


@app.patch("/admin/policies/{policy_id}/status")
def update_policy_status(
    policy_id: str,
    body: PolicyStatusUpdate,
    x_admin_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return _policy_call(
        lambda: policy_store.change_status(policy_id, body.enabled, body.expected_version, _actor(x_admin_id))
    )


# ---------------------------------------------------------------- 문서 키워드 (설계: keyword-detection-design.md §5)
#
# 대시보드가 승인 대기 키워드를 보고 승인·거부한다(HITL). 승인한 키워드는 /admin/reload-signatures로 반영된다 -
# 반영 시점(승인 즉시 / 수동 / 일괄)은 아직 정하지 않았다.
#
# ⚠️ 키워드 목록은 그 자체로 기밀이다. 프로젝트 결정상 인증을 두지 않지만, GET /admin/keywords는 /detect·/health와
# 노출되는 것의 성격이 다르다. 외부 노출 전에 인증을 다시 검토해야 한다.


class KeywordCreate(BaseModel):
    keyword: str = Field(min_length=1, max_length=keyword_store.MAX_LENGTH * 2)  # 정규화 전 길이. 실제 검사는 저장소
    doc_id: str = Field(min_length=1, max_length=200)
    approve: bool = False  # 관리자가 직접 넣는 키워드는 바로 승인할 수 있다


class KeywordUpdate(BaseModel):
    keyword: str = Field(min_length=1, max_length=keyword_store.MAX_LENGTH * 2)  # 정규화 전 길이. 실제 검사는 저장소


def _keyword_call(callback):
    try:
        return callback()
    except keyword_store.KeywordError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}) from exc


def _require_indexed_document(doc_id: str) -> None:
    """키워드는 색인된 문서에만 붙인다. 오타로 없는 문서에 붙으면 출처를 추적할 수 없다."""
    try:
        indexed = app.state.redis.sismember("wh:docs", doc_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"code": "INDEX_UNAVAILABLE", "message": "Redis unavailable."}) from exc
    if not indexed:
        raise HTTPException(status_code=404, detail={"code": "DOC_NOT_FOUND", "message": "Document is not indexed."})


@app.get("/admin/keywords")
def list_keywords(status: str | None = None, doc_id: str | None = None) -> dict[str, Any]:
    return {"keywords": _keyword_call(lambda: keyword_store.list_keywords(status, doc_id))}


@app.post("/admin/keywords", status_code=201)
def add_keyword(body: KeywordCreate, x_admin_id: str | None = Header(default=None)) -> dict[str, Any]:
    _require_indexed_document(body.doc_id)
    created = _keyword_call(
        lambda: keyword_store.add(body.keyword, body.doc_id, source="manual", approve=body.approve,
                                  actor=_actor(x_admin_id))
    )
    return {**created, "reload_required": created["status"] == "approved"}


@app.post("/admin/keywords/{keyword_id}/approve")
def approve_keyword(keyword_id: int, x_admin_id: str | None = Header(default=None)) -> dict[str, Any]:
    approved = _keyword_call(lambda: keyword_store.approve(keyword_id, _actor(x_admin_id)))
    return {**approved, "reload_required": True}


@app.patch("/admin/keywords/{keyword_id}")
def update_keyword(keyword_id: int, body: KeywordUpdate) -> dict[str, Any]:
    """승인 대기 키워드의 표현을 고친다. 탐지에 쓰이지 않는 상태라 재로딩이 필요 없다. 승인된 것은 409."""
    return _keyword_call(lambda: keyword_store.update(keyword_id, body.keyword))


@app.get("/admin/keyword-jobs")
def list_keyword_jobs(status: str | None = None) -> dict[str, Any]:
    return {"jobs": _keyword_call(lambda: keyword_store.list_jobs(status)),
            "counts": _keyword_call(keyword_store.job_counts)}


@app.post("/admin/documents/{doc_id}/extract-keywords", status_code=202)
def extract_keywords(doc_id: str) -> dict[str, Any]:
    """재추출 요청. 대기·진행 중 작업이 있으면 그것을 돌려준다. 버전은 추출 서비스가 처리 시점의 최신으로 본다."""
    _require_indexed_document(doc_id)
    return _keyword_call(lambda: keyword_store.enqueue_job(doc_id, keyword_store.LATEST_VERSION))


@app.post("/admin/keyword-jobs/{job_id}/retry")
def retry_keyword_job(job_id: int) -> dict[str, Any]:
    return _keyword_call(lambda: keyword_store.retry_job(job_id))


@app.delete("/admin/keywords/{keyword_id}", status_code=204)
def delete_keyword(keyword_id: int) -> None:
    """거부 = 삭제. 승인돼 있던 키워드를 지웠다면 재로딩해야 탐지에서 빠진다."""
    _keyword_call(lambda: keyword_store.delete(keyword_id))


# ---------------------------------------------------------------- 기간 보고서 (설계: llm-report-format-design.md)
#
# 대시보드 버튼 → POST로 기간을 넘기면 202와 report_id를 돌려준다. 생성은 30초~수 분(LLM) 걸리므로
# GET /admin/reports/{id}로 상태를 보고, done이면 /file로 HTML을 받는다. 한 번에 하나만 돈다.
# GPU가 꺼져 있으면 LLM 문구 대신 SQL 문장으로 만든다(llm_used=false, llm_error에 사유).


class ReportCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    start: date = Field(alias="from", description="시작일(포함)")
    end: date = Field(alias="to", description="종료일(포함)")
    use_llm: bool = True
    # 2026-10-12 설계 v2(llm-report-2026-10-12.md 4.6-e·4.11). 둘 다 선택 - 없으면 지금과 같이 동작한다.
    # content_trend: 내용 경향 포함. 없으면 전역 스위치(REPORT_CONTENT_TREND)를 따르고, 전역 꺼짐이면 켬을 보내도 끔.
    # blind_pair: 같은 사실로 LLM판·집계판 블라인드 비교 파일을 더 만든다(시험 4). 불린만 받는다(문자열 "true" 거부).
    content_trend: StrictBool | None = None
    blind_pair: StrictBool = False


def _report_call(callback):
    try:
        return callback()
    except ReportError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}) from exc


@app.post("/admin/reports", status_code=202)
def create_report(body: ReportCreate) -> dict[str, Any]:
    return _report_call(lambda: app.state.reports.start(body.start, body.end, body.use_llm,
                                                        content_trend=body.content_trend, blind_pair=body.blind_pair))


@app.get("/admin/reports")
def list_reports() -> dict[str, Any]:
    # content_trend_enabled: 전역 스위치 상태 - 대시보드가 '내용 경향 포함' 체크를 끄고 '관리자 설정으로 꺼짐'을 보인다
    return {"reports": app.state.reports.list(), "content_trend_enabled": content_trend_enabled()}


@app.get("/admin/reports/{report_id}")
def report_status(report_id: str) -> dict[str, Any]:
    return _report_call(lambda: app.state.reports.status(report_id))


@app.get("/admin/reports/{report_id}/file")
def report_file(report_id: str, download: bool = False) -> FileResponse:
    """기본은 화면 표시(inline) - 대시보드가 iframe으로 바로 띄운다. `?download=1`이면 내려받기(attachment)."""
    path = _report_call(lambda: app.state.reports.file(report_id))
    return FileResponse(path, media_type="text/html; charset=utf-8", filename=f"{report_id}.html",
                        content_disposition_type="attachment" if download else "inline")


# GPU(LLM 서버) 연결 상태 - 리포트 문구·키워드 추출이 쓰는 같은 주소를 본다. 읽기 전용(깨우지 않는다).
# 꺼져 있으면 GPU_CHECK_TIMEOUT초까지 기다린다 - 대시보드 백엔드가 Detection을 3초에 끊으므로 그보다 짧게 둔다.
# 여러 화면이 동시에 물어도 GPU_STATUS_TTL초 동안은 마지막 결과를 돌려준다.
# 인스턴스 ID가 설정돼 있으면 EC2 상태(instance_state)도 함께 본다 - running이 아니면 LLM 주소는 묻지 않는다(기다림 없음).
_REPORT_LLM_URL = os.environ.get("REPORT_LLM_URL", "http://10.0.3.254:9000/v1/chat/completions")
GPU_MODELS_URL = _REPORT_LLM_URL.rsplit("/chat/completions", 1)[0] + "/models"
GPU_STATUS_TTL = 10.0
GPU_CHECK_TIMEOUT = 2.0
_gpu_cache: dict[str, Any] = {"at": 0.0, "value": None}
_gpu_lock = threading.Lock()
_gpu_control_lock = threading.Lock()


def _gpu_snapshot() -> dict[str, Any]:
    controllable = bool(report_gpu.INSTANCE_ID)
    state = None
    if controllable:
        try:
            state = report_gpu.instance_state(instance_id=report_gpu.INSTANCE_ID)
        except report_gpu.GpuControlError:
            state = None    # 상태를 못 읽어도 LLM 응답 여부는 보여 준다
    if state is not None and state != "running":
        connection = {"connected": False, "models": [], "latency_ms": None, "error": None}
    else:
        connection = report_gpu.connection_status(GPU_MODELS_URL, GPU_CHECK_TIMEOUT)
    return {**connection, "instance_state": state, "controllable": controllable,
            "checked_at": datetime.now(timezone.utc).isoformat()}


@app.get("/admin/gpu")
def gpu_status() -> dict[str, Any]:
    with _gpu_lock:
        now = time.monotonic()
        if _gpu_cache["value"] is None or now - _gpu_cache["at"] >= GPU_STATUS_TTL:
            _gpu_cache["value"] = _gpu_snapshot()
            _gpu_cache["at"] = now
        return _gpu_cache["value"]


def _gpu_busy_reasons() -> list[str]:
    """GPU를 쓰는 중인 작업. 리포트 생성(자동 켜기·부팅 대기 포함)과 실행 중인 키워드 추출."""
    reasons = []
    if any(report.get("status") == "running" for report in app.state.reports.list()):
        reasons.append("report")
    jobs = _keyword_jobs_state()
    if jobs and jobs.get("running", 0) > 0:
        reasons.append("keyword_job")
    return reasons


def _gpu_control(action: str) -> dict[str, Any]:
    if not report_gpu.INSTANCE_ID:
        raise HTTPException(status_code=409, detail={"code": "GPU_NOT_CONFIGURED",
                                                     "message": "GPU instance id is not configured."})
    with _gpu_control_lock:
        if action == "stop":
            busy = _gpu_busy_reasons()
            if busy:
                raise HTTPException(status_code=409, detail={"code": "GPU_BUSY",
                                                             "message": f"GPU is in use: {', '.join(busy)}."})
        try:
            result = report_gpu.control(action, instance_id=report_gpu.INSTANCE_ID)
        except report_gpu.GpuControlError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}) from exc
    with _gpu_lock:
        _gpu_cache["value"] = None    # 다음 조회는 바뀐 상태를 새로 읽는다
    return result


# 대시보드 GPU 켜기·끄기(2026-10-07). 켜기는 stopped에서만, 끄기는 running에서만 - 그 밖은 409 GPU_STATE.
# 끄기는 리포트 생성·키워드 추출이 GPU를 쓰는 중이면 409 GPU_BUSY. 보고서가 켠 GPU는 생성 뒤 자식 프로세스가 끈다(reporting.gpu.auto_stop).
@app.post("/admin/gpu/start")
def start_gpu() -> dict[str, Any]:
    return _gpu_control("start")


@app.post("/admin/gpu/stop")
def stop_gpu() -> dict[str, Any]:
    return _gpu_control("stop")


# ---------------------------------------------------------------- 시스템 상태 (2026-10-12)
#
# 대시보드 '시스템 상태' 화면용. 접근 규칙은 /admin/gpu와 같다(인증 없음, 보안 그룹으로만 막는다). 읽기 전용이다.
# 일반 def라 스레드 풀에서 돈다. AWS 조회(EC2·RDS)는 system_status가 백그라운드로 돌리고 최대 2초만 기다리므로
# 이 엔드포인트 때문에 /detect가 막히지 않는다. 비밀(DSN 등)과 RDS 호스트는 응답에 싣지 않는다.


def _or_none(read):
    """상태 한 조각을 못 읽어도 나머지는 보여 준다."""
    try:
        return read()
    except Exception:  # noqa: BLE001
        return None


@app.get("/admin/system-status")
def admin_system_status() -> dict[str, Any]:
    signatures = _or_none(_signature_state) or {}
    return system_status.COLLECTOR.collect(
        redis_client=app.state.redis,
        shipper_status=_or_none(lambda: read_status(app.state.decision_log.path)),
        signatures=signatures,
        policies=_or_none(lambda: len(policy_store.list_policies())),
        keyword_jobs=_or_none(_keyword_jobs_state),
        redact_pdf=REDACT_PDF_ENABLED,
    )
