"""Detection API — windowhash(창 해시 탐지)를 HTTP로 노출한다.

Gateway EC2와 Detection EC2는 별개 인스턴스이고, 이 모듈은 그 네트워크 홉의 서버 쪽이다. 실시간 조회는 Redis만 본다.
적재는 `windowhash.cli ingest`가 별도 배치로 담당한다.

기록: 로그 파일 `DETECTION_LOG_PATH`(기본 /opt/detection/logs/decisions.jsonl)에만 쓴다. RDS `decisions`로는 별도 서비스
`detection_service.log_shipper`(detection-logshipper.service)가 옮긴다 - 이 API는 RDS에 연결하지 않는다(2026-09-15).
`/health`는 전송 서비스 상태 파일을 읽어 `log_sync`로 보여준다.
설계: docs/pipelines/detection-decision-log-design.md §11, infra/postgres/schema_mvp.sql
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from signature import engine as signature
from windowhash.index import connect as connect_redis

from . import keyword_store, pipeline, policy_store
from .decision_log import DEFAULT_PATH as DEFAULT_LOG_PATH
from .decision_log import DecisionLog
from .log_shipper import read_status
from .schemas import DetectRequest, DetectResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.redis = connect_redis()
    app.state.decision_log = DecisionLog(os.environ.get("DETECTION_LOG_PATH", DEFAULT_LOG_PATH))
    policy_store.configure_database(os.environ.get("POLICY_DB") or os.environ.get("SIGNATURE_DB"))
    # 키워드 DB는 시그니처 DB와 따로다(시그니처 DB 디렉터리는 서비스가 쓸 수 없다). 실패해도 예외를 올리지 않는다 -
    # 키워드 관리 API만 503이 되고 탐지는 뜬다(2026-10-01 사고 이후).
    keyword_store.configure_database(os.environ.get("KEYWORD_DB"))
    try:
        yield
    finally:
        app.state.redis.close()


app = FastAPI(lifespan=lifespan)


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
                                          "last_ok_ts", "last_error", "started_ts", "updated_ts")}
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
    }


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


@app.delete("/admin/keywords/{keyword_id}", status_code=204)
def delete_keyword(keyword_id: int) -> None:
    """거부 = 삭제. 승인돼 있던 키워드를 지웠다면 재로딩해야 탐지에서 빠진다."""
    _keyword_call(lambda: keyword_store.delete(keyword_id))
