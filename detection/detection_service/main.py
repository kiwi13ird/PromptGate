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

from fastapi import FastAPI

from windowhash.index import connect as connect_redis

from . import pipeline
from .decision_log import DEFAULT_PATH as DEFAULT_LOG_PATH
from .decision_log import DecisionLog
from .log_shipper import read_status
from .schemas import DetectRequest, DetectResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.redis = connect_redis()
    app.state.decision_log = DecisionLog(os.environ.get("DETECTION_LOG_PATH", DEFAULT_LOG_PATH))
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


@app.get("/health")
def health() -> dict[str, Any]:
    sync = read_status(app.state.decision_log.path)
    if sync is not None:
        sync = {k: sync.get(k) for k in ("pending_bytes", "shipped_total", "rejected_total", "consecutive_failures",
                                          "last_ok_ts", "last_error", "started_ts", "updated_ts")}
    return {"status": "ok", "log_sync": sync}
