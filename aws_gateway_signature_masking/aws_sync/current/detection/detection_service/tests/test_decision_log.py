"""판정 기록 - 탐지 API는 로그 파일에만 쓰고, 줄은 응답과 같은 열 + decision_id·ts·prompt를 갖는다(2026-09-15)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

import detection_service.pipeline as pipeline
from detection_service.decision_log import COLUMNS, DecisionLog
from signature import engine
from windowhash import ingest, store

from test_main import _CONFIDENTIAL_DOC  # noqa: F401


@pytest.fixture()
def logged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    doc_path = tmp_path / "confidential.txt"
    doc_path.write_text(_CONFIDENTIAL_DOC, encoding="utf-8")
    conn = store.connect(tmp_path / "windowhash.sqlite3")
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    assert ingest.ingest_file(conn, fake_redis, doc_path)["ok"]
    conn.close()

    monkeypatch.setenv("DETECTION_LOG_PATH", str(tmp_path / "logs" / "decisions.jsonl"))
    monkeypatch.setenv("DETECTION_PG_DSN", "postgresql://must-not-be-used")
    import detection_service.main as main_module

    monkeypatch.setattr(main_module, "connect_redis", lambda: fake_redis)
    with TestClient(main_module.app, raise_server_exceptions=False) as c:
        yield c, tmp_path


def _lines(tmp_path: Path) -> list[dict]:
    p = tmp_path / "logs" / "decisions.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


def test_block_row_matches_response_and_keeps_prompt_only_in_records(logged):
    client, tmp_path = logged
    excerpt = _CONFIDENTIAL_DOC[100:400]
    body = client.post("/detect", json={"request_id": "L1", "normalized_text": excerpt, "source": {"service": "OpenAI", "format": "chatgpt_web"}}).json()
    (rec,) = _lines(tmp_path)
    assert list(rec.keys()) == list(COLUMNS)
    for k in ("request_id", "blocked", "decided_by", "doc_id", "doc_span", "input_span", "score", "pii_hits", "reason", "hash_status", "signature_status", "total_ms"):
        assert rec[k] == body[k], k
    assert rec["blocked"] is True and rec["doc_id"] == "confidential"
    assert rec["service"] == "OpenAI" and rec["format"] == "chatgpt_web" and rec["text_chars"] == 300
    assert rec["prompt"] == excerpt and "prompt" not in body and "decision_id" not in body
    assert uuid.UUID(rec["decision_id"])


def test_api_does_not_touch_postgres(logged, monkeypatch: pytest.MonkeyPatch):
    import detection_service.pg_store as pg_store

    def boom(dsn):
        raise AssertionError("탐지 API가 RDS에 연결했다")

    monkeypatch.setattr(pg_store, "_default_connect", boom)
    client, tmp_path = logged
    assert client.post("/detect", json={"request_id": "L0", "normalized_text": "안녕하세요 반갑습니다"}).status_code == 200
    assert len(_lines(tmp_path)) == 1


def test_pass_row_is_recorded_with_prompt(logged):
    client, tmp_path = logged
    client.post("/detect", json={"request_id": "L2", "normalized_text": "오늘 점심 메뉴는   김치찌개였다."})
    (rec,) = _lines(tmp_path)
    assert rec["blocked"] is False and rec["decided_by"] == "none" and rec["doc_id"] is None
    assert rec["prompt"] == "오늘 점심 메뉴는 김치찌개였다."  # 정규화된 본문


def test_ts_is_receive_time(logged, monkeypatch: pytest.MonkeyPatch):
    client, tmp_path = logged
    import time

    before = time.time()
    client.post("/detect", json={"request_id": "L2t", "normalized_text": "시각 확인"})
    (rec,) = _lines(tmp_path)
    assert before <= rec["ts"] <= time.time()


def test_same_request_id_twice_gives_two_distinct_decisions(logged):
    client, tmp_path = logged
    for text in ("첫 번째 입력", "두 번째 입력"):
        assert client.post("/detect", json={"request_id": "dup", "normalized_text": text}).status_code == 200
    a, b = _lines(tmp_path)
    assert a["request_id"] == b["request_id"] == "dup" and a["decision_id"] != b["decision_id"]


def test_empty_request_id_is_rejected_and_not_logged(logged):
    client, tmp_path = logged
    assert client.post("/detect", json={"request_id": "", "normalized_text": "빈 번호"}).status_code == 422
    assert client.post("/detect", json={"normalized_text": "번호 없음"}).status_code == 422
    assert _lines(tmp_path) == []


def test_signature_block_records_counts_only(logged, monkeypatch: pytest.MonkeyPatch):
    class _RRN:
        entity_type = "KR_RRN"

        def analyze(self, text):
            i = text.find("990314-1234567")
            return [engine.Hit(self.entity_type, i, i + 14, 0.95)] if i >= 0 else []

    monkeypatch.setattr(engine, "RECOGNIZERS", (_RRN(),))
    client, tmp_path = logged
    client.post("/detect", json={"request_id": "L3", "normalized_text": "주민등록번호 990314-1234567"})
    (rec,) = _lines(tmp_path)
    assert rec["decided_by"] == "signature" and rec["pii_hits"] == "KR_RRN:1"
    assert "990314" not in rec["reason"]


def test_unexpected_exception_is_logged_as_error_row_then_500(logged, monkeypatch: pytest.MonkeyPatch):
    def broken(r, text, row):
        raise KeyError("boom")

    monkeypatch.setattr(pipeline, "_decide", broken)
    client, tmp_path = logged
    assert client.post("/detect", json={"request_id": "L6", "normalized_text": "무언가"}).status_code == 500
    (rec,) = _lines(tmp_path)
    assert rec["request_id"] == "L6" and rec["hash_status"] == "error" and rec["signature_status"] == "error"
    assert rec["decided_by"] == "none" and rec["reason"] == "internal error: KeyError" and rec["prompt"] == "무언가"


def test_log_write_failure_does_not_break_response(logged, monkeypatch: pytest.MonkeyPatch):
    client, tmp_path = logged

    def boom(self, record):
        raise OSError("disk full")

    monkeypatch.setattr(DecisionLog, "_rotate_if_needed", boom)
    body = client.post("/detect", json={"request_id": "L4", "normalized_text": "안녕하세요 반갑습니다"})
    assert body.status_code == 200 and body.json()["blocked"] is False


def test_rotation_keeps_all_lines(tmp_path: Path):
    log = DecisionLog(tmp_path / "d.jsonl", max_bytes=300, backups=50)
    for i in range(40):
        assert log.write({"decision_id": f"id{i}", "request_id": f"r{i}", "ts": 1.0, "prompt": "x" * 30})
    ids = []
    for p in sorted(tmp_path.glob("d.jsonl*")):
        ids += [json.loads(x)["decision_id"] for x in p.read_text(encoding="utf-8").splitlines()]
    assert sorted(ids) == sorted(f"id{i}" for i in range(40))
