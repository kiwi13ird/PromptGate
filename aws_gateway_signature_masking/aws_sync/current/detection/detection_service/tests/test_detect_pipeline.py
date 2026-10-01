"""pipeline 테스트 - 전처리 → ① 해시 → (차단이면 즉시) → ② 패턴매칭 → 응답. API 경계(TestClient)에서 확인한다.

PII 인식기는 아직 없으므로 가짜 인식기를 `signature.engine.RECOGNIZERS`에 꽂아 순서와 단락, 격리 규칙을 본다.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import detection_service.pipeline as pipeline
from signature import engine

from test_main import _CONFIDENTIAL_DOC, client  # noqa: F401


class _RRNStub:
    entity_type = "KR_RRN"

    def __init__(self):
        self.seen: list[str] = []

    def analyze(self, text: str) -> list[engine.Hit]:
        self.seen.append(text)
        i = text.find("990314-1234567")
        return [engine.Hit(self.entity_type, i, i + 14, 0.95)] if i >= 0 else []


class _Boom:
    entity_type = "BOOM"

    def analyze(self, text: str) -> list[engine.Hit]:
        raise RuntimeError("recognizer crashed")


def _detect(client: TestClient, text: str) -> dict:
    resp = client.post("/detect", json={"request_id": "p1", "normalized_text": text})
    assert resp.status_code == 200
    return resp.json()


def test_hash_pass_then_signature_blocks(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    stub = _RRNStub()
    monkeypatch.setattr(engine, "RECOGNIZERS", (stub,))
    raw = "담당자  주민등록번호  990314-1234567  ​참고"  # 다중 공백 + 제로폭 - 전처리로 정리돼야 한다
    body = _detect(client, raw)
    assert stub.seen == [pipeline.preprocess(raw)]  # ②는 전처리된 텍스트를 한 번 받는다
    assert body["blocked"] is True and body["decided_by"] == "signature"
    assert body["pii_hits"] == "KR_RRN:1" and body["reason"] == "패턴 적중: KR_RRN:1"
    assert body["doc_id"] is None and "990314" not in body["reason"]
    assert body["decision"] == {"action": "block", "reason_code": "pii", "user_message": pipeline.USER_MESSAGE_PII, "http_status": 403}


def test_hash_block_short_circuits_signature(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    stub = _RRNStub()
    monkeypatch.setattr(engine, "RECOGNIZERS", (stub,))
    body = _detect(client, _CONFIDENTIAL_DOC[100:400] + " 주민등록번호 990314-1234567")
    assert body["blocked"] is True and body["decided_by"] == "windowhash"
    assert stub.seen == [] and body["signature_status"] == "skipped" and body["pii_hits"] is None


def test_signature_error_is_isolated(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(engine, "RECOGNIZERS", (_Boom(),))
    body = _detect(client, "오늘 점심 메뉴는 김치찌개였다.")
    assert body["blocked"] is False and body["hash_status"] == "ok" and body["signature_status"] == "error"


def test_hash_error_falls_through_to_signature(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(engine, "RECOGNIZERS", (_RRNStub(),))

    def broken(*_a, **_k):
        raise ConnectionError("redis down")

    monkeypatch.setattr(pipeline.detect, "query_text", broken)
    body = _detect(client, "주민등록번호 990314-1234567")
    assert body["hash_status"] == "error" and body["signature_status"] == "ok"
    assert body["blocked"] is True and body["decided_by"] == "signature"  # 해시가 죽어도 패턴은 산다


def test_hash_error_and_no_hits_passes_with_error_reason(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    def broken(*_a, **_k):
        raise ConnectionError("redis down")

    monkeypatch.setattr(pipeline.detect, "query_text", broken)
    body = _detect(client, "오늘 점심 메뉴는 김치찌개였다.")
    assert body["blocked"] is False and body["reason"] == "windowhash error" and body["hash_status"] == "error"


def test_preprocess_is_idempotent():
    once = pipeline.preprocess("안녕하세요   반갑습니다")
    assert once == pipeline.preprocess(once)
