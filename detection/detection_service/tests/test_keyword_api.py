"""문서 키워드 관리 API + 탐지 연결 통합 테스트.

운영과 같은 조건을 만든다: 정책 표에 `POLICY-PII-MASK`(PII → MASK)가 있다. 키워드 인식기가 `category`를
잘못 내면 키워드가 차단되지 않고 마스킹되므로, 이 조건에서 **차단**이 나오는지가 핵심 검증이다.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

from signature import engine as signature

_SCHEMA = """
CREATE TABLE signature_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('CREDENTIAL', 'PII')), entity_type TEXT NOT NULL,
    pattern TEXT NOT NULL, score REAL NOT NULL, context_keywords TEXT,
    requires_context INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE detection_policies (
    policy_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL CHECK (target_type IN ('category', 'entity_type', 'detector_rule_id')),
    target_value TEXT NOT NULL, action TEXT NOT NULL CHECK (action IN ('ALLOW', 'MASK')),
    priority INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)), UNIQUE (target_type, target_value, version)
);
INSERT INTO signature_rules (rule_id, name, category, entity_type, pattern, score)
VALUES ('SIG-CRED-001', 'GitHub token', 'CREDENTIAL', 'GITHUB_TOKEN', 'ghp_[A-Za-z0-9]{36}', 0.95);
INSERT INTO detection_policies VALUES ('POLICY-PII-MASK', 'category', 'PII', 'MASK', 100, 1, 1);
INSERT INTO detection_policies VALUES ('POLICY-CREDENTIAL-MASK', 'category', 'CREDENTIAL', 'MASK', 100, 1, 1);
"""

_DOC = "01_사업전략_방향_보고서"


def _make_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keyword_db: Path):
    db = tmp_path / "signature.db"
    connection = sqlite3.connect(db)
    connection.executescript(_SCHEMA)
    connection.commit()
    connection.close()

    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    fake_redis.sadd("wh:docs", _DOC)

    monkeypatch.setenv("SIGNATURE_DB", str(db))
    monkeypatch.setenv("KEYWORD_DB", str(keyword_db))  # 운영처럼 시그니처 DB와 별도 파일
    monkeypatch.setenv("DETECTION_LOG_PATH", str(tmp_path / "logs" / "decisions.jsonl"))
    monkeypatch.delenv("POLICY_DB", raising=False)
    import detection_service.main as main_module

    monkeypatch.setattr(main_module, "connect_redis", lambda: fake_redis)
    signature.configure_database(str(db))
    return TestClient(main_module.app)


_SAVED = ("RECOGNIZERS", "LOADED_AT", "RULE_SOURCE", "DATABASE_RULES", "KEYWORDS", "KEYWORD_SOURCE", "KEYWORD_ERROR")


@pytest.fixture()
def restore_state():
    from detection_service import keyword_store, policy_store

    saved = {name: getattr(signature, name) for name in _SAVED}
    yield
    for name, value in saved.items():
        setattr(signature, name, value)
    policy_store.configure_database(None)
    keyword_store.configure_database(None)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_state):
    (tmp_path / "kw").mkdir()
    with _make_client(tmp_path, monkeypatch, tmp_path / "kw" / "keyword.db") as c:
        yield c


def _detect(client: TestClient, text: str) -> dict:
    r = client.post("/detect", json={"request_id": "selftest-keyword", "normalized_text": text,
                                     "source": {"service": "test", "content_type": "prompt"}})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- 핵심: 승인 → 재로딩 → 차단


def test_approved_keyword_blocks_even_with_pii_mask_policy(client: TestClient):
    created = client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC, "approve": True})
    assert created.status_code == 201, created.text
    assert created.json()["reload_required"] is True

    assert _detect(client, "그린라이트 일정 어떻게 돼?")["blocked"] is False  # 재로딩 전에는 반영 안 됨

    assert client.post("/admin/reload-signatures").json()["signatures"]["keywords"] == 1
    body = _detect(client, "그린라이트 일정 어떻게 돼?")
    assert body["blocked"] is True
    assert body["decided_by"] == "signature"
    assert body["pii_hits"] == "DOC_KEYWORD:1"
    assert body["decision"]["action"] == "block"  # PII로 오인됐다면 "mask"
    assert body["mask_spans"] == []
    assert body["policy_id"] is None  # 맞는 정책 없음 -> fail-safe BLOCK


def test_pending_keyword_does_not_block(client: TestClient):
    client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC})
    client.post("/admin/reload-signatures")
    assert _detect(client, "그린라이트 일정")["blocked"] is False


def test_approve_then_delete_round_trip(client: TestClient):
    kid = client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC}).json()["id"]

    approved = client.post(f"/admin/keywords/{kid}/approve", headers={"X-Admin-Id": "admin-kim"})
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["decided_by"] == "admin-kim"
    client.post("/admin/reload-signatures")
    assert _detect(client, "그린라이트")["blocked"] is True

    assert client.delete(f"/admin/keywords/{kid}").status_code == 204
    client.post("/admin/reload-signatures")
    assert _detect(client, "그린라이트")["blocked"] is False


# ---------------------------------------------------------------- 목록·검증


def test_list_filters_by_status(client: TestClient):
    client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC, "approve": True})
    client.post("/admin/keywords", json={"keyword": "블루문", "doc_id": _DOC})
    pending = client.get("/admin/keywords", params={"status": "pending"}).json()["keywords"]
    assert [k["keyword"] for k in pending] == ["블루문"]
    assert len(client.get("/admin/keywords").json()["keywords"]) == 2


def test_keyword_is_normalized_before_storing(client: TestClient):
    """전각 공백·앞뒤 공백을 탐지 입력과 같은 규칙으로 정리해 저장한다."""
    created = client.post("/admin/keywords", json={"keyword": "  그린　라이트 ", "doc_id": _DOC}).json()
    assert created["keyword"] == "그린 라이트"


def test_unindexed_document_is_rejected(client: TestClient):
    r = client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": "없는_문서"})
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "DOC_NOT_FOUND"


def test_duplicate_is_conflict(client: TestClient):
    client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC})
    r = client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC})
    assert r.status_code == 409


def test_too_short_is_rejected(client: TestClient):
    r = client.post("/admin/keywords", json={"keyword": "가", "doc_id": _DOC})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "KEYWORD_TOO_SHORT"


def test_unknown_id_is_404(client: TestClient):
    assert client.post("/admin/keywords/999/approve").status_code == 404
    assert client.delete("/admin/keywords/999").status_code == 404


def test_invalid_status_filter_is_400(client: TestClient):
    assert client.get("/admin/keywords", params={"status": "rejected"}).status_code == 400


def test_health_shows_count_not_keywords(client: TestClient):
    """키워드 목록은 기밀이다 - 인증 없는 /health에는 개수만."""
    client.post("/admin/keywords", json={"keyword": "그린라이트", "doc_id": _DOC, "approve": True})
    client.post("/admin/reload-signatures")
    health = client.get("/health")
    assert health.json()["signatures"]["keywords"] == 1
    assert "그린라이트" not in health.text


# ---------------------------------------------------------------- 키워드 DB를 못 써도 탐지는 뜬다 (2026-10-01 사고 재현)


def test_unusable_keyword_db_does_not_stop_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_state):
    """키워드 DB 디렉터리가 없어 표를 못 만든다 - 운영에서 쓰기 불가 디렉터리였던 상황과 같은 실패.

    탐지 API는 떠야 하고 /detect는 정상이어야 한다. 키워드 관리 API만 503, /health에 이유가 보인다.
    """
    unusable = tmp_path / "does-not-exist" / "keyword.db"
    with _make_client(tmp_path, monkeypatch, unusable) as c:
        body = _detect(c, "오늘 점심 추천해줘")
        assert body["blocked"] is False

        r = c.get("/admin/keywords")
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "KEYWORD_UNAVAILABLE"

        health = c.get("/health").json()["signatures"]
        assert health["keyword_admin"] != "ok"

        # 재로딩도 키워드 때문에 실패하지 않는다
        assert c.post("/admin/reload-signatures").status_code == 200


# ---------------------------------------------------------------- 추출 작업 API


def test_extract_keywords_job_api(client):
    r = client.post(f"/admin/documents/{_DOC}/extract-keywords")
    assert r.status_code == 202 and r.json()["status"] == "queued" and r.json()["doc_version"] == 0
    again = client.post(f"/admin/documents/{_DOC}/extract-keywords")
    assert again.json()["id"] == r.json()["id"]                          # 대기 중이면 새로 안 만든다
    assert client.post("/admin/documents/없는문서/extract-keywords").status_code == 404
    jobs = client.get("/admin/keyword-jobs").json()
    assert jobs["counts"]["queued"] == 1 and jobs["jobs"][0]["doc_id"] == _DOC
    assert client.get("/admin/keyword-jobs?status=bogus").status_code == 400
    retry = client.post(f"/admin/keyword-jobs/{r.json()['id']}/retry")
    assert retry.status_code == 409 and retry.json()["detail"]["code"] == "NOT_FAILED"
    health = client.get("/health").json()["keyword_jobs"]
    assert health["queued"] == 1 and "extractor" in health


def test_list_exposes_reason_fields_and_detection_ignores_them(client: TestClient):
    """선정 이유(근거 문장·자동 검사)가 목록 응답에 실리고, 승인 키워드 차단에는 영향이 없다(2026-10-13)."""
    from detection_service import keyword_store

    keyword_store.add_extracted(_DOC, [{"keyword": "그린라이트", "reason": "사업 코드명이라 외부에 알려지면 안 된다",
                                        "evidence": "그린라이트 일정은 비공개이다.",
                                        "reason_check": {"ok": True, "source": "llm", "foreign_tokens": []},
                                        "reason_version": "keyword_reason.v1", "doc_hits": 1, "neg_hits": 0}])
    [row] = client.get("/admin/keywords").json()["keywords"]
    assert row["evidence"] == "그린라이트 일정은 비공개이다."
    assert row["reason_check"] == {"ok": True, "source": "llm", "foreign_tokens": []}
    assert row["reason_version"] == "keyword_reason.v1"
    client.post(f"/admin/keywords/{row['id']}/approve")
    client.post("/admin/reload-signatures")
    assert _detect(client, "그린라이트 일정 어떻게 돼?")["blocked"] is True
