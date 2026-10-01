"""detection_service 통합 테스트 - ingest부터 API 왕복까지, API 경계에서 실제로 관찰되는 값으로 검증한다.

실제 Redis 대신 fakeredis를 쓰고, 앱의 `connect_redis()`를 monkeypatch해 테스트가 미리 채운 인스턴스를 돌려준다.
"""

from __future__ import annotations

from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

from windowhash import ingest, store

_CONFIDENTIAL_DOC = (
    "프로젝트 오로라 내부 검토 보고서. 차기 결제 시스템은 2027년 3분기 출시를 목표로 하며, "
    "예상 개발 비용은 42억 원이다. 담당 조직은 결제플랫폼팀이고 총괄 책임자는 김서연 상무다. "
    "외부 유출 시 계약 위반에 해당하는 기밀 정보를 포함한다. 파트너사인 한빛페이먼츠와의 정산 "
    "수수료율은 거래액의 0.85퍼센트로 합의됐고, 계약 기간은 3년이며 연장 조항이 포함돼 있다. "
    "핵심 위험 요소는 카드사 연동 지연과 PG 라이선스 갱신이다. 대응책으로 예비 연동 파트너 두 곳과 "
    "사전 협의를 마쳤고, 라이선스 갱신 신청은 2026년 11월까지 완료할 계획이다. "
    "인력 계획은 백엔드 개발자 여덟 명, 프론트엔드 개발자 네 명, 보안 검토 인력 두 명으로 구성된다. "
    "외주 비중은 전체 공수의 30퍼센트를 넘지 않도록 제한하며, 분기별로 이사회에 보고한다. "
)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    doc_path = tmp_path / "confidential.txt"
    doc_path.write_text(_CONFIDENTIAL_DOC, encoding="utf-8")
    conn = store.connect(tmp_path / "test.sqlite3")
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    assert ingest.ingest_file(conn, fake_redis, doc_path)["ok"]
    conn.close()

    monkeypatch.setenv("DETECTION_LOG_PATH", str(tmp_path / "logs" / "decisions.jsonl"))
    monkeypatch.delenv("DETECTION_PG_DSN", raising=False)
    import detection_service.main as main_module

    monkeypatch.setattr(main_module, "connect_redis", lambda: fake_redis)
    with TestClient(main_module.app) as c:
        yield c


def test_health(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["log_sync"] is None  # 전송 서비스 상태 파일이 없을 때


def test_unrelated_input_passes(client: TestClient) -> None:
    body = client.post("/detect", json={"request_id": "r1", "normalized_text": "오늘 점심 메뉴는 김치찌개였다.", "source": {}}).json()
    assert body["blocked"] is False and body["decided_by"] == "none"
    assert body["doc_id"] is None and body["score"] is None and body["pii_hits"] is None
    assert body["hash_status"] == "ok" and body["signature_status"] == "ok"
    assert body["decision"] == {"action": "allow", "reason_code": "none", "user_message": None, "http_status": None}
    assert "prompt" not in body  # 원문은 응답에 없다


def test_exact_copy_is_blocked(client: TestClient) -> None:
    body = client.post("/detect", json={"request_id": "r2", "normalized_text": _CONFIDENTIAL_DOC, "source": {"service": "OpenAI"}}).json()
    assert body["blocked"] is True and body["decided_by"] == "windowhash"
    assert body["doc_id"] == "confidential" and body["score"] >= 0.95


def test_partial_excerpt_is_blocked_with_position(client: TestClient) -> None:
    body = client.post("/detect", json={"request_id": "r4", "normalized_text": _CONFIDENTIAL_DOC[100:400], "source": {}}).json()
    assert body["blocked"] is True and body["request_id"] == "r4"
    lo, hi = (int(x) for x in body["doc_span"].split("-"))
    assert 95 <= lo <= 105 and 395 <= hi <= 410  # 문서 쪽 구간이 발췌 위치(100~400)를 가리킨다
    assert body["input_span"] == "0-300"
    assert "그대로 일치" in body["reason"] and body["signature_status"] == "skipped"
    assert body["decision"]["action"] == "block" and body["decision"]["http_status"] == 403
    assert "confidential" not in body["decision"]["user_message"]  # 문서명 비노출


def test_sentence_shuffled_excerpt_is_still_blocked(client: TestClient) -> None:
    sentences = [s.strip() + "." for s in _CONFIDENTIAL_DOC.split(". ") if s.strip()]
    body = client.post("/detect", json={"request_id": "r5", "normalized_text": " ".join(sentences[::-1][:4])}).json()
    assert body["blocked"] is True


def test_request_without_source_defaults(client: TestClient) -> None:
    assert client.post("/detect", json={"request_id": "r3", "normalized_text": "안녕하세요"}).status_code == 200
