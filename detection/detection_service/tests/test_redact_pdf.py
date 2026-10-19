"""POST /redact/pdf - 계약(명세 §3.2)·처리(§3.3)·실패 처리를 API 경계(TestClient)와 실제 자식 프로세스로 확인한다.

정답 대조: 합성 PDF마다 넣은 가짜 값 목록이 있다. 결과가 masked면 독립 검사기(`pdf_oracle` - PyMuPDF 2종·pypdf·pypdfium2
추출 + 모든 xref 객체·스트림 문자열)에서 값이 0이어야 하고, 아니면 residual/unsupported여야 한다(T2-1·T2-2).
인식기 규칙·정책은 운영 Detection과 같은 것(10/11 읽기 전용 조회: DB 규칙 4개, PII·CREDENTIAL → MASK)을 시험 DB에 넣는다.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import fakeredis
import fitz
import pytest
from fastapi.testclient import TestClient

import pdf_oracle as oracle
import pdf_synth as synth
from detection_service import policy_store, redact_pdf
from signature import engine as signature

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# 운영 signature.db의 활성 규칙(2026-10-11 읽기 전용 조회와 같은 패턴)
PROD_RULES = [
    ("SIG-CRED-001", "CREDENTIAL", "GITHUB_TOKEN", r"(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)", 0, None),
    ("SIG-CRED-002", "CREDENTIAL", "GENERIC_API_KEY", r"[A-Za-z0-9_\-]{16,128}", 1,
     "api_key,apikey,api key,x-api-key,access_key,access key,client_secret,client secret"),
    ("SIG-CRED-003", "CREDENTIAL", "PASSWORD", r'(?=[^\s"`,;]{6,128})(?=[^\s"`,;]*[A-Za-z])[^\s"`,;]{6,128}', 1,
     "password,passwd,pwd,비밀번호,db_password,database_password"),
    ("SIG-PII-001", "PII", "KR_BANK_ACCOUNT", r"[0-9]{2,6}(?:-[0-9]{2,6}){1,4}", 1,
     "계좌번호,계좌,입금계좌,account number,bank account"),
]

_SCHEMA = """
CREATE TABLE signature_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    category TEXT NOT NULL, entity_type TEXT NOT NULL, pattern TEXT NOT NULL, score REAL NOT NULL,
    context_keywords TEXT, requires_context INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT);
CREATE TABLE detection_policies (
    policy_id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_value TEXT NOT NULL, action TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1);
INSERT INTO detection_policies VALUES ('POLICY-PII-MASK', 'category', 'PII', 'MASK', 100, 1, 1);
INSERT INTO detection_policies VALUES ('POLICY-CREDENTIAL-MASK', 'category', 'CREDENTIAL', 'MASK', 100, 1, 1);
"""

_SAVED = ("RECOGNIZERS", "LOADED_AT", "RULE_SOURCE", "DATABASE_RULES", "KEYWORDS", "KEYWORD_SOURCE", "KEYWORD_ERROR")


def make_rule_db(path: Path, extra_rules=()) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(_SCHEMA)
    for rule_id, category, entity, pattern, requires, keywords in [*PROD_RULES, *extra_rules]:
        connection.execute(
            "INSERT INTO signature_rules (rule_id, name, category, entity_type, pattern, score, context_keywords,"
            " requires_context) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (rule_id, rule_id, category, entity, pattern, 0.9, keywords, requires))
    connection.commit()
    connection.close()
    return path


class Ctx:
    def __init__(self, client: TestClient, tmp_path: Path, redis_client) -> None:
        self.client = client
        self.tmp_path = tmp_path
        self.redis = redis_client

    def post(self, data: bytes, *, prefix="req1", deadline_ms=20000, extra=None, **kw):
        headers = {"Content-Type": "application/pdf", "X-Request-Prefix": prefix, "X-Deadline-Ms": str(deadline_ms),
                   "X-Source-Service": "ChatGPT", "X-Source-Endpoint": "/backend-api/files"}
        headers.update(extra or {})
        return self.client.post("/redact/pdf", content=data, headers=headers, **kw)

    def rows(self) -> list[dict]:
        path = self.tmp_path / "logs" / "decisions.jsonl"
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def _client(tmp_path, monkeypatch, extra_rules=()):
    db = make_rule_db(tmp_path / "signature.db", extra_rules)
    (tmp_path / "kw").mkdir(exist_ok=True)
    monkeypatch.setenv("SIGNATURE_DB", str(db))
    monkeypatch.setenv("KEYWORD_DB", str(tmp_path / "kw" / "keyword.db"))
    monkeypatch.setenv("DETECTION_LOG_PATH", str(tmp_path / "logs" / "decisions.jsonl"))
    monkeypatch.delenv("POLICY_DB", raising=False)
    import detection_service.main as main_module

    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(main_module, "connect_redis", lambda: fake)
    signature.configure_database(str(db))
    return main_module, fake


@pytest.fixture()
def env(tmp_path, monkeypatch):
    from detection_service import keyword_store

    saved = {name: getattr(signature, name) for name in _SAVED}
    main_module, fake = _client(tmp_path, monkeypatch)
    with TestClient(main_module.app) as client:
        yield Ctx(client, tmp_path, fake)
    for name, value in saved.items():
        setattr(signature, name, value)
    policy_store.configure_database(None)
    keyword_store.configure_database(None)
    redact_pdf.RUNTIME.test_ops = False
    redact_pdf.RUNTIME.discard()


def assert_masked_without_leaks(response, values, keep=()):
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf", response.text[:300]
    assert response.headers["x-redact-status"] == "masked"
    assert response.content.startswith(b"%PDF-")
    leaks = oracle.leaks(response.content, values)
    assert leaks == {}, leaks
    kept = oracle.kept(response.content, list(keep))
    return kept


# ---------------------------------------------------------------- 계약


def test_masked_response_contract(env):
    data, values, keep = synth.plain()
    assert set(oracle.leaks(data, values)) == set(values)            # 넣은 값이 원본에는 있다(검사기 확인)
    r = env.post(data)
    kept = assert_masked_without_leaks(r, values, keep)
    assert kept == keep
    h = r.headers
    assert (h["x-redact-pages"], h["x-redact-text-pages"], h["x-redact-masked-pages"]) == ("1", "1", "1")
    assert h["x-redact-pii-hits"] == "EMAIL_ADDRESS:1,KR_PHONE_NUMBER:1,KR_RRN:1"
    assert float(h["x-redact-elapsed-ms"]) > 0
    assert fitz.open(stream=r.content, filetype="pdf").page_count == 1


def test_json_status_shape_has_no_values(env):
    data, values, _ = synth.line_split()
    r = env.post(data)
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert set(body) == {"status", "pages", "text_pages", "masked_pages", "pii_hits", "residual", "decision",
                         "detail", "elapsed_ms"}
    assert body["status"] == "residual" and body["residual"] == "KR_RRN:1"
    assert r.headers["x-redact-status"] == "residual"
    for v in values + ["900101", "1234567"]:
        assert v not in r.text


def test_page_rows_use_page_locator_and_block_order(env):
    data, _, _ = synth.multipage(3, 6)
    r = env.post(data, prefix="rid-1#file:2", extra={"X-Source-Filename": "%EC%83%81%EB%8B%B4%20%EA%B8%B0%EB%A1%9D.pdf",
                                                     "X-Source-Service": "Claude"})
    assert r.headers["x-redact-status"] == "masked"
    rows = env.rows()
    assert [row["request_id"] for row in rows] == [f"rid-1#file:2#f:0:pdf:body:p{n}" for n in range(3)]
    assert [row["block_order"] for row in rows] == [0, 1, 2]
    assert {row["format"] for row in rows} == {"pdf"} and {row["content_type"] for row in rows} == {"file"}
    assert {row["filename"] for row in rows} == {"상담 기록.pdf"} and {row["service"] for row in rows} == {"Claude"}
    masked_rows = [row for row in rows if row["masked_text"]]
    assert masked_rows and all(row["findings"] for row in masked_rows)


def test_endpoint_query_string_is_dropped(env):
    headers = {"x-request-prefix": "rid-q", "x-deadline-ms": "1000", "content-type": "application/pdf",
               "x-source-endpoint": "/backend-api/files?token=abc"}
    assert redact_pdf.parse_headers(headers).endpoint == "/backend-api/files"
    assert redact_pdf.parse_headers({**headers, "x-source-endpoint": "?token=abc"}).endpoint is None
    r = env.post(synth.clean_doc()[0], prefix="rid-q", extra={"X-Source-Endpoint": "/backend-api/files?token=abc"})
    assert r.json()["status"] == "clean"
    assert "token" not in json.dumps(env.rows())


# ---------------------------------------------------------------- 정답 대조: 지워져야 하는 경우


MASKED_CASES = {
    "plain": synth.plain,
    "table": synth.table,
    "multipage30": lambda: synth.multipage(30),
    "tight_lines": synth.tight_lines,
    "rotated_page_90": lambda: synth.rotated_page(90),
    "rotated_page_180": lambda: synth.rotated_page(180),
    "rotated_page_270": lambda: synth.rotated_page(270),
    "rotated_text": synth.rotated_text,
    "hidden_text": synth.hidden_text,
    "en_dash": synth.en_dash,
    "annotations_and_form": synth.annotations_and_form,
    "document_level": synth.document_level,
    "shared_header": synth.shared_header,
    "off_page_and_cropbox": synth.off_page,
    "password_label": synth.password_label,
    "actualtext_glyph_value": lambda: synth.actual_text("shown"),
    "simple_font": synth.helvetica_simple,
    "owner_password_only": lambda: synth.encrypted(False),
    "upload_test1_fixture": lambda: ((FIXTURES / "upload_test1_fake.pdf").read_bytes(),
                                     ["900101-1234568", "010-1234-5678", "hong.gildong@example.com"], ["보안개발팀"]),
}


@pytest.mark.parametrize("name", sorted(MASKED_CASES))
def test_masked_cases_leave_no_value_anywhere(env, name):
    data, values, keep = MASKED_CASES[name]()
    r = env.post(data, prefix=f"case-{name}")
    kept = assert_masked_without_leaks(r, values, keep)
    assert kept == list(keep), f"일반 낱말 유지 {len(kept)}/{len(keep)}"


def test_tight_line_spacing_keeps_neighbour_lines(env):
    data, values, keep = synth.tight_lines(pitch=9.0)
    r = env.post(data)
    assert_masked_without_leaks(r, values)
    text = oracle.squash(oracle.extract_texts(r.content)["pymupdf_glyph"])
    for word in ("위줄정기점검회의록ABCDEFGHIJKLMNOP", "아래줄품질관리팀QuarterlyReviewQRSTUVWX", "값줄주민"):
        assert word in text


def test_password_label_is_removed_with_value(env):
    data, values, _ = synth.password_label()
    r = env.post(data)
    assert_masked_without_leaks(r, values)
    text = oracle.extract_texts(r.content)["pymupdf_glyph"]
    assert "비밀번호" not in text and "Database" in text and "서버 접속 정보" in text
    assert "[PASSWORD]" in text


def test_masked_values_get_type_labels(env):
    """10/12: 지운 자리에 질문과 같은 대체 글자([KR_RRN] 등)를 흰 글씨로 넣는다 - 모든 추출기에서 보이고 값은 없다."""
    data, values, keep = synth.plain()
    r = env.post(data)
    assert_masked_without_leaks(r, values, keep)
    texts = oracle.extract_texts(r.content)
    for name in ("pymupdf_glyph", "pypdf"):
        if name in texts:
            for label in ("[KR_RRN]", "[KR_PHONE_NUMBER]", "[EMAIL_ADDRESS]"):
                assert label in texts[name], (name, label)


def test_document_level_strings_are_scrubbed(env):
    data, values, _ = synth.document_level()
    r = env.post(data)
    assert_masked_without_leaks(r, values)
    out = fitz.open(stream=r.content, filetype="pdf")
    assert out.get_toc() == [] and not out.get_xml_metadata()
    assert not any(v for k, v in out.metadata.items() if k not in ("format", "producer", "encryption"))
    catalog = out.xref_object(out.pdf_catalog(), compressed=True)
    for key in ("StructTreeRoot", "AcroForm", "PageLabels", "Names", "Outlines"):
        assert f"/{key} null" in catalog or f"/{key}" not in catalog
    assert all(not list(page.annots()) and not list(page.widgets()) for page in out)


# ---------------------------------------------------------------- 정답 대조: 막혀야 하는 경우


REFUSED_CASES = {
    "line_split": (synth.line_split, "residual"),
    "letter_spaced": (synth.letter_spaced, "residual"),
    "actualtext_only_value": (lambda: synth.actual_text("hidden"), "residual"),
    "chrome_wrapped_values": (lambda: ((FIXTURES / "chrome_table_fake.pdf").read_bytes(), [], []), "residual"),
    "chrome_ligature_spaced": (lambda: ((FIXTURES / "chrome_ligature_fake.pdf").read_bytes(), [], []), "residual"),
    "scanned": (synth.scanned, "unsupported"),
    "user_password": (lambda: synth.encrypted(True), "unsupported"),
}


@pytest.mark.parametrize("name", sorted(REFUSED_CASES))
def test_refused_cases(env, name):
    build, expected = REFUSED_CASES[name]
    data, _, _ = build()
    r = env.post(data)
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json"), r.text[:200]
    assert r.json()["status"] == expected, r.json()


def test_unsupported_details(env):
    assert env.post(synth.scanned()[0]).json()["detail"] == "no_text"
    assert env.post(synth.encrypted(True)[0]).json()["detail"] == "encrypted"


def test_clean_pdf(env):
    data, _, _ = synth.clean_doc()
    body = env.post(data).json()
    assert body["status"] == "clean" and body["pages"] == 1 and body["text_pages"] == 1 and body["masked_pages"] is None


def test_residual_from_document_string_left_by_cleanup(env):
    """정리 목록 밖 자리(선택 내용 층 이름 /OCProperties)에 값 → 객체 사전 검사가 잡아 residual."""
    data, values, _ = synth.plain()
    doc = fitz.open(stream=data, filetype="pdf")
    ocg = doc.add_ocg(f"layer {synth.RRN}")
    doc[0].insert_text((60, 300), "layer text", fontname="helv", fontsize=9, oc=ocg)
    r = env.post(doc.tobytes())
    assert r.json()["status"] == "residual" and r.json()["residual"] == "KR_RRN:1"


# ---------------------------------------------------------------- 판정·정책 조합 (T2-3)


def test_blocked_by_confidential_document(env):
    from windowhash import ingest, store

    secret = ("프로젝트 오로라 내부 검토 보고서. 차기 결제 시스템은 2027년 3분기 출시를 목표로 하며, 예상 개발 비용은 42억 원이다. "
              "담당 조직은 결제플랫폼팀이고 총괄 책임자는 김서연 상무다. 외부 유출 시 계약 위반에 해당하는 기밀 정보를 포함한다. "
              "파트너사인 한빛페이먼츠와의 정산 수수료율은 거래액의 0.85퍼센트로 합의됐고 계약 기간은 3년이다.")
    doc_path = env.tmp_path / "secret.txt"
    doc_path.write_text(secret, encoding="utf-8")
    conn = store.connect(env.tmp_path / "wh.sqlite3")
    assert ingest.ingest_file(conn, env.redis, doc_path)["ok"]
    conn.close()
    doc = fitz.open()
    page = synth.new_page(doc)
    page.insert_textbox(fitz.Rect(40, 40, 560, 800), secret, fontname="kr", fontsize=10)
    page2 = synth.new_page(doc)
    synth.put(page2, (60, 80), f"연락처 {synth.PHONE}")
    r = env.post(synth.finish(doc))
    body = r.json()
    assert body["status"] == "blocked" and body["detail"] == "page:0"
    decision = body["decision"]
    assert set(decision) == set(redact_pdf_detect_keys())
    assert decision["decided_by"] == "windowhash" and decision["decision"]["reason_code"] == "doc_excerpt"
    assert decision["request_id"] == "req1#f:0:pdf:body:p0" and decision["masked_text"] is None
    assert "오로라" not in r.text


def redact_pdf_detect_keys():
    from detection_service.schemas import DetectResponse

    return DetectResponse.model_fields.keys()


def test_blocked_by_policy(env):
    policy_store.update("POLICY-PII-MASK", "BLOCK_NOTIFY", 1, "test")
    body = env.post(synth.plain()[0]).json()
    assert body["status"] == "blocked" and body["decision"]["decision"]["reason_code"] == "pii"
    assert all(f["replacement"] is None for f in body["decision"]["findings"])


def test_allow_policy_values_stay_and_are_not_residual(env):
    policy_store.create("EMAIL_ADDRESS", "ALLOW", "test")
    data, values, _ = synth.plain()
    r = env.post(data)
    assert r.headers["x-redact-status"] == "masked"
    leaks = oracle.leaks(r.content, values)
    assert set(leaks) == {synth.EMAIL}                    # ALLOW 적중은 지우지 않고 잔존으로 세지 않는다


def test_mask_partial_removes_whole_value(env):
    policy_store.update("POLICY-PII-MASK", "MASK_PARTIAL", 1, "test")
    data, values, _ = synth.plain()
    r = env.post(data)
    assert_masked_without_leaks(r, values + ["900101-", "010-1234-"])  # 부분 가림 정책도 PDF는 값 전체를 지운다


def test_overlapping_findings_are_masked_not_500(tmp_path, monkeypatch):
    """두 인식기 적중이 겹침(주민번호 안의 숫자 묶음을 잡는 DB 규칙) - 지금 운영은 /detect 500(명세 §3.4)."""
    from detection_service import keyword_store

    saved = {name: getattr(signature, name) for name in _SAVED}
    extra = [("SIG-TEST-OVERLAP", "PII", "TEST_DIGITS", r"(?<!\d)\d{6}-\d{3}", 0, None)]
    main_module, fake = _client(tmp_path, monkeypatch, extra)
    try:
        with TestClient(main_module.app) as client:
            ctx = Ctx(client, tmp_path, fake)
            data, values, _ = synth.plain()
            assert_masked_without_leaks(ctx.post(data), values)
            r = client.post("/detect", json={"request_id": "ov1", "normalized_text": f"주민 {synth.RRN} 끝"})
            assert r.status_code == 200, r.text
            assert r.json()["pii_hits"] == "KR_RRN:1,TEST_DIGITS:1" and len(r.json()["mask_spans"]) == 1
    finally:
        for name, value in saved.items():
            setattr(signature, name, value)
        policy_store.configure_database(None)
        keyword_store.configure_database(None)
        redact_pdf.RUNTIME.discard()


# ---------------------------------------------------------------- 입력 검사


@pytest.mark.parametrize("prefix", ["", "a b", "x" * 151, "가나".encode("utf-8"), "a/b", "a.b"])
def test_bad_prefix_is_400(env, prefix):
    r = env.client.post("/redact/pdf", content=b"%PDF-1.4", headers={"Content-Type": "application/pdf",
                                                                      "X-Request-Prefix": prefix, "X-Deadline-Ms": "1000"})
    assert r.status_code == 400 and r.json()["detail"] == "bad_request_prefix"


def test_prefix_charset_edges_are_accepted(env):
    r = env.post(synth.clean_doc()[0], prefix="Ab09#:_-" + "x" * 142)
    assert r.status_code == 200 and r.json()["status"] == "clean"


@pytest.mark.parametrize("deadline", [None, "", "abc", "99", "30001", "-5", "1.5"])
def test_bad_deadline_is_400(env, deadline):
    headers = {"Content-Type": "application/pdf", "X-Request-Prefix": "r1"}
    if deadline is not None:
        headers["X-Deadline-Ms"] = deadline
    r = env.client.post("/redact/pdf", content=b"%PDF-1.4", headers=headers)
    assert r.status_code == 400 and r.json()["detail"] == "bad_deadline"


@pytest.mark.parametrize("headers,detail", [
    ({"X-Source-Filename": "%FF%FE.pdf"}, "bad_source_filename"),
    ({"X-Source-Filename": "a" * 256}, "bad_source_filename"),
    ({"X-Source-Filename": "%0Aname.pdf"}, "bad_source_filename"),
    ({"X-Source-Service": "Chat<GPT>"}, "bad_source_service"),
    ({"X-Source-Endpoint": "/x" * 300}, "bad_source_endpoint"),
])
def test_bad_source_headers_are_400(env, headers, detail):
    r = env.post(synth.clean_doc()[0], extra=headers)
    assert r.status_code == 400 and r.json()["detail"] == detail


def test_content_type_and_magic(env):
    r = env.post(synth.clean_doc()[0], extra={"Content-Type": "application/octet-stream"})
    assert r.status_code == 415 and r.json()["detail"] == "content_type_not_pdf"
    r = env.post(b"not a pdf at all " * 100)
    assert r.status_code == 415 and r.json()["detail"] == "not_pdf"
    r = env.post(b"\x00" * 1100 + b"%PDF-1.7")          # 머리 1024바이트 밖
    assert r.status_code == 415


def test_content_length_over_limit_is_413_before_reading(env):
    r = env.post(b"%PDF-1.4 small", extra={"Content-Length": str(20 * 1024 * 1024 + 1)})
    assert r.status_code == 413 and r.json()["detail"] == "too_large"


def test_streamed_body_over_limit_is_413(env):
    def chunks():
        yield b"%PDF-1.4\n"
        for _ in range(21):
            yield b"0" * (1024 * 1024)

    r = env.client.post("/redact/pdf", content=chunks(), headers={"Content-Type": "application/pdf",
                                                                   "X-Request-Prefix": "big", "X-Deadline-Ms": "20000"})
    assert r.status_code == 413


def test_result_too_large_is_unsupported(env, monkeypatch):
    monkeypatch.setattr(redact_pdf, "MAX_OUTPUT_BYTES", 2000)
    body = env.post(synth.plain()[0]).json()
    assert body["status"] == "unsupported" and body["detail"] == "result_too_large"


def test_text_budget_follows_deadline(env):
    env.post(synth.clean_doc()[0])                     # 자식을 먼저 띄워 둔다(띄우는 시간이 시한을 먹지 않게)
    data, _, _ = synth.multipage(40, 25)               # 공백 아닌 글자 약 4만 자 > 500ms 몫 20,161자
    body = env.post(data, deadline_ms=500).json()
    assert body["status"] == "unsupported" and body["detail"] == "text_too_large", body


# ---------------------------------------------------------------- 동시 실행·시한·자식 장애 (T2-9)


def test_busy_when_another_job_holds_the_slot(env):
    assert redact_pdf.RUNTIME.slot.acquire(timeout=1)
    try:
        t = time.monotonic()
        body = env.post(synth.clean_doc()[0], deadline_ms=300).json()
        assert body["status"] == "busy" and time.monotonic() - t < 2
    finally:
        redact_pdf.RUNTIME.slot.release()
    assert env.post(synth.clean_doc()[0]).json()["status"] == "clean"


def _with_test_op(monkeypatch, op: dict):
    real = redact_pdf.run_job

    def run_job(worker, body, meta, deadline, redis_client, decision_log, job):
        worker.request({"op": "test", **op}, None, deadline)
        return real(worker, body, meta, deadline, redis_client, decision_log, job)

    redact_pdf.RUNTIME.discard()
    redact_pdf.RUNTIME.test_ops = True
    monkeypatch.setattr(redact_pdf, "run_job", run_job)


def test_worker_timeout_kills_child_then_recovers(env, monkeypatch):
    _with_test_op(monkeypatch, {"what": "sleep", "seconds": 30})
    t = time.monotonic()
    body = env.post(synth.clean_doc()[0], deadline_ms=1500).json()
    assert body["status"] == "timeout" and body["detail"] == "worker" and time.monotonic() - t < 5
    assert redact_pdf.RUNTIME.worker is None
    monkeypatch.undo()
    assert env.post(synth.clean_doc()[0]).json()["status"] == "clean"


def test_child_exit_is_error_then_recovers(env, monkeypatch):
    _with_test_op(monkeypatch, {"what": "exit"})
    body = env.post(synth.clean_doc()[0]).json()
    assert body["status"] == "error" and body["detail"].startswith("worker:")
    monkeypatch.undo()
    assert env.post(synth.plain()[0]).headers["x-redact-status"] == "masked"


def test_kill_minus_9_during_processing(env):
    data, _, _ = synth.multipage(150, 30)
    env.post(synth.clean_doc()[0])                     # 자식을 띄워 둔다
    worker = redact_pdf.RUNTIME.worker
    assert worker is not None
    result = {}

    def call():
        result["r"] = env.post(data, deadline_ms=30000)

    thread = threading.Thread(target=call)
    thread.start()
    for _ in range(1000):                               # 작업이 잠금을 잡을 때까지(처리 중)
        if redact_pdf.RUNTIME.slot._value == 0:
            break
        time.sleep(0.002)
    time.sleep(0.05)
    worker.proc.kill()
    thread.join(60)
    assert result["r"].status_code == 200 and result["r"].json()["status"] in ("error", "timeout")
    assert env.client.get("/health").json()["status"] == "ok"
    assert env.post(synth.plain()[0]).headers["x-redact-status"] == "masked"


def test_oversized_reply_kills_child(env):
    worker = redact_pdf.Worker.spawn(time.monotonic() + 30, test_ops=True)
    try:
        with pytest.raises(redact_pdf.WorkerError):
            worker.request({"op": "test", "what": "oversize", "chars": 5000}, None, time.monotonic() + 10, max_json=1000)
        assert worker.dead
        worker.proc.wait(5)
        assert worker.proc.poll() is not None
    finally:
        worker.close()


def test_child_environment_has_no_service_secrets(env, monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "fake-secret-value")
    monkeypatch.setenv("DETECTION_PG_DSN", "postgresql://fake")
    worker = redact_pdf.Worker.spawn(time.monotonic() + 30)
    try:
        reply, _ = worker.request({"op": "probe"}, None, time.monotonic() + 30)
    finally:
        worker.close()
    allowed = set(redact_pdf.CHILD_ENV_KEEP) | {"__PYVENV_LAUNCHER__"}
    # Windows는 프로세스 시작 때 몇 가지를 스스로 넣는다(대소문자 무시로 비교)
    keys = {k.upper() for k in reply["env_keys"]}
    assert keys <= {k.upper() for k in allowed}, keys
    assert reply["fitz"]


@pytest.mark.skipif(sys.platform != "linux", reason="RLIMIT_AS·nice·oom_score_adj는 Linux")
def test_child_limits_on_linux(env, monkeypatch):
    monkeypatch.setenv("DETECTION_REDACT_PDF_RLIMIT_MB", "700")
    worker = redact_pdf.Worker.spawn(time.monotonic() + 30, test_ops=True)
    try:
        reply, _ = worker.request({"op": "probe"}, None, time.monotonic() + 30)
        assert reply["rlimit_as"] == 700 * 1024 * 1024 and reply["rlimit_core"] == 0
        assert reply["nice"] >= 10 and reply["oom_score_adj"] == 1000
        with pytest.raises(redact_pdf.WorkerError, match="MemoryError"):
            worker.request({"op": "test", "what": "alloc", "mb": 900}, None, time.monotonic() + 30)
    finally:
        worker.close()


def test_malformed_pdfs_never_crash_the_service(env):
    """고정 씨앗 변형(잘림·바이트 뒤집기·구조 키워드 훼손) - 응답은 200(정해진 상태값) 또는 415만, 서비스·Redis는 그대로."""
    import random

    rng = random.Random(20261011)
    seeds = [synth.plain()[0], synth.table()[0], synth.annotations_and_form()[0], synth.document_level()[0]]
    keys_before = sorted(env.redis.keys("*"))
    seen = {}
    for i in range(60):
        data = bytearray(rng.choice(seeds))
        kind = i % 4
        if kind == 0:
            data = data[:rng.randrange(16, len(data))]
        elif kind == 1:
            for _ in range(rng.randrange(1, 40)):
                data[rng.randrange(9, len(data))] = rng.randrange(256)
        elif kind == 2:
            for word in (b"obj", b"endobj", b"stream", b"xref", b"trailer", b"/Length", b"startxref"):
                at = data.find(word, rng.randrange(0, len(data)))
                if at > 0:
                    data[at:at + len(word)] = bytes(rng.randrange(33, 127) for _ in word)
        else:
            cut = rng.randrange(9, len(data))
            data = data[:cut] + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 400))) + data[cut:]
        r = env.post(bytes(data), prefix=f"fuzz-{i}", deadline_ms=10000)
        assert r.status_code in (200, 415), (i, r.status_code, r.text[:200])
        if r.status_code == 200:
            status = r.headers["x-redact-status"]
            assert status in redact_pdf.STATUSES
            seen[status] = seen.get(status, 0) + 1
            if status == "masked":
                assert r.content.startswith(b"%PDF-")
    assert env.client.get("/health").json()["status"] == "ok"
    assert sorted(env.redis.keys("*")) == keys_before
    assert seen  # 어떤 상태가 나왔는지(보고용)


def test_health_reports_redact_pdf(env):
    assert env.client.get("/health").json()["redact_pdf"] is True


# ---------------------------------------------------------------- 기동 경로 격리


def _run_python(code: str, tmp_path: Path) -> str:
    out = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=180,
                         env={**_base_env(), "PYTHONPATH": str(ROOT),
                              "DETECTION_LOG_PATH": str(tmp_path / "decisions.jsonl")})
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout.strip().splitlines()[-1]


def _base_env():
    import os

    return {k: v for k, v in os.environ.items() if k.upper() in {"PATH", "SYSTEMROOT", "TEMP", "TMP", "LANG", "HOME"}}


def test_parent_never_opens_the_pdf_with_mupdf(env, monkeypatch):
    """부모는 PyMuPDF로 PDF를 열지 않는다(자식만). 부모에 fitz가 이미 실려 있는 것은 기존 등록 파서
    (`preprocessing.pdf_parser`, 기동 때 import) 때문이고, /redact/pdf 경로는 그것을 쓰지 않는다."""
    data, values, keep = synth.plain()

    def forbidden(*_a, **_k):
        raise AssertionError("parent opened a PDF with MuPDF")

    import pymupdf

    for module in (pymupdf, fitz):
        monkeypatch.setattr(module, "open", forbidden)
        monkeypatch.setattr(module, "Document", forbidden)
    r = env.post(data)
    assert r.headers["x-redact-status"] == "masked"
    monkeypatch.undo()
    assert_masked_without_leaks(r, values, keep)


def test_import_failure_keeps_detect_up(tmp_path):
    code = """
import sys, importlib.abc, fakeredis
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name == 'detection_service.redact_pdf':
            raise ImportError('simulated')
sys.meta_path.insert(0, Block())
import detection_service.main as m
from fastapi.testclient import TestClient
fake = fakeredis.FakeRedis(decode_responses=True)
m.connect_redis = lambda: fake
with TestClient(m.app) as c:
    h = c.get('/health').json()['redact_pdf']
    d = c.post('/detect', json={'request_id': 'x1', 'normalized_text': 'hello'}).status_code
    p = c.post('/redact/pdf', content=b'%PDF-1.4', headers={'Content-Type': 'application/pdf'}).status_code
print(h, d, p)
"""
    assert _run_python(code, tmp_path) == "False 200 404"


def test_module_top_level_imports():
    import ast

    stdlib = set(sys.stdlib_module_names)
    for name, allowed_extra in (("redact_pdf.py", {"fastapi"}), ("pdf_worker.py", set())):
        tree = ast.parse((ROOT / "detection_service" / name).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, f"{name}: 상대 import는 함수 안에서만"
                roots = {(node.module or "").split(".")[0]}
            else:
                continue
            assert roots <= stdlib | allowed_extra | {"__future__"}, (name, roots)
