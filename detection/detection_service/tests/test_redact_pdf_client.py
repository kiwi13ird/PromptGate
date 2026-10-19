"""호출 참고 구현(`verify/redact_pdf_call.py`)으로 실제 HTTP(uvicorn) 왕복 - Gateway가 보게 될 계약 그대로(명세 §3.2·§3.5)."""

from __future__ import annotations

import threading
import time

import pytest
import uvicorn

import pdf_oracle as oracle
import pdf_synth as synth
from detection_service import policy_store, redact_pdf
from signature import engine as signature
from verify import redact_pdf_call as call

from test_redact_pdf import _SAVED, _client


@pytest.fixture()
def server(tmp_path, monkeypatch):
    from detection_service import keyword_store

    saved = {name: getattr(signature, name) for name in _SAVED}
    main_module, _ = _client(tmp_path, monkeypatch)
    config = uvicorn.Config(main_module.app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(500):
        if srv.started and srv.servers:
            break
        time.sleep(0.01)
    port = srv.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(10)
    for name, value in saved.items():
        setattr(signature, name, value)
    policy_store.configure_database(None)
    keyword_store.configure_database(None)
    redact_pdf.RUNTIME.discard()


SOURCE = {"service": "ChatGPT", "endpoint": "/backend-api/files", "filename": "인사 기록 (최종).pdf"}


def test_masked_round_trip(server):
    data, values, keep = synth.plain()
    result = call.redact_pdf(server, "rid-9#file:0", data, SOURCE, timeout=20)
    assert result.status == "masked" and result.reason is None
    assert result.pages == 1 and result.masked_pages == 1 and result.pii_hits.startswith("EMAIL_ADDRESS:1")
    assert oracle.leaks(result.pdf, values) == {} and oracle.kept(result.pdf, keep) == keep


def test_json_statuses_round_trip(server):
    assert call.redact_pdf(server, "r1", synth.clean_doc()[0], SOURCE, timeout=20).status == "clean"
    res = call.redact_pdf(server, "r2", synth.line_split()[0], SOURCE, timeout=20)
    assert (res.status, res.residual, res.pdf) == ("residual", "KR_RRN:1", None)
    res = call.redact_pdf(server, "r3", synth.scanned()[0], SOURCE, timeout=20)
    assert (res.status, res.detail) == ("unsupported", "no_text")


def test_http_errors_become_error_results(server):
    assert call.redact_pdf(server, "bad prefix", b"%PDF-1.4", SOURCE, timeout=5).reason == "bad_prefix"
    assert call.redact_pdf(server, "r4", b"plain text, not a pdf", SOURCE, timeout=5).reason == "http_415"
    assert call.redact_pdf("http://127.0.0.1:9", "r5", b"%PDF-1.4", SOURCE, timeout=2).reason.startswith("io:")


def test_deadline_header_is_80_percent_and_busy_is_reported(server):
    assert redact_pdf.RUNTIME.slot.acquire(timeout=1)
    try:
        t = time.monotonic()
        res = call.redact_pdf(server, "r6", synth.clean_doc()[0], SOURCE, timeout=1.0)
        took = time.monotonic() - t
    finally:
        redact_pdf.RUNTIME.slot.release()
    assert res.status == "busy" and 0.7 <= took < 1.0      # 서버 시한 = 0.8초에 busy, 호출 시한(1초) 안에 응답
