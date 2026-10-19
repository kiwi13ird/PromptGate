"""집계 사유 코드 맞추기(2026-10-15 감사) - 실제 운영 사유 코드로 만든 가짜 자료.

운영 RDS `dashboard_security_events`의 reason_code 전체(10/15): client_blocked · client_id_missing · detection_unreachable ·
doc_excerpt · file_uninspectable_image · file_uninspectable_other · mask_application_failed · pii · (없음).
Gateway 코드에만 있는 값: detection_timeout · detection_parse_error · detection_error · file_uninspectable_scanned_pdf ·
file_too_large · file_masking_failed. Detection 값: doc_excerpt · pii · none.
수정 전 코드(ACCESS_RC = ip_blocked·extension_blocked)는 접속 차단을 '개인정보·인증정보 차단'으로 셌다.
"""

from __future__ import annotations

import json
import re
import sys
import types
from collections import Counter
from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import frame as fr
from reporting import llm
from reporting import __main__ as M

from fake_llm import FakeLLM
from synth import FakeConn, ev, kst
from test_pipeline import make_conn

T0, T1 = ag.kst_bounds(date(2026, 10, 1), date(2026, 10, 13))
U = "chrome-cccc-0003"

# (사유 코드, 조치, 검출) → 기대 분류. 운영·Gateway·Detection에서 나오는 값 전부
DOC = ["01_전략_보고서"]
PHONE = {"KR_PHONE_NUMBER": 1}
TABLE = [
    ("client_blocked", "BLOCK", {}, "access"),
    ("client_id_missing", "BLOCK", {}, "access"),
    ("ip_blocked", "BLOCK", {}, "access"),                 # 옛 이름도 받음
    ("extension_blocked", "BLOCK", {}, "access"),
    ("detection_unreachable", "ALLOW", {"deg": True}, "no_check"),
    ("detection_timeout", "ALLOW", {"deg": True}, "no_check"),
    ("detection_timeout", "BLOCK", {"deg": True}, "no_check"),
    ("detection_parse_error", "ALLOW", {"deg": True}, "no_check"),
    ("detection_error", "ALLOW", {"deg": True}, "no_check"),
    ("file_uninspectable_image", "ALLOW", {}, "uninspectable"),
    ("file_uninspectable_scanned_pdf", "BLOCK", {}, "uninspectable"),
    ("file_uninspectable_other", "BLOCK", {}, "uninspectable"),
    ("file_too_large", "BLOCK", {}, "uninspectable"),
    ("mask_application_failed", "BLOCK", {"ents": PHONE}, "mask_failed"),
    ("file_masking_failed", "BLOCK", {}, "mask_failed"),
    ("doc_excerpt", "BLOCK", {"docs": DOC}, "doc"),
    ("doc_excerpt", "BLOCK", {}, "other"),                 # 검출 목록 없이 사유만(운영 9/29 파일 1건) - 2026-10-17 SPEC 2.6: 그 밖
    ("pii", "BLOCK", {"ents": PHONE}, "pii"),
    ("pii", "MASK", {"ents": PHONE}, "pii"),
    ("pii", "BLOCK", {}, "other"),                         # 운영 9/29 파일 1건 - 2026-10-17 SPEC 2.6: 그 밖
    ("pii", "BLOCK", {"ents": {"DOC_KEYWORD": 1}}, "keyword"),
    (None, "BLOCK", {"ents": PHONE}, "pii"),               # 9/15~9/23 옛 형식, 검출 있음
    (None, "BLOCK", {}, "other"),                          # 9/23 옛 형식, 사유·검출 없음(운영 16건) - 개인정보 아님
    (None, "ALLOW", {}, "clean"),
    (None, "ALLOW", {"ents": PHONE}, "clean"),
]


def _row(rc, action, kw, t="2026-10-05 10:00:00", client=U, ct_="prompt", **more):
    kw = dict(kw)
    return ev(t, client, "ChatGPT", action, ct_, rc=rc, docs=kw.pop("docs", ()), ents=kw.pop("ents", None),
              deg=kw.pop("deg", False), **more)


@pytest.mark.parametrize("rc,action,kw,want", TABLE)
def test_every_real_reason_code_has_the_right_category(rc, action, kw, want):
    r = _row(rc, action, kw)
    assert ag._cat(action, rc or "", kw.get("deg", False), r["dets"]) == want


def test_real_access_codes_leave_the_totals_and_pii_card():
    rows = [_row("client_id_missing", "BLOCK", {}, client=None, t=f"2026-10-05 10:{m:02d}:00") for m in range(5)]
    rows += [_row("client_blocked", "BLOCK", {}, t="2026-10-05 11:00:00"),
             _row("pii", "BLOCK", {"ents": PHONE}, t="2026-10-05 12:00:00")]
    by_rc: Counter = Counter()
    evs, ex = ag.prepare_events(rows, T0, T1, access_by_rc=by_rc)
    assert ex == {"test": 0, "demo": 0, "resend": 0, "resend_file": 0, "resend_prompt": 0, "access": 6}
    assert by_rc == {"client_id_missing": 5, "client_blocked": 1}
    m = ag.metrics(evs, date(2026, 10, 1), date(2026, 10, 13))
    assert m["cards"]["total"] == 1 and m["cards"]["pii_block"] == 1 and m["cards"]["block"] == 1


def test_orphan_reason_codes_counted_as_rest():
    """사유 코드만 있고 검출 목록이 없는 차단은 기밀·개인정보 카드에 들지 않고 '그 밖'(2026-10-17 SPEC 2.6, 대시보드와 같음)."""
    rows = [_row("doc_excerpt", "BLOCK", {}, ct_="file", t="2026-10-05 10:00:00"),
            _row(None, "BLOCK", {}, t="2026-10-05 10:10:00"),
            _row("pii", "BLOCK", {}, ct_="file", t="2026-10-05 10:20:00")]
    evs, _ = ag.prepare_events(rows, T0, T1)
    ag.attach_decisions(evs, {})
    c = ag.metrics(evs, date(2026, 10, 1), date(2026, 10, 13))["cards"]
    assert (c["secret"], c["secret_doc"], c["pii_block"], c["rest"], c["total"]) == (0, 0, 0, 3, 3)


def test_access_rows_do_not_change_resend_folding():
    """접기는 접속 차단 분리보다 먼저 - 접속 차단 행이 끼어도 파일 재전송 묶음은 같다(FOLD_RULE.md 4·5)."""
    f = dict(ct_="file", fid="f1")
    rows = [_row("doc_excerpt", "BLOCK", {"docs": DOC}, t="2026-10-05 10:00:00", **f),
            _row("client_blocked", "BLOCK", {}, t="2026-10-05 10:00:01"),
            _row("doc_excerpt", "BLOCK", {"docs": DOC}, t="2026-10-05 10:00:04", **f),     # 4초 - 접힘
            _row("doc_excerpt", "BLOCK", {"docs": DOC}, t="2026-10-05 10:00:08.300", **f)]  # 직전(접힌 행)에서 4.3초 - 접힘
    evs, ex = ag.prepare_events(rows, T0, T1)
    assert ex == {"test": 0, "demo": 0, "resend": 2, "resend_file": 2, "resend_prompt": 0, "access": 1} and len(evs) == 1


def test_coverage_has_access_row_split_by_code():
    rows = [_row("client_id_missing", "BLOCK", {}, client=None, t="2026-10-05 10:00:00"),
            _row("client_id_missing", "BLOCK", {}, client=None, t="2026-10-05 10:05:00"),
            _row("client_blocked", "BLOCK", {}, t="2026-10-06 10:00:00"),
            _row("client_blocked", "BLOCK", {}, t="2026-09-25 10:00:00"),                 # 이전 기간
            _row(None, "ALLOW", {}, t="2026-09-18 10:00:00"),                                # 비교 가능하게(이전 기간 앞)
            _row(None, "ALLOW", {}, t="2026-10-05 09:00:00")]
    a = ag.collect(FakeConn(rows, []), date(2026, 10, 1), date(2026, 10, 13))
    assert a["excluded"]["access"] == 3 and a["prev_excluded"]["access"] == 1
    fx = types.SimpleNamespace(by_id={}, get=lambda k: {"value": 0})
    cov = {r["key"]: r for r in fr.coverage(a, fx)}
    assert cov["access"]["cur"] == "3건" and cov["access"]["prev"] == "1건" and not cov["access"]["sub"]
    assert cov["access:client_id_missing"]["cur"] == "2건" and cov["access:client_id_missing"]["prev"] == "0건"
    assert cov["access:client_blocked"]["cur"] == "1건" and cov["access:client_blocked"]["label"] == "차단한 확장 ID"
    assert a["cur"]["cards"]["total"] == 1 and a["cur"]["cards"]["pii_block"] == 0


# ---------------------------------------------------------------- LLM 요청 본문: 접속 차단 행은 LLM 입력을 바꾸지 않는다

def _access_rows():
    out = []
    for i, t in enumerate(("2026-10-02 09:00:00", "2026-10-05 10:30:00", "2026-10-09 23:59:00", "2026-09-25 12:00:00")):
        out.append(ev(t, None, "Gemini", "BLOCK", "prompt", rc="client_id_missing", eid=f"acc-m{i}"))
    out.append(ev("2026-10-06 08:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", "prompt", rc="client_blocked", eid="acc-b1"))
    return out


def _run(tmp_path, monkeypatch, url, extra, name):
    conn = make_conn()
    conn = FakeConn(list(conn.events) + extra, conn.decisions, conn.documents, aliases=conn.aliases) \
        if hasattr(conn, "events") else conn
    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(connect=lambda dsn, autocommit=False: conn))
    monkeypatch.setenv("DETECTION_PG_DSN", "postgresql://fake")
    monkeypatch.setenv("REPORT_CONTENT_TREND", "on")
    monkeypatch.setattr(llm, "LLM_URL", url)
    out = tmp_path / f"{name}.html"
    assert M.main(["--from", "2026-10-01", "--to", "2026-10-13", "--out", str(out), "--no-local-api"]) == 0
    return out.read_text(encoding="utf-8"), json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))


def test_llm_request_bodies_ignore_access_rows(tmp_path, monkeypatch):
    got = {}
    for name, extra in (("plain", []), ("with_access", _access_rows())):
        with FakeLLM("good") as fake:
            html, log = _run(tmp_path, monkeypatch, fake.url, extra, name)
        got[name] = (sorted(r["body"] for r in fake.requests), html, log)
    (b0, h0, l0), (b1, h1, l1) = got["plain"], got["with_access"]
    assert len(b0) > 0 and b0 == b1                         # LLM에 가는 글이 바이트까지 같다
    assert l0["cards"] == l1["cards"] and l0["items"] == l1["items"]
    assert l0["excluded"]["access"] == 0 and l1["excluded"] == {**l0["excluded"], "access": 4}
    assert "접속 차단 4" in h1 and 'id="cov-access"' in h1 and 'id="cov-access-client_id_missing"' in h1
    strip = lambda h: re.sub(r"생성 \d{4}-\d{2}-\d{2} \d{2}:\d{2}", "", h)  # noqa: E731
    assert strip(h0) != strip(h1)
    # 다른 곳은 관측 범위 '접속 차단' 줄과 머리 제외 줄뿐
    norm = lambda h: re.sub(r'<tr id="cov-access[^"]*">.*?</tr>| · 접속 차단 \d+', "", strip(h), flags=re.S)  # noqa: E731
    assert norm(h0) == norm(h1)
