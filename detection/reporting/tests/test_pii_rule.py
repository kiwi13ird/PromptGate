"""개인정보·기밀 차단은 검출된 값이 있어야 센다(2026-10-17, docs/handoff/stats-rules-2026-10-16/SPEC.md 2.6).

대시보드 hasSensitiveFinding(app.mjs)과 같은 규칙: 문서 검출기가 낸 탐지 또는 패턴 검사(SIGNATURE) 값 1개 이상.
검출 목록 없이 사유 코드(pii·doc_excerpt)만 남은 차단(운영 9/29 파일 차단 2건)은 '그 밖'(카드 밖 차단)으로 센다.
수정 전 코드는 사유 코드만 보고 개인정보·기밀 차단으로 셌다 → 아래 시험은 수정 전 코드에서 모두 실패해야 한다.
"""

from __future__ import annotations

from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import frame as fr

from synth import FakeConn, ev

T0, T1 = ag.kst_bounds(date(2026, 9, 15), date(2026, 10, 2))
U = "chrome-pppp-0017"
DOC = ["01_전략_보고서"]
PHONE = {"KR_PHONE_NUMBER": 1}


def _sig_zero(t, rc="pii", action="BLOCK", ct_="file"):
    """패턴 검사 탐지는 있지만 값이 0개인 행(대시보드 hasSensitiveFinding = 거짓)."""
    r = ev(t, U, "ChatGPT", action, ct_, rc=rc)
    r["dets"] = [{"detector": "SIGNATURE", "doc": None, "ents": [{"entity_type": "KR_PHONE_NUMBER", "count": 0}]}]
    return r


@pytest.mark.parametrize("rc,action", [("pii", "BLOCK"), ("pii", "MASK"), ("doc_excerpt", "BLOCK"), ("doc_excerpt", "MASK")])
def test_reason_code_alone_is_other(rc, action):
    r = ev("2026-09-29 15:33:00", U, "ChatGPT", action, "file", rc=rc)
    assert ag._cat(action, rc, False, r["dets"]) == "other"


@pytest.mark.parametrize("action", ["BLOCK", "MASK"])
def test_signature_without_values_is_other(action):
    r = _sig_zero("2026-09-29 15:33:00", action=action)
    assert ag._cat(action, "pii", False, r["dets"]) == "other"


def test_period_cards_match_dashboard_rule():
    """9/29 형태 그대로: 사유만 pii 1 · 사유만 doc_excerpt 1 · 값 있는 개인정보 1 · 문서 일치 1."""
    rows = [ev("2026-09-29 15:27:00", U, "ChatGPT", "BLOCK", "file", rc="doc_excerpt", eid="o-doc"),
            ev("2026-09-29 15:33:00", U, "ChatGPT", "BLOCK", "file", rc="pii", eid="o-pii"),
            ev("2026-09-29 16:00:00", U, "ChatGPT", "BLOCK", rc="pii", ents=PHONE, eid="v-pii"),
            ev("2026-09-29 16:10:00", U, "ChatGPT", "BLOCK", rc="doc_excerpt", docs=DOC, eid="v-doc")]
    evs, _ = ag.prepare_events(rows, T0, T1)
    ag.attach_decisions(evs, {})
    cats = {e["id"]: e["cat"] for e in evs}
    assert cats == {"o-doc": "other", "o-pii": "other", "v-pii": "pii", "v-doc": "doc"}
    c = ag.metrics(evs, date(2026, 9, 15), date(2026, 10, 2))["cards"]
    assert (c["block"], c["secret"], c["secret_doc"], c["pii_block"], c["rest"]) == (4, 1, 1, 1, 2)


def test_rest_blocks_stay_out_of_detected_frame():
    """'그 밖' 차단은 탐지(기밀·개인정보) 묶음에 들지 않는다."""
    rows = [ev("2026-09-29 15:27:00", U, "ChatGPT", "BLOCK", "file", rc="doc_excerpt"),
            ev("2026-09-29 15:33:00", U, "ChatGPT", "BLOCK", "file", rc="pii")]
    evs, _ = ag.prepare_events(rows, T0, T1)
    assert all(e["cat"] not in fr.DETECTED_CATS for e in evs)


def test_collect_counts_only_findings():
    rows = [ev("2026-09-29 15:27:00", U, "ChatGPT", "BLOCK", "file", rc="doc_excerpt"),
            ev("2026-09-29 15:33:00", U, "ChatGPT", "BLOCK", "file", rc="pii"),
            _sig_zero("2026-09-29 15:40:00"),
            ev("2026-09-29 16:00:00", U, "ChatGPT", "BLOCK", rc="pii", ents=PHONE),
            ev("2026-09-16 10:00:00", U, "ChatGPT", "ALLOW")]
    a = ag.collect(FakeConn(rows, []), date(2026, 9, 22), date(2026, 10, 2))
    c = a["cur"]["cards"]
    assert (c["block"], c["pii_block"], c["secret"], c["rest"]) == (4, 1, 0, 3)
