"""내용 경향(설계 v2 4.6-e) - 재가림·400자, 표본 고르기(비례·결정적), 범주 집계, 전역 스위치. 값은 전부 가짜."""

from collections import Counter
from datetime import date

import pytest

from reporting import aggregate as ag
from reporting import content as ct

from synth import FakeConn, dec, ev


def test_remask_rules():
    rows = [
        {"text": "두번째 셀 [EMAIL_ADDRESS]", "order": 2, "findings": []},
        {"text": "첫 셀 고객 010-****-5678 연락, 메일 kim.a@corp.example.co.kr, 주소 https://x.example.com/a?b=1",
         "order": 1, "findings": [{"t": "KR_PHONE_NUMBER", "r": "010-****-5678"}]},
        {"text": "토큰 ghp_ABCDEFGHIJKLMNOPQRSTUVWX 와 사이트 corp-intra.kr 2026년 10월 12일", "order": 3, "findings": []},
    ]
    t = ct.remask(rows)
    assert t.startswith("첫 셀 고객 [KR_PHONE_NUMBER] 연락") and " / 두번째 셀 [EMAIL_ADDRESS] / 토큰" in t
    assert "[주소]" in t and "kim.a" not in t and "https" not in t and "corp-intra.kr" not in t
    assert "[값]" in t and "ghp_" not in t
    assert not any(ch.isdigit() for ch in t) and "####년 ##월 ##일" in t


def test_remask_truncates_at_word_boundary():
    t = ct.remask([{"text": ("가나다 " * 200).strip(), "order": 0, "findings": []}])
    assert len(t) <= ct.TEXT_LIMIT and t.endswith("가나다")


def _pool(n_by_group):
    out = []
    for (client, svc, ctt), n in n_by_group.items():
        for k in range(n):
            out.append({"id": f"{client}-{svc}-{ctt}-{k}", "client": client, "svc": svc, "ct": ctt})
    return out


def test_select_sample_proportional_and_deterministic():
    pool = _pool({("u1", "ChatGPT", "file"): 50, ("u2", "Claude", "prompt"): 30, ("x", "Gemini", "prompt"): 20})
    s1 = ct.select_sample(pool)
    s2 = ct.select_sample(list(reversed(pool)))
    assert [e["id"] for e in s1] == [e["id"] for e in s2]          # 다시 만들어도 같은 표본
    assert len(s1) == 60
    assert Counter(e["client"] for e in s1) == {"u1": 30, "u2": 18, "x": 12}
    small = _pool({("u1", "ChatGPT", "file"): 7})
    assert sorted(e["id"] for e in ct.select_sample(small)) == sorted(e["id"] for e in small)


def test_select_sample_largest_remainder():
    pool = _pool({("a", "s", "p"): 1, ("b", "s", "p"): 1, ("c", "s", "p"): 1, ("d", "s", "p"): 1})
    assert len(ct.select_sample(pool, limit=3)) == 3


def test_fix_sub_and_tally_without_user_split():
    assert ct.fix_sub("CS", "HR_PAY") == "CS_OTHER" and ct.fix_sub("ETC", "CS_LIST") == "ETC_UNKNOWN"
    assert ct.fix_sub("HR", "HR_PAY") == "HR_PAY"
    classified = [{"cat": "CS", "sub": "CS_LIST", "task": "FORMAT"}] * 3 + [{"cat": "CS", "sub": "CS_REPLY", "task": "WRITE"}]
    events = [{"action": "BLOCK", "cat": "doc", "docs": ("01_전략",)}, {"action": "BLOCK", "cat": "doc", "docs": ("09_미분류",)}]
    rows = ct.tally(classified, {"01_전략": "PLAN"}, events)
    assert [(r["cat"], r["mask"], r["secret"]) for r in rows] == [("CS", 4, 0), ("PLAN", 0, 1)]
    assert rows[0]["top_subs"] == [("고객 명단·연락처", 3), ("문의 답변 작성", 1)]
    assert rows[0]["top_task"] == [("정리·표 변환", 3)]
    assert "client" not in str(rows)


@pytest.mark.parametrize("env, on", [({}, False), ({"REPORT_CONTENT_TREND": "on"}, True),
                                     ({"REPORT_CONTENT_TREND": "off"}, False), ({"REPORT_CONTENT_TENDENCY": "on"}, True),
                                     ({"REPORT_CONTENT_TREND": "true"}, True)])
def test_global_switch_defaults_off(monkeypatch, env, on):
    monkeypatch.delenv("REPORT_CONTENT_TREND", raising=False)
    monkeypatch.delenv("REPORT_CONTENT_TENDENCY", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert ct.global_enabled() is on


def test_build_items_reads_only_masked_rows_of_mask_events():
    m1 = ev("2026-10-10 10:00:00", "chrome-1", "ChatGPT", "MASK", "file", ents={"KR_RRN": 1})
    m2 = ev("2026-10-10 10:05:00", "chrome-1", "ChatGPT", "MASK", "prompt", ents={"KR_RRN": 1})   # 가린 글 없음
    b1 = ev("2026-10-10 10:10:00", "chrome-1", "ChatGPT", "BLOCK", docs=["01_전략"])
    decs = [dec(m1["root"], m1["occurred_at"], ct_="file", filename="급여_대장.xlsx", masked="이름 [KR_RRN] 급여 300", order=1, suffix="#f:0"),
            dec(m1["root"], m1["occurred_at"], ct_="file", filename="급여_대장.xlsx", masked="부서 인사팀", order=0, suffix="#f:1"),
            dec(m1["root"], m1["occurred_at"], ct_="file", filename="급여_대장.xlsx", masked="재검사", order=2, suffix="#verify"),
            dec(b1["root"], b1["occurred_at"], doc="01_전략", match_rate=1.0)]
    conn = FakeConn([m1, m2, b1], decs)
    t0, t1 = ag.kst_bounds(date(2026, 10, 10), date(2026, 10, 11))
    evs, _ = ag.prepare_events(conn.events, t0, t1)
    info = ct.build_items(conn, evs, t0, t1)
    assert info["pool"] == 1 and info["mask_events"] == 2
    [item] = info["items"]
    assert item == {"i": "C01", "path": "파일", "fmt": "XLSX", "text": "부서 인사팀 / 이름 [KR_RRN] 급여 ###", "_ev": item["_ev"]}
    assert "급여_대장" not in str({k: v for k, v in item.items() if k != "_ev"})          # 파일 이름은 안 넘김
    assert ct.batch_hash(ct.batches(info["items"])[0]) == ct.batch_hash(ct.batches(info["items"])[0])
