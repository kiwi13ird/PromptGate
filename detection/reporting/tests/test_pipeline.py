"""보고서 전체 흐름 - 합성 DB(FakeConn) + 가짜 LLM 서버. 운영 RDS·GPU 없이 python -m reporting을 끝까지 돌린다.

시험 7(유출, 로컬 부분): 합성 표본에 심은 고유 문자열(카나리아)이 보고서 HTML·JSON에 없고, LLM에는 표본 분류 호출에만 간다.
시험 9(대체 문장): 호출 하나 JSON 깨짐·시간 초과 → 그 섹션만 집계 문장. GPU 없음 → 전부 집계 문장, 생성은 성공.
시험 10(같은 입력 2회): 표본·출력 같음. 블라인드 비교판(LLM·집계, 출처 표시 숨김).
"""

from __future__ import annotations

import json
import re
import sys
import types
from datetime import timedelta

import pytest

from reporting import llm
from reporting import __main__ as M

from fake_llm import FakeLLM
from render_markers import assert_no_provenance
from synth import FakeConn, dec, ev, incident_fixture, kst

CANARY = "카나리아참새부엉이"


def make_conn() -> FakeConn:
    rows, decs = incident_fixture()
    rows.append(ev("2026-09-19 00:00:00", "chrome-zz", "ChatGPT", "BLOCK", docs=["01_전략_보고서"], eid="old"))
    by = {r["event_id"]: r for r in rows}
    masked = {
        "a3": (f"고객 {CANARY} 님께 [KR_PHONE_NUMBER]로 연락 010-****-5678 hong@corp.example.com",
               [{"entity_type": "KR_PHONE_NUMBER", "replacement": "010-****-5678", "start": 0, "end": 1, "policy_action": "MASK"}]),
        "b1": ("급여 명세 정리 [EMAIL_ADDRESS] 기준 2026년 10월", []),
        "b2": ("급여 명세 표 변환 [EMAIL_ADDRESS]", []),
        "b3": ("토큰 [GITHUB_TOKEN] 설정 오류 로그 분석", []),
        "x2": (f"계약서 검토 요청 [KR_PHONE_NUMBER] {CANARY}", []),
    }
    svc = {"a3": "ChatGPT", "b1": "Claude", "b2": "Claude", "b3": "Claude", "x2": "Gemini"}
    for eid, (text, fs) in masked.items():
        e = by[eid]
        decs.append(dec(e["root"], e["occurred_at"], service=svc[eid], masked=text, findings=fs, order=0))
    docs = [{"doc_id": d, "format": "docx", "status": "active", "index_status": "indexed", "classification": None,
             "registered_at": kst("2026-09-01 00:00:00")} for d in ("01_전략_보고서", "02_채용_평가서", "03_협상_전략", "04_급여대장")]
    return FakeConn(rows, decs, docs, aliases={"chrome-aaaa-0001": "영업지원-1"})


def run(tmp_path, monkeypatch, url, *args, env=None, name="report_x"):
    conn = make_conn()
    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(connect=lambda dsn, autocommit=False: conn))
    monkeypatch.setenv("DETECTION_PG_DSN", "postgresql://fake")
    monkeypatch.setenv("REPORT_CONTENT_TREND", (env or {}).get("REPORT_CONTENT_TREND", "on"))
    monkeypatch.setattr(llm, "LLM_URL", url)
    out = tmp_path / f"{name}.html"
    rc = M.main(["--from", "2026-10-01", "--to", "2026-10-13", "--out", str(out), "--no-local-api", *args])
    html = out.read_text(encoding="utf-8") if out.exists() else None
    log = json.loads(out.with_suffix(".json").read_text(encoding="utf-8")) if out.with_suffix(".json").exists() else None
    return rc, html, log, conn


def _visible(html: str) -> str:
    """본문만 - <style> 안의 글(클래스 이름 등)은 빼고 문장만 본다."""
    return re.sub(r"<style>.*?</style>", "", html, flags=re.S)


def test_good_llm_all_sections_and_leak_canary(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, html, log, conn = run(tmp_path, monkeypatch, fake.url)
    assert rc == 0 and log["llm_used"] and log["mode"] == "llm", log["fallback_sections"]
    assert log["dropped"] == []
    assert_no_provenance(html)
    assert sorted(fake.tasks()) == sorted(["rank", "commentary", "users", "doccat", "classify", "narrate", "narrate",
                                           "narrate", "commentary", "recs"])
    assert all(r["temperature"] == 0 and r["seed"] == 0 and r["thinking"] == {"enable_thinking": False} for r in fake.requests)
    assert all("report_" in r["system"] or "[작업" in r["system"] for r in fake.requests)
    # 자리표시는 모두 렌더됨, 렌더 결과 예
    assert "{F_" not in html and "{U" not in html and "{I" not in html
    assert "기밀 차단 11건 늘어남(1→12)" in html
    assert "영업지원-1" in html                                   # 별칭은 렌더에만
    assert all("영업지원" not in r["body"] and "chrome-aaaa" not in r["body"] for r in fake.requests)
    # 내용 경향: 범주별 건수만, 사용자별 없음
    rows = {r["cat"]: r for r in log["content"]["rows"]}
    assert rows["CS"]["mask"] == 1 and rows["HR"]["mask"] == 2 and rows["LEGAL"]["mask"] == 1 and rows["ETC"]["mask"] == 1
    assert rows["PLAN"]["secret"] == 8 and rows["HR"]["secret"] == 4
    assert log["content"]["sample"] == 5 and log["content"]["pool"] == 5
    assert all(set(c) == {"cat", "sub", "task"} for c in log["content"]["classified"])
    # 유출: 카나리아는 표본 분류 호출에만, 보고서·생성 기록에는 없음
    assert CANARY not in html and CANARY not in json.dumps(log, ensure_ascii=False)
    hit = {r["task"] for r in fake.requests if CANARY in r["body"]}
    assert hit == {"classify"}
    cls = next(r for r in fake.requests if r["task"] == "classify")
    assert "010-****-5678" not in cls["body"] and "hong@" not in cls["body"] and "2026" not in cls["body"]
    assert "[주소]" in cls["body"] and "[KR_PHONE_NUMBER]" in cls["body"]
    # 가린 글은 켰을 때만 읽음
    assert any("masked_text" in s for s in conn.sql)


def test_malicious_llm_output_is_dropped(tmp_path, monkeypatch):
    with FakeLLM("bad") as fake:
        rc, html, log, _ = run(tmp_path, monkeypatch, fake.url)
    assert rc == 0 and log["llm_used"]
    vis = _visible(html)
    assert_no_provenance(html)
    for banned in ("17건 늘어남", "대부분 정상", "유출됨", "의도적", "수정 후 재시도", "evil", "SQL 기록", "고의로", "F_LEAK"):
        assert banned not in vis, banned
    reasons = {d["why"].split(" ")[0] for d in log["dropped"]}
    assert {"1", "2", "4", "5", "6", "9", "11", "14", "15"} <= reasons, reasons
    assert any(d["why"] == "14 표본 글 겹침" for d in log["dropped"])            # 표본 글 인용 시도
    assert any(d["why"].startswith("16 ") for d in log["dropped"])               # 문서 대상 차단
    assert log["users_high"] == 3                                                 # 규칙 등급으로 되돌림
    assert set(log["fallback_sections"]) >= {"S1", "S2", "S3", "S4", "S5", "S7", "S9", "S10"}   # S8은 합성 자료에 변경이 없어 안 부름
    # 범주와 안 맞는 하위 유형은 그 범주 '기타', 없는 범주·없는 항목은 버림
    assert log["content"]["classified"] == [{"cat": "CS", "sub": "CS_OTHER", "task": "FORMAT"}] * 2
    assert CANARY not in html


def test_one_task_failing_only_replaces_that_section(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CALL_TIMEOUT", 1.0)
    with FakeLLM("good", fail={"commentary": "badjson", "narrate": "timeout"}) as fake:
        rc, html, log, _ = run(tmp_path, monkeypatch, fake.url)
    assert rc == 0 and log["llm_used"] and log["mode"] == "partial"
    assert {s: log["sources"][s] for s in ("S2", "S3", "S4", "S8", "S9")} == dict.fromkeys(("S2", "S3", "S4", "S8", "S9"), "sql")
    assert log["sources"]["summary"] == "llm" and log["sources"]["recs"] == "llm"
    errs = {c["name"]: c["status"] for c in log["calls"]}
    assert errs["commentary_a"] == "error" and errs["narrate_0"] == "error" and errs["users"] == "ok"
    # 일부 문장이 집계 문장으로 바뀌어도 보고서 HTML에는 표시하지 않는다. 기록은 생성 기록 JSON에만
    assert "일부 집계" not in html and "집계 문장" not in html
    assert set(log["fallback_sections"]) >= {"S2", "S3", "S4", "S5", "S9"}
    assert {s["src"] for s in log["provenance"]["sentences"] if s["sec"] == "S2"} == {"sql"}


def test_gpu_unreachable_falls_back_everywhere(tmp_path, monkeypatch):
    rc, html, log, conn = run(tmp_path, monkeypatch, "http://127.0.0.1:9/v1/chat/completions")
    assert rc == 0 and not log["llm_used"] and log["mode"] == "sql"
    assert log["content_trend"]["state"] == "failed" and log["content_trend"]["reason"] == "GPU 응답 없음"
    assert log["writer"] == "집계 문장 (LLM 호출 실패)"
    assert_no_provenance(html)
    assert "GPU" not in html and "LLM" not in html and "집계 문장" not in html     # 이유·작성 방식은 JSON에만
    assert "내용 경향 분류 안 함(분류 실패)" in html
    # 대체 요약 3줄: 기밀 차단 → 검사 없이 통과 → 이전 대비 차이가 가장 큰 카드(이름표 붙음)
    body = _visible(html)
    assert "기밀 차단 12건(이전 1건) · 문서 일치 12건 · 키워드 0건" in body
    assert "검사 없이 통과 2건(이전 0건)" in body and "검사 28건 늘어남(1→29)" in body


def test_global_off_never_reads_masked_text(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, html, log, conn = run(tmp_path, monkeypatch, fake.url, "--content-trend", env={"REPORT_CONTENT_TREND": "off"})
    assert rc == 0
    assert log["content_trend"] == {"requested": True, "effective": False, "state": "off_global", "note": "off(전역)"}
    assert not any("masked_text" in s for s in conn.sql)
    assert "classify" not in fake.tasks() and "doccat" not in fake.tasks()
    assert "내용 경향 꺼짐(관리자 설정)" in html


def test_per_report_off_and_no_llm(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, html, log, conn = run(tmp_path, monkeypatch, fake.url, "--no-content-trend")
        assert log["content_trend"]["state"] == "off" and not any("masked_text" in s for s in conn.sql)
        rc, html, log, conn = run(tmp_path, monkeypatch, fake.url, "--no-llm", name="report_y")
        assert log["mode"] == "sql" and log["content_trend"]["state"] == "no_llm"
        assert [t for t in fake.tasks() if t == "classify"] == []


def test_blind_pair_hides_provenance(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, html, log, _ = run(tmp_path, monkeypatch, fake.url, "--blind")
    assert set(log["blind"].values()) == {"llm", "sql"}
    pair = {}
    for label in ("A", "B"):
        h = (tmp_path / f"report_x.blind-{label}.html").read_text(encoding="utf-8")
        body = _visible(h)
        assert_no_provenance(h)
        pair[log["blind"][label]] = body
    assert pair["llm"] != pair["sql"]
    assert "기밀 차단 11건 늘어남(1→12)" in pair["llm"]


def test_same_input_twice_same_output(tmp_path, monkeypatch):
    outs = []
    for n in range(2):
        with FakeLLM("good") as fake:
            rc, html, log, _ = run(tmp_path, monkeypatch, fake.url, name=f"report_{n}")
        outs.append((re.sub(r"생성 \d{4}-\d{2}-\d{2} \d{2}:\d{2}", "", html), log["content"]["batch_hashes"],
                     log["content"]["classified"]))
    assert outs[0] == outs[1]


def test_sum_mismatch_fails_without_file(tmp_path, monkeypatch):
    from reporting import aggregate as ag
    monkeypatch.setitem(ag.CARD_FILTERS, "mask", lambda e: e["action"] in ("MASK", "ALLOW"))
    rc, html, log, _ = run(tmp_path, monkeypatch, "http://127.0.0.1:9/v1/chat/completions")
    assert rc == 2 and html is None and log is None
