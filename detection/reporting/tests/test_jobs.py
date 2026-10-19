"""보고서 작업 관리 + API. 실제 생성기 대신 가짜 `reporting` 패키지를 자식 프로세스로 띄운다(DB·GPU 없이)."""

from __future__ import annotations

import time
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reporting.jobs import ReportError, ReportJobs, validate_period

FAKE_MAIN = '''
import argparse, json, sys, time
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--from", dest="start"); p.add_argument("--to", dest="end"); p.add_argument("--out")
p.add_argument("--env-file"); p.add_argument("--no-llm", action="store_true")
p.add_argument("--content-trend", dest="ct", action="store_true", default=None)
p.add_argument("--no-content-trend", dest="ct", action="store_false")
p.add_argument("--blind", action="store_true")
a = p.parse_args()
mode = Path(a.env_file).read_text().strip()
out = Path(a.out)
if mode == "slow":
    out.with_suffix(".progress").write_text(json.dumps({"stage": "llm", "llm_done": 5, "llm_total": 15}))
    time.sleep(1.5)
if mode == "fail":
    print("psycopg.OperationalError: connection refused", file=sys.stderr)
    sys.exit(1)
out.write_text("<title>r</title><p>ok</p>", encoding="utf-8")
out.with_suffix(".json").write_text(json.dumps({"from": a.start, "to": a.end, "use_llm": not a.no_llm,
    "generated_at": "2026-10-01T00:00:00+00:00", "rows": 7, "items": 5, "llm_used": not a.no_llm, "llm_error": None,
    "llm_ms": 10, "agg_ms": 5, "kept": 3, "dropped": [{"x": 1}], "compare_from": "2026-09-01", "compare_to": "2026-09-14",
    "content_trend": {"requested": a.ct, "effective": bool(a.ct), "state": "on" if a.ct else "off", "note": None},
    "incidents": {"total": 4, "narrated": 2}, "users_high": 1, "blind": {"A": "llm", "B": "sql"} if a.blind else None,
    "argv": sys.argv[1:]}), encoding="utf-8")
'''


@pytest.fixture
def fake(tmp_path):
    pkg = tmp_path / "src" / "reporting"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(FAKE_MAIN)
    env = tmp_path / "pg.env"
    env.write_text("ok")
    return tmp_path, env


def _wait(jobs, rid, timeout=10):
    t = time.time()
    while time.time() - t < timeout:
        st = jobs.status(rid)
        if st["status"] != "running":
            return st
        time.sleep(0.05)
    raise AssertionError("timeout")


def test_period_validation():
    validate_period(date(2026, 9, 1), date(2026, 9, 1), today=date(2026, 10, 1))
    for s, e, code in [(date(2026, 9, 2), date(2026, 9, 1), "INVALID_PERIOD"),
                       (date(2025, 1, 1), date(2026, 9, 1), "PERIOD_TOO_LONG"),
                       (date(2026, 10, 5), date(2026, 10, 6), "INVALID_PERIOD")]:
        with pytest.raises(ReportError) as e_:
            validate_period(s, e, today=date(2026, 10, 1))
        assert e_.value.code == code


def test_done_flow_passes_exclusive_end_and_reports_inclusive(fake):
    root, env = fake
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    st = jobs.start(date(2026, 9, 15), date(2026, 10, 1))
    st = _wait(jobs, st["report_id"])
    assert st["status"] == "done"
    assert st["from"] == "2026-09-15" and st["to"] == "2026-10-01"      # 자식에는 10-02(배타)로 넘겼다
    assert st["llm_used"] is True and st["lines_dropped"] == 1
    assert jobs.file(st["report_id"]).read_text(encoding="utf-8").startswith("<title>")
    assert not (root / "out" / f"{st['report_id']}.err").exists()
    assert [r["report_id"] for r in jobs.list()] == [st["report_id"]]


def test_busy_while_running(fake):
    root, env = fake
    env.write_text("slow")
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    st = jobs.start(date(2026, 9, 1), date(2026, 9, 2))
    assert st["status"] == "running"
    with pytest.raises(ReportError) as e:
        jobs.start(date(2026, 9, 1), date(2026, 9, 2))
    assert e.value.status_code == 409
    with pytest.raises(ReportError) as e:
        jobs.file(st["report_id"])
    assert e.value.code == "NOT_READY"
    assert _wait(jobs, st["report_id"])["status"] == "done"


def test_failure_reports_last_stderr_line(fake):
    root, env = fake
    env.write_text("fail")
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    st = _wait(jobs, jobs.start(date(2026, 9, 1), date(2026, 9, 2))["report_id"])
    assert st == {"report_id": st["report_id"], "status": "failed",
                  "error": "psycopg.OperationalError: connection refused"}


def test_unknown_or_malicious_id_is_404(fake):
    root, env = fake
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    for rid in ["../../etc/passwd", "report_2026-09-01_2026-09-02_20261001T000000"]:
        with pytest.raises(ReportError) as e:
            jobs.status(rid)
        assert e.value.status_code == 404


def test_missing_env_file_is_503(tmp_path):
    jobs = ReportJobs(tmp_path / "out", str(tmp_path / "nope.env"))
    with pytest.raises(ReportError) as e:
        jobs.start(date(2026, 9, 1), date(2026, 9, 2))
    assert e.value.status_code == 503


def test_api_roundtrip(fake, monkeypatch):
    root, env = fake
    import fakeredis
    from detection_service import main

    monkeypatch.setattr(main, "connect_redis", lambda: fakeredis.FakeRedis(decode_responses=True))
    monkeypatch.setenv("REPORT_OUT_DIR", str(root / "out"))
    monkeypatch.setenv("REPORT_ENV_FILE", str(env))
    with TestClient(main.app) as client:
        main.app.state.reports.cwd = root / "src"
        main.app.state.reports.nice = False
        bad = client.post("/admin/reports", json={"from": "2026-09-10", "to": "2026-09-01"})
        assert bad.status_code == 400 and bad.json()["detail"]["code"] == "INVALID_PERIOD"
        r = client.post("/admin/reports", json={"from": "2026-09-15", "to": "2026-10-01", "use_llm": False})
        assert r.status_code == 202
        rid = r.json()["report_id"]
        st = _wait(main.app.state.reports, rid)
        assert st["status"] == "done" and st["llm_used"] is False
        assert client.get(f"/admin/reports/{rid}").json()["status"] == "done"
        f = client.get(f"/admin/reports/{rid}/file")
        assert f.status_code == 200 and f.headers["content-type"].startswith("text/html")
        assert f.headers["content-disposition"].startswith("inline")          # 대시보드 iframe에 바로 보인다
        d = client.get(f"/admin/reports/{rid}/file?download=1")
        assert d.headers["content-disposition"].startswith("attachment")
        assert client.get("/admin/reports").json()["reports"][0]["report_id"] == rid
        assert client.get("/admin/reports/nope").status_code == 404


# ---------------------------------------------------------------- 2026-10-12 설계 v2: 내용 경향·블라인드·상태 필드

def _argv(jobs, rid):
    import json as _json
    return _json.loads((jobs.out_dir / f"{rid}.json").read_text(encoding="utf-8"))["argv"]


@pytest.mark.parametrize("glob, use_llm, requested, flag", [
    ("on", True, None, "--content-trend"), ("on", True, True, "--content-trend"), ("on", True, False, "--no-content-trend"),
    ("off", True, True, "--no-content-trend"), ("", True, None, "--no-content-trend"), ("on", False, True, "--no-content-trend")])
def test_content_trend_flag_follows_global_switch(fake, monkeypatch, glob, use_llm, requested, flag):
    root, env = fake
    monkeypatch.setenv("REPORT_CONTENT_TREND", glob)
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    st = _wait(jobs, jobs.start(date(2026, 9, 1), date(2026, 9, 2), use_llm, content_trend=requested)["report_id"])
    assert flag in _argv(jobs, st["report_id"]) and "--blind" not in _argv(jobs, st["report_id"])
    assert st["content_trend"] is (flag == "--content-trend")


def test_blind_pair_and_new_status_fields(fake, monkeypatch):
    root, env = fake
    monkeypatch.setenv("REPORT_CONTENT_TREND", "on")
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    st = _wait(jobs, jobs.start(date(2026, 9, 15), date(2026, 9, 28), blind_pair=True)["report_id"])
    assert "--blind" in _argv(jobs, st["report_id"])
    assert (st["items"], st["compare_from"], st["compare_to"]) == (5, "2026-09-01", "2026-09-14")
    assert (st["llm_lines"], st["llm_dropped"], st["users_high"], st["blind"]) == (3, 1, 1, True)
    assert st["incidents"] == {"total": 4, "narrated": 2} and st["content_trend"] is True


def test_running_status_shows_llm_progress(fake):
    root, env = fake
    env.write_text("slow")
    jobs = ReportJobs(root / "out", str(env), cwd=root / "src", nice=False)
    rid = jobs.start(date(2026, 9, 1), date(2026, 9, 2))["report_id"]
    for _ in range(100):
        st = jobs.status(rid)
        if st.get("llm_progress"):
            break
        time.sleep(0.02)
    assert st["status"] == "running" and st["stage"] == "llm" and st["llm_progress"] == "5/15"
    _wait(jobs, rid)


def test_old_report_json_still_listed(fake):
    """10/1~10/11에 만든 옛 생성 기록(raw 키, 새 필드 없음)도 목록에 그대로 나온다."""
    import json as _json
    root, env = fake
    out = root / "out"
    out.mkdir()
    rid = "report_2026-10-01_2026-10-07_20261007T111446"
    (out / f"{rid}.html").write_text("<p>old</p>", encoding="utf-8")
    (out / f"{rid}.json").write_text(_json.dumps({"from": "2026-10-01", "to": "2026-10-08", "use_llm": True, "rows": 12364,
                                                  "raw": {"summary": []}, "kept": 4, "dropped": []}), encoding="utf-8")
    st = ReportJobs(out, str(env)).status(rid)
    assert st["status"] == "done" and st["llm_used"] is True and st["items"] is None and st["to"] == "2026-10-07"


def test_api_validates_new_options_and_lists_switch(fake, monkeypatch):
    root, env = fake
    import fakeredis
    from detection_service import main

    monkeypatch.setattr(main, "connect_redis", lambda: fakeredis.FakeRedis(decode_responses=True))
    monkeypatch.setenv("REPORT_OUT_DIR", str(root / "out"))
    monkeypatch.setenv("REPORT_ENV_FILE", str(env))
    monkeypatch.setenv("REPORT_CONTENT_TREND", "off")
    with TestClient(main.app) as client:
        main.app.state.reports.cwd = root / "src"
        main.app.state.reports.nice = False
        for bad in ({"content_trend": "yes"}, {"content_trend": 1}, {"blind_pair": "true"}, {"blind_pair": None}):
            r = client.post("/admin/reports", json={"from": "2026-09-01", "to": "2026-09-02", **bad})
            assert r.status_code == 422, bad
        r = client.post("/admin/reports", json={"from": "2026-09-01", "to": "2026-09-02", "content_trend": True})
        assert r.status_code == 202
        st = _wait(main.app.state.reports, r.json()["report_id"])
        assert st["content_trend"] is False                         # 전역 꺼짐이면 켬을 보내도 끔
        assert "--no-content-trend" in _argv(main.app.state.reports, st["report_id"])
        lst = client.get("/admin/reports").json()
        assert lst["content_trend_enabled"] is False and lst["reports"][0]["report_id"] == st["report_id"]
        monkeypatch.setenv("REPORT_CONTENT_TREND", "on")
        assert client.get("/admin/reports").json()["content_trend_enabled"] is True
