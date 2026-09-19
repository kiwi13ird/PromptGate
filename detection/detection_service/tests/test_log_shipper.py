"""전송 서비스 - 로그 파일의 모든 판정이 DB에 정확히 한 번씩 들어가는지. 가짜 DB(decision_id 딕셔너리)로 확인한다.

실제 RDS 대상 시험은 서버에서 따로 한다(verify/log_shipper_rds_check.py).
"""

from __future__ import annotations

import json
import random
import uuid
from pathlib import Path

import pytest

from detection_service import log_check
from detection_service.decision_log import DecisionLog, rotated_path
from detection_service.log_shipper import Offset, Shipper, offset_path, rejected_path, status_path


class DbDown(Exception):
    sqlstate = "08006"  # 연결 끊김


class CheckViolation(Exception):
    sqlstate = "23514"


class FakeDb:
    """decision_id 기본키 + ON CONFLICT DO NOTHING + 트랜잭션(전부 아니면 전무)."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.down = False
        self.crash_after_commit = False
        self.bad_ids: set[str] = set()
        self.calls = 0

    def insert_many(self, records):
        self.calls += 1
        if self.down:
            raise DbDown("connection refused")
        if any(r["decision_id"] in self.bad_ids for r in records):
            raise CheckViolation("violates check constraint")
        for r in records:
            self.rows.setdefault(r["decision_id"], r)
        if self.crash_after_commit:
            self.crash_after_commit = False
            raise DbDown("connection lost after commit")  # 커밋은 됐는데 응답을 못 받은 경우
        return len(records)


def _rec(i: int, **kw) -> dict:
    return {"decision_id": str(uuid.uuid4()), "request_id": f"r{i}", "ts": 1789400000.0 + i, "service": None,
            "format": None, "text_chars": 3, "blocked": False, "decided_by": "none", "reason": "매치 없음",
            "hash_status": "ok", "signature_status": "ok", "total_ms": 0.1, "prompt": f"입력 {i}", **kw}


def _drain(shipper: Shipper, limit: int = 10_000) -> None:
    for _ in range(limit):
        if not shipper.ship_once():
            return
    raise AssertionError("did not settle")


def _all_ids(log: DecisionLog) -> list[str]:
    ids = []
    for p in [log.path] + [rotated_path(log.path, i) for i in range(1, log.backups + 1)]:
        if p.exists():
            ids += [json.loads(x)["decision_id"] for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
    return ids


@pytest.fixture()
def env(tmp_path: Path):
    log = DecisionLog(tmp_path / "decisions.jsonl", max_bytes=10_000_000, backups=9)
    db = FakeDb()
    shipper = Shipper(log.path, db, batch_lines=7)
    shipper.init_offset(start_at_end=False)
    return log, db, shipper


def test_ships_every_line_once(env):
    log, db, shipper = env
    recs = [_rec(i) for i in range(100)]
    for r in recs:
        log.write(r)
    _drain(shipper)
    assert set(db.rows) == {r["decision_id"] for r in recs} and len(db.rows) == 100
    assert shipper.status["shipped_total"] == 100 and shipper.status["pending_bytes"] == 0


def test_db_down_keeps_offset_then_catches_up(env):
    log, db, shipper = env
    for i in range(20):
        log.write(_rec(i))
    db.down = True
    for _ in range(5):
        with pytest.raises(DbDown):
            shipper.ship_once()
    assert shipper.load_offset().pos == 0 and db.rows == {}
    for i in range(20, 30):  # 장애 중에도 기록은 계속된다
        log.write(_rec(i))
    db.down = False
    _drain(shipper)
    assert len(db.rows) == 30


def test_crash_after_commit_resends_without_duplicates(env):
    log, db, shipper = env
    for i in range(30):
        log.write(_rec(i))
    shipper.ship_once()
    db.crash_after_commit = True
    with pytest.raises(DbDown):
        shipper.ship_once()  # 7줄은 DB에 들어갔지만 위치는 안 옮겨졌다
    # 서비스 재시작 = 새 Shipper가 파일에서 위치를 읽는다
    restarted = Shipper(log.path, db, batch_lines=7)
    _drain(restarted)
    assert len(db.rows) == 30 and sorted(db.rows) == sorted(_all_ids(log))


def test_partial_last_line_waits_until_complete(env):
    log, db, shipper = env
    log.write(_rec(0))
    half = json.dumps(_rec(1), ensure_ascii=False).encode("utf-8")
    with log.path.open("ab") as f:
        f.write(half[:40])  # 쓰는 중인 줄
    _drain(shipper)
    assert len(db.rows) == 1
    with log.path.open("ab") as f:
        f.write(half[40:] + b"\n")
    _drain(shipper)
    assert len(db.rows) == 2


def test_follows_rotation_without_loss(tmp_path: Path):
    log = DecisionLog(tmp_path / "decisions.jsonl", max_bytes=2_000, backups=1000)
    db = FakeDb()
    shipper = Shipper(log.path, db, batch_lines=5, backups=1000)
    shipper.init_offset(start_at_end=False)
    rng = random.Random(7)
    written = []
    for i in range(600):
        r = _rec(i, prompt="가" * rng.randint(1, 200))
        assert log.write(r)
        written.append(r["decision_id"])
        if rng.random() < 0.3:  # 쓰기와 전송이 섞여 진행 - 전송이 뒤처진 채로 회전이 계속 일어난다
            shipper.ship_once()
    _drain(shipper)
    assert len(list(tmp_path.glob("decisions.jsonl.*"))) > 50  # 회전이 여러 번 일어났다
    assert set(db.rows) == set(written) and len(db.rows) == 600 and shipper.status["lost_files_total"] == 0


def test_rotation_while_db_down_then_recover(tmp_path: Path):
    log = DecisionLog(tmp_path / "decisions.jsonl", max_bytes=1_500, backups=1000)
    db = FakeDb()
    shipper = Shipper(log.path, db, batch_lines=50, backups=1000)
    shipper.init_offset(start_at_end=False)
    for i in range(10):
        log.write(_rec(i))
    shipper.ship_once()
    db.down = True
    for i in range(10, 300):  # 장애 중 파일이 여러 번 회전
        log.write(_rec(i))
        try:
            shipper.ship_once()
        except DbDown:
            pass
    db.down = False
    _drain(shipper)
    assert len(list(tmp_path.glob("decisions.jsonl.*"))) > 50
    assert len(db.rows) == 300 and set(db.rows) == set(_all_ids(log)) and shipper.status["lost_files_total"] == 0


def test_rotated_past_backups_is_reported(tmp_path: Path):
    log = DecisionLog(tmp_path / "decisions.jsonl", max_bytes=500, backups=2)
    db = FakeDb()
    shipper = Shipper(log.path, db, batch_lines=50, backups=2)
    shipper.init_offset(start_at_end=False)
    log.write(_rec(0))
    shipper.ship_once()  # 첫 파일을 추적 중
    db.down = True
    for i in range(1, 60):  # 장애가 길어 추적하던 파일이 백업 수(2)를 넘겨 지워진다
        log.write(_rec(i))
    db.down = False
    _drain(shipper)
    assert shipper.status["lost_files_total"] >= 1  # 조용히 지나가지 않는다
    assert set(_all_ids(log)) <= set(db.rows)  # 남아 있는 파일(.2 .1 지금)은 모두 들어갔다


def test_data_error_isolates_bad_row(env):
    log, db, shipper = env
    recs = [_rec(i) for i in range(10)]
    db.bad_ids = {recs[3]["decision_id"]}
    for r in recs:
        log.write(r)
    _drain(shipper)
    assert len(db.rows) == 9 and recs[3]["decision_id"] not in db.rows
    (rej,) = rejected_path(log.path).read_text(encoding="utf-8").splitlines()
    assert json.loads(json.loads(rej)["line"])["decision_id"] == recs[3]["decision_id"]
    assert shipper.status["rejected_total"] == 1


def test_bad_and_legacy_lines_are_skipped_and_counted(env):
    log, db, shipper = env
    with log.path.open("ab") as f:
        f.write(b'{"request_id": "old", "blocked": false}\n')  # 옛 형식(decision_id 없음)
        f.write(b"not json\n")
    log.write(_rec(1))
    _drain(shipper)
    assert len(db.rows) == 1
    assert shipper.status["legacy_lines_total"] == 1 and shipper.status["bad_lines_total"] == 1


def test_start_at_end_skips_existing_lines(tmp_path: Path):
    log = DecisionLog(tmp_path / "decisions.jsonl")
    for i in range(5):
        log.write(_rec(i))
    db = FakeDb()
    shipper = Shipper(log.path, db)
    shipper.init_offset(start_at_end=True)
    new = _rec(99)
    log.write(new)
    _drain(shipper)
    assert list(db.rows) == [new["decision_id"]]


def test_long_line_over_read_limit(env):
    log, db, _ = env
    shipper = Shipper(log.path, db, max_read_bytes=64)
    big = _rec(0, prompt="긴" * 5000)
    log.write(big)
    log.write(_rec(1))
    _drain(shipper)
    assert len(db.rows) == 2 and db.rows[big["decision_id"]]["prompt"] == "긴" * 5000


def test_status_file_written(env):
    log, db, shipper = env
    log.write(_rec(0))
    _drain(shipper)
    shipper.write_status()
    st = json.loads(status_path(log.path).read_text(encoding="utf-8"))
    assert st["shipped_total"] == 1 and st["pending_bytes"] == 0


def test_log_check_scan_splits_shipped_and_pending(env):
    log, db, shipper = env
    for i in range(10):
        log.write(_rec(i))
    shipper.batch_lines = 4
    shipper.ship_once()
    s = log_check.scan(log.path, shipper.load_offset())
    assert len(s["shipped"]) == 4 and len(s["pending"]) == 6 and s["duplicates"] == 0
    assert set(s["shipped"]) == set(db.rows)
    assert offset_path(log.path).exists() and isinstance(shipper.load_offset(), Offset)


def test_status_totals_survive_restart(env):
    log, db, shipper = env
    for i in range(3):
        log.write(_rec(i))
    _drain(shipper)
    shipper.write_status()
    restarted = Shipper(log.path, db)
    assert restarted.status["shipped_total"] == 3 and restarted.status["last_ok_ts"] == shipper.status["last_ok_ts"]
