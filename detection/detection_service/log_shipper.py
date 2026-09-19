"""판정 로그 전송 서비스 - decisions.jsonl을 RDS `decisions`로 옮긴다 (detection-logshipper.service).

탐지 API는 로그 파일에만 쓰고, 이 서비스가 따로 돌며 파일을 RDS로 복사한다. 파일이 원본이고 DB는 사본이다.

동작 (한 차례 = ship_once):
  1. 진행 위치 파일(shipper.offset: {"ino": 파일 식별자, "pos": 보낸 바이트})을 읽는다.
  2. 그 식별자의 파일을 찾는다 - 지금 파일이거나, 회전돼 이름이 바뀐 decisions.jsonl.1 … .N.
  3. pos부터 읽어 줄바꿈으로 끝난 줄만 최대 BATCH_LINES줄 모은다(쓰는 중인 마지막 줄은 다음 차례).
  4. 한 트랜잭션으로 INSERT … ON CONFLICT (decision_id) DO NOTHING.
  5. **커밋에 성공한 뒤에만** 위치를 옮겨 저장한다(임시 파일 + 원자적 교체).
  실패하면 위치를 그대로 두고 1→2→4…30초 간격으로 다시 시도한다. 도중에 죽어도 같은 줄을 다시 보내고,
  decision_id가 같아 DB 행은 늘지 않는다.

회전: 위치가 가리키는 파일이 회전된 파일이면 끝까지 보낸 뒤 한 단계 새 파일(.k-1, 마지막은 지금 파일) 처음으로 넘어간다.
데이터 오류(SQLSTATE 22·23, 예: CHECK 위반)로 묶음이 실패하면 한 줄씩 넣어 문제 줄만 shipper.rejected.jsonl로 빼고 진행한다.
연결 오류·표 없음 같은 나머지 오류는 재시도한다(줄을 버리지 않는다).
상태는 shipper.status.json에 남긴다 - 탐지 API의 /health가 읽는다.

실행: python -m detection_service.log_shipper [--start-at-end]
  --start-at-end  진행 위치 파일이 없을 때 지금 파일의 끝에서 시작(배포 직전까지의 줄은 이미 DB에 있을 때)
환경변수: DETECTION_PG_DSN(필수), DETECTION_LOG_PATH(기본 /opt/detection/logs/decisions.jsonl)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .decision_log import BACKUPS, DEFAULT_PATH, rotated_path

log = logging.getLogger("detection.log_shipper")

BATCH_LINES = 500
MAX_READ_BYTES = 8 * 1024 * 1024
IDLE_SLEEP = 1.0
MAX_BACKOFF = 30.0


def offset_path(log_path: Path) -> Path:
    return log_path.with_name("shipper.offset")


def status_path(log_path: Path) -> Path:
    return log_path.with_name("shipper.status.json")


def rejected_path(log_path: Path) -> Path:
    return log_path.with_name("shipper.rejected.jsonl")


def _atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    # 0600: 상태의 last_error에는 DB 오류 메시지(실패한 행의 프롬프트 일부)가 들어갈 수 있다
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _is_data_error(exc: BaseException) -> bool:
    state = getattr(exc, "sqlstate", None) or ""
    return state.startswith("22") or state.startswith("23")


@dataclass
class Offset:
    ino: int | None
    pos: int


class Shipper:
    def __init__(self, log_path: Path | str, writer: Any, *, backups: int = BACKUPS, batch_lines: int = BATCH_LINES,
                 max_read_bytes: int = MAX_READ_BYTES):
        self.log_path = Path(log_path)
        self.writer = writer
        self.backups = backups
        self.batch_lines = batch_lines
        self.max_read_bytes = max_read_bytes
        self.status: dict[str, Any] = {
            "shipped_total": 0, "rejected_total": 0, "bad_lines_total": 0, "legacy_lines_total": 0,
            "lost_files_total": 0, "last_ok_ts": None, "last_error": None, "last_error_ts": None,
            "consecutive_failures": 0, "pending_bytes": None, "started_ts": time.time(),
        }
        # 재시작해도 누적 건수·마지막 성공 시각은 이어간다(헬스 체크가 재시작 직후 비어 보이지 않게)
        prev = read_status(self.log_path)
        if prev:
            for k in ("shipped_total", "rejected_total", "bad_lines_total", "legacy_lines_total", "lost_files_total"):
                if isinstance(prev.get(k), int):
                    self.status[k] = prev[k]
            self.status["last_ok_ts"] = prev.get("last_ok_ts")

    # ---- 진행 위치 ----
    def load_offset(self) -> Offset | None:
        try:
            d = json.loads(offset_path(self.log_path).read_text(encoding="utf-8"))
            return Offset(d.get("ino"), int(d["pos"]))
        except FileNotFoundError:
            return None

    def save_offset(self, off: Offset) -> None:
        _atomic_write_json(offset_path(self.log_path), {"ino": off.ino, "pos": off.pos})

    def init_offset(self, *, start_at_end: bool) -> Offset:
        off = self.load_offset()
        if off is not None:
            return off
        try:
            st = self.log_path.stat()
            off = Offset(st.st_ino, st.st_size if start_at_end else 0)
        except FileNotFoundError:
            off = Offset(None, 0)
        self.save_offset(off)
        log.info("offset initialized: %s", off)
        return off

    # ---- 파일 찾기 ----
    def _chain(self) -> list[Path]:
        """새 파일부터: [decisions.jsonl, .1, .2, …]."""
        return [self.log_path] + [rotated_path(self.log_path, i) for i in range(1, self.backups + 1)]

    def _find(self, ino: int) -> int | None:
        for idx, p in enumerate(self._chain()):
            try:
                if p.stat().st_ino == ino:
                    return idx
            except FileNotFoundError:
                continue
        return None

    def _oldest_ino(self) -> int | None:
        for p in reversed(self._chain()):
            try:
                return p.stat().st_ino
            except FileNotFoundError:
                continue
        return None

    def _pending_bytes(self, idx: int, pos: int) -> int:
        total = 0
        for i, p in enumerate(self._chain()[: idx + 1]):
            try:
                size = p.stat().st_size
            except FileNotFoundError:
                continue
            total += max(size - pos, 0) if i == idx else size
        return total

    # ---- 한 차례 ----
    def ship_once(self) -> bool:
        """진전이 있으면 True(바로 다음 차례), 보낼 것이 없으면 False(쉬었다가). DB 실패는 예외."""
        off = self.load_offset() or self.init_offset(start_at_end=False)
        if off.ino is None:
            # 시작할 때 파일이 없었다 = 지금 있는 파일은 모두 아직 안 보낸 것. 가장 오래된 파일부터(첫 차례 전에 회전됐을 수 있다).
            oldest = self._oldest_ino()
            if oldest is None:
                self.status["pending_bytes"] = 0
                return False
            off = Offset(oldest, 0)
            self.save_offset(off)

        idx = self._find(off.ino)
        if idx is None:
            # 위치가 가리키던 파일이 없다 - 백업 수를 넘겨 회전으로 지워졌거나 누가 지웠다.
            # 남아 있는 가장 오래된 파일 처음부터 다시 간다(잃는 것을 최소로). 이미 보낸 줄이 섞여도 decision_id로 걸러진다.
            self.status["lost_files_total"] += 1
            oldest = self._oldest_ino()
            log.error("offset file (ino=%s) not found; restarting at oldest remaining file", off.ino)
            self.save_offset(Offset(oldest, 0))
            return True

        path = self._chain()[idx]
        try:
            f = path.open("rb")
        except FileNotFoundError:
            return True  # 찾은 직후 회전됨 - 다시 찾는다
        with f:
            st = os.fstat(f.fileno())
            if st.st_ino != off.ino:
                return True
            pos = off.pos
            if pos > st.st_size:
                log.error("offset %d beyond file size %d (truncated?); restarting file", pos, st.st_size)
                pos = 0
            f.seek(pos)
            data = f.read(self.max_read_bytes)
            while b"\n" not in data:  # 한 줄이 읽기 한도보다 긴 경우(긴 프롬프트) - 줄 끝이나 파일 끝까지 더 읽는다
                more = f.read(self.max_read_bytes)
                if not more:
                    break
                data += more

        end = data.rfind(b"\n")
        if end < 0:
            if idx > 0:
                # 회전된 파일은 더 늘지 않는다 - 끝까지 봤으면(또는 줄바꿈 없는 찌꺼기만 남았으면) 한 단계 새 파일로.
                if data:
                    log.error("dropping %d trailing bytes without newline in %s", len(data), path.name)
                    self.status["bad_lines_total"] += 1
                nxt = self._chain()[idx - 1]
                try:
                    self.save_offset(Offset(nxt.stat().st_ino, 0))
                except FileNotFoundError:
                    self.save_offset(Offset(None, 0))
                return True
            self.status["pending_bytes"] = self._pending_bytes(idx, pos)
            return False

        lines = data[: end + 1].split(b"\n")[:-1][: self.batch_lines]
        consumed = sum(len(x) + 1 for x in lines)
        records: list[tuple[bytes, dict[str, Any]]] = []
        for raw in lines:
            try:
                rec = json.loads(raw)
            except ValueError:
                self.status["bad_lines_total"] += 1
                log.error("unparseable log line skipped (%d bytes)", len(raw))
                continue
            if not isinstance(rec, dict) or not rec.get("decision_id"):
                self.status["legacy_lines_total"] += 1  # decision_id 없는 옛 형식 줄
                continue
            records.append((raw, rec))

        self._insert(records)
        new_pos = pos + consumed
        self.save_offset(Offset(off.ino, new_pos))
        self.status["shipped_total"] += len(records)
        self.status["last_ok_ts"] = time.time()
        self.status["consecutive_failures"] = 0
        self.status["pending_bytes"] = self._pending_bytes(idx, new_pos)
        return True

    def _insert(self, records: list[tuple[bytes, dict[str, Any]]]) -> None:
        if not records:
            return
        try:
            self.writer.insert_many([r for _, r in records])
            return
        except Exception as exc:
            if not _is_data_error(exc):
                raise
            log.warning("batch data error, isolating bad rows: %s", exc)
        for raw, rec in records:
            try:
                self.writer.insert_many([rec])
            except Exception as exc:
                if not _is_data_error(exc):
                    raise
                self._reject(raw, exc)

    def _reject(self, raw: bytes, exc: BaseException) -> None:
        p = rejected_path(self.log_path)
        new = not p.exists()
        with p.open("ab") as f:
            entry = {"error": f"{type(exc).__name__}: {exc}", "sqlstate": getattr(exc, "sqlstate", None),
                     "line": raw.decode("utf-8", "replace")}
            f.write((json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
        if new:
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        self.status["rejected_total"] += 1
        log.error("row rejected by database: %s", exc)

    def write_status(self) -> None:
        try:
            _atomic_write_json(status_path(self.log_path), {**self.status, "updated_ts": time.time()})
        except Exception as exc:
            log.warning("status write failed: %s", exc)

    # ---- 반복 ----
    def run(self, stop: threading.Event | None = None, *, idle_sleep: float = IDLE_SLEEP) -> None:
        stop = stop or threading.Event()
        backoff = 1.0
        last_status = 0.0
        while not stop.is_set():
            try:
                progressed = self.ship_once()
                backoff = 1.0
                if not progressed:
                    stop.wait(idle_sleep)
            except Exception as exc:
                self.status["last_error"] = f"{type(exc).__name__}: {exc}"[:500]
                self.status["last_error_ts"] = time.time()
                self.status["consecutive_failures"] += 1
                log.warning("ship failed (%d in a row), retry in %.0fs: %s",
                            self.status["consecutive_failures"], backoff, exc)
                self.write_status()
                stop.wait(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
                continue
            now = time.monotonic()
            if now - last_status >= 1.0:
                self.write_status()
                last_status = now


def read_status(log_path: Path | str) -> dict[str, Any] | None:
    try:
        return json.loads(status_path(Path(log_path)).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    from .pg_store import PgWriter

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--start-at-end", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    dsn = os.environ.get("DETECTION_PG_DSN", "").strip()
    if not dsn:
        log.error("DETECTION_PG_DSN is not set")
        return 2
    log_path = Path(os.environ.get("DETECTION_LOG_PATH", DEFAULT_PATH))
    shipper = Shipper(log_path, PgWriter(dsn))
    shipper.init_offset(start_at_end=args.start_at_end)
    log.info("shipping %s -> decisions (offset %s)", log_path, shipper.load_offset())
    shipper.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
