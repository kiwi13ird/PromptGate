"""보고서 생성 작업 - 탐지 API가 받은 요청을 자식 프로세스(`python -m reporting`)로 돌린다.

왜 자식 프로세스인가:
- 탐지 API는 RDS에 연결하지 않는다(2026-09-15 원칙). 접속 정보는 자식이 `--env-file`로 직접 읽는다
- 생성은 LLM 대기로 30초 이상 걸린다. 탐지 요청 처리와 같은 프로세스·스레드 풀을 쓰지 않는다
- `nice`로 우선순위를 낮춰 같은 인스턴스의 /detect 응답을 지킨다

한 번에 하나만 돈다(GPU 하나). 돌고 있으면 새 요청은 409.
작업 상태는 출력 디렉터리의 파일로 판단한다 - API가 재시작돼도 끝난 보고서 목록은 남는다:
  <id>.html  보고서
  <id>.json  생성 기록(집계·LLM 소요, 제외 줄 등 - reporting.__main__이 쓴다)
  <id>.err   실패 시 stderr 끝부분
  <id>.blind-A.html·<id>.blind-B.html  블라인드 비교판(blind_pair, 어느 쪽이 LLM인지는 .json의 blind)
진행 중 작업은 메모리에만 있다. 재시작 중 끊긴 작업은 .html·.json이 없으므로 목록에 안 보인다(다시 요청하면 된다).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

MAX_DAYS = 366
_ID = re.compile(r"^report_\d{4}-\d{2}-\d{2}_\d{4}-\d{2}-\d{2}_\d{8}T\d{6}$")
SRC_DIR = Path(__file__).resolve().parents[1]


class ReportError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 400, code: str = "REPORT_ERROR") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def content_trend_enabled() -> bool:
    """전역 내용 경향 스위치(REPORT_CONTENT_TREND). 꺼져 있으면 요청이 켬이어도 끔으로 돌린다(설계 v2 4.6-e)."""
    from .content import global_enabled

    return global_enabled()


@dataclass
class _Running:
    report_id: str
    start: date
    end: date            # 포함
    use_llm: bool
    content_trend: bool = False
    blind_pair: bool = False
    started: float = field(default_factory=time.time)
    proc: subprocess.Popen | None = None


def validate_period(start: date, end: date, today: date | None = None) -> None:
    """end는 포함 날짜. 미래 날짜는 오늘까지로 보지 않고 거부한다(빈 보고서가 정상처럼 보이지 않게)."""
    today = today or datetime.now(timezone.utc).date()
    if end < start:
        raise ReportError("'to' must be on or after 'from'.", code="INVALID_PERIOD")
    if (end - start).days + 1 > MAX_DAYS:
        raise ReportError(f"Period must be at most {MAX_DAYS} days.", code="PERIOD_TOO_LONG")
    if start > today:
        raise ReportError("'from' is in the future.", code="INVALID_PERIOD")


class ReportJobs:
    def __init__(self, out_dir: str | Path, env_file: str | None, *, python: str = sys.executable,
                 nice: bool = True, cwd: str | Path = SRC_DIR) -> None:
        self.out_dir = Path(out_dir)
        self.cwd = Path(cwd)
        self.env_file = env_file
        self.python = python
        self.nice = nice and hasattr(os, "nice")
        self._lock = threading.Lock()
        self._running: _Running | None = None

    # ------------------------------------------------------------ 시작
    def start(self, start: date, end: date, use_llm: bool = True, content_trend: bool | None = None,
              blind_pair: bool = False) -> dict:
        """content_trend: None이면 전역 스위치를 따름(켜져 있으면 포함). 전역 꺼짐이면 무엇을 보내도 끔.
        LLM을 안 쓰면 내용 경향도 끔. blind_pair: 같은 사실로 LLM판·집계판 블라인드 비교 파일 2개를 더 만든다."""
        validate_period(start, end)
        trend = bool(use_llm and content_trend_enabled() and content_trend is not False)
        if not self.env_file or not Path(self.env_file).is_file():
            raise ReportError("Report database settings are not configured.", status_code=503,
                              code="REPORT_UNAVAILABLE")
        with self._lock:
            if self._running is not None and self._running.proc is not None and self._running.proc.poll() is None:
                raise ReportError("Another report is being generated.", status_code=409, code="REPORT_BUSY")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            report_id = f"report_{start}_{end}_{stamp}"
            self.out_dir.mkdir(parents=True, exist_ok=True)
            cmd = [self.python, "-m", "reporting", "--from", str(start), "--to", str(end + timedelta(days=1)),
                   "--out", str(self.out_dir / f"{report_id}.html"), "--env-file", self.env_file]
            if not use_llm:
                cmd.append("--no-llm")
            cmd.append("--content-trend" if trend else "--no-content-trend")
            if blind_pair:
                cmd.append("--blind")
            run = _Running(report_id, start, end, use_llm, trend, blind_pair)
            err = open(self.out_dir / f"{report_id}.err", "wb")
            run.proc = subprocess.Popen(cmd, cwd=self.cwd, stdout=subprocess.DEVNULL, stderr=err,
                                        preexec_fn=(lambda: os.nice(10)) if self.nice else None)
            err.close()
            self._running = run
            threading.Thread(target=self._reap, args=(run,), daemon=True).start()
        return self.status(report_id)

    def _reap(self, run: _Running) -> None:
        run.proc.wait()
        err = self.out_dir / f"{run.report_id}.err"
        if run.proc.returncode == 0 and err.exists():
            err.unlink(missing_ok=True)   # 성공이면 stderr는 남길 이유가 없다
        (self.out_dir / f"{run.report_id}.progress").unlink(missing_ok=True)

    # ------------------------------------------------------------ 조회
    def _check_id(self, report_id: str) -> None:
        if not _ID.match(report_id):    # 경로 조작 방지 - 파일 이름으로 쓰인다
            raise ReportError("Report not found.", status_code=404, code="NOT_FOUND")

    def status(self, report_id: str) -> dict:
        self._check_id(report_id)
        run = self._running if self._running and self._running.report_id == report_id else None
        if run is not None and run.proc is not None and run.proc.poll() is None:
            stage, llm_progress = _read_progress(self.out_dir / f"{report_id}.progress")
            return {"report_id": report_id, "status": "running", "stage": stage, "llm_progress": llm_progress,
                    "from": str(run.start), "to": str(run.end), "use_llm": run.use_llm,
                    "content_trend": run.content_trend, "elapsed_seconds": round(time.time() - run.started)}
        meta = self.out_dir / f"{report_id}.json"
        if meta.is_file() and (self.out_dir / f"{report_id}.html").is_file():
            log = json.loads(meta.read_text(encoding="utf-8"))
            gpu_log = log.get("gpu") or {}
            trend = log.get("content_trend") if isinstance(log.get("content_trend"), dict) else {}
            inc = log.get("incidents") if isinstance(log.get("incidents"), dict) else {}
            return {"report_id": report_id, "status": "done", "from": log.get("from"), "to": _inclusive(log.get("to")),
                    "compare_from": log.get("compare_from"), "compare_to": log.get("compare_to"),
                    "use_llm": log.get("use_llm"), "generated_at": log.get("generated_at"),
                    "rows": log.get("rows"), "items": log.get("items"),
                    # 옛 보고서(10/1~10/11)는 llm_used 대신 raw가 있다
                    "llm_used": log["llm_used"] if "llm_used" in log else log.get("raw") is not None,
                    "mode": log.get("mode"), "writer": log.get("writer"),
                    "llm_error": log.get("llm_error"), "llm_ms": log.get("llm_ms"), "agg_ms": log.get("agg_ms"),
                    "lines_kept": log.get("kept"), "lines_dropped": len(log.get("dropped") or []),
                    "llm_lines": log.get("kept"), "llm_dropped": len(log.get("dropped") or []),
                    "content_trend": trend.get("effective"), "content_trend_state": trend.get("state"),
                    "incidents": inc or None, "users_high": log.get("users_high"),
                    "gpu_started": bool(gpu_log.get("started")), "gpu_waited_s": gpu_log.get("waited_s"),
                    "gpu_auto_stop": gpu_log.get("auto_stop"),
                    "blind": bool(log.get("blind")),
                    "file": f"/admin/reports/{report_id}/file"}
        err = self.out_dir / f"{report_id}.err"
        if err.is_file():
            tail = err.read_bytes()[-800:].decode("utf-8", errors="replace")
            return {"report_id": report_id, "status": "failed", "error": tail.strip().splitlines()[-1] if tail.strip() else "unknown"}
        raise ReportError("Report not found.", status_code=404, code="NOT_FOUND")

    def list(self) -> list[dict]:
        ids = {p.stem for p in self.out_dir.glob("report_*.json")} | {p.stem for p in self.out_dir.glob("report_*.err")}
        if self._running is not None:
            ids.add(self._running.report_id)
        out = []
        for report_id in sorted(ids, reverse=True):
            try:
                out.append(self.status(report_id))
            except ReportError:
                continue
        return out

    def file(self, report_id: str) -> Path:
        st = self.status(report_id)
        if st["status"] != "done":
            raise ReportError(f"Report is {st['status']}.", status_code=409, code="NOT_READY")
        return self.out_dir / f"{report_id}.html"


def _read_progress(path: Path) -> tuple[str | None, str | None]:
    """진행 파일: JSON {"stage", "llm_done", "llm_total"}(2026-10-12~) 또는 옛 글자 한 줄. 반환 (단계, 'LLM 5/15')."""
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None, None
    if not raw:
        return None, None
    if raw.startswith("{"):
        try:
            body = json.loads(raw)
        except ValueError:
            return None, None
        done, total = body.get("llm_done"), body.get("llm_total")
        return body.get("stage"), (f"{done}/{total}" if total else None)
    return raw, None


def _inclusive(end_exclusive: str | None) -> str | None:
    if not end_exclusive:
        return None
    return str(date.fromisoformat(end_exclusive) - timedelta(days=1))
