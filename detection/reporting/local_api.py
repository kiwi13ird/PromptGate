"""Detection 로컬 API 읽기(GET만) - 정책 변경·키워드 수·생성 시점 상태·GPU 사용 중 여부.

보고서 자식 프로세스는 탐지 API와 같은 인스턴스에서 돈다(127.0.0.1:8000). 실패하면 None - 해당 줄은 '확인 실패'.
키워드 목록은 그 자체로 기밀이므로 개수만 센다(글자는 저장·출력하지 않는다).
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Callable

BASE = os.environ.get("REPORT_DETECTION_API", "http://127.0.0.1:8000").rstrip("/")


def get_json(path: str, *, base: str = BASE, timeout: float = 5.0) -> Any:
    with urllib.request.urlopen(base + path, timeout=timeout) as r:
        return json.loads(r.read())


def _safe(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001 - 로컬 API는 보조 자료
        return None


def keyword_counts(get=get_json) -> dict | None:
    def run():
        ap = get("/admin/keywords?status=approved")["keywords"]
        pe = get("/admin/keywords?status=pending")["keywords"]
        return {"approved": len(ap), "pending": len(pe)}
    return _safe(run)


def policy_changes(t0: datetime, t1: datetime, get=get_json) -> list[dict] | None:
    """기간 안 탐지 정책 버전 변경(조치 전→후). 시각은 정책 저장소 문자열(UTC ISO)을 한국 시각으로."""
    from .aggregate import kst_hm

    def parse(ts: str) -> datetime | None:
        try:
            d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo is None:
            from datetime import timezone
            d = d.replace(tzinfo=timezone.utc)
        return d

    def run():
        out = []
        for p in get("/admin/policies"):
            pid = p.get("policy_id") or p.get("id")
            if not pid:
                continue
            versions = sorted(get(f"/admin/policies/{urllib.parse.quote(str(pid))}/versions"), key=lambda v: v["version"])
            for prev, cur in zip([None, *versions], versions):
                at = parse(cur.get("created_at"))
                if prev is None or at is None or not (t0 <= at < t1):
                    continue
                before = prev["action"] if prev.get("enabled", True) else "꺼짐"
                after = cur["action"] if cur.get("enabled", True) else "꺼짐"
                if before != after:
                    out.append({"target": p.get("detection_target") or pid, "at": kst_hm(at), "before": before,
                                "after": after, "by": cur.get("changed_by")})
        return out
    return _safe(run)


def system_status(get=get_json) -> dict | None:
    def run():
        s = get("/admin/system-status")
        inst = (s.get("instances") or {}).get("items") or []
        return {"detection": (s.get("detection") or {}).get("status"),
                "redis_ok": (s.get("redis") or {}).get("ok"),
                "log_ok": (s.get("log_shipping") or {}).get("ok"),
                "log_pending": (s.get("log_shipping") or {}).get("pending_bytes"),
                "rds": (s.get("rds") or {}).get("status"),
                "instances": [{"role": i.get("role"), "state": i.get("state")} for i in inst],
                "checked_at": s.get("checked_at")}
    return _safe(run)


def gpu_busy(own_report_id: str, get=get_json) -> list[str] | None:
    """GPU를 쓰는 다른 작업. None = 확인 못 함(그때는 끄지 않는다)."""
    def run():
        reasons = []
        health = get("/health")
        jobs = health.get("keyword_jobs")
        if jobs and (jobs.get("queued", 0) or jobs.get("running", 0)):
            reasons.append("keyword_job")
        reports = get("/admin/reports").get("reports") or []
        if any(r.get("status") == "running" and r.get("report_id") != own_report_id for r in reports):
            reasons.append("report")
        return reasons
    return _safe(run)
