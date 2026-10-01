"""Record safe metadata-only performance samples through Gateway 8081."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import os
import statistics
import time
import urllib.request

from dashboard_event_sender import _metrics_url


PROXY_URL = os.getenv("GATEWAY_BENCHMARK_PROXY", "http://127.0.0.1:8081")
TARGET_URL = os.getenv("GATEWAY_BENCHMARK_TARGET", "https://chatgpt.com/")
REQUESTS_PER_CLIENT = 3


def _request() -> tuple[float, bool]:
    proxy = urllib.request.ProxyHandler({"http": PROXY_URL, "https": PROXY_URL})
    opener = urllib.request.build_opener(proxy)
    request = urllib.request.Request(TARGET_URL, method="HEAD")
    started = time.perf_counter()
    try:
        with opener.open(request, timeout=10) as response:
            response.read(0)
        return (time.perf_counter() - started) * 1000, False
    except Exception:
        return (time.perf_counter() - started) * 1000, True


def _record(payload: dict) -> None:
    metrics_url = _metrics_url()
    token = os.getenv("DASHBOARD_INGEST_TOKEN")
    if not metrics_url or not token:
        raise RuntimeError("Dashboard endpoint is not configured.")
    url = metrics_url.removesuffix("/traffic/metrics") + "/traffic/performance-runs"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Dashboard returned HTTP {response.status}.")


def main() -> None:
    for concurrency in (1, 2, 4):
        total = concurrency * REQUESTS_PER_CLIENT
        started_at = dt.datetime.now(dt.timezone.utc)
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(lambda _: _request(), range(total)))
        duration = time.perf_counter() - started
        latencies = [latency for latency, _ in results]
        errors = sum(int(error) for _, error in results)
        ordered = sorted(latencies)
        p95_index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.95) - 1))
        payload = {
            "run_id": f"gateway-bench-{started_at.strftime('%Y%m%dT%H%M%SZ')}-c{concurrency}",
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "duration_sec": max(1, round(duration)),
            "concurrent_clients": concurrency,
            "total_requests": total,
            "throughput_rps": round(total / duration, 3),
            "avg_latency_ms": round(statistics.fmean(latencies), 2),
            "p95_latency_ms": round(ordered[p95_index], 2),
            "timeout_rate": round(errors / total, 6),
        }
        _record(payload)
        print(
            f"recorded {payload['run_id']} requests={total} "
            f"rps={payload['throughput_rps']} p95_ms={payload['p95_latency_ms']}"
        )


if __name__ == "__main__":
    main()
