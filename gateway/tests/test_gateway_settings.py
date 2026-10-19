"""Gateway 처리 설정(2026-10-10): 검증·환경변수 기본값·보관·디스크 사본·지표 응답 전달.

가짜 값만 쓴다. 대시보드 백엔드와 같은 규칙인지는 node가 있으면 실제 gateway-settings.mjs로 대조한다
(GW_TEST_DASHBOARD_SERVER_DIR, 없으면 그 시험만 건너뜀).
실행: python -m unittest tests.test_gateway_settings -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import io
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="gw-settings-tests-")
os.environ.setdefault("DASHBOARD_OUTBOX_PATH", str(Path(_TMP) / "outbox.sqlite3"))   # gateway를 불러도 작업 폴더에 쓰지 않게
os.environ.setdefault("SIGNATURE_REVIEW_DIR", str(Path(_TMP) / "review"))
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard_event_sender  # noqa: E402
from gateway_metrics_delivery import MetricsPublisher  # noqa: E402
from gateway_settings import (  # noqa: E402
    SettingsError,
    SettingsHolder,
    env_defaults,
    file_max_bytes_from_env,
    file_max_chars,
    parse_settings,
    parse_settings_fields,
)
from tests.gw_support import REVISION_1, REVISION_2, settings_doc  # noqa: E402

DASHBOARD_SERVER_DIR = Path(os.environ.get(
    "GW_TEST_DASHBOARD_SERVER_DIR",
    "C:/Users/user/AppData/Local/Temp/claude/C--Users-user-Desktop-kisia-project/"
    "32d4e37a-7639-4ae3-a018-7182e5d25155/scratchpad/dash-work/server"))
METRICS_URL = "http://127.0.0.1:19100/api/traffic/metrics"


def holder(cache_path=None, url=METRICS_URL, environ=None):
    logs = []
    value = SettingsHolder(env_defaults(environ or {}), cache_path=cache_path, metrics_url=url, logger=logs.append)
    return value, logs


def error_field(document):
    try:
        parse_settings(document)
    except SettingsError as exc:
        return exc.field
    return None


class ValidationTests(unittest.TestCase):
    def test_valid_document(self):
        settings = parse_settings(settings_doc(prompt=("block", 1.5), file=("forward", 3), notify=True, version=7))
        self.assertEqual((settings.version, settings.revision, settings.source), (7, REVISION_1, "DASHBOARD"))
        self.assertEqual((settings.prompt.action, settings.prompt.seconds, settings.prompt.failure_policy),
                         ("block", 1.5, "FAIL_CLOSED"))
        self.assertEqual((settings.file.action, settings.file.seconds, settings.file.failure_policy),
                         ("forward", 3.0, "FAIL_OPEN"))
        self.assertTrue(settings.notify_on_allow)
        self.assertEqual(settings.timeout_for("image"), settings.file)   # 모르는 종류 = 파일 규칙

    def test_seconds_bounds_and_types(self):
        for value in (0.05, 0.125, 30, 2):
            self.assertIsNone(error_field(settings_doc(file=("block", value))), value)
        for value in (0.04, 30.01, 0, -1, float("nan"), float("inf"), True, "2", None):
            self.assertEqual(error_field(settings_doc(file=("block", value))), "timeout.file.seconds", value)

    def test_unknown_or_missing_fields(self):
        doc = settings_doc()
        doc["extra"] = 1
        self.assertEqual(error_field(doc), "gateway_settings")
        doc = settings_doc()
        del doc["notify_on_allow"]
        self.assertEqual(error_field(doc), "gateway_settings")
        doc = settings_doc()
        doc["timeout"]["prompt"]["note"] = "x"
        self.assertEqual(error_field(doc), "timeout.prompt")
        doc = settings_doc()
        del doc["uninspectable"]["other"]
        self.assertEqual(error_field(doc), "uninspectable")

    def test_value_errors_report_the_field_path(self):
        self.assertEqual(error_field(settings_doc(prompt=("allow", 0.5))), "timeout.prompt.action")
        self.assertEqual(error_field(settings_doc(image="forward")), "uninspectable.image")
        self.assertEqual(error_field({**settings_doc(), "notify_on_allow": "true"}), "notify_on_allow")
        self.assertEqual(error_field({**settings_doc(), "version": 0}), "version")
        self.assertEqual(error_field({**settings_doc(), "version": True}), "version")
        self.assertEqual(error_field({**settings_doc(), "revision": "ABCDEF00-0000-4000-8000-000000000001"}), "revision")
        self.assertEqual(error_field({**settings_doc(), "updated_at": "2026-10-10T05:12:00"}), "updated_at")
        self.assertEqual(error_field({**settings_doc(), "updated_by": ""}), "updated_by")
        self.assertEqual(error_field([]), "gateway_settings")

    def test_shapes_are_checked_before_values(self):
        doc = settings_doc(prompt=("allow", 99))
        doc["uninspectable"] = {"image": "allow"}
        self.assertEqual(error_field(doc), "uninspectable")   # 백엔드와 같은 순서(모양 400 → 값 422)
        self.assertEqual(error_field(settings_doc(prompt=("allow", 99), file=("x", 99))), "timeout.prompt.action")

    def test_file_max_chars(self):
        self.assertEqual(file_max_chars(2.0), 80645)
        self.assertEqual([file_max_chars(s) for s in (0.5, 1, 5, 10, 30)], [20161, 40322, 201612, 403225, 1209677])


class EnvironmentTests(unittest.TestCase):
    def test_no_environment_gives_spec_defaults(self):
        settings = env_defaults({})
        self.assertEqual((settings.prompt.action, settings.prompt.seconds), ("forward", 0.5))
        self.assertEqual((settings.file.action, settings.file.seconds), ("block", 2.0))
        self.assertEqual((settings.image, settings.scanned_pdf, settings.other), ("allow", "block", "block"))
        self.assertEqual((settings.notify_on_allow, settings.source, settings.version, settings.revision),
                         (False, "ENV_DEFAULT", 0, None))
        self.assertEqual(file_max_bytes_from_env({}), 20 * 1024 * 1024)

    def test_environment_values(self):
        settings = env_defaults({"DETECTION_FAILURE_POLICY": "fail_closed", "DETECTION_TIMEOUT_SECONDS": "0.125",
                                 "GATEWAY_FILE_TIMEOUT_ACTION": "forward", "GATEWAY_FILE_TIMEOUT_SECONDS": "30",
                                 "GATEWAY_UNINSPECTABLE_IMAGE": "block", "GATEWAY_UNINSPECTABLE_SCANNED_PDF": "allow",
                                 "GATEWAY_UNINSPECTABLE_OTHER": "allow", "GATEWAY_NOTIFY_ON_ALLOW": "true"})
        self.assertEqual((settings.prompt.action, settings.prompt.seconds), ("block", 0.125))
        self.assertEqual((settings.file.action, settings.file.seconds), ("forward", 30.0))
        self.assertEqual((settings.image, settings.scanned_pdf, settings.other, settings.notify_on_allow),
                         ("block", "allow", "allow", True))

    def test_invalid_environment_fails_at_start(self):
        for name, value in (("DETECTION_FAILURE_POLICY", "maybe"), ("DETECTION_TIMEOUT_SECONDS", "0.04"),
                            ("GATEWAY_FILE_TIMEOUT_SECONDS", "abc"), ("GATEWAY_FILE_TIMEOUT_SECONDS", "nan"),
                            ("GATEWAY_FILE_TIMEOUT_SECONDS", "inf"), ("GATEWAY_FILE_TIMEOUT_SECONDS", "30.01"),
                            ("GATEWAY_FILE_TIMEOUT_ACTION", "allow"), ("GATEWAY_UNINSPECTABLE_IMAGE", "deny"),
                            ("GATEWAY_NOTIFY_ON_ALLOW", "yes")):
            with self.assertRaises(ValueError, msg=f"{name}={value}") as caught:
                env_defaults({name: value})
            self.assertIn(name, str(caught.exception))   # 어떤 변수가 틀렸는지(값은 싣지 않음)
        with self.assertRaises(ValueError):
            file_max_bytes_from_env({"GATEWAY_FILE_MAX_BYTES": "0"})

    def test_gateway_import_fails_on_an_invalid_environment(self):
        env = {**os.environ, "GATEWAY_FILE_TIMEOUT_SECONDS": "0.01", "PYTHONIOENCODING": "utf-8"}
        env.pop("DASHBOARD_EVENT_URL", None)
        result = subprocess.run([sys.executable, "-c", "import gateway"], cwd=ROOT, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ValueError", result.stderr)
        self.assertIn("GATEWAY_FILE_TIMEOUT_SECONDS", result.stderr)


class HolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gw-settings-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cache = self.tmp / "var" / "gateway-settings.json"

    def test_starts_from_environment_defaults(self):
        value, logs = holder(self.cache)
        self.assertEqual(value.current().source, "ENV_DEFAULT")
        self.assertEqual(logs, ["[SETTINGS] source=ENV_DEFAULT version=0"])
        self.assertEqual(value.report_field(), {})   # 대시보드가 칸을 주기 전에는 싣지 않는다

    def test_offer_replaces_only_when_version_or_revision_differs(self):
        value, logs = holder(self.cache)
        changes = []
        value.set_on_change(lambda: changes.append(1))
        value.offer({"accepted": True, "gateway_settings": settings_doc(file=("forward", 4.0))})
        first = value.current()
        self.assertEqual((first.version, first.file.seconds, first.source), (1, 4.0, "DASHBOARD"))
        value.offer({"accepted": True, "gateway_settings": settings_doc(file=("forward", 4.0))})
        self.assertIs(value.current(), first)                     # 같은 판: 그대로(적용 시각도 그대로)
        value.offer({"accepted": True, "gateway_settings": settings_doc(file=("forward", 5.0), revision=REVISION_2)})
        self.assertEqual((value.current().version, value.current().file.seconds), (1, 5.0))   # 같은 번호 다른 revision
        value.offer({"accepted": True, "gateway_settings": settings_doc(file=("block", 2.0), version=0 + 1,
                                                                        revision=REVISION_1)})
        self.assertEqual(value.current().revision, REVISION_1)    # 번호가 같거나 작아져도 "다르면" 따라간다
        self.assertEqual(len(changes), 3)
        self.assertEqual(sum("applied version=1" in line for line in logs), 3)

    def test_invalid_document_is_rejected_once_and_kept_out(self):
        value, logs = holder(self.cache)
        value.offer({"gateway_settings": settings_doc(file=("forward", 4.0))})
        good = value.current()
        bad = settings_doc(file=("forward", 99), version=2, revision=REVISION_2)
        for _ in range(3):
            value.offer({"gateway_settings": bad})
        self.assertIs(value.current(), good)
        self.assertEqual(value.report()["rejected"],
                         {"version": 2, "revision": REVISION_2, "field": "timeout.file.seconds"})
        rejected_logs = [line for line in logs if "rejected" in line]
        self.assertEqual(rejected_logs, ["[SETTINGS] rejected version=2 field=timeout.file.seconds"])
        value.offer({"gateway_settings": {**bad, "version": "x", "revision": "bad"}})
        self.assertEqual(value.report()["rejected"], {"version": None, "revision": None, "field": "version"})

    def test_null_returns_to_environment_defaults_and_removes_the_cache(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_settings": settings_doc(file=("forward", 4.0))})
        self.assertTrue(self.cache.exists())
        value.offer({"gateway_settings": None})
        self.assertEqual((value.current().source, value.current().file.seconds), ("ENV_DEFAULT", 2.0))
        self.assertFalse(self.cache.exists())

    def test_payload_without_the_field_changes_nothing(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_settings": settings_doc(file=("forward", 4.0))})
        current = value.current()
        for payload in ({"accepted": True}, None, [], "x"):
            value.offer(payload)
        self.assertIs(value.current(), current)

    def test_cache_is_private_and_reloaded_after_restart(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_settings": settings_doc(file=("forward", 4.0), version=3)})
        stored = json.loads(self.cache.read_text(encoding="utf-8"))
        self.assertEqual(set(stored), {"metrics_url_sha256", "document"})
        self.assertNotIn(METRICS_URL, self.cache.read_text(encoding="utf-8"))
        if os.name == "posix":
            self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.cache.parent.glob("*.tmp")), [])
        restarted, logs = holder(self.cache)
        self.assertEqual((restarted.current().source, restarted.current().version, restarted.current().file.seconds),
                         ("CACHE", 3, 4.0))
        self.assertEqual(logs, ["[SETTINGS] source=CACHE version=3"])
        restarted.offer({"gateway_settings": settings_doc(file=("forward", 4.0), version=3)})
        self.assertEqual(restarted.current().source, "DASHBOARD")   # 같은 판을 대시보드가 확인

    def test_cache_from_another_dashboard_or_broken_is_ignored(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_settings": settings_doc(file=("forward", 4.0))})
        other, logs = holder(self.cache, url="http://127.0.0.1:9/api/traffic/metrics")
        self.assertEqual(other.current().source, "ENV_DEFAULT")
        self.assertIn("[SETTINGS] cache ignored reason=other_dashboard", logs)
        self.cache.write_text("{not json", encoding="utf-8")
        broken, logs = holder(self.cache)
        self.assertEqual(broken.current().source, "ENV_DEFAULT")
        self.assertTrue(any("cache ignored" in line for line in logs))
        stored = {"metrics_url_sha256": __import__("hashlib").sha256(METRICS_URL.encode()).hexdigest(),
                  "document": settings_doc(file=("forward", 99))}
        self.cache.write_text(json.dumps(stored), encoding="utf-8")
        invalid, logs = holder(self.cache)
        self.assertEqual(invalid.current().source, "ENV_DEFAULT")
        self.assertIn("[SETTINGS] cache ignored reason=invalid field=timeout.file.seconds", logs)

    def test_no_dashboard_means_no_cache(self):
        value, _ = holder(self.cache, url=None)
        value.offer({"gateway_settings": settings_doc()})
        self.assertFalse(self.cache.exists())

    def test_weakening_changes_are_logged_by_field_name_only(self):
        value, logs = holder(self.cache)
        value.offer({"gateway_settings": settings_doc(prompt=("block", 2.0), file=("block", 2.0), other="block")})
        value.offer({"gateway_settings": settings_doc(prompt=("forward", 1.0), file=("forward", 2.0), other="allow",
                                                      revision=REVISION_2, version=2)})
        weakened = [line for line in logs if "weakened" in line]
        self.assertEqual(weakened, ["[SETTINGS] weakened fields=timeout.prompt.action,timeout.prompt.seconds,"
                                    "timeout.file.action,uninspectable.other"])

    def test_readers_always_see_one_whole_version(self):
        value, _ = holder(None)
        documents = [settings_doc(prompt=("forward", 0.5), file=("block", 2.0), version=1, revision=REVISION_1),
                     settings_doc(prompt=("block", 1.5), file=("forward", 3.0), version=2, revision=REVISION_2)]
        allowed = {(1, 0.5, 2.0), (2, 1.5, 3.0)}
        stop = threading.Event()
        seen, bad = set(), []

        def read():
            while not stop.is_set():
                current = value.current()
                key = (current.version, current.prompt.seconds, current.file.seconds)
                seen.add(key)
                if key not in allowed and current.source != "ENV_DEFAULT":
                    bad.append(key)
        readers = [threading.Thread(target=read) for _ in range(4)]
        for reader in readers:
            reader.start()
        index, deadline = 0, time.monotonic() + 0.5
        while time.monotonic() < deadline or len(seen & allowed) < 2:
            value.offer({"gateway_settings": documents[index % 2]})
            index += 1
            time.sleep(0.0005)
            if time.monotonic() > deadline + 5:
                break
        stop.set()
        for reader in readers:
            reader.join()
        self.assertEqual(bad, [])
        self.assertEqual(seen & allowed, allowed)   # 두 판 모두 읽혔다

    def test_report_field_follows_the_dashboard(self):
        value, logs = holder(None)
        self.assertEqual(value.report_field(), {})
        value.offer({"accepted": True, "gateway_settings": None})   # 새 대시보드, 저장 없음
        report = value.report_field()["settings_applied"]
        self.assertEqual((report["source"], report["version"], report["revision"], report["rejected"]),
                         ("ENV_DEFAULT", 0, None, None))
        self.assertTrue(report["applied_at"].endswith("Z"))
        value.on_metrics_status(400)                   # 실은 전송이 400(옛 대시보드로 되돌림)
        self.assertEqual(value.report_field(), {})
        value.on_metrics_status(400)
        self.assertEqual(value.report_field(), {})
        value.offer({"accepted": True})                 # 옛 대시보드 응답: 그대로 뺀다
        self.assertEqual(value.report_field(), {})
        value.offer({"accepted": True, "gateway_settings": settings_doc()})   # 칸이 다시 옴
        self.assertEqual(value.report_field()["settings_applied"]["revision"], REVISION_1)
        self.assertEqual(sum("report omitted" in line for line in logs), 1)


@unittest.skipUnless(shutil.which("node") and (DASHBOARD_SERVER_DIR / "gateway-settings.mjs").exists(),
                     "node or dashboard server copy not available")
class BackendParityTests(unittest.TestCase):
    """대시보드 백엔드 gateway-settings.mjs와 같은 결과인지 실제 JS로 대조."""

    def run_node(self, payload):
        module = (DASHBOARD_SERVER_DIR / "gateway-settings.mjs").as_uri()
        script = (
            f"import {{ parseGatewaySettings, parseSettingsApplied }} from '{module}';\n"
            "import { readFileSync } from 'node:fs';\n"
            "const input = JSON.parse(readFileSync(0, 'utf8'));\n"
            "const out = { fields: input.fields.map((value) => { try { parseGatewaySettings(value); return null; }"
            " catch (error) { return error.path ?? 'ERROR'; } }),\n"
            "  reports: input.reports.map((value) => { try { const parsed = parseSettingsApplied(value);"
            " return { ok: true, applied_at: parsed.applied_at, rejected: parsed.rejected }; }"
            " catch (error) { return { ok: false, error: String(error.message) }; } }) };\n"
            "console.log(JSON.stringify(out));\n"
        )
        folder = Path(tempfile.mkdtemp(prefix="gw-node-"))
        self.addCleanup(shutil.rmtree, folder, True)
        path = folder / "parity.mjs"
        path.write_text(script, encoding="utf-8")
        result = subprocess.run(["node", str(path)], input=json.dumps(payload), capture_output=True, text=True,
                                encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_same_field_paths_as_the_backend(self):
        cases = []
        for prompt, file in ((("forward", 0.5), ("block", 2.0)), (("block", 0.125), ("forward", 30)),
                             (("allow", 0.5), ("block", 2.0)), (("forward", 0.04), ("block", 2.0)),
                             (("forward", 0.5), ("block", 30.01)), (("forward", True), ("block", 2.0)),
                             (("forward", "1"), ("x", 99))):
            doc = settings_doc(prompt=prompt, file=file)
            cases.append({key: doc[key] for key in ("timeout", "uninspectable", "notify_on_allow")})
        base = {key: settings_doc()[key] for key in ("timeout", "uninspectable", "notify_on_allow")}
        cases += [{**base, "extra": 1}, {"timeout": base["timeout"], "uninspectable": base["uninspectable"]},
                  {**base, "uninspectable": {"image": "allow"}}, {**base, "uninspectable": {**base["uninspectable"],
                                                                                        "image": "deny"}},
                  {**base, "notify_on_allow": "false"},
                  {**base, "timeout": {"prompt": {"action": "block"}, "file": base["timeout"]["file"]}}]
        python = []
        for case in cases:
            try:
                parse_settings_fields(case)
                python.append(None)
            except SettingsError as exc:
                python.append("body" if exc.field == "gateway_settings" else exc.field)
        javascript = self.run_node({"fields": cases, "reports": []})["fields"]
        self.assertEqual(python, javascript)
        self.assertGreaterEqual(sum(field is not None for field in python), 9)

    def test_applied_reports_are_accepted_by_the_backend(self):
        tmp = Path(tempfile.mkdtemp(prefix="gw-settings-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        cache = tmp / "s.json"
        reports = []
        value, _ = holder(cache)
        value.offer({"gateway_settings": None})
        reports.append(value.report())                                   # ENV_DEFAULT
        value.offer({"gateway_settings": settings_doc(prompt=("block", 0.125), file=("forward", 30), notify=True)})
        reports.append(value.report())                                   # DASHBOARD
        value.offer({"gateway_settings": settings_doc(file=("forward", 99), version=2, revision=REVISION_2)})
        reports.append(value.report())                                   # rejected 칸 있음
        restarted, _ = holder(cache)
        reports.append(restarted.report())                               # CACHE
        results = self.run_node({"fields": [], "reports": reports})["reports"]
        self.assertTrue(all(result["ok"] for result in results), results)
        self.assertTrue(all(result["applied_at"] for result in results))   # 시간 형식도 백엔드가 받음(null 아님)
        self.assertEqual(results[2]["rejected"], {"version": 2, "revision": REVISION_2, "field": "timeout.file.seconds"})


class FakeResponse:
    def __init__(self, status, body=b""):
        self.status, self.body = status, body

    def getcode(self):
        return self.status

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class SenderTests(unittest.TestCase):
    def send(self, opener):
        return dashboard_event_sender.send_dashboard_metrics({"total_requests": 1}, url=METRICS_URL, token="t",
                                                              opener=opener, logger=lambda message: None)

    def test_2xx_body_is_returned_as_payload(self):
        body = json.dumps({"accepted": True, "gateway_settings": settings_doc()}).encode()
        result = self.send(lambda request, timeout: FakeResponse(202, body))
        self.assertEqual((result.status, result.http_status), ("sent", 202))
        self.assertEqual(result.payload["gateway_settings"]["revision"], REVISION_1)

    def test_old_response_and_bad_bodies(self):
        self.assertEqual(self.send(lambda r, timeout: FakeResponse(202, b'{"accepted":true}')).payload,
                         {"accepted": True})
        for body in (b"x" * 70000, b"not json", b"[1,2]", b"", "\ud800".encode("utf-8", "surrogatepass")):
            result = self.send(lambda r, timeout, body=body: FakeResponse(202, body))
            self.assertEqual((result.status, result.payload), ("sent", None))
        big = json.dumps({"accepted": True, "pad": "x" * 70000}).encode()
        self.assertIsNone(self.send(lambda r, timeout: FakeResponse(202, big)).payload)

    def test_http_error_keeps_the_status_code(self):
        def opener(request, timeout):
            raise urllib.error.HTTPError(METRICS_URL, 400, "Bad Request", {}, io.BytesIO(b'{"secret":"x"}'))
        logs = []
        result = dashboard_event_sender.send_dashboard_metrics({}, url=METRICS_URL, token="t", opener=opener,
                                                                logger=logs.append)
        self.assertEqual((result.status, result.http_status, result.payload), ("failed", 400, None))
        self.assertEqual(logs, ["[DASHBOARD] metrics delivery failed error_type=HTTP_400"])

    def test_real_http_server(self):
        responses = {"/ok": (202, json.dumps({"accepted": True, "gateway_settings": settings_doc()}).encode()),
                     "/bad": (400, b'{"error":"unknown field"}')}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                status, body = responses[self.path]
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        ok = dashboard_event_sender.send_dashboard_metrics({}, url=base + "/ok", token="t", timeout=2,
                                                            logger=lambda m: None)
        self.assertEqual((ok.status, ok.payload["gateway_settings"]["version"]), ("sent", 1))
        bad = dashboard_event_sender.send_dashboard_metrics({}, url=base + "/bad", token="t", timeout=2,
                                                             logger=lambda m: None)
        self.assertEqual((bad.status, bad.http_status, bad.payload), ("failed", 400, None))

    def test_metrics_url_requires_the_token(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_EVENT_URL": "http://x/api/events/ingest"}, clear=False):
            os.environ.pop("DASHBOARD_INGEST_TOKEN", None)
            self.assertIsNone(dashboard_event_sender.metrics_url())
            os.environ["DASHBOARD_INGEST_TOKEN"] = "t"
            try:
                self.assertEqual(dashboard_event_sender.metrics_url(), "http://x/api/traffic/metrics")
            finally:
                os.environ.pop("DASHBOARD_INGEST_TOKEN", None)


class PublisherTests(unittest.TestCase):
    def run_publisher(self, responses, *, settings=None, heartbeat=30.0, wait_for=2, timeout=5.0):
        """responses: 전송마다 돌려줄 DeliveryResult 목록(마지막 것을 되풀이)."""
        sent = []
        done = threading.Event()

        def sender(snapshot):
            sent.append(snapshot)
            if len(sent) >= wait_for:
                done.set()
            return responses[min(len(sent) - 1, len(responses) - 1)]
        settings = settings or holder(None)[0]
        publisher = MetricsPublisher(lambda: {"total_requests": len(sent), **settings.report_field()}, sender=sender,
                                     heartbeat=heartbeat, min_interval=0.05, logger=lambda m: None,
                                     on_payload=settings.offer, on_status=settings.on_metrics_status)
        settings.set_on_change(publisher.notify)
        started = time.monotonic()
        publisher.start()
        done.wait(timeout)
        publisher.stop()
        return sent, settings, time.monotonic() - started

    def delivered(self, payload=None, status=202):
        return dashboard_event_sender.DeliveryResult(status="sent" if status < 300 else "failed",
                                                     http_status=status, payload=payload)

    def test_applying_settings_sends_the_report_right_away(self):
        sent, settings, elapsed = self.run_publisher(
            [self.delivered({"accepted": True, "gateway_settings": settings_doc(version=4)}), self.delivered({})])
        self.assertNotIn("settings_applied", sent[0])
        self.assertEqual(sent[1]["settings_applied"]["version"], 4)
        self.assertLess(elapsed, 3)       # 주기(30초)를 기다리지 않고 바로 다음 전송

    def test_old_dashboard_never_gets_the_report(self):
        sent, _, _ = self.run_publisher([self.delivered({"accepted": True})], heartbeat=0.1, wait_for=3)
        self.assertTrue(all("settings_applied" not in snapshot for snapshot in sent))

    def test_report_is_dropped_after_400_and_restored_when_the_field_returns(self):
        responses = [self.delivered({"accepted": True, "gateway_settings": None}),
                     self.delivered(None, 400),
                     self.delivered({"accepted": True}),
                     self.delivered({"accepted": True, "gateway_settings": None}),
                     self.delivered({"accepted": True, "gateway_settings": None})]
        sent, _, _ = self.run_publisher(responses, heartbeat=0.1, wait_for=5)
        self.assertEqual(["settings_applied" in snapshot for snapshot in sent[:5]], [False, True, False, False, True])

    def test_callback_failure_does_not_stop_delivery(self):
        sent = []

        def sender(snapshot):
            sent.append(snapshot)
            return self.delivered({"accepted": True})
        statuses = []
        publisher = MetricsPublisher(lambda: {}, sender=sender, heartbeat=0.05, min_interval=0.01,
                                     logger=statuses.append, on_payload=mock.Mock(side_effect=RuntimeError("x")),
                                     on_status=mock.Mock(side_effect=RuntimeError("y")))
        publisher.start()
        deadline = time.monotonic() + 3
        while len(sent) < 3 and time.monotonic() < deadline:
            time.sleep(0.02)
        publisher.stop()
        self.assertGreaterEqual(len(sent), 3)
        self.assertIn("[DASHBOARD] metrics status=sent", statuses)
        self.assertNotIn("[DASHBOARD] metrics status=failed", statuses)


class GatewaySnapshotTests(unittest.TestCase):
    """요청마다 찍는 지표 로그·이벤트 메타데이터에는 설정 보고가 없다. 지표 전송기만 싣는다."""

    def test_report_only_in_the_publisher_snapshot(self):
        import gateway
        value, _ = holder(None)
        relay = mock.patch.object(gateway, "fetch_relay_status", return_value={"ok": True, "connected": 0, "registered": 0})
        with mock.patch.object(gateway, "GATEWAY_SETTINGS", value), relay:
            self.assertNotIn("settings_applied", gateway._publisher_snapshot())
            value.offer({"accepted": True, "gateway_settings": settings_doc()})
            self.assertEqual(gateway._publisher_snapshot()["settings_applied"]["revision"], REVISION_1)
            self.assertNotIn("settings_applied", gateway._gateway_metrics_snapshot())
            from gateway_dashboard_metadata import attach_metadata
            event = {"requestId": "r"}
            with mock.patch.dict(os.environ, {"DASHBOARD_EXTENDED_METADATA": "1"}):
                attach_metadata(event, SimpleNamespace(action="allow"), {"contentType": "prompt"},
                                gateway._gateway_metrics_snapshot())
            self.assertNotIn("settings", json.dumps(event))


if __name__ == "__main__":
    unittest.main()


class ModulePathTests(unittest.TestCase):
    """10/11 운영 실측: event_adapter가 상위 폴더를 sys.path 맨 앞에 넣어, 상위 폴더에 남은 옛
    dashboard_event_sender.py가 ~/llm-gateway 것 대신 불려 왔다(새 gateway는 metrics_url이 없어 적재 실패)."""

    def test_stale_copy_in_the_parent_folder_is_not_imported(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            gw = parent / "llm-gateway"
            shutil.copytree(ROOT, gw, ignore=shutil.ignore_patterns("tests", "__pycache__", "var", "*.pyc"))
            (parent / "dashboard_event_sender.py").write_text("STALE = True\n", encoding="utf-8")
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            env.pop("DASHBOARD_EVENT_URL", None)
            env.pop("PYTHONPATH", None)
            code = "import gateway, dashboard_event_sender as d; print(d.__file__)"
            result = subprocess.run([sys.executable, "-c", code], cwd=gw, env=env, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            self.assertEqual(Path(result.stdout.strip().splitlines()[-1]).resolve(),
                             (gw / "dashboard_event_sender.py").resolve())
