"""접속 차단(2026-10-12) - gateway_access 단위 시험 + 실제 mitmproxy flow·훅 + 실제 mitmproxy(DumpMaster).

확장 프로그램 ID 차단(403 JSON·안내 페이지), 예외(llm-gateway.local·127.0.0.1·::1), '확장 ID 없는 접속 차단' 켬/끔,
Gateway 시계로 만료, 문서 검증, 디스크 사본(0600)·시작 때 읽기·손상 사본은 풀린 상태(fail-open),
보안 이벤트 10분 1건, 막은 업로드는 파일 작업 스레드에 가지 않음, access_applied는 문서·사본을 본 뒤에만.
가짜 값만 쓴다(문서용 IP 203.0.113.x·198.51.100.x, 가짜 확장 ID·규칙 번호). Detection·대시보드는 가짜다.
대시보드 백엔드와 같은 규칙인지는 node가 있으면 실제 gateway-access.mjs·validation.mjs로 대조한다
(GW_TEST_DASHBOARD_SERVER_DIR, 없으면 그 시험만 건너뜀).
실행: python -m unittest tests.test_gateway_access -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from mitmproxy.test import tflow, tutils  # noqa: E402

import dashboard_event_sender  # noqa: E402
import gateway  # noqa: E402
import gateway_access as A  # noqa: E402
from dashboard_event_mapper import build_dashboard_event  # noqa: E402
from gateway_access import AccessError, AccessHolder, ConnectionClientIds, parse_access  # noqa: E402
from gateway_client_tracker import ClientTracker  # noqa: E402
from gateway_metrics_delivery import MetricsPublisher  # noqa: E402
from gateway_metrics_ext import MetricsExtNegotiator  # noqa: E402
from gateway_settings import SettingsHolder, env_defaults  # noqa: E402
from tests.gw_support import run_hook, settings_doc  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_SERVER_DIR = bundle.DASHBOARD_SERVER_DIR
METRICS_URL = "http://127.0.0.1:19100/api/traffic/metrics"
IP_A = "203.0.113.10"
IP_B = "198.51.100.20"
CLIENT_A = "chrome-00000000-0000-4000-8000-00000000000a"
CLIENT_B = "chrome-00000000-0000-4000-8000-00000000000b"
RULE_1 = "1a2b3c4d-0000-4000-8000-000000000001"
RULE_2 = "5e6f7a8b-0000-4000-8000-000000000002"
REV_1 = "00000000-0000-4000-8000-0000000000a1"
REV_2 = "00000000-0000-4000-8000-0000000000a2"
T0 = datetime(2026, 10, 12, 5, 0, 0, tzinfo=timezone.utc).timestamp()
IN_1H = "2026-10-12T06:00:00.000Z"          # T0 + 3600 (한국 시각 10/12 15:00)
PAST = "2026-10-12T04:00:00.000Z"
PROMPT_BODY = json.dumps({"action": "next", "messages": [{"author": {"role": "user"}, "content": {
    "content_type": "text", "parts": ["가짜 질문"]}}]}, ensure_ascii=False).encode()
NAVIGATE = ((b"sec-fetch-mode", b"navigate"), (b"sec-fetch-dest", b"document"))


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


def rule(rule_id=RULE_1, client_id=CLIENT_A, expires_at=None):
    return {"id": rule_id, "client_id": client_id, "expires_at": expires_at}


def access_doc(rules=(), require=False, version=1, revision=REV_1, updated_at="2026-10-12T05:00:00.000Z"):
    return {"version": version, "revision": revision, "updated_at": updated_at, "require_client_id": require,
            "rules": [dict(item) if isinstance(item, dict) else item for item in rules]}


def error_field(document):
    try:
        parse_access(document)
    except AccessError as exc:
        return exc.field
    return None


def holder(cache_path=None, url=METRICS_URL, clock=None):
    logs = []
    value = AccessHolder(cache_path=cache_path, metrics_url=url, logger=logs.append, clock=clock or Clock())
    return value, logs


# ------------------------------------------------------------------ 1. 문서 검증

class ValidationTests(unittest.TestCase):
    def test_valid_document(self):
        access = parse_access(access_doc([rule(), rule(RULE_2, CLIENT_B, IN_1H)], require=True, version=7))
        self.assertEqual((access.version, access.revision, access.source, access.require_client_id),
                         (7, REV_1, "DASHBOARD", True))
        self.assertEqual([r.id for r in access.rules], [RULE_1, RULE_2])
        self.assertEqual(access.rules[1].expires_ts, T0 + 3600)
        self.assertTrue(access.applied_at.endswith("Z"))
        self.assertEqual(access.document(), access_doc([rule(), rule(RULE_2, CLIENT_B, IN_1H)], require=True, version=7))

    def test_document_shape(self):
        for document in (None, [], "x", {**access_doc(), "mode": "blocklist"},
                         {k: v for k, v in access_doc().items() if k != "rules"}):
            self.assertEqual(error_field(document), "gateway_access", document)

    def test_top_level_values(self):
        cases = {
            "version": [0, -1, True, "1", 1.0, 2 ** 53],
            "revision": ["ABCDEF00-0000-4000-8000-000000000001", "x", None, 1],
            "updated_at": ["2026-10-12T05:00:00", "2026-13-12T05:00:00Z", "", None, "x" * 51],
            "require_client_id": ["true", 1, None],
        }
        for name, values in cases.items():
            for value in values:
                self.assertEqual(error_field({**access_doc(), name: value}), name, (name, value))
        self.assertEqual(error_field({**access_doc(), "rules": {}}), "rules")
        self.assertEqual(error_field({**access_doc(), "rules": None}), "rules")

    def test_rule_limit(self):
        many = [rule(f"00000000-0000-4000-8000-{n:012x}", f"chrome-{n}") for n in range(A.MAX_RULES)]
        self.assertEqual(len(parse_access(access_doc(many)).rules), 500)
        extra = many + [rule("00000000-0000-4000-8000-ffffffffffff", "chrome-x")]
        self.assertEqual(error_field(access_doc(extra)), "rules")

    def test_rule_values_report_the_rule_index(self):
        good = rule()
        cases = [
            ({**good, "note": "x"}, "rules.1"),
            ({"id": RULE_2, "client_id": CLIENT_B}, "rules.1"),
            ("x", "rules.1"),
            ({**good, "id": RULE_1.upper()}, "rules.1.id"),
            ({**good, "id": RULE_1}, "rules.1.id"),                   # 번호 중복
            ({**good, "id": RULE_2, "client_id": "chrome a"}, "rules.1.client_id"),
            ({**good, "id": RULE_2, "client_id": "-chrome"}, "rules.1.client_id"),
            ({**good, "id": RULE_2, "client_id": "c" * 81}, "rules.1.client_id"),
            ({**good, "id": RULE_2, "client_id": None}, "rules.1.client_id"),
            ({**good, "id": RULE_2, "expires_at": "2026-10-12 06:00:00Z"}, "rules.1.expires_at"),
            ({**good, "id": RULE_2, "expires_at": "2026-10-12T06:00:00"}, "rules.1.expires_at"),
            ({**good, "id": RULE_2, "expires_at": "2026-02-30T06:00:00Z"}, "rules.1.expires_at"),
            ({**good, "id": RULE_2, "expires_at": 1760000000}, "rules.1.expires_at"),
        ]
        for second, field in cases:
            self.assertEqual(error_field(access_doc([good, second])), field, second)
        self.assertIsNone(error_field(access_doc([good, rule(RULE_2, "c" * 80, "2026-10-12T06:00:00+09:00")])))
        self.assertIsNone(error_field(access_doc([good, rule(RULE_2, CLIENT_A, PAST)])))   # 이미 만료돼도 받는다

    def test_shapes_are_checked_before_values(self):
        doc = access_doc([rule(), {"id": "bad"}], version=0)
        self.assertEqual(error_field(doc), "rules.1")
        self.assertEqual(error_field({**access_doc([{**rule(), "id": "bad"}]), "version": 0}), "version")

    def test_iso_timestamps(self):
        self.assertEqual(A.iso_timestamp("2026-10-12T05:00:00.000Z"), T0)
        self.assertEqual(A.iso_timestamp("2026-10-12T14:00:00+09:00"), T0)
        self.assertEqual(A.iso_timestamp("2026-10-12T05:00Z"), T0)
        self.assertAlmostEqual(A.iso_timestamp("2026-10-12T05:00:00.123456789Z"), T0 + 0.123456, places=5)
        for value in ("2026-10-12", "2026-10-12T25:00:00Z", None, 5, "2026-10-12T05:00:00.Z"):
            self.assertIsNone(A.iso_timestamp(value), value)


# ------------------------------------------------------------------ 2. 판단

class DecisionTests(unittest.TestCase):
    def test_expiry_follows_the_gateway_clock(self):
        access = parse_access(access_doc([rule(expires_at=IN_1H)]))
        self.assertEqual(access.match(CLIENT_A, T0 + 3599.999).id, RULE_1)
        self.assertIsNone(access.match(CLIENT_A, T0 + 3600))
        self.assertIsNone(access.match(CLIENT_B, T0))
        self.assertEqual(access.active_count(T0), 1)
        self.assertEqual(access.active_count(T0 + 3600), 0)

    def test_permanent_and_overlapping_rules(self):
        access = parse_access(access_doc([rule(RULE_1, CLIENT_A, IN_1H), rule(RULE_2, CLIENT_A, None)]))
        self.assertEqual(access.match(CLIENT_A, T0 + 10 ** 6).id, RULE_2)
        self.assertEqual(access.match(CLIENT_A, T0).id, RULE_2)       # 영구가 먼저
        later = parse_access(access_doc([rule(RULE_1, CLIENT_A, IN_1H),
                                         rule(RULE_2, CLIENT_A, "2026-10-13T05:00:00.000Z")]))
        self.assertEqual(later.match(CLIENT_A, T0).id, RULE_2)

    def test_decide(self):
        blocked = parse_access(access_doc([rule()]))
        both = parse_access(access_doc([rule()], require=True))
        require = parse_access(access_doc([], require=True))
        decide = A.decide
        self.assertEqual(decide(blocked, CLIENT_A, navigation=False, preflight=False, now=T0).reason_code,
                         "client_blocked")
        self.assertEqual(decide(blocked, CLIENT_A, navigation=True, preflight=True, now=T0).rule.id, RULE_1)
        self.assertIsNone(decide(blocked, CLIENT_B, navigation=False, preflight=False, now=T0))
        self.assertIsNone(decide(blocked, None, navigation=False, preflight=False, now=T0))
        missing = decide(require, None, navigation=False, preflight=False, now=T0)
        self.assertEqual((missing.reason_code, missing.rule, missing.client_id), ("client_id_missing", None, None))
        self.assertIsNone(decide(require, None, navigation=True, preflight=False, now=T0))
        self.assertIsNone(decide(require, None, navigation=False, preflight=True, now=T0))
        self.assertIsNone(decide(require, CLIENT_B, navigation=False, preflight=False, now=T0))
        self.assertEqual(decide(both, CLIENT_A, navigation=False, preflight=False, now=T0).reason_code, "client_blocked")
        self.assertFalse(A.EMPTY.enforcing)
        self.assertTrue(require.enforcing and blocked.enforcing)

    def test_request_kinds(self):
        nav = {"sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}
        self.assertTrue(A.top_level_navigation("GET", nav))
        self.assertTrue(A.top_level_navigation("head", nav))
        self.assertFalse(A.top_level_navigation("POST", nav))                      # 폼 전송 화면 이동은 막는다
        self.assertFalse(A.top_level_navigation("GET", {**nav, "sec-fetch-dest": "iframe"}))
        self.assertFalse(A.top_level_navigation("GET", {"sec-fetch-mode": "cors", "sec-fetch-dest": "empty"}))
        self.assertFalse(A.top_level_navigation("GET", {}))
        self.assertTrue(A.cors_preflight("OPTIONS", {"access-control-request-method": "POST"}))
        self.assertFalse(A.cors_preflight("OPTIONS", {}))

    def test_exempt_peers(self):
        for ip in ("127.0.0.1", "127.5.6.7", "::1", "::ffff:127.0.0.1", "::1%lo"):
            self.assertTrue(A.exempt_peer(ip), ip)
        for ip in (IP_A, "10.0.0.1", "::ffff:203.0.113.10", None, "", "not-an-ip"):
            self.assertFalse(A.exempt_peer(ip), ip)

    def test_connection_ids(self):
        ids = ConnectionClientIds(max_entries=2)
        ids.remember("c1", CLIENT_A)
        ids.remember("c2", CLIENT_B)
        ids.remember(None, CLIENT_A)
        self.assertEqual((ids.get("c1"), ids.get("c2"), ids.get(None)), (CLIENT_A, CLIENT_B, None))
        ids.remember("c3", CLIENT_A)
        self.assertEqual((len(ids), ids.get("c1")), (2, None))              # 상한: 오래된 것부터
        ids.forget("c2")
        self.assertIsNone(ids.get("c2"))


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.access = parse_access(access_doc([rule(expires_at=IN_1H), rule(RULE_2, CLIENT_B)]))

    def test_json_response(self):
        decision = A.AccessDecision("client_blocked", self.access.rules[0], CLIENT_A)
        response = A.block_response(decision, "req-1", navigate=False)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(json.loads(response.content), {"error": {
            "type": "access_blocked", "message": "관리자에 의해 LLM 사용이 제한되었습니다.",
            "reason_code": "client_blocked", "request_id": "req-1"}})

    def test_html_page(self):
        decision = A.AccessDecision("client_blocked", self.access.rules[0], CLIENT_A)
        response = A.block_response(decision, "req-1", navigate=True)
        page = response.content.decode("utf-8")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["content-type"], "text/html; charset=utf-8")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("default-src 'none'", response.headers["content-security-policy"])
        self.assertIn("<title>LLM 사용 제한</title>", page)
        self.assertIn('lang="ko"', page)
        self.assertIn("관리자에 의해 LLM 사용이 제한되었습니다.", page)
        self.assertIn("<dd>1a2b3c4d</dd>", page)                          # 규칙 번호 앞 8자
        self.assertIn("<dd>10/12 15:00</dd>", page)                       # 해제 예정(한국 시각)
        self.assertNotIn(RULE_1, page)
        self.assertNotIn(CLIENT_A, page)
        for external in ("<script", "<link", "<img", "src=", "href=", "url(", "http://", "https://", "@import"):
            self.assertNotIn(external, page)
        permanent = A.block_response(A.AccessDecision("client_blocked", self.access.rules[1], CLIENT_B), "r", navigate=True)
        self.assertIn("<dd>관리자 해제 시</dd>", permanent.content.decode("utf-8"))
        missing = A.block_response(A.AccessDecision("client_id_missing"), "r", navigate=True).content.decode("utf-8")
        self.assertNotIn("차단 번호", missing)
        self.assertIn("<dd>관리자 해제 시</dd>", missing)


class CounterTests(unittest.TestCase):
    def test_event_limiter_ten_minutes_per_key(self):
        clock = Clock()
        limiter = A.EventLimiter(clock=clock, max_keys=3)
        self.assertTrue(limiter.allow(("r", "a")))
        self.assertFalse(limiter.allow(("r", "a")))
        self.assertTrue(limiter.allow(("r", "b")))
        clock.now += 599.9
        self.assertFalse(limiter.allow(("r", "a")))
        clock.now += 0.1
        self.assertTrue(limiter.allow(("r", "a")))
        for key in ("c", "d", "e"):
            limiter.allow(("r", key))
        self.assertLessEqual(len(limiter._seen), 3)

    def test_denied_counter_five_minute_window(self):
        clock = Clock()
        counter = A.DeniedCounter(clock=clock)
        for _ in range(3):
            counter.add()
        clock.now += 100
        counter.add()
        self.assertEqual(counter.count(), 4)
        clock.now += 200
        self.assertEqual(counter.count(), 1)
        clock.now += 100
        self.assertEqual(counter.count(), 0)


# ------------------------------------------------------------------ 3. 보관·사본·보고

class HolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gw-access-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cache = self.tmp / "var" / "gateway-access.json"

    def test_starts_empty_without_a_report(self):
        value, logs = holder(self.cache)
        self.assertEqual(value.current().source, "NONE")
        self.assertEqual(logs, ["[ACCESS] source=NONE version=- rules=0 require_client_id=false"])
        self.assertEqual(value.report_field(), {})

    def test_offer_replaces_only_when_version_or_revision_differs(self):
        value, logs = holder(self.cache)
        changes = []
        value.set_on_change(lambda: changes.append(1))
        value.offer({"accepted": True, "gateway_access": access_doc([rule()], version=3)})
        first = value.current()
        value.offer({"gateway_access": access_doc([rule()], version=3)})
        self.assertIs(value.current(), first)
        value.offer({"gateway_access": access_doc([rule(), rule(RULE_2, CLIENT_B)], version=3, revision=REV_2)})
        self.assertEqual(len(value.current().rules), 2)
        value.offer({"gateway_access": access_doc([], version=1, revision=REV_1)})   # 번호가 작아져도 따른다
        self.assertEqual((value.current().version, value.current().rules), (1, ()))
        self.assertEqual(len(changes), 3)
        self.assertEqual(sum("[ACCESS] applied" in line for line in logs), 3)
        self.assertFalse(any(CLIENT_A in line or CLIENT_B in line for line in logs))

    def test_invalid_document_is_rejected_kept_out_and_cleared_by_the_next_good_one(self):
        value, logs = holder(self.cache)
        value.offer({"gateway_access": access_doc([rule()])})
        good = value.current()
        bad = access_doc([rule(), rule(RULE_2, "bad id")], version=2, revision=REV_2)
        for _ in range(3):
            value.offer({"gateway_access": bad})
        self.assertIs(value.current(), good)
        self.assertEqual(value.report()["rejected"], "rules.1.client_id")
        self.assertEqual([line for line in logs if "rejected" in line],
                         ["[ACCESS] rejected version=2 field=rules.1.client_id"])
        value.offer({"gateway_access": access_doc([rule()])})                 # 같은 판 다시 확인
        self.assertIsNone(value.report()["rejected"])
        value.offer({"gateway_access": "x"})
        self.assertEqual(value.report()["rejected"], "gateway_access")
        value.offer({"gateway_access": None})
        self.assertIsNone(value.report()["rejected"])

    def test_null_clears_and_removes_the_cache(self):
        value, logs = holder(self.cache)
        value.offer({"gateway_access": access_doc([rule()], require=True)})
        self.assertTrue(self.cache.exists())
        value.offer({"gateway_access": None})
        current = value.current()
        self.assertEqual((current.source, current.rules, current.require_client_id, current.version), ("NONE", (), False, None))
        self.assertFalse(self.cache.exists())
        self.assertIn("[ACCESS] cleared source=NONE", logs)
        report = value.report()
        self.assertEqual((report["version"], report["revision"], report["applied_at"], report["source"]),
                         (None, None, None, "NONE"))

    def test_payload_without_the_field_changes_nothing(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_access": access_doc([rule()])})
        current = value.current()
        for payload in ({"accepted": True}, None, [], "x", {"gateway_settings": settings_doc()}):
            value.offer(payload)
        self.assertIs(value.current(), current)

    def test_cache_is_private_and_reloaded_after_restart(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_access": access_doc([rule(expires_at=IN_1H)], require=True, version=4)})
        text = self.cache.read_text(encoding="utf-8")
        self.assertEqual(set(json.loads(text)), {"metrics_url_sha256", "document"})
        self.assertNotIn(METRICS_URL, text)
        if os.name == "posix":
            self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.cache.parent.glob("*.tmp")), [])
        restarted, logs = holder(self.cache)
        current = restarted.current()
        self.assertEqual((current.source, current.version, current.require_client_id, current.rules[0].id),
                         ("CACHE", 4, True, RULE_1))
        self.assertEqual(logs, ["[ACCESS] source=CACHE version=4 rules=1 require_client_id=true"])
        self.assertEqual(restarted.report_field()["access_applied"]["source"], "CACHE")   # 사본을 읽었으면 바로 보고
        restarted.offer({"gateway_access": access_doc([rule(expires_at=IN_1H)], require=True, version=4)})
        self.assertEqual(restarted.current().source, "DASHBOARD")

    def test_broken_or_foreign_cache_runs_unblocked_with_a_warning(self):
        value, _ = holder(self.cache)
        value.offer({"gateway_access": access_doc([rule()], require=True)})
        foreign, logs = holder(self.cache, url="http://127.0.0.1:9/api/traffic/metrics")
        self.assertEqual((foreign.current().source, foreign.current().enforcing), ("NONE", False))
        self.assertIn("[ACCESS] WARNING cache ignored; running without access rules reason=other_dashboard", logs)
        self.assertEqual(foreign.report_field(), {})
        self.cache.write_text("{not json", encoding="utf-8")
        broken, logs = holder(self.cache)
        self.assertFalse(broken.current().enforcing)
        self.assertIn("[ACCESS] WARNING cache ignored; running without access rules reason=JSONDecodeError", logs)
        stored = {"metrics_url_sha256": hashlib.sha256(METRICS_URL.encode()).hexdigest(),
                  "document": access_doc([rule(client_id="bad id")])}
        self.cache.write_text(json.dumps(stored), encoding="utf-8")
        invalid, logs = holder(self.cache)
        self.assertFalse(invalid.current().enforcing)
        self.assertIn("[ACCESS] WARNING cache ignored; running without access rules reason=invalid "
                      "field=rules.0.client_id", logs)
        self.cache.write_bytes(b"\xff\xfe\x00")
        undecodable, logs = holder(self.cache)
        self.assertFalse(undecodable.current().enforcing)
        self.assertTrue(any("WARNING cache ignored" in line for line in logs))

    def test_no_dashboard_means_no_cache(self):
        value, _ = holder(self.cache, url=None)
        value.offer({"gateway_access": access_doc([rule()])})
        self.assertFalse(self.cache.exists())
        self.assertEqual(value.current().source, "DASHBOARD")

    def test_report_shape_and_gating(self):
        clock = Clock()
        value, logs = holder(None, clock=clock)
        self.assertEqual(value.report_field(), {})
        value.offer({"accepted": True, "gateway_access": None})                 # 새 대시보드, 저장 없음
        self.assertEqual(value.report_field(), {"access_applied": {
            "version": None, "revision": None, "source": "NONE", "applied_at": None, "rejected": None,
            "active_rules": 0, "require_client_id": False, "denied_5m": 0}})
        value.offer({"gateway_access": access_doc([rule(expires_at=IN_1H), rule(RULE_2, CLIENT_B)], require=True,
                                                  version=5)})
        value.note_denied()
        value.note_denied()
        report = value.report_field()["access_applied"]
        self.assertEqual({k: report[k] for k in ("version", "revision", "source", "rejected", "active_rules",
                                                 "require_client_id", "denied_5m")},
                         {"version": 5, "revision": REV_1, "source": "DASHBOARD", "rejected": None, "active_rules": 2,
                          "require_client_id": True, "denied_5m": 2})
        self.assertRegex(report["applied_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        clock.now += 3600
        self.assertEqual(value.report()["active_rules"], 1)                    # Gateway 시계로 만료
        clock.now += 300
        self.assertEqual(value.report()["denied_5m"], 0)
        value.on_metrics_status(400)                                             # 실은 전송이 400
        self.assertEqual(value.report_field(), {})
        value.on_metrics_status(400)
        value.offer({"accepted": True})                                          # 옛 대시보드 응답: 계속 뺀다
        self.assertEqual(value.report_field(), {})
        value.offer({"accepted": True, "gateway_access": access_doc([], version=6)})
        self.assertEqual(value.report_field()["access_applied"]["version"], 6)
        self.assertEqual(sum("report omitted" in line for line in logs), 1)
        json.dumps(value.report_field())

    def test_400_without_a_report_in_that_request_keeps_the_report(self):
        value, _ = holder(None)
        value.report_field()                                                     # 칸 전: 싣지 않음
        value.offer({"gateway_access": access_doc()})
        value.on_metrics_status(400)                                             # 보고를 싣지 않은 전송의 400
        self.assertIn("access_applied", value.report_field())

    def test_readers_always_see_one_whole_version(self):
        value, _ = holder(None)
        documents = [access_doc([rule()], require=False, version=1, revision=REV_1),
                     access_doc([rule(RULE_2, CLIENT_B)], require=True, version=2, revision=REV_2)]
        allowed = {(1, RULE_1, False), (2, RULE_2, True)}
        stop, bad, seen = threading.Event(), [], set()

        def read():
            while not stop.is_set():
                current = value.current()
                if current.version is None:
                    continue
                key = (current.version, current.rules[0].id, current.require_client_id)
                seen.add(key)
                if key not in allowed:
                    bad.append(key)
        readers = [threading.Thread(target=read) for _ in range(4)]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + 0.5
        index = 0
        while (time.monotonic() < deadline or len(seen) < 2) and time.monotonic() < deadline + 5:
            value.offer({"gateway_access": documents[index % 2]})
            index += 1
            time.sleep(0.0005)
        stop.set()
        for reader in readers:
            reader.join()
        self.assertEqual(bad, [])
        self.assertEqual(seen, allowed)


# ------------------------------------------------------------------ 4. 실제 mitmproxy flow·훅

class FlowBase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.logs = []
        self.access = AccessHolder(cache_path=None, metrics_url=None, logger=self.logs.append, clock=self.clock)
        self.detection_calls, self.queued, self.extension = [], [], []
        self.output = io.StringIO()
        self.tracker = ClientTracker(clock=self.clock)
        self.upload_submits = []
        original_submit = gateway._submit_file_work

        def submit(fn, *args):
            self.upload_submits.append(fn.__name__)
            return original_submit(fn, *args)
        patches = [
            mock.patch.object(gateway, "GATEWAY_ACCESS", self.access),
            mock.patch.object(gateway, "_access_connection_ids", ConnectionClientIds()),
            mock.patch.object(gateway, "_client_tracker", self.tracker),
            mock.patch.object(gateway, "check_detection", bundle.fake_detection(self.detection_calls)),
            mock.patch.object(gateway, "send_to_next_module", lambda event: None),
            mock.patch.object(gateway, "dashboard_integration_enabled", lambda: True),
            mock.patch.object(gateway._gateway_event_outbox, "enqueue",
                              lambda event: self.queued.append(event) or SimpleNamespace(status="queued")),
            mock.patch.object(gateway, "send_extension_event", lambda event: self.extension.append(event)),
            mock.patch.object(gateway, "fetch_relay_status", return_value={"ok": True, "connected": 0, "registered": 0}),
            mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None),
            mock.patch.object(gateway, "_submit_file_work", submit),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        gateway._dedupe_seen.clear()

    def use(self, rules=(), require=False, version=1, revision=REV_1):
        self.access.offer({"gateway_access": access_doc(rules, require=require, version=version, revision=revision)})

    def make(self, *, host="chatgpt.com", method=b"POST", path=b"/backend-api/f/conversation", content=PROMPT_BODY,
             headers=(), client=CLIENT_A, peer=IP_A, conn=None, content_type=b"application/json"):
        items = [(b"content-type", content_type)] if content_type else []
        items += list(headers)
        if client:
            items.append((b"x-llmsgw-client-id", client.encode()))
        req = tutils.treq(host=host, port=443, scheme=b"https", method=method, path=path, content=content,
                          headers=tuple(items))
        flow = tflow.tflow(req=req, client_conn=conn)
        flow.client_conn.peername = (peer, 50123)
        return flow

    def send(self, flow, *, finish=True):
        """request 훅 → (mitmproxy처럼) 응답이 정해졌으면 response 훅. 통과한 요청은 upstream 200을 흉내."""
        with contextlib.redirect_stdout(self.output):
            gateway.client_connected(flow.client_conn)
            run_hook(gateway.request(flow))
            if finish:
                if flow.response is None:
                    flow.forwarded = True
                    flow.response = tutils.tresp(status_code=200)
                gateway.response(flow)
        return flow

    def claude_upload(self, **kwargs):
        boundary = "----gwaccess"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"memo.txt\"\r\n"
                f"Content-Type: text/plain\r\n\r\n").encode() + "회의 메모".encode() + f"\r\n--{boundary}--\r\n".encode()
        return self.make(host="claude.ai", path=bundle.CLAUDE_UPLOAD_PATH.encode(), content=body,
                         content_type=f"multipart/form-data; boundary={boundary}".encode(), **kwargs)


class FlowTests(FlowBase):
    def test_blocked_client_gets_403_json_without_detection_or_metrics(self):
        self.use([rule()])
        before = (gateway._gateway_metrics["total_requests"], len(gateway._gateway_latencies_ms))
        flow = self.send(self.make())
        self.assertEqual(flow.response.status_code, 403)
        body = json.loads(flow.response.content)
        self.assertEqual(body["error"]["type"], "access_blocked")
        self.assertEqual(body["error"]["reason_code"], "client_blocked")
        self.assertEqual(body["error"]["message"], "관리자에 의해 LLM 사용이 제한되었습니다.")
        self.assertEqual(body["error"]["request_id"], flow.metadata["gw_request_id"])
        self.assertFalse(getattr(flow, "forwarded", False))
        self.assertEqual(self.detection_calls, [])
        self.assertNotIn("gw_metrics_started_at", flow.metadata)
        self.assertEqual((gateway._gateway_metrics["total_requests"], len(gateway._gateway_latencies_ms)), before)
        self.assertEqual(self.access.report()["denied_5m"], 1)
        self.assertNotIn(CLIENT_A, self.output.getvalue())                  # 로그에 확장 ID·IP 없음
        self.assertIn("[ACCESS] denied reason=client_blocked rule=1a2b3c4d navigate=no event=recorded", self.output.getvalue())
        self.assertNotIn(IP_A, self.output.getvalue())

    def test_navigation_gets_the_html_page(self):
        self.use([rule(expires_at=IN_1H)])
        flow = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None,
                                  headers=((b"sec-fetch-mode", b"navigate"), (b"sec-fetch-dest", b"iframe"))))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.headers["content-type"], "text/html; charset=utf-8")
        self.assertEqual(flow.response.headers["cache-control"], "no-store")
        page = flow.response.content.decode("utf-8")
        self.assertIn("<title>LLM 사용 제한</title>", page)
        self.assertIn("<dd>1a2b3c4d</dd>", page)
        self.assertIn("<dd>10/12 15:00</dd>", page)

    def test_other_clients_on_the_same_ip_pass(self):
        self.use([rule()])
        flow = self.send(self.make(client=CLIENT_B))
        self.assertTrue(flow.forwarded)
        self.assertEqual(len(self.detection_calls), 1)
        self.assertNotIn("x-llmsgw-client-id", flow.request.headers)      # 지금처럼 지우고 보낸다
        self.assertEqual(self.access.report()["denied_5m"], 0)

    def test_exempt_hosts_and_loopback(self):
        self.use([rule()], require=True)
        health = self.send(self.make(host="llm-gateway.local", method=b"GET", path=b"/__llmsgw/health", content=b""))
        self.assertEqual(health.response.status_code, 200)
        self.assertEqual(json.loads(health.response.content)["status"], "ok")
        bare = self.send(self.make(host="llm-gateway.local", method=b"GET", path=b"/__llmsgw/health", content=b"",
                                  client=None))
        self.assertEqual(bare.response.status_code, 200)
        relay = self.send(self.make(host="llm-gateway.local", method=b"GET", path=b"/__llmsgw/my/requests", content=b""))
        self.assertEqual(relay.response.status_code, 401)                 # 지금과 같은 중계 응답(열람 키 없음)
        for peer in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            flow = self.send(self.make(peer=peer))
            self.assertTrue(flow.forwarded, peer)
            flow = self.send(self.make(peer=peer, client=None))
            self.assertTrue(flow.forwarded, peer)
        spoofed = self.send(self.make(host="chatgpt.com", headers=((b"host", b"llm-gateway.local"),)))
        self.assertEqual(spoofed.response.status_code, 403)              # 예외는 실제 목적지 기준
        self.assertEqual(self.access.report()["denied_5m"], 1)

    def test_require_client_id_on_and_off(self):
        flow = self.send(self.make(client=None))
        self.assertTrue(flow.forwarded)                                  # 목록 없음: 지금처럼
        self.detection_calls.clear()
        self.use([], require=True)
        flow = self.send(self.make(client=None))
        self.assertEqual((flow.response.status_code, json.loads(flow.response.content)["error"]["reason_code"]),
                         (403, "client_id_missing"))
        self.assertEqual(self.detection_calls, [])
        flow = self.send(self.make(client="bad id!"))                     # 형식이 틀린 ID = 없음
        self.assertEqual(flow.response.status_code, 403)
        flow = self.send(self.make(client=CLIENT_B))
        self.assertTrue(flow.forwarded)
        page = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None, client=None,
                                  headers=NAVIGATE))
        self.assertTrue(page.forwarded)                                  # 최상위 페이지(확장이 머리를 못 붙임)
        form = self.send(self.make(path=b"/", client=None, headers=NAVIGATE))
        self.assertEqual(form.response.headers["content-type"], "text/html; charset=utf-8")   # POST 화면 이동은 막음
        preflight = self.send(self.make(method=b"OPTIONS", content=b"", content_type=None, client=None,
                                       headers=((b"access-control-request-method", b"POST"),)))
        self.assertTrue(preflight.forwarded)
        other = self.send(self.make(host="example.org", path=b"/", client=None))
        self.assertEqual(other.response.status_code, 403)                # LLM 밖 목적지도(이벤트는 없음)
        self.use([], require=False, version=2)
        flow = self.send(self.make(client=None))
        self.assertTrue(flow.forwarded)

    def test_expiry_by_the_gateway_clock(self):
        self.use([rule(expires_at=IN_1H)])
        self.clock.now = T0 + 3599
        self.assertEqual(self.send(self.make()).response.status_code, 403)
        self.clock.now = T0 + 3600
        self.assertTrue(self.send(self.make()).forwarded)

    def test_navigation_uses_the_id_seen_earlier_on_the_same_connection(self):
        self.use([rule()])
        first = self.send(self.make(client=CLIENT_A, method=b"GET", path=b"/backend-api/me", content=b""))
        self.assertEqual(first.response.status_code, 403)
        nav = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None, client=None,
                                 headers=NAVIGATE, conn=first.client_conn))
        self.assertEqual((nav.response.status_code, nav.response.headers["content-type"]),
                         (403, "text/html; charset=utf-8"))
        fresh = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None, client=None, headers=NAVIGATE))
        self.assertTrue(fresh.forwarded)                                 # 새 연결: ID를 모름 → 통과
        with contextlib.redirect_stdout(self.output):
            gateway.client_disconnected(first.client_conn)
        again = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None, client=None,
                                   headers=NAVIGATE, conn=first.client_conn))
        self.assertTrue(again.forwarded)                                 # 끊긴 연결의 ID는 지움

    def test_blocked_uploads_never_reach_the_worker_pool(self):
        self.use([rule()])
        flow = self.send(self.claude_upload())
        self.assertTrue(gateway.is_file_upload_request(flow))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.upload_submits, [])
        self.assertEqual(self.detection_calls, [])
        self.assertEqual(self.queued[0]["contentType"], "file")
        allowed = self.send(self.claude_upload(client=CLIENT_B))
        self.assertEqual(self.upload_submits, ["_run_file_request"])     # 막히지 않은 업로드는 지금처럼
        self.assertTrue(allowed.forwarded)

    def test_security_event_shape_and_ten_minute_dedupe(self):
        self.use([rule()])
        self.send(self.make())
        self.assertEqual(len(self.queued), 1)
        event = self.queued[0]
        self.assertEqual({k: event.get(k) for k in ("finalAction", "recommendedAction", "reasonCode", "accessRuleId",
                                                    "detectionOutcome", "degraded", "contentType", "clientId",
                                                    "targetLlm", "enforcement", "detections")},
                         {"finalAction": "BLOCK", "recommendedAction": "BLOCK", "reasonCode": "client_blocked",
                          "accessRuleId": RULE_1, "detectionOutcome": "UNAVAILABLE", "degraded": False,
                          "contentType": "prompt", "clientId": CLIENT_A, "targetLlm": "ChatGPT",
                          "enforcement": {"applied": True, "httpStatus": 403}, "detections": []})
        self.assertNotIn("processingMs", event)                          # 지연 표본에 넣지 않음
        self.assertNotIn("failurePolicy", event)
        self.assertEqual(len(self.extension), 1)                          # 확장 프로그램 알림(기존 중계)
        self.assertEqual((self.extension[0]["clientId"], self.extension[0]["notify"]), (CLIENT_A, True))
        for _ in range(3):
            self.assertEqual(self.send(self.make()).response.status_code, 403)
        self.clock.now += 599
        self.send(self.make(method=b"GET", path=b"/", content=b"", headers=NAVIGATE))
        self.assertEqual((len(self.queued), len(self.extension)), (1, 1))    # 같은 규칙·확장 ID: 10분에 1건
        self.assertIn("event=suppressed", self.output.getvalue())
        self.clock.now += 1
        self.send(self.make())
        self.assertEqual(len(self.queued), 2)
        self.assertEqual(self.access.report()["denied_5m"], 2)            # T0의 4건은 5분이 지나 빠짐

    def test_missing_id_events_are_per_ip_and_have_no_rule(self):
        self.use([], require=True)
        self.send(self.make(client=None))
        self.send(self.make(client=None))
        self.send(self.make(client=None, peer=IP_B, host="claude.ai", path=bundle.COMPLETION_PATH.encode()))
        self.assertEqual(len(self.queued), 2)
        first, second = self.queued
        self.assertEqual((first["reasonCode"], first["clientId"], first["targetLlm"]),
                         ("client_id_missing", "unknown-client", "ChatGPT"))
        self.assertNotIn("accessRuleId", first)
        self.assertEqual((second["targetLlm"], second["detectionOutcome"]), ("Claude", "UNAVAILABLE"))
        self.assertEqual(self.access.report()["denied_5m"], 3)

    def test_viewer_key_fingerprint_is_kept_for_my_requests(self):
        self.use([rule()])
        key = "A" * 43
        flow = self.send(self.make(headers=((b"x-llmsgw-viewer-key", key.encode()),)))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.queued[0]["viewerKeyHash"], hashlib.sha256(key.encode()).hexdigest())

    def test_blocked_client_id_is_noted_in_the_connected_ip_table(self):
        self.use([rule()])
        self.send(self.make())
        row = {r["ip"]: r for r in self.tracker.snapshot()}[IP_A]
        self.assertEqual((row["client_id"], row["requests_5m"], row["inflight"]), (CLIENT_A, 0, 0))

    def test_check_failure_passes_the_request(self):
        self.use([rule()])
        with mock.patch.object(self.access, "current", side_effect=RuntimeError("boom")),                 mock.patch.object(gateway, "_access_failure_logged_at", 0.0):
            flow = self.send(self.make())
            self.assertTrue(flow.forwarded)
            self.send(self.make())
        self.assertEqual(self.output.getvalue().count("[ACCESS] WARNING check failed; request passed error_type=RuntimeError"), 1)

    def test_event_failure_still_blocks(self):
        self.use([rule()])
        with mock.patch.object(gateway, "_report_access_event", side_effect=RuntimeError("x")):
            flow = self.send(self.make())
        self.assertEqual(flow.response.status_code, 403)
        self.assertIn("[ACCESS] event omitted error_type=RuntimeError", self.output.getvalue())


class PublisherTests(FlowBase):
    def test_publisher_payload_has_access_applied_only_after_a_document(self):
        self.assertNotIn("access_applied", gateway._publisher_snapshot())
        self.use([rule()], version=3)
        snapshot = gateway._publisher_snapshot()
        self.assertEqual(snapshot["access_applied"]["version"], 3)
        self.assertNotIn("access_applied", gateway._gateway_metrics_snapshot())   # 요청마다 찍는 지표 로그에는 없음
        json.dumps(snapshot)

    def test_publisher_payload_has_access_applied_after_a_cache_at_start(self):
        tmp = Path(tempfile.mkdtemp(prefix="gw-access-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        first, _ = holder(tmp / "a.json")
        first.offer({"gateway_access": access_doc([rule()], version=8)})
        restarted, _ = holder(tmp / "a.json")
        with mock.patch.object(gateway, "GATEWAY_ACCESS", restarted):
            report = gateway._publisher_snapshot()["access_applied"]
        self.assertEqual((report["source"], report["version"], report["active_rules"]), ("CACHE", 8, 1))

    def test_one_metrics_response_feeds_both_settings_and_access(self):
        settings = SettingsHolder(env_defaults({}), cache_path=None, metrics_url=None, logger=lambda m: None)
        sent = []
        responses = [dashboard_event_sender.DeliveryResult(status="sent", http_status=202, payload={
            "accepted": True, "gateway_settings": settings_doc(version=2),
            "gateway_access": access_doc([rule()], version=4)})]
        publisher = MetricsPublisher(lambda: {**settings.report_field(), **self.access.report_field()},
                                     sender=lambda s: sent.append(s) or responses[0], heartbeat=30, min_interval=0.05,
                                     logger=lambda m: None,
                                     on_payload=gateway._each(settings.offer, self.access.offer),
                                     on_status=gateway._each(settings.on_metrics_status, self.access.on_metrics_status))
        self.access.set_on_change(publisher.notify)
        publisher.start()
        deadline = time.monotonic() + 5
        while len(sent) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        publisher.stop()
        self.assertEqual(set(sent[0]) & {"settings_applied", "access_applied"}, set())
        self.assertEqual((sent[1]["settings_applied"]["version"], sent[1]["access_applied"]["version"]), (2, 4))

    def test_a_failing_handler_does_not_block_the_other(self):
        calls = []
        deliver = gateway._each(mock.Mock(side_effect=RuntimeError("x")), calls.append)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            deliver({"gateway_access": None})
        self.assertEqual(calls, [{"gateway_access": None}])
        self.assertIn("metrics response handling failed error_type=RuntimeError", out.getvalue())

    def test_module_publisher_feeds_the_access_holder(self):
        # 운영 전송기(_gateway_metrics_publisher)가 시작 때 만든 GATEWAY_ACCESS에도 응답을 넘기는지
        # 2026-10-15: 지표 확장 칸 협상기(metrics_ext)도 같은 응답을 받는다(설정·접속 차단 다음, tests/test_gateway_metrics_ext.py)
        for callback in (gateway._gateway_metrics_publisher._on_payload, gateway._gateway_metrics_publisher._on_status):
            handlers = callback.__closure__[0].cell_contents
            self.assertEqual([type(handler.__self__) for handler in handlers],
                             [SettingsHolder, AccessHolder, MetricsExtNegotiator])


class AccessMapperTests(unittest.TestCase):
    def build(self, **overrides):
        values = dict(request_id="r1", reason_code="client_blocked", access_rule_id=RULE_1)
        values.update(overrides)
        return build_dashboard_event(result=A.AccessBlockResult(**values), request_id="r1",
                                     identity={"client_id": CLIENT_A}, target_llm="Gemini", host="gemini.google.com",
                                     endpoint="/", content_type="prompt", enforcement_applied=True, http_status=403)

    def test_access_reasons_map_to_unavailable_with_the_rule_id(self):
        event, reason = self.build()
        self.assertIsNone(reason)
        self.assertEqual((event["detectionOutcome"], event["degraded"], event["accessRuleId"], event["finalAction"]),
                         ("UNAVAILABLE", False, RULE_1, "BLOCK"))
        event, _ = self.build(reason_code="client_id_missing", access_rule_id=None)
        self.assertEqual((event["detectionOutcome"], event["reasonCode"]), ("UNAVAILABLE", "client_id_missing"))
        self.assertNotIn("accessRuleId", event)
        event, _ = self.build(access_rule_id=RULE_1.upper())
        self.assertNotIn("accessRuleId", event)                           # 대시보드는 소문자 UUID만 받는다
        event, _ = self.build(reason_code="client_id_missing", access_rule_id=RULE_1)
        self.assertNotIn("accessRuleId", event)                           # client_blocked일 때만


# ------------------------------------------------------------------ 5. 실제 mitmproxy(DumpMaster)

class RealProxyTests(unittest.TestCase):
    """실제 mitmproxy에 gateway를 올린다. 시험 연결은 127.0.0.1에서 오므로(늘 예외) 막는 시험은 접속 IP 예외만 끈다."""

    def setUp(self):
        from tests.test_gateway_file_worker import FakeDetection, ProxyRig
        self.FakeDetection, self.ProxyRig = FakeDetection, ProxyRig
        self.access, _ = holder(None, url=None, clock=time.time)
        self.access.offer({"gateway_access": access_doc([rule()])})

    def call(self, rig, method, url, headers):
        host = url.split("/")[2]
        conn = http.client.HTTPConnection("127.0.0.1", rig.port, timeout=15)
        try:
            body = b"{}" if method == "POST" else None
            conn.request(method, url, body=body, headers={"Host": host, "Connection": "close", **headers})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_blocked_id_through_a_real_proxy(self):
        detection = self.FakeDetection()
        with mock.patch.object(gateway, "GATEWAY_ACCESS", self.access), \
                mock.patch.object(gateway, "access_exempt_peer", lambda ip: False), \
                self.ProxyRig(self, detection) as rig:
            fetch = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                              {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_A})
            page = self.call(rig, "GET", "http://chatgpt.com/",
                             {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe", "X-LLMSGW-Client-ID": CLIENT_A})
            health = self.call(rig, "GET", "http://llm-gateway.local/__llmsgw/health", {"X-LLMSGW-Client-ID": CLIENT_A})
            other = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                              {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_B})
        self.assertEqual(fetch[0], 403)
        self.assertEqual(json.loads(fetch[2])["error"]["reason_code"], "client_blocked")
        self.assertEqual(page[0], 403)
        self.assertTrue(page[1].get("content-type", page[1].get("Content-Type", "")).startswith("text/html"))
        self.assertIn("LLM 사용 제한", page[2].decode("utf-8"))
        self.assertEqual(health[0], 200)
        self.assertEqual(other[0], 200)
        self.assertEqual([path for _, path, _ in rig.received], ["/backend-api/f/conversation"])   # 막힌 요청은 안 나감
        self.assertEqual(detection.counts["prompt"], 0)                   # 빈 질문 본문: 통과한 것도 검사할 글자 없음
        self.assertEqual(self.access.report()["denied_5m"], 2)
        self.assertEqual(rig.errors, [])
        self.assertNotIn("Traceback", rig.out.getvalue())

    def test_loopback_is_never_blocked_through_a_real_proxy(self):
        detection = self.FakeDetection()
        self.access.offer({"gateway_access": access_doc([rule()], require=True, version=2)})
        with mock.patch.object(gateway, "GATEWAY_ACCESS", self.access), self.ProxyRig(self, detection) as rig:
            blocked_id = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                                   {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_A})
            no_id = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                              {"Content-Type": "application/json"})
        self.assertEqual((blocked_id[0], no_id[0]), (200, 200))
        self.assertEqual(self.access.report()["denied_5m"], 0)
        self.assertEqual(rig.errors, [])


# ------------------------------------------------------------------ 6. 대시보드 백엔드 대조

@unittest.skipUnless(shutil.which("node") and (DASHBOARD_SERVER_DIR / "gateway-access.mjs").exists()
                     and (DASHBOARD_SERVER_DIR / "validation.mjs").exists(),
                     "node or dashboard server copy not available")
class BackendParityTests(unittest.TestCase):
    """대시보드 백엔드(gateway-access.mjs·validation.mjs)가 만든 문서를 Gateway가 받고, Gateway 보고·이벤트를 백엔드가 받는지."""

    def run_node(self, payload):
        access = (DASHBOARD_SERVER_DIR / "gateway-access.mjs").as_uri()
        validation = (DASHBOARD_SERVER_DIR / "validation.mjs").as_uri()
        script = (
            f"import * as access from '{access}';\n"
            f"import * as validation from '{validation}';\n"
            "import { readFileSync } from 'node:fs';\n"
            "const input = JSON.parse(readFileSync(0, 'utf8'));\n"
            "if (typeof access.gatewayAccessDocument !== 'function' || typeof access.parseAccessApplied !== 'function')"
            " { console.log(JSON.stringify({ missing: true })); process.exit(0); }\n"
            "const docs = input.rows.map((row) => access.gatewayAccessDocument(row, input.now));\n"
            "const reports = input.reports.map((value) => { try { access.parseAccessApplied(value); return 'ok'; }"
            " catch (error) { return String(error.message); } });\n"
            "const events = input.events.map((value) => { try { validation.validateCanonicalEvent(value); return 'ok'; }"
            " catch (error) { return `${error.path ?? ''} ${error.message}`; } });\n"
            "console.log(JSON.stringify({ docs, reports, events }));\n"
        )
        folder = Path(tempfile.mkdtemp(prefix="gw-node-"))
        self.addCleanup(shutil.rmtree, folder, True)
        path = folder / "parity.mjs"
        path.write_text(script, encoding="utf-8")
        result = subprocess.run(["node", str(path)], input=json.dumps(payload), capture_output=True, text=True,
                                encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(result.stdout)
        if out.get("missing"):
            self.skipTest("backend copy has no gatewayAccessDocument/parseAccessApplied yet")
        return out

    def test_documents_reports_and_events(self):
        now_ms = int(T0 * 1000)

        def stored(rule_id, client_id, expires_at, removed_at=None):
            return {"id": rule_id, "client_id": client_id, "reasons": ["OTHER"], "memo": "가짜 메모",
                    "expires_at": expires_at, "created_by": "admin", "created_at": "2026-10-12T04:00:00.000Z",
                    "removed_by": "admin" if removed_at else None, "removed_at": removed_at}
        rows = [
            {"version": 3, "revision": REV_1, "updated_at": "2026-10-12T05:00:00.000Z", "require_client_id": True,
             "rules": [stored(RULE_1, CLIENT_A, IN_1H), stored(RULE_2, CLIENT_B, None),
                       stored("00000000-0000-4000-8000-000000000003", "chrome-old", PAST),
                       stored("00000000-0000-4000-8000-000000000004", "chrome-gone", None, "2026-10-12T04:30:00.000Z")]},
            {"version": 1, "revision": REV_2, "updated_at": "2026-10-12T05:00:00.000Z", "require_client_id": False,
             "rules": []},
        ]
        value, _ = holder(None)
        reports = []
        value.offer({"gateway_access": None})
        reports.append(value.report())                                   # NONE
        value.offer({"gateway_access": access_doc([rule(expires_at=IN_1H)], require=True, version=3)})
        value.note_denied()
        reports.append(value.report())                                   # DASHBOARD
        value.offer({"gateway_access": access_doc([rule(client_id="bad id")], version=4, revision=REV_2)})
        reports.append(value.report())                                   # rejected
        tmp = Path(tempfile.mkdtemp(prefix="gw-access-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        cached, _ = holder(tmp / "a.json")
        cached.offer({"gateway_access": access_doc([rule()], version=9)})
        reports.append(holder(tmp / "a.json")[0].report())               # CACHE
        events = []
        for reason, rule_id, content_type in (("client_blocked", RULE_1, "prompt"), ("client_id_missing", None, "file")):
            event, _ = build_dashboard_event(
                result=A.AccessBlockResult(request_id="00000000-0000-4000-8000-0000000000e1", reason_code=reason,
                                           access_rule_id=rule_id),
                request_id="00000000-0000-4000-8000-0000000000e1",
                identity={"client_id": CLIENT_A} if rule_id else {}, target_llm="Claude", host="claude.ai",
                endpoint="/api/x", content_type=content_type, enforcement_applied=True, http_status=403)
            events.append(event)
        out = self.run_node({"rows": rows, "now": now_ms, "reports": reports, "events": events})
        parsed = [parse_access(document) for document in out["docs"]]
        self.assertEqual([r.id for r in parsed[0].rules], [RULE_1, RULE_2])   # 적용 중인 것만, 사유·메모 없음
        self.assertTrue(parsed[0].require_client_id)
        self.assertEqual(parsed[1].rules, ())
        self.assertNotIn("가짜 메모", json.dumps(out["docs"], ensure_ascii=False))
        self.assertEqual(out["reports"], ["ok"] * 4)
        self.assertEqual(out["events"], ["ok"] * 2)


if __name__ == "__main__":
    unittest.main()
