"""접속 차단 사유 안내(2026-10-12 오후) - 규칙의 reasons·user_memo 칸, 403 안내 페이지·JSON의 사유, 접속 상태(access-status).

옛 모양 문서(사유 칸 없음)와 새 모양 문서를 모두 받는지, 모르는 칸(관리자 메모 memo 등)은 지금처럼 거부하는지,
안내 페이지에서 user_memo가 HTML 이스케이프되는지, GET http://llm-gateway.local/__llmsgw/access-status가
차단·풀림·확장 ID 없음·만료·같은 연결 ID·접속 IP 예외를 실제 집행과 같게 답하는지, 차단 중에도 답하는지(예외),
로그에 확장 ID·메모가 없는지를 실제 mitmproxy flow·훅(tflow)과 실제 mitmproxy(DumpMaster)로 본다.
가짜 값만 쓴다(문서용 IP, 가짜 확장 ID·규칙 번호·메모). Detection·대시보드는 가짜다.
실행: python -m unittest tests.test_gateway_access_reasons -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import http.client
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import tests.test_gateway_access as base  # noqa: E402  (임시 폴더·환경 변수 준비는 그 모듈·bundle이 한다)

import gateway  # noqa: E402
import gateway_access as A  # noqa: E402
from gateway_access import AccessError, parse_access  # noqa: E402

CLIENT_A, CLIENT_B, CLIENT_C = base.CLIENT_A, base.CLIENT_B, "chrome-00000000-0000-4000-8000-00000000000c"
RULE_1, RULE_2 = base.RULE_1, base.RULE_2
RULE_3 = "9c0d1e2f-0000-4000-8000-000000000003"
IP_A, T0, IN_1H, NAVIGATE = base.IP_A, base.T0, base.IN_1H, base.NAVIGATE
REASONS = ["INVESTIGATION", "ADMIN_REQUEST"]
REASON_ITEMS = [{"code": "INVESTIGATION", "label": "보안 조사 중"}, {"code": "ADMIN_REQUEST", "label": "관리자 요청"}]
MISSING_ITEMS = [{"code": "CLIENT_ID_MISSING", "label": "확장 프로그램 식별 정보 없음"}]
MEMO = "가짜 안내: 보안 담당자에게 문의"
NASTY = "<script>alert(1)</script> & \"따옴표\" '홑'"
NASTY_ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;따옴표&quot; &#x27;홑&#x27;"
STATUS = b"/__llmsgw/access-status"
_ABSENT = object()


def reason_rule(rule_id=RULE_1, client_id=CLIENT_A, expires_at=None, reasons=REASONS, user_memo=_ABSENT):
    item = base.rule(rule_id, client_id, expires_at)
    if reasons is not None:
        item["reasons"] = list(reasons)
    if user_memo is not _ABSENT:
        item["user_memo"] = user_memo
    return item


def status_body(**overrides):
    body = {"blocked": False, "reason_code": None, "reasons": [], "user_memo": None, "until": None, "block_id": None,
            "require_client_id": False, "client_id_present": True, "checked_at": "2026-10-12T05:00:00.000Z"}
    body.update(overrides)
    return body


# ------------------------------------------------------------------ 1. 문서 칸

class ReasonFieldTests(unittest.TestCase):
    def test_old_and_new_rule_shapes_are_both_accepted(self):
        doc = base.access_doc([base.rule(), reason_rule(RULE_2, CLIENT_B, IN_1H, user_memo=MEMO),
                               reason_rule(RULE_3, CLIENT_C, reasons=["OTHER"], user_memo=None)])
        access = parse_access(doc)
        old, new, null_memo = access.rules
        self.assertEqual((old.reasons, old.user_memo), (None, None))
        self.assertEqual((new.reasons, new.user_memo, new.expires_ts), (tuple(REASONS), MEMO, T0 + 3600))
        self.assertEqual((null_memo.reasons, null_memo.user_memo), (("OTHER",), None))
        written = access.document()["rules"]
        self.assertEqual(written[0], base.rule())                         # 옛 모양은 옛 모양 그대로
        self.assertEqual(written[1], reason_rule(RULE_2, CLIENT_B, IN_1H, user_memo=MEMO))
        self.assertEqual(written[2], reason_rule(RULE_3, CLIENT_C, reasons=["OTHER"]))   # null = 칸 없음과 같음
        self.assertEqual([r.document() for r in parse_access(access.document()).rules], written)

    def test_every_reason_code_and_label(self):
        self.assertEqual(list(A.REASON_LABELS), ["LEAK_DOC_REPEAT", "PII_REPEAT", "INVESTIGATION", "LEAVE",
                                                 "ADMIN_REQUEST", "OTHER"])
        self.assertEqual(list(A.REASON_LABELS.values()), ["기밀 문서 반복 유출 시도", "개인정보 반복 입력", "보안 조사 중",
                                                          "퇴사·휴직 예정", "관리자 요청", "기타"])
        access = parse_access(base.access_doc([reason_rule(reasons=list(A.REASON_LABELS))]))
        self.assertEqual(access.rules[0].reasons, tuple(A.REASON_LABELS))

    def test_reason_values(self):
        for value in ([], list(A.REASON_LABELS) + ["OTHER"], ["OTHER", "OTHER"], ["UNKNOWN"], ["investigation"],
                      "INVESTIGATION", None, {"INVESTIGATION": 1}, [1], [["OTHER"]], [None]):
            doc = base.access_doc([base.rule(), reason_rule(RULE_2, CLIENT_B, reasons=None) | {"reasons": value}])
            self.assertEqual(base.error_field(doc), "rules.1.reasons", value)

    def test_user_memo_values(self):
        for value in ("a", "가" * 200, NASTY, None, "😀" * 200):
            doc = base.access_doc([reason_rule(user_memo=value)])
            self.assertIsNone(base.error_field(doc), value)
        for value in ("", "가" * 201, "줄\n바꿈", "탭\t", "벨\x07", "\x7f", 5, [], {"x": 1}, "짝없음\ud800", True):
            doc = base.access_doc([base.rule(), reason_rule(RULE_2, CLIENT_B, user_memo=value)])
            self.assertEqual(base.error_field(doc), "rules.1.user_memo", repr(value))
        without_reasons = base.access_doc([base.rule() | {"user_memo": MEMO}])   # 사유 없이 안내만 와도 받는다
        self.assertEqual(parse_access(without_reasons).rules[0].user_memo, MEMO)

    def test_unknown_fields_are_still_rejected(self):
        for extra in ({"memo": "관리자 메모"}, {"show_memo_to_user": True}, {"reason": ["OTHER"]},
                      {"reasons_labels": ["기타"]}):
            doc = base.access_doc([base.rule(), reason_rule(RULE_2, CLIENT_B) | extra])
            self.assertEqual(base.error_field(doc), "rules.1", extra)
        missing = reason_rule(RULE_2, CLIENT_B)
        del missing["expires_at"]
        self.assertEqual(base.error_field(base.access_doc([base.rule(), missing])), "rules.1")
        self.assertEqual(base.error_field({**base.access_doc(), "reasons": ["OTHER"]}), "gateway_access")

    def test_shapes_are_checked_before_values(self):
        doc = base.access_doc([reason_rule(reasons=None) | {"reasons": "bad"}, reason_rule(RULE_2, CLIENT_B) | {"x": 1}])
        self.assertEqual(base.error_field(doc), "rules.1")

    def test_rejected_document_keeps_the_current_list(self):
        value, logs = base.holder(None)
        value.offer({"gateway_access": base.access_doc([reason_rule(user_memo=MEMO)])})
        good = value.current()
        value.offer({"gateway_access": base.access_doc([reason_rule() | {"memo": "관리자 메모"}], version=2,
                                                       revision=base.REV_2)})
        self.assertIs(value.current(), good)
        self.assertEqual(value.report()["rejected"], "rules.0")
        self.assertFalse(any(MEMO in line or "관리자 메모" in line or CLIENT_A in line for line in logs))

    def test_cache_keeps_reasons_and_user_memo(self):
        tmp = Path(tempfile.mkdtemp(prefix="gw-access-reasons-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        cache = tmp / "gateway-access.json"
        first, _ = base.holder(cache)
        doc = base.access_doc([reason_rule(expires_at=IN_1H, user_memo=MEMO), base.rule(RULE_2, CLIENT_B)], version=5)
        first.offer({"gateway_access": doc})
        self.assertEqual(json.loads(cache.read_text(encoding="utf-8"))["document"], doc)
        restarted, _ = base.holder(cache)
        rules = restarted.current().rules
        self.assertEqual((restarted.current().source, rules[0].reasons, rules[0].user_memo, rules[1].reasons),
                         ("CACHE", tuple(REASONS), MEMO, None))


@unittest.skipUnless(shutil.which("node") and (base.DASHBOARD_SERVER_DIR / "gateway-access.mjs").exists(),
                     "node or dashboard server copy not available")
class ReasonLabelParityTests(unittest.TestCase):
    def test_labels_match_the_dashboard(self):
        module = (base.DASHBOARD_SERVER_DIR / "gateway-access.mjs").as_uri()
        folder = Path(tempfile.mkdtemp(prefix="gw-node-"))
        self.addCleanup(shutil.rmtree, folder, True)
        script = folder / "labels.mjs"
        script.write_text(f"import {{ BLOCK_REASONS }} from '{module}';\nconsole.log(JSON.stringify(BLOCK_REASONS ?? null));\n",
                          encoding="utf-8")
        result = subprocess.run(["node", str(script)], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        labels = json.loads(result.stdout)
        if labels is None:
            self.skipTest("dashboard copy has no BLOCK_REASONS")
        self.assertEqual(list(labels.items()), list(A.REASON_LABELS.items()))


# ------------------------------------------------------------------ 2. 403 안내(단위)

class BlockResponseTests(unittest.TestCase):
    def decision(self, item=None, reason="client_blocked"):
        if item is None:
            return A.AccessDecision(reason)
        access = parse_access(base.access_doc([item]))
        return A.AccessDecision(reason, access.rules[0], access.rules[0].client_id)

    def test_json_with_reasons_and_memo(self):
        response = A.block_response(self.decision(reason_rule(user_memo=MEMO)), "req-1", navigate=False)
        self.assertEqual(json.loads(response.content), {"error": {
            "type": "access_blocked", "message": "관리자에 의해 LLM 사용이 제한되었습니다.", "reason_code": "client_blocked",
            "request_id": "req-1", "reasons": REASON_ITEMS, "user_memo": MEMO}})

    def test_json_without_memo_and_old_rule(self):
        no_memo = json.loads(A.block_response(self.decision(reason_rule()), "r", navigate=False).content)["error"]
        self.assertEqual((no_memo["reasons"], "user_memo" in no_memo), (REASON_ITEMS, False))
        old = json.loads(A.block_response(self.decision(base.rule()), "r", navigate=False).content)["error"]
        self.assertEqual(set(old), {"type", "message", "reason_code", "request_id"})     # 지금과 같은 모양
        missing = json.loads(A.block_response(self.decision(reason="client_id_missing"), "r",
                                              navigate=False).content)["error"]
        self.assertEqual((missing["reason_code"], missing["reasons"], "user_memo" in missing),
                         ("client_id_missing", MISSING_ITEMS, False))

    def test_page_shows_reasons_and_escapes_the_memo(self):
        page = A.block_response(self.decision(reason_rule(expires_at=IN_1H, user_memo=NASTY)), "req-1",
                                navigate=True).content.decode("utf-8")
        self.assertIn("<p>사유: 보안 조사 중 · 관리자 요청</p>", page)
        self.assertIn(f"<p>관리자 안내: {NASTY_ESCAPED}</p>", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("alert(1)</script>", page)
        self.assertIn("<dd>1a2b3c4d</dd>", page)
        self.assertIn("<dd>10/12 15:00</dd>", page)
        self.assertLess(page.index("사유:"), page.index("<dl>"))
        for external in ("<link", "<img", "src=", "href=", "url(", "http://", "https://", "@import"):
            self.assertNotIn(external, page)

    def test_page_without_reasons_or_memo(self):
        old = A.block_response(self.decision(base.rule()), "r", navigate=True).content.decode("utf-8")
        self.assertNotIn("사유", old)
        self.assertNotIn('class="why"', old)
        no_memo = A.block_response(self.decision(reason_rule()), "r", navigate=True).content.decode("utf-8")
        self.assertIn("사유: 보안 조사 중 · 관리자 요청", no_memo)
        self.assertNotIn("관리자 안내", no_memo)
        missing = A.block_response(A.AccessDecision("client_id_missing"), "r", navigate=True).content.decode("utf-8")
        self.assertIn("<p>사유: 확장 프로그램 식별 정보 없음</p>", missing)
        self.assertNotIn("관리자 안내", missing)


# ------------------------------------------------------------------ 3. 실제 mitmproxy flow·훅

class ReasonFlowTests(base.FlowBase):
    def test_old_shape_document_keeps_the_current_403(self):
        self.use([base.rule()])
        body = json.loads(self.send(self.make()).response.content)["error"]
        self.assertEqual(set(body), {"type", "message", "reason_code", "request_id"})
        page = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None, headers=NAVIGATE))
        self.assertEqual(page.response.status_code, 403)
        self.assertNotIn("사유", page.response.content.decode("utf-8"))

    def test_new_shape_document_shows_reasons_and_memo(self):
        self.use([reason_rule(expires_at=IN_1H, user_memo=NASTY)])
        flow = self.send(self.make())
        body = json.loads(flow.response.content)["error"]
        self.assertEqual((flow.response.status_code, body["reason_code"], body["reasons"], body["user_memo"]),
                         (403, "client_blocked", REASON_ITEMS, NASTY))
        self.assertEqual(self.detection_calls, [])
        page = self.send(self.make(method=b"GET", path=b"/", content=b"", content_type=None, headers=NAVIGATE))
        text = page.response.content.decode("utf-8")
        self.assertEqual((page.response.status_code, page.response.headers["content-type"]),
                         (403, "text/html; charset=utf-8"))
        self.assertIn("<p>사유: 보안 조사 중 · 관리자 요청</p>", text)
        self.assertIn(f"<p>관리자 안내: {NASTY_ESCAPED}</p>", text)
        self.assertNotIn("<script", text)
        self.assertEqual(self.queued[0]["accessRuleId"], RULE_1)          # 이벤트 모양은 그대로(사유는 대시보드가 붙임)
        self.assertNotIn("reasons", self.queued[0])
        self.assertNotIn(CLIENT_A, self.output.getvalue())
        self.assertNotIn("alert(1)", self.output.getvalue())

    def test_missing_id_page_and_json_show_the_fixed_reason(self):
        self.use([], require=True)
        body = json.loads(self.send(self.make(client=None)).response.content)["error"]
        self.assertEqual((body["reason_code"], body["reasons"]), ("client_id_missing", MISSING_ITEMS))
        form = self.send(self.make(path=b"/", client=None, headers=NAVIGATE))       # POST 화면 이동은 막힘
        self.assertIn("<p>사유: 확장 프로그램 식별 정보 없음</p>", form.response.content.decode("utf-8"))


class AccessStatusTests(base.FlowBase):
    def status(self, client=CLIENT_A, **kwargs):
        kwargs.setdefault("method", b"GET")
        kwargs.setdefault("path", STATUS)
        flow = self.send(self.make(host="llm-gateway.local", content=b"", content_type=None, client=client, **kwargs))
        return flow

    def body(self, flow):
        self.assertEqual(flow.response.status_code, 200)
        return json.loads(flow.response.content)

    def test_unblocked_without_any_document(self):
        flow = self.status()
        self.assertEqual(self.body(flow), status_body())
        headers = flow.response.headers
        self.assertEqual((headers["content-type"], headers["cache-control"], headers["x-content-type-options"]),
                         ("application/json; charset=utf-8", "no-store", "nosniff"))
        self.assertNotIn("access-control-allow-origin", headers)          # 웹 페이지는 못 읽음
        self.assertEqual(self.detection_calls, [])
        self.assertNotIn("gw_metrics_started_at", flow.metadata)

    def test_blocked_with_reasons_memo_and_expiry(self):
        self.use([reason_rule(expires_at=IN_1H, user_memo=MEMO)], require=True)
        self.assertEqual(self.body(self.status()), status_body(
            blocked=True, reason_code="client_blocked", reasons=REASON_ITEMS, user_memo=MEMO,
            until="2026-10-12T06:00:00.000Z", block_id="1a2b3c4d", require_client_id=True))

    def test_until_is_utc_and_permanent_is_null(self):
        self.use([reason_rule(expires_at="2026-10-12T15:00:00+09:00")])
        self.assertEqual(self.body(self.status())["until"], "2026-10-12T06:00:00.000Z")
        self.use([base.rule()], version=2)                                 # 옛 모양·영구
        self.assertEqual(self.body(self.status()), status_body(blocked=True, reason_code="client_blocked",
                                                               block_id="1a2b3c4d"))

    def test_only_the_asking_clients_rule_is_shown(self):
        self.use([reason_rule(user_memo=MEMO), reason_rule(RULE_2, CLIENT_B, IN_1H, reasons=["LEAVE"])])
        other = self.status(client=CLIENT_C)
        self.assertEqual(self.body(other), status_body())
        text = other.response.content.decode("utf-8")
        for secret in (RULE_1, RULE_1[:8], RULE_2[:8], CLIENT_A, CLIENT_B, MEMO, "보안 조사 중"):
            self.assertNotIn(secret, text)
        b = self.body(self.status(client=CLIENT_B))
        self.assertEqual((b["block_id"], b["reasons"], b["user_memo"]),
                         ("5e6f7a8b", [{"code": "LEAVE", "label": "퇴사·휴직 예정"}], None))
        self.assertNotIn(MEMO, json.dumps(b, ensure_ascii=False))

    def test_no_or_invalid_client_id(self):
        self.use([reason_rule()])
        for client in (None, "bad id!"):
            self.assertEqual(self.body(self.status(client=client)), status_body(client_id_present=False))
        self.use([reason_rule()], require=True, version=2)
        for client in (None, "bad id!", " "):
            self.assertEqual(self.body(self.status(client=client)), status_body(
                blocked=True, reason_code="client_id_missing", reasons=MISSING_ITEMS, require_client_id=True,
                client_id_present=False))
        self.assertEqual(self.body(self.status(client=CLIENT_C))["blocked"], False)   # ID가 있으면 없음 차단과 무관

    def test_header_name_is_case_insensitive(self):
        self.use([reason_rule()])
        flow = self.status(client=None, headers=((b"X-LLMSGW-Client-Id", CLIENT_A.encode()),))
        self.assertEqual(self.body(flow)["block_id"], "1a2b3c4d")

    def test_expiry_by_the_gateway_clock(self):
        self.use([reason_rule(expires_at=IN_1H, user_memo=MEMO)])
        self.clock.now = T0 + 3599
        self.assertTrue(self.body(self.status())["blocked"])
        self.clock.now = T0 + 3600
        self.assertEqual(self.body(self.status()), status_body(checked_at="2026-10-12T06:00:00.000Z"))

    def test_cleared_document_unblocks(self):
        self.use([reason_rule()], require=True)
        self.access.offer({"gateway_access": None})
        self.assertEqual(self.body(self.status(client=None)), status_body(client_id_present=False))

    def test_falls_back_to_the_id_seen_on_the_same_connection(self):
        self.use([reason_rule(user_memo=MEMO)])
        first = self.send(self.make())
        self.assertEqual(first.response.status_code, 403)
        same = self.body(self.status(client=None, conn=first.client_conn))
        self.assertEqual((same["blocked"], same["client_id_present"], same["user_memo"]), (True, True, MEMO))
        fresh = self.body(self.status(client=None))
        self.assertEqual((fresh["blocked"], fresh["client_id_present"]), (False, False))
        header_wins = self.body(self.status(client=CLIENT_C, conn=first.client_conn))
        self.assertEqual(header_wins["blocked"], False)                   # 직접 붙인 머리가 먼저

    def test_answers_while_blocked_and_counts_nothing(self):
        self.use([reason_rule()], require=True)
        before = (gateway._gateway_metrics["total_requests"], len(gateway._gateway_latencies_ms))
        for client in (CLIENT_A, None):
            self.assertEqual(self.status(client=client).response.status_code, 200)
        health = self.send(self.make(host="llm-gateway.local", method=b"GET", path=b"/__llmsgw/health", content=b"",
                                     content_type=None))
        self.assertEqual(health.response.status_code, 200)
        self.assertEqual(self.access.report()["denied_5m"], 0)
        self.assertEqual((self.queued, self.extension, self.detection_calls), ([], [], []))
        self.assertEqual((gateway._gateway_metrics["total_requests"], len(gateway._gateway_latencies_ms)), before)
        self.assertEqual(self.send(self.make()).response.status_code, 403)   # LLM 요청은 그대로 막힘

    def test_loopback_peer_mirrors_enforcement(self):
        self.use([reason_rule()], require=True)
        for peer in ("127.0.0.1", "::1"):
            self.assertEqual(self.body(self.status(peer=peer)), status_body(require_client_id=True))
            self.assertTrue(self.send(self.make(peer=peer)).forwarded)

    def test_query_string_methods_and_neighbour_paths(self):
        self.use([reason_rule()])
        self.assertTrue(self.body(self.status(path=STATUS + b"?t=1"))["blocked"])
        post = self.status(method=b"POST")
        self.assertEqual((post.response.status_code, post.response.headers["allow"]), (405, "GET"))
        self.assertEqual(json.loads(post.response.content), {"error": {"code": "METHOD_NOT_ALLOWED"}})
        neighbour = self.status(path=STATUS + b"/x")
        self.assertEqual(neighbour.response.status_code, 404)              # 내 기록 중계 모듈이 직접 404
        self.assertFalse(getattr(neighbour, "forwarded", False))

    def test_failure_is_503_not_blocked(self):
        self.use([reason_rule()])
        with mock.patch.object(gateway, "access_status", side_effect=RuntimeError("boom")):
            flow = self.status()
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(json.loads(flow.response.content), {"error": {"code": "STATUS_UNAVAILABLE"}})
        self.assertIn("[ACCESS] status failed error_type=RuntimeError", self.output.getvalue())

    def test_logs_have_no_client_id_or_memo(self):
        self.use([reason_rule(user_memo=MEMO), base.rule(RULE_2, CLIENT_B)], require=True)
        for client in (CLIENT_A, CLIENT_B, CLIENT_C, None):
            self.status(client=client)
        self.send(self.make())
        out = self.output.getvalue()
        for secret in (CLIENT_A, CLIENT_B, CLIENT_C, MEMO, IP_A):
            self.assertNotIn(secret, out)
        self.assertNotIn("access-status", out)                           # 상태 요청은 줄을 남기지 않는다
        self.assertFalse(any(CLIENT_A in line or MEMO in line for line in self.logs))


# ------------------------------------------------------------------ 4. 실제 mitmproxy(DumpMaster)

FAR = "2099-01-01T00:00:00.000Z"


class ReasonRealProxyTests(unittest.TestCase):
    """실제 mitmproxy에 gateway를 올린다. 시험 연결은 127.0.0.1에서 오므로 막는 시험은 접속 IP 예외만 끈다."""

    def setUp(self):
        from tests.test_gateway_file_worker import FakeDetection, ProxyRig
        self.FakeDetection, self.ProxyRig = FakeDetection, ProxyRig
        self.access, self.logs = base.holder(None, url=None, clock=time.time)

    def request(self, conn, method, url, headers):
        body = b"{}" if method == "POST" else None
        conn.request(method, url, body=body, headers={"Host": url.split("/")[2], **headers})
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()

    def call(self, rig, method, url, headers):
        conn = http.client.HTTPConnection("127.0.0.1", rig.port, timeout=15)
        try:
            return self.request(conn, method, url, {"Connection": "close", **headers})
        finally:
            conn.close()

    def run_rig(self, exempt_off=True):
        patches = [mock.patch.object(gateway, "GATEWAY_ACCESS", self.access)]
        if exempt_off:
            patches.append(mock.patch.object(gateway, "access_exempt_peer", lambda ip: False))
        return patches

    def test_new_shape_document_through_a_real_proxy(self):
        self.access.offer({"gateway_access": base.access_doc([reason_rule(expires_at=FAR, user_memo=NASTY)])})
        detection = self.FakeDetection()
        status_url = "http://llm-gateway.local/__llmsgw/access-status"
        p1, p2 = self.run_rig()
        with p1, p2, self.ProxyRig(self, detection) as rig:
            fetch = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                              {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_A})
            page = self.call(rig, "GET", "http://chatgpt.com/",
                             {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe", "X-LLMSGW-Client-ID": CLIENT_A})
            blocked = self.call(rig, "GET", status_url, {"X-LLMSGW-Client-Id": CLIENT_A})
            other = self.call(rig, "GET", status_url, {"X-LLMSGW-Client-Id": CLIENT_B})
            bare = self.call(rig, "GET", status_url, {})
            allowed = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                                {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_B})
            # 같은 연결: 앞 요청의 식별 머리로 상태를 답한다(머리 없이 물어도)
            conn = http.client.HTTPConnection("127.0.0.1", rig.port, timeout=15)
            try:
                first = self.request(conn, "POST", "http://chatgpt.com/backend-api/f/conversation",
                                     {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_A})
                same = self.request(conn, "GET", status_url, {})
            finally:
                conn.close()
        error = json.loads(fetch[2])["error"]
        self.assertEqual((fetch[0], error["reasons"], error["user_memo"]), (403, REASON_ITEMS, NASTY))
        text = page[2].decode("utf-8")
        self.assertEqual(page[0], 403)
        self.assertTrue(page[1]["content-type"].startswith("text/html"))
        self.assertIn("<p>사유: 보안 조사 중 · 관리자 요청</p>", text)
        self.assertIn(f"<p>관리자 안내: {NASTY_ESCAPED}</p>", text)
        self.assertNotIn("<script", text)
        self.assertEqual(blocked[0], 200)
        self.assertEqual((blocked[1]["content-type"], blocked[1]["cache-control"]),
                         ("application/json; charset=utf-8", "no-store"))
        status = json.loads(blocked[2])
        self.assertRegex(status.pop("checked_at"), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertEqual(status, {"blocked": True, "reason_code": "client_blocked", "reasons": REASON_ITEMS,
                                  "user_memo": NASTY, "until": FAR, "block_id": "1a2b3c4d",
                                  "require_client_id": False, "client_id_present": True})
        self.assertEqual((other[0], json.loads(other[2])["blocked"]), (200, False))
        self.assertNotIn(NASTY, other[2].decode("utf-8"))
        self.assertEqual(json.loads(bare[2])["client_id_present"], False)
        self.assertEqual(allowed[0], 200)
        self.assertEqual((first[0], same[0]), (403, 200))
        self.assertEqual((json.loads(same[2])["blocked"], json.loads(same[2])["client_id_present"]), (True, True))
        self.assertEqual([path for _, path, _ in rig.received], ["/backend-api/f/conversation"])   # 허용된 1건만 나감
        self.assertEqual(self.access.report()["denied_5m"], 3)               # 상태 요청은 세지 않음
        out = rig.out.getvalue()
        for secret in (CLIENT_A, CLIENT_B, "alert(1)"):
            self.assertNotIn(secret, out)
        self.assertEqual(rig.errors, [])
        self.assertNotIn("Traceback", out)

    def test_old_shape_document_through_a_real_proxy(self):
        self.access.offer({"gateway_access": base.access_doc([base.rule(expires_at=FAR)], require=True)})
        detection = self.FakeDetection()
        p1, p2 = self.run_rig()
        with p1, p2, self.ProxyRig(self, detection) as rig:
            fetch = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                              {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_A})
            missing = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                                {"Content-Type": "application/json"})
            status = self.call(rig, "GET", "http://llm-gateway.local/__llmsgw/access-status",
                               {"X-LLMSGW-Client-Id": CLIENT_A})
        self.assertEqual(set(json.loads(fetch[2])["error"]), {"type", "message", "reason_code", "request_id"})
        self.assertEqual(json.loads(missing[2])["error"]["reasons"], MISSING_ITEMS)
        body = json.loads(status[2])
        self.assertEqual((status[0], body["blocked"], body["reasons"], body["user_memo"], body["until"],
                          body["require_client_id"]), (200, True, [], None, FAR, True))
        self.assertEqual(rig.received, [])
        self.assertEqual(rig.errors, [])

    def test_loopback_status_through_a_real_proxy(self):
        self.access.offer({"gateway_access": base.access_doc([reason_rule()])})
        detection = self.FakeDetection()
        p1, = self.run_rig(exempt_off=False)
        with p1, self.ProxyRig(self, detection) as rig:
            status = self.call(rig, "GET", "http://llm-gateway.local/__llmsgw/access-status",
                               {"X-LLMSGW-Client-Id": CLIENT_A})
            fetch = self.call(rig, "POST", "http://chatgpt.com/backend-api/f/conversation",
                              {"Content-Type": "application/json", "X-LLMSGW-Client-ID": CLIENT_A})
        self.assertEqual((status[0], json.loads(status[2])["blocked"], fetch[0]), (200, False, 200))
        self.assertEqual(rig.errors, [])


if __name__ == "__main__":
    unittest.main()
