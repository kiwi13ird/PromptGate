"""2026-10-16 남은 로직 2가지 - 실제 mitmproxy flow로 request()·response() 훅을 지난다(가짜 Detection·가짜 대시보드 큐).

1. 접속 차단 보안 이벤트는 검사 대상 요청(질문·파일 업로드)을 막았을 때만, 입력 유형은 그 요청 종류대로.
   배경 요청(Gemini batchexecute·Codex·웹소켓·Claude 원격 측정·화면 로딩 등) 차단은 이벤트·확장 알림 없이
   denied_5m('최근 5분 막은 요청')·[ACCESS] 로그(event=skipped kind=other)로만 센다. 10분 대표 기록 칸도 검사 대상 요청만 쓴다.
2. 이벤트 endpoint·Detection source·로그 'Path:' 줄에 주소 쿼리(ChatGPT 업로드 주소 서명 sig= 등)를 남기지 않는다.

가짜 값만 쓴다(문서용 IP, 가짜 확장 ID·서명). 실행: python -m unittest tests.test_gateway_final_logic -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_gateway_access import (  # noqa: E402  (임시 폴더·환경 변수 준비는 bundle 모듈이 한다)
    CLIENT_A, CLIENT_B, IP_A, NAVIGATE, RULE_1, FlowBase, rule,
)
from tests.test_gateway_bundle_flows import COMPLETION_PATH, DASHBOARD_SERVER_DIR, FILE_ID, RRN  # noqa: E402
from tests.test_gateway_claude_rpc_prompt import CLEAN_PROMPT, PERFORM_PATH, other_action, perform_action  # noqa: E402
from tests.test_gateway_dedupe_proto import DedupeBase  # noqa: E402
from mitmproxy.test import tutils  # noqa: E402

import gateway  # noqa: E402

FAKE_SIG = "ZmFrZS1zaWduYXR1cmUtbm90LXJlYWw%3D"    # 지어낸 서명값(로그·이벤트 어디에도 남으면 안 됨)
SIGNED_QUERY = (f"?se=2026-10-16T00%3A05%3A00Z&sp=cw&sv=2024-08-04&sr=b&skoid=fake-oid&sktid=fake-tid"
                f"&skt=2026-10-16T00%3A00%3A00Z&ske=2026-10-17T00%3A00%3A00Z&sks=b&skv=2024-08-04&sig={FAKE_SIG}")
STREAM_GENERATE = "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=fake&_reqid=1&rt=c"
BATCHEXECUTE = "/_/BardChatUi/data/batchexecute?rpcids=fake&source-path=%2Fapp&bl=fake&_reqid=2&rt=c"
GEMINI_FORM = b"f.req=%5Bnull%2C%22%5B%5B%5C%22fake%5C%22%5D%5D%22%5D&at=fake"


class AccessEventScopeTests(FlowBase):
    """배경 요청 차단은 이벤트 없이 세기만, 검사 대상 요청 차단은 그 종류대로 이벤트."""

    # (이름, make 인자) - 운영 10/15 감사에서 이벤트로 남은 배경 요청 경로와 같은 모양(값은 지어냄)
    BACKGROUND = (
        ("Gemini batchexecute", dict(host="gemini.google.com", path=BATCHEXECUTE.encode(), content=GEMINI_FORM,
                                     content_type=b"application/x-www-form-urlencoded;charset=UTF-8")),
        ("Codex 백엔드", dict(path=b"/backend-api/codex/tasks/list", method=b"GET", content=b"", content_type=None)),
        ("ChatGPT 웹소켓", dict(path=b"/backend-api/celsius/ws/user", method=b"GET", content=b"", content_type=None,
                             headers=((b"connection", b"Upgrade"), (b"upgrade", b"websocket")))),
        ("Claude 원격 측정", dict(host="claude.ai", path=b"/api/event_logging/batch", content=b'{"events":[]}')),
        ("ChatGPT 계정 조회", dict(path=b"/backend-api/me", method=b"GET", content=b"", content_type=None)),
        ("ChatGPT 화면 이동(POST)", dict(path=b"/", headers=NAVIGATE)),
        ("Claude 다른 동작 PerformAction", dict(host="claude.ai", path=PERFORM_PATH.encode(), content=other_action(),
                                             content_type=b"application/proto")),
    )

    def kinds_in_log(self):
        return [line.split(" kind=", 1)[1].split(" ", 1)[0]
                for line in self.output.getvalue().splitlines() if line.startswith("[ACCESS] denied")]

    def test_background_requests_are_blocked_counted_and_not_recorded(self):
        for require, client, reason in ((True, None, "client_id_missing"), (False, CLIENT_A, "client_blocked")):
            with self.subTest(reason=reason):
                self.queued.clear()
                self.extension.clear()
                self.output.truncate(0)
                self.output.seek(0)
                self.use([] if require else [rule()], require=require, version=2 if require else 3)
                before = self.access.report()["denied_5m"]
                for name, kwargs in self.BACKGROUND:
                    flow = self.send(self.make(client=client, **kwargs))
                    self.assertEqual(flow.response.status_code, 403, name)                 # 막는 것은 그대로
                    self.assertFalse(getattr(flow, "forwarded", False), name)
                    self.assertEqual(json.loads(flow.response.content)["error"]["reason_code"] if
                                     flow.response.headers.get("content-type", "").startswith("application/json")
                                     else reason, reason, name)
                self.assertEqual(self.queued, [])                                          # 보안 이벤트 없음
                self.assertEqual(self.extension, [])                                       # 확장 알림 없음
                self.assertEqual(self.access.report()["denied_5m"] - before, len(self.BACKGROUND))  # 지표로는 셈
                self.assertEqual(self.kinds_in_log(), ["other"] * len(self.BACKGROUND))
                self.assertEqual(self.output.getvalue().count("event=skipped kind=other"), len(self.BACKGROUND))
                self.assertEqual(self.detection_calls, [])

    def test_background_block_does_not_take_the_ten_minute_slot(self):
        self.use([], require=True)
        self.send(self.make(client=None, host="gemini.google.com", path=BATCHEXECUTE.encode(), content=GEMINI_FORM,
                            content_type=b"application/x-www-form-urlencoded"))
        self.send(self.make(client=None, path=b"/backend-api/me", method=b"GET", content=b"", content_type=None))
        prompt = self.send(self.make(client=None))                     # 같은 IP의 질문: 앞 배경 요청 때문에 빠지면 안 됨
        self.assertEqual(prompt.response.status_code, 403)
        self.assertEqual([(e["contentType"], e["endpoint"], e["reasonCode"]) for e in self.queued],
                         [("prompt", "/backend-api/f/conversation", "client_id_missing")])
        self.send(self.make(client=None))                              # 그 뒤 10분 안 같은 IP 질문은 지금처럼 대표 1건
        self.assertEqual(len(self.queued), 1)
        self.assertEqual(self.access.report()["denied_5m"], 4)

    def test_prompt_routes_are_recorded_as_prompt(self):
        cases = (
            ("ChatGPT 질문", dict(), "ChatGPT", "/backend-api/f/conversation"),
            ("Claude completion", dict(host="claude.ai", path=COMPLETION_PATH.encode(),
                                       content=json.dumps({"prompt": "가짜 질문"}).encode()), "Claude", COMPLETION_PATH),
            ("Claude 새 화면 질문", dict(host="claude.ai", path=PERFORM_PATH.encode(), content=perform_action(CLEAN_PROMPT),
                                     content_type=b"application/proto"), "Claude", PERFORM_PATH),
            ("Gemini 질문", dict(host="gemini.google.com", path=STREAM_GENERATE.encode(), content=GEMINI_FORM,
                               content_type=b"application/x-www-form-urlencoded;charset=UTF-8"),
             "Gemini", STREAM_GENERATE.split("?", 1)[0]),
            ("OpenAI API", dict(host=gateway.OPENAI_HOST, path=gateway.OPENAI_RESPONSES_ENDPOINT.encode(),
                                content=b'{"input":"fake"}'), "ChatGPT", gateway.OPENAI_RESPONSES_ENDPOINT),
        )
        self.use([], require=True)
        for index, (name, kwargs, target, endpoint) in enumerate(cases):
            with self.subTest(name):
                peer = f"203.0.113.{100 + index}"                       # IP마다 대표 기록 칸이 따로
                flow = self.send(self.make(client=None, peer=peer, **kwargs))
                self.assertEqual(flow.response.status_code, 403)
                event = self.queued[-1]
                self.assertEqual((event["contentType"], event["targetLlm"], event["endpoint"], event["reasonCode"]),
                                 ("prompt", target, endpoint, "client_id_missing"))
        self.assertEqual(len(self.queued), len(cases))
        self.assertEqual(self.kinds_in_log(), ["prompt"] * len(cases))

    def test_file_routes_are_recorded_as_file(self):
        cases = (
            ("ChatGPT 파일 예약", dict(path=b"/backend-api/files", content=b'{"file_name":"a.txt","file_size":3}'),
             "ChatGPT", "/backend-api/files"),
            ("ChatGPT 원본 PUT", dict(host="sdmntprkoreacentral.oaiusercontent.com", method=b"PUT",
                                    path=f"/files/{FILE_ID}/raw{SIGNED_QUERY}".encode(), content=b"abc",
                                    content_type=b"application/octet-stream"), "ChatGPT", f"/files/{FILE_ID}/raw"),
            ("Gemini 업로드", dict(host=gateway._GEMINI_UPLOAD_HOST, path=b"/upload/", content=b"abc",
                                 content_type=b"application/x-www-form-urlencoded"), "Gemini", "/upload/"),
        )
        self.use([rule()])
        for index, (name, kwargs, target, endpoint) in enumerate(cases):
            with self.subTest(name):
                self.clock.now += 601                                    # 같은 확장 ID: 10분 칸이 지나게
                flow = self.send(self.make(**kwargs))
                self.assertEqual(flow.response.status_code, 403)
                event = self.queued[-1]
                self.assertEqual((event["contentType"], event["targetLlm"], event["endpoint"], event["accessRuleId"]),
                                 ("file", target, endpoint, RULE_1))
        self.assertEqual(len(self.queued), len(cases))
        self.assertEqual(self.upload_submits, [])                         # 막힌 업로드는 작업 스레드에 가지 않음
        self.assertEqual(len(self.extension), len(cases))                 # 확장 알림은 이벤트와 함께(기존 중계)

    def test_claude_upload_is_file_and_kind_check_failure_records_nothing(self):
        self.use([rule()])
        self.send(self.claude_upload())
        self.assertEqual([e["contentType"] for e in self.queued], ["file"])
        self.clock.now += 601
        with mock.patch.object(gateway, "is_file_upload_request", side_effect=RuntimeError("boom")):
            flow = self.send(self.make())
        self.assertEqual(flow.response.status_code, 403)                   # 판단 실패: 막는 것은 그대로, 이벤트만 없음
        self.assertEqual(len(self.queued), 1)
        self.assertIn("[ACCESS] request kind check failed error_type=RuntimeError", self.output.getvalue())

    def test_access_page_counters_and_blocked_table_stay_the_same(self):
        self.use([rule()])
        self.send(self.make(path=b"/backend-api/me", method=b"GET", content=b"", content_type=None))
        row = {r["ip"]: r for r in self.tracker.snapshot()}[IP_A]
        self.assertEqual((row["client_id"], row["requests_5m"], row["inflight"]), (CLIENT_A, 0, 0))   # 연결 IP 표 '차단 중'
        self.assertEqual(self.access.report()["denied_5m"], 1)
        self.assertEqual(self.access.report()["active_rules"], 1)
        allowed = self.send(self.make(client=CLIENT_B))                     # 막히지 않은 확장은 지금처럼 검사
        self.assertTrue(allowed.forwarded)
        self.assertEqual(len(self.detection_calls), 1)


class QueryStrippingTests(DedupeBase):
    """주소 쿼리(서명·토큰)는 이벤트 endpoint·Detection source·로그 어디에도 남지 않는다. 호스트·경로는 남는다."""

    def signed_put(self, content, filename="upload.bin"):
        gateway.CHATGPT_FILE_META[FILE_ID] = filename
        req = tutils.treq(host="sdmntprkoreacentral.oaiusercontent.com", port=443, scheme=b"https", method=b"PUT",
                          path=f"/files/{FILE_ID}/raw{SIGNED_QUERY}".encode(), content=content,
                          headers=((b"content-type", b"application/octet-stream"),))
        return self.run_flow(req)

    def assert_no_query_values(self, text):
        for value in (FAKE_SIG, "sig=", "skoid=", "fake-oid", "sktid="):
            self.assertNotIn(value, text)

    def test_chatgpt_raw_put_event_keeps_host_and_path_only(self):
        flow = self.attempt(lambda: self.signed_put(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504))   # 검사 불가 → 403
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(len(self.queued), 1)
        event = self.queued[0]
        self.assertEqual((event["host"], event["endpoint"]), ("sdmntprkoreacentral.oaiusercontent.com", f"/files/{FILE_ID}/raw"))
        self.assert_no_query_values(json.dumps(self.queued + self.extension, ensure_ascii=False))
        self.assert_no_query_values(self.log.getvalue())
        self.assertIn(f"/files/{FILE_ID}/raw", self.log.getvalue())

    def test_chatgpt_raw_put_detection_source_and_inspected_event(self):
        flow = self.attempt(lambda: self.signed_put(f"name hong RRN {RRN}".encode(), "memo.txt"))
        self.assertTrue(self.calls)
        for call in self.calls:
            self.assert_no_query_values(json.dumps(call["source"]))
        self.assertEqual({e["endpoint"] for e in self.queued}, {f"/files/{FILE_ID}/raw"})
        self.assert_no_query_values(self.log.getvalue())

    def test_chatgpt_multipart_detection_source_has_no_query(self):
        boundary = "----gwfinal"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"memo.txt\"\r\n"
                f"Content-Type: text/plain\r\n\r\n").encode() + f"RRN {RRN}".encode() + f"\r\n--{boundary}--\r\n".encode()
        req = tutils.treq(host="chatgpt.com", port=443, scheme=b"https", method=b"POST",
                          path=f"/backend-api/files/upload{SIGNED_QUERY}".encode(), content=body,
                          headers=((b"content-type", f"multipart/form-data; boundary={boundary}".encode()),))
        self.attempt(lambda: self.run_flow(req))
        self.assertTrue(self.calls)
        self.assertEqual({call["source"].get("endpoint") for call in self.calls}, {"/backend-api/files/upload"})
        self.assertEqual({e["endpoint"] for e in self.queued}, {"/backend-api/files/upload"})
        self.assert_no_query_values(self.log.getvalue())

    def test_download_link_path_line_has_no_signature(self):
        req = tutils.treq(host="chatgpt.com", port=443, scheme=b"https", method=b"GET",
                          path=f"/backend-api/estuary/content?id=file_fake&ts=1&p=fs&cid=1&sig={FAKE_SIG}&v=0".encode(),
                          content=b"", headers=())
        flow = self.attempt(lambda: self.run_flow(req))
        self.assertTrue(flow.metadata["test_forwarded"])
        self.assertIn("Path: /backend-api/estuary/content", self.log.getvalue())
        self.assert_no_query_values(self.log.getvalue())

    def test_url_path_helper(self):
        self.assertEqual(gateway._url_path("/a/b?x=1&sig=2#frag"), "/a/b")
        self.assertEqual(gateway._url_path("/a/b#frag"), "/a/b")
        self.assertEqual(gateway._url_path("/a/b"), "/a/b")
        self.assertEqual(gateway._url_path(None), "")


@unittest.skipUnless(shutil.which("node") and (DASHBOARD_SERVER_DIR / "validation.mjs").exists(),
                     "node or dashboard server copy not available")
class DashboardAcceptsTheEventsTests(FlowBase):
    """바뀐 값(입력 유형 file·경로만 남긴 endpoint)으로 만든 이벤트를 대시보드 백엔드 검증(validation.mjs)이 그대로 받는지.
    이벤트 계약(칸 이름·허용 값)은 바꾸지 않았다. GW_TEST_DASHBOARD_SERVER_DIR = 운영 대시보드 server/ 사본."""

    def validate(self, events):
        validation = (DASHBOARD_SERVER_DIR / "validation.mjs").as_uri()
        script = (f"import * as validation from '{validation}';\n"
                  "import { readFileSync } from 'node:fs';\n"
                  "const events = JSON.parse(readFileSync(0, 'utf8'));\n"
                  "console.log(JSON.stringify(events.map((value) => { try { const e = validation.validateCanonicalEvent(value);"
                  " return ['ok', e.contentType ?? null, e.endpoint ?? null]; } catch (error) {"
                  " return [`${error.path ?? ''} ${error.message}`]; } })));\n")
        folder = Path(tempfile.mkdtemp(prefix="gw-node-final-"))
        self.addCleanup(shutil.rmtree, folder, True)
        (folder / "check.mjs").write_text(script, encoding="utf-8")
        result = subprocess.run(["node", str(folder / "check.mjs")], input=json.dumps(events), capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_backend_accepts_access_events_of_each_kind(self):
        self.use([], require=True)
        sends = (
            dict(),                                                                              # ChatGPT 질문
            dict(path=b"/backend-api/files", content=b'{"file_name":"a.txt","file_size":3}'),    # ChatGPT 파일 예약
            dict(host="sdmntprkoreacentral.oaiusercontent.com", method=b"PUT",
                 path=f"/files/{FILE_ID}/raw{SIGNED_QUERY}".encode(), content=b"abc",
                 content_type=b"application/octet-stream"),                                      # 서명 주소 원본 PUT
            dict(host="gemini.google.com", path=STREAM_GENERATE.encode(), content=GEMINI_FORM,
                 content_type=b"application/x-www-form-urlencoded"),                             # Gemini 질문
        )
        for index, kwargs in enumerate(sends):
            self.send(self.make(client=None, peer=f"203.0.113.{150 + index}", **kwargs))
        self.assertEqual(len(self.queued), len(sends))
        results = self.validate(self.queued)
        self.assertEqual(results, [
            ["ok", "prompt", "/backend-api/f/conversation"],
            ["ok", "file", "/backend-api/files"],
            ["ok", "file", f"/files/{FILE_ID}/raw"],
            ["ok", "prompt", STREAM_GENERATE.split("?", 1)[0]],
        ])


if __name__ == "__main__":
    unittest.main()
