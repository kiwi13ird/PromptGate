"""2026-10-11 - 실제 mitmproxy flow로 request()·response() 훅을 지난다.

1. 같은 업로드 재시도: 시도마다 막고(403·503), 대시보드 이벤트·확장 프로그램 알림은 처음 한 번만
   (ChatGPT 원본 PUT 같은 파일 번호 3번, Claude multipart 같은 바이트 + 이름 3번, 503 실패 닫힘, 검사 불가 허용 기록).
   다른 파일·다른 사용자·창이 지난 뒤 다시 올림은 따로 기록. 질문 이벤트는 줄이지 않는다.
   10/11 검토 반영: 간격은 이번 시도 첫 바이트 기준(본문을 천천히 보내는 재시도도 1건, 실제 DumpMaster + 소켓),
   [DEDUPE] 줄의 recordedRequestId(대시보드에 있는 첫 시도 번호).
2. Claude rpc protobuf 구조 기록: 가짜 개인정보·시험 표지 글자는 로그에 없고 marker 표시만, 전달 본문은 바이트 그대로
   (실제 DumpMaster + 로컬 upstream이 받은 본문 비교 포함), Detection 호출 없음.
   10/11 검토 반영: gzip 프레임 폭탄 255개의 메모리·시간 상한, 잘못 읽힌 글자의 기록 한계(틀 1자 수준) 고정.
가짜 값만 쓴다. 실행: python -m unittest tests.test_gateway_dedupe_proto -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import io
import json
import os
import socket
import threading
import time
import tracemalloc
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from tests.test_gateway_bundle_flows import (  # noqa: E402
    CFB, CLAUDE_UPLOAD_PATH, FILE_ID, ORG, RRN, SECRET, Base, fake_detection, failure_result,
)
from tests.gw_support import FixedSettings, png_bytes, run_hook, text_pdf, zip_bytes  # noqa: E402
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
import gateway_proto  # noqa: E402

FILE_ID_2 = "00000000-aaaa-8206-bbbb-000000000002"
FILE_ID_3 = "00000000-aaaa-8206-bbbb-000000000003"
PII_PDF = text_pdf(f"name hong RRN {RRN}")          # 개인정보 PDF: 가림 판정인데 PDF는 가릴 수 없어 403
HWPX = zip_bytes({"mimetype": "application/hwp+zip", "Contents/section0.xml": "<hs:sec/>"})
PROMPT = "PGTEST 주민번호 900101-1234568"           # 질문 칸을 찾는 가짜 질문(시험 표지 + 가상 주민등록번호)
PROMPT_UUID = "00000000-0000-4000-8000-00000000c0de"
PARENT_UUID = "00000000-0000-4000-8000-00000000beef"
MAP_KEY = "hong.gildong@example.test"
RPC_PATH = f"/api/organizations/{ORG}/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction"
TIMELINE_PATH = RPC_PATH.replace("PerformAction", "StreamTimeline")


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def fv(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def fl(number: int, payload) -> bytes:
    payload = payload.encode("utf-8") if isinstance(payload, str) else payload
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def perform_action(prompt: str = PROMPT) -> bytes:
    """PerformAction 비슷한 가짜 본문(지어낸 스키마): 대화 번호, 메시지{부모 번호, 내용{질문}, 시각}, 지도 항목{키: 메일}, 바이트.

    10/11 저녁: 메시지를 2 대신 15 아래에 둔다(운영 실측의 '다른 동작' 976바이트 PerformAction처럼). 질문 칸 2.3은 이제
    검사하므로(test_gateway_claude_rpc_prompt), 이 파일의 구조 기록·전달 시험은 질문 칸이 없는 다른 동작 본문으로 본다."""
    content = fl(1, prompt) + fv(2, 1)
    message = fl(1, PARENT_UUID) + fl(3, content) + fv(5, 1_760_000_000_000)
    return (fl(1, PROMPT_UUID) + fl(15, message) + fl(4, fl(1, MAP_KEY) + fl(2, "x"))
            + fl(6, bytes(range(0, 40, 3))) + fl(8, "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMw"))


def frame(payload: bytes, flags: int = 0) -> bytes:
    return bytes([flags]) + len(payload).to_bytes(4, "big") + payload


SECRET_VALUES = ("PGTEST", "900101", "1234568", "주민번호", PROMPT_UUID, PARENT_UUID, MAP_KEY, "hong", "gildong",
                 "example.test", "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMw", "1760000000000",
                 json.dumps("주민번호")[1:-1], json.dumps(PROMPT)[1:-1])


class DedupeBase(Base):
    """실제 report_dashboard_event·mapper로 이벤트를 만들고, 내구 큐·확장 알림 전송만 가로챈다."""

    def setUp(self):
        super().setUp()
        gateway.report_dashboard_event = self._orig[1]
        env = mock.patch.dict(os.environ, {"DASHBOARD_EVENT_URL": "http://127.0.0.1:9/api/events/ingest",
                                           "DASHBOARD_INGEST_TOKEN": "test-token-not-used"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("DASHBOARD_REPORT_ALLOW_EVENTS", None)
        self.queued, self.extension, self.log = [], [], io.StringIO()
        patchers = (mock.patch.object(gateway._gateway_event_outbox, "enqueue",
                                      side_effect=lambda e: self.queued.append(e) or SimpleNamespace(status="queued")),
                    mock.patch.object(gateway, "send_extension_event", side_effect=self.extension.append))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        getattr(gateway, "_dedupe_seen", {}).clear()   # 고치기 전 gateway.py로 같은 시험을 돌려 실패를 확인할 때도 불러지게

    def attempt(self, send, *, upstream_status=200):
        """요청 하나(시도 하나): request() → (전달이면 upstream 응답) → response(). 출력은 self.log에 모은다."""
        with contextlib.redirect_stdout(self.log):
            flow = send()
            if flow.response is None:
                flow.response = tutils.tresp(status_code=upstream_status)
                forwarded = True
            else:
                forwarded = False
            with mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
                gateway.response(flow)
        flow.metadata["test_forwarded"] = forwarded
        return flow

    def dedupe_lines(self):
        return [line for line in self.log.getvalue().splitlines() if line.startswith("[DEDUPE]")]

    def age_dedupe_entries(self, seconds):
        """기록 시각을 seconds만큼 앞으로 돌린다(기다리지 않고 창이 지난 상황을 만든다)."""
        for entry in gateway._dedupe_seen.values():
            entry[0] -= seconds

    def claude_retry(self, filename, ctype, content, attempt_no, path=CLAUDE_UPLOAD_PATH, peer=None):
        """Claude 재시도마다 브라우저는 새 multipart 경계를 만든다."""
        boundary = f"----gwretry{attempt_no}x{len(filename)}"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                f"Content-Type: {ctype}\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        req = tutils.treq(host="claude.ai", port=443, scheme=b"https", method=b"POST", path=path.encode(),
                          content=body, headers=((b"content-type", f"multipart/form-data; boundary={boundary}".encode()),))
        flow = tflow.tflow(req=req)
        if peer:
            flow.client_conn.peername = peer
        run_hook(gateway.request(flow))
        return flow

    def put(self, content, file_id=FILE_ID, filename="upload.bin"):
        gateway.CHATGPT_FILE_META[file_id] = filename
        req = tutils.treq(host="sdmntprkoreacentral.oaiusercontent.com", port=443, scheme=b"https", method=b"PUT",
                          path=f"/files/{file_id}/raw?se=2026-10-11".encode(), content=content,
                          headers=((b"content-type", b"application/octet-stream"),))
        return self.run_flow(req)


class ChatGptRetryTests(DedupeBase):
    def test_three_retries_of_each_blocked_file_record_once(self):
        # 10/11 실측과 같은 모양: 개인정보 PDF·HWP·HWPX를 ChatGPT가 같은 파일 번호로 3번씩 보냄
        cases = [(FILE_ID, PII_PDF, "p.pdf", "mask_application_failed"), (FILE_ID_2, CFB, "a.hwp", "file_uninspectable_other"),
                 (FILE_ID_3, HWPX, "a.hwpx", "file_uninspectable_other")]
        for file_id, content, filename, reason in cases:
            flows = [self.attempt(lambda: self.put(content, file_id, filename)) for _ in range(3)]
            for flow in flows:                                 # 시도마다 막는다(원본은 한 번도 안 나감)
                self.assertFalse(flow.metadata["test_forwarded"])
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(json.loads(flow.response.get_text())["error"]["reason_code"], reason)
        self.assertEqual([(e["finalAction"], e["reasonCode"], e["fileId"]) for e in self.queued],
                         [("BLOCK", reason, gateway.canonical_file_ref(file_id)) for file_id, _, _, reason in cases])
        self.assertEqual([(e["finalAction"], e["notify"]) for e in self.extension], [("BLOCK", True)] * 3)
        lines = self.dedupe_lines()
        self.assertEqual([line.rsplit("suppressed=", 1)[1] for line in lines], ["1", "2"] * 3)
        for line in lines:
            self.assertIn("service=ChatGPT action=BLOCK", line)
            for value in (FILE_ID, gateway.canonical_file_ref(FILE_ID), "p.pdf", "a.hwp", RRN):
                self.assertNotIn(value, line)

    def test_replay_of_the_slowest_measured_retry_sequence(self):
        # 운영 로그에서 가장 느린 재시도(10/07, 응답 → 다음 응답 1.868 s·2.174 s)를 실제 시간으로 다시 보낸다
        flows = [self.attempt(lambda: self.put(CFB))]
        for gap in (1.868, 2.174):
            time.sleep(gap)
            flows.append(self.attempt(lambda: self.put(CFB)))
        self.assertEqual([flow.response.status_code for flow in flows], [403, 403, 403])
        self.assertEqual(len(self.queued), 1)
        self.assertEqual(len(self.extension), 1)

    def test_different_files_are_recorded_separately(self):
        self.attempt(lambda: self.put(CFB, FILE_ID, "a.hwp"))
        self.attempt(lambda: self.put(CFB, FILE_ID_2, "a.hwp"))     # 같은 내용이어도 새 업로드(새 파일 번호)
        self.assertEqual(len(self.queued), 2)
        self.assertEqual(len(self.extension), 2)
        self.assertEqual(self.dedupe_lines(), [])

    def test_reupload_after_the_window_is_recorded(self):
        self.attempt(lambda: self.put(CFB))
        self.age_dedupe_entries(gateway.DEDUPE_WINDOW_SECONDS * 0.6)
        self.attempt(lambda: self.put(CFB))          # 창 안: 억제, 마지막 시각을 늦춘다
        self.age_dedupe_entries(gateway.DEDUPE_WINDOW_SECONDS * 0.6)
        self.attempt(lambda: self.put(CFB))          # 첫 시도 기준으로는 창을 넘었지만 앞 시도 기준으로는 안 → 억제
        self.assertEqual(len(self.queued), 1)
        self.age_dedupe_entries(gateway.DEDUPE_WINDOW_SECONDS + 0.5)
        flow = self.attempt(lambda: self.put(CFB))   # 창이 지난 뒤 다시 올림 → 기록
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(len(self.queued), 2)
        self.assertEqual(len(self.extension), 2)

    def test_a_different_verdict_for_the_same_file_is_recorded(self):
        self.attempt(lambda: self.put(b"plain memo", FILE_ID, "m.txt"))                  # 허용(이벤트 없음)
        gateway.check_detection = lambda *a, **k: failure_result("TIMEOUT", k["failure_policy"], k["request_id"])
        self.attempt(lambda: self.put(b"plain memo", FILE_ID, "m.txt"))                  # 503 detection_timeout
        gateway.check_detection = fake_detection(self.calls)
        self.attempt(lambda: self.put(SECRET.encode(), FILE_ID, "m.txt"))                # 403 doc_excerpt
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued],
                         [("BLOCK", "detection_timeout"), ("BLOCK", "doc_excerpt")])

    def test_fail_closed_503_retries_record_once(self):
        gateway.check_detection = lambda *a, **k: failure_result("TIMEOUT", k["failure_policy"], k["request_id"])
        flows = [self.attempt(lambda: self.put(b"plain memo", FILE_ID, "m.txt")) for _ in range(3)]
        self.assertEqual([flow.response.status_code for flow in flows], [503, 503, 503])
        self.assertEqual([(e["finalAction"], e["reasonCode"], e["degraded"]) for e in self.queued],
                         [("BLOCK", "detection_timeout", True)])
        self.assertEqual(len(self.extension), 1)

    def test_processing_error_503_retries_record_once(self):
        with mock.patch.object(gateway, "_classify_upload", side_effect=RuntimeError("boom")):
            flows = [self.attempt(lambda: self.put(b"plain memo")) for _ in range(3)]
        self.assertEqual([flow.response.status_code for flow in flows], [503, 503, 503])
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued], [("BLOCK", "file_masking_failed")])

    def test_uninspectable_allow_records_once(self):
        flows = [self.attempt(lambda: self.put(png_bytes(), FILE_ID, "p.png"), upstream_status=500) for _ in range(3)]
        self.assertTrue(all(flow.metadata["test_forwarded"] for flow in flows))    # 허용이라 시도마다 전달
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued],
                         [("ALLOW", "file_uninspectable_image")])
        self.assertEqual(len(self.extension), 1)

    def test_multipart_uploads_use_bytes_and_name(self):
        self.attempt(lambda: self.chatgpt_multipart(CFB, "a.hwp"))
        self.attempt(lambda: self.chatgpt_multipart(CFB, "a.hwp"))
        self.attempt(lambda: self.chatgpt_multipart(CFB, "b.hwp"))
        self.assertEqual(len(self.queued), 2)

    def test_prompt_events_are_not_reduced(self):
        for _ in range(2):
            flow = self.attempt(lambda: self.chatgpt_prompt(f"{SECRET} 요약"))
            self.assertEqual(flow.response.status_code, 403)
        self.assertEqual([(e["contentType"], e["finalAction"]) for e in self.queued], [("prompt", "BLOCK")] * 2)
        self.assertEqual(self.dedupe_lines(), [])


class ClaudeRetryTests(DedupeBase):
    def test_multipart_retries_with_new_boundaries_record_once(self):
        for index in range(3):
            flow = self.attempt(lambda: self.claude_retry("a.hwp", "application/x-hwp", CFB, index))
            self.assertEqual(flow.response.status_code, 403)
        for index in range(3):
            flow = self.attempt(lambda: self.claude_retry("p.pdf", "application/pdf", PII_PDF, index))
            self.assertEqual(flow.response.status_code, 403)
        self.assertEqual([(e["targetLlm"], e["reasonCode"]) for e in self.queued],
                         [("Claude", "file_uninspectable_other"), ("Claude", "mask_application_failed")])
        self.assertEqual(len(self.extension), 2)
        self.assertEqual(len(self.dedupe_lines()), 4)

    def test_double_upload_to_two_endpoints_records_once(self):
        # 옛 화면: 같은 파일을 wiggle/upload-file·convert_document 두 곳에 보냄(10/01 실측 4쌍)
        wiggle = f"/api/organizations/{ORG}/conversations/{PROMPT_UUID}/wiggle/upload-file"
        convert = f"/api/organizations/{ORG}/convert_document"
        self.attempt(lambda: self.claude_retry("a.hwp", "application/x-hwp", CFB, 1, path=wiggle))
        self.attempt(lambda: self.claude_retry("a.hwp", "application/x-hwp", CFB, 2, path=convert))
        self.assertEqual(len(self.queued), 1)

    def test_other_name_other_bytes_and_other_user_are_separate(self):
        self.attempt(lambda: self.claude_retry("a.hwp", "application/x-hwp", CFB, 1))
        self.attempt(lambda: self.claude_retry("b.hwp", "application/x-hwp", CFB, 2))            # 다른 이름
        self.attempt(lambda: self.claude_retry("a.hwp", "application/x-hwp", CFB + b"\x01", 3))  # 다른 바이트
        self.attempt(lambda: self.claude_retry("a.hwp", "application/x-hwp", CFB, 4, peer=("10.0.0.2", 50000)))
        self.assertEqual(len(self.queued), 4)

    def test_multi_file_upload_keys_each_file_record(self):
        clean = ("memo.txt", "text/plain", b"plain meeting memo")
        os.environ["DASHBOARD_REPORT_ALLOW_EVENTS"] = "true"
        self.addCleanup(os.environ.pop, "DASHBOARD_REPORT_ALLOW_EVENTS", None)
        for _ in range(2):
            self.attempt(lambda: self.claude_upload(clean, ("p.png", "image/png", png_bytes())))
        self.assertEqual([(e["finalAction"], e.get("reasonCode")) for e in self.queued],
                         [("ALLOW", None), ("ALLOW", "file_uninspectable_image")])
        self.attempt(lambda: self.claude_upload(clean, ("q.png", "image/png", png_bytes())))   # 이미지 이름이 다름
        self.assertEqual([(e["finalAction"], e.get("reasonCode")) for e in self.queued[2:]],
                         [("ALLOW", None), ("ALLOW", "file_uninspectable_image")])

    def test_unparsed_multipart_retries_record_once(self):
        raw = (b"--WRONG\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\n"
               + f"RRN {RRN}".encode() + b"\r\n--WRONG--\r\n")
        for index in range(3):     # 머리의 경계는 시도마다 바뀐다(본문 신원에서 뺀다)
            flow = self.attempt(lambda: self.claude_upload(raw_body=raw, boundary=f"expected-boundary-{index}"))
            self.assertEqual(flow.response.status_code, 403)
        self.assertEqual([e["reasonCode"] for e in self.queued], ["file_uninspectable_other"])
        self.attempt(lambda: self.claude_upload(raw_body=raw.replace(b"RRN", b"rrn"), boundary="expected-boundary-9"))
        self.assertEqual(len(self.queued), 2)


class DedupeMemoryTests(DedupeBase):
    def test_keys_are_bounded_and_old_keys_leave(self):
        with mock.patch.object(gateway, "DEDUPE_MAX_KEYS", 10):
            for index in range(25):
                self.attempt(lambda: self.claude_retry(f"f{index}.hwp", "application/x-hwp", CFB, index))
            self.assertLessEqual(len(gateway._dedupe_seen), 10)
        self.assertEqual(len(self.queued), 25)
        self.age_dedupe_entries(gateway.DEDUPE_RETENTION_SECONDS + 1)
        self.attempt(lambda: self.claude_retry("new.hwp", "application/x-hwp", CFB, 99))
        self.assertEqual(len(gateway._dedupe_seen), 1)

    def test_retention_covers_the_window_and_the_longest_wait(self):
        self.assertEqual(gateway.DEDUPE_WINDOW_SECONDS, 2 * gateway.DEDUPE_MEASURED_MAX_GAP_SECONDS)
        self.assertGreaterEqual(gateway.DEDUPE_RETENTION_SECONDS,
                                gateway.DEDUPE_WINDOW_SECONDS + 2 * gateway.SETTINGS_MAX_SECONDS)

    def test_a_failing_check_keeps_the_record(self):
        with mock.patch.object(gateway, "_dedupe_check", side_effect=RuntimeError("boom")):
            for _ in range(2):
                self.attempt(lambda: self.put(CFB))
        self.assertEqual(len(self.queued), 2)


class RetryArrivalTests(DedupeBase):
    """10/11 검토: 간격은 '앞 시도 기록 → 이번 시도 첫 바이트'. request 훅은 본문을 다 받은 뒤 불리므로(stream_large_bodies
    없음) 훅 시작 시각으로 재면 업로드 시간이 간격에 들어가 큰 파일·느린 회선의 재시도가 다시 2~3건씩 기록됐다."""

    def put_first_byte(self, seconds_ago=None, *, first_byte=None):
        """첫 바이트가 seconds_ago초 전에 온 ChatGPT 원본 PUT(본문을 받느라 그만큼 걸린 시도)."""
        gateway.CHATGPT_FILE_META[FILE_ID] = "a.hwp"
        req = tutils.treq(host="sdmntprkoreacentral.oaiusercontent.com", port=443, scheme=b"https", method=b"PUT",
                          path=f"/files/{FILE_ID}/raw?se=2026-10-11".encode(), content=CFB,
                          headers=((b"content-type", b"application/octet-stream"),))
        flow = tflow.tflow(req=req)
        flow.request.timestamp_start = first_byte if first_byte is not None else time.time() - seconds_ago
        run_hook(gateway.request(flow))
        return flow

    def test_body_upload_time_is_not_part_of_the_gap(self):
        self.attempt(lambda: self.put(CFB, FILE_ID, "a.hwp"))
        # 앞 시도 기록 6.3초 뒤에 응답 단계에 왔지만, 첫 바이트는 기록 0.3초 뒤(본문 받기 6.0초 > 창 4.348초)
        self.age_dedupe_entries(6.3)
        flow = self.attempt(lambda: self.put_first_byte(6.0))
        self.assertEqual(flow.response.status_code, 403)               # 집행은 시도마다 그대로
        self.assertEqual(len(self.queued), 1)
        self.assertEqual(len(self.extension), 1)
        line, = self.dedupe_lines()
        gap_ms = int(line.split("gap_ms=", 1)[1].split()[0])
        self.assertTrue(250 <= gap_ms <= 1000, line)                   # 재시도 대기만(약 300 ms)

    def test_implausible_first_byte_times_use_the_hook_start(self):
        # 지켜야 할 동작: 첫 바이트 시각이 미래(시계가 뒤로 감)거나 보관 시간보다 오래 전(시험 도구 기본값 2000년 포함)이면
        # request 훅 시작 시각으로 잰다 → 창이 지난 다시 올림은 기록
        cases = (time.time() + 30, time.time() - gateway.DEDUPE_RETENTION_SECONDS - 5, 946681200.0, float("nan"))
        self.attempt(lambda: self.put(CFB, FILE_ID, "a.hwp"))
        for index, first_byte in enumerate(cases, 2):
            self.age_dedupe_entries(gateway.DEDUPE_WINDOW_SECONDS + 1)
            self.attempt(lambda: self.put_first_byte(first_byte=first_byte))
            self.assertEqual(len(self.queued), index, first_byte)
        self.assertEqual(self.dedupe_lines(), [])

    def test_dedupe_line_names_the_recorded_request(self):
        # 억제한 시도의 403 본문·차단 이유 보기 링크 번호는 대시보드에 없다 → [DEDUPE] 줄에 기록한 첫 시도 번호를 함께 남긴다
        flows = [self.attempt(lambda: self.put(PII_PDF, FILE_ID, "p.pdf")) for _ in range(3)]
        recorded = [event["requestId"] for event in self.queued]
        self.assertEqual(len(recorded), 1)
        self.assertEqual(json.loads(flows[0].response.get_text())["error"]["request_id"], recorded[0])
        lines = self.dedupe_lines()
        self.assertEqual(len(lines), 2)
        for flow, line in zip(flows[1:], lines):
            attempt_id = json.loads(flow.response.get_text())["error"]["request_id"]
            self.assertNotEqual(attempt_id, recorded[0])
            self.assertIn(f" requestId={attempt_id} ", line)
            self.assertIn(f" recordedRequestId={recorded[0]} ", line)


class SlowBodyRetryEndToEndTests(DedupeBase):
    """실제 mitmproxy(DumpMaster)에 소켓으로 머리를 먼저 보내고 본문을 천천히 흘려 보낸다(10/11 검토 재현과 같은 모양).
    창을 0.8초로 줄여 빨리 돈다: 재시도 대기 0.3초 + 본문 1.6초 > 창. 고치기 전에는 시도마다 기록(이벤트 3건·알림 3번)."""

    WINDOW = 0.8
    TRICKLE = 1.6
    RETRY_WAIT = 0.3

    def test_retry_whose_body_outlasts_the_window_records_once(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        body = CFB + b"\x00" * (256 * 1024)      # 가짜 HWP(검사할 수 없는 형식 → Detection 전에 403)
        gateway.CHATGPT_FILE_META[FILE_ID] = "a.hwp"
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        state = {}

        async def run_master():
            master = DumpMaster(options.Options(listen_host="127.0.0.1", listen_port=port),
                                with_termlog=False, with_dumper=False)
            master.addons.add(gateway)
            state["master"] = master
            await master.run()

        def put_once(trickle):
            sock = socket.create_connection(("127.0.0.1", port), timeout=30)
            head = (f"PUT http://sdmntprkoreacentral.oaiusercontent.com/files/{FILE_ID}/raw?se=2026-10-11 HTTP/1.1\r\n"
                    f"Host: sdmntprkoreacentral.oaiusercontent.com\r\nContent-Type: application/octet-stream\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
            sock.sendall(head)
            chunks = 16
            size = len(body) // chunks + 1
            for index in range(chunks):
                sock.sendall(body[index * size:(index + 1) * size])
                if trickle:
                    time.sleep(trickle / chunks)
            data = b""
            while True:
                part = sock.recv(65536)
                if not part:
                    break
                data += part
            sock.close()
            return data.split(b"\r\n", 1)[0].decode()

        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=lambda: loop.run_until_complete(run_master()), daemon=True)
        with mock.patch.object(gateway, "DEDUPE_WINDOW_SECONDS", self.WINDOW), \
                mock.patch.object(gateway._gateway_event_outbox, "start", lambda: None), \
                mock.patch.object(gateway._gateway_metrics_publisher, "start", lambda: None), \
                mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None), \
                contextlib.redirect_stdout(self.log):
            thread.start()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
                time.sleep(0.1)
            statuses = [put_once(0)]
            for _ in range(2):                   # ChatGPT처럼 같은 파일 번호로 두 번 더(본문은 천천히)
                time.sleep(self.RETRY_WAIT)
                statuses.append(put_once(self.TRICKLE))
            time.sleep(0.2)
            loop.call_soon_threadsafe(state["master"].shutdown)
            thread.join(10)
        self.assertEqual([status.split(" ", 2)[1] for status in statuses], ["403"] * 3)
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued],
                         [("BLOCK", "file_uninspectable_other")])
        self.assertEqual(len(self.extension), 1)
        lines = self.dedupe_lines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            gap_ms = int(line.split("gap_ms=", 1)[1].split()[0])
            self.assertLess(gap_ms, self.WINDOW * 1000, line)       # 본문 1.6초는 간격에 없다


class ProtoLogTests(Base):
    """Claude rpc protobuf 구조 기록. 값은 남기지 않고 표시만."""

    def setUp(self):
        super().setUp()
        gateway._claude_rpc_shape_counts.clear()
        gateway._claude_rpc_shape_window[0] = 0.0

    def rpc(self, body: bytes, content_type=b"application/proto", path=RPC_PATH, headers=()):
        req = tutils.treq(host="claude.ai", port=443, scheme=b"https", method=b"POST", path=path.encode(),
                          content=body, headers=((b"content-type", content_type),) + tuple(headers))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            flow = self.run_flow(req)
        lines = [line for line in out.getvalue().splitlines() if line.startswith("[CLAUDE-RPC]")]
        return flow, lines, out.getvalue()

    @staticmethod
    def record(line):
        return json.loads(line[len("[CLAUDE-RPC] "):])

    def assert_no_values(self, text):
        for value in SECRET_VALUES:
            self.assertNotIn(value, text)

    def test_marker_field_is_found_without_logging_values(self):
        body = perform_action()
        flow, lines, output = self.rpc(body)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.raw_content, body)               # 전달 본문은 바이트 그대로
        self.assertEqual((self.calls, self.reports), ([], []))         # Detection 호출·기록 없음(형식 찾기만)
        self.assert_no_values(output)                                  # 줄 전체(다른 로그 포함)에 값 없음
        record = self.record(lines[0])
        self.assertEqual((record["format"], record["bytes"], record["method"]),
                         ("proto", len(body), "anthropic.bard.api.v1alpha.ConversationService/PerformAction"))
        self.assertEqual(record["marker_paths"], ["15.3.1"])
        leaves = {leaf["path"]: leaf for leaf in record["leaves"]}
        self.assertEqual(set(leaves["15.3.1"]), {"path", "wire", "len", "kind", "flags"})
        self.assertEqual((leaves["15.3.1"]["kind"], leaves["15.3.1"]["wire"], leaves["15.3.1"]["len"]),
                         ("text", 2, len(PROMPT.encode())))
        self.assertEqual(leaves["15.3.1"]["flags"],
                         ["has_whitespace", "has_hangul", "has_latin_word", "digit_run_6plus", "marker"])
        self.assertEqual(leaves["1"]["flags"], ["digit_run_6plus", "looks_uuid"])     # 가짜 UUID의 00000000
        self.assertEqual(leaves["15.1"]["flags"], ["digit_run_6plus", "looks_uuid"])
        self.assertEqual(leaves["4.1"]["flags"], ["has_latin_word", "has_at_sign"])   # 지도 키(메일)도 값은 없음
        self.assertEqual(leaves["8"]["flags"], ["looks_base64"])
        self.assertEqual((leaves["6"]["kind"], leaves["15.5"]["kind"]), ("bytes", "varint"))
        self.assertNotIn("flags", leaves["15.5"])

    def test_stream_frames_with_gzip(self):
        body = frame(fl(1, "첫 프레임")) + frame(gzip.compress(perform_action(), mtime=0), 1)
        flow, lines, output = self.rpc(body, b"application/connect+proto", TIMELINE_PATH,
                                       ((b"connect-content-encoding", b"gzip"),))
        self.assertEqual(flow.request.raw_content, body)
        self.assert_no_values(output)
        self.assertNotIn("첫 프레임", output)
        record = self.record(lines[0])
        self.assertEqual((record["format"], record["connect_content_encoding"]), ("connect+proto", "gzip"))
        self.assertEqual(record["marker_paths"], ["1:15.3.1"])
        self.assertEqual({leaf["frame"] for leaf in record["leaves"]}, {0, 1})
        _, lines, _ = self.rpc(body, b"application/connect+proto", TIMELINE_PATH)    # 압축 방식 머리 없음
        self.assertEqual([(leaf["kind"], leaf.get("reason")) for leaf in self.record(lines[0])["leaves"]][-1],
                         ("unparsed", "compressed_no_encoding"))

    def test_unary_content_encoding(self):
        body = gzip.compress(perform_action(), mtime=0)
        flow, lines, output = self.rpc(body, headers=((b"content-encoding", b"gzip"),))
        self.assertEqual(flow.request.raw_content, body)
        self.assertEqual(self.record(lines[0])["marker_paths"], ["15.3.1"])
        self.assert_no_values(output)
        _, lines, _ = self.rpc(perform_action(), headers=((b"content-encoding", b"br"),))
        self.assertEqual(self.record(lines[0])["leaves"],
                         [{"path": "", "wire": None, "len": len(perform_action()), "kind": "unparsed",
                           "reason": "content_encoding"}])

    def test_marker_bypasses_the_hourly_limit_with_its_own_cap(self):
        plain = perform_action("평범한 질문입니다")
        for _ in range(gateway.CLAUDE_RPC_SHAPE_PER_HOUR):
            self.assertEqual(len(self.rpc(plain)[1]), 1)
        self.assertEqual(self.rpc(plain)[1], [])                      # 메서드 상한
        for _ in range(gateway.CLAUDE_RPC_MARKER_PER_HOUR):
            _, lines, _ = self.rpc(perform_action())
            self.assertEqual(self.record(lines[0])["marker_paths"], ["15.3.1"])
        self.assertEqual(self.rpc(perform_action())[1], [])           # 표지 상한
        with mock.patch.dict(os.environ, {"GATEWAY_LOG_CLAUDE_RPC_SHAPE": "0"}):
            gateway._claude_rpc_shape_window[0] = 0.0
            self.assertEqual(self.rpc(perform_action())[1], [])

    def test_malformed_and_large_bodies(self):
        flow, lines, _ = self.rpc(b'{"prompt": "x"}')
        self.assertIsNone(flow.response)
        self.assertEqual(self.record(lines[0])["leaves"],
                         [{"path": "", "wire": None, "len": 15, "kind": "unparsed", "reason": "not_protobuf"}])
        many = b"".join(fl(1, f"항목 {index} PGTEST") for index in range(3000))
        flow, lines, output = self.rpc(many)
        self.assertEqual(flow.request.raw_content, many)
        self.assertLessEqual(len(lines[0]), gateway.CLAUDE_RPC_LINE_MAX + len("[CLAUDE-RPC] "))
        record = self.record(lines[0])
        self.assertEqual((record["leaves_total"], record["truncated"]), (3000, True))
        self.assertLessEqual(len(record["leaves"]), gateway.CLAUDE_RPC_PROTO_MAX_LEAVES)
        self.assertEqual(len(record["marker_paths"]), 10)
        self.assertNotIn("항목", output)
        self.assertNotIn("PGTEST", output)

    def test_walker_failure_never_changes_forwarding(self):
        body = perform_action()
        with mock.patch.object(gateway_proto, "leaves", side_effect=RuntimeError("boom")):
            flow, lines, output = self.rpc(body)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.raw_content, body)
        self.assertEqual(lines, ["[CLAUDE-RPC] shape log failed error_type= RuntimeError"])
        self.assert_no_values(output)

    def test_compressed_frame_bomb_is_bounded_in_memory_and_time(self):
        # 10/11 검토: 압축 해제 상한이 프레임마다 따로였다. 0바이트 4 MiB를 gzip한 프레임 255개(본문 약 1 MiB)로
        # 동기 request 훅 안에서 메모리가 약 1 GiB까지 올랐다 → 상한은 본문 전체 합계, 남은 압축 프레임은 풀지 않음(limit)
        one = gzip.compress(b"\x00" * gateway_proto.MAX_DECOMPRESSED_BYTES, compresslevel=9, mtime=0)
        body = b"".join(frame(one, 1) for _ in range(255))
        self.assertLessEqual(len(body), gateway.CLAUDE_RPC_SHAPE_MAX_BODY)     # 기록 대상 크기 안
        headers = ((b"connect-content-encoding", b"gzip"),)
        started = time.perf_counter()
        flow, lines, _ = self.rpc(body, b"application/connect+proto", TIMELINE_PATH, headers)
        elapsed = time.perf_counter() - started
        self.assertEqual(flow.request.raw_content, body)
        self.assertIsNone(flow.response)
        record = self.record(lines[0])
        self.assertEqual(record["leaves_total"], 255)
        self.assertEqual([(leaf["kind"], leaf.get("reason")) for leaf in record["leaves"]][:3],
                         [("unparsed", "not_protobuf"), ("unparsed", "limit"), ("unparsed", "limit")])
        self.assertLess(elapsed, 0.25)
        gateway._claude_rpc_shape_counts.clear()
        tracemalloc.start()
        try:
            self.rpc(body, b"application/connect+proto", TIMELINE_PATH, headers)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLessEqual(peak, 64 * 1024 * 1024)

    def test_misread_prompt_leaves_only_framing_characters(self):
        # 알려진 한계(모듈 설명·NOTES): 글자가 메시지로 잘못 읽히면 틀 바이트가 경로 번호·len으로 남는다(단계마다 1자 수준).
        # '* 김철수 900101-1234568 확인.'(34바이트) = 필드 5(0x2A '*') 길이 32(0x20 ' ') → 되살릴 수 있는 것은 '* '뿐
        prompt = "* 김철수 900101-1234568 확인."
        _, lines, output = self.rpc(perform_action(prompt))
        misread = [(leaf["path"], leaf["wire"], leaf["len"]) for leaf in self.record(lines[0])["leaves"]
                   if leaf["path"].startswith("15.3.1.")]
        self.assertEqual(misread, [("15.3.1.5", 2, 32)])
        self.assertEqual(bytes([5 << 3 | 2, 32]), prompt.encode()[:2])
        for value in ("900101", "1234568", "김철수", "확인", json.dumps(prompt)[1:-1]):
            self.assertNotIn(value, output)


class ProtoForwardingEndToEndTests(unittest.TestCase):
    """실제 mitmproxy(DumpMaster)에 gateway를 올리고, 로컬 upstream이 받은 본문이 보낸 본문과 바이트까지 같은지 본다."""

    def test_upstream_receives_identical_bytes(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        received = []

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.headers.get("content-type"), self.rfile.read(int(self.headers.get("content-length") or 0))))
                self.send_response(200)
                self.send_header("content-type", "application/proto")
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)

        class Redirect:
            def request(self, flow):
                flow.request.host, flow.request.port, flow.request.scheme = "127.0.0.1", upstream.server_address[1], "http"

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        state = {}

        async def run_master():
            master = DumpMaster(options.Options(listen_host="127.0.0.1", listen_port=port),
                                with_termlog=False, with_dumper=False)
            master.addons.add(gateway, Redirect())
            state["master"] = master
            await master.run()

        bodies = [(b"application/proto", perform_action()),
                  (b"application/connect+proto", frame(perform_action()) + frame(fl(1, "둘째")))]
        calls, out = [], io.StringIO()
        gateway._claude_rpc_shape_counts.clear()
        gateway._claude_rpc_shape_window[0] = 0.0
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=lambda: loop.run_until_complete(run_master()), daemon=True)
        with mock.patch.object(gateway, "check_detection", fake_detection(calls)), \
                mock.patch.object(gateway, "send_to_next_module", lambda event: None), \
                contextlib.redirect_stdout(out):
            thread.start()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
                time.sleep(0.1)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
            for content_type, body in bodies:
                path = RPC_PATH if content_type == b"application/proto" else TIMELINE_PATH
                request = urllib.request.Request(f"http://claude.ai{path}", method="POST", data=body,
                                                 headers={"content-type": content_type.decode()})
                with opener.open(request, timeout=10) as response:
                    self.assertEqual(response.status, 200)
            time.sleep(0.2)
            loop.call_soon_threadsafe(state["master"].shutdown)
            thread.join(10)
        self.assertEqual([body for _, body in received], [body for _, body in bodies])
        self.assertEqual(calls, [])
        output = out.getvalue()
        for value in SECRET_VALUES + ("둘째",):
            self.assertNotIn(value, output)
        records = [json.loads(line[len("[CLAUDE-RPC] "):]) for line in output.splitlines()
                   if line.startswith("[CLAUDE-RPC] {")]
        self.assertEqual([(r["format"], r["marker_paths"]) for r in records],
                         [("proto", ["15.3.1"]), ("connect+proto", ["0:15.3.1"])])


class ProtoDeployTests(bundle.DeployOrderTests):
    """새 gateway.py는 gateway_proto.py 없이 불러지지 않는다(둘을 함께 올린다)."""

    def test_new_gateway_without_the_proto_module_fails_to_import(self):
        folder = self.staged()
        (folder / "gateway_proto.py").unlink()
        result = self.import_gateway(folder)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gateway_proto", result.stderr)

    # 부모 시험은 test_gateway_bundle_flows에서 이미 돈다
    test_new_gateway_with_the_old_metrics_module_fails_to_import = None
    test_all_new_files_import = None
    test_environment_fallback_and_disk_cache_at_start = None


if __name__ == "__main__":
    unittest.main()
