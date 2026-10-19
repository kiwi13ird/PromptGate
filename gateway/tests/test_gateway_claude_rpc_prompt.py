"""2026-10-11 저녁 - Claude 새 화면 질문(PerformAction 잎 2.3) 검사. 실제 mitmproxy flow로 request()·response() 훅을 지난다.

본문은 10/11 05:08 UTC 운영 구조 기록(값 없음)과 같은 잎 경로·종류·길이로 만든 가짜 protobuf다(값은 모두 지어냄).
  질문 전송: 1.1.1 글자 21 · 1.1.2 · 1.2 UUID · 1.3 · 1.7.{1,2,3,6,8,10} · 1.14 글자 5 · 1.15 바이트 32 · 2.1/2.2 UUID ·
            2.3 질문 · 2.7.2 글자 15 · 2.8.1.{1,7} · 2.8.1.8.1.{1 글자, 2} × 12 · 2.8.1.{10,14} · 2.12 글자 10 · 2.13 글자 5 · 2.18
  다른 동작(976바이트): 1.2 · 1.3 · 1.7.* · 1.14 · 15.1.7.2 · 15.1.8.1.* · 15.1.12 · 15.1.13 · 15.1.18 (질문 칸 없음)
사용자 결정: 질문을 검사하고 개인정보면 막는다(가림 없음, GATEWAY_CLAUDE_RPC_MASK=1일 때만 가림).
가짜 값만 쓴다. 실행: python -m unittest tests.test_gateway_claude_rpc_prompt -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from tests.test_gateway_bundle_flows import RRN, SECRET, SlowDetection, failure_result, fake_detection  # noqa: E402
from tests.test_gateway_dedupe_proto import DedupeBase, fl, frame, fv, varint  # noqa: E402
from tests.test_detection_client import RawDetection  # noqa: E402
from tests.gw_support import FixedSettings, run_hook  # noqa: E402
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
import gateway_proto  # noqa: E402

RPC = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/"
PERFORM_PATH = RPC + "PerformAction"
ACCOUNT = "acct_0000000000000000"            # 1.1.1 글자 21(지어낸 값)
CONV_UUID = "00000000-0000-4000-8000-0000000c0de1"
MSG_UUID = "00000000-0000-4000-8000-0000000c0de2"
PARENT_UUID = "00000000-0000-4000-8000-0000000c0de3"
MODEL = "claude-fake-4-5"                    # 2.7.2 글자 15
LOCALE = "ko-KR"                             # 1.14·2.13 글자 5
TIME_ZONE = "Asia/Seoul"                     # 2.12 글자 10
NONCE = bytes(range(0x80, 0xA0))             # 1.15 바이트 32(무엇인지 모름: 무결성 표지일 수 있음)
TOOL_LENGTHS = (47, 80, 55, 88, 89, 88, 58, 91, 49, 82, 23, 27)
TOOLS = [("fake_feature_" + "abcdefghij" * 10)[:n] for n in TOOL_LENGTHS]
PII_PROMPT = f"PGTEST 주민번호 {RRN} 확인해줘"     # 가짜 주민등록번호(가짜 Detection이 가림 판정)
CLEAN_PROMPT = "PGTEST 다음 주 회의 일정 정리해줘"
DOC_PROMPT = f"{SECRET} 요약해줘"                   # 보호 문서 일치(가짜 Detection이 차단)
PROMPT_VALUES = (RRN, "900101", "1234567", "주민번호", "회의 일정", SECRET, ACCOUNT, CONV_UUID, MSG_UUID, PARENT_UUID,
                 json.dumps("주민번호")[1:-1], json.dumps(PII_PROMPT)[1:-1])
SEND_SHAPE = (
    [("1.1.1", "text", 21), ("1.1.2", "varint", 1), ("1.2", "text", 36), ("1.3", "varint", 1)]
    + [(f"1.7.{n}", "varint", 1) for n in (1, 2, 3, 6, 8, 10)]
    + [("1.14", "text", 5), ("1.15", "bytes", 32), ("2.1", "text", 36), ("2.2", "text", 36), ("2.3", "text", None),
       ("2.7.2", "text", 15), ("2.8.1.1", "varint", 1), ("2.8.1.7", "varint", 1)]
    + [leaf for n in TOOL_LENGTHS for leaf in (("2.8.1.8.1.1", "text", n), ("2.8.1.8.1.2", "varint", 1))]
    + [("2.8.1.10", "varint", 1), ("2.8.1.14", "varint", 1), ("2.12", "text", 10), ("2.13", "text", 5),
       ("2.18", "varint", 1)])


def client_info(*, full=True) -> bytes:
    flags = b"".join(fv(n, 1) for n in (1, 2, 3, 6, 8, 10))
    head = fl(1, fl(1, ACCOUNT) + fv(2, 1)) if full else b""
    tail = fl(15, NONCE) if full else b""
    return head + fl(2, CONV_UUID) + fv(3, 1) + fl(7, flags) + fl(14, LOCALE) + tail


def settings_block() -> bytes:
    tools = fl(8, b"".join(fl(1, fl(1, name) + fv(2, 1)) for name in TOOLS))   # 8 하나 안에 1이 12번(크기가 실측과 같다)
    return fl(1, fv(1, 1) + fv(7, 1) + tools + fv(10, 1) + fv(14, 1))


def send_message(*prompts) -> bytes:
    return (fl(1, MSG_UUID) + fl(2, PARENT_UUID) + b"".join(fl(3, prompt) for prompt in prompts)
            + fl(7, fl(2, MODEL)) + fl(8, settings_block()) + fl(12, TIME_ZONE) + fl(13, LOCALE) + fv(18, 1))


def perform_action(*prompts, actions=None) -> bytes:
    """질문 전송 PerformAction(운영 실측 모양). actions: 동작 메시지(2)를 여러 개 넣을 때 각 질문 목록."""
    groups = actions if actions is not None else [prompts or (PII_PROMPT,)]
    return fl(1, client_info()) + b"".join(fl(2, send_message(*group)) for group in groups)


def other_action() -> bytes:
    """같은 화면의 다른 PerformAction(976바이트 실측 모양: 2 대신 15, 질문 칸 없음)."""
    inner = fl(7, fl(2, MODEL)) + fl(8, settings_block()) + fl(12, TIME_ZONE) + fl(13, LOCALE) + fv(18, 1)
    return fl(1, client_info(full=False)) + fl(15, fl(1, inner))


def leaf_shape(body: bytes):
    return [(r["path"], r["kind"], r["length"]) for r in gateway_proto.walk(body)]


class RpcBase(DedupeBase):
    """실제 report_dashboard_event·mapper로 이벤트를 만들고 내구 큐·확장 알림만 가로챈다(DedupeBase)."""

    def setUp(self):
        super().setUp()
        gateway._claude_rpc_shape_counts.clear()
        gateway._claude_rpc_shape_window[0] = 0.0
        os.environ.pop("GATEWAY_CLAUDE_RPC_MASK", None)
        self.use_settings()                       # 기본 처리 설정(질문 원본 전송 0.5초)

    def env(self, **values):
        patcher = mock.patch.dict(os.environ, values)
        patcher.start()
        self.addCleanup(patcher.stop)

    def send(self, body, *, path=PERFORM_PATH, content_type=b"application/proto", headers=(), peer=None,
             method=b"POST", client_id=None):
        headers = ((b"content-type", content_type),) + tuple(headers)
        if client_id:
            headers += ((b"x-llmsgw-client-id", client_id.encode()),)
        req = tutils.treq(host="claude.ai", port=443, scheme=b"https", method=method, path=path.encode(),
                          content=body, headers=headers)
        flow = tflow.tflow(req=req)
        if peer:
            flow.client_conn.peername = peer
        run_hook(gateway.request(flow))
        return flow

    def rpc(self, body, **kwargs):
        return self.attempt(lambda: self.send(body, **kwargs))

    def connect_error(self, flow):
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.headers.get("content-type"), "application/json")
        body = json.loads(flow.response.get_text())
        self.assertEqual(set(body), {"code", "message"})
        return flow.response.status_code, body["code"], body["message"]

    def rpc_lines(self):
        return [json.loads(line[len("[CLAUDE-RPC] "):]) for line in self.log.getvalue().splitlines()
                if line.startswith("[CLAUDE-RPC] {")]

    def events(self):
        return [(e["contentType"], e["targetLlm"], e["finalAction"], e["recommendedAction"], e.get("reasonCode"),
                 e["degraded"]) for e in self.queued]


class FixtureTests(unittest.TestCase):
    def test_fixture_mirrors_the_observed_structure(self):
        body = perform_action("x" * 42)
        expected = [(path, kind, 42 if length is None else length) for path, kind, length in SEND_SHAPE]
        self.assertEqual(leaf_shape(body), expected)                  # 운영 기록과 같은 47잎
        self.assertEqual(len(body), 1154)                             # 운영 기록 bytes와 같은 크기(질문 42바이트)
        other = other_action()
        self.assertEqual(len(other), 976)
        paths = [path for path, _, _ in leaf_shape(other)]
        self.assertEqual(len(paths), 41)
        self.assertEqual(paths[:9], ["1.2", "1.3"] + [f"1.7.{n}" for n in (1, 2, 3, 6, 8, 10)] + ["1.14"])
        self.assertTrue(all(path.startswith("15.1.") for path in paths[9:]))


class ValuesAtTests(unittest.TestCase):
    """gateway_proto.values_at: 판정 없이 정확한 경로의 원본 바이트."""

    def test_exact_path_raw_bytes_regardless_of_kind(self):
        prompts = ["평범한 질문", "제어\x01문자 900101-1234567", "\x12\x0e900101-1234567", "* 김철수 900101-1234568 확인.", ""]
        body = perform_action(*prompts)
        values, reason = gateway_proto.values_at(body, "2.3")
        self.assertIsNone(reason)
        self.assertEqual([value for _, value in values], [p.encode() for p in prompts])
        kinds = {r["loc"]: r["kind"] for r in gateway_proto.walk(body) if r["path"].startswith("2.3")}
        self.assertEqual([kinds.get(loc) for loc, _ in values], ["text", "bytes", None, None, "empty"])
        # 제어 문자 → bytes(text_values에는 없음), 메시지로 읽힌 두 질문은 잎이 아님(None) - 그래도 원본 값은 나온다
        self.assertNotIn(values[1][0], [loc for _, loc, _ in gateway_proto.text_values(body)])
        for index, (loc, _) in enumerate(values):                     # loc는 walk·replace_text의 자리와 같다
            replaced = gateway_proto.replace_text(body, loc, "X")
            if kinds.get(loc) is None:
                self.assertIsNone(replaced)                           # 메시지 자리는 replace_text가 바꾸지 않음(가림 → 차단)
            else:
                self.assertEqual(gateway_proto.values_at(replaced, "2.3")[0][index], (loc, b"X"))

    def test_repeated_actions_and_missing_paths(self):
        body = perform_action(actions=[("하나",), ("둘", "셋")])
        values, reason = gateway_proto.values_at(body, "2.3")
        self.assertEqual(([v for _, v in values], reason), (["하나".encode(), "둘".encode(), "셋".encode()], None))
        self.assertEqual(gateway_proto.values_at(other_action(), "2.3"), ([], None))
        self.assertEqual(gateway_proto.values_at(b"", "2.3"), ([], None))
        # 2가 표준 파서로도 메시지가 아니면 사유(10/11 검토 1: 사유 줄이 남게). 값이 없다고 조용히 넘기지 않는다
        self.assertEqual(gateway_proto.values_at(fl(2, "글자만 있는 2"), "2.3"), ([], "not_protobuf"))

    def test_unreadable_bodies(self):
        self.assertEqual(gateway_proto.values_at(b"\xff\xff\xff", "2.3"), ([], "not_protobuf"))
        self.assertEqual(gateway_proto.values_at(perform_action()[:-3], "2.3"), ([], "not_protobuf"))
        self.assertEqual(gateway_proto.values_at(b"\x08\x01" * (gateway_proto.MAX_FIELDS + 1), "2.3"), ([], "limit"))
        self.assertEqual(gateway_proto.values_at(b"\x00" * 10, "2.3", max_bytes=5), ([], "too_large"))
        self.assertEqual(gateway_proto.values_at(perform_action(), "a.b"), ([], "error"))

    def test_prompt_content_cannot_exhaust_the_limits(self):
        # 질문 칸 안은 읽지 않는다: 숫자 필드 2만 개로 읽히는 'hi' 반복, 메시지처럼 생긴 깊은 중첩도 그대로 값 하나
        nested = b"x"
        for _ in range(200):
            nested = fl(1, nested)
        for prompt in ("hi" * 30000, nested):
            values, reason = gateway_proto.values_at(perform_action(prompt), "2.3")
            self.assertEqual((len(values), reason), (1, None))
            self.assertEqual(values[0][1], prompt.encode() if isinstance(prompt, str) else prompt)


class PromptVerdictTests(RpcBase):
    def test_personal_data_blocks_with_a_connect_error(self):
        body = perform_action(PII_PROMPT)
        flow = self.rpc(body)
        self.assertFalse(flow.metadata["test_forwarded"])            # upstream으로 안 나감
        status, code, message = self.connect_error(flow)
        self.assertEqual((status, code), (403, "permission_denied"))
        self.assertEqual(message, gateway.CLAUDE_RPC_MASK_BLOCK_MESSAGE)
        self.assertTrue(flow.response.headers.get("X-LLMSGW-Review-URL", "").startswith("http"))
        call, = self.calls
        self.assertEqual(call["text"], gateway.normalize_text(PII_PROMPT))
        self.assertEqual(call["source"], {"service": "Claude", "endpoint": PERFORM_PATH, "content_type": "prompt"})
        self.assertEqual((call["timeout"], call["failure_policy"]), (0.5, "FAIL_OPEN"))   # 질문 규칙(기본값)
        self.assertEqual(self.events(), [("prompt", "Claude", "BLOCK", "BLOCK", "mask_application_failed", False)])
        event, = self.queued
        self.assertEqual(event["detections"][0]["detector"], "SIGNATURE")
        self.assertEqual(event["detections"][0]["entityCounts"], [{"entityType": "KR_RRN", "count": 1}])
        self.assertEqual(event["enforcement"], {"applied": True, "httpStatus": 403})
        self.assertEqual(event["endpoint"], PERFORM_PATH)
        self.assertNotIn("maskEvidence", event)
        notice, = self.extension
        self.assertEqual((notice["finalAction"], notice["notify"], notice["requestId"]), ("BLOCK", True, event["requestId"]))
        self.assertEqual((flow.metadata["gw_action"], flow.metadata["gw_latency_sample"]), ("block", True))
        for value in PROMPT_VALUES:
            self.assertNotIn(value, self.log.getvalue())

    def test_clean_prompt_is_forwarded_byte_identical_like_other_prompts(self):
        body = perform_action(CLEAN_PROMPT)
        for allow_events in (None, "true"):
            with self.subTest(allow_events=allow_events):
                self.queued.clear()
                self.extension.clear()
                self.calls.clear()
                with mock.patch.dict(os.environ, {"DASHBOARD_REPORT_ALLOW_EVENTS": allow_events} if allow_events else {}):
                    flow = self.rpc(body)
                    chatgpt = self.attempt(lambda: self.chatgpt_prompt(CLEAN_PROMPT))
                self.assertTrue(flow.metadata["test_forwarded"])
                self.assertEqual(flow.request.raw_content, body)
                self.assertEqual(len(self.calls), 2)
                self.assertEqual(self.calls[0]["text"], self.calls[1]["text"])
                self.assertTrue(chatgpt.metadata["test_forwarded"])
                rows = [(e["targetLlm"], e["contentType"], e["finalAction"], e["detectionOutcome"]) for e in self.queued]
                if allow_events:     # 다른 질문과 같은 허용 기록 정책(DASHBOARD_REPORT_ALLOW_EVENTS)
                    self.assertEqual(rows, [("Claude", "prompt", "ALLOW", "NO_MATCH"), ("ChatGPT", "prompt", "ALLOW", "NO_MATCH")])
                else:
                    self.assertEqual(rows, [])
                    self.assertIn("reason=ALLOW event reporting disabled", self.log.getvalue())
                self.assertEqual(flow.metadata["gw_action"], "allow")

    def test_protected_document_blocks_with_the_detection_reason(self):
        flow = self.rpc(perform_action(DOC_PROMPT))
        status, code, message = self.connect_error(flow)
        self.assertEqual((status, code, message), (403, "permission_denied", "보호 문서와 일치해 전송을 차단했습니다."))
        self.assertEqual(self.events(), [("prompt", "Claude", "BLOCK", "BLOCK", "doc_excerpt", False)])
        self.assertEqual(self.queued[0]["detections"][0]["detector"], "WINDOW_HASH")
        self.assertEqual(len(self.extension), 1)

    def test_detection_without_a_user_message_uses_the_default_block_text(self):
        def check(*args, **kwargs):
            self.calls.append(kwargs)
            return bundle.DetectionResult(blocked=True, reason="x", request_id=kwargs["request_id"], action="block",
                                          reason_code="policy_block")
        gateway.check_detection = check
        status, code, message = self.connect_error(self.rpc(perform_action(CLEAN_PROMPT)))
        self.assertEqual((status, code), (403, "permission_denied"))
        self.assertTrue(message.startswith("보안 정책에 따라 외부 전송을 차단했습니다."))

    def test_control_characters_and_message_like_prompts_are_still_inspected(self):
        # 질문 글자가 bytes(제어 문자)나 메시지(예: '\x12\x0e' + 번호)로 읽혀도 2.3 원본 바이트를 검사한다
        for prompt in (f"번호\x01 {RRN}", f"\x12\x0e{RRN}", f"* 김철수 {RRN} 확인."):
            with self.subTest(prompt=repr(prompt[:6])):
                self.calls.clear()
                flow = self.rpc(perform_action(prompt))
                self.assertEqual(self.connect_error(flow)[0], 403)
                self.assertEqual(self.calls[0]["text"], gateway.normalize_text(prompt))
                self.assertIn(RRN, self.calls[0]["text"])


class NotAPromptTests(RpcBase):
    def assert_untouched(self, flow, body):
        self.assertTrue(flow.metadata["test_forwarded"])
        self.assertEqual(flow.request.raw_content, body)
        self.assertEqual((self.calls, self.queued, self.extension), ([], [], []))

    def test_other_actions_and_methods_are_untouched(self):
        cases = [
            ("other PerformAction", other_action(), PERFORM_PATH, b"application/proto"),
            ("ReportViewing", fl(1, CONV_UUID) + fv(2, 1), RPC + "ReportViewing", b"application/proto"),
            ("ReportViewing with a 2.3", perform_action(PII_PROMPT), RPC + "ReportViewing", b"application/proto"),
            ("StreamTimeline", frame(fl(1, CONV_UUID) + fv(2, 3)), RPC + "StreamTimeline", b"application/connect+proto"),
            ("StreamTimeline with a 2.3", frame(perform_action(PII_PROMPT)), RPC + "StreamTimeline",
             b"application/connect+proto"),
            ("GetNewConversationDefaults", b"", RPC + "GetNewConversationDefaults", b"application/proto"),
            ("empty PerformAction", b"", PERFORM_PATH, b"application/proto"),
            ("blank prompt", perform_action(" ​\n "), PERFORM_PATH, b"application/proto"),
            # 알려진 범위 밖(NOTES): connect+proto·JSON으로 온 PerformAction은 아직 검사하지 않는다(구조 기록으로 찾는다)
            ("PerformAction as connect+proto", frame(perform_action(PII_PROMPT)), PERFORM_PATH, b"application/connect+proto"),
        ]
        for name, body, path, content_type in cases:
            with self.subTest(case=name):
                flow = self.rpc(body, path=path, content_type=content_type)
                self.assert_untouched(flow, body)
        flow = self.rpc(perform_action(PII_PROMPT), method=b"PUT")
        self.assert_untouched(flow, perform_action(PII_PROMPT))
        self.assertNotIn("[CLAUDE-RPC-PROMPT]", self.log.getvalue())
        records = self.rpc_lines()
        self.assertTrue(records)
        self.assertTrue(all(record.get("prompt_paths", []) == [] for record in records))

    def test_malformed_bodies_are_forwarded_unchanged_without_exceptions(self):
        cases = [
            ("garbage", b"\xff\xfe\xfd\xfc", (), "not_protobuf"),
            ("truncated", perform_action(PII_PROMPT)[:-7], (), "not_protobuf"),
            ("json body", json.dumps({"prompt": RRN}).encode(), (), "not_protobuf"),
            ("gzip header, plain body", perform_action(PII_PROMPT), ((b"content-encoding", b"gzip"),), "content_encoding"),
            ("broken gzip", gzip.compress(perform_action(PII_PROMPT), mtime=0)[:-9], ((b"content-encoding", b"gzip"),),
             "content_encoding"),
            ("br", perform_action(PII_PROMPT), ((b"content-encoding", b"br"),), "content_encoding"),
            ("too many top-level fields", b"\x08\x01" * (gateway_proto.MAX_FIELDS + 1) + fl(2, fl(3, RRN)), (), "limit"),
        ]
        for name, body, headers, reason in cases:
            with self.subTest(case=name):
                self.log.truncate(0)
                self.log.seek(0)
                flow = self.rpc(body, headers=headers)
                self.assert_untouched(flow, body)
                self.assertIn(f"[CLAUDE-RPC-PROMPT] not inspected reason={reason} bytes={len(body)}", self.log.getvalue())
                self.assertNotIn(RRN, self.log.getvalue())
        with mock.patch.object(gateway_proto, "values_at", side_effect=RuntimeError("boom")):
            flow = self.rpc(perform_action(PII_PROMPT))
        self.assert_untouched(flow, perform_action(PII_PROMPT))
        self.assertIn("[CLAUDE-RPC-PROMPT] read failed error_type= RuntimeError", self.log.getvalue())

    def test_body_over_the_walk_limit_is_forwarded_and_logged(self):
        # 알려진 틈(NOTES): 4 MiB를 넘는 본문은 읽지 않고 오늘처럼 전달한다(기록 없음, 한 줄만)
        body = perform_action("가" * (gateway_proto.MAX_BODY_BYTES // 3 + 10) + RRN)
        self.assertGreater(len(body), gateway_proto.MAX_BODY_BYTES)
        flow = self.rpc(body)
        self.assert_untouched(flow, body)
        self.assertIn(f"[CLAUDE-RPC-PROMPT] not inspected reason=too_large bytes={len(body)}", self.log.getvalue())


class EncodingAndSizeTests(RpcBase):
    def test_gzip_and_deflate_bodies(self):
        for name, compress in (("gzip", lambda data: gzip.compress(data, mtime=0)), ("deflate", zlib.compress)):
            with self.subTest(encoding=name):
                self.queued.clear()
                self.calls.clear()
                gateway._dedupe_seen.clear()          # 같은 질문의 재시도가 아니라 다른 압축 방식 시험
                headers = ((b"content-encoding", name.encode()),)
                blocked = self.rpc(compress(perform_action(PII_PROMPT)), headers=headers)
                self.assertEqual(self.connect_error(blocked)[:2], (403, "permission_denied"))
                self.assertEqual(self.calls[0]["text"], gateway.normalize_text(PII_PROMPT))
                clean_body = compress(perform_action(CLEAN_PROMPT))
                clean = self.rpc(clean_body, headers=headers)
                self.assertTrue(clean.metadata["test_forwarded"])
                self.assertEqual(clean.request.raw_content, clean_body)       # 압축된 바이트 그대로
                self.assertEqual([e["reasonCode"] for e in self.queued], ["mask_application_failed"])

    def test_very_long_prompt_has_no_character_cap_like_other_prompts(self):
        prompt = "회의록 정리 " * 70000 + RRN     # 약 49만 자, 본문 약 1.2 MB(구조 기록 상한 1 MiB는 넘고 걷기 상한 4 MiB 안)
        flow = self.rpc(perform_action(prompt))
        self.assertEqual(self.connect_error(flow)[0], 403)
        claude_text = self.calls[0]["text"]
        self.assertEqual(len(claude_text), len(gateway.normalize_text(prompt)))
        self.attempt(lambda: self.chatgpt_prompt(prompt))
        self.assertEqual(len(self.calls[1]["text"]), len(prompt))       # ChatGPT 질문도 자르지 않는다
        self.assertEqual(self.rpc_lines()[0]["format"], "too_large")
        self.assertEqual(self.rpc_lines()[0]["prompt_paths"], ["2.3"])


class MultipleFieldTests(RpcBase):
    def test_each_prompt_field_is_inspected_and_one_event_is_recorded(self):
        flow = self.rpc(perform_action(CLEAN_PROMPT, PII_PROMPT))
        self.assertEqual(self.connect_error(flow)[0], 403)
        self.assertEqual([call["text"] for call in self.calls],
                         [gateway.normalize_text(CLEAN_PROMPT), gateway.normalize_text(PII_PROMPT)])
        self.assertEqual(self.events(), [("prompt", "Claude", "BLOCK", "BLOCK", "mask_application_failed", False)])
        self.assertEqual(len(self.extension), 1)

    def test_two_actions_with_personal_data_merge_the_counts(self):
        self.rpc(perform_action(actions=[(PII_PROMPT,), (f"다른 번호 {RRN} {RRN}",)]))
        self.assertEqual(len(self.calls), 2)
        event, = self.queued
        self.assertEqual(event["detections"][0]["entityCounts"], [{"entityType": "KR_RRN", "count": 3}])

    def test_a_block_stops_the_remaining_fields(self):
        flow = self.rpc(perform_action(DOC_PROMPT, PII_PROMPT))
        self.assertEqual(self.connect_error(flow)[2], "보호 문서와 일치해 전송을 차단했습니다.")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([e["reasonCode"] for e in self.queued], ["doc_excerpt"])

    def test_clean_fields_record_one_allow_event(self):
        self.env(DASHBOARD_REPORT_ALLOW_EVENTS="true")
        flow = self.rpc(perform_action(CLEAN_PROMPT, "PGTEST 둘째 칸", ""))
        self.assertTrue(flow.metadata["test_forwarded"])
        self.assertEqual(len(self.calls), 2)                             # 빈 칸은 보내지 않음
        self.assertEqual([e["finalAction"] for e in self.queued], ["ALLOW"])


class TimeoutTests(RpcBase):
    """질문 처리 설정(대시보드 'Gateway 처리 설정')의 대기 시간·처리. 실제 detection_client + 느린 로컬 서버."""

    def setUp(self):
        super().setUp()
        gateway.check_detection = self._orig[0]
        self.server = SlowDetection(delay=1.0)
        self.addCleanup(self.server.close)
        patcher = mock.patch.object(gateway, "DETECTION_BASE_URL", self.server.url)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_forward_setting_forwards_with_a_degraded_event(self):
        self.use_settings(prompt=("forward", 0.2))
        body = perform_action(PII_PROMPT)
        started = time.monotonic()
        flow = self.rpc(body)
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertTrue(flow.metadata["test_forwarded"])
        self.assertEqual(flow.request.raw_content, body)
        chatgpt = self.attempt(lambda: self.chatgpt_prompt(PII_PROMPT))
        self.assertTrue(chatgpt.metadata["test_forwarded"])
        rows = [(e["targetLlm"], e["finalAction"], e["degraded"], e["reasonCode"], e["failurePolicy"], e["detectionOutcome"])
                for e in self.queued]
        self.assertEqual(rows, [("Claude", "ALLOW", True, "detection_timeout", "FAIL_OPEN", "UNAVAILABLE"),
                                ("ChatGPT", "ALLOW", True, "detection_timeout", "FAIL_OPEN", "UNAVAILABLE")])
        self.assertEqual(flow.metadata["gw_degraded"], True)

    def test_block_setting_returns_503_like_other_prompts(self):
        self.use_settings(prompt=("block", 0.2))
        flow = self.rpc(perform_action(CLEAN_PROMPT))
        status, code, message = self.connect_error(flow)
        self.assertEqual((status, code), (503, "unavailable"))
        self.assertEqual(message, "보안 검사를 완료하지 못해 장애 처리 정책에 따라 전송을 차단했습니다.")
        chatgpt = self.attempt(lambda: self.chatgpt_prompt(CLEAN_PROMPT))
        self.assertEqual(chatgpt.response.status_code, 503)
        rows = [(e["targetLlm"], e["finalAction"], e["degraded"], e["reasonCode"], e["failurePolicy"],
                 e["enforcement"]["httpStatus"]) for e in self.queued]
        self.assertEqual(rows, [("Claude", "BLOCK", True, "detection_timeout", "FAIL_CLOSED", 503),
                                ("ChatGPT", "BLOCK", True, "detection_timeout", "FAIL_CLOSED", 503)])


class RetryTests(RpcBase):
    def test_retries_of_a_blocked_prompt_record_once(self):
        cases = [(PII_PROMPT, "mask_application_failed", 403), (DOC_PROMPT, "doc_excerpt", 403)]
        for prompt, reason, status in cases:
            flows = [self.rpc(perform_action(prompt)) for _ in range(3)]
            self.assertEqual([self.connect_error(flow)[0] for flow in flows], [status] * 3)   # 시도마다 막는다
            self.assertTrue(all(not flow.metadata["test_forwarded"] for flow in flows))
        self.assertEqual([e["reasonCode"] for e in self.queued], [reason for _, reason, _ in cases])
        self.assertEqual([(e["finalAction"], e["notify"]) for e in self.extension], [("BLOCK", True)] * 2)
        lines = self.dedupe_lines()
        self.assertEqual([line.rsplit("suppressed=", 1)[1] for line in lines], ["1", "2"] * 2)
        for line in lines:
            self.assertIn("service=Claude action=BLOCK", line)
            for value in PROMPT_VALUES:
                self.assertNotIn(value, line)

    def test_fail_closed_retries_record_once(self):
        self.use_settings(prompt=("block", 0.5))
        gateway.check_detection = lambda *a, **k: failure_result("TIMEOUT", k["failure_policy"], k["request_id"])
        flows = [self.rpc(perform_action(CLEAN_PROMPT)) for _ in range(3)]
        self.assertEqual([self.connect_error(flow)[:2] for flow in flows], [(503, "unavailable")] * 3)
        self.assertEqual([(e["finalAction"], e["reasonCode"]) for e in self.queued], [("BLOCK", "detection_timeout")])
        self.assertEqual(len(self.extension), 1)

    def test_other_prompt_other_client_and_after_the_window_are_recorded(self):
        self.rpc(perform_action(PII_PROMPT))
        self.rpc(perform_action(PII_PROMPT + " 다시"))                               # 다른 질문
        self.rpc(perform_action(PII_PROMPT), client_id="client-fake-2")               # 다른 사용자(확장 번호)
        self.rpc(perform_action(PII_PROMPT), peer=("10.0.0.2", 50000))                # 다른 사용자(IP)
        self.assertEqual(len(self.queued), 4)
        self.rpc(perform_action(PII_PROMPT))                                          # 첫 시도의 재시도
        self.assertEqual(len(self.queued), 4)
        self.age_dedupe_entries(gateway.DEDUPE_WINDOW_SECONDS + 0.5)
        self.rpc(perform_action(PII_PROMPT))                                          # 창이 지난 뒤
        self.assertEqual(len(self.queued), 5)
        self.assertEqual(len(self.extension), 5)

    def test_same_prompt_in_new_messages_differs_only_by_ids(self):
        # 재시도 신원은 질문 글자만: 대화·메시지 번호가 달라도(Claude가 다시 만든 요청) 같은 질문이면 한 번
        self.rpc(perform_action(PII_PROMPT))
        changed = perform_action(PII_PROMPT).replace(MSG_UUID.encode(), b"00000000-0000-4000-8000-0000000c0de9")
        self.rpc(changed)
        self.assertEqual(len(self.queued), 1)

    def test_allowed_prompts_are_not_reduced(self):
        self.env(DASHBOARD_REPORT_ALLOW_EVENTS="true")
        for _ in range(2):
            self.rpc(perform_action(CLEAN_PROMPT))
        self.assertEqual([e["finalAction"] for e in self.queued], ["ALLOW", "ALLOW"])
        self.assertEqual(self.dedupe_lines(), [])


class MaskSwitchTests(RpcBase):
    """GATEWAY_CLAUDE_RPC_MASK=1일 때만 가린다(기본 0 = 차단). 1.15(32바이트)가 무결성 표지면 Claude가 거부할 수 있어 실제 시험 전에는 끔."""

    def masked_body_ok(self, original: bytes, forwarded: bytes, replacements: dict):
        """forwarded를 다시 읽어 2.3만 바뀌고 나머지 잎(값까지)은 같은지, 정규 인코딩인지."""
        before = gateway_proto.leaves(original)
        after = gateway_proto.leaves(forwarded)
        self.assertEqual(len(before), len(after))
        for (rb, vb), (ra, va) in zip(before, after):
            self.assertEqual((rb["path"], rb["loc"]), (ra["path"], ra["loc"]))
            if rb["loc"] in replacements:
                self.assertEqual(va, replacements[rb["loc"]])
            else:
                self.assertEqual((rb["kind"], rb["length"], vb), (ra["kind"], ra["length"], va))
        self.assertEqual(gateway_proto.encode(forwarded), forwarded)

    def test_default_is_block(self):
        for value in (None, "0", "true", "yes"):
            with self.subTest(value=value):
                self.queued.clear()
                with mock.patch.dict(os.environ, {"GATEWAY_CLAUDE_RPC_MASK": value} if value else {}):
                    flow = self.rpc(perform_action(PII_PROMPT + str(value)))
                self.assertEqual(self.connect_error(flow)[0], 403)
                self.assertEqual([e["reasonCode"] for e in self.queued], ["mask_application_failed"])

    def test_mask_replaces_only_the_prompt_field(self):
        self.env(GATEWAY_CLAUDE_RPC_MASK="1")
        body = perform_action(PII_PROMPT)
        flow = self.rpc(body)
        self.assertTrue(flow.metadata["test_forwarded"])
        forwarded = flow.request.raw_content
        masked = gateway.normalize_text(PII_PROMPT).replace(RRN, "[KR_RRN]")
        values, _ = gateway_proto.values_at(forwarded, "2.3")
        self.assertEqual([value.decode() for _, value in values], [masked])
        self.masked_body_ok(body, forwarded, {values[0][0]: masked})
        self.assertEqual(flow.request.headers["content-length"], str(len(forwarded)))
        self.assertNotIn(RRN.encode(), forwarded)
        self.assertEqual(len(forwarded), len(body) - len(PII_PROMPT.encode()) + len(masked.encode()))
        event, = self.queued
        self.assertEqual((event["finalAction"], event["enforcement"], event.get("reasonCode")),
                         ("MASK", {"applied": True}, "pii"))
        self.assertNotIn("maskEvidence", event)        # 대시보드가 받는 표현(JSON_TEXT·GEMINI_FORM_TEXT)이 아니라 싣지 않음
        self.assertEqual((self.extension[0]["finalAction"], self.extension[0]["notify"]), ("MASK", True))
        self.assertEqual(flow.metadata["gw_action"], "mask")

    def test_mask_with_gzip_and_two_fields(self):
        self.env(GATEWAY_CLAUDE_RPC_MASK="1")
        original = perform_action(actions=[(CLEAN_PROMPT, PII_PROMPT), (f"둘째 {RRN}",)])
        flow = self.rpc(gzip.compress(original, mtime=0), headers=((b"content-encoding", b"gzip"),))
        self.assertTrue(flow.metadata["test_forwarded"])
        forwarded = gzip.decompress(flow.request.raw_content)     # 같은 압축으로 다시 실림
        values, _ = gateway_proto.values_at(forwarded, "2.3")
        self.assertEqual([value.decode() for _, value in values],
                         [CLEAN_PROMPT, gateway.normalize_text(PII_PROMPT).replace(RRN, "[KR_RRN]"), "둘째 [KR_RRN]"])
        self.masked_body_ok(original, forwarded, {values[1][0]: values[1][1].decode(), values[2][0]: "둘째 [KR_RRN]"})
        self.assertEqual(flow.request.headers["content-length"], str(len(flow.request.raw_content)))
        self.assertEqual([e["finalAction"] for e in self.queued], ["MASK"])
        self.assertEqual(self.queued[0]["detections"][0]["entityCounts"], [{"entityType": "KR_RRN", "count": 2}])

    def test_mask_that_cannot_be_applied_blocks(self):
        self.env(GATEWAY_CLAUDE_RPC_MASK="1")
        # 질문이 메시지처럼 읽히면 replace_text가 그 자리를 바꾸지 않는다 → 원본을 보내지 않고 차단
        body = perform_action(f"* 김철수 {RRN} 확인.")
        flow = self.rpc(body)
        self.assertEqual(self.connect_error(flow)[0], 403)
        self.assertEqual([e["reasonCode"] for e in self.queued], ["mask_application_failed"])
        self.queued.clear()
        gateway.check_detection = lambda *a, **k: bundle.DetectionResult(
            blocked=False, reason="sig", request_id=k["request_id"], decided_by="signature", action="mask_full",
            reason_code="pii", pii_hits="KR_RRN:1", masked_text=None, mask_spans=[])   # 가릴 글자 없음
        flow = self.rpc(perform_action(PII_PROMPT))
        self.assertEqual(self.connect_error(flow)[0], 403)
        self.assertEqual(flow.request.raw_content, perform_action(PII_PROMPT))
        self.assertEqual([e["reasonCode"] for e in self.queued], ["mask_application_failed"])


class StructureLogTests(RpcBase):
    def test_prompt_paths_without_values(self):
        self.rpc(perform_action(PII_PROMPT))
        self.rpc(perform_action(CLEAN_PROMPT, "PGTEST 둘째"))
        self.rpc(other_action())
        records = self.rpc_lines()
        self.assertEqual([(r["marker_paths"], r["prompt_paths"]) for r in records],
                         [(["2.3"], ["2.3"]), (["2.3", "2.3"], ["2.3", "2.3"]), ([], [])])
        self.assertEqual(list(records[0])[:9], ["method", "content_type", "content_encoding", "bytes", "format",
                                                "leaves_total", "marker_paths", "prompt_paths", "leaves"])
        output = self.log.getvalue()
        for value in PROMPT_VALUES + (MODEL, TIME_ZONE, TOOLS[0]):
            self.assertNotIn(value, output)

    def test_rate_limit_and_switch_do_not_stop_inspection(self):
        for _ in range(gateway.CLAUDE_RPC_SHAPE_PER_HOUR + gateway.CLAUDE_RPC_MARKER_PER_HOUR):
            self.rpc(perform_action("PGTEST 평범한 질문"))
        before = len(self.rpc_lines())
        self.assertEqual(before, gateway.CLAUDE_RPC_SHAPE_PER_HOUR + gateway.CLAUDE_RPC_MARKER_PER_HOUR)
        flow = self.rpc(perform_action(PII_PROMPT))                   # 기록 상한을 넘어도 검사·차단
        self.assertEqual(len(self.rpc_lines()), before)
        self.assertEqual(self.connect_error(flow)[0], 403)
        with mock.patch.dict(os.environ, {"GATEWAY_LOG_CLAUDE_RPC_SHAPE": "0"}):
            gateway._claude_rpc_shape_window[0] = 0.0
            flow = self.rpc(perform_action(DOC_PROMPT))
        self.assertEqual(self.connect_error(flow)[0], 403)
        self.assertEqual(len(self.rpc_lines()), before)

    def test_logger_failure_does_not_stop_inspection(self):
        with mock.patch.object(gateway_proto, "leaves", side_effect=RuntimeError("boom")):
            flow = self.rpc(perform_action(PII_PROMPT))
        self.assertIn("[CLAUDE-RPC] shape log failed error_type= RuntimeError", self.log.getvalue())
        self.assertEqual(self.connect_error(flow)[0], 403)
        self.assertNotIn("gw_claude_rpc_prompt", flow.metadata)          # 읽은 본문은 검사 뒤 지운다


class EventValidationTests(RpcBase):
    """새 이벤트 모양을 대시보드 validation.mjs(로컬 사본)로 확인. node·사본이 없으면 건너뜀."""

    def collect(self):
        self.env(DASHBOARD_REPORT_ALLOW_EVENTS="true")
        self.rpc(perform_action(PII_PROMPT))
        self.rpc(perform_action(DOC_PROMPT))
        self.rpc(perform_action(CLEAN_PROMPT))
        with mock.patch.dict(os.environ, {"GATEWAY_CLAUDE_RPC_MASK": "1"}):
            self.rpc(perform_action(PII_PROMPT + " 가림"))
        gateway.check_detection = lambda *a, **k: failure_result("TIMEOUT", k["failure_policy"], k["request_id"])
        self.rpc(perform_action(CLEAN_PROMPT + " 지연"))
        with mock.patch.object(gateway, "GATEWAY_SETTINGS", FixedSettings(prompt=("block", 0.5))):
            self.rpc(perform_action(CLEAN_PROMPT + " 차단"))
        return list(self.queued)

    def test_shapes(self):
        events = self.collect()
        self.assertEqual([(e["finalAction"], e.get("reasonCode"), e["degraded"], e["detectionOutcome"]) for e in events],
                         [("BLOCK", "mask_application_failed", False, "MATCH"), ("BLOCK", "doc_excerpt", False, "MATCH"),
                          ("ALLOW", None, False, "NO_MATCH"), ("MASK", "pii", False, "MATCH"),
                          ("ALLOW", "detection_timeout", True, "UNAVAILABLE"),
                          ("BLOCK", "detection_timeout", True, "UNAVAILABLE")])
        self.assertTrue(all(e["contentType"] == "prompt" and e["targetLlm"] == "Claude" for e in events))
        dump = os.environ.get("GW_BUNDLE_EVENT_DUMP")
        if dump:
            with open(dump, "a", encoding="utf-8") as handle:
                for index, event in enumerate(events):
                    handle.write(json.dumps({"case": f"claude_rpc.{index}", "event": event}, ensure_ascii=False) + "\n")

    @unittest.skipUnless(shutil.which("node") and (bundle.DASHBOARD_SERVER_DIR / "validation.mjs").exists(),
                         "node or dashboard server copy not available")
    def test_dashboard_validation_accepts_every_shape(self):
        events = self.collect()
        module = (bundle.DASHBOARD_SERVER_DIR / "validation.mjs").as_uri()
        script = (f"import {{ validateCanonicalEvent }} from '{module}';\n"
                  "import { readFileSync } from 'node:fs';\n"
                  "const events = JSON.parse(readFileSync(0, 'utf8'));\n"
                  "const out = events.map((event) => { try { validateCanonicalEvent(event); return { ok: true }; }"
                  " catch (error) { return { ok: false, error: String(error.message), path: error.path }; } });\n"
                  "console.log(JSON.stringify(out));\n")
        folder = Path(tempfile.mkdtemp(prefix="gw-node-rpc-"))
        self.addCleanup(shutil.rmtree, folder, True)
        (folder / "validate.mjs").write_text(script, encoding="utf-8")
        result = subprocess.run(["node", str(folder / "validate.mjs")], input=json.dumps(events), capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        verdicts = json.loads(result.stdout)
        self.assertEqual(len(verdicts), 6)
        self.assertTrue(all(v["ok"] for v in verdicts), verdicts)


class EndToEndTests(unittest.TestCase):
    """실제 mitmproxy(DumpMaster)에 gateway를 올리고 소켓으로 보낸다: 깨끗한 질문은 upstream이 같은 바이트를 받고,
    개인정보 질문은 브라우저가 Connect 오류(403 JSON)를 받고 upstream에는 가지 않는다. 가림을 켜면 가린 본문이 간다."""

    def test_forward_block_and_mask_over_the_wire(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        received = []

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers.get("content-length") or 0)))
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
                if flow.response is None:
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

        calls, out = [], io.StringIO()
        gateway._claude_rpc_shape_counts.clear()
        gateway._claude_rpc_shape_window[0] = 0.0
        gateway._dedupe_seen.clear()
        clean, pii = perform_action(CLEAN_PROMPT), perform_action(PII_PROMPT)
        results = []
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=lambda: loop.run_until_complete(run_master()), daemon=True)
        with mock.patch.object(gateway, "check_detection", fake_detection(calls)), \
                mock.patch.object(gateway, "send_to_next_module", lambda event: None), \
                mock.patch.object(gateway, "send_extension_event", lambda event: None), \
                mock.patch.object(gateway._gateway_event_outbox, "start", lambda: None), \
                mock.patch.object(gateway._gateway_metrics_publisher, "start", lambda: None), \
                mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None), \
                contextlib.redirect_stdout(out):
            thread.start()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
                time.sleep(0.1)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
            for body, mask in ((clean, "0"), (pii, "0"), (pii, "1")):
                with mock.patch.dict(os.environ, {"GATEWAY_CLAUDE_RPC_MASK": mask}):
                    request = urllib.request.Request(f"http://claude.ai{PERFORM_PATH}", method="POST", data=body,
                                                     headers={"content-type": "application/proto"})
                    try:
                        with opener.open(request, timeout=10) as response:
                            results.append((response.status, response.headers.get("content-type"), response.read()))
                    except urllib.error.HTTPError as error:
                        results.append((error.code, error.headers.get("content-type"), error.read()))
            time.sleep(0.2)
            loop.call_soon_threadsafe(state["master"].shutdown)
            thread.join(10)
        self.assertEqual([status for status, _, _ in results], [200, 403, 200])
        self.assertEqual(results[1][1], "application/json")
        self.assertEqual(json.loads(results[1][2]), {"code": "permission_denied",
                                                     "message": gateway.CLAUDE_RPC_MASK_BLOCK_MESSAGE})
        self.assertEqual(len(received), 2)                                   # 차단한 요청은 upstream에 없음
        self.assertEqual(received[0], clean)                                 # 바이트 그대로
        values, _ = gateway_proto.values_at(received[1], "2.3")
        self.assertEqual([value.decode() for _, value in values], [gateway.normalize_text(PII_PROMPT).replace(RRN, "[KR_RRN]")])
        self.assertNotIn(RRN.encode(), received[1])
        self.assertEqual(len(calls), 3)
        for value in PROMPT_VALUES:
            self.assertNotIn(value, out.getvalue())


# ============================================================
# 10/11 밤 검토 반영(6단계 마무리). 고치기 전(6단계 끝 b9630e59…)에는 실패해야 하는 시험들
# ============================================================

def tag(number: int, wire: int) -> bytes:
    return varint(number << 3 | wire)


def overlong(value: int, total: int = 2) -> bytes:
    """value를 total바이트 varint로 적는다(최소 길이가 아님: 이어짐 표시 + 끝 0x00). 표준 파서는 받아들이고 브라우저는 만들지 않는다."""
    minimal = varint(value)
    assert total > len(minimal)
    return bytes(byte | 0x80 for byte in minimal) + b"\x80" * (total - len(minimal) - 1) + b"\x00"


PII_BYTES = PII_PROMPT.encode()


def send_variant(extra=b"", *, prompt_field=None, prefix=b"", action_length=None) -> bytes:
    """실측 모양 질문 전송인데 동작 메시지(2) 안에 정규가 아닌 바이트를 넣는다(직접 만든 요청만 이런 바이트를 보낸다)."""
    prompt_field = fl(3, PII_PROMPT) if prompt_field is None else prompt_field
    inner = (prefix + fl(1, MSG_UUID) + fl(2, PARENT_UUID) + prompt_field + fl(7, fl(2, MODEL)) + fl(8, settings_block())
             + fl(12, TIME_ZONE) + fl(13, LOCALE) + fv(18, 1) + extra)
    length = varint(len(inner)) if action_length is None else action_length(len(inner))
    return fl(1, client_info()) + tag(2, 2) + length + inner


# 표준 파서(protoc 29.3 --decode, ProtocCrossCheckTests)가 받아들이고 2.3을 질문으로 읽는 정규가 아닌 본문
NONCANONICAL = {
    "reserved field 19000 in 2": send_variant(tag(19000, 0) + varint(1)),
    "reserved field 19999 empty in 2": send_variant(tag(19999, 2) + varint(0)),
    "unknown group at the end of 2": send_variant(tag(99, 3) + tag(99, 4)),
    "unknown group with content first in 2": send_variant(prefix=tag(99, 3) + fv(1, 5) + fl(2, "x") + tag(99, 4)),
    "nested unknown groups in 2": send_variant(tag(98, 3) + tag(99, 3) + fv(1, 1) + tag(99, 4) + tag(98, 4)),
    "non-minimal length of 2.3": send_variant(prompt_field=tag(3, 2) + overlong(len(PII_BYTES)) + PII_BYTES),
    "non-minimal tag of 2.3": send_variant(prompt_field=overlong(3 << 3 | 2) + varint(len(PII_BYTES)) + PII_BYTES),
    "5-byte tag of 2.3": send_variant(prompt_field=overlong(3 << 3 | 2, 5) + varint(len(PII_BYTES)) + PII_BYTES),
    "5-byte length of 2.3": send_variant(prompt_field=tag(3, 2) + overlong(len(PII_BYTES), 5) + PII_BYTES),
    "non-minimal length of 2": send_variant(action_length=lambda n: overlong(n, 3)),
    "10-byte varint over 64 bits in 2": send_variant(tag(5, 0) + b"\xff" * 9 + b"\x7f"),   # protoc는 넘친 비트를 버리고 읽음
    "reserved field at the top": perform_action(PII_PROMPT) + tag(19000, 0) + varint(1),
    "unknown group at the top": tag(7, 3) + fv(1, 1) + tag(7, 4) + perform_action(PII_PROMPT),
}
# 표준 파서도 틀렸다고 보는 바이트(넉넉하게 읽어도 틀림). 2의 끝 또는 본문 끝에 붙인다
INVALID = {
    "wire type 6": tag(5, 6),
    "wire type 7": tag(5, 7),
    "group end without a start": tag(99, 4),
    "group end with another number": tag(98, 3) + tag(99, 4),
    "unterminated group": tag(99, 3) + fv(1, 1),
    "field number 0": b"\x00\x01",
    "field number 2^29": tag(1 << 29, 0) + varint(1),
    "length past the end": tag(5, 2) + varint(100) + b"x",
    "varint over 10 bytes": tag(5, 0) + b"\xff" * 10 + b"\x01",
    "truncated varint": tag(5, 0) + b"\x80",
}


class NonCanonicalEncodingTests(RpcBase):
    """검토 1: 값 찾기가 경로 중간을 표준 파서보다 엄격하게 읽으면, 표준 파서가 받아들이는 바이트 하나로 질문이 검사 없이 나간다."""

    def test_values_at_reads_what_standard_parsers_accept(self):
        for name, body in NONCANONICAL.items():
            with self.subTest(case=name):
                values, reason = gateway_proto.values_at(body, "2.3")
                self.assertEqual(([value for _, value in values], reason), ([PII_BYTES], None))

    def test_values_at_also_reads_longer_varints_other_parsers_accept(self):
        # protoc(C++)는 태그·길이를 5바이트까지만 읽지만 Go·prost는 10바이트까지 읽는다 → 넉넉한 쪽에 맞춤
        for body in (send_variant(prompt_field=overlong(3 << 3 | 2, 10) + varint(len(PII_BYTES)) + PII_BYTES),
                     send_variant(prompt_field=tag(3, 2) + overlong(len(PII_BYTES), 10) + PII_BYTES),
                     send_variant(action_length=lambda n: overlong(n, 10))):
            self.assertEqual([value for _, value in gateway_proto.values_at(body, "2.3")[0]], [PII_BYTES])

    def test_values_at_keeps_canonical_positions(self):
        # 정규 본문의 자리(loc)는 walk·replace_text와 같다(가림이 같은 자리를 바꾼다)
        body = perform_action(CLEAN_PROMPT, PII_PROMPT)
        values, _ = gateway_proto.values_at(body, "2.3")
        walked = [r["loc"] for r in gateway_proto.walk(body) if r["path"] == "2.3"]
        self.assertEqual([loc for loc, _ in values], walked)
        self.assertEqual(gateway_proto.values_at(NONCANONICAL["unknown group with content first in 2"], "2.3")[0][0][0],
                         (1, 3))                                     # 그룹 하나 = 필드 하나(자리 번호 1칸)

    def test_invalid_protobuf_is_still_rejected(self):
        for name, junk in INVALID.items():
            with self.subTest(case=name):
                self.assertEqual(gateway_proto.values_at(send_variant(junk), "2.3"), ([], "not_protobuf"))
                self.assertEqual(gateway_proto.values_at(perform_action(PII_PROMPT) + junk, "2.3"), ([], "not_protobuf"))

    def test_noncanonical_bodies_are_inspected_and_blocked(self):
        for name, body in NONCANONICAL.items():
            with self.subTest(case=name):
                self.calls.clear()
                self.queued.clear()
                gateway._dedupe_seen.clear()
                flow = self.rpc(body)
                self.assertFalse(flow.metadata["test_forwarded"])
                self.assertEqual(self.connect_error(flow)[:2], (403, "permission_denied"))
                self.assertEqual([call["text"] for call in self.calls], [gateway.normalize_text(PII_PROMPT)])
                self.assertEqual([e["reasonCode"] for e in self.queued], ["mask_application_failed"])

    def test_mask_switch_cannot_rewrite_a_noncanonical_body_and_blocks(self):
        # 가림은 엄격한 파서(replace_text)를 쓴다 → 같은 본문은 가림 실패 → 원본을 보내지 않고 차단
        self.env(GATEWAY_CLAUDE_RPC_MASK="1")
        for name in ("reserved field 19000 in 2", "non-minimal length of 2.3", "unknown group at the end of 2",
                     "reserved field at the top"):
            with self.subTest(case=name):
                self.queued.clear()
                gateway._dedupe_seen.clear()
                body = NONCANONICAL[name]
                flow = self.rpc(body)
                self.assertFalse(flow.metadata["test_forwarded"])
                self.assertEqual(self.connect_error(flow)[0], 403)
                self.assertEqual(flow.request.raw_content, body)
                self.assertEqual([e["reasonCode"] for e in self.queued], ["mask_application_failed"])

    def test_unreadable_action_message_leaves_a_reason_line(self):
        # 2가 넉넉하게 읽어도 메시지가 아니면 사유 줄을 남기고 전달(못 읽은 본문은 전달: NOTES 남은 것 2, 실패 닫힘은 사용자 결정)
        for name, body in (("wire type 7 in 2", send_variant(INVALID["wire type 7"])), ("text 2", fl(2, "글자만 있는 2")),
                           ("unterminated group in 2", send_variant(INVALID["unterminated group"]))):
            with self.subTest(case=name):
                self.log.truncate(0)
                self.log.seek(0)
                flow = self.rpc(body)
                self.assertTrue(flow.metadata["test_forwarded"])
                self.assertEqual(flow.request.raw_content, body)
                self.assertEqual((self.calls, self.queued), ([], []))
                self.assertIn(f"[CLAUDE-RPC-PROMPT] not inspected reason=not_protobuf bytes={len(body)}", self.log.getvalue())
                self.assertNotIn(RRN, self.log.getvalue())

    def test_a_readable_action_is_inspected_next_to_an_unreadable_one(self):
        body = perform_action(PII_PROMPT) + fl(2, INVALID["wire type 7"])
        self.assertEqual(gateway_proto.values_at(body, "2.3"), ([((1, 2), PII_BYTES)], "not_protobuf"))
        flow = self.rpc(body)
        self.assertEqual(self.connect_error(flow)[0], 403)
        self.assertEqual(len(self.calls), 1)
        self.assertIn(f"[CLAUDE-RPC-PROMPT] partly unreadable reason=not_protobuf bytes={len(body)}", self.log.getvalue())


@unittest.skipUnless(shutil.which("protoc"), "protoc not available")
class ProtocCrossCheckTests(unittest.TestCase):
    """정답 대조: 표준 파서(protoc --decode, 스키마 Req{repeated Send action = 2}·Send{repeated bytes text = 3})가 읽는 질문 값과
    values_at이 같은지. 서버에 protoc가 없으면 건너뜀(로컬 libprotoc 29.3)."""

    SCHEMA = ('syntax = "proto3";\nmessage Send { repeated bytes text = 3; }\n'
              'message Req { repeated Send action = 2; }\n')

    @classmethod
    def setUpClass(cls):
        cls.folder = Path(tempfile.mkdtemp(prefix="gw-protoc-"))
        (cls.folder / "req.proto").write_text(cls.SCHEMA, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.folder, True)

    def protoc(self, body: bytes):
        """(읽힘, [질문 바이트]) - protoc 글자 형식 출력의 text: 줄만 되돌린다."""
        import codecs
        result = subprocess.run(["protoc", f"-I{self.folder}", "--decode=Req", "req.proto"], input=body,
                                capture_output=True, cwd=self.folder, timeout=30)
        if result.returncode != 0:
            return False, []
        values = []
        for line in result.stdout.decode("ascii").splitlines():
            line = line.strip()
            if line.startswith('text: "') and line.endswith('"'):
                values.append(codecs.escape_decode(line[len('text: "'):-1].encode("ascii"))[0])
        return True, values

    def test_values_at_matches_protoc(self):
        cases = dict(NONCANONICAL)
        cases.update({"canonical": perform_action(PII_PROMPT), "two actions": perform_action(actions=[("a",), ("b", "c")]),
                      "other action": other_action()})
        for name, body in cases.items():
            with self.subTest(case=name):
                ok, expected = self.protoc(body)
                self.assertTrue(ok)
                values, reason = gateway_proto.values_at(body, "2.3")
                self.assertEqual(([value for _, value in values], reason), (expected, None))

    def test_protoc_rejects_what_values_at_rejects(self):
        for name, junk in INVALID.items():
            for where, body in (("in 2", send_variant(junk)), ("at the end", perform_action(PII_PROMPT) + junk)):
                with self.subTest(case=name, where=where):
                    self.assertEqual(self.protoc(body), (False, []))
        self.assertEqual(self.protoc(perform_action(PII_PROMPT) + fl(2, INVALID["wire type 7"])), (False, []))


class BrokenDetectionResponseTests(RpcBase):
    """검토 2: Detection 응답이 깨지면(IncompleteRead·BadStatusLine 등) 예외로 원본이 나가지 않고 질문 처리 설정대로 집행."""

    def setUp(self):
        super().setUp()
        gateway.check_detection = self._orig[0]                 # 실제 detection_client.check

    def detection(self, mode):
        server = RawDetection(mode)
        self.addCleanup(server.close)
        patcher = mock.patch.object(gateway, "DETECTION_BASE_URL", server.url)
        patcher.start()
        self.addCleanup(patcher.stop)

    def rows(self):
        return [(e["targetLlm"], e["finalAction"], e["degraded"], e["reasonCode"], e["failurePolicy"]) for e in self.queued]

    def test_block_setting_returns_503(self):
        self.use_settings(prompt=("block", 0.5))
        for mode in ("truncated_body", "bad_status_line", "line_too_long", "broken_chunked"):
            with self.subTest(mode=mode):
                self.queued.clear()
                gateway._dedupe_seen.clear()
                self.detection(mode)
                flow = self.rpc(perform_action(PII_PROMPT))
                self.assertFalse(flow.metadata["test_forwarded"])
                self.assertEqual(self.connect_error(flow)[:2], (503, "unavailable"))
                self.assertEqual(self.rows(), [("Claude", "BLOCK", True, "detection_error", "FAIL_CLOSED")])
        self.queued.clear()
        self.detection("truncated_body")
        chatgpt = self.attempt(lambda: self.chatgpt_prompt(PII_PROMPT))     # 다른 질문 경로도 같은 클라이언트
        self.assertFalse(chatgpt.metadata["test_forwarded"])
        self.assertEqual(chatgpt.response.status_code, 503)
        self.assertEqual(self.rows(), [("ChatGPT", "BLOCK", True, "detection_error", "FAIL_CLOSED")])

    def test_forward_setting_forwards_with_a_degraded_event(self):
        self.use_settings(prompt=("forward", 0.5))
        self.detection("bad_status_line")
        body = perform_action(PII_PROMPT)
        flow = self.rpc(body)
        self.assertTrue(flow.metadata["test_forwarded"])
        self.assertEqual(flow.request.raw_content, body)
        self.assertEqual(self.rows(), [("Claude", "ALLOW", True, "detection_error", "FAIL_OPEN")])
        self.assertTrue(flow.metadata["gw_degraded"])

    def test_an_exception_while_inspecting_follows_the_prompt_setting(self):
        def boom(*args, **kwargs):
            raise RuntimeError("boom")
        gateway.check_detection = boom
        for setting, forwarded, row in ((("block", 0.5), False, ("Claude", "BLOCK", True, "detection_error", "FAIL_CLOSED")),
                                        (("forward", 0.5), True, ("Claude", "ALLOW", True, "detection_error", "FAIL_OPEN"))):
            with self.subTest(setting=setting[0]):
                self.queued.clear()
                gateway._dedupe_seen.clear()
                with mock.patch.object(gateway, "GATEWAY_SETTINGS", FixedSettings(prompt=setting)):
                    flow = self.rpc(perform_action(PII_PROMPT))
                self.assertEqual(flow.metadata["test_forwarded"], forwarded)
                if not forwarded:
                    self.assertEqual(self.connect_error(flow)[:2], (503, "unavailable"))
                self.assertEqual(self.rows(), [row])
        self.assertIn("[CLAUDE-RPC-PROMPT] inspection failed error_type= RuntimeError", self.log.getvalue())


class PromptStructureLineTests(RpcBase):
    """검토 3: 구조 기록 줄의 질문 칸(2.3)은 경로·길이·marker만. 질문 내용에서 나온 표시(한글·숫자 6자리·@ …)와 하위 경로는 없음."""

    def prompt_entries(self, record):
        return [leaf for leaf in record["leaves"] if leaf["path"] == "2.3" or leaf["path"].startswith("2.3.")]

    def record_for(self, body, **kwargs):
        self.log.truncate(0)
        self.log.seek(0)
        gateway._claude_rpc_shape_counts.clear()
        gateway._dedupe_seen.clear()
        self.rpc(body, **kwargs)
        record, = self.rpc_lines()
        return record

    def test_prompt_field_is_one_entry_with_length_and_marker_only(self):
        cases = {
            "marker, digits, mail": f"PGTEST 홍길동 {RRN} hong@example.test",
            "no marker": f"홍길동 주민번호 {RRN} 확인",
            "reads as a message": f"* 김철수 {RRN} 확인.",
            "control characters": f"번호\x01 {RRN}",
        }
        for name, prompt in cases.items():
            with self.subTest(case=name):
                record = self.record_for(perform_action(prompt))
                expected = {"path": "2.3", "wire": 2, "len": len(prompt.encode()), "kind": "prompt"}
                if "PGTEST" in prompt:
                    expected["flags"] = ["marker"]
                self.assertEqual(self.prompt_entries(record), [expected])
                self.assertEqual([leaf["path"] for leaf in record["leaves"]], [path for path, _, _ in SEND_SHAPE])
                self.assertEqual(record["leaves_total"], len(SEND_SHAPE))
                self.assertEqual(record["marker_paths"], ["2.3"] if "PGTEST" in prompt else [])
                self.assertEqual(record["prompt_paths"], ["2.3"])
                model = next(leaf for leaf in record["leaves"] if leaf["path"] == "2.7.2")
                self.assertIn("has_latin_word", model["flags"])             # 다른 칸의 표시는 그대로
                self.assertNotIn(RRN, self.log.getvalue())

    def test_several_prompt_fields_and_gzip(self):
        record = self.record_for(gzip.compress(perform_action(CLEAN_PROMPT, f"둘째 {RRN}"), mtime=0),
                                 headers=((b"content-encoding", b"gzip"),))
        self.assertEqual(self.prompt_entries(record),
                         [{"path": "2.3", "wire": 2, "len": len(CLEAN_PROMPT.encode()), "kind": "prompt", "flags": ["marker"]},
                          {"path": "2.3", "wire": 2, "len": len(f"둘째 {RRN}".encode()), "kind": "prompt"}])

    def test_other_methods_and_actions_keep_the_full_structure(self):
        # 다른 동작(15)·다른 메서드는 다른 동작 찾기용이라 그대로(질문 칸으로 정해지지 않은 곳)
        viewing = self.record_for(perform_action(PII_PROMPT), path=RPC + "ReportViewing")
        entry, = self.prompt_entries(viewing)
        self.assertEqual(entry["kind"], "text")
        self.assertIn("has_hangul", entry["flags"])
        other = self.record_for(other_action())
        self.assertEqual(other["leaves_total"], 41)
        self.assertTrue(any(leaf["path"] == "15.1.7.2" and "flags" in leaf for leaf in other["leaves"]))

    def test_prompt_in_a_body_the_structure_walk_cannot_read(self):
        # 구조 걷기(엄격)는 못 읽어도 값 찾기(넉넉)가 찾은 질문 칸은 한 항목으로 남아 표지를 찾을 수 있다
        for name in ("non-minimal length of 2.3", "reserved field at the top"):
            with self.subTest(case=name):
                record = self.record_for(NONCANONICAL[name])
                self.assertIn({"path": "2.3", "wire": 2, "len": len(PII_BYTES), "kind": "prompt", "flags": ["marker"]},
                              record["leaves"])
                self.assertIn("2.3", record["marker_paths"])
                for leaf in record["leaves"]:
                    if leaf["path"] in ("2", "2.3"):
                        self.assertLessEqual(set(leaf.get("flags", [])), {"marker"}, leaf)


class InspectionResultLineTests(RpcBase):
    """검토 4: 구조 기록 줄은 검사 대상 칸(prompt_paths)만 적고, 실제 검사 결과는 검사 뒤 한 줄(값 없음)로 남긴다."""

    def result_lines(self):
        return [line for line in self.log.getvalue().splitlines() if line.startswith("[CLAUDE-RPC-PROMPT] inspected=")]

    def test_structure_line_names_targets_and_result_line_counts_verdicts(self):
        flow = self.rpc(perform_action(DOC_PROMPT, PII_PROMPT, CLEAN_PROMPT))
        self.assertEqual(len(self.calls), 1)                                 # 차단에서 멈춤
        self.assertEqual(self.connect_error(flow)[0], 403)
        record, = self.rpc_lines()
        self.assertEqual(record["prompt_paths"], ["2.3"] * 3)
        self.assertNotIn("inspected_paths", record)
        self.assertEqual(self.result_lines(), ["[CLAUDE-RPC-PROMPT] inspected=1 of 3 degraded=0 action=block status=403"])

    def test_result_line_for_allow_mask_and_mask_block(self):
        self.rpc(perform_action(CLEAN_PROMPT, "PGTEST 둘째"))
        self.rpc(perform_action(PII_PROMPT))
        with mock.patch.dict(os.environ, {"GATEWAY_CLAUDE_RPC_MASK": "1"}):
            self.rpc(perform_action(PII_PROMPT + " 가림"))
        self.assertEqual(self.result_lines(),
                         ["[CLAUDE-RPC-PROMPT] inspected=2 of 2 degraded=0 action=allow status=forwarded",
                          "[CLAUDE-RPC-PROMPT] inspected=1 of 1 degraded=0 action=block status=403",
                          "[CLAUDE-RPC-PROMPT] inspected=1 of 1 degraded=0 action=mask status=forwarded"])

    def test_result_line_when_detection_fails(self):
        gateway.check_detection = self._orig[0]
        server = RawDetection("bad_status_line")
        self.addCleanup(server.close)
        with mock.patch.object(gateway, "DETECTION_BASE_URL", server.url):
            with mock.patch.object(gateway, "GATEWAY_SETTINGS", FixedSettings(prompt=("block", 0.5))):
                self.rpc(perform_action(PII_PROMPT))
            gateway._dedupe_seen.clear()
            with mock.patch.object(gateway, "GATEWAY_SETTINGS", FixedSettings(prompt=("forward", 0.5))):
                self.rpc(perform_action(PII_PROMPT))
        self.assertEqual(self.result_lines(),
                         ["[CLAUDE-RPC-PROMPT] inspected=0 of 1 degraded=1 action=block status=503",
                          "[CLAUDE-RPC-PROMPT] inspected=0 of 1 degraded=1 action=allow_degraded status=forwarded"])
        record = self.rpc_lines()[0]
        self.assertEqual(record["prompt_paths"], ["2.3"])                   # 대상 칸(검사 결과가 아님)

    def test_no_result_line_without_inspection(self):
        self.rpc(other_action())
        self.rpc(b"\xff\xfe")
        self.assertEqual(self.result_lines(), [])


if __name__ == "__main__":
    unittest.main()
