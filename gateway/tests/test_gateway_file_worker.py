"""파일 업로드 작업 스레드(2026-10-11, T0 A안) 시험.

request 훅이 async가 되고 파일 업로드만 전용 작업 스레드(GATEWAY_FILE_WORKERS = 4)에서 지금 처리를 그대로 돈다.
질문·그 밖 요청은 지금처럼 이벤트 루프에서 바로 처리한다.

1. 어느 요청이 작업 스레드로 가는지(업로드 갈래 모두 / 질문은 루프)와 실제로 어느 스레드에서 처리되는지
2. 실제 mitmproxy(DumpMaster) + 가짜 Detection 서버(T0 하네스와 같은 지연 규칙: 질문 즉시, 칸 4ms, 파일 전체는 지정):
   업로드 검사 중에도 질문이 늦지 않음, 업로드 4건 넘게 동시(작업 스레드 수를 넘으면 줄을 섬)
3. PDFium 잠금: PDF 추출은 한 번에 하나, 시간 한도는 잠금을 얻은 뒤부터, PDF가 아닌 파일은 잠그지 않음
4. 공유 표(가린 파일 크기·올린 파일 번호·업로드 신원 진단)를 작업 스레드와 루프가 함께 쓸 때
5. 실패는 원본을 보내지 않음(작업 스레드 안 예외·넘기기 실패 → 503 + 기록). 루프(질문) 쪽 예외 처리는 지금 그대로
6. 줄 선 시간은 지표 지연과 따로, done() 뒤 다시 만들기, 같은 업로드 재시도 기록 한 번만, 요청마다 설정 고정

가짜 값만 쓴다. 실제 Detection·대시보드에 연결하지 않는다(로컬 시험 서버만).
실행: python -m unittest tests.test_gateway_file_worker -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import io
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import unittest
import urllib.parse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
from tests.test_gateway_bundle_flows import (  # noqa: E402
    CFB, CLAUDE_UPLOAD_PATH, COMPLETION_PATH, ORG, RRN, Base, docx_bytes, fake_detection, xlsx_bytes,
)
from tests.gw_support import FixedSettings, png_bytes, run_hook, text_pdf  # noqa: E402
from tests.test_gateway_dedupe_proto import DedupeBase  # noqa: E402
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402
import gateway_file_classes  # noqa: E402

PUT_HOST = "sdmntprkoreacentral.oaiusercontent.com"
DOCX_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
RPC_PATH = f"/api/organizations/{ORG}/claudeai-rpc/anthropic.claudeai.v1.ConversationService/PerformAction"
BIG_TEXT = "가" * (300 * 1024 // 3 + 10)    # UTF-8로 300 KiB 넘는 질문 글자


def file_id(n: int) -> str:
    return f"00000000-aaaa-8206-bbbb-{n:012d}"


# ------------------------------------------------------------------ 요청 만들기

def put_req(fid, content):
    """ChatGPT 원본 PUT."""
    return tutils.treq(host=PUT_HOST, port=443, scheme=b"https", method=b"PUT",
                       path=f"/files/{fid}/raw?se=2026-10-11".encode(), content=content,
                       headers=((b"content-type", b"application/octet-stream"),))


def multipart(content, filename, boundary="----gwworkerboundary", field="file"):
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}".encode()


def chatgpt_multipart_req(content, filename="a.docx"):
    body, ctype = multipart(content, filename)
    return tutils.treq(host="chatgpt.com", port=443, scheme=b"https", method=b"POST", path=b"/backend-api/files/upload",
                       content=body, headers=((b"content-type", ctype),))


def claude_upload_req(content, filename="a.docx", path=CLAUDE_UPLOAD_PATH):
    body, ctype = multipart(content, filename, boundary="----gwworkerclaude")
    return tutils.treq(host="claude.ai", port=443, scheme=b"https", method=b"POST", path=path.encode(),
                       content=body, headers=((b"content-type", ctype),))


def gemini_bytes_req(content):
    return tutils.treq(host="push.clients6.google.com", port=443, scheme=b"https", method=b"POST",
                       path=b"/upload/?upload_id=fake-upload-1&upload_protocol=resumable", content=content,
                       headers=((b"content-type", b"application/x-www-form-urlencoded;charset=utf-8"),))


def gemini_init_req(filename="a.docx"):
    return tutils.treq(host="push.clients6.google.com", port=443, scheme=b"https", method=b"POST", path=b"/upload/",
                       content=f"File name: {filename}".encode(),
                       headers=((b"content-type", b"application/x-www-form-urlencoded;charset=utf-8"),))


def openai_files_req(content, filename="a.docx"):
    body, ctype = multipart(content, filename, boundary="----gwworkeropenai")
    return tutils.treq(host="api.openai.com", port=443, scheme=b"https", method=b"POST", path=b"/v1/files",
                       content=body, headers=((b"content-type", ctype),))


def json_req(host, path, payload, method=b"POST", content_type=b"application/json"):
    content = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
    return tutils.treq(host=host, port=443, scheme=b"https", method=method, path=path.encode(), content=content,
                       headers=((b"content-type", content_type),))


def conversation_req(text, attachments=()):
    message = {"author": {"role": "user"}, "content": {"content_type": "text", "parts": [text]},
               "metadata": {"attachments": [{"id": ref, "name": "a.docx"} for ref in attachments]}}
    return json_req("chatgpt.com", "/backend-api/f/conversation", {"action": "next", "messages": [message]})


def claim_req(fid, size):
    return json_req("chatgpt.com", "/backend-api/files/process_upload_stream", {"file_id": fid, "file_size": size})


def flow_of(req):
    return tflow.tflow(req=req)


async def gather_requests(flows):
    """한 이벤트 루프에서 request 훅 여러 개를 함께 돌린다(실제 mitmproxy처럼 연결마다 훅 하나)."""
    await asyncio.gather(*(gateway.request(flow) for flow in flows))


def blocked_status(flow):
    return flow.response.status_code if flow.response is not None else None


class Tracker:
    """동시에 몇 개가 안에 있었는지 센다."""

    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0

    @contextlib.contextmanager
    def inside(self):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            yield
        finally:
            with self.lock:
                self.active -= 1


class WorkerBase(Base):
    def setUp(self):
        super().setUp()
        self.use_settings()
        gateway.CHATGPT_UPLOADED_REFS.clear()
        gateway.GEMINI_FILE_META.clear()
        self.log = io.StringIO()

    def run_flows(self, reqs):
        flows = [flow_of(req) for req in reqs]
        with contextlib.redirect_stdout(self.log):
            asyncio.run(gather_requests(flows))
        return flows


# ------------------------------------------------------------------ 1. 어느 요청이 작업 스레드로 가는지

class OffloadRoutingTests(WorkerBase):
    UPLOADS = {
        "chatgpt_raw_put": lambda: put_req(file_id(1), docx_bytes("회의 메모")),
        "chatgpt_multipart": lambda: chatgpt_multipart_req(docx_bytes("회의 메모")),
        "claude_multipart": lambda: claude_upload_req(docx_bytes("회의 메모")),
        "claude_multipart_other_path": lambda: claude_upload_req(
            docx_bytes("회의 메모"), path=f"/api/organizations/{ORG}/convert_document"),
        "gemini_resumable_bytes": lambda: gemini_bytes_req(docx_bytes("회의 메모")),
        "gemini_resumable_init": lambda: gemini_init_req(),
        "openai_files": lambda: openai_files_req(docx_bytes("회의 메모")),
        # 업로드 경로인데 위 갈래가 아닌 큰 본문(모르는 업로드 모양): 256 KiB 이상이면 작업 스레드
        "chatgpt_files_large_json": lambda: json_req("chatgpt.com", "/backend-api/files/process_upload_stream",
                                                     {"pad": "x" * (256 * 1024)}),
        "openai_uploads_large": lambda: json_req("api.openai.com", "/v1/uploads/upload_1/parts", b"x" * (256 * 1024),
                                                 content_type=b"application/octet-stream"),
    }
    OTHERS = {
        "chatgpt_prompt": lambda: conversation_req("회의 요약"),
        "chatgpt_prompt_large": lambda: conversation_req(BIG_TEXT),
        "claude_completion_large": lambda: json_req("claude.ai", COMPLETION_PATH, {
            "prompt": "요약", "attachments": [{"file_name": "a.txt", "extracted_content": BIG_TEXT}]}),
        "claude_rpc": lambda: json_req("claude.ai", RPC_PATH, b"\x0a\x03abc", content_type=b"application/proto"),
        "gemini_prompt": lambda: json_req("gemini.google.com", "/_/BardChatUi/data/assistant.lamda.BardFrontendService/"
                                                               "StreamGenerate", b"f.req=x",
                                          content_type=b"application/x-www-form-urlencoded"),
        "openai_responses_large": lambda: json_req("api.openai.com", "/v1/responses",
                                                   {"model": "m", "input": BIG_TEXT}),
        "chatgpt_files_small_json": lambda: json_req("chatgpt.com", "/backend-api/files", {"file_name": "a.docx"}),
        "chatgpt_multipart_not_upload_path": lambda: tutils.treq(
            host="chatgpt.com", port=443, scheme=b"https", method=b"POST", path=b"/backend-api/f/conversation",
            content=multipart(b"x", "a.txt")[0], headers=((b"content-type", multipart(b"x", "a.txt")[1]),)),
        "gateway_health": lambda: tutils.treq(host="llm-gateway.local", port=80, scheme=b"http", method=b"GET",
                                              path=b"/__llmsgw/health", content=b""),
        "gateway_local_large_multipart": lambda: tutils.treq(
            host="llm-gateway.local", port=80, scheme=b"http", method=b"POST", path=b"/__llmsgw/my/requests",
            content=b"x" * (300 * 1024), headers=((b"content-type", b"multipart/form-data; boundary=x"),)),
        "static_asset": lambda: tutils.treq(host="cdn.oaistatic.com", port=443, scheme=b"https", method=b"GET",
                                            path=b"/assets/a.js", content=b""),
        "gemini_push_other_path": lambda: json_req("push.clients6.google.com", "/upload/status", {"a": 1}),
    }

    def test_upload_requests_go_to_the_worker_pool(self):
        for name, make in self.UPLOADS.items():
            with self.subTest(name):
                self.assertTrue(gateway.is_file_upload_request(flow_of(make())))

    def test_prompts_and_other_requests_stay_on_the_loop(self):
        for name, make in self.OTHERS.items():
            with self.subTest(name):
                self.assertFalse(gateway.is_file_upload_request(flow_of(make())))

    def test_upload_handling_runs_on_a_worker_thread_and_prompts_on_the_loop(self):
        handled = []
        original = gateway._handle_request

        def spy(flow):
            handled.append((flow.request.path, threading.current_thread().name))
            return original(flow)
        with mock.patch.object(gateway, "_handle_request", spy):
            uploads = self.run_flows([make() for make in self.UPLOADS.values()])
            others = self.run_flows([make() for make in self.OTHERS.values()])
        threads = dict(handled)
        main = threading.main_thread().name
        for flow in uploads:
            self.assertTrue(threads[flow.request.path].startswith("gw-file"), flow.request.path)
            self.assertIn("gw_file_queue_wait_ms", flow.metadata)
        for flow in others:
            self.assertEqual(threads[flow.request.path], main, flow.request.path)
            self.assertNotIn("gw_file_queue_wait_ms", flow.metadata)
        # 업로드는 실제로 검사했다(Detection 호출이 작업 스레드에서). 질문도 검사했다(루프에서)
        self.assertTrue(any(call["source"].get("content_type") == "file" for call in self.calls))
        self.assertTrue(any(call["source"].get("content_type") == "prompt" for call in self.calls))


# ------------------------------------------------------------------ 2. 실제 mitmproxy(DumpMaster)

class FakeDetection:
    """가짜 Detection 서버(T0 하네스 fakes.py와 같은 규칙). 판정은 모두 허용(가릴 것 없음): 칸 경로를 끝까지 타게."""

    def __init__(self, file_latency=0.1, cell_latency=0.004, prompt_latency=0.0, file_hook=None):
        self.file_latency, self.cell_latency, self.prompt_latency = file_latency, cell_latency, prompt_latency
        self.file_hook = file_hook
        self.counts = {"prompt": 0, "file": 0, "cell": 0}
        self.file_calls = Tracker()
        self.lock = threading.Lock()
        rig = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
                rid = str(body.get("request_id") or "")
                if (body.get("source") or {}).get("content_type") == "prompt":
                    kind, delay = "prompt", rig.prompt_latency
                elif "#" in rid:
                    kind, delay = "cell", rig.cell_latency
                else:
                    kind, delay = "file", rig.file_latency
                with rig.lock:
                    rig.counts[kind] += 1
                if kind == "file":
                    with rig.file_calls.inside():
                        if rig.file_hook:
                            rig.file_hook()
                        time.sleep(delay)
                elif delay:
                    time.sleep(delay)
                data = json.dumps({
                    "blocked": False, "reason": "fake allow", "request_id": rid, "decided_by": "none",
                    "pii_hits": None, "mask_spans": [], "findings": [], "masked_text": None,
                    "decision": {"action": "allow", "reason_code": "none", "user_message": None, "http_status": None},
                }).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ProxyRig:
    """DumpMaster(gateway + 로컬 upstream으로 돌리기 + 기록) + 가짜 Detection + 가짜 upstream."""

    def __init__(self, test, detection: FakeDetection):
        self.test, self.detection = test, detection
        self.received, self.records, self.errors = [], [], []
        rig = self

        class Upstream(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _take(self):
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                rig.received.append((self.command, self.path.split("?", 1)[0], body))
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_PUT = do_POST = _take

            def log_message(self, *args):
                pass
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.upstream.daemon_threads = True
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        up_port = self.upstream.server_address[1]

        class Redirect:
            def request(self, flow):
                flow.request.host, flow.request.port, flow.request.scheme = "127.0.0.1", up_port, "http"

        class Record:
            def response(self, flow):
                rig.records.append({k: flow.metadata.get(k) for k in (
                    "gw_file_queue_wait_ms", "gw_processing_ms", "gw_latency_ms")} | {
                    "path": flow.request.path.split("?", 1)[0], "status": flow.response.status_code})

        class Errors(logging.Handler):
            def emit(self, record):
                rig.errors.append(record.getMessage())
        self.error_handler = Errors(level=logging.ERROR)
        self.addons = (Redirect(), Record())
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.out = io.StringIO()

    def __enter__(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
        self.state = {}

        async def run_master():
            master = DumpMaster(options.Options(listen_host="127.0.0.1", listen_port=self.port),
                                with_termlog=False, with_dumper=False)
            # mitmproxy ErrorCheck는 시작 중 ERROR 기록이 하나라도 있으면 프록시를 끝낸다(듣기 소켓은 남아 연결이 응답 없이 멈춤).
            # 앞 시험의 이벤트 루프를 치우며 asyncio가 남기는 'Task was destroyed' ERROR가 그 사이에 오면 이 시험과 무관하게
            # 멈췄다(10/11 병합 트리 전체 시험 1회, 'Error logged during startup, exiting...'). 시험 프록시에서는 뺀다
            errorcheck = master.addons.get("errorcheck")
            if errorcheck is not None:
                errorcheck.finish()
                master.addons.remove(errorcheck)
            master.addons.add(gateway, *self.addons)
            self.state["master"] = master
            await master.run()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=lambda: self.loop.run_until_complete(run_master()), daemon=True)
        self.stack = contextlib.ExitStack()
        for patcher in (mock.patch.object(gateway, "DETECTION_BASE_URL", self.detection.url),
                        mock.patch.object(gateway, "send_to_next_module", lambda event: None),
                        mock.patch.object(gateway, "_gateway_latencies_ms", deque(maxlen=500)),
                        mock.patch.object(gateway, "GATEWAY_SETTINGS",
                                          FixedSettings(prompt=("forward", 2.0), file=("block", 5.0)))):
            self.stack.enter_context(patcher)
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        # mitmproxy 오류(Addon error·연결 처리 중단 등)만 모은다. asyncio가 앞 시험의 Windows accept 작업을 치울 때 남기는
        # 'Task was destroyed' 줄은 이 시험과 무관하다
        logging.getLogger("mitmproxy").addHandler(self.error_handler)
        self.thread.start()
        # 준비 확인 = 이 Gateway가 답하는지(헬스 체크). 포트에 다른 것이 붙어 있으면 시험 준비 실패로 바로 알린다
        deadline = time.monotonic() + 15
        while True:
            try:
                if self.call("GET", "http://llm-gateway.local/__llmsgw/health", None, "application/json",
                             timeout=2)[0] == 200:
                    return self
            except (OSError, http.client.HTTPException):
                pass
            if time.monotonic() > deadline:
                self.__exit__(None, None, None)
                raise RuntimeError(f"test proxy on port {self.port} did not answer the gateway health check")
            time.sleep(0.1)

    def __exit__(self, *exc):
        time.sleep(0.2)
        if "master" in self.state:
            self.loop.call_soon_threadsafe(self.state["master"].shutdown)
        self.thread.join(15)
        if not self.thread.is_alive():
            self.loop.close()
        logging.getLogger("mitmproxy").removeHandler(self.error_handler)
        self.stack.close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.detection.close()

    def call(self, method, url, body, content_type, timeout=30):
        """프록시로 요청 하나(새 연결). (상태, 걸린 초, 끝난 시각)"""
        host = urllib.parse.urlsplit(url).hostname
        started = time.perf_counter()
        status = None
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, url, body=body,
                         headers={"Host": host, "Content-Type": content_type, "Connection": "close"})
            response = conn.getresponse()
            response.read()
            status = response.status
        finally:
            conn.close()
        done = time.perf_counter()
        return status, done - started, done

    def prompt(self, k):
        body = json.dumps({"action": "next", "messages": [{"author": {"role": "user"}, "content": {
            "content_type": "text", "parts": [f"시험 질문 {k}: 다음 주 회의 일정 정리해 줘"]}}]}, ensure_ascii=False).encode()
        return self.call("POST", "http://chatgpt.com/backend-api/f/conversation", body, "application/json")

    def put(self, fid, content):
        return self.call("PUT", f"http://files.oaiusercontent.com/files/{fid}/raw", content, "application/octet-stream")


def p95(values):
    ordered = sorted(values)
    return ordered[max(0, -(-len(ordered) * 95 // 100) - 1)]


class ProxyConcurrencyTests(unittest.TestCase):
    """실제 mitmproxy에 gateway를 올린다. 이전(동기 훅)에는 업로드 검사가 끝날 때까지 루프가 멈춰 질문이 그만큼 기다렸다."""

    def setUp(self):
        gateway.CHATGPT_FILE_META.clear()
        gateway.CHATGPT_SANITIZED_FILE_SIZE.clear()
        gateway._dedupe_seen.clear()
        self.report = mock.patch.object(gateway, "report_dashboard_event", lambda *a, **k: None)
        self.report.start()
        self.addCleanup(self.report.stop)

    def test_prompts_are_not_delayed_while_an_upload_is_being_inspected(self):
        entered, release = threading.Event(), threading.Event()

        def hold_first_file_call():
            entered.set()
            release.wait(4.0)        # 파일 전체 검사가 이 동안 끝나지 않는다(Detection 대기 시간 5초 안)
        detection = FakeDetection(file_latency=0.0, cell_latency=0.004, file_hook=hold_first_file_call)
        workbook = xlsx_bytes([(f"A{i}", f"가짜 값 {i}") for i in range(1, 201)])   # 칸 200개(칸마다 4ms)
        upload = {}
        with ProxyRig(self, detection) as rig:
            thread = threading.Thread(target=lambda: upload.update(r=rig.put(file_id(41), workbook)))
            thread.start()
            if not entered.wait(15):
                release.set()
                self.fail(f"upload never reached Detection: counts={detection.counts} received={len(rig.received)} "
                          f"errors={rig.errors} gateway log tail={rig.out.getvalue()[-3000:]!r}")
            prompts = [rig.prompt(k) for k in range(5)]
            released_at = time.perf_counter()
            release.set()
            thread.join(30)
        self.assertEqual([status for status, _, _ in prompts], [200] * 5)
        self.assertLess(max(seconds for _, seconds, _ in prompts), 1.0, prompts)   # 동기 훅이면 약 4초씩
        self.assertTrue(all(done < released_at for _, _, done in prompts))          # 업로드 검사가 끝나기 전에 답을 받았다
        self.assertEqual(upload["r"][0], 200)
        self.assertEqual([(m, b) for m, p, b in rig.received if m == "PUT"], [("PUT", workbook)])   # 허용: 바이트 그대로
        self.assertEqual((detection.counts["prompt"], detection.counts["file"]), (5, 1))
        self.assertGreaterEqual(detection.counts["cell"], 200)
        self.assertEqual(rig.errors, [])

    def test_more_concurrent_uploads_than_workers_with_prompts_running(self):
        detection = FakeDetection(file_latency=0.5, cell_latency=0.004)
        uploads = {   # PDF 2·XLSX 2·DOCX 2 = 6건(작업 스레드 4개를 넘음)
            file_id(51): text_pdf("fake pdf one"), file_id(52): text_pdf("fake pdf two"),
            file_id(53): xlsx_bytes([(f"A{i}", f"v{i}") for i in range(1, 41)]),
            file_id(54): xlsx_bytes([(f"B{i}", f"w{i}") for i in range(1, 41)]),
            file_id(55): docx_bytes(*[f"문단 {i}" for i in range(30)]),
            file_id(56): docx_bytes(*[f"다른 문단 {i}" for i in range(30)]),
        }
        results, prompts, stop = {}, [], threading.Event()
        with ProxyRig(self, detection) as rig:
            def prompt_loop():
                k = 0
                while not stop.is_set():
                    prompts.append(rig.prompt(k))
                    k += 1
                    time.sleep(0.1)
            prompter = threading.Thread(target=prompt_loop)
            prompter.start()
            time.sleep(0.5)
            threads = [threading.Thread(target=lambda fid=fid, data=data: results.__setitem__(fid, rig.put(fid, data)))
                       for fid, data in uploads.items()]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)
            time.sleep(0.5)
            stop.set()
            prompter.join(10)
        self.assertEqual({fid: r[0] for fid, r in results.items()}, {fid: 200 for fid in uploads})
        self.assertEqual(sorted(b for m, p, b in rig.received if m == "PUT"), sorted(uploads.values()))
        self.assertEqual(detection.counts["file"], 6)
        self.assertEqual(detection.file_calls.peak, gateway.GATEWAY_FILE_WORKERS)   # 4개가 함께, 넘는 것은 줄을 섬
        self.assertEqual({status for status, _, _ in prompts}, {200})
        self.assertGreaterEqual(len(prompts), 8)
        self.assertLess(p95([seconds for _, seconds, _ in prompts]), 0.5)
        upload_records = [r for r in rig.records if r["path"].startswith("/files/")]
        self.assertEqual(len(upload_records), 6)
        waits = sorted(r["gw_file_queue_wait_ms"] for r in upload_records)
        self.assertGreaterEqual(waits[-1], 200)              # 넘친 업로드는 줄을 섰다(앞 업로드 0.5초 이상)
        for record in upload_records:                        # 지표 지연(processingMs) = Gateway 처리만(줄 선 시간 빠짐)
            self.assertEqual(record["gw_latency_ms"], record["gw_processing_ms"])
            self.assertLess(record["gw_processing_ms"], 500 + 1500)
        self.assertEqual(rig.errors, [])
        self.assertNotIn("Traceback", rig.out.getvalue())


# ------------------------------------------------------------------ 3. PDFium 잠금

class PdfiumLockTests(WorkerBase):
    def test_pdf_extraction_is_serialized_and_other_files_are_not(self):
        pdf_inside, all_inside = Tracker(), Tracker()
        original_pdf, original_inspect = gateway_file_classes.extract_pdf, gateway.inspect_upload

        def slow_pdf(*args, **kwargs):
            with pdf_inside.inside():
                time.sleep(0.15)
                return original_pdf(*args, **kwargs)

        def tracked_inspect(data, **kwargs):
            with all_inside.inside():
                if not data.startswith(b"%PDF-"):
                    time.sleep(0.15)      # PDF가 아닌 파일도 0.15초(잠그지 않으므로 PDF와 겹친다)
                return original_inspect(data, **kwargs)
        reqs = [put_req(file_id(60 + i), text_pdf(f"fake pdf {i}")) for i in range(3)]
        reqs += [put_req(file_id(70 + i), xlsx_bytes([("A1", f"v{i}")])) for i in range(2)]
        with mock.patch.object(gateway_file_classes, "extract_pdf", slow_pdf), \
                mock.patch.object(gateway, "inspect_upload", tracked_inspect):
            flows = self.run_flows(reqs)
        self.assertEqual(pdf_inside.peak, 1)              # PDF는 한 번에 하나
        self.assertGreaterEqual(all_inside.peak, 2)       # XLSX는 PDF를 기다리지 않는다
        self.assertEqual([blocked_status(flow) for flow in flows], [None] * 5)
        whole = [call for call in self.calls if "#" not in call["request_id"]]
        self.assertEqual(len(whole), 5)

    def test_time_budget_starts_after_the_lock_is_acquired(self):
        # 파일 대기 0.5초. PDF마다 잠금 안에서 0.3초: 세 번째 PDF는 0.6초를 기다린다. 시한을 잠금 전부터 재면 '너무 큼'으로 막힌다
        self.use_settings(file=("block", 0.5))
        original_pdf = gateway_file_classes.extract_pdf

        def slow_pdf(*args, **kwargs):
            time.sleep(0.3)
            return original_pdf(*args, **kwargs)
        reqs = [put_req(file_id(80 + i), text_pdf(f"fake pdf {i}")) for i in range(3)]
        with mock.patch.object(gateway_file_classes, "extract_pdf", slow_pdf):
            flows = self.run_flows(reqs)
        self.assertEqual([blocked_status(flow) for flow in flows], [None] * 3)
        self.assertEqual(len([call for call in self.calls if "#" not in call["request_id"]]), 3)
        self.assertNotIn("file_too_large", self.log.getvalue())
        waits = [float(m) for m in re.findall(r"\[FILE\] pdf lock wait_ms=([\d.]+)", self.log.getvalue())]
        self.assertGreaterEqual(len(waits), 2)
        self.assertGreaterEqual(max(waits), 500)


# ------------------------------------------------------------------ 4. 공유 표

class SharedTableTests(WorkerBase):
    def fine_grained_switching(self):
        """GIL을 아주 자주 넘기게 해(1µs) 스레드가 섞이는 지점을 늘린다. 끝나면 되돌린다."""
        previous = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        self.addCleanup(sys.setswitchinterval, previous)

    def test_uploaded_ref_table_updates_are_atomic(self):
        # 올린 파일 번호 표: 넣기·순서 바꾸기·1000개 넘으면 지우기가 한 번에 일어나야 한다. 잠금 안에서 보는 쪽은 늘 1000개
        # (잠금이 없으면 1001개인 중간 상태가 보인다: 10/11 확인)
        self.fine_grained_switching()
        for i in range(1000):
            gateway._remember_uploaded_ref(f"filler{i}")
        errors, seen, stop = [], set(), threading.Event()

        def writer(seed):
            try:
                for i in range(20000):
                    gateway._remember_uploaded_ref(f"w{seed}-{i % 1500}")
            except Exception as exc:
                errors.append(repr(exc))

        def reader():
            while not stop.is_set():
                with gateway._upload_state_lock:
                    seen.add(len(gateway.CHATGPT_UPLOADED_REFS))
                    sum(f"w0-{i}" in gateway.CHATGPT_UPLOADED_REFS for i in range(0, 1500, 50))
        writers = [threading.Thread(target=writer, args=(seed,)) for seed in range(4)]
        watcher = threading.Thread(target=reader)
        watcher.start()
        for thread in writers:
            thread.start()
        for thread in writers:
            thread.join(60)
        stop.set()
        watcher.join(10)
        self.assertEqual(errors, [])
        self.assertEqual(seen, {1000})
        self.assertEqual(len(gateway.CHATGPT_UPLOADED_REFS), 1000)

    def test_completion_lookups_while_sanitized_sizes_are_added(self):
        # 완료 요청(루프)이 가린 크기 표를 훑는 동안 작업 스레드가 크기를 넣는다(apply_raw_upload와 같은 문장).
        # 훑는 쪽이 사본을 쓰지 않으면 RuntimeError(dictionary changed size during iteration)가 난다(10/11 확인).
        # 업로드 신원 진단도 함께: 완료 요청은 compare(안쪽 표를 훑음), 파일 만들기 응답 훅은 remember(넣고 지움)
        self.fine_grained_switching()
        for i in range(2000):
            gateway.CHATGPT_SANITIZED_FILE_SIZE[f"filler-{i}"] = i
        errors, barrier = [], threading.Barrier(5)

        def creator():
            barrier.wait()
            try:
                for n in range(600):
                    created = flow_of(json_req("chatgpt.com", "/backend-api/files", {"file_name": "a.docx"}))
                    created.client_conn.peername = ("192.0.2.10", 50000)
                    created.response = tutils.tresp(content=json.dumps({
                        "file_id": f"file-{n}", "reservation_id": f"res-{n}",
                        "upload_url": f"https://{PUT_HOST}/files/new-0-{n}/raw"}).encode())
                    gateway.response(created)
            except Exception as exc:
                errors.append(repr(exc))

        def writer(seed):
            barrier.wait()
            for i in range(3000):
                with gateway._upload_state_lock:
                    gateway.CHATGPT_SANITIZED_FILE_SIZE[f"new-{seed}-{i}"] = i
                time.sleep(0)

        def reader(index):
            barrier.wait()
            try:
                for n in range(150):
                    flow = flow_of(claim_req(f"nope-{index}-{n}", 1))
                    flow.client_conn.peername = ("192.0.2.10", 50001)
                    if n % 2:
                        gateway._rewrite_completion_file_size(flow, None)
                    else:
                        run_hook(gateway.request(flow))     # 완료 요청 전체(신원 진단 compare·크기 요약 포함)
            except Exception as exc:
                errors.append(repr(exc))
        threads = [threading.Thread(target=writer, args=(seed,)) for seed in range(2)]
        threads += [threading.Thread(target=reader, args=(index,)) for index in range(2)]
        threads.append(threading.Thread(target=creator))
        with contextlib.redirect_stdout(self.log), mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(120)
        self.assertEqual(errors, [])
        self.assertEqual(len(gateway.CHATGPT_SANITIZED_FILE_SIZE), 2000 + 2 * 3000)

    def test_size_table_and_identity_diagnostic_with_uploads_and_loop_requests_together(self):
        # 큰 표(훑는 데 시간이 걸리게) + 작업 스레드는 가린 크기를 넣고 루프는 완료 요청·질문·응답 훅으로 훑는다.
        # 루프는 한 바퀴마다 2ms 쉰다: 쉬지 않고 CPU를 쓰면 GIL 때문에 작업 스레드가 거의 돌지 못한다(10/11 실측: 업로드 12건
        # 0.74초 → 102초). 운영 루프는 대부분 네트워크를 기다리므로 그 극단은 시험하지 않는다
        for i in range(5000):
            gateway.CHATGPT_SANITIZED_FILE_SIZE[f"filler-{i}"] = i
        for i in range(995):
            gateway._remember_uploaded_ref(f"filler{i}")
        uploads = {file_id(100 + i): docx_bytes(f"주민등록번호 {RRN}", f"문단 {i}") for i in range(12)}
        loop_errors, loop_rounds = [], [0]

        async def loop_traffic(done):
            while not done.is_set():
                try:
                    unknown = flow_of(claim_req(file_id(999), 1234))
                    await gateway.request(unknown)                          # 표를 훑는다(일치 없음)
                    await gateway.request(flow_of(conversation_req("요약", [f"file_{file_id(100)}"])))
                    created = flow_of(json_req("chatgpt.com", "/backend-api/files", {"file_name": "a.docx"}))
                    created.response = tutils.tresp(content=json.dumps({
                        "file_id": "file-created", "upload_url": f"https://{PUT_HOST}/files/{file_id(101)}/raw"}).encode())
                    with mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
                        gateway.response(created)                           # 업로드 신원 진단 remember
                except Exception as exc:
                    loop_errors.append(repr(exc))
                loop_rounds[0] += 1
                await asyncio.sleep(0.002)

        async def scenario():
            done = asyncio.Event()
            traffic = asyncio.create_task(loop_traffic(done))
            flows = [flow_of(put_req(fid, data)) for fid, data in uploads.items()]
            # 업로드 경로의 큰 완료 요청(256 KiB 이상)도 작업 스레드에서 표·신원 진단을 훑는다
            big_claims = [flow_of(json_req("chatgpt.com", "/backend-api/files/process_upload_stream",
                                           {"file_id": file_id(900 + i), "file_size": 1, "pad": "x" * (256 * 1024)}))
                          for i in range(4)]
            await asyncio.gather(*(gateway.request(flow) for flow in flows + big_claims))
            self.assertTrue(all("gw_file_queue_wait_ms" in flow.metadata for flow in big_claims))
            done.set()
            await traffic
            return flows
        with contextlib.redirect_stdout(self.log):
            flows = asyncio.run(scenario())
        self.assertEqual(loop_errors, [])
        self.assertGreater(loop_rounds[0], 3)
        self.assertNotIn("upload processing failed", self.log.getvalue())
        for flow in flows:
            fid = flow.request.path.split("/")[2]
            self.assertIsNone(flow.response)
            self.assertNotIn(RRN.encode(), flow.request.raw_content)       # 가렸다
            self.assertEqual(gateway.CHATGPT_SANITIZED_FILE_SIZE[fid], len(flow.request.raw_content))
        self.assertLessEqual(len(gateway.CHATGPT_UPLOADED_REFS), 1000)
        # 완료 요청이 가린 크기로 바뀐다(표 내용이 맞다)
        for flow in flows:
            fid = flow.request.path.split("/")[2]
            claim = flow_of(claim_req(fid, len(uploads[fid])))
            with contextlib.redirect_stdout(self.log):
                run_hook(gateway.request(claim))
            self.assertEqual(json.loads(claim.request.raw_content)["file_size"], len(flow.request.raw_content))


# ------------------------------------------------------------------ 5. 실패는 원본을 보내지 않음

class FailClosedTests(WorkerBase):
    def assert_fail_closed(self, flow, target):
        self.assertEqual(blocked_status(flow), 503)
        self.assertEqual(json.loads(flow.response.content), {"error": {"type": "file_masking_failed"}})
        self.assertEqual(flow.metadata.get("gw_action"), "block")
        report, = [r for r in self.reports if r.http_status == 503]
        self.assertEqual((report.result.action, report.result.reason_code, report.applied),
                         ("block", "file_masking_failed", True))
        self.assertEqual((report.context["targetLlm"], report.context["contentType"]), (target, "file"))
        self.assertIn("[FILE-WORKER] upload processing failed", self.log.getvalue())

    def run_one(self, req):
        flow, = self.run_flows([req])
        return flow

    def test_exceptions_inside_the_worker_block_every_upload_kind(self):
        boom = RuntimeError("fake failure")
        cases = [
            ("chatgpt_raw_put", lambda: put_req(file_id(200), docx_bytes("메모")), "read_and_strip_identity", "ChatGPT"),
            ("chatgpt_multipart", lambda: chatgpt_multipart_req(docx_bytes("메모")), "extract_file_upload_info",
             "ChatGPT"),
            ("claude_multipart", lambda: claude_upload_req(docx_bytes("메모")), "extract_claude_file_upload_info",
             "Claude"),
            ("gemini_resumable", lambda: gemini_bytes_req(docx_bytes("메모")), "_create_gemini_resumable_file_event",
             "Gemini"),
            ("openai_files", lambda: openai_files_req(docx_bytes("메모")), "create_file_event", "ChatGPT"),
        ]
        for name, make, target_function, target in cases:
            with self.subTest(name):
                self.reports.clear()
                self.log = io.StringIO()
                with mock.patch.object(gateway, target_function, side_effect=boom):
                    flow = self.run_one(make())
                self.assert_fail_closed(flow, target)
                # 이전(동기 훅): 이 예외는 request() 밖으로 나가고 mitmproxy가 원래 요청을 보냈다

    def test_pending_allow_record_is_dropped_when_the_worker_fails_afterwards(self):
        self.use_settings(image="allow")
        original = gateway.detect_claude_file_upload

        def then_fail(flow, identity):
            original(flow, identity)          # 이미지(허용) → 허용 기록 보류
            raise RuntimeError("fake failure after pending allow")
        with mock.patch.object(gateway, "detect_claude_file_upload", then_fail):
            flow = self.run_one(claude_upload_req(png_bytes(), "a.png"))
        self.assert_fail_closed(flow, "Claude")
        self.assertEqual([r.result.action for r in self.reports], ["block"])   # 나가지 않은 이미지의 허용 기록 없음
        self.assertIn("uninspected allow events dropped", self.log.getvalue())

    def test_handing_off_to_the_pool_fails(self):
        handled = []
        with mock.patch.object(gateway, "_submit_file_work",
                               side_effect=RuntimeError("cannot schedule new futures after shutdown")), \
                mock.patch.object(gateway, "_handle_request", side_effect=lambda flow: handled.append(flow)):
            flow = self.run_one(put_req(file_id(201), docx_bytes("메모")))
        self.assertEqual(handled, [])
        self.assert_fail_closed(flow, "ChatGPT")

    def test_failure_record_itself_failing_still_blocks(self):
        with mock.patch.object(gateway, "read_and_strip_identity", side_effect=RuntimeError("fake")), \
                mock.patch.object(gateway, "fail_closed_file_upload", side_effect=RuntimeError("record failed")):
            flow = self.run_one(put_req(file_id(202), docx_bytes("메모")))
        self.assertEqual(blocked_status(flow), 503)
        self.assertIn("failure record omitted", self.log.getvalue())

    def test_pool_keeps_working_after_a_failure(self):
        with mock.patch.object(gateway, "read_and_strip_identity", side_effect=RuntimeError("fake")):
            self.run_one(put_req(file_id(203), docx_bytes("메모")))
        flow = self.run_one(put_req(file_id(204), docx_bytes("다음 메모")))
        self.assertIsNone(flow.response)
        self.assertTrue(any(file_id(204) in str(call["source"].get("endpoint")) for call in self.calls))

    def test_loop_side_exception_handling_is_unchanged(self):
        # 질문 경로(루프)는 이번 변경 범위 밖: 예외는 지금처럼 mitmproxy에 넘어간다(mitmproxy는 기록하고 원래 요청을 보냄)
        with mock.patch.object(gateway, "extract_chatgpt_prompt", side_effect=RuntimeError("fake")), \
                contextlib.redirect_stdout(self.log):
            flow = flow_of(conversation_req("요약"))
            with self.assertRaises(RuntimeError):
                run_hook(gateway.request(flow))
        self.assertIsNone(flow.response)


# ------------------------------------------------------------------ 6. 줄 선 시간·지표, done(), 기록 한 번만, 설정 고정

class QueueAndMetricsTests(WorkerBase):
    def test_queue_wait_is_recorded_separately_from_processing_time(self):
        gateway.check_detection = fake_detection(self.calls, delay=0.4)     # 업로드마다 파일 전체 호출 1번(TXT)
        latencies = deque(maxlen=50)
        reqs = [put_req(file_id(300 + i), f"가짜 메모 {i}".encode()) for i in range(6)]
        with mock.patch.object(gateway, "_gateway_latencies_ms", latencies), \
                mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
            flows = self.run_flows(reqs)
            with contextlib.redirect_stdout(self.log):
                for flow in flows:
                    flow.response = tutils.tresp()
                    gateway.response(flow)
        waits = sorted(flow.metadata["gw_file_queue_wait_ms"] for flow in flows)
        self.assertTrue(all(wait < 150 for wait in waits[:4]), waits)       # 작업 스레드 4개는 바로
        self.assertTrue(all(wait >= 300 for wait in waits[4:]), waits)      # 넘친 2건은 앞 업로드(0.4초)를 기다림
        for flow in flows:
            self.assertGreaterEqual(flow.metadata["gw_processing_ms"], 380)
            self.assertLess(flow.metadata["gw_processing_ms"], 750)          # 줄 선 시간(0.4초)이 들어가지 않는다
        self.assertEqual(sorted(latencies), sorted(flow.metadata["gw_processing_ms"] for flow in flows))
        lines = [line for line in self.log.getvalue().splitlines() if line.startswith("[METRICS] gateway_ms=")]
        self.assertEqual(len(lines), 6)
        self.assertTrue(all("file_queue_wait_ms=" in line for line in lines))

    def test_prompt_metrics_line_is_unchanged(self):
        with mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
            flow, = self.run_flows([conversation_req("요약")])
            with contextlib.redirect_stdout(self.log):
                flow.response = tutils.tresp()
                gateway.response(flow)
        line, = [line for line in self.log.getvalue().splitlines() if line.startswith("[METRICS] gateway_ms=")]
        self.assertNotIn("file_queue_wait_ms", line)


class LifecycleTests(WorkerBase):
    def setUp(self):
        super().setUp()
        for name in ("_gateway_metrics_publisher", "_gateway_event_outbox"):
            patcher = mock.patch.object(gateway, name, SimpleNamespace(stop=lambda: None, start=lambda: None,
                                                                       notify=lambda: None,
                                                                       snapshot=lambda: {}))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_done_lets_running_and_queued_uploads_finish_then_a_new_pool_is_made(self):
        entered, release = threading.Semaphore(0), threading.Event()
        base_check = fake_detection(self.calls)

        def held(*args, **kwargs):
            entered.release()
            release.wait(10)
            return base_check(*args, **kwargs)
        gateway.check_detection = held
        reqs = [put_req(file_id(400 + i), f"가짜 메모 {i}".encode()) for i in range(6)]
        flows = [flow_of(req) for req in reqs]
        pools = {}

        async def scenario():
            tasks = [asyncio.create_task(gateway.request(flow)) for flow in flows]
            for _ in range(gateway.GATEWAY_FILE_WORKERS):        # 작업 스레드 4개가 모두 검사 중, 2건은 줄에
                while not entered.acquire(blocking=False):
                    await asyncio.sleep(0.01)
            pools["old"] = gateway._file_executor
            gateway.done()
            pools["after_done"] = gateway._file_executor
            release.set()
            await asyncio.gather(*tasks)
        with contextlib.redirect_stdout(self.log):
            asyncio.run(scenario())
            gateway.check_detection = base_check
            after, = self.run_flows([put_req(file_id(410), "다음 메모".encode())])
        self.assertIsNone(pools["after_done"])
        self.assertTrue(pools["old"]._shutdown)
        self.assertEqual([blocked_status(flow) for flow in flows], [None] * 6)   # 받은 업로드는 끝까지(취소 없음)
        self.assertEqual(len(self.calls), 7)
        self.assertIsNone(after.response)
        self.assertIsNotNone(gateway._file_executor)
        self.assertIsNot(gateway._file_executor, pools["old"])

    def test_submit_never_reaches_a_closed_pool(self):
        errors, stop = [], threading.Event()

        def submitter():
            try:
                for _ in range(300):
                    gateway._submit_file_work(lambda: None).result(5)
            except Exception as exc:
                errors.append(repr(exc))

        def closer():
            while not stop.is_set():
                gateway._shutdown_file_executor()
                time.sleep(0.001)
        threads = [threading.Thread(target=submitter) for _ in range(4)]
        closing = threading.Thread(target=closer)
        closing.start()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        stop.set()
        closing.join(10)
        self.assertEqual(errors, [])


class DedupeAndSettingsTests(DedupeBase):
    def setUp(self):
        super().setUp()
        self.use_settings()

    def test_concurrent_retries_of_the_same_blocked_upload_are_recorded_once(self):
        gateway.CHATGPT_FILE_META[file_id(500)] = "a.hwp"
        flows = [flow_of(put_req(file_id(500), CFB)) for _ in range(3)]
        with contextlib.redirect_stdout(self.log):
            asyncio.run(gather_requests(flows))
            with mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None):
                for flow in flows:
                    gateway.response(flow)
        self.assertEqual([blocked_status(flow) for flow in flows], [403] * 3)   # 시도마다 막는다
        self.assertEqual(len(self.queued), 1)                                    # 기록·알림은 한 번
        self.assertEqual(len(self.extension), 1)
        self.assertEqual(len(self.dedupe_lines()), 2)

    def test_settings_are_fixed_per_request_while_an_upload_runs_in_a_worker(self):
        first = FixedSettings(prompt=("forward", 0.5), file=("block", 3.0)).settings
        second = FixedSettings(prompt=("forward", 0.3), file=("block", 1.0)).settings
        holder = SimpleNamespace(value=first, current=lambda: holder.value)
        patcher = mock.patch.object(gateway, "GATEWAY_SETTINGS", holder)
        patcher.start()
        self.addCleanup(patcher.stop)
        calls, entered, release = [], threading.Event(), threading.Event()
        base_check = fake_detection(calls)

        def check(*args, **kwargs):
            if (kwargs.get("source") or {}).get("content_type") == "file" and "#" not in kwargs["request_id"]:
                entered.set()
                release.wait(10)
            return base_check(*args, **kwargs)
        gateway.check_detection = check
        upload = flow_of(put_req(file_id(501), docx_bytes(f"주민등록번호 {RRN}", "문단 둘")))
        prompt = flow_of(conversation_req("회의 요약"))

        async def scenario():
            task = asyncio.create_task(gateway.request(upload))
            while not entered.is_set():
                await asyncio.sleep(0.01)
            holder.value = second                     # 업로드 검사 중에 대시보드 설정이 바뀜
            await gateway.request(prompt)             # 루프의 질문은 새 설정
            release.set()
            await task
        with contextlib.redirect_stdout(self.log):
            asyncio.run(scenario())
        file_timeouts = {call["timeout"] for call in calls if call["source"].get("content_type") == "file"}
        prompt_timeouts = [call["timeout"] for call in calls if call["source"].get("content_type") == "prompt"]
        self.assertEqual(file_timeouts, {3.0})        # 업로드는 시작 때 설정 그대로(칸 검사 포함)
        self.assertEqual(prompt_timeouts, [0.3])
        self.assertGreater(len([call for call in calls if "#" in call["request_id"]]), 0)
        self.assertNotIn(RRN.encode(), upload.request.raw_content)


if __name__ == "__main__":
    unittest.main()
