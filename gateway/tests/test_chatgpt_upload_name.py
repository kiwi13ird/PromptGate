"""ChatGPT 파일 이름 기록(2026-10-12).

증상: 대시보드의 ChatGPT 파일 기록 이름이 '<UUID>.<형식>'(파일 번호). Claude는 이름.
원인: 이름은 예약 요청 JSON에, 번호(upload_url의 /files/<UUID>/raw)는 응답에만 있는데 요청 본문 하나에서 둘을 함께
찾았다(한 번도 기억 못 함). 옛 모양 POST /backend-api/files는 아예 보지 않았다.
고침: 요청 훅이 이름을 flow에 두고 응답 훅이 upload_url 번호와 잇는다. 원본 PUT은 정규화 번호로 찾는다.

1. 실제 훅(request·response) 순서: 예약 → 원본 PUT → 완료. 이름 키 모양마다, 옛 모양 경로, 가림 + 완료 크기 고침
2. 잇지 않는 경우(번호로 기록): 이름·주소가 둘 이상, 실패 응답, 이름 아닌 name, 예약 없음
3. multipart: part 이름 그대로 / 'blob'이면 경로 번호로 기억한 이름
4. 동시 업로드(작업 스레드 4개) 이름 섞이지 않음, 기억 상한, 로그에 이름·번호 없음, 구조 줄(키 이름·종류·길이만)
5. 실제 mitmproxy(DumpMaster): 예약 응답의 upload_url로 PUT → 완료, 6건 동시, 키 모양 섞어서

가짜 값만 쓴다. 실제 Detection·대시보드에 연결하지 않는다.
실행: python -m unittest tests.test_chatgpt_upload_name -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import tests.test_gateway_bundle_flows as bundle  # noqa: F401,E402  (임시 폴더·환경 변수 준비)
from tests.test_gateway_bundle_flows import RRN, Base, docx_bytes  # noqa: E402
from tests.test_gateway_file_worker import (  # noqa: E402
    PUT_HOST, ProxyRig, file_id, flow_of, json_req, multipart, put_req,
)
from tests.gw_support import run_hook  # noqa: E402
from mitmproxy.test import tflow, tutils  # noqa: E402

import gateway  # noqa: E402

RESERVE_PATH = "/backend-api/files/upload_reservations"
LEGACY_PATH = "/backend-api/files"
NAME_RE = re.compile("가짜|" + re.escape(json.dumps("가짜")[1:-1]))   # 시험 이름은 모두 '가짜'로 시작(ASCII JSON 줄 포함)


def reservation_id(fid: str) -> str:
    return "file_" + fid.replace("-", "")


def upload_url(fid: str, host=PUT_HOST) -> str:
    return f"https://{host}/files/{fid}/raw?se=2026-10-12&sp=cw&sig=FAKE-SIGNATURE"


def new_response(fid):
    """새 모양(10/11 운영 실측 키): reservation_id + upload_url."""
    return {"reservation_id": reservation_id(fid), "upload_url": upload_url(fid), "status": "success"}


def legacy_response(fid, server_id):
    """옛 모양(POST /backend-api/files): file_id + upload_url."""
    return {"status": "success", "file_id": server_id, "upload_url": upload_url(fid)}


def claim_and_finish_req(fid, size):
    return json_req("chatgpt.com", f"{RESERVE_PATH}/{reservation_id(fid)}/claim_and_finish", {"file_size": size})


def doc(marker, *extra):
    return docx_bytes(f"[{marker}] 가짜 회의 메모", *extra)


class NameFlowBase(Base):
    def setUp(self):
        super().setUp()
        self.use_settings()
        self.log = io.StringIO()
        self.events = []
        gateway.send_to_next_module = self.events.append
        for patcher in (mock.patch.object(gateway, "_emit_gateway_metrics", lambda: None),
                        mock.patch.object(gateway, "CHATGPT_FILE_SHAPE_PER_HOUR", 1000)):
            patcher.start()
            self.addCleanup(patcher.stop)
        gateway._chatgpt_file_shape_window[:] = [0.0, 0]
        gateway.CHATGPT_UPLOADED_REFS.clear()

    def capture(self):
        """로그 모으기. 여러 스레드가 함께 부르는 시험은 바깥(주 스레드)에서 한 번만 바꾼다(sys.stdout은 하나)."""
        if threading.current_thread() is threading.main_thread():
            return contextlib.redirect_stdout(self.log)
        return contextlib.nullcontext()

    def reserve(self, body, response, path=RESERVE_PATH, status=200, peer=("192.0.2.20", 50000)):
        flow = flow_of(json_req("chatgpt.com", path, body))
        flow.client_conn.peername = peer
        with self.capture():
            run_hook(gateway.request(flow))
            flow.response = tutils.tresp(status_code=status, content=json.dumps(response).encode(),
                                         headers=((b"content-type", b"application/json"),))
            gateway.response(flow)
        return flow

    def put(self, fid, content, peer=("192.0.2.20", 50001)):
        flow = flow_of(put_req(fid, content))
        flow.client_conn.peername = peer
        with self.capture():
            run_hook(gateway.request(flow))
        return flow

    def finish(self, req, peer=("192.0.2.20", 50002)):
        flow = flow_of(req)
        flow.client_conn.peername = peer
        with self.capture():
            run_hook(gateway.request(flow))
        return flow

    def file_calls(self, marker=None):
        return [call for call in self.calls if call["source"].get("content_type") == "file"
                and (marker is None or f"[{marker}]" in call["text"])]

    def assert_recorded_name(self, marker, expected):
        calls = self.file_calls(marker)
        self.assertTrue(calls, f"no Detection file call for {marker}")
        self.assertEqual({call["source"].get("filename") for call in calls}, {expected}, marker)
        whole = [call for call in calls if "#" not in call["request_id"]]
        self.assertEqual(len(whole), 1)                                  # 파일 전체 검사 1번(+ 칸 검사)
        events = [e for e in self.events if any(f"[{marker}]" in (c.get("content") or "") for c in e["contents"])]
        self.assertEqual([e["contents"][0]["filename"] for e in events], [expected])

    def assert_log_clean(self, *values):
        text = self.log.getvalue()
        self.assertIsNone(NAME_RE.search(text), "file name leaked into the gateway log")
        for line in text.splitlines():
            if line.startswith(("[CHATGPT-FILE-NAME]", "[CHATGPT-FILE-SHAPE]", "Filename:")):
                for value in values:
                    self.assertNotIn(value, line)
                self.assertNotIn("FAKE-SIGNATURE", line)


# ------------------------------------------------------------------ 1. 예약 → 원본 PUT → 완료

class ReservationThenPutTests(NameFlowBase):
    VARIANTS = {   # 이름 키 모양(대소문자·'_' 무시) + 그 밖 칸
        "file_name": lambda name: {"file_name": name, "file_size": 1234, "use_case": "multimodal"},
        "fileName": lambda name: {"fileName": name, "fileSize": 1234, "useCase": "multimodal"},
        "filename": lambda name: {"filename": name, "file_size": 1234},
        "name": lambda name: {"name": name, "size": 1234, "use_case": "multimodal"},
        "FILE-NAME": lambda name: {"FILE-NAME": name, "file_size": 1234},
        "nested.file.name": lambda name: {"file": {"name": name, "size": 1234}, "use_case": "multimodal"},
        "nested.files[0].file_name": lambda name: {"files": [{"file_name": name, "file_size": 1234}]},
    }

    def test_each_name_key_variant_reaches_detection_and_the_event(self):
        for index, (variant, make) in enumerate(self.VARIANTS.items()):
            with self.subTest(variant):
                fid, name, marker = file_id(300 + index), f"가짜 보고서 {index}.docx", f"V{index}"
                created = self.reserve(make(name), new_response(fid))
                self.assertEqual(created.metadata["gw_chatgpt_reservation"]["name_count"], 1)
                flow = self.put(fid, doc(marker))
                self.assertIsNone(flow.response)
                self.assert_recorded_name(marker, name)
                done = self.finish(claim_and_finish_req(fid, len(doc(marker))))
                self.assertIsNone(done.response)
        self.assert_log_clean(*(file_id(300 + i) for i in range(len(self.VARIANTS))))

    def test_legacy_files_endpoint_without_trailing_slash(self):
        fid = file_id(320)
        self.reserve({"file_name": "가짜 명세.docx", "file_size": 10}, legacy_response(fid, "file-FakeLegacyId0001"),
                     path=LEGACY_PATH)
        self.put(fid, doc("L1"))
        self.assert_recorded_name("L1", "가짜 명세.docx")
        # 옛 모양 완료(process_upload_stream)도 그대로 통과
        done = self.finish(json_req("chatgpt.com", "/backend-api/files/process_upload_stream",
                                    {"file_id": "file-FakeLegacyId0001", "file_size": 10}))
        self.assertIsNone(done.response)

    def test_masked_upload_keeps_the_name_and_completion_size_is_rewritten(self):
        fid = file_id(330)
        original = doc("M1", f"주민등록번호 {RRN}")
        self.reserve({"file_name": "가짜 명단.docx", "file_size": len(original)}, new_response(fid))
        flow = self.put(fid, original)
        self.assertIsNone(flow.response)
        self.assertNotIn(RRN.encode(), flow.request.raw_content)           # 가렸다
        self.assert_recorded_name("M1", "가짜 명단.docx")
        done = self.finish(claim_and_finish_req(fid, len(original)))
        self.assertEqual(json.loads(done.request.get_text())["file_size"], len(flow.request.raw_content))
        self.assertEqual(self.reports[-1].result.action, "mask_full")
        self.assertEqual(self.reports[-1].context["fileId"], fid.replace("-", ""))

    def test_path_prefix_and_control_characters_are_dropped(self):
        fid = file_id(340)
        self.reserve({"file_name": "C:\\fakepath\\가짜\t계약서.docx"}, new_response(fid))
        self.put(fid, doc("P1"))
        self.assert_recorded_name("P1", "가짜계약서.docx")

    def test_name_is_found_by_either_id_shape(self):
        fid = file_id(350)
        self.reserve({"file_name": "가짜 안내.docx"}, new_response(fid))
        canonical = fid.replace("-", "")
        self.assertEqual(gateway.CHATGPT_FILE_META.get(canonical), "가짜 안내.docx")
        self.assertEqual(gateway._chatgpt_file_name(fid), "가짜 안내.docx")
        self.assertEqual(gateway._chatgpt_file_name(reservation_id(fid)), "가짜 안내.docx")
        self.assertEqual(gateway._chatgpt_file_name(fid.upper()), "가짜 안내.docx")
        self.assertIsNone(gateway._chatgpt_file_name(file_id(351)))

    def test_retry_put_for_the_same_upload_url_keeps_the_name(self):
        fid = file_id(360)
        self.reserve({"file_name": "가짜 재시도.docx"}, new_response(fid))
        self.put(fid, doc("R1"))
        self.put(fid, doc("R1"))
        self.assertEqual({c["source"].get("filename") for c in self.file_calls("R1")}, {"가짜 재시도.docx"})


# ------------------------------------------------------------------ 2. 잇지 않는 경우(번호로 기록)

class NotLinkedTests(NameFlowBase):
    def fallback(self, fid):
        return f"{fid}.docx"

    def test_put_without_reservation_falls_back_to_the_id(self):
        fid = file_id(400)
        self.put(fid, doc("N0"))
        self.assert_recorded_name("N0", self.fallback(fid))
        self.assertIn("Filename: (metadata not resolved)", self.log.getvalue())

    def test_two_names_in_one_reservation_are_not_linked(self):
        fid = file_id(401)
        self.reserve({"files": [{"file_name": "가짜 하나.docx"}, {"file_name": "가짜 둘.docx"}]}, new_response(fid))
        self.put(fid, doc("N1"))
        self.assert_recorded_name("N1", self.fallback(fid))
        self.assertIn('"name_count":2', self.log.getvalue())

    def test_two_upload_urls_in_one_response_are_not_linked(self):
        a, b = file_id(402), file_id(403)
        self.reserve({"file_name": "가짜 묶음.docx"},
                     {"uploads": [new_response(a), new_response(b)]})
        self.put(a, doc("N2"))
        self.assert_recorded_name("N2", self.fallback(a))
        self.assertIn('"raw_url_count":2', self.log.getvalue())

    def test_failed_reservation_response_is_not_linked(self):
        fid = file_id(404)
        self.reserve({"file_name": "가짜 실패.docx"}, new_response(fid), status=429)
        self.put(fid, doc("N3"))
        self.assert_recorded_name("N3", self.fallback(fid))

    def test_name_without_a_dot_is_not_a_file_name(self):
        fid = file_id(405)
        self.reserve({"name": "multimodal", "file_size": 3}, new_response(fid))
        self.put(fid, doc("N4"))
        self.assert_recorded_name("N4", self.fallback(fid))

    def test_completion_bodies_do_not_start_a_reservation(self):
        for path in (f"{RESERVE_PATH}/{reservation_id(file_id(406))}/claim_and_finish",
                     "/backend-api/files/process_upload_stream"):
            with self.subTest(path):
                flow = self.reserve({"file_name": "가짜 완료.docx", "file_size": 1}, new_response(file_id(406)),
                                    path=path)
                self.assertNotIn("gw_chatgpt_reservation", flow.metadata)
        self.assertIsNone(gateway._chatgpt_file_name(file_id(406)))


# ------------------------------------------------------------------ 3. multipart

class MultipartNameTests(NameFlowBase):
    def multipart_flow(self, content, filename, path="/backend-api/files/upload"):
        body, ctype = multipart(content, filename)
        req = tutils.treq(host="chatgpt.com", port=443, scheme=b"https", method=b"POST", path=path.encode(),
                          content=body, headers=((b"content-type", ctype),))
        flow = tflow.tflow(req=req)
        with contextlib.redirect_stdout(self.log):
            run_hook(gateway.request(flow))
        return flow

    def test_part_filename_is_recorded(self):
        self.multipart_flow(doc("U1"), "가짜 업로드.docx")
        self.assert_recorded_name("U1", "가짜 업로드.docx")

    def test_blob_part_uses_the_name_remembered_for_the_path_id(self):
        fid = file_id(500)
        self.reserve({"file_name": "가짜 블롭.docx"}, {"file_id": reservation_id(fid)})   # 주소 없이 번호 하나
        self.multipart_flow(doc("U2"), "blob", path=f"/backend-api/files/{reservation_id(fid)}/upload")
        self.assert_recorded_name("U2", "가짜 블롭.docx")

    def test_blob_part_without_a_remembered_name_stays_as_before(self):
        self.multipart_flow(doc("U3"), "blob", path=f"/backend-api/files/{reservation_id(file_id(501))}/upload")
        self.assert_recorded_name("U3", "blob")


# ------------------------------------------------------------------ 4. 동시 업로드·상한·로그

class ConcurrencyAndLogTests(NameFlowBase):
    def test_parallel_uploads_on_the_worker_pool_keep_their_own_names(self):
        uploads = {file_id(600 + i): (f"가짜 동시 {i}.docx", f"C{i}") for i in range(10)}
        for fid, (name, _) in uploads.items():
            self.reserve({"file_name": name, "file_size": 1}, new_response(fid))
        flows = [flow_of(put_req(fid, doc(marker))) for fid, (_, marker) in reversed(list(uploads.items()))]

        async def all_puts():
            await asyncio.gather(*(gateway.request(flow) for flow in flows))
        with contextlib.redirect_stdout(self.log):
            asyncio.run(all_puts())
        self.assertTrue(all("gw_file_queue_wait_ms" in flow.metadata for flow in flows))   # 작업 스레드에서
        for fid, (name, marker) in uploads.items():
            self.assert_recorded_name(marker, name)
        self.assert_log_clean(*uploads)

    def test_reservations_and_puts_interleaved_from_threads(self):
        errors, barrier = [], threading.Barrier(6)

        def one(i):
            try:
                barrier.wait()
                fid = file_id(700 + i)
                self.reserve({"fileName": f"가짜 스레드 {i}.docx"}, new_response(fid), peer=("192.0.2.30", 51000 + i))
                self.put(fid, doc(f"T{i}"), peer=("192.0.2.30", 52000 + i))
            except Exception as exc:
                errors.append(repr(exc))
        threads = [threading.Thread(target=one, args=(i,)) for i in range(6)]
        with contextlib.redirect_stdout(self.log):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(120)
        self.assertEqual(errors, [])
        for i in range(6):
            self.assert_recorded_name(f"T{i}", f"가짜 스레드 {i}.docx")

    def test_remembered_names_are_bounded(self):
        with mock.patch.object(gateway, "CHATGPT_FILE_META_MAX", 50):
            for i in range(120):
                gateway._remember_chatgpt_file_name([file_id(800 + i)], f"가짜 {i}.docx")
            self.assertEqual(len(gateway.CHATGPT_FILE_META), 50)
            self.assertIsNone(gateway._chatgpt_file_name(file_id(800)))
            self.assertEqual(gateway._chatgpt_file_name(file_id(919)), "가짜 119.docx")

    def test_structure_line_has_key_names_types_and_lengths_only(self):
        fid = file_id(900)
        name = "가짜 구조.docx"
        self.reserve({"file_name": name, "file_size": 77, "use_case": "multimodal", "reset_rate_limits": False},
                     new_response(fid))
        lines = [line for line in self.log.getvalue().splitlines() if line.startswith("[CHATGPT-FILE-SHAPE] ")]
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0].split(" ", 1)[1])
        self.assertEqual(record["path"], RESERVE_PATH)
        self.assertEqual(record["status"], 200)
        self.assertEqual(record["request"]["shape"], {"file_name": f"str:{len(name)}", "file_size": "num",
                                                      "use_case": "str:10", "reset_rate_limits": "bool"})
        self.assertEqual(sorted(record["response"]["shape"]), ["reservation_id", "status", "upload_url"])
        self.assertTrue(all(str(v).startswith("str:") for v in record["response"]["shape"].values()))
        result = [line for line in self.log.getvalue().splitlines() if line.startswith("[CHATGPT-FILE-NAME] ")]
        self.assertEqual(json.loads(result[0].split(" ", 2)[2]), {
            "status": 200, "name_found": True, "name_key": "file_name", "name_count": 1,
            "id_fields": ["reservation_id"], "raw_url_count": 1, "linked": True})
        self.assert_log_clean(fid, fid.replace("-", ""), reservation_id(fid))

    def test_structure_line_hides_keys_that_look_like_values(self):
        self.reserve({"가짜 이름.docx": {"size": 1}}, new_response(file_id(901)))
        line = next(line for line in self.log.getvalue().splitlines() if line.startswith("[CHATGPT-FILE-SHAPE] "))
        self.assertIn('"<map:1>"', line)
        self.assert_log_clean()

    def test_structure_lines_are_rate_limited_and_can_be_turned_off(self):
        with mock.patch.object(gateway, "CHATGPT_FILE_SHAPE_PER_HOUR", 3):
            gateway._chatgpt_file_shape_window[:] = [0.0, 0]
            for i in range(5):
                self.reserve({"file_name": f"가짜 {i}.docx"}, new_response(file_id(910 + i)))
        self.assertEqual(self.log.getvalue().count("[CHATGPT-FILE-SHAPE]"), 3)
        self.assertEqual(self.log.getvalue().count("[CHATGPT-FILE-NAME]"), 5)        # 결과 줄은 늘
        self.assertEqual(gateway._chatgpt_file_name(file_id(914)), "가짜 4.docx")     # 잇기는 상한과 무관
        self.log = io.StringIO()
        with mock.patch.dict("os.environ", {"GATEWAY_LOG_CHATGPT_FILE_SHAPE": "0"}):
            self.reserve({"file_name": "가짜 끔.docx"}, new_response(file_id(920)))
        self.assertNotIn("[CHATGPT-FILE-SHAPE]", self.log.getvalue())

    def test_unreadable_response_does_not_break_the_response_hook(self):
        flow = flow_of(json_req("chatgpt.com", RESERVE_PATH, {"file_name": "가짜 깨짐.docx"}))
        with contextlib.redirect_stdout(self.log):
            run_hook(gateway.request(flow))
            flow.response = tutils.tresp(status_code=200, content=b"\xff\xfe not json",
                                         headers=((b"content-type", b"application/json"),))
            gateway.response(flow)
        self.assertIn('"linked":false', self.log.getvalue())
        self.assertNotIn("link failed", self.log.getvalue())


# ------------------------------------------------------------------ 5. 실제 mitmproxy(DumpMaster)

class RecordingDetection:
    """가짜 Detection(모두 허용). 파일 검사 요청마다 (request_id, source.filename, 글자)를 남긴다."""

    def __init__(self):
        self.calls, self.lock = [], threading.Lock()
        rig = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
                source = body.get("source") or {}
                if source.get("content_type") == "file":
                    with rig.lock:
                        rig.calls.append((str(body.get("request_id")), source.get("filename"),
                                          body.get("normalized_text") or ""))
                data = json.dumps({
                    "blocked": False, "reason": "fake allow", "request_id": body.get("request_id"),
                    "decided_by": "none", "pii_hits": None, "mask_spans": [], "findings": [], "masked_text": None,
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


class ChatGPTUpstreamRig(ProxyRig):
    """ProxyRig(DumpMaster + gateway) + ChatGPT처럼 답하는 가짜 upstream: 예약 → upload_url, PUT·완료 → 200."""

    def __init__(self, test, detection):
        super().__init__(test, detection)
        self.upstream.shutdown()
        self.upstream.server_close()
        rig, counter, lock = self, [0], threading.Lock()
        self.issued = {}

        class Upstream(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _take(self):
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                path = self.path.split("?", 1)[0]
                rig.received.append((self.command, path, body))
                payload = {}
                if self.command == "POST" and path in (RESERVE_PATH, LEGACY_PATH):
                    with lock:
                        counter[0] += 1
                        fid = file_id(1000 + counter[0])
                    rig.issued[fid] = json.loads(body)
                    payload = (new_response(fid) if path == RESERVE_PATH
                               else legacy_response(fid, f"file-FakeLegacy{counter[0]:04d}"))
                elif self.command == "POST":
                    payload = {"status": "success"}
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

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
        self.addons = (Redirect(), self.addons[1])

    def exchange(self, method, url, body, content_type):
        """call()과 같되 응답 본문도 돌려준다."""
        import http.client
        host = urllib.parse.urlsplit(url).hostname
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.request(method, url, body=body, headers={"Host": host, "Content-Type": content_type,
                                                           "Connection": "close"})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()


class ProxyReservationTests(unittest.TestCase):
    def setUp(self):
        gateway.CHATGPT_FILE_META.clear()
        gateway.CHATGPT_SANITIZED_FILE_SIZE.clear()
        gateway._dedupe_seen.clear()
        gateway._chatgpt_file_shape_window[:] = [0.0, 0]
        for patcher in (mock.patch.object(gateway, "report_dashboard_event", lambda *a, **k: None),):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_reservation_put_completion_through_mitmproxy_six_at_once(self):
        bodies = [   # (예약 경로, 요청 JSON 만들기, 완료 만들기)
            (RESERVE_PATH, lambda n: {"file_name": n, "file_size": 1, "use_case": "multimodal"}),
            (RESERVE_PATH, lambda n: {"fileName": n, "fileSize": 1}),
            (RESERVE_PATH, lambda n: {"filename": n, "file_size": 1}),
            (RESERVE_PATH, lambda n: {"name": n, "size": 1}),
            (RESERVE_PATH, lambda n: {"file": {"file_name": n}, "use_case": "multimodal"}),
            (LEGACY_PATH, lambda n: {"file_name": n, "file_size": 1}),
        ]
        detection = RecordingDetection()
        results, errors = {}, []
        with ChatGPTUpstreamRig(self, detection) as rig:
            barrier = threading.Barrier(len(bodies))

            def one(i, path, make):
                try:
                    name, content = f"가짜 프록시 {i}.docx", doc(f"X{i}")
                    barrier.wait()
                    status, raw = rig.exchange("POST", f"http://chatgpt.com{path}",
                                               json.dumps(make(name), ensure_ascii=False).encode(), "application/json")
                    reply = json.loads(raw)
                    target = urllib.parse.urlsplit(reply["upload_url"])
                    put_status, _ = rig.exchange("PUT", f"http://{target.hostname}{target.path}?{target.query}",
                                                 content, "application/octet-stream")
                    if path == RESERVE_PATH:
                        done = rig.exchange("POST", f"http://chatgpt.com{RESERVE_PATH}/{reply['reservation_id']}"
                                                    "/claim_and_finish", json.dumps({"file_size": len(content)}).encode(),
                                            "application/json")
                    else:
                        done = rig.exchange("POST", "http://chatgpt.com/backend-api/files/process_upload_stream",
                                            json.dumps({"file_id": reply["file_id"], "file_size": len(content)}).encode(),
                                            "application/json")
                    results[i] = (status, put_status, done[0], name, content)
                except Exception as exc:
                    errors.append(repr(exc))
            threads = [threading.Thread(target=one, args=(i, path, make)) for i, (path, make) in enumerate(bodies)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(rig.errors, [])
        log = rig.out.getvalue()
        for i, (status, put_status, done_status, name, content) in results.items():
            with self.subTest(i):
                self.assertEqual((status, put_status, done_status), (200, 200, 200))
                calls = [c for c in detection.calls if f"[X{i}]" in c[2]]
                self.assertTrue(calls)
                self.assertEqual({filename for _, filename, _ in calls}, {name})       # 대시보드 기록 이름 = Detection에 간 이름
                self.assertEqual(len([c for c in calls if "#" not in c[0]]), 1)
                self.assertIn(("PUT", content), [(m, b) for m, p, b in rig.received if m == "PUT"])
        self.assertEqual(len(results), len(bodies))
        self.assertEqual(log.count('"linked":true'), len(bodies))
        self.assertIsNone(NAME_RE.search(log), "file name leaked into the gateway log")


if __name__ == "__main__":
    unittest.main()
