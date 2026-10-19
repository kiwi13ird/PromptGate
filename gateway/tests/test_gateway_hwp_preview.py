"""미리보기가 본문과 다른 HWP·HWPX 검사·가림 (2026-10-14). 가짜 값만 쓴다.

10/14 21:22 KST Claude에 올린 HWP(44,544바이트)가 hwp_preview_mismatch → 검사 불가(other) → 403
"이 파일 형식은 내용을 검사할 수 없어…"로 막혔다. 본문만 바꾸고 미리보기(PrvText)를 다시 만들지 않은 파일이었다.
같은 분류기를 쓰는 ChatGPT도 같은 결과다(ChatGPT HWP 업로드 로그는 10/11 이후 0건).
바꾼 규칙: 불일치면 미리보기 글자를 검사 글자 끝과 칸 목록(f:0:{kind}:side:preview0)에 넣는다.
  - 깨끗하면 원본 그대로 전달, 본문·미리보기에 가릴 값이 있으면 본문 가림 + 미리보기 통째로 지움 → 재검사 → 전달
  - 미리보기에만 가릴 값이 있으면 문단은 그대로, 미리보기만 지움
1. 분류·칸 목록·가림 모듈  2. 실제 request() 훅 × Claude multipart·ChatGPT 원본 PUT·ChatGPT multipart (가짜 Detection)
실행: python -m unittest tests.test_gateway_hwp_preview -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import unittest

from tests.test_gateway_hwp_mask import (  # noqa: E402  (임시 폴더·환경 변수 준비도 이 모듈이 한다)
    FILE_ID, HWP_RRN, LIMIT, PHONE, RRN, FlowBase, hwp_doc, hwpx_doc, multipart_body, multipart_files, reread,
    results_for, rrn_rule, run_hook, tflow, tutils,
)

import gateway  # noqa: E402
import gateway_file_classes  # noqa: E402
from gateway_file_classes import inspect_upload  # noqa: E402
from signature_detector.document import hwp_mask, hwp_segments  # noqa: E402


def preview_extra_text(*args):
    # 수정 전 코드로 돌릴 때도 모듈은 불러지게(그 시험만 실패)
    return gateway_file_classes.preview_extra_text(*args)

TEMPLATE_PREVIEW = "프로젝트 중간점검 보고서(가짜)\r\n<현재 진행 단계><□ 데이터 수집 □ 전처리 □ 모델 학습>\r\n"


def edited_hwp():
    """사용자가 올린 파일 모양: 양식 HWP 본문 칸을 같은 길이 값으로 덮어쓰고 미리보기는 옛 양식 그대로."""
    return hwp_doc(body=["프로젝트 중간점검 보고서(가짜)"], rows=[("현재 진행 단계", f"{RRN} □ 모델 학습")],
                   prvtext=TEMPLATE_PREVIEW)


def edited_hwpx():
    return hwpx_doc(body=["프로젝트 중간점검 보고서(가짜)"], rows=[("현재 진행 단계", f"{RRN} □ 모델 학습")],
                    prvtext=TEMPLATE_PREVIEW)


def preview_only_pii(kind):
    """본문은 깨끗하고 미리보기(옛 판)에만 주민번호."""
    build = hwp_doc if kind == "hwp" else hwpx_doc
    return build(body=["가짜 회의록", "다음 회의는 목요일"], prvtext=f"가짜 회의록\r\n<주민등록번호><{RRN}>\r\n")


def stale_clean(kind):
    build = hwp_doc if kind == "hwp" else hwpx_doc
    return build(body=["새 판 회의록(가짜)"], prvtext="옛 판 회의록 제목(가짜)\r\n")


def classify(data):
    return inspect_upload(data, max_bytes=LIMIT, max_chars=80645, deadline=1e18)


def preview_blank(doc):
    return doc.preview_text().replace("\x00", "").strip() == ""


# ------------------------------------------------------------------ 1. 모듈

class PreviewClassifyTests(unittest.TestCase):
    def test_mismatched_preview_is_inspected_with_its_text_at_the_end(self):
        for kind, data in (("hwp", edited_hwp()), ("hwpx", edited_hwpx())):
            with self.subTest(kind):
                result = classify(data)
                self.assertEqual((result.kind, result.group, result.detail), (kind, None, f"{kind}_preview_extra"))
                lines = result.text.split("\n")
                self.assertEqual(lines[-2:], ["프로젝트 중간점검 보고서(가짜)",
                                              "현재 진행 단계 | □ 데이터 수집 □ 전처리 □ 모델 학습"])
                self.assertIn(f"현재 진행 단계 | {RRN} □ 모델 학습", lines)      # 본문은 그대로 앞에
                body = "\n".join(reread(data).lines())
                self.assertTrue(result.text.startswith(body))

    def test_matching_preview_adds_nothing(self):
        data = hwp_doc(body=["가짜 회의록", "다음 회의는 목요일"], prvtext="가짜 회의록\r\n다음 회의")
        result = classify(data)
        self.assertEqual((result.group, result.detail), (None, "hwp"))
        self.assertEqual(result.text, "\n".join(reread(data).lines()))
        self.assertEqual(preview_extra_text("", "본문"), "")

    def test_preview_cells_become_pipe_separated_lines(self):
        text = preview_extra_text("<성명><김가짜>\r\n<주민등록번호><%s>\r\n머리 줄\r\n\x00" % RRN, "다른 본문")
        self.assertEqual(text, f"성명 | 김가짜\n주민등록번호 | {RRN}\n머리 줄")


class PreviewSegmentTests(unittest.TestCase):
    def segments(self, kind, data):
        return hwp_segments.extract_segments(hwp_segments.read_document(data), kind)

    def test_preview_cell_only_when_the_preview_differs(self):
        for kind in ("hwp", "hwpx"):
            with self.subTest(kind):
                last = self.segments(kind, preview_only_pii(kind))[-1]
                self.assertEqual(last.segment_id, f"f:0:{kind}:side:preview0")
                self.assertEqual(last.text, f"가짜 회의록\n주민등록번호 | {RRN}")
                same = hwp_doc(body=["가짜 회의록"], prvtext="가짜 회의록\r\n") if kind == "hwp" else \
                    hwpx_doc(body=["가짜 회의록"], prvtext="가짜 회의록\r\n")
                self.assertFalse(any("preview" in s.segment_id for s in self.segments(kind, same)))

    def test_preview_only_mask_blanks_the_preview_and_keeps_the_paragraphs(self):
        for kind in ("hwp", "hwpx"):
            with self.subTest(kind):
                data = preview_only_pii(kind)
                art = sanitize_with(kind, data)
                self.assertNotEqual(art.sanitized_bytes, data)
                before, after = reread(data), reread(art.sanitized_bytes)
                self.assertEqual(after.lines(), before.lines())
                self.assertTrue(preview_blank(after))
                self.assertEqual((art.verify.text, art.verify.spans), ("\n".join(after.lines()), ()))
                if kind == "hwp":
                    self.assertEqual(len(art.sanitized_bytes), len(data))
                    old, new = hwp_mask._all_streams(data), hwp_mask._all_streams(art.sanitized_bytes)
                    self.assertEqual({n for n in old if old[n] != new[n]}, {"PrvText"})
                self.assertNotIn(RRN.encode("utf-16-le"), art.sanitized_bytes)
                self.assertNotIn(RRN.encode(), art.sanitized_bytes)
                # 가린 파일은 미리보기가 비어 다시 분류해도 불일치가 아니다
                self.assertEqual(classify(art.sanitized_bytes).detail, kind)

    def test_body_and_preview_mask_together(self):
        art = sanitize_with("hwp", edited_hwp())
        after = reread(art.sanitized_bytes)
        self.assertIn(f"현재 진행 단계 | {HWP_RRN} □ 모델 학습", after.lines())
        self.assertTrue(preview_blank(after))

    def test_clean_stale_preview_is_returned_unchanged(self):
        for kind in ("hwp", "hwpx"):
            with self.subTest(kind):
                data = stale_clean(kind)
                art = sanitize_with(kind, data)
                self.assertEqual(art.sanitized_bytes, data)
                self.assertIsNone(art.verify)


def sanitize_with(kind, data):
    doc = hwp_segments.read_document(data)
    segments = hwp_segments.extract_segments(doc, kind)
    return hwp_segments.sanitize_document(kind, data, results_for(segments, rrn_rule()), doc=doc, segments=segments)


# ------------------------------------------------------------------ 2. 실제 request() 훅

class PreviewFlowMatrix:
    """세 경로 공통. 하위 클래스가 send(data, filename)·forwarded(flow)를 정한다. 기본 설정: 검사 불가(other) = 차단."""

    def test_user_file_shape_is_masked_and_forwarded_instead_of_403(self):
        for kind, data in (("hwp", edited_hwp()), ("hwpx", edited_hwpx())):
            with self.subTest(kind):
                self.reports.clear()
                self.detection.detects.clear()
                flow = self.send(data, f"중간점검.{kind}")
                self.assertIsNone(flow.response)                    # 이전: 403 file_uninspectable_other
                out = reread(self.forwarded(flow))
                self.assertNotIn(RRN, "\n".join(out.lines()))
                self.assertTrue(preview_blank(out))
                self.assertNotIn(RRN.encode("utf-16-le"), flow.request.raw_content)
                report, = self.reports
                self.assertEqual((report.result.action, report.applied, report.result.reason_code),
                                 ("mask_full", True, "pii"))
                whole = next(d for d in self.detection.detects if "#" not in d["request_id"])
                self.assertIn("□ 데이터 수집 □ 전처리", whole["normalized_text"])   # 미리보기 글자도 검사
                self.assertTrue(any(d["request_id"].endswith(f"#f:0:{kind}:side:preview0") for d in self.detection.detects))
                self.assertEqual(len(self.verify_ids()), 2)

    def test_pii_only_in_the_preview_is_masked(self):
        for kind in ("hwp", "hwpx"):
            with self.subTest(kind):
                self.reports.clear()
                data = preview_only_pii(kind)
                flow = self.send(data, f"회의록.{kind}")
                self.assertIsNone(flow.response)
                out = reread(self.forwarded(flow))
                self.assertEqual(out.lines(), reread(data).lines())           # 문단은 그대로
                self.assertTrue(preview_blank(out))
                self.assertNotIn(RRN.encode("utf-16-le"), flow.request.raw_content)
                self.assertNotIn(RRN.encode(), flow.request.raw_content)
                report, = self.reports
                self.assertEqual((report.result.action, report.applied), ("mask_full", True))

    def test_clean_stale_preview_is_forwarded_unchanged(self):
        for kind in ("hwp", "hwpx"):
            with self.subTest(kind):
                self.reports.clear()
                data = stale_clean(kind)
                flow = self.send(data, f"회의록.{kind}")
                self.assertIsNone(flow.response)
                self.assertEqual(self.forwarded(flow), data)
                self.assertEqual([r.result.action for r in self.reports], ["allow"])
                self.assertNotEqual(self.reports[0].result.reason_code, "file_uninspectable_other")

    def test_other_allowed_setting_no_longer_lets_it_through_unchecked(self):
        # 10/14 21:23 운영: 검사 불가 허용으로 바꾼 뒤 같은 파일이 검사 없이 나갔다(ALLOW file_uninspectable_other)
        self.use_settings(other="allow")
        flow = self.send(edited_hwp(), "중간점검.hwp")
        self.assertIsNone(flow.response)
        self.assertNotIn(RRN, "\n".join(reread(self.forwarded(flow)).lines()))
        self.assertEqual(self.reports[0].result.action, "mask_full")

    def test_user_file_with_phone_shape_value(self):
        # 실제 파일처럼 다른 값(전화번호 모양)도 본문에 있지만 가짜 Detection은 주민번호만 가린다 - 전화번호 칸은 그대로
        data = hwp_doc(body=["프로젝트 중간점검 보고서(가짜)"], rows=[("현재 진행 단계", f"{PHONE}리 {RRN}")],
                       prvtext=TEMPLATE_PREVIEW)
        flow = self.send(data, "a.hwp")
        self.assertIsNone(flow.response)
        lines = reread(self.forwarded(flow)).lines()
        self.assertIn(f"현재 진행 단계 | {PHONE}리 {HWP_RRN}", lines)


class ClaudePreviewFlowTests(PreviewFlowMatrix, FlowBase):
    target_llm = "Claude"
    boundary = "----claudehwppreviewboundary"

    def send(self, content, filename):
        req = tutils.treq(host="claude.ai", port=443, scheme=b"https", method=b"POST",
                          path=b"/api/00000000-0000-4000-8000-00000000c1a0/upload",
                          content=multipart_body(self.boundary, [(filename, "application/x-hwp", content)]),
                          headers=((b"content-type", f"multipart/form-data; boundary={self.boundary}".encode()),))
        flow = tflow.tflow(req=req)
        run_hook(gateway.request(flow))
        return flow

    def forwarded(self, flow):
        payload, = multipart_files(flow.request.raw_content, self.boundary)
        return payload


class ChatGptPutPreviewFlowTests(PreviewFlowMatrix, FlowBase):
    def send(self, content, filename):
        gateway.CHATGPT_FILE_META[FILE_ID] = filename
        req = tutils.treq(host="sdmntprkoreacentral.oaiusercontent.com", port=443, scheme=b"https", method=b"PUT",
                          path=f"/files/{FILE_ID}/raw?se=2026-10-14&sig=fake".encode(), content=content,
                          headers=((b"content-type", b"application/octet-stream"),))
        flow = tflow.tflow(req=req)
        run_hook(gateway.request(flow))
        return flow

    def forwarded(self, flow):
        return flow.request.raw_content


class ChatGptMultipartPreviewFlowTests(PreviewFlowMatrix, FlowBase):
    boundary = "----gwhwppreviewboundary"

    def send(self, content, filename):
        req = tutils.treq(host="chatgpt.com", port=443, scheme=b"https", method=b"POST",
                          path=b"/backend-api/files/upload", content=multipart_body(
                              self.boundary, [(filename, "application/octet-stream", content)]),
                          headers=((b"content-type", f"multipart/form-data; boundary={self.boundary}".encode()),))
        flow = tflow.tflow(req=req)
        run_hook(gateway.request(flow))
        return flow

    def forwarded(self, flow):
        payload, = multipart_files(flow.request.raw_content, self.boundary)
        return payload


if __name__ == "__main__":
    unittest.main()
