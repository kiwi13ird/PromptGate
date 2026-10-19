"""HWP·HWPX 칸 검사·가림 (2026-10-11, masking-design/SPEC.md §4.1·§4.4, 3단계 Gateway).

칸 = hwpdoc 문단(글자 있는 것) + 부가 글자(수식·필드 명령·요약 정보·개체 설명문·HWPX 메타·바탕쪽 등, 검사만).
  칸 번호  f:0:{hwp|hwpx}:{locator} (DOCX 문법), 부가 글자는 f:0:{kind}:side:{종류}{N}
  미리보기 칸(2026-10-14) f:0:{kind}:side:preview0 - 미리보기가 본문과 다를 때만. 가림이면 미리보기를 통째로 지움
  이름표   병합 범위로 만든 격자에서 (행, 열-1)을 덮는 칸(자기 자신 제외), 없으면 (0, 열)을 덮는 칸의 글자가
           canonical_label이면 그 칸 문단의 문맥(DOCX file_segments.extract_docx_segments와 같은 규칙. python-docx는 병합 칸을
           반복해 같은 효과). 격자 칸 수가 구조 예산(max_decompressed // 64, hwpdoc과 같은 규칙)을 넘는 문서는 정확한 주소만 본다
가림은 replacement가 있는 finding만(정책 ALLOW 적중은 그대로). HWPX는 표시 치환(hwpx_mask), HWP는 같은 길이(hwp_mask:
완전 가림은 '[유형]' + 공백, 들어가지 않으면 '*', 2026-10-12).
가린 뒤 hwpdoc으로 다시 읽어 확인하고(locator 목록·글자·부가 글자 같음, 미리보기 글자 없음) 재검사 글자와 바꾼 구간을 돌려준다
(Gateway가 _verify_masked로 Detection 재검사 - 바꾼 구간 안에 완전히 든 적중만 무시).
거절은 모두 MaskRefused(부가 글자 가림 요청·제어 글자·크기 못 맞춤·재현 실패 등).
hwpdoc·olefile은 HWP·HWPX를 가릴 때만 불러온다(gateway_runtime이 이 모듈을 함수 안에서 import).
"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from signature_detector.contextual_pii import canonical_label
from signature_detector.contracts import CheckableSegment, MaskRefused, SegmentResult, validate_segment_result
from signature_detector.document import hwpdoc
from signature_detector.document.file_segments import SanitizedArtifacts
from signature_detector.policy import PolicyAction

MAX_DECOMPRESSED = 20 * 1024 * 1024
_MASK = {PolicyAction.MASK_PARTIAL, PolicyAction.MASK_FULL}
# 미리보기 칸(2026-10-14): 본문과 다른 미리보기 글자. 대시보드는 'side:'로 시작하는 칸을 그리지 않는다(부가 글자와 같음).
# 가림 판정이면 문단은 바꾸지 않고 미리보기만 통째로 지운다(hwp_mask·hwpx_mask가 가릴 때 늘 하는 일)
PREVIEW_LOCATOR = "side:preview0"


@dataclass(frozen=True)
class HwpVerify:
    """재검사 입력: 가린 파일을 다시 뽑은 글자('\\n'.join(lines()))와 그 글자 좌표의 바꾼 구간."""

    text: str
    spans: tuple


def read_document(data: bytes, max_decompressed: int = MAX_DECOMPRESSED):
    return hwpdoc.read(data, max_decompressed=max_decompressed)


def _cell_labels(doc, max_items: int) -> dict[int, str]:
    """문단 번호 → 이름표 글자(명세 §4.1 격자 방식)."""
    cells: dict[tuple, list] = {}           # (표, 행, 열) → [행 병합, 열 병합, 문단 번호들]
    for pi, para in enumerate(doc.paragraphs):
        if para.cell is not None:
            tid, row, col, rowspan, colspan = para.cell
            cells.setdefault((tid, row, col), [rowspan, colspan, []])[2].append(pi)
    if not cells:
        return {}
    grid: dict[tuple, tuple] = {}
    left = max_items
    for key, (rowspan, colspan, _) in cells.items():
        rowspan, colspan = max(1, rowspan), max(1, colspan)
        left -= rowspan * colspan
        if left < 0:
            grid = {key: key for key in cells}     # 비정상으로 큰 병합: 정확한 주소만
            break
        tid, row, col = key
        for r in range(row, row + rowspan):
            for c in range(col, col + colspan):
                grid.setdefault((tid, r, c), key)

    def cell_text(key):
        return "\n".join(doc.paragraphs[pi].text for pi in cells[key][2]).strip()

    labels: dict[int, str] = {}
    for key, (_, _, paras) in cells.items():
        tid, row, col = key
        label = None
        for probe, needed in (((tid, row, col - 1), col > 0), ((tid, 0, col), row > 0)):
            if label or not needed:
                continue
            owner = grid.get(probe)
            if owner is not None and owner != key:
                candidate = cell_text(owner)
                if canonical_label(candidate):
                    label = candidate
        if label:
            for pi in paras:
                labels[pi] = label
    return labels


def preview_extra(doc) -> str:
    """본문과 다른 미리보기 글자(Gateway 분류 gateway_file_classes.preview_extra_text와 같은 규칙·같은 글자), 같으면 ''."""
    from gateway_file_classes import preview_extra_text  # noqa: PLC0415  (분류와 한 규칙만 쓴다)

    return preview_extra_text(doc.preview_text(), doc.paragraph_text())


def extract_segments(doc, kind: str, max_decompressed: int = MAX_DECOMPRESSED) -> list[CheckableSegment]:
    """칸 목록. 미리보기가 본문과 다르면(2026-10-14) 미리보기 칸(PREVIEW_LOCATOR)을 맨 뒤에 하나 더 둔다."""
    labels = _cell_labels(doc, max_decompressed // 64)
    segments = [CheckableSegment(f"f:0:{kind}:{para.locator}", "file", para.text, labels.get(pi), para.block_order)
                for pi, para in enumerate(doc.paragraphs) if para.text.strip()]
    segments += [CheckableSegment(f"f:0:{kind}:{side.locator}", "file", side.text)
                 for side in doc.side if side.text.strip()]
    extra = preview_extra(doc)
    if extra.strip():
        segments.append(CheckableSegment(f"f:0:{kind}:{PREVIEW_LOCATOR}", "file", extra))
    return segments


def _span(kind: str, finding) -> tuple:
    """HWPX (start, end, replacement) - 표시를 그대로 씀. HWP는 완전 가림 표시를 덧붙인다(hwp_mask.full_mask_token)."""
    if kind == "hwp":
        from signature_detector.document.hwp_mask import full_mask_token  # noqa: PLC0415

        return finding.start, finding.end, finding.replacement, full_mask_token(finding)
    return finding.start, finding.end, finding.replacement


def _edits(doc, kind: str, segments, results: list[SegmentResult]):
    """Detection 칸 판정 → ({문단 번호: [(start, end, replacement[, HWP 완전 가림 표시])]}, {문단 번호: masked_text},
    미리보기 칸 가림 여부)."""
    by_id = {segment.segment_id: segment for segment in segments}
    result_by_id = {result.segment_id: result for result in results}
    if len(by_id) != len(segments) or set(result_by_id) != set(by_id) or len(result_by_id) != len(results):
        raise ValueError(f"{kind.upper()} Detection results are missing, duplicated, or unexpected")
    para_by_locator = {para.locator: pi for pi, para in enumerate(doc.paragraphs)}
    prefix = f"f:0:{kind}:"
    edits: dict[int, list] = {}
    expected: dict[int, str] = {}
    preview_masked = False
    for segment_id, result in result_by_id.items():
        if result.action is PolicyAction.BLOCK_NOTIFY:
            raise PermissionError(f"{kind.upper()} blocked by Signature policy")
        if result.action not in _MASK:
            continue
        validate_segment_result(by_id[segment_id], result)
        locator = segment_id[len(prefix):]
        if locator == PREVIEW_LOCATOR:
            preview_masked = True                                  # 미리보기는 통째로 지운다(구간을 쓰지 않음)
            continue
        if locator.startswith("side:"):
            raise MaskRefused(f"{kind}_side_text_mask")         # 부가 글자는 검사만(가릴 자리가 없음)
        spans = sorted((_span(kind, f) for f in result.findings if f.replacement is not None), key=lambda s: s[:2])
        if not spans:
            raise MaskRefused(f"{kind}_mask_without_spans")
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise MaskRefused(f"{kind}_overlapping_spans")
        pi = para_by_locator[locator]
        edits[pi] = spans
        expected[pi] = result.masked_text
    return edits, expected, preview_masked


def _recheck(kind: str, masked: bytes, doc, new_texts: dict, marks: dict, max_decompressed: int) -> HwpVerify:
    """가린 바이트를 다시 읽어 확인(명세 §4.4)하고 재검사 글자·바꾼 구간을 만든다."""
    try:
        again = hwpdoc.read(masked, max_decompressed=max_decompressed)
    except hwpdoc.HwpError as exc:
        raise MaskRefused(f"{kind}_reparse_{type(exc).__name__}") from None
    if [p.locator for p in again.paragraphs] != [p.locator for p in doc.paragraphs]:
        raise MaskRefused(f"{kind}_reparse_locators")
    for pi, (before, after) in enumerate(zip(doc.paragraphs, again.paragraphs)):
        if after.text != new_texts.get(pi, before.text):
            raise MaskRefused(f"{kind}_reparse_text")
    if [(s.locator, s.text) for s in again.side] != [(s.locator, s.text) for s in doc.side]:
        raise MaskRefused(f"{kind}_reparse_side")
    if any(not char.isspace() and char != "\x00" for char in again.preview_text()):
        raise MaskRefused(f"{kind}_preview_not_blank")
    lines, spans = again.lines_with_spans(marks)
    return HwpVerify("\n".join(lines), tuple(spans))


def sanitize_document(kind: str, file_bytes: bytes, results: list[SegmentResult], *, doc=None, segments=None,
                      max_decompressed: int = MAX_DECOMPRESSED) -> SanitizedArtifacts:
    """칸 판정을 적용한 HWP·HWPX. 바꿀 칸이 없으면 원본 그대로(verify 없음). 검토용 사본은 만들지 않는다(review_bytes = 보낼 바이트).
    미리보기 칸만 가림이면(2026-10-14) 문단은 그대로 두고 미리보기 글자·그림만 지운 파일(verify 있음, 바꾼 구간 없음)."""
    started = perf_counter()
    if doc is None:
        doc = read_document(file_bytes, max_decompressed)
    if segments is None:
        segments = extract_segments(doc, kind, max_decompressed)
    edits, expected, preview_masked = _edits(doc, kind, segments, results)
    if not edits and not preview_masked:
        return SanitizedArtifacts(file_bytes, file_bytes, len(segments), (perf_counter() - started) * 1000)
    if kind == "hwpx":
        from signature_detector.document.hwpx_mask import mask_hwpx  # noqa: PLC0415

        masked, new_texts, marks = mask_hwpx(file_bytes, doc, edits, max_decompressed=max_decompressed)
        for pi, text in new_texts.items():
            if text != expected[pi]:
                # 구간 안 요소 글자(탭 등)를 남겨 Detection이 만든 글자와 다름 - 같은 결과를 보장할 수 없다
                raise MaskRefused("hwpx_masked_text_mismatch")
    elif kind == "hwp":
        from signature_detector.document.hwp_mask import mask_hwp  # noqa: PLC0415

        masked, new_texts, marks = mask_hwp(file_bytes, doc, edits, max_decompressed=max_decompressed)
    else:
        raise ValueError(f"unsupported HWP kind: {kind}")
    verify = _recheck(kind, masked, doc, new_texts, marks, max_decompressed)
    print(f"[HWP-MASK] kind={kind} paragraphs={len(edits)} spans={sum(len(s) for s in edits.values())} "
          f"preview_hit={int(preview_masked)} "
          f"bytes={len(file_bytes)}->{len(masked)} ms={(perf_counter() - started) * 1000:.1f}")
    return SanitizedArtifacts(masked, masked, len(segments), (perf_counter() - started) * 1000, verify)
