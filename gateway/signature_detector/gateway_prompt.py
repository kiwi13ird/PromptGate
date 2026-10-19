"""OpenAI Responses API prompt segment 추출과 안전한 재삽입."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from signature_detector.contracts import CheckableSegment, SegmentResult, validate_segment_result
from signature_detector.policy import PolicyAction


@dataclass(frozen=True)
class PromptBinding:
    segment: CheckableSegment
    source_path: tuple[str | int, ...]


def extract_openai_prompt_bindings(body: dict) -> list[PromptBinding]:
    bindings: list[PromptBinding] = []

    def add(text: str, path: tuple[str | int, ...]):
        if text.strip():
            bindings.append(PromptBinding(CheckableSegment(f"p:{len(bindings)}", "prompt", text), path))

    input_data = body.get("input")
    if isinstance(input_data, str):
        add(input_data, ("input",))
    elif isinstance(input_data, list):
        for item_index, item in enumerate(input_data):
            if isinstance(item, str):
                add(item, ("input", item_index))
                continue
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, str):
                add(content, ("input", item_index, "content"))
            elif isinstance(content, list):
                for content_index, content_item in enumerate(content):
                    if isinstance(content_item, dict) and content_item.get("type") == "input_text":
                        text = content_item.get("text")
                        if isinstance(text, str):
                            add(text, ("input", item_index, "content", content_index, "text"))
    return bindings


def _set_path(root: dict, path: tuple[str | int, ...], value: str) -> None:
    target = root
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def apply_openai_prompt_results(body: dict, bindings: list[PromptBinding], results: list[SegmentResult]) -> dict:
    """모든 결과를 검증한 뒤 복사본에 원자적으로 적용한다."""

    result_by_id = {result.segment_id: result for result in results}
    expected = {binding.segment.segment_id for binding in bindings}
    if set(result_by_id) != expected or len(result_by_id) != len(results):
        raise ValueError("Detection segment results are missing, duplicated, or unexpected")
    for binding in bindings:
        validate_segment_result(binding.segment, result_by_id[binding.segment.segment_id])
        if result_by_id[binding.segment.segment_id].action is PolicyAction.BLOCK_NOTIFY:
            raise PermissionError("prompt blocked by Signature policy")

    rewritten = deepcopy(body)
    for binding in bindings:
        result = result_by_id[binding.segment.segment_id]
        if result.action in {PolicyAction.MASK_PARTIAL, PolicyAction.MASK_FULL}:
            _set_path(rewritten, binding.source_path, result.masked_text)
    return rewritten
