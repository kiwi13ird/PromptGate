"""event_adapter 테스트 - 실제 gateway.py가 만드는 Gateway Event 모양(§0.2 실측)을 그대로
입력으로 써서, content 키 유무에 따른 선택/스킵과 정규화까지 검증한다.
"""

from __future__ import annotations

from event_adapter import extract_checkable_text


def test_single_prompt_is_returned_normalized():
    event = {"contents": [{"type": "prompt", "content": "hello gateway"}]}
    assert extract_checkable_text(event) == "hello gateway"


def test_file_with_extracted_content_is_included():
    event = {"contents": [{"type": "file", "filename": "test.txt", "purpose": "user_data", "content": "회사 기밀 내용"}]}
    assert extract_checkable_text(event) == "회사 기밀 내용"


def test_file_reference_without_content_is_skipped():
    # /v1/responses에서 이전에 업로드한 파일을 file_id로만 참조하는 경우 - content가 없다.
    event = {"contents": [{"type": "file", "file_id": "file-abc123", "filename": "old.pdf"}]}
    assert extract_checkable_text(event) == ""


def test_image_content_is_skipped():
    event = {"contents": [{"type": "image", "content": {"type": "image_url", "image_url": "..."}}]}
    assert extract_checkable_text(event) == ""


def test_multiple_prompts_are_joined_with_newline():
    event = {
        "contents": [
            {"type": "prompt", "content": "첫 번째 문장"},
            {"type": "prompt", "content": "두 번째 문장"},
        ]
    }
    assert extract_checkable_text(event) == "첫 번째 문장\n두 번째 문장"


def test_mixed_prompt_and_unresolvable_file_reference_keeps_only_prompt():
    event = {
        "contents": [
            {"type": "prompt", "content": "이 파일 요약해줘"},
            {"type": "file", "file_id": "file-abc123", "filename": "old.pdf"},
        ]
    }
    assert extract_checkable_text(event) == "이 파일 요약해줘"


def test_empty_contents_returns_empty_string():
    assert extract_checkable_text({"contents": []}) == ""


def test_missing_contents_key_returns_empty_string():
    assert extract_checkable_text({}) == ""


def test_normalization_is_actually_applied():
    # normalizer.py 자체 관례대로 특수 유니코드는 리터럴이 아니라 \uXXXX로 명시한다.
    zero_width_space = "​"
    event = {"contents": [{"type": "prompt", "content": f"hello{zero_width_space}gateway"}]}
    assert extract_checkable_text(event) == "hellogateway"
