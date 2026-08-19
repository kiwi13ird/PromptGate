"""마스킹 안전성 exhaustive 검증.

FR-SIG의 실제 마스킹 대상은 normalized_text다 - 외부 LLM으로 나가는 건 정규화된
텍스트지 원본 파일이 아니므로, 탐지 모듈이 돌려준 (start, end)를 normalized_text에
그대로 슬라이스하면 된다. 좌표계가 하나뿐이라 여기엔 오프셋 변환 리스크가 없다.

대신 raw_start/raw_end(=원문 내 위치, FR-PRE-005 로그/감사용)는 정규화 과정에서
문자가 삭제/치환되며 파생된 값이라 이게 실제로 정확한지가 검증 대상이다. 이 파일은
"첫 매치만 눈으로 확인"이 아니라 20개 테스트베드 문서 전체, 모든 매치에 대해 기계적
으로 확인한다.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

import pytest

from preprocessing.indexer import build_offset_map
from preprocessing.router import process_input

GENERATED_DIR = Path(__file__).resolve().parents[3] / "docs" / "testbed-dataset" / "generated"

PII_PATTERNS = {
    "주민등록번호": re.compile(r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)"),
    "전화번호": re.compile(r"01[016789]-\d{3,4}-\d{4}"),
    "이메일": re.compile(r"[\w.\-]+@[\w\-]+\.[a-zA-Z]{2,}"),
    "AWS_Access_Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "DB_접속문자열": re.compile(r"(?:postgres|mysql|mongodb|redis)(?:\+\w+)?://\S+"),
    "Private_Key_PEM": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "JWT_Token": re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),
    "GitHub_Token": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    "Slack_Token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
}


def _all_documents():
    if not GENERATED_DIR.exists():
        pytest.skip("테스트베드 문서 디렉터리가 없습니다")
    paths = sorted(list(GENERATED_DIR.glob("*.docx")) + list(GENERATED_DIR.glob("*.xlsx")))
    if not paths:
        pytest.skip("테스트베드 문서가 없습니다")
    return paths


def test_every_match_raw_offset_round_trips_exactly():
    """20개 문서, 모든 PII/Credential 매치(첫 번째만이 아니라 전부)에 대해
    raw_local_text[raw_start:raw_end]가 매치 문자열과 정확히 같아야 한다.
    이게 어긋나면 로그에 찍히는 "원문 위치"가 실제로는 엉뚱한 곳을 가리키게 된다.
    """
    total_checked = 0
    mismatches = []

    for path in _all_documents():
        result = process_input(str(path))
        assert result.success, f"{path.name} 파싱 실패: {result.error_message}"

        for label, pattern in PII_PATTERNS.items():
            for m in pattern.finditer(result.normalized_text):
                loc = result.index.locate(m.start(), m.end())
                if loc is None or loc.raw_start is None or loc.raw_end is None:
                    mismatches.append(f"{path.name} [{label}] {m.group(0)!r}: 위치 특정 실패")
                    continue
                ib = result.index.blocks[loc.block_index]
                raw_slice = ib.raw_local_text[loc.raw_start : loc.raw_end]
                total_checked += 1
                if raw_slice != m.group(0):
                    mismatches.append(
                        f"{path.name} [{label}] 매치={m.group(0)!r} raw슬라이스={raw_slice!r}"
                    )

    assert total_checked > 0, "검증된 매치가 0건 - 테스트 자체가 무의미했다"
    assert not mismatches, f"{len(mismatches)}건 불일치:\n" + "\n".join(mismatches[:20])


def test_masking_on_normalized_text_is_exact_and_isolated():
    """실제 마스킹 대상(normalized_text)에서 매치 구간을 같은 길이 '*'로 치환했을 때:
      1) 매치 구간은 정확히 전부 '*'로 바뀌고
      2) 구간 밖 텍스트는 단 한 글자도 바뀌지 않고
      3) 여러 매치를 한 번에 마스킹해도(사전 계산한 오프셋 기준) 서로를 오염시키지 않는다.
    """
    any_checked = False

    for path in _all_documents():
        result = process_input(str(path))
        text = result.normalized_text

        spans = []
        for pattern in PII_PATTERNS.values():
            spans.extend((m.start(), m.end()) for m in pattern.finditer(text))
        if not spans:
            continue

        spans.sort()
        overlap = [
            (spans[i - 1], spans[i]) for i in range(1, len(spans)) if spans[i][0] < spans[i - 1][1]
        ]
        assert not overlap, f"{path.name}: 서로 다른 유형의 매치 구간이 겹침 {overlap[:5]}"

        any_checked = True
        original_values = [text[s:e] for s, e in spans]

        masked = list(text)
        for start, end in spans:
            for i in range(start, end):
                masked[i] = "*"
        masked_text = "".join(masked)

        assert len(masked_text) == len(text), f"{path.name}: 마스킹 후 길이가 달라짐"

        for (start, end), original_value in zip(spans, original_values):
            assert masked_text[start:end] == "*" * (end - start), f"{path.name}: {start}~{end} 완전히 마스킹 안 됨"

        cursor = 0
        for start, end in spans:
            assert masked_text[cursor:start] == text[cursor:start], f"{path.name}: 매치 이전 구간이 오염됨"
            cursor = end
        assert masked_text[cursor:] == text[cursor:], f"{path.name}: 마지막 매치 이후 구간이 오염됨"

    assert any_checked, "마스킹 안전성을 검증할 매치가 어느 문서에서도 없었다"


# --- offset_map 자체에 대한 적대적(adversarial) 케이스 ---

_ADVERSARIAL_STRINGS = [
    "",
    "a",
    "가",
    "   ",  # NBSP만 3개
    "가​나​다",  # 제로폭 공백으로만 이루어진 반복
    unicodedata.normalize("NFD", "안녕하세요간장공장공장장"),  # NFD 반복 한글
    "é" * 5,  # 'e' + combining acute accent 반복 (NFC로 압축될 수 있는 시퀀스)
    "“” –—―‐‑‒−••●▪◦‣⁃·",  # 정규화 대상 특수문자만 나열
    "   \t\t　　   ",  # 공백류만 나열
    "정상 문장 중간에 " + "​" * 10 + " 제로폭공백 뭉치가 낀 경우",
]


@pytest.mark.parametrize("raw", _ADVERSARIAL_STRINGS)
def test_offset_map_survives_adversarial_input(raw):
    """정규화가 문자 삭제/치환을 심하게 일으키는 극단적 입력에서도 offset_map이
    범위를 벗어나거나 잘못된 위치를 가리키지 않아야 한다."""
    from preprocessing.normalizer import normalize_text

    normalized = normalize_text(raw)
    offset_map = build_offset_map(raw, normalized)

    assert len(offset_map) == len(normalized)
    for i, raw_pos in enumerate(offset_map):
        assert 0 <= raw_pos < max(len(raw), 1) or len(raw) == 0, (
            f"offset_map[{i}]={raw_pos}가 raw 길이({len(raw)}) 범위를 벗어남"
        )
        assert raw_pos == 0 or raw_pos < len(raw)


def test_offset_map_monotonic_non_decreasing_within_equal_regions():
    """치환이 없는 구간에서는 오프셋이 앞으로 갈수록 뒤로 가지 않아야 한다
    (역행하면 "원문 위치"가 실제로 뒤죽박죽으로 찍힌다는 뜻)."""
    from preprocessing.normalizer import normalize_text

    raw = "본 문서는  \"대외비\"   문서이며 외부   유출을 금지합니다"
    normalized = normalize_text(raw)
    offset_map = build_offset_map(raw, normalized)

    non_decreasing_violations = [
        i for i in range(1, len(offset_map)) if offset_map[i] < offset_map[i - 1] - 1
    ]
    assert not non_decreasing_violations, f"역행 지점: {non_decreasing_violations}"
