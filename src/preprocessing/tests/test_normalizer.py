import unicodedata

from preprocessing.normalizer import (
    is_normalization_stable,
    normalize_for_matching,
    normalize_text,
)


def test_nfd_nfc_equivalence():
    """FR-PRE-001 검증 기준: 동일 내용, 다른 유니코드 표기 -> 동일한 정규화 결과."""
    text = "안녕하세요 보안팀입니다"
    mac_form = unicodedata.normalize("NFD", text)  # macOS 파일시스템 표기
    win_form = unicodedata.normalize("NFC", text)  # Windows/DOCX 표기
    assert mac_form != win_form
    assert normalize_text(mac_form) == normalize_text(win_form)


def test_whitespace_variants_collapse():
    # NBSP x2, 전각 공백, 제로폭 공백(비가시), 탭 순서로 섞은 문자열.
    # 제로폭 공백은 시각적 간격이 없으므로 "CD"처럼 완전히 붙어야 하고,
    # 그 외 공백류(NBSP/전각/탭)는 모두 눈에 보이는 공백 한 칸으로 남아야 한다.
    s = "A\xa0\xa0B　C​D\tE"
    assert normalize_text(s) == "A B CD E"


def test_smart_quotes_and_dashes():
    s = "“NDA” – ‘draft’ • bullet"
    assert normalize_text(s) == "\"NDA\" - 'draft' - bullet"


def test_crlf_normalized():
    assert normalize_text("line1\r\nline2\rline3") == "line1\nline2\nline3"


def test_idempotent():
    s = "“NDA” test  string"
    once = normalize_text(s)
    assert is_normalization_stable(once)
    assert normalize_text(once) == once


def test_normalize_for_matching_strips_spaces():
    assert normalize_for_matching("010 - 1234 - 5678") == "010-1234-5678"


def test_empty_input():
    assert normalize_text("") == ""
    assert normalize_text(None) == ""


def test_control_characters_stripped():
    # PDF 폰트 인코딩이 깨진 글리프가 NUL로 추출되는 실제 사례(C2_비콘_통신_탐지.pdf)를 재현.
    s = "Command\x00and Control) \x01\x1f끝\x7f"
    assert normalize_text(s) == "Commandand Control) 끝"


def test_tab_newline_carriage_return_not_treated_as_control():
    assert normalize_text("a\tb\nc\r\nd") == "a b\nc\nd"
