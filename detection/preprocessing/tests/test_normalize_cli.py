from preprocessing.normalize_cli import build_index_info, demo_variants, _run_single


def test_demo_variants_share_same_content():
    """데모 변형들은 인코딩/기호/공백만 다를 뿐 실제로는 같은 문장이어야 한다."""
    variants = demo_variants()
    assert len(variants) >= 4


def test_demo_variants_normalize_to_identical_text():
    """FR-PRE-001 검증 기준: 다른 환경에서 작성된 동일 내용 -> 동일 정규화 결과."""
    variants = demo_variants()
    normalized_set = {v["normalized"] for v in variants}
    assert len(normalized_set) == 1


def test_demo_variants_raw_forms_differ():
    """애초에 raw 표현이 서로 달라야 정규화가 뭔가를 한 게 증명된다 (전부 raw까지
    같으면 정규화 없이도 통과하는 무의미한 테스트가 된다)."""
    variants = demo_variants()
    raw_set = {v["raw"] for v in variants}
    assert len(raw_set) == len(variants)


def test_index_info_word_offsets_identity_case():
    raw = "010-1234-5678로 연락주세요"
    info = build_index_info(raw, raw)
    assert info["offset_map"] == list(range(len(raw)))
    assert [w["text"] for w in info["words"]] == ["010-1234-5678로", "연락주세요"]
    first = info["words"][0]
    assert raw[first["raw_start"] : first["raw_end"]] == "010-1234-5678로"


def test_index_info_tracks_offset_shift_on_deletion():
    """정규화가 문자를 삭제해도(연속 공백 축약 등) 단어별 raw 오프셋이 밀려서
    정확히 원문 위치를 가리켜야 한다."""
    raw = "본  문서는 대외비입니다"  # 공백 2개
    normalized = "본 문서는 대외비입니다"  # 정규화 후 1개로 축약
    info = build_index_info(raw, normalized)
    word = next(w for w in info["words"] if w["text"] == "문서는")
    assert raw[word["raw_start"] : word["raw_end"]] == "문서는"


def test_run_single_includes_index():
    results = _run_single("테스트 문장입니다", label="x")
    assert "index" in results[0]
    assert results[0]["index"]["words"]
