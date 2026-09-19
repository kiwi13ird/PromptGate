import random

from windowhash.hashing import WINDOW, compact, window_hashes, window_span


def test_compact_keeps_only_letters_and_digits_with_offsets():
    comp = compact("김도현 | 경영기획실, (대표이사)\t2016-03-02")
    text = "".join(chr(c) for c in comp.codes)
    assert text == "김도현경영기획실대표이사20160302"
    assert comp.offsets[0] == 0 and comp.offsets[3] == 6  # '경'은 원문 6번째


def test_compact_is_separator_invariant():
    row = ["2026-07", "NW16-0001", "김도현", "경영기획실", "9000000"]
    variants = [" | ".join(row), "\t".join(row), " ".join(row), "\n".join(row), ", ".join(row)]
    hashes = {tuple(window_hashes(compact(v).codes, window=10)) for v in variants}
    assert len(hashes) == 1


def test_window_count_and_short_input():
    codes = compact("가" * 40).codes
    assert len(window_hashes(codes, window=30)) == 11
    assert window_hashes(compact("가" * 29).codes, window=30) == []


def test_shared_span_shares_a_hash():
    """압축 후 WINDOW자 이상 겹치면 창 해시를 반드시 하나 이상 공유한다."""
    rng = random.Random(1)
    syl = [chr(c) for c in range(0xAC00, 0xAC00 + 2000)]
    for _ in range(100):
        a = "".join(rng.choice(syl) for _ in range(300))
        shared = a[100 : 100 + WINDOW]
        b = "".join(rng.choice(syl) for _ in range(50)) + shared + "".join(rng.choice(syl) for _ in range(50))
        assert set(window_hashes(compact(a).codes)) & set(window_hashes(compact(b).codes))


def test_window_span_maps_back_to_original_offsets():
    text = "  가나다 | 라마바   사아자"
    comp = compact(text)
    start, end = window_span(comp, 0, window=6)
    assert text[start:end].replace(" ", "").replace("|", "") == "가나다라마바"
