"""hwpdoc 자원 상한 시험 (2026-10-11 검토 지적 2~4 + 같은 종류로 더 찾은 것). 글자는 모두 가짜 값.

  CFB(olefile 단계)  DIFAT 순환·긴 DIFAT 사슬·미니 스트림 순환(루트 크기 거짓), FAT 섹터 수·머리 칸 범위, 중복 스트림,
                     디렉터리 항목·구역 스트림이 많은 파일(olefile 0.47 안의 제곱 시간)
  구조 개수          빈 문단·글자 문단·표 칸·부가 글자 홍수(HWP), 빈 요소 홍수(HWPX) → HwpTooLarge, 메모리 상한
  HWPX 표            cellAddr 없는 행이 많은 표(행 순번 찾기의 제곱 시간)
  HWP 문단           한 문단에 PARA_TEXT가 아주 많을 때(문자열 이어 붙이기의 제곱 시간)

시간 상한은 수정 전 실측(각 시험 주석)보다 크게 낮고 수정 뒤 로컬 실측의 4배 이상(서버 2 vCPU 여유). 메모리는 tracemalloc 최고치.
"""

from __future__ import annotations

import struct
import time
import tracemalloc

import pytest

import hwp_synth as S
from hwp_synth import hp_p, hp_run, hp_t
from preprocessing import hwpdoc

MAX = 20 * 1024 * 1024
SECTOR = 512


def _base() -> bytearray:
    return bytearray(S.build_hwp([S.p(0, "가짜 본문 문장 하나 둘 셋 넷 다섯 여섯 일곱 여덟")]))


# ---------------------------------------------------------------- 조작 CFB 만들기 (검토 재현 stage1-verify/v4_olefile.py와 같은 방식)

def difat_cycle(k: int) -> bytes:
    """DIFAT 섹터 하나가 자기 자신을 다음으로 가리키고, 머리는 DIFAT k개·FAT 109 + 127k개라고 선언."""
    b = _base()
    d = len(b) // SECTOR - 1
    fat0 = struct.unpack_from("<I", b, 76)[0]
    b += struct.pack("<I", fat0) * 127 + struct.pack("<I", d)
    struct.pack_into("<I", b, 0x2C, 109 + 127 * k)
    struct.pack_into("<I", b, 0x44, d)
    struct.pack_into("<I", b, 0x48, k)
    return bytes(b)


def difat_chain(m: int) -> bytes:
    """순환 없는 DIFAT 사슬 m개, 항목은 모두 같은 FAT 섹터(FAT 109 + 127m개 선언)."""
    b = _base()
    n0 = len(b) // SECTOR - 1
    fat0 = struct.unpack_from("<I", b, 76)[0]
    for i in range(m):
        b += struct.pack("<I", fat0) * 127 + struct.pack("<I", n0 + i + 1 if i < m - 1 else 0xFFFFFFFE)
    struct.pack_into("<I", b, 0x2C, 109 + 127 * m)
    struct.pack_into("<I", b, 0x44, n0)
    struct.pack_into("<I", b, 0x48, m)
    return bytes(b)


def mini_cycle(root_size: int) -> bytes:
    """미니 스트림(루트 항목) 사슬 끝을 처음으로 되돌리고 루트 크기를 root_size로 선언."""
    b = _base()
    fat0 = struct.unpack_from("<I", b, 76)[0]
    dir0 = struct.unpack_from("<I", b, 0x30)[0]
    root = (dir0 + 1) * SECTOR
    start = struct.unpack_from("<I", b, root + 116)[0]
    fatoff = (fat0 + 1) * SECTOR
    s = start
    while struct.unpack_from("<I", b, fatoff + 4 * s)[0] < 0xFFFFFFF0:
        s = struct.unpack_from("<I", b, fatoff + 4 * s)[0]
    struct.pack_into("<I", b, fatoff + 4 * s, start)
    struct.pack_into("<I", b, root + 120, root_size)
    return bytes(b)


def _dir_entry_offset(cfb: bytes, name: str) -> int:
    dir_start = struct.unpack_from("<I", cfb, 48)[0]
    off = SECTOR + dir_start * SECTOR
    target = name.encode("utf-16-le") + b"\x00\x00"
    while off + 128 <= len(cfb):
        if cfb[off:off + len(target)] == target:
            return off
        off += 128
    raise KeyError(name)


def with_extra_fat_sectors(cfb: bytes, k: int) -> bytes:
    """FREESECT만 든 FAT 섹터 k개를 파일 끝에 덧붙인 사본 - 한컴 저장본에 흔한 모양(팀 7/19, 견본 1/389, 필요 수보다 1~2개)."""
    b = bytearray(cfb)
    n_fat = struct.unpack_from("<I", b, 0x2C)[0]
    fat0 = struct.unpack_from("<I", b, 76)[0]
    for _ in range(k):
        new = len(b) // SECTOR - 1
        assert new < 128
        b += b"\xff" * SECTOR
        struct.pack_into("<I", b, (fat0 + 1) * SECTOR + 4 * new, 0xFFFFFFFD)      # FATSECT 표시
        struct.pack_into("<I", b, 76 + 4 * n_fat, new)
        n_fat += 1
    struct.pack_into("<I", b, 0x2C, n_fat)
    return bytes(b)


def _timed(fn):
    t = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t


def _peak(fn):
    tracemalloc.start()
    try:
        out = fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return out, peak


def _read_error(data: bytes, budget: int = MAX):
    try:
        hwpdoc.read(data, max_decompressed=budget)
    except hwpdoc.HwpError as exc:
        return exc
    return None


# ---------------------------------------------------------------- 지적 2: olefile을 부르기 전 CFB 머리 확인

@pytest.mark.parametrize("make", [
    pytest.param(lambda: difat_cycle(100), id="difat-cycle-k100"),          # 수정 전 sniff·read 각 5.2초
    pytest.param(lambda: difat_chain(100), id="difat-chain-m100"),          # 수정 전 5.2초, sniff 'hwp'
    pytest.param(lambda: mini_cycle(256 << 20), id="mini-cycle-256MiB"),    # 수정 전 sniff 'hwp', read 정상, +591MB
    pytest.param(lambda: mini_cycle(64 << 20), id="mini-cycle-64MiB"),
])
def test_crafted_cfb_is_rejected_fast_with_bounded_memory(make):
    data = make()
    ((sniffed, error), peak), seconds = _timed(lambda: _peak(lambda: (hwpdoc.sniff(data), _read_error(data))))
    assert sniffed is None
    assert isinstance(error, hwpdoc.HwpCorrupt), error
    assert seconds < 1.0, seconds
    assert peak < 16 << 20, peak


@pytest.mark.parametrize("offset,fmt,value", [
    (0x1C, "<H", 0xFEFF),        # 바이트 순서
    (0x1E, "<H", 10),            # 섹터 크기 1024(3판은 9, 4판은 12만)
    (0x1E, "<H", 12),            # 3판인데 4096
    (0x20, "<H", 7),             # 미니 섹터 128
    (0x2C, "<I", 0),             # FAT 섹터 0개
    (0x2C, "<I", 50),            # FAT 섹터가 파일 섹터 수보다 많음
    (0x48, "<I", 1),             # DIFAT 섹터 수가 FAT 섹터 수와 안 맞음
    (0x40, "<I", 10_000),        # 미니 FAT 섹터가 파일 섹터 수보다 많음
    (0x30, "<I", 10_000),        # 디렉터리 시작이 파일 밖
])
def test_bad_cfb_header_fields_are_corrupt(offset, fmt, value):
    b = _base()
    struct.pack_into(fmt, b, offset, value)
    data = bytes(b)
    assert hwpdoc.sniff(data) is None
    assert isinstance(_read_error(data), hwpdoc.HwpCorrupt)


@pytest.mark.parametrize("k", [1, 2])
def test_extra_free_fat_sectors_like_hancom_still_read(k):
    data = with_extra_fat_sectors(bytes(_base()), k)
    assert struct.unpack_from("<I", data, 0x2C)[0] == 1 + k
    assert hwpdoc.sniff(data) == "hwp"
    assert hwpdoc.read(data, max_decompressed=MAX).lines() == ["가짜 본문 문장 하나 둘 셋 넷 다섯 여섯 일곱 여덟"]


def difat_long_valid(n_fat: int) -> bytes:
    """머리 칸이 모두 범위 안인 긴 DIFAT: FAT 섹터 n_fat개 선언(파일 섹터 수 이하가 되게 빈 섹터를 채움), DIFAT 항목은 모두
    같은 FAT 섹터. 머리 확인을 통과하므로 olefile FAT 적재 자체가 선형이어야 한다."""
    b = _base()
    fat0 = struct.unpack_from("<I", b, 76)[0]
    per = SECTOR // 4 - 1
    n_difat = -(-(n_fat - 109) // per)
    first = len(b) // SECTOR - 1
    for i in range(n_difat):
        nxt = first + i + 1 if i < n_difat - 1 else 0xFFFFFFFE
        b += struct.pack("<I", fat0) * per + struct.pack("<I", nxt)
    while len(b) // SECTOR - 1 < n_fat:
        b += b"\x00" * SECTOR
    struct.pack_into("<109I", b, 76, *([fat0] * 109))
    struct.pack_into("<I", b, 0x2C, n_fat)
    struct.pack_into("<I", b, 0x44, first)
    struct.pack_into("<I", b, 0x48, n_difat)
    return bytes(b)


def test_long_difat_with_counts_in_range_is_linear():
    """FAT 섹터 8,000개 선언(4MB 파일). olefile 0.47 그대로면 FAT 배열을 섹터마다 새로 이어 붙여 복사량이 제곱
    (약 16GB, 수 초). 선형판은 수십 ms. 내용은 정상으로 읽힌다(뒤 FAT 항목은 쓰이지 않음)."""
    data = difat_long_valid(8000)
    assert len(data) // SECTOR - 1 >= 8000
    doc, seconds = _timed(lambda: hwpdoc.read(data, max_decompressed=MAX))
    assert doc.lines() == ["가짜 본문 문장 하나 둘 셋 넷 다섯 여섯 일곱 여덟"]
    assert seconds < 1.0, seconds


def test_stream_referenced_twice_is_corrupt():
    """두 구역 스트림이 같은 시작 섹터를 가리키면 손상(olefile DEFECT_INCORRECT로 엶). 수정 전에는 그대로 읽었다."""
    big = S.p(0, "가짜 본문 " * 400)
    data = bytearray(S.build_hwp([big, big], flags=0))
    off0, off1 = _dir_entry_offset(data, "Section0"), _dir_entry_offset(data, "Section1")
    data[off1 + 116:off1 + 120] = data[off0 + 116:off0 + 120]
    assert isinstance(_read_error(bytes(data)), hwpdoc.HwpCorrupt)


def test_many_empty_sections_are_linear():
    """길이 0인 구역 스트림 12,000개(비압축). 수정 전: olefile 경로 찾기가 형제 수에 비례해 6,000개 2.4초 → 12,000개 약 9.5초."""
    streams = {"FileHeader": S.file_header(0), "DocInfo": b"\x00" * 8, "BodyText/Section0": S.p(0, "가짜 본문")}
    for i in range(1, 12_000):
        streams[f"BodyText/Section{i}"] = b""
    data = S.write_cfb(streams)
    doc, seconds = _timed(lambda: hwpdoc.read(data, max_decompressed=MAX))
    assert doc.lines() == ["가짜 본문"] and doc.stats["sections"] == 12_000
    assert seconds < 3.0, seconds


def test_many_directory_entries_are_linear():
    """1바이트 그림 BinData 30,000개. 수정 전: olefile 중복 스트림 확인이 목록 검색이라 16,000개 0.8초 → 30,000개 약 2.9초."""
    streams = {"FileHeader": S.file_header(0), "DocInfo": b"\x00" * 8, "BodyText/Section0": S.p(0, "가짜 본문")}
    for i in range(30_000):
        streams[f"BinData/B{i:05d}.png"] = b"x"
    data = S.write_cfb(streams)
    doc, seconds = _timed(lambda: hwpdoc.read(data, max_decompressed=MAX))
    assert doc.media == 30_000
    assert seconds < 1.5, seconds


def test_olefile_version_is_pinned():
    """hwpdoc은 olefile 0.47의 내부 함수 세 개를 선형 시간판으로 바꿔 쓴다 - 판이 바뀌면 다시 확인해야 함."""
    import olefile

    assert olefile.__version__ == "0.47"


# ---------------------------------------------------------------- 지적 3: 문단·칸·부가 글자 수 상한

def _flood_cases():
    """(만들기, 예산). 구역 바이트는 시험 안에서 만든다(모듈 import·수집 때 만들지 않게)."""
    def empty_paras():                                                                       # 4MB, 빈 PARA_HEADER
        return S.p(0, "가짜 본문 문단") + struct.pack("<I", 66) * 1_000_000

    def text_paras():                                                                        # 3MB, 한 글자 문단
        return (struct.pack("<I", 66) + S.rec(67, 1, "가".encode("utf-16-le"))) * 300_000

    def cells():                                                                             # 3.8MB, 칸 10만
        return S.p(0, "", S.table(1, [(r, c, 1, 1, []) for r in range(50_000) for c in range(2)], 50_000, 2))

    def fields():                                                                            # 4.2MB, 필드 20만
        return S.p(0, "가짜 본문", *(S.field(1, "%hlk", "x") for _ in range(200_000)))

    return [
        pytest.param(lambda: S.build_hwp([empty_paras()]), 4 << 20, id="hwp-empty-paragraphs-1M"),
        pytest.param(lambda: S.build_hwp([text_paras()]), 4 << 20, id="hwp-text-paragraphs-300k"),
        pytest.param(lambda: S.build_hwp([cells()]), 4 << 20, id="hwp-cells-100k"),
        pytest.param(lambda: S.build_hwp([fields()]), 8 << 20, id="hwp-side-200k"),
        pytest.param(lambda: S.build_hwpx([hp_p(hp_t("가짜 본문")) + "<hp:p/>" * 1_000_000]), 8 << 20, id="hwpx-empty-p-1M"),
        pytest.param(lambda: S.build_hwpx([hp_p(hp_t("가짜 본문" + "<a/>" * 1_500_000))]), 8 << 20, id="hwpx-empty-elements-1.5M"),
    ]


@pytest.mark.parametrize("make,budget", _flood_cases())
def test_structure_floods_are_too_large_with_bounded_memory(make, budget):
    """작은 파일(수~수십 KB)이 문단·칸·부가 글자·XML 요소를 수십만~백만 개 만든다. 수정 전: 모두 정상 HwpDoc,
    빈 문단 100만 개에 최고 832MB(검토 v5_paras.py), HWPX 빈 문단 100만 개에 약 530MB.
    수정 뒤: 구조 수가 예산/64(HWPX 요소는 '<' 수가 예산/16)를 넘으면 HwpTooLarge."""
    data = make()
    assert len(data) * 10 < budget
    error, peak = _peak(lambda: _read_error(data, budget))
    assert isinstance(error, hwpdoc.HwpTooLarge), error
    assert peak < 64 << 20, peak


def test_empty_paragraph_flood_through_registration_path(tmp_path):
    """Detection 등록 경로(20MiB 예산): 수정 전 success=True(최고 832MB), 수정 뒤 CorruptedDocumentError."""
    from preprocessing.router import process_input  # noqa: PLC0415 - 이 시험만 등록 경로 전체가 필요(3.11 hwpdoc 단독 점검에서 뺌)

    path = tmp_path / "flood.hwp"
    path.write_bytes(S.build_hwp([S.p(0, "가짜 본문 문단") + struct.pack("<I", 66) * 1_000_000]))
    (doc, peak) = _peak(lambda: process_input(str(path)))
    assert not doc.success and doc.error_type == "CorruptedDocumentError", (doc.error_type, doc.error_message)
    assert "상한" in doc.error_message
    assert peak < 256 << 20, peak


def test_structure_limit_scales_with_budget():
    """상한은 예산에 비례: 같은 문서가 큰 예산에서는 읽힌다(문단 7만 개, 칸·부가 글자 없음)."""
    data = S.build_hwp([S.p(0, "가짜 본문 문단") + struct.pack("<I", 66) * 70_000])
    assert isinstance(_read_error(data, 4 << 20), hwpdoc.HwpTooLarge)        # 4MiB / 64 = 65,536 < 70,001
    assert len(hwpdoc.read(data, max_decompressed=8 << 20).paragraphs) == 70_001


# ---------------------------------------------------------------- 지적 4: cellAddr 없는 HWPX 표 행

def test_hwpx_rows_without_cell_address_are_linear():
    """<hp:tr><hp:tc/></hp:tr> 8,000행(2.8KB). 수정 전 16.5초(행마다 형제 hp:tr 목록을 새로 만들어 .index())."""
    data = S.build_hwpx([hp_p(hp_t("가짜 본문 문장")) + hp_p(hp_run("<hp:tbl>" + "<hp:tr><hp:tc/></hp:tr>" * 8000 + "</hp:tbl>"))])
    doc, seconds = _timed(lambda: hwpdoc.read(data, max_decompressed=MAX))
    assert doc.body_lines() == ["가짜 본문 문장"]
    assert seconds < 3.0, seconds


def test_hwpx_row_numbers_without_cell_address_follow_tr_order():
    rows = "".join(f"<hp:tr><hp:tc><hp:subList>{hp_p(hp_t(f'행{i}'))}</hp:subList></hp:tc></hp:tr>" for i in range(300))
    data = S.build_hwpx([hp_p(hp_run(f"<hp:tbl><hp:sz width='1' height='1'/>{rows}</hp:tbl>"))])
    doc = hwpdoc.read(data, max_decompressed=MAX)
    cells = [p for p in doc.paragraphs if p.cell]
    assert [p.locator for p in cells] == [f"body:t0:r{i}:c0:p0" for i in range(300)]
    assert [p.text for p in cells] == [f"행{i}" for i in range(300)]


# ---------------------------------------------------------------- 한 문단에 PARA_TEXT 여러 개

def test_many_para_text_records_in_one_paragraph_are_linear():
    """PARA_HEADER 하나 아래 한 글자 PARA_TEXT 60만 개(3.6MB 풀림, 파일 약 8KB). 수정 전: 문자열을 매번 새로 이어 붙여
    40만 개 3.7초·100만 개 118초(제곱), 60만 개는 다른 시험과 함께 돌 때 27초. 레코드당 처리 비용이 커서 절대 시간 대신
    4배 늘렸을 때의 시간 비(선형 ≈ 4, 제곱 ≈ 16)로 본다."""
    def run(n):
        data = S.build_hwp([S.rec(66, 0, b"\x00" * 22) + S.rec(67, 1, "가".encode("utf-16-le")) * n])
        doc, seconds = _timed(lambda: hwpdoc.read(data, max_decompressed=MAX))
        (para,) = doc.paragraphs
        assert para.text == "가" * n and len(para.offsets) == n
        return seconds

    small, large = run(150_000), run(600_000)
    assert large < 8 * small, (small, large)
    assert large < 10.0, large


def test_split_para_text_keeps_text_and_offsets():
    """여러 PARA_TEXT는 순서대로 잇고 위치도 각 레코드의 바이트 위치를 유지한다(동작 그대로)."""
    sec = S.rec(66, 0, b"\x00" * 22) + S.rec(67, 1, "가나".encode("utf-16-le")) + S.rec(67, 1, "다".encode("utf-16-le"))
    doc = hwpdoc.read(S.build_hwp([sec], flags=0), max_decompressed=MAX)
    (para,) = doc.paragraphs
    assert para.text == "가나다"
    assert [sec[o:o + 2].decode("utf-16-le") for o in para.offsets] == ["가", "나", "다"]
