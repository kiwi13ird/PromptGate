"""고정 씨앗 변형 시험: 망가뜨린 HWP 레코드·HWP 파일·HWPX XML·HWPX 파일은 HwpError(또는 정상)만 낸다.
(로컬에서는 같은 방식으로 팀 HWP 구역까지 섞어 2만 7천 회 돌려 HwpError 밖 예외 0 - stage1/fuzz_result.txt)"""

from __future__ import annotations

import io
import random
import zipfile

import hwp_synth as S
import test_hwpdoc_hwp as T
import test_hwpdoc_hwpx as X
from preprocessing import hwpdoc


def _mutate(rnd: random.Random, b: bytes) -> bytes:
    b = bytearray(b)
    for _ in range(rnd.choice((1, 1, 2, 4, 16))):
        i = rnd.randrange(len(b))
        op = rnd.random()
        if op < 0.6:
            b[i] = rnd.randrange(256)
        elif op < 0.8:
            del b[i:i + rnd.randrange(1, 64)]
        else:
            b[i:i] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 32)))
        if not b:
            b = bytearray(b"\x00")
    return bytes(b)


def _outcome(data: bytes) -> str:
    try:
        hwpdoc.read(data, max_decompressed=1 << 22).lines()
        return "ok"
    except hwpdoc.HwpError as exc:
        return type(exc).__name__


def test_mutations_raise_only_parser_errors():
    rnd = random.Random(20261011)
    sections = T._sample_sections()
    hwpx = X._sample()
    zf = zipfile.ZipFile(io.BytesIO(hwpx))
    parts = {n: zf.read(n) for n in zf.namelist()}
    seen = set()
    for _ in range(300):
        k = rnd.randrange(len(sections))
        mutated = list(sections)
        mutated[k] = _mutate(rnd, sections[k])
        seen.add(_outcome(S.build_hwp(mutated, flags=rnd.choice((0, 1)))))
        seen.add(_outcome(_mutate(rnd, S.build_hwp(sections))))
        name = rnd.choice([n for n in parts if n.endswith((".xml", ".hpf"))])
        changed = dict(parts, **{name: _mutate(rnd, parts[name])})
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zo:
            for n, v in changed.items():
                zo.writestr(n, v)
        seen.add(_outcome(buf.getvalue()))
        seen.add(_outcome(_mutate(rnd, hwpx)))
    assert {"ok", "HwpCorrupt", "HwpUnsupported"} <= seen


def test_cfb_header_mutations_raise_only_parser_errors_quickly():
    """CFB 머리 칸·DIFAT 배열 변형(검토 지적 2의 조작 CFB 3종 + 한컴식 FAT 여유 + 범위 안 긴 DIFAT을 씨앗으로).
    sniff·read 모두 HwpError 또는 정상만, 한 건(sniff + read) 0.5초 안. 로컬 2만 회 최장 8ms(stage1/round2/header_fuzz.py)."""
    import struct
    import time

    import test_hwpdoc_limits as L

    rnd = random.Random(1011)
    seeds = [L.difat_cycle(100), L.difat_chain(100), L.mini_cycle(256 << 20),
             L.with_extra_fat_sectors(bytes(L._base()), 2), L.difat_long_valid(300), T._sample()]
    fields = [(0x1A, "<H"), (0x1C, "<H"), (0x1E, "<H"), (0x20, "<H"), (0x2C, "<I"), (0x30, "<I"), (0x3C, "<I"),
              (0x40, "<I"), (0x44, "<I"), (0x48, "<I")] + [(0x4C + 4 * i, "<I") for i in range(4)]
    values = [0, 1, 2, 3, 6, 9, 12, 108, 109, 110, 127, 128, 4096, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE,
              0xFFFFFFFF]
    seen = set()
    slowest = 0.0
    for _ in range(600):
        b = bytearray(rnd.choice(seeds))
        for _ in range(rnd.choice((1, 1, 2, 3))):
            off, fmt = rnd.choice(fields)
            mask = 0xFFFF if fmt == "<H" else 0xFFFFFFFF
            value = rnd.choice(values) if rnd.random() < 0.7 else rnd.randrange(mask + 1)
            struct.pack_into(fmt, b, off, value & mask)
        data = bytes(b)
        t = time.perf_counter()
        assert hwpdoc.sniff(data) in (None, "hwp")
        seen.add(_outcome(data))
        slowest = max(slowest, time.perf_counter() - t)
    assert seen <= {"ok", "HwpCorrupt", "HwpUnsupported", "HwpTooLarge"} and "HwpCorrupt" in seen and "ok" in seen
    assert slowest < 0.5, slowest
