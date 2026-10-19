"""gateway_proto(2026-10-11): 스키마 없는 protobuf 걷기 - wire 형식, 메시지/글자/바이트 판정, 프레임·gzip,
손상 입력(무작위 변형 1,000개), 상한, 다시 만들기(정규 인코딩이면 원본과 같음)·값 바꾸기(감싼 길이 고침).
10/11 검토 반영: 압축 해제 상한 본문 합계·읽지 못한 프레임 내용 안 붙잡음·검사용 글자 후보(text_values).
가짜 값만 쓴다. 실행: python -m unittest tests.test_gateway_proto -v (Gateway 사본 폴더에서)
"""

from __future__ import annotations

import gzip
import random
import re
import sys
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gateway_proto as gp  # noqa: E402

PROMPT = "PGTEST 주민번호 900101-1234568"      # 가짜 질문(시험 표지 + 가상 주민등록번호)
CONV = "00000000-0000-4000-8000-00000000c0de"
PARENT = "00000000-0000-4000-8000-00000000beef"


def varint(value: int) -> bytes:
    if value < 0:
        value += 1 << 64
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def fv(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def fl(number: int, payload) -> bytes:
    payload = payload.encode("utf-8") if isinstance(payload, str) else payload
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def f32(number: int, raw: bytes) -> bytes:
    return varint(number << 3 | 5) + raw


def f64(number: int, raw: bytes) -> bytes:
    return varint(number << 3 | 1) + raw


def frame(payload: bytes, flags: int = 0) -> bytes:
    return bytes([flags]) + len(payload).to_bytes(4, "big") + payload


def perform_action(prompt: str = PROMPT) -> bytes:
    """PerformAction 비슷한 가짜 본문(스키마는 지어낸 것): 대화 번호, 메시지{부모 번호, 내용{질문}, 시각}, 지도 항목, 바이트."""
    content = fl(1, prompt) + fv(2, 1)
    message = fl(1, PARENT) + fl(3, content) + fv(5, 1_760_000_000_000)
    entry = fl(1, "hong.gildong@example.test") + fl(2, "x")
    return fl(1, CONV) + fl(2, message) + fl(4, entry) + fl(6, bytes(range(0, 40, 3))) + f64(7, b"\x01" * 8)


def kinds(body, **kwargs):
    return [(r["path"], r["kind"]) for r in gp.walk(body, **kwargs)]


class WireFormatTests(unittest.TestCase):
    def test_scalar_fields(self):
        body = fv(1, 0) + fv(2, 300) + fv(3, -1) + f32(4, b"abcd") + f64(5, b"\x00" * 8) + fv(6, 2 ** 63)
        records = gp.walk(body)
        self.assertEqual([(r["path"], r["wire"], r["length"], r["kind"]) for r in records],
                         [("1", 0, 1, "varint"), ("2", 0, 2, "varint"), ("3", 0, 10, "varint"),
                          ("4", 5, 4, "fixed32"), ("5", 1, 8, "fixed64"), ("6", 0, 10, "varint")])
        self.assertEqual([r["loc"] for r in records], [(0,), (1,), (2,), (3,), (4,), (5,)])

    def test_nested_paths_and_locations(self):
        body = fv(9, 1) + fl(1, fv(7, 1) + fl(3, fl(2, "깊은 곳의 글자") + fv(4, 5)) + fl(3, fl(2, "둘째")))
        records = gp.walk(body)
        self.assertEqual([(r["path"], r["loc"], r["kind"]) for r in records], [
            ("9", (0,), "varint"), ("1.7", (1, 0), "varint"), ("1.3.2", (1, 1, 0), "text"),
            ("1.3.4", (1, 1, 1), "varint"), ("1.3.2", (1, 2, 0), "text")])
        self.assertEqual([value for _, _, value in gp.text_values(body)], ["깊은 곳의 글자", "둘째"])

    def test_perform_action_like_body(self):
        body = perform_action()
        self.assertEqual(kinds(body), [("1", "text"), ("2.1", "text"), ("2.3.1", "text"), ("2.3.2", "varint"),
                                       ("2.5", "varint"), ("4.1", "text"), ("4.2", "text"), ("6", "bytes"),
                                       ("7", "fixed64")])
        self.assertIn(("2.3.1", (1, 1, 0), PROMPT), gp.text_values(body))

    def test_empty_body_and_empty_value(self):
        self.assertEqual(gp.walk(b""), [])
        self.assertEqual(kinds(fl(1, b"")), [("1", "empty")])


class HeuristicTests(unittest.TestCase):
    """모듈 설명의 판정 규칙 하나하나."""

    def test_wrapper_with_spaces_and_hangul_inside_is_a_message(self):
        # '\n"PGTEST 주민번호 …' = 필드 1(길이 34). 공백·한글은 안쪽 내용에만 → 메시지, 안쪽은 글자
        wrapper = fl(1, PROMPT)
        self.assertEqual(wrapper[:2], b'\n"')
        self.assertEqual(kinds(fl(5, wrapper)), [("5.1", "text")])

    def test_short_word_that_parses_as_numbers_is_text(self):
        self.assertEqual(gp._parse_fields(b"hi", 0, 2, gp._Budget())[0].number, 13)   # {13: 105}로도 읽힌다
        self.assertEqual(kinds(fl(1, "hi")), [("1", "text")])

    def test_uuid_and_hex_wrappers_are_messages(self):
        self.assertEqual(kinds(fl(2, fl(1, CONV))), [("2.1", "text")])
        hex32 = "0123456789abcdef0123456789abcdef"
        wrapped = fl(1, hex32)
        self.assertEqual(wrapped[:2], b"\n ")                  # 길이 머리 0x20 = 공백(길이 머리의 공백은 글자 근거가 아님)
        self.assertEqual(kinds(fl(2, wrapped)), [("2.1", "text")])

    def test_high_bytes_in_framing_make_printable_text_win(self):
        # '가a ' + 32자: 메시지로도 읽히지만(태그 varint = '가a', 길이 0x20) 틀에 0x80 이상 → 글자
        text = "가a " + "x" * 32
        self.assertIsNotNone(gp._parse_fields(text.encode(), 0, len(text.encode()), gp._Budget()))
        self.assertEqual(kinds(fl(1, text)), [("1", "text")])
        # 같은 틀이라도 내용이 출력할 수 없는 바이트면 메시지
        raw = "가a".encode() + bytes([3]) + b"\x00\x01\x02"
        record, = gp.walk(fl(1, raw))
        self.assertTrue(record["path"].startswith("1."))       # 필드 1은 메시지, 그 안 길이 3짜리가 바이트
        self.assertEqual((record["kind"], record["length"]), ("bytes", 3))

    def test_space_in_a_number_position_makes_text_win(self):
        payload = b"H \n!" + b"y" * 33       # {9: 32, 1: 'yyy…'}로도 읽힌다. 공백이 varint 값 자리 → 글자
        self.assertEqual(kinds(fl(1, payload)), [("1", "text")])

    def test_control_bytes_in_framing_mean_message(self):
        self.assertEqual(kinds(fl(1, fl(2, "a b c"))), [("1.2", "text")])    # 길이 머리 0x05 = 제어 문자

    def test_packed_numbers_ambiguity(self):
        # 스키마 없이는 packed [8, 1]과 메시지 {1: 1}이 같은 바이트다 → 메시지로 본다. [1, 2, 3]은 메시지가 아님 → 바이트
        self.assertEqual(kinds(fl(4, b"\x08\x01")), [("4.1", "varint")])
        self.assertEqual(kinds(fl(4, bytes([1, 2, 3]))), [("4", "bytes")])
        self.assertEqual(kinds(fl(4, varint(300) + varint(5))), [("4", "bytes")])
        for body in (fl(4, b"\x08\x01"), fl(4, bytes([1, 2, 3]))):
            self.assertEqual(gp.encode(body), body)

    def test_invalid_utf8_is_bytes_and_control_text_is_bytes(self):
        self.assertEqual(kinds(fl(1, b"\xff\xfe\xfd")), [("1", "bytes")])
        self.assertEqual(kinds(fl(1, "tab\tand\nnewline ok")), [("1", "text")])
        self.assertEqual(kinds(fl(1, "bell\x07char")), [("1", "bytes")])

    def test_reserved_field_numbers_and_groups_are_not_messages(self):
        self.assertEqual(kinds(fl(1, fv(19000, 1))), [("1", "bytes")])
        self.assertEqual(kinds(fl(1, varint(2 << 3 | 3) + varint(2 << 3 | 4))), [("1", "bytes")])


class MalformedTests(unittest.TestCase):
    def unparsed(self, body, reason="not_protobuf", **kwargs):
        records = gp.walk(body, **kwargs)
        self.assertEqual([(r["kind"], r["reason"]) for r in records], [("unparsed", reason)], records)

    def test_malformed_top_level(self):
        for body in (b"\x08", b"\x08\x80", fl(1, b"abc")[:-1], b"\x0a\x05ab", varint(0) + b"\x01",
                     varint(1 << 3 | 3), varint(1 << 3 | 6), varint(1 << 3 | 7), fv(19999, 1),
                     b"\x88\x00\x01",              # 태그를 군더더기 바이트로 적음
                     b"\x0a\x83\x00abc",           # 길이를 군더더기 바이트로 적음
                     b'{"prompt":"x"}', "평문 질문".encode(), b"\x08" + b"\xff" * 11):
            with self.subTest(body=body[:20]):
                self.unparsed(body)

    def test_limits(self):
        deep = fl(1, "바닥")
        for _ in range(200):
            deep = fl(1, deep)
        records = gp.walk(deep)                     # 깊이 상한 아래는 메시지로 풀지 않는다(예외 없음)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["path"].count("."), gp.MAX_DEPTH - 1)
        self.assertIn(records[0]["kind"], ("bytes", "text"))
        self.unparsed(fv(1, 1) * (gp.MAX_FIELDS + 1), "limit")
        # 안쪽 값에서 필드 수 상한을 넘으면 그 값만 메시지로 풀지 않는다: 'hi'를 2만 5천 번 되풀이한 질문도 글자로 남는다
        repeated = "hi" * 25_000
        body = fl(1, CONV) + fl(2, fl(3, fl(1, repeated))) + fl(9, fv(1, 5))
        self.assertEqual(kinds(body), [("1", "text"), ("2.3.1", "text"), ("9", "bytes")])   # 상한 뒤 값은 풀지 않음
        self.assertIn(("2.3.1", (1, 0, 0), repeated), gp.text_values(body))
        self.assertEqual(gp.encode(body), body)
        records = gp.walk(frame(fl(1, "앞 프레임")) + frame(fv(1, 1) * (gp.MAX_FIELDS + 1)) + frame(fl(1, "뒤")),
                          enveloped=True)
        self.assertEqual([(r["frame"], r["kind"], r.get("reason")) for r in records],
                         [(0, "text", None), (1, "unparsed", "limit"), (2, "unparsed", "limit")])
        with mock.patch.object(gp, "MAX_BODY_BYTES", 10):
            self.unparsed(fv(1, 1) * 6, "too_large")
        with mock.patch.object(gp, "MAX_TEXT_SCAN_BYTES", 8):
            self.unparsed(fl(1, "글자 확인 상한을 넘는 글자"), "limit")
        with mock.patch.object(gp, "MAX_FRAMES", 2):
            self.unparsed(frame(fv(1, 1)) * 3, "limit", enveloped=True)
        self.assertIsNone(gp.encode(fv(1, 1) * (gp.MAX_FIELDS + 1)))

    def test_fuzzed_mutations_never_raise(self):
        rng = random.Random(20261011)
        seeds = [perform_action(), frame(perform_action()) + frame(fl(1, "둘째 프레임")),
                 frame(gzip.compress(perform_action(), mtime=0), 1)]

        def mutate(data: bytes) -> bytes:
            data = bytearray(data)
            for _ in range(rng.randint(1, 4)):
                op = rng.randrange(6)
                pos = rng.randrange(len(data) + 1)
                if op == 0 and data:
                    data[min(pos, len(data) - 1)] ^= 1 << rng.randrange(8)
                elif op == 1 and data:
                    data[min(pos, len(data) - 1)] = rng.randrange(256)
                elif op == 2:
                    data[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 6)))
                elif op == 3:
                    del data[pos:pos + rng.randint(1, 6)]
                elif op == 4:
                    del data[pos:]
                else:
                    start = rng.randrange(len(data) + 1)
                    data[pos:pos] = data[start:start + rng.randint(1, 12)]
            return bytes(data)

        outcomes = {"parsed": 0, "unparsed": 0}
        for index in range(1000):
            seed = seeds[index % len(seeds)]
            body = mutate(seed)
            for enveloped, encoding in ((False, None), (True, "gzip")):
                records = gp.walk(body, enveloped=enveloped, encoding=encoding)
                self.assertIsInstance(records, list)
                values = gp.text_values(body, enveloped=enveloped, encoding=encoding)
                self.assertTrue(all(isinstance(text, str) for _, _, text in values))
                rebuilt = gp.encode(body, enveloped=enveloped, encoding=encoding)
                self.assertTrue(rebuilt is None or isinstance(rebuilt, bytes))
                if values:
                    replaced = gp.replace_text(body, values[0][1], "[MASKED]", enveloped=enveloped, encoding=encoding)
                    self.assertTrue(replaced is None or isinstance(replaced, bytes))
                if not enveloped:
                    outcomes["unparsed" if records and records[0]["kind"] == "unparsed" else "parsed"] += 1
        for _ in range(200):                         # 완전히 무작위인 바이트
            body = bytes(rng.randrange(256) for _ in range(rng.randint(0, 300)))
            gp.walk(body)
            gp.walk(body, enveloped=True, encoding="gzip")
            gp.encode(body)
        self.assertGreater(outcomes["parsed"], 50)   # 변형이 걷기의 여러 갈래를 지났다
        self.assertGreater(outcomes["unparsed"], 50)


class EnvelopeTests(unittest.TestCase):
    def test_frames_and_end_stream(self):
        body = frame(fl(1, "첫째")) + frame(perform_action()) + frame(b'{"metadata":{}}', 2)
        records = gp.walk(body, enveloped=True)
        self.assertEqual([(r["frame"], r["path"], r["kind"]) for r in records][:3],
                         [(0, "1", "text"), (1, "1", "text"), (1, "2.1", "text")])
        self.assertEqual((records[-1]["frame"], records[-1]["kind"]), (2, "end_stream"))
        self.assertIn(("2.3.1", (1, 1, 1, 0), PROMPT), gp.text_values(body, enveloped=True))
        self.assertEqual(gp.encode(body, enveloped=True), body)

    def test_truncated_and_bad_frames(self):
        good = frame(fl(1, "온전"))
        records = gp.walk(good + frame(fl(1, "잘림"))[:-2], enveloped=True)
        self.assertEqual([(r["kind"], r.get("reason")) for r in records],
                         [("text", None), ("unparsed", "truncated_frame")])
        records = gp.walk(good + b"\x00\x00", enveloped=True)
        self.assertEqual(records[-1]["reason"], "truncated_frame")
        self.assertEqual(gp.walk(frame(fl(1, "x"), 0x80), enveloped=True)[0]["reason"], "bad_frame_flags")
        self.assertEqual(gp.walk(frame(b"\x08", 0), enveloped=True)[0]["reason"], "not_protobuf")
        self.assertIsNone(gp.encode(good + b"\x00\x00", enveloped=True))

    def test_gzip_frames(self):
        packed = gzip.compress(perform_action(), mtime=0)
        body = frame(packed, 1)
        self.assertIn(("2.3.1", (0, 1, 1, 0), PROMPT), gp.text_values(body, enveloped=True, encoding="gzip"))
        self.assertEqual(gp.walk(body, enveloped=True)[0]["reason"], "compressed_no_encoding")
        self.assertEqual(gp.walk(body, enveloped=True, encoding="br")[0]["reason"], "unsupported_encoding")
        broken = frame(packed[:-6] + b"\x00" * 6, 1)
        self.assertEqual(gp.walk(broken, enveloped=True, encoding="gzip")[0]["reason"], "decompress_failed")
        bomb = frame(gzip.compress(fl(1, "a" * 5000), mtime=0), 1)
        with mock.patch.object(gp, "MAX_DECOMPRESSED_BYTES", 1000):     # 10/11 검토 뒤: 상한 초과는 limit(깨진 압축과 구분)
            self.assertEqual(gp.walk(bomb, enveloped=True, encoding="gzip")[0]["reason"], "limit")
        self.assertEqual(gp.encode(body, enveloped=True, encoding="gzip"), body)   # 바뀌지 않은 압축 프레임은 그대로

    def test_unary_decompress_helper(self):
        data = perform_action()
        self.assertEqual(gp.decompress(gzip.compress(data), "gzip"), data)
        self.assertEqual(gp.decompress(data, ""), data)
        self.assertEqual(gp.decompress(data, "identity"), data)
        self.assertIsNone(gp.decompress(data, "br"))
        self.assertIsNone(gp.decompress(b"not gzip", "gzip"))


class ReviewFixTests(unittest.TestCase):
    """10/11 검토 확인 반영: 압축 해제 상한은 본문 합계, 읽지 못한 프레임은 풀린 내용을 붙잡지 않음, 검사용 글자 후보."""

    def test_decompression_budget_is_shared_by_all_frames(self):
        packed = frame(gzip.compress(fl(1, "a" * 600), mtime=0), 1)          # 프레임마다 603바이트로 풀림
        with mock.patch.object(gp, "MAX_DECOMPRESSED_BYTES", 1000):
            records = gp.walk(packed + frame(fl(1, "압축 안 한 프레임")) + packed * 2, enveloped=True, encoding="gzip")
            self.assertEqual([(r["frame"], r["kind"], r.get("reason")) for r in records],
                             [(0, "text", None), (1, "text", None), (2, "unparsed", "limit"), (3, "unparsed", "limit")])
            self.assertIsNone(gp.encode(packed * 2, enveloped=True, encoding="gzip"))
            self.assertEqual(gp.decompress(gzip.compress(b"x" * 900), "gzip"), b"x" * 900)   # unary는 그대로 상한 하나
            self.assertIsNone(gp.decompress(gzip.compress(b"x" * 1001), "gzip"))

    def test_frame_bomb_stays_within_one_decompression_budget(self):
        # 0바이트 4 MiB를 gzip한 프레임 255개(본문 약 1 MiB): 고치기 전에는 프레임마다 4 MiB씩 풀어 목록에 붙잡았다(약 1 GiB)
        one = gzip.compress(b"\x00" * gp.MAX_DECOMPRESSED_BYTES, compresslevel=9, mtime=0)
        body = b"".join(frame(one, 1) for _ in range(255))
        tracemalloc.start()
        try:
            records = gp.walk(body, enveloped=True, encoding="gzip")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual([(r["frame"], r.get("reason")) for r in records][:2], [(0, "not_protobuf"), (1, "limit")])
        self.assertEqual({r.get("reason") for r in records[1:]}, {"limit"})
        self.assertLessEqual(peak, 2 * gp.MAX_DECOMPRESSED_BYTES + len(body))

    def test_unparsed_frames_do_not_keep_their_payloads(self):
        one = gzip.compress(b"\x00" * 1000, mtime=0)
        units = gp._parsed_units(frame(one, 1) * 3 + frame(b"\x08"), True, "gzip", gp._Budget())
        self.assertEqual([(unit[1], unit[2], unit[3]) for unit in units], [(None, None, "not_protobuf")] * 4)

    def test_printable_value_read_as_a_message_is_also_a_text_candidate(self):
        # 'Y'(필드 11 fixed64) + '900101-1'(그 값 8바이트) + '2'(필드 6 길이 붙은 값) + '3'(길이 51) + 51자 = 62바이트.
        # 메시지로 읽혀 글자 잎은 51자뿐이고, 원문에 이어진 가짜 주민번호 900101-1234567이 어느 글자 잎에도 없었다
        tail = "4567 is my number, please fill in the form for me o"
        prompt = "Y900101-123" + tail
        self.assertEqual((len(tail), len(prompt.encode())), (51, 62))
        body = fl(1, CONV) + fl(2, fl(3, fl(1, prompt)))
        self.assertEqual(kinds(body), [("1", "text"), ("2.3.1.11", "fixed64"), ("2.3.1.6", "text")])   # 구조 판정 그대로
        values = gp.text_values(body)
        # 감싼 필드 3('\n>' + 질문)도 틀이 출력 가능한 글자라 후보로 나온다. 후보는 자기 잎들보다 앞(문서 순서)
        self.assertEqual(values, [("1", (0,), CONV), ("2.3", (1, 0), fl(1, prompt).decode()),
                                  ("2.3.1", (1, 0, 0), prompt), ("2.3.1.6", (1, 0, 0, 1), tail)])
        self.assertTrue(any(re.fullmatch(r"Y(\d{6}-[1-4]\d{6}).*", text) for _, _, text in values))
        self.assertIsNone(gp.replace_text(body, (1, 0, 0), "[MASKED]"))     # 후보 자리는 메시지라 바꾸지 않는다
        # 진짜 감싼 메시지도 값 전체가 출력 가능하면 후보가 함께 나온다(검사에는 중복이 안전한 쪽)
        self.assertEqual(gp.text_values(fl(5, fl(1, PROMPT))), [("5", (0,), fl(1, PROMPT).decode()), ("5.1", (0, 0), PROMPT)])
        # 틀에 제어 문자가 있으면(대부분의 진짜 메시지: 0x08·0x10·0x12·0x1a 태그) 후보 없음
        self.assertEqual([path for path, _, _ in gp.text_values(perform_action())], ["1", "2.1", "2.3.1", "4.1", "4.2"])
        with mock.patch.object(gp, "MAX_TEXT_SCAN_BYTES", len(body)):        # 후보 확인도 글자 확인 상한을 같이 쓴다
            self.assertEqual([r["kind"] for r, _ in gp.leaves(body, message_text=True)], ["unparsed"])
            self.assertEqual(len(gp.walk(body)), 3)


def random_message(rng: random.Random, depth: int = 0) -> bytes:
    out = b""
    for _ in range(rng.randint(0, 6)):
        number = rng.choice([1, 2, 3, 4, 5, 15, 16, 2047, 2048, 18999, 20000, (1 << 29) - 1])
        choice = rng.randrange(6 if depth < 4 else 5)
        if choice == 0:
            out += fv(number, rng.choice([0, 1, 127, 128, 300, 2 ** 32, 2 ** 63, -5]))
        elif choice == 1:
            out += f32(number, bytes(rng.randrange(256) for _ in range(4)))
        elif choice == 2:
            out += f64(number, bytes(rng.randrange(256) for _ in range(8)))
        elif choice == 3:
            out += fl(number, rng.choice(["", "짧은 글", PROMPT, "x" * rng.choice([1, 127, 128, 300])]))
        elif choice == 4:
            out += fl(number, bytes(rng.randrange(256) for _ in range(rng.randint(0, 40))))
        else:
            out += fl(number, random_message(rng, depth + 1))
    return out


class ReencodeTests(unittest.TestCase):
    def test_round_trip_of_canonical_encodings(self):
        rng = random.Random(7)
        for index in range(400):
            body = random_message(rng)
            with self.subTest(index=index):
                self.assertEqual(gp.encode(body), body)
                enveloped = frame(body) + frame(random_message(rng))
                self.assertEqual(gp.encode(enveloped, enveloped=True), enveloped)

    def test_replace_fixes_every_enclosing_length(self):
        body = perform_action("짧음")
        loc = next(loc for path, loc, _ in gp.text_values(body) if path == "2.3.1")
        before = gp.text_values(body)
        for new in ("", "PGTEST [KR_RRN]", "가" * 60):      # 길이 머리가 1바이트 → 2바이트로 커지는 경우 포함
            with self.subTest(new=len(new)):
                out = gp.replace_text(body, loc, new)
                self.assertIsNotNone(out)
                after = gp.text_values(out)
                expected = [(p, l, new if l == loc else v) for p, l, v in before]
                if new == "":
                    expected = [item for item in expected if item[1] != loc]   # 빈 값은 empty 잎
                    self.assertIn(("2.3.1", "empty"), kinds(out))
                self.assertEqual(after, expected)
                self.assertEqual([r for r in gp.walk(out) if r["loc"] != loc],
                                 [r for r in gp.walk(body) if r["loc"] != loc])
                self.assertEqual(gp.encode(out), out)

    def test_replace_keeps_untouched_bytes_verbatim(self):
        overlong = varint(3 << 3) + b"\x81\x80\x00"          # 군더더기 바이트로 적은 varint 값(읽기는 허용)
        body = overlong + fl(1, fl(2, "바꿀 글"))
        out = gp.replace_text(body, (1, 0), "바뀐 글자")
        self.assertTrue(out.startswith(overlong))
        self.assertEqual(gp.text_values(out), [("1.2", (1, 0), "바뀐 글자")])
        self.assertNotEqual(gp.encode(body), body)            # 정규 인코딩으로 다시 만들면 달라진다(설명대로)

    def test_replace_in_enveloped_and_gzip_frames(self):
        body = frame(fl(1, "그대로")) + frame(perform_action())
        loc = (1, 1, 1, 0)
        out = gp.replace_text(body, loc, "[MASKED]", enveloped=True)
        self.assertEqual(out[:len(frame(fl(1, "그대로")))], frame(fl(1, "그대로")))
        self.assertIn(("2.3.1", loc, "[MASKED]"), gp.text_values(out, enveloped=True))
        packed = frame(gzip.compress(perform_action(), mtime=0), 1)
        out = gp.replace_text(packed, (0, 1, 1, 0), "[MASKED]", enveloped=True, encoding="gzip")
        self.assertEqual(out[0], 1)
        self.assertIn(("2.3.1", (0, 1, 1, 0), "[MASKED]"), gp.text_values(out, enveloped=True, encoding="gzip"))

    def test_replace_rejects_wrong_locations(self):
        body = perform_action()
        for loc in ((), (9,), (1, 1), (1, 3), (0, 0), (1, 1, 1)):    # 없는 자리·메시지·숫자 자리
            with self.subTest(loc=loc):
                self.assertIsNone(gp.replace_text(body, loc, "x"))
        self.assertIsNone(gp.replace_text(b"\x08", (0,), "x"))
        self.assertIsNone(gp.replace_text(frame(body), (5, 0), "x", enveloped=True))
        self.assertEqual(gp.replace_text(body, (3,), b"\x00\x01"), body.replace(fl(6, bytes(range(0, 40, 3))),
                                                                               fl(6, b"\x00\x01")))


if __name__ == "__main__":
    unittest.main()
