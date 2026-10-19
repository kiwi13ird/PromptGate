"""Claude 새 화면 rpc 본문(protobuf)을 스키마 없이 읽는다 (2026-10-11).

claude.ai 새 화면은 질문을 POST …/claudeai-rpc/…ConversationService/PerformAction 으로 보낸다.
  application/proto          Connect unary: 본문 전체가 protobuf 메시지 하나(압축은 Content-Encoding)
  application/connect+proto  Connect stream: 5바이트 머리(표시 1 + 길이 4, big-endian) + 메시지, 여러 개
                             표시 0x01 = 압축(connect-content-encoding, gzip만 품), 0x02 = 끝 메시지(JSON)
스키마(.proto)가 없으므로 wire 형식만 따라간다: varint(0)·fixed64(1)·길이 붙은 값(2)·fixed32(5).
그룹(3·4)과 6·7은 쓰지 않는 형식이라 틀린 것으로 본다(proto3에는 그룹이 없다). 단 values_at(질문 칸 찾기)은 표준 파서처럼
그룹을 건너뛰고 예약 번호·최소 길이가 아닌 varint도 받는다(아래 '넉넉한 읽기').

길이 붙은 값(2)이 메시지인지 글자인지 바이트인지는 스키마 없이는 정할 수 없다. 규칙(blackboxprotobuf·
protoc --decode_raw처럼 메시지 먼저, 거기에 글자 쪽 예외를 더함):
  1. 길이 0                                         → empty
  2. 메시지로 끝까지 읽히지 않음                     → 출력 가능한 UTF-8이면 text, 아니면 bytes
     (메시지로 읽힘 = 필드 번호 1..2^29-1이고 19000~19999(예약)가 아님, wire 0·1·2·5, 길이가 범위 안,
      태그·길이 varint가 최소 길이로 적힘, 남는 바이트 없음)
  3. 메시지로 읽히는데 그 메시지 자신의 틀 바이트(태그·길이 머리·varint 값·fixed 값, 안쪽 길이 붙은 값의
     내용은 뺌)에 제어 문자(\\t\\n\\r 말고)가 있음        → message (글자일 수 없다)
  4. 메시지로 읽히고 틀 바이트가 모두 출력 가능한데,
     a) 틀 바이트에 0x80 이상, 또는 길이 머리가 아닌 자리에 공백(0x20)이 있거나
     b) 길이 붙은 필드가 하나도 없으면(숫자만 있는 메시지)
     본문 전체가 출력 가능한 UTF-8이면 text, 아니면 message
  5. 그 밖                                           → message
  출력 가능 = 엄격한 UTF-8이고 제어 문자(Cc)가 \\t\\n\\r 말고 없음.
  근거: 진짜 메시지의 공백·한글은 안쪽 문자열 내용에 있고 틀 바이트는 이진값이다. 글자를 메시지로 잘못 읽으면
  공백·한글 바이트가 태그·varint 자리에 떨어진다. 예) '\\n"PGTEST 주민번호 …'는 필드 1(길이 34)짜리 메시지
  (틀 = 0x0a 0x22, 공백·한글은 안쪽) → message, 안쪽은 text. 'hi'는 {13: 105}로 읽히지만 숫자만 → text.
  남는 모호함(스키마 없이는 못 가름): packed 숫자 배열 [8, 1]은 메시지 {1: 1}과 바이트가 같다 → message.
  [1, 2, 3]처럼 메시지로 안 읽히면 bytes. 틀이 모두 출력 가능하고 공백이 없는 짧은 메시지와 같은 바이트의 글자
  (예: 'b%' + 37자)는 message로 본다.

상한(넘으면 예외 대신 'unparsed'): 본문 MAX_BODY_BYTES, 깊이 MAX_DEPTH(넘는 곳은 메시지로 풀지 않고 text/bytes),
필드 수 MAX_FIELDS(실패한 시도 포함. 최상위에서 넘으면 unparsed, 안쪽 값에서 넘으면 그 값부터 메시지로 풀지 않고
text/bytes), 글자 확인 바이트 MAX_TEXT_SCAN_BYTES, 프레임 MAX_FRAMES, 압축 해제 MAX_DECOMPRESSED_BYTES(본문 전체 합계:
모든 압축 프레임을 합쳐 센다. 남은 예산을 넘는 프레임은 넘는 순간 멈추고 'limit'. unary 압축 decompress()는 상한 하나).
읽지 못한 프레임은 풀린 내용을 붙잡지 않는다(길이만). 공개 함수는 예외를 밖으로 내보내지 않는다.

알려진 한계(구조 기록): 글자가 메시지로 잘못 읽히면 그 글자의 틀 바이트(태그·길이 머리)가 잎 경로의 필드 번호와 len으로
남는다. 잘못 읽힌 단계마다 태그 글자 1자 + 길이 값 수준(예 '* 김철수 …' 34바이트 → 경로 끝 5(0x2A '*')·len 32(0x20 ' ')).
값·부분 문자열 자체는 기록에 들어가지 않는다.

제공:
  leaves(body, enveloped=, encoding=) -> [(기록, 값)]   값은 text면 str, bytes면 bytes, 그 밖은 None
  walk(...)        -> [기록]  기록 = {"path": "1.3.2", "loc": (0, 4, 1), "wire": 2, "length": 34, "kind": "text"}
                      (enveloped면 "frame": 번호, loc 맨 앞이 프레임 번호). kind: text·bytes·empty·varint·fixed32·
                      fixed64·end_stream·unparsed(+ "reason")
  text_values(...) -> [(path, loc, 글자)]  검사용(로그에 쓰지 않는다). 메시지로 읽힌 길이 붙은 값도 값 전체가 출력 가능한
                      UTF-8이면 그 원문을 후보로 함께 낸다(자기 잎들보다 앞). 메시지로 잘못 읽힌 질문의 태그·varint·fixed
                      자리에 떨어진 글자(예: 주민번호 앞부분)도 검사 글자에 남게(10/11 검토). 구조 판정(walk)은 그대로.
                      상한을 넘으면 빈 목록 → 검사하는 쪽은 leaves()의 unparsed를 함께 볼 것
  encode(...)      -> 다시 만든 본문(정규 인코딩이면 원본과 같다) 또는 None
  replace_text(body, loc, 새 값, ...) -> 그 자리 값을 바꾸고 감싼 길이를 모두 고친 본문 또는 None
  values_at(body, "2.3") -> ([(loc, 원본 바이트)], 사유)  unary 본문에서 정확한 경로의 길이 붙은 값 전부(10/11 질문 검사용).
                      글자·메시지 판정을 거치지 않는다: 경로 중간만 메시지로 읽고 끝 값은 종류와 상관없이 원본 바이트.
                      끝 값 안은 읽지 않으므로 질문 내용이 상한·판정에 영향을 주지 않는다.
                      본문·경로 중간은 표준 파서만큼 넉넉하게 읽는다(예약 번호·그룹·최소 길이가 아닌 varint 받음, 10/11 밤 검토).
                      위 '메시지로 읽힘' 규칙(엄격)은 구조 판정·replace_text에만 쓴다
"""

from __future__ import annotations

import re
import zlib

MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_FIELDS = 20_000
MAX_TEXT_SCAN_BYTES = 16 * 1024 * 1024
MAX_FRAMES = 1_000
MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024

WIRE_VARINT, WIRE_I64, WIRE_LEN, WIRE_I32 = 0, 1, 2, 5
WIRE_START_GROUP, WIRE_END_GROUP = 3, 4      # values_at의 넉넉한 읽기만 건너뛴다(구조 판정에서는 틀린 것)
_MAX_FIELD_NUMBER = (1 << 29) - 1
_RESERVED_FIELDS = range(19000, 20000)
FLAG_COMPRESSED, FLAG_END_STREAM = 0x01, 0x02
# 출력 가능 판정: \t\n\r 말고 C0·DEL·C1 제어 문자(유니코드 Cc 전부)
_CONTROL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_TEXT_FRAMING_BYTES = (0x09, 0x0A, 0x0D)

# 'unparsed' 사유(고정 낱말만. 본문 값은 들어가지 않는다)
REASONS = ("not_protobuf", "too_large", "limit", "truncated_frame", "bad_frame_flags", "compressed_no_encoding",
           "unsupported_encoding", "decompress_failed", "error")


class _Limit(Exception):
    """상한을 넘음(밖으로 나가지 않는다)."""


class _Field:
    __slots__ = ("number", "wire", "start", "tag_end", "value_start", "end", "kind", "children", "whole_text")

    def __init__(self, number, wire, start, tag_end, value_start, end):
        self.number = number
        self.wire = wire
        self.start = start            # 태그 첫 바이트
        self.tag_end = tag_end        # 태그 끝(길이 붙은 값이면 길이 머리 시작)
        self.value_start = value_start
        self.end = end
        self.kind = None
        self.children = None
        self.whole_text = None        # 메시지일 때 값 전체가 출력 가능한 글자인지: None = 아직 모름, False = 아님


class _Budget:
    __slots__ = ("fields", "scan", "inflate")

    def __init__(self):
        self.fields = MAX_FIELDS
        self.scan = MAX_TEXT_SCAN_BYTES
        self.inflate = MAX_DECOMPRESSED_BYTES     # 압축 프레임을 모두 합친 해제 바이트(10/11 검토: 프레임마다 따로였음)


def _read_varint(buf, pos: int, end: int, *, minimal: bool = False):
    """(값, 다음 위치) 또는 (None, 위치). 10바이트·2^64를 넘으면 실패. minimal이면 0으로 끝나는 군더더기 바이트도 실패."""
    result = shift = 0
    start = pos
    while pos < end:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if result >> 64:
                return None, pos
            if minimal and byte == 0 and pos - start > 1:
                return None, pos
            return result, pos
        shift += 7
        if shift >= 70:
            return None, pos
    return None, pos


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _parse_fields(buf, start: int, end: int, budget: _Budget):
    """buf[start:end]를 메시지로 읽는다. 끝까지 틀림없이 읽히면 필드 목록, 아니면 None."""
    fields = []
    pos = start
    while pos < end:
        budget.fields -= 1
        if budget.fields < 0:
            raise _Limit()
        field_start = pos
        tag, pos = _read_varint(buf, pos, end, minimal=True)
        if tag is None or pos - field_start > 5:
            return None
        number, wire = tag >> 3, tag & 7
        if number < 1 or number > _MAX_FIELD_NUMBER or number in _RESERVED_FIELDS:
            return None
        tag_end = pos
        if wire == WIRE_VARINT:
            value, value_end = _read_varint(buf, pos, end)
            if value is None:
                return None
            field = _Field(number, wire, field_start, tag_end, tag_end, value_end)
        elif wire == WIRE_I64 or wire == WIRE_I32:
            value_end = pos + (8 if wire == WIRE_I64 else 4)
            if value_end > end:
                return None
            field = _Field(number, wire, field_start, tag_end, tag_end, value_end)
        elif wire == WIRE_LEN:
            length, value_start = _read_varint(buf, pos, end, minimal=True)
            if length is None or length > end - value_start:
                return None
            field = _Field(number, wire, field_start, tag_end, value_start, value_start + length)
        else:
            return None
        fields.append(field)
        pos = field.end
    return fields


# ---- 넉넉한 읽기(values_at의 경로 걷기용, 10/11 밤 검토) ----
# 질문 칸을 찾는 길은 표준 protobuf 파서가 받아들이는 본문을 모두 받아들여야 한다. 더 엄격하면 직접 만든 요청이
# 서버는 읽는 바이트 하나(예약 번호·모르는 그룹·최소 길이가 아닌 varint)로 질문을 검사 밖으로 뺄 수 있다.
# 기준(로컬 protoc 29.3로 확인 + Go protowire·prost 규칙): 태그·길이 varint는 10바이트까지 받음(protoc는 5바이트까지,
# Go·prost는 10바이트까지), 값 varint는 10바이트까지(10번째 바이트의 넘친 비트는 protoc처럼 버림), 예약 번호
# 19000~19999 받음, 그룹(3)은 번호가 같은 끝(4)까지 한 필드로 건너뜀(안쪽 그룹 포함, 깊이 제한 없음 - 필드 수 상한만).
# 틀린 것(표준 파서도 틀림): 필드 번호 0·2^29 이상, 짝 없는 그룹 끝·번호가 다른 끝·닫히지 않은 그룹, wire 6·7,
# 범위를 넘는 길이, 잘린 값, 10바이트를 넘는 varint, 2^64를 넘는 태그·길이.
# 정규 인코딩 본문에서는 _parse_fields와 같은 필드 목록(같은 자리 번호)을 낸다. 구조 판정·replace_text는 엄격한 쪽 그대로.

def _skip_varint(buf, pos: int, end: int):
    """값 varint 다음 위치 또는 None(10바이트를 넘거나 잘림). 값은 쓰지 않으므로 넘친 비트는 묻지 않는다."""
    limit = min(end, pos + 10)
    while pos < limit:
        byte = buf[pos]
        pos += 1
        if not byte & 0x80:
            return pos
    return None


def _lenient_tag(buf, pos: int, end: int, budget: _Budget):
    """(필드 번호, wire, 다음 위치) 또는 None. 태그 varint의 길이는 묻지 않고 예약 번호도 받는다. 필드 수 상한을 같이 쓴다."""
    budget.fields -= 1
    if budget.fields < 0:
        raise _Limit()
    tag, pos = _read_varint(buf, pos, end)
    if tag is None:
        return None
    number = tag >> 3
    if number < 1 or number > _MAX_FIELD_NUMBER:
        return None
    return number, tag & 7, pos


def _lenient_scalar_end(buf, wire: int, pos: int, end: int):
    """wire 0·1·5 값의 끝 위치 또는 None."""
    if wire == WIRE_VARINT:
        return _skip_varint(buf, pos, end)
    value_end = pos + (8 if wire == WIRE_I64 else 4)
    return value_end if value_end <= end else None


def _lenient_length(buf, pos: int, end: int):
    """길이 붙은 값의 (내용 시작, 끝) 또는 None. 길이 varint의 최소 길이는 묻지 않는다."""
    length, value_start = _read_varint(buf, pos, end)
    if length is None or length > end - value_start:
        return None
    return value_start, value_start + length


def _skip_group(buf, pos: int, end: int, number: int, budget: _Budget):
    """그룹 시작 태그 바로 뒤에서, 번호가 같은 끝 태그 뒤 위치까지 건너뛴다(안쪽 그룹은 쌓아 둠, 재귀 없음). 틀리면 None."""
    open_groups = [number]
    while pos < end:
        tag = _lenient_tag(buf, pos, end, budget)
        if tag is None:
            return None
        inner, wire, pos = tag
        if wire == WIRE_LEN:
            span = _lenient_length(buf, pos, end)
            if span is None:
                return None
            pos = span[1]
        elif wire == WIRE_START_GROUP:
            open_groups.append(inner)
        elif wire == WIRE_END_GROUP:
            if open_groups.pop() != inner:
                return None
            if not open_groups:
                return pos
        elif wire in (WIRE_VARINT, WIRE_I64, WIRE_I32):
            pos = _lenient_scalar_end(buf, wire, pos, end)
            if pos is None:
                return None
        else:
            return None
    return None


def _parse_fields_lenient(buf, start: int, end: int, budget: _Budget):
    """buf[start:end]를 표준 파서만큼 넉넉하게 메시지로 읽는다(위 설명). 필드 목록 또는 None. 그룹은 wire 3 필드 하나."""
    fields = []
    pos = start
    while pos < end:
        field_start = pos
        tag = _lenient_tag(buf, pos, end, budget)
        if tag is None:
            return None
        number, wire, pos = tag
        if wire == WIRE_LEN:
            span = _lenient_length(buf, pos, end)
            if span is None:
                return None
            field = _Field(number, wire, field_start, pos, span[0], span[1])
        elif wire == WIRE_START_GROUP:
            group_end = _skip_group(buf, pos, end, number, budget)
            if group_end is None:
                return None
            field = _Field(number, wire, field_start, pos, pos, group_end)
        elif wire in (WIRE_VARINT, WIRE_I64, WIRE_I32):
            value_end = _lenient_scalar_end(buf, wire, pos, end)
            if value_end is None:
                return None
            field = _Field(number, wire, field_start, pos, pos, value_end)
        else:       # 짝 없는 그룹 끝(4), 6, 7
            return None
        fields.append(field)
        pos = field.end
    return fields


def _framing(buf, fields):
    """(제어 문자 있음, 0x80 이상 있음, 길이 머리 밖 공백 있음, 길이 붙은 필드 있음) - 메시지 자신의 틀 바이트만 본다."""
    control = high = space = has_len = False
    for field in fields:
        if field.wire == WIRE_LEN:
            has_len = True
            scalar = buf[field.start:field.tag_end]
            length_prefix = buf[field.tag_end:field.value_start]
        else:
            scalar = buf[field.start:field.end]
            length_prefix = b""
        for byte in scalar:
            if byte >= 0x80:
                high = True
            elif byte == 0x20:
                space = True
            elif (byte < 0x20 and byte not in _TEXT_FRAMING_BYTES) or byte == 0x7F:
                control = True
        for byte in length_prefix:
            if byte >= 0x80:
                high = True
            elif (byte < 0x20 and byte not in _TEXT_FRAMING_BYTES) or byte == 0x7F:
                control = True
    return control, high, space, has_len


def _printable_text(buf, start: int, end: int, budget: _Budget):
    budget.scan -= end - start
    if budget.scan < 0:
        raise _Limit()
    try:
        text = bytes(buf[start:end]).decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _CONTROL_RE.search(text):
        return None
    return text


def _classify(buf, field: _Field, depth: int, budget: _Budget) -> None:
    """길이 붙은 필드 하나의 종류를 정한다(모듈 설명의 규칙). 메시지면 안쪽도 정한다."""
    start, end = field.value_start, field.end
    if start == end:
        field.kind = "empty"
        return
    try:
        children = _parse_fields(buf, start, end, budget) if depth < MAX_DEPTH else None
    except _Limit:
        # 필드 수 상한: 이 값부터는 메시지로 풀지 않고 글자·바이트로 본다(본문 전체를 unparsed로 만들지 않는다.
        # 예: 'hi'를 수만 번 되풀이한 질문은 숫자 필드 수만 개로도 읽혀 상한을 넘는다 → 글자로 남아야 검사된다)
        children = None
    if children is None:
        field.kind = "text" if _printable_text(buf, start, end, budget) is not None else "bytes"
        return
    control, high, space, has_len = _framing(buf, children)
    if control:
        field.whole_text = False
    elif high or space or not has_len:
        if _printable_text(buf, start, end, budget) is not None:
            field.kind = "text"
            return
        field.whole_text = False
    field.kind = "message"
    field.children = children
    for child in children:
        if child.wire == WIRE_LEN:
            _classify(buf, child, depth + 1, budget)


def _parse_message(buf, budget: _Budget):
    """최상위 메시지(본문 또는 프레임 하나). 메시지로 읽히지 않으면 None."""
    fields = _parse_fields(buf, 0, len(buf), budget)
    if fields is None:
        return None
    for field in fields:
        if field.wire == WIRE_LEN:
            _classify(buf, field, 1, budget)
    return fields


def _inflate(data: bytes, encoding: str | None, limit: int):
    """(풀린 바이트, None) 또는 (None, 사유). 사유: unsupported_encoding · limit(limit 바이트를 넘음) · decompress_failed.
    limit + 1 바이트까지만 푼다(넘는 순간 멈춤)."""
    name = (encoding or "").strip().lower()
    if name in ("", "identity"):
        return bytes(data), None
    if name == "gzip":
        wbits = 16 + zlib.MAX_WBITS
    elif name == "deflate":
        wbits = zlib.MAX_WBITS
    else:
        return None, "unsupported_encoding"
    limit = max(0, int(limit))        # max_length 0은 '끝없이'라서 늘 1 이상을 넘긴다
    try:
        decoder = zlib.decompressobj(wbits)
        out = decoder.decompress(data, limit + 1)
        if len(out) > limit:
            return None, "limit"
        if decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
            return None, "decompress_failed"
        return out, None
    except (zlib.error, ValueError, OverflowError):
        return None, "decompress_failed"


def decompress(data: bytes, encoding: str | None, limit: int | None = None):
    """gzip·deflate를 상한(기본 MAX_DECOMPRESSED_BYTES) 안에서 푼다. 'identity'·빈 값은 그대로. 모르는 방식·실패·상한 초과는 None."""
    return _inflate(data, encoding, MAX_DECOMPRESSED_BYTES if limit is None else limit)[0]


def _leaf_records(buf, fields, path, loc, frame, out, candidates=None):
    """candidates(검사용일 때만 _Budget): 메시지로 읽힌 값도 값 전체가 출력 가능한 글자면 text 후보 기록을 먼저 낸다."""
    for index, field in enumerate(fields):
        field_path = path + (str(field.number),)
        field_loc = loc + (index,)
        if field.wire == WIRE_LEN and field.kind == "message":
            if candidates is not None and field.whole_text is None:
                text = _printable_text(buf, field.value_start, field.end, candidates)
                if text is not None:
                    record = {"path": ".".join(field_path), "loc": field_loc, "wire": field.wire,
                              "length": field.end - field.value_start, "kind": "text", "message_text": True}
                    if frame is not None:
                        record["frame"] = frame
                    out.append((record, text))
            _leaf_records(buf, field.children, field_path, field_loc, frame, out, candidates)
            continue
        if field.wire == WIRE_VARINT:
            kind, value = "varint", None
        elif field.wire == WIRE_I64:
            kind, value = "fixed64", None
        elif field.wire == WIRE_I32:
            kind, value = "fixed32", None
        else:
            kind = field.kind
            raw = bytes(buf[field.value_start:field.end])
            value = raw.decode("utf-8") if kind == "text" else (raw if kind == "bytes" else None)
        record = {"path": ".".join(field_path), "loc": field_loc, "wire": field.wire,
                  "length": field.end - field.value_start, "kind": kind}
        if frame is not None:
            record["frame"] = frame
        out.append((record, value))


def _unparsed(length: int, reason: str, frame=None, loc=()):
    record = {"path": "", "loc": loc, "wire": None, "length": length, "kind": "unparsed", "reason": reason}
    if frame is not None:
        record["frame"] = frame
    return record, None


def _frames(body: bytes):
    """[(번호, 표시, 내용 시작, 끝)] 또는 틀린 곳에서 멈추고 (번호, None, 위치, 길이 끝)을 마지막에 둔다."""
    frames = []
    pos = 0
    while pos < len(body):
        index = len(frames)
        if index >= MAX_FRAMES:
            raise _Limit()
        if len(body) - pos < 5:
            frames.append((index, None, pos, len(body)))
            break
        flags = body[pos]
        length = int.from_bytes(body[pos + 1:pos + 5], "big")
        start = pos + 5
        if length > len(body) - start:
            frames.append((index, None, pos, len(body)))
            break
        frames.append((index, flags, start, start + length))
        pos = start + length
    return frames


def _frame_payload(body: bytes, flags: int, start: int, end: int, encoding, budget: _Budget):
    """(내용 또는 None, 사유). 압축 프레임은 본문 전체가 같이 쓰는 해제 예산(budget.inflate) 안에서만 푼다."""
    if flags & ~(FLAG_COMPRESSED | FLAG_END_STREAM):
        return None, "bad_frame_flags"
    if not flags & FLAG_COMPRESSED:
        return body[start:end], None
    name = (encoding or "").strip().lower()
    if name in ("", "identity"):
        return None, "compressed_no_encoding"
    if name not in ("gzip", "deflate"):
        return None, "unsupported_encoding"
    payload, reason = _inflate(body[start:end], name, budget.inflate)
    if payload is None:
        return None, reason
    budget.inflate -= len(payload)
    return payload, None


def _parsed_units(body: bytes, enveloped: bool, encoding, budget: _Budget):
    """[(프레임 번호 또는 None, 내용, 필드 목록 또는 None, 사유, 길이)] - leaves·encode·replace_text가 같이 쓴다.

    읽지 못한 프레임은 내용을 None으로 두고 길이만 남긴다(풀린 내용을 목록에 붙잡지 않는다. 10/11 검토)."""
    if not enveloped:
        return [(None, body, _parse_message(body, budget), "not_protobuf", len(body))]
    units = []
    for index, flags, start, end in _frames(body):
        if flags is None:
            units.append((index, None, None, "truncated_frame", 0))
            continue
        if flags & FLAG_END_STREAM and not flags & ~(FLAG_COMPRESSED | FLAG_END_STREAM):
            units.append((index, body[start:end], "end_stream", None, end - start))
            continue
        payload, reason = _frame_payload(body, flags, start, end, encoding, budget)
        if payload is None:
            units.append((index, None, None, reason, end - start))
            continue
        try:
            fields, reason = _parse_message(payload, budget), "not_protobuf"
        except _Limit:      # 상한(본문 전체가 같이 쓴다)을 넘은 프레임만 unparsed. 앞 프레임 결과는 남긴다
            fields, reason = None, "limit"
        units.append((index, payload if fields is not None else None, fields, reason, len(payload)))
    return units


def leaves(body, *, enveloped: bool = False, encoding: str | None = None, message_text: bool = False):
    """잎 목록 [(기록, 값)]. 값: text → str, bytes → bytes, 그 밖 → None. 예외를 내보내지 않는다.

    enveloped: application/connect+proto(5바이트 머리 프레임). encoding: connect-content-encoding(프레임 압축).
    message_text: 검사용. 메시지로 읽힌 길이 붙은 값도 값 전체가 출력 가능한 UTF-8이면 text 후보 기록
    ({"kind": "text", "message_text": True}, 값 = 원문)을 그 자리 잎들보다 먼저 낸다. 글자 확인 상한을 같이 쓴다."""
    try:
        body = bytes(body or b"")
        if len(body) > MAX_BODY_BYTES:
            return [_unparsed(len(body), "too_large")]
        budget = _Budget()
        out = []
        for frame, payload, fields, reason, length in _parsed_units(body, enveloped, encoding, budget):
            loc = (frame,) if frame is not None else ()
            if fields == "end_stream":
                record = {"path": "", "loc": loc, "wire": None, "length": length, "kind": "end_stream",
                          "frame": frame}
                out.append((record, None))
            elif fields is None:
                out.append(_unparsed(length, reason, frame, loc))
            else:
                _leaf_records(payload, fields, (), loc, frame, out, budget if message_text else None)
        return out
    except _Limit:
        return [_unparsed(len(body or b""), "limit")]
    except Exception:   # 마지막 안전망: 걷기는 절대 요청 처리를 깨지 않는다
        return [_unparsed(len(body or b""), "error")]


def walk(body, *, enveloped: bool = False, encoding: str | None = None) -> list[dict]:
    """값 없는 잎 기록만."""
    return [record for record, _ in leaves(body, enveloped=enveloped, encoding=encoding)]


def text_values(body, *, enveloped: bool = False, encoding: str | None = None) -> list[tuple]:
    """[(path, loc, 글자)] - 검사할 글자(메시지로 읽힌 출력 가능한 값의 원문 후보 포함). 로그에 쓰지 않는다."""
    return [(record["path"], record["loc"], value)
            for record, value in leaves(body, enveloped=enveloped, encoding=encoding, message_text=True)
            if record["kind"] == "text"]


def values_at(body, path, *, max_bytes: int = MAX_BODY_BYTES):
    """unary 본문(압축을 푼 것)에서 필드 번호 경로(예 "2.3")에 있는 길이 붙은 값을 모두 찾는다(2026-10-11, 질문 검사).

    leaves()와 달리 글자·메시지 판정을 하지 않는다. 경로 중간(예 2)만 메시지로 읽고, 끝(예 3)은 text·bytes·message
    어느 쪽으로 읽힐 값이든 원본 바이트를 그대로 낸다 - 질문 글자가 메시지처럼 읽히거나(예 '* 김철수 …') 제어 문자가 들어
    있어도(bytes) 검사에서 빠지지 않게. 끝 값 안은 읽지 않으므로 질문 내용이 필드 수·글자 확인 상한이나 판정에 영향을 주지
    않는다(바깥 틀은 브라우저의 인코더가 만든다). 반복 필드(같은 번호가 여러 번)는 모두.

    본문·경로 중간은 표준 protobuf 파서만큼 넉넉하게 읽는다(_parse_fields_lenient, 10/11 밤 검토: 예약 번호·모르는 그룹·
    최소 길이가 아닌 varint 하나로 질문 칸을 놓치지 않게). 그룹은 필드 하나로 셈(자리 번호 1칸).

    반환 (값 목록, 사유). 값 = (loc, 바이트): loc는 walk·replace_text의 'loc'와 같은 자리(최상위부터 필드 위치,
    정규 인코딩 본문에서). 사유 None = 경로를 끝까지 읽음(값이 없을 수 있다).
    사유 낱말 = 읽지 못한 곳이 있음: too_large·limit·error·최상위 not_protobuf → 값 없음.
    경로 중간 값(예 2)이 넉넉하게 읽어도 메시지가 아니면 'not_protobuf'와 함께 읽은 갈래의 값은 그대로 낸다(조용히 빠뜨리지 않음).
    예외를 내보내지 않는다."""
    try:
        body = bytes(body or b"")
        if len(body) > max_bytes:
            return [], "too_large"
        numbers = [int(part) for part in str(path).split(".")]
        if not numbers or any(number < 1 for number in numbers):
            return [], "error"
        budget = _Budget()
        fields = _parse_fields_lenient(body, 0, len(body), budget)
        if fields is None:
            return [], "not_protobuf"
        found = []
        unreadable = False
        level = [(fields, ())]
        last = len(numbers) - 1
        for depth, number in enumerate(numbers):
            next_level = []
            for current, loc in level:
                for index, field in enumerate(current):
                    if field.number != number or field.wire != WIRE_LEN:
                        continue
                    if depth == last:
                        found.append((loc + (index,), body[field.value_start:field.end]))
                        continue
                    children = _parse_fields_lenient(body, field.value_start, field.end, budget)
                    if children is None:
                        unreadable = True        # 이 갈래는 메시지가 아님(표준 파서도 못 읽음) → 사유를 남김
                    elif children:
                        next_level.append((children, loc + (index,)))
            level = next_level
        found.sort(key=lambda item: item[0])
        return found, ("not_protobuf" if unreadable else None)
    except _Limit:
        return [], "limit"
    except Exception:
        return [], "error"


def _encode_fields(buf, fields) -> bytes:
    """정규 인코딩으로 다시 만든다(태그·varint·길이를 최소 길이로). 정규 입력이면 원본과 같다."""
    out = bytearray()
    for field in fields:
        out += _encode_varint((field.number << 3) | field.wire)
        if field.wire == WIRE_VARINT:
            out += _encode_varint(_read_varint(buf, field.value_start, field.end)[0])
        elif field.wire == WIRE_LEN:
            payload = (_encode_fields(buf, field.children) if field.kind == "message"
                       else bytes(buf[field.value_start:field.end]))
            out += _encode_varint(len(payload)) + payload
        else:
            out += buf[field.value_start:field.end]
    return bytes(out)


def _frame_bytes(flags: int, payload: bytes) -> bytes:
    return bytes([flags]) + len(payload).to_bytes(4, "big") + payload


def _recompress(payload: bytes, encoding) -> bytes:
    name = (encoding or "").strip().lower()
    if name == "gzip":
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    else:
        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


def _rebuild_units(body: bytes, enveloped: bool, encoding, change):
    """프레임(또는 본문) 하나씩 change(번호, 내용, 필드)로 새 내용을 받아 다시 붙인다. None이 하나라도 있으면 None."""
    budget = _Budget()
    if len(body) > MAX_BODY_BYTES:
        return None
    units = _parsed_units(body, enveloped, encoding, budget)
    if not enveloped:
        _, payload, fields, _, _ = units[0]
        return None if fields is None else change(None, payload, fields)
    frames = {index: (flags, start, end) for index, flags, start, end in _frames(body)}
    out = bytearray()
    for index, payload, fields, _, _ in units:
        flags, start, end = frames[index]
        if fields is None or flags is None:
            return None
        if fields == "end_stream":
            out += body[start - 5:end]
            continue
        new_payload = change(index, payload, fields)
        if new_payload is None:
            return None
        if new_payload == payload:
            out += body[start - 5:end]          # 바뀌지 않은 프레임은 원래 바이트(압축 포함) 그대로
        elif flags & FLAG_COMPRESSED:
            out += _frame_bytes(flags, _recompress(new_payload, encoding))
        else:
            out += _frame_bytes(flags, new_payload)
    return bytes(out)


def encode(body, *, enveloped: bool = False, encoding: str | None = None):
    """읽은 구조를 정규 인코딩으로 다시 만든 본문. 정규 인코딩 입력이면 원본과 같다. 읽을 수 없으면 None."""
    try:
        return _rebuild_units(bytes(body or b""), enveloped, encoding,
                              lambda _index, payload, fields: _encode_fields(payload, fields))
    except _Limit:
        return None
    except Exception:
        return None


def _replace_in(buf, fields, region, loc, new_payload: bytes):
    """loc 자리 값만 바꾼 region 바이트. 감싼 길이를 모두 고치고 나머지 바이트는 원본 그대로."""
    if not loc or not 0 <= loc[0] < len(fields):
        return None
    target = fields[loc[0]]
    if target.wire != WIRE_LEN:
        return None
    if len(loc) == 1:
        if target.kind == "message":
            return None
        payload = new_payload
    else:
        if target.kind != "message":
            return None
        payload = _replace_in(buf, target.children, (target.value_start, target.end), loc[1:], new_payload)
        if payload is None:
            return None
    return (bytes(buf[region[0]:target.start]) + bytes(buf[target.start:target.tag_end])
            + _encode_varint(len(payload)) + payload + bytes(buf[target.end:region[1]]))


def replace_text(body, loc, new_value, *, enveloped: bool = False, encoding: str | None = None):
    """loc(walk 기록의 'loc') 자리의 text·bytes·empty 값을 new_value(str → UTF-8, bytes)로 바꾼 본문.

    감싼 메시지·프레임 길이를 모두 고친다. 바뀌지 않은 부분은 원래 바이트 그대로. 압축 프레임은 다시 압축한다.
    자리가 틀리거나(메시지·숫자 자리 포함) 본문을 읽을 수 없으면 None(예외 없음)."""
    try:
        body = bytes(body or b"")
        new_payload = new_value.encode("utf-8") if isinstance(new_value, str) else bytes(new_value)
        loc = tuple(loc)
        if enveloped:
            if not loc:
                return None
            frame, inner = loc[0], loc[1:]
        else:
            frame, inner = None, loc
        state = {"hit": False}

        def change(index, payload, fields):
            if index != frame:
                return payload
            state["hit"] = True
            return _replace_in(payload, fields, (0, len(payload)), inner, new_payload)

        rebuilt = _rebuild_units(body, enveloped, encoding, change)
        return rebuilt if rebuilt is not None and state["hit"] else None
    except _Limit:
        return None
    except Exception:
        return None
