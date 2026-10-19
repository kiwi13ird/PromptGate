"""Byte-preserving Claude multipart file replacement, independent of enforcement."""
import re
from email.parser import BytesParser
from email.policy import default


def replace_files(body, content_type, replacements):
    """Replace filename-bearing parts by ordinal; keep fields and headers untouched."""
    message = BytesParser(policy=default).parsebytes(('Content-Type: ' + content_type + '\r\n\r\n').encode())
    boundary = message.get_boundary()
    if not boundary or len(boundary) > 200:
        raise ValueError('invalid multipart boundary')
    marker = boundary.encode('ascii')
    matches = list(re.finditer(rb'(?:\A|\r\n)--' + re.escape(marker) + rb'(--)?(?:\r\n|\Z)', body))
    if len(matches) < 2 or matches[0].start() != 0 or not matches[-1].group(1):
        raise ValueError('incomplete multipart')
    edits = []
    index = 0
    for current, following in zip(matches, matches[1:]):
        if current.group(1):
            raise ValueError('unexpected closing boundary')
        part_start, part_end = current.end(), following.start()
        separator = body.find(b'\r\n\r\n', part_start, part_end)
        if separator < 0:
            raise ValueError('missing part headers')
        headers = BytesParser(policy=default).parsebytes(body[part_start:separator] + b'\r\n\r\n')
        if headers.get_filename() is not None:
            if index >= len(replacements):
                raise ValueError('file count mismatch')
            original, sanitized = replacements[index]
            if headers.get('Content-Transfer-Encoding', 'binary').lower() not in {'binary', '7bit', '8bit'}:
                raise ValueError('unsupported transfer encoding')
            payload_start = separator + 4
            if body[payload_start:part_end] != original:
                raise ValueError('file payload mismatch')
            if sanitized != original and b'--' + marker in sanitized:
                # 2026-10-11: 바꿔 넣을 바이트(가린 PDF·DOCX)에 경계 문자열이 있으면 받는 쪽이 거기서 끊어 읽는다
                raise ValueError('multipart boundary inside the replacement bytes')
            edits.append((payload_start, part_end, sanitized))
            index += 1
    if index != len(replacements) or not index:
        raise ValueError('file count mismatch')
    for start, end, sanitized in reversed(edits):
        body = body[:start] + sanitized + body[end:]
    return body
