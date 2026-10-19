"""8081 업로드 body 교체와 review artifact 저장."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from signature_detector.gateway_runtime import sanitize_uploaded_file


REVIEW_DIR = Path(os.getenv("SIGNATURE_REVIEW_DIR", "/home/ubuntu/llm-gateway/review_artifacts"))


@dataclass(frozen=True)
class FileMaskOutcome:
    sanitized_bytes: bytes
    review_id: str | None
    review_path: Path | None
    elapsed_ms: float
    verify: object | None = None   # HWP·HWPX 재검사 입력(hwp_segments.HwpVerify)


def sanitize_for_upload(filename: str, file_bytes: bytes, request_id: str, detect, *, keep_review: bool = True,
                        **options) -> FileMaskOutcome:
    """keep_review=False(2026-10-11, HWP·HWPX): 검토용 사본을 디스크에 남기지 않는다(review_id 없음 → Review 머리도 없음).
    options는 sanitize_uploaded_file에 그대로(allow_hwp·max_decompressed)."""
    artifacts = sanitize_uploaded_file(filename, file_bytes, request_id, detect, **options)
    if not keep_review:
        return FileMaskOutcome(artifacts.sanitized_bytes, None, None, artifacts.elapsed_ms,
                               getattr(artifacts, "verify", None))
    review_id = uuid.uuid4().hex
    extension = filename.rsplit(".", 1)[-1].lower()
    REVIEW_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    review_path = REVIEW_DIR / f"{review_id}.{extension}"
    review_path.write_bytes(artifacts.review_bytes)
    review_path.chmod(0o600)
    return FileMaskOutcome(artifacts.sanitized_bytes, review_id, review_path, artifacts.elapsed_ms)


def replace_multipart_file(body: bytes, content_type: str, sanitized_bytes: bytes) -> bytes:
    """multipart의 name=file payload만 byte 단위로 교체한다."""

    marker = "boundary="
    if marker not in content_type:
        raise ValueError("multipart boundary is missing")
    boundary = content_type.split(marker, 1)[1].strip().strip('"').encode("ascii")
    delimiter = b"--" + boundary
    if delimiter in sanitized_bytes:
        # 2026-10-11(명세 §3.5): 바꿔 넣을 바이트(가린 PDF·DOCX 압축열)에 경계 문자열이 우연히 들어 있으면
        # 받는 쪽이 파일을 거기서 끊어 읽는다 - 보내지 않는다(호출 쪽이 503 + 기록)
        raise ValueError("multipart boundary inside the replacement bytes")
    chunks = body.split(delimiter)
    replaced = 0
    output = [chunks[0]]
    for chunk in chunks[1:]:
        if b'name="file"' in chunk or b"name=file" in chunk:
            header_end = chunk.find(b"\r\n\r\n")
            if header_end < 0:
                raise ValueError("multipart file headers are malformed")
            payload_start = header_end + 4
            payload_end = len(chunk) - 2 if chunk.endswith(b"\r\n") else len(chunk)
            chunk = chunk[:payload_start] + sanitized_bytes + chunk[payload_end:]
            replaced += 1
        output.append(chunk)
    if replaced != 1:
        raise ValueError(f"expected one multipart file part, found {replaced}")
    return delimiter.join(output)


def load_review_artifact(review_id: str):
    # Original reviews contain secrets. Disable legacy unauthenticated delivery.
    if os.getenv('SIGNATURE_PRIVATE_REVIEW_DOWNLOAD', '0') != '1':
        return None
    if len(review_id) != 32 or any(char not in "0123456789abcdef" for char in review_id):
        return None
    matches = list(REVIEW_DIR.glob(f"{review_id}.*"))
    if len(matches) != 1:
        return None
    path = matches[0]
    return path.name, path.read_bytes()
