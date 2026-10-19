"""Read Gateway-only identity headers and remove them before upstream forwarding."""

import hashlib
import re

# 내 요청 기록(2026-10-09): 확장 프로그램의 열람 키. 값은 남기지 않고 지문(SHA-256)만 대시보드로 보낸다
VIEWER_KEY_HEADER = "x-llmsgw-viewer-key"
_VIEWER_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

IDENTITY_HEADERS = {
    "x-llmsgw-client-id": "client_id",
    "x-llmsgw-tenant-id": "tenant_id",
    "x-llmsgw-extension-version": "extension_version",
}


def read_and_strip_identity(flow) -> dict[str, str]:
    identity: dict[str, str] = {}
    headers = flow.request.headers

    for header_name, field_name in IDENTITY_HEADERS.items():
        value = headers.get(header_name)
        if not value:
            continue

        identity[field_name] = str(value)[:128]
        try:
            del headers[header_name]
        except KeyError:
            pass

    viewer_key = headers.get(VIEWER_KEY_HEADER)
    if viewer_key is not None:
        try:
            del headers[VIEWER_KEY_HEADER]   # 형식이 틀려도 LLM 서비스로는 보내지 않는다
        except KeyError:
            pass
        if _VIEWER_KEY_RE.match(str(viewer_key)):
            identity["viewer_key_hash"] = hashlib.sha256(str(viewer_key).encode("ascii")).hexdigest()

    return identity
