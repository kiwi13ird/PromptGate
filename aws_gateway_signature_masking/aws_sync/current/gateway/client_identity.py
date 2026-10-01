"""Read Gateway-only identity headers and remove them before upstream forwarding."""

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

    return identity
