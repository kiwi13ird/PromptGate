import json
import urllib.request


EXTENSION_EVENT_URL = "http://127.0.0.1:8766/event"
TIMEOUT_SECONDS = 0.2


def send_extension_event(event: dict):
    """
    Best-effort delivery.
    Extension/WebSocket failure must never affect Gateway BLOCK/PASS.
    """
    try:
        payload = json.dumps(
            event,
            ensure_ascii=False
        ).encode("utf-8")

        request = urllib.request.Request(
            EXTENSION_EVENT_URL,
            data=payload,
            headers={
                "Content-Type": "application/json"
            },
            method="POST",
        )

        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT_SECONDS
        ) as response:
            status = response.getcode()

        print(
            f"[EXTENSION] event sent "
            f"eventId={event.get('eventId')} "
            f"clientId={event.get('clientId')} "
            f"status={status}"
        )

    except Exception as exc:
        print(
            f"[EXTENSION] event delivery failed "
            f"eventId={event.get('eventId')} "
            f"error={type(exc).__name__}"
        )
