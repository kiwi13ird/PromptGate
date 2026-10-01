import asyncio
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from websockets.asyncio.server import serve


clients = {}
event_loop = None


async def send_to_extension(event):
    client_id = event.get("clientId")

    if not client_id:
        print("[WS] Event missing clientId")
        return

    websocket = clients.get(client_id)

    if websocket is None:
        print(f"[WS] Client not connected: {client_id}")
        return

    # Gateway Event -> Extension Event
    extension_event = {
        "type": "SECURITY_EVENT",
        "eventId": event.get("eventId"),
        "timestamp": event.get("timestamp"),
        "clientId": client_id,
        "targetLlm": event.get("targetLlm", "Unknown"),
        "action": event.get("finalAction", "BLOCK"),
        "severity": "HIGH",
        "detector": "Gateway",
        "matchType": "POLICY"
    }

    await websocket.send(json.dumps(extension_event))

    print(
        f"[WS] Security Event sent "
        f"clientId={client_id} "
        f"action={extension_event['action']}"
    )


async def websocket_heartbeat(websocket):
    try:
        while True:
            await asyncio.sleep(20)
            await websocket.send(json.dumps({"type": "HEARTBEAT"}))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        print(f"[WS] Heartbeat stopped: {exc}")

async def websocket_handler(websocket):
    client_id = None
    heartbeat_task = asyncio.create_task(websocket_heartbeat(websocket))

    print(f"[WS] New connection: {websocket.remote_address}")

    try:
        async for raw_message in websocket:
            print(f"[WS] Received: {raw_message}")

            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                continue

            if message.get("type") == "REGISTER":
                client_id = message.get("clientId")

                if not client_id:
                    continue

                clients[client_id] = websocket

                print(f"[WS] Registered clientId={client_id}")

    finally:
        heartbeat_task.cancel()
        if client_id and clients.get(client_id) is websocket:
            del clients[client_id]

        print(f"[WS] Disconnected clientId={client_id}")


class EventHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/event":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            event = json.loads(body)

            asyncio.run_coroutine_threadsafe(
                send_to_extension(event),
                event_loop
            )

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        except Exception as exc:
            print(f"[HTTP] Event error: {exc}")

            self.send_response(400)
            self.end_headers()

    def log_message(self, format, *args):
        return


def start_http_server():
    server = HTTPServer(("127.0.0.1", 8766), EventHandler)

    print("[HTTP] Gateway Event receiver on 127.0.0.1:8766")

    server.serve_forever()


async def main():
    global event_loop

    event_loop = asyncio.get_running_loop()

    Thread(
        target=start_http_server,
        daemon=True
    ).start()

    print("[WS] Server starting on 0.0.0.0:8765")

    async with serve(websocket_handler, "0.0.0.0", 8765):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
