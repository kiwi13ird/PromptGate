import asyncio
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from websockets.asyncio.server import serve
from extension_event_view import extension_event_view


clients = {}
event_loop = None
# For GET /status: number of open websocket connections. Only the event loop thread changes it; the HTTP thread only reads it.
connected_count = 0


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
    extension_event = extension_event_view(event)
    if extension_event is None:
        return

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
    global connected_count
    client_id = None
    heartbeat_task = asyncio.create_task(websocket_heartbeat(websocket))

    print(f"[WS] New connection: {websocket.remote_address}")

    connected_count += 1
    try:
        async for raw_message in websocket:
            print("[WS] Received registration/control message")

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
        connected_count -= 1
        heartbeat_task.cancel()
        if client_id and clients.get(client_id) is websocket:
            del clients[client_id]

        print(f"[WS] Disconnected clientId={client_id}")


def status_snapshot():
    """Body of GET /status: counts only (open connections, registered client ids), never the ids themselves."""
    return {"connected": connected_count, "registered": len(clients)}


class EventHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path.split("?", 1)[0] != "/status":
            self.send_response(404)
            self.end_headers()
            return

        try:
            body = json.dumps(status_snapshot()).encode("utf-8")
        except Exception as exc:
            print(f"[HTTP] Status error: {type(exc).__name__}", flush=True)
            self.send_response(500)
            self.end_headers()
            return

        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError as exc:
            print(f"[HTTP] Status reply failed: {type(exc).__name__}", flush=True)

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
