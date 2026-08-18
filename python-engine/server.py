"""
server.py — Local Real-Time SSE (Server-Sent Events) & API Server
===================================================================
Provides zero-configuration real-time IPC between Python engine and React UI.
Uses Python built-in http.server — no extra dependencies required!

Endpoints:
  GET  http://localhost:5000/events  — SSE stream (live packets, stats, threats)
  POST http://localhost:5000/unblock — Remove Windows Firewall rule for IP
  GET  http://localhost:5000/status  — Health check
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import queue
import time
import logging
from urllib.parse import parse_qs, urlparse

from blocker import unblock_ip

logger = logging.getLogger("cybersentinel.server")

# Event queue for connected SSE clients
_sse_clients = set()
_client_lock = threading.Lock()


class SSEServerHandler(BaseHTTPRequestHandler):
    """HTTP request handler supporting SSE streaming and CORS headers."""

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs
        return

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path == "/events":
            # Server-Sent Events endpoint
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._set_cors_headers()
            self.end_headers()

            client_queue = queue.Queue(maxsize=100)
            with _client_lock:
                _sse_clients.add(client_queue)

            logger.info(f"[SSE] Client connected. Total clients: {len(_sse_clients)}")

            # Send initial connection event
            init_msg = json.dumps({"type": "INIT", "status": "CONNECTED", "timestamp": time.time()})
            try:
                self.wfile.write(f"data: {init_msg}\n\n".encode("utf-8"))
                self.wfile.flush()
            except Exception:
                with _client_lock:
                    _sse_clients.discard(client_queue)
                return

            # Keep stream open and push queued events
            try:
                while True:
                    try:
                        event_data = client_queue.get(timeout=15)
                        payload = f"data: {json.dumps(event_data)}\n\n".encode("utf-8")
                        self.wfile.write(payload)
                        self.wfile.flush()
                    except queue.Empty:
                        # Heartbeat ping every 15s to keep connection alive
                        ping = f"data: {json.dumps({'type': 'PING'})}\n\n".encode("utf-8")
                        self.wfile.write(ping)
                        self.wfile.flush()
            except (ConnectionResetError, BrokenPipeError, Exception):
                pass
            finally:
                with _client_lock:
                    _sse_clients.discard(client_queue)
                logger.info("[SSE] Client disconnected")

        elif parsed_url.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "running", "clients": len(_sse_clients)}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path == "/unblock":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                data = json.loads(body)
                ip = data.get("ip")
                if ip:
                    success = unblock_ip(ip)
                    response = {"success": success, "ip": ip, "message": f"IP {ip} unblocked" if success else "Failed to unblock"}
                else:
                    response = {"success": False, "message": "Missing 'ip' parameter"}
            except Exception as e:
                response = {"success": False, "message": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def broadcast_event(event_type: str, data: dict):
    """Broadcast an event to all connected SSE browser clients."""
    payload = {"type": event_type, "data": data, "timestamp": time.time()}
    with _client_lock:
        stale = set()
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                stale.add(q)
        for q in stale:
            _sse_clients.discard(q)


def start_sse_server(host="0.0.0.0", port=5000):
    """Start the SSE HTTP server in a background daemon thread."""
    server = HTTPServer((host, port), SSEServerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="SSEServerThread")
    server_thread.start()
    logger.info(f"[SSE SERVER] Listening on http://{host}:{port}/events")
    print(f"[+] Real-Time Server listening on http://localhost:{port}/events")
    return server
