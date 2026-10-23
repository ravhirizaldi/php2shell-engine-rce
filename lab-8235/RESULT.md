# PHP 8.2.35 mod_php — patched-build negative control

**Status: NEGATIVE — fixed release. The engine chain does not arm.**
The one-shot driver now detects 8.2.35+ and reports the target as not
vulnerable without attempting the chain.

| | |
|---|---|
| Target image | `php@sha256:fa8966fbaaa06981e549e7a33eb8a68f4cf677d6a82e1d6350adc5d85fe8f740` (`php:8.2.35-apache`) |
| libphp.so SHA-256 | `caa626e6e5b520f5921bb0d9f01781a7cf0b9eab4d9e4cf1ee43324e619240ab` |
| Offsets (recorded) | `zif_system=0x3A1DA0`, `zval_ptr_dtor=0x491910`, `php_session_reset_id=0x34D6F0` |
| Lab container | `p2s-8235`, `127.0.0.1:18135` |
| Apache | single worker, `KeepAlive Off` |
| PHP config | stock `php.ini-production`, `memory_limit=128M`, `post_max_size=8M`, `session.upload_progress` enabled |
| Date | 2026-10-23 |

## Result

A1 is the arming stage: on a vulnerable build it ends in `HTTP/1.0 500`,
211 bytes, no `Set-Cookie`, with the bailout in `php_session_reset_id` /
`send_cookie`. On 8.2.35 every tested A1 shape **completes normally**:

| progress | status | bytes | Set-Cookie |
|---|---|---|---|
| 10, 100, 300, 500, 800, 1000, 1200, 1500, 2000, 4000, 8000, 16000, 32000 | `HTTP/1.1 200 OK` | 253 | 44 bytes |

No `zend_mm_heap corrupted`, no child abort, no 500 arming signature across
13 variants. The B1 stale-id probe with the 8.3 geometry returns a normal
session cookie (`decoded=34`, ASCII top qwords), i.e. no OOB leak window.
The chain cannot proceed: there is no stale `PS(id)` to forge against.

```
A1 -> status='HTTP/1.1 200 OK' bytes=253 set-cookie=[34]
B1 -> status='HTTP/1.1 200 OK' bytes=253 set-cookie=[34]
[!] leak failed: no heap pointers in leak window (decoded=34 bytes)
```

## Why

Fixed by the same PHP commit `3584a98bda` that ships 8.2.35: delayed
soft-OOM (`UnwindExit`), hard-OOM `_exit(137)`, early `BG()` reset before
rfc1867 parsing, and rfc1867 hardening. The chain's A1/B1 pair depends on
the old `longjmp` bailout leaving stale request globals for the next
request; that state is gone. The 8.2 branch shows the identical patched
signature to 8.3.36.

## Driver behavior

`oneshot-8426/exploit.py` carries `PATCHED_RELEASES` and
`patched_release()` and gates on the preflight banner:

```
[!] target build PHP/8.2.35 is at or above the fixed release 8.2.35: the
    OOM/early-reset engine primitives are patched.
[*] verdict: NOT VULNERABLE to the engine-level CVE-2026-109618/109619
    chain; no chain attempted.
```

The same gate covers 8.3.36, 8.4.27 and 8.5.12+. Vulnerable 8.3.29 /
8.4.26 profiles are unchanged.

## Evidence

- `evidence/a1-sweep.txt` — 13-variant A1 arming sweep
- `evidence/leak-8235.log` — A1/B1 leak probe, normal cookie
- `evidence/docker-log-exits.txt` — empty; no crashes during the sweep
- `evidence/oneshot-verdict.txt` — driver patched-build verdict
- `evidence/symbols.txt`, `evidence/libphp-sha256.txt` — build identity
- `run.sh`, `docker/`, `evidence/` — exact lab target; the engine binary is derived from the recorded image digest

## Reproduction

```sh
./run.sh
SPEC=$(python3 -c "print(','.join(['G:300:0xE2']*16+['X:900']))")
python3 ../oneshot-8426/pure_shell.py --host 127.0.0.1 --port 18135 \
  --path /index.php --outdir ./out --zif 0x3a1da0 --dtor 0x491910 \
  --a1-progress 1000 --b1-fake-len 0xC8000 --b1-spec "$SPEC" \
  --b1-page-off 0x968 --leak --retries 1 --timeout 120
```

Scope: local lab, engine-level chain only. Chain A (raw `upload_progress`
filename write + an application LFI) is a separate technique and is not
implemented or tested here; this result does not claim it is blocked.
